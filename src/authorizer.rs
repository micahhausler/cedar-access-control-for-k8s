use std::sync::Arc;

use axum::extract::Json;
use cedar_policy::Decision;
use k8s_openapi::api::authorization::v1::{
    SubjectAccessReview, SubjectAccessReviewStatus, ResourceAttributes,
};
use cedar_policy::Schema;
use log::*;
use uuid;

use crate::policy_store;

#[derive(Clone)]
pub struct AuthorizerServer {
    stores: Arc<policy_store::TieredPolicyStores<'static>>,
    schema: Option<Arc<Schema>>,
}

impl AuthorizerServer {
    pub fn new(stores: policy_store::TieredPolicyStores<'static>, schema: Option<Arc<Schema>>) -> Self {
        Self {
            stores: Arc::new(stores),
            schema,
        }
    }

    // Wrapper function that adds logging
    pub async fn with_logging(
        &self,
        Json(review): Json<SubjectAccessReview>,
        handler: fn(&Self, Json<SubjectAccessReview>) -> Json<SubjectAccessReview>,
    ) -> Json<SubjectAccessReview> {
        let username = review.spec.user.as_deref().unwrap_or("");
        let uid = review.spec.uid.as_deref().unwrap_or("");

        if username == "" {
            return Json(no_opinion(review));
        }

        info!(
            "Processing authorization request for user '{}' (uid: '{}')",
            username, uid
        );

        let response = handler(self, Json(review.clone()));
        let result = match response.0.status.as_ref() {
            Some(status) => {
                if status.allowed {
                    "allow"
                } else if status.denied.unwrap_or(false) {
                    "deny"
                } else {
                    "no opinion"
                }
            }
            None => "no status",
        };

        info!(
            "Authorization result {}: {} (user '{}'/'{}')",
            response.0.metadata.uid.as_deref().unwrap_or("unknown"),
            result,
            username,
            uid,
        );

        response
    }

    // Handler for authorization webhook
    pub fn authorize_handler(
        &self,
        Json(review): Json<SubjectAccessReview>,
    ) -> Json<SubjectAccessReview> {
        // Generate a request id for logging purposes
        let request_id = uuid::Uuid::new_v4().to_string();
        let mut response = review.clone();
        response.metadata.uid = Some(request_id);


        // check for empty group/resource/verb (should never happen)
        if review.spec.resource_attributes.as_ref().is_some()
            && review.spec.resource_attributes.as_ref().unwrap_or(&ResourceAttributes::default()).group.is_none()
            && review.spec.resource_attributes.as_ref().unwrap_or(&ResourceAttributes::default()).resource.is_none()
            && review.spec.resource_attributes.as_ref().unwrap_or(&ResourceAttributes::default()).verb.is_none()
        {
            return Json(no_opinion(response));
        }


        // Always allow self to read policies
        if review.spec.user == Some("cedar-authorizer".to_string())
            && review.spec.resource_attributes.as_ref().is_some()
            && review.spec.resource_attributes.as_ref().unwrap().group
                == Some("cedar.k8s.aws".to_string())
            && review.spec.resource_attributes.as_ref().unwrap().resource
                == Some("policies".to_string())
        {
            info!("No opinion for cedar-authorizer reading Cedar policies");
            return Json(no_opinion(response));
        }

        // cedar-authorizer can read RBAC policies
        if review.spec.user == Some("cedar-authorizer".to_string())
            && review.spec.resource_attributes.as_ref().is_some()
            && review.spec.resource_attributes.as_ref().unwrap().group
                == Some("rbac.authorization.k8s.io".to_string())
            && ["get", "list", "watch"].contains(
                &review
                    .spec
                    .resource_attributes
                    .as_ref()
                    .unwrap()
                    .verb
                    .as_deref()
                    .unwrap_or(""),
            )
        {
            info!("No opinion for cedar-authorizer reading RBAC policies");
            return Json(no_opinion(response));
        }

        // skip system users (anonymous, internal identities) for development, helps from accidentally halting normal operations
        if review.spec.user.is_some()
            && review.spec.user.as_ref().unwrap().starts_with("system:")
            && !review
                .spec
                .user
                .as_ref()
                .unwrap()
                .starts_with("system:node:")
            && !review
                .spec
                .user
                .as_ref()
                .unwrap()
                .starts_with("system:serviceaccount:")
        {
            info!(
                "No opinion for system user {}",
                review.spec.user.as_ref().unwrap()
            );
            return Json(no_opinion(response));
        }

        let (entities, request) = match crate::k8s_entities::create_entities_and_request(&review, self.schema.clone()) {    
            Ok((entities, request)) => (entities, request),
            Err(e) => {
                error!("Error creating entities and request: {}", e);
                return Json(no_opinion(response));
            }
        };
        let cedar_response = self.stores.is_authorized(&entities, &request);

        match cedar_response {
            Ok(cedar_response) => {
                if cedar_response.decision() == Decision::Deny
                    && cedar_response.diagnostics().errors().count() == 0
                    && cedar_response.diagnostics().reason().count() == 0
                {
                    return Json(no_opinion(response));
                }

                // Create response
                response.status = Some(SubjectAccessReviewStatus {
                    allowed: cedar_response.decision() == Decision::Allow,
                    denied: Some(cedar_response.decision() == Decision::Deny),
                    reason: None,
                    ..Default::default()
                });

                return Json(response)
            }
            Err(e) => {
                error!("Error authorizing request: {}", e);
                return Json(no_opinion(response));
            }
        }

    }
}

fn no_opinion(sar: SubjectAccessReview) -> SubjectAccessReview {
    let mut response = sar;
    response.status = Some(SubjectAccessReviewStatus {
        allowed: false,
        denied: Some(false),
        evaluation_error: None,
        reason: None,
    });
    response
}
