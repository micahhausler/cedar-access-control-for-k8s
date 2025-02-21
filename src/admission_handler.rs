use std::sync::Arc;

use axum::extract::Json;
use cedar_policy;
use kube::core::admission::{AdmissionResponse, AdmissionReview};
use kube::core::DynamicObject;

use crate::admission_entities::request_from_review;
use crate::policy_store;

#[derive(Clone)]
pub struct AdmissionServer {
    stores: Arc<policy_store::TieredPolicyStores<'static>>,
}

impl AdmissionServer {
    pub fn new(stores: policy_store::TieredPolicyStores<'static>) -> Self {
        Self {
            stores: Arc::new(stores),
        }
    }

    pub async fn handle(
        &self,
        Json(review): Json<AdmissionReview<DynamicObject>>,
    ) -> Json<AdmissionReview<DynamicObject>> {
        let (request, entities) = request_from_review(&review).unwrap();
        let cedar_response = self.stores.is_authorized(&entities, &request).unwrap();
        let allowed = cedar_response.decision() != cedar_policy::Decision::Deny;
        let mut resp = AdmissionResponse::from(&review.request.unwrap());
        resp.types = review.types;
        if !allowed {
            resp = resp.deny("Not authorized by Cedar policies");
        }

        Json(resp.into_review())
    }
}
