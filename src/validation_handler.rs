use axum::response::IntoResponse;
use axum::Json;
use cedar_policy::{PolicySet, Validator};
use kube::core::{
    admission::{AdmissionRequest, AdmissionResponse, AdmissionReview, Operation},
    DynamicObject, ResourceExt,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::Arc;
use log::*;

#[derive(Clone)]
pub struct ValidationServer {
    validator: Arc<Validator>,
}

impl ValidationServer {
    pub fn new(validator: Validator) -> Self {
        Self {
            validator: Arc::new(validator),
        }
    }

    pub async fn handle(
        &self,
        Json(review): Json<AdmissionReview<DynamicObject>>,
    ) -> impl IntoResponse {
        // Parse incoming webhook AdmissionRequest first
        let req: AdmissionRequest<_> = match review.try_into() {
            Ok(req) => req,
            Err(err) => {
                error!("invalid request: {}", err.to_string());
                return Json(AdmissionResponse::invalid(err.to_string()).into_review());
            }
        };

        // Allow any non-cedar policy types.
        if req.kind.group != "cedar.k8s.aws" || req.kind.kind != "Policy" {
            return Json(AdmissionResponse::from(&req).into_review());
        }
        // Only validate on create/update
        if req.operation == Operation::Delete || req.operation == Operation::Connect {
            return Json(AdmissionResponse::from(&req).into_review());
        }
        
        // Then construct a AdmissionResponse
        let mut res = AdmissionResponse::from(&req);
        // req.Object always exists for us, but could be None if extending to DELETE events
        // we don't care about oldObject for deletes/updates, since we're only validating the new content
        if let Some(obj) = req.object {
            let name = obj.name_any(); // apiserver may not have generated a name yet
            res = match self.validate(res.clone(), &obj) {
                Ok(res) => {
                    info!("accepted: {:?} on Policy {}", req.operation, name);
                    res
                }
                Err(err) => {
                    warn!("denied: {:?} on Policy {} ({})", req.operation, name, err);
                    res.deny(err.to_string())
                }
            };
        };
        // Wrap the AdmissionResponse wrapped in an AdmissionReview
        Json(res.into_review())
    }

    fn validate(
        &self,
        mut res: AdmissionResponse,
        obj: &DynamicObject,
    ) -> Result<AdmissionResponse, Box<dyn Error>> {
        let policy = convert_dynamic_to_policy(obj)?;

        if policy.spec.is_none() {
            return Err("Policy spec is empty".into());
        }

        let policy_spec = match policy.spec {
            Some(spec) => spec,
            None => return Err("Policy spec is empty".into()),
        };

        let policy_set = match policy_spec.content.parse::<PolicySet>() {
            Ok(ps) => ps,
            Err(e) => return Err(Box::new(e)),
        };

        if !policy_spec.validation.enforced {
            return Ok(res);
        }

        // check if validation is enforced
        let validation_mode = match policy_spec.validation.validation_mode {
            ValidationMode::Permissive => cedar_policy::ValidationMode::Permissive,
            ValidationMode::Strict => cedar_policy::ValidationMode::Strict,
            ValidationMode::Partial => cedar_policy::ValidationMode::Partial,
        };

        let result = self.validator.validate(&policy_set, validation_mode);

        if result.validation_warnings().count() != 0 {
            res.warnings = Some(result
                .validation_warnings()
                .map(|w| w.to_string())
                .collect());
        }
        if result.validation_passed() {
            return Ok(res);
        }
        let errors: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
        return Err(errors.join(", ").into());
    }
}

fn convert_dynamic_to_policy(obj: &DynamicObject) -> Result<Policy, serde_json::Error> {
    // First convert the DynamicObject to a serde_json::Value
    let value = serde_json::to_value(obj)?;
    // Then convert the Value into your Policy struct
    serde_json::from_value(value)
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum ValidationMode {
    #[default]
    #[serde(rename = "permissive")]
    Permissive,
    #[serde(rename = "strict")]
    Strict,
    #[serde(rename = "partial")]
    Partial,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicyValidation {
    /// Enforced indicates if creation or updates to the policy require schema validation
    /// Syntax validation is always enforced.
    pub enforced: bool,
    /// ValidationMode indicates which validation mode to use.
    /// A value of `strict` requires that only literals are passed to extension functions (IP, decimal, datetime), and not entity attributes.
    /// See https://docs.cedarpolicy.com/policies/validation.html#validation-benefits-of-schema for more details.
    #[serde(rename = "validationMode")]
    pub validation_mode: ValidationMode,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicySpec {
    /// Content of the Cedar policy
    pub content: String,
    /// Validation configuration for the policy
    pub validation: PolicyValidation,
}

/// Policy is a Cedar Policy CRD
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// Standard object's metadata
    pub metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
    pub spec: Option<PolicySpec>,
} 