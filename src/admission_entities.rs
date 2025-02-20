use anyhow::{anyhow, Result};
use kube::core::admission::AdmissionReview;
use kube::core::DynamicObject;
use cedar_policy::{
    Authorizer, Response, Context, Request, PolicySet, 
    Entities, Entity, EntityId, EntityTypeName, EntityUid, 
    Expression, RestrictedExpression};
use k8s_openapi::api::authorization::v1::SubjectAccessReview;
use k8s_openapi::api::authorization::v1::SubjectAccessReviewSpec;
use crate::k8s_entities::create_user_entity;
use std::collections::{HashMap, HashSet};
use serde_json::Value;
use std::str::FromStr;

const MAX_DEPTH: i32 = 32;

/// Walks a serde_json::Value and converts it to a Cedar RestrictedExpression
fn walk_value(depth: i32, group: &str, version: &str, kind: &str, key_name: &str, value: &Value) -> Result<RestrictedExpression> {
    if depth <= 0 {
        return Err(anyhow!("Max depth reached"));
    }


    match value {
        Value::Null => Ok(RestrictedExpression::new_string("".to_string())),
        Value::Bool(b) => Ok(RestrictedExpression::new_bool(*b)),
        Value::Number(n) => {
            if n.is_i64() {
                Ok(RestrictedExpression::new_long(n.as_i64().unwrap()))
            } else {
                Ok(RestrictedExpression::new_decimal(n.to_string()))
            }
        },
        Value::String(s) => {
            // Handle IP addresses for known IP fields
            let ip_fields = ["podIP", "clusterIP", "loadBalancerIP", "hostIP", "ip", "podIPs", "hostIPs"];
            if ip_fields.contains(&key_name) {
                // Note: Cedar's IP handling might differ from Go's implementation
                Ok(RestrictedExpression::new_ip(s.to_string()))
            } else {
                Ok(RestrictedExpression::new_string(s.to_string()))
            }
        },
        Value::Array(arr) => {
            let mut values = Vec::new();
            for item in arr {
                values.push(walk_value(depth - 1, group, version, kind, key_name, item)?);
            }
            Ok(RestrictedExpression::new_set(values))
        },
        Value::Object(map) => {
            // Special handling for labels and annotations
            if key_name == "labels" || key_name == "annotations" {
                let mut set = Vec::new();
                for (k, v) in map {
                    if let Value::String(v) = v {
                        let record = RestrictedExpression::new_record(HashMap::from([
                            ("key".to_string(), RestrictedExpression::new_string(k.clone())),
                            ("value".to_string(), RestrictedExpression::new_string(v.clone())),
                        ]))?;
                        set.push(record);
                    }
                }
                return Ok(RestrictedExpression::new_set(set));
            }

            // Handle known key-value string maps (similar to Go's knownKeyValueStringMapAttributes)
            let known_maps: HashMap<&str, HashMap<&str, HashMap<&str, Vec<&str>>>> = {
                let mut m = HashMap::new();
                
                // core/v1
                let mut core = HashMap::new();
                let mut v1 = HashMap::new();
                v1.insert("ConfigMap", vec!["data", "binaryData"]);
                v1.insert("CSIPersistentVolumeSource", vec!["volumeAttributes"]);
                v1.insert("CSIVolumeSource", vec!["volumeAttributes"]);
                v1.insert("FlexPersistentVolumeSource", vec!["options"]);
                v1.insert("FlexVolumeSource", vec!["options"]);
                v1.insert("PersistentVolumeClaimStatus", vec!["allocatedResourceStatuses"]);
                v1.insert("Pod", vec!["nodeSelector"]);
                v1.insert("ReplicationController", vec!["selector"]);
                v1.insert("Secret", vec!["data", "stringData"]);
                v1.insert("Service", vec!["selector"]);
                core.insert("v1", v1);
                m.insert("core", core);

                // discovery/v1
                let mut discovery = HashMap::new();
                let mut v1 = HashMap::new();
                v1.insert("Endpoint", vec!["deprecatedTopology"]);
                discovery.insert("v1", v1);
                m.insert("discovery", discovery);

                // node/v1
                let mut node = HashMap::new();
                let mut v1 = HashMap::new();
                v1.insert("Scheduling", vec!["nodeSelectors"]);
                node.insert("v1", v1);
                m.insert("node", node);

                // storage/v1
                let mut storage = HashMap::new();
                let mut v1 = HashMap::new();
                v1.insert("StorageClass", vec!["parameters"]);
                v1.insert("VolumeAttachmentStatus", vec!["attachmentMetadata"]);
                storage.insert("v1", v1);
                m.insert("storage", storage);

                // meta/v1
                let mut meta = HashMap::new();
                let mut v1 = HashMap::new();
                v1.insert("LabelSelector", vec!["matchLabels"]);
                v1.insert("ObjectMeta", vec!["annotations", "labels"]);
                meta.insert("v1", v1);
                m.insert("meta", meta);

                m
            };


            if let Some(api_group) = known_maps.get(group) {
                if let Some(api_version) = api_group.get(version) {
                    if let Some(attr_names) = api_version.get(kind) {
                        if attr_names.contains(&key_name) {
                            let mut set = Vec::new();
                            for (k, v) in map {
                                if let Value::String(v) = v {
                                    let record = RestrictedExpression::new_record(HashMap::from([
                                        ("key".to_string(), RestrictedExpression::new_string(k.clone())),
                                        ("value".to_string(), RestrictedExpression::new_string(v.clone())),
                                    ]))?;
                                    set.push(record);
                                }
                            }
                            return Ok(RestrictedExpression::new_set(set));
                        }
                    }
                }
            }

            // Handle known key-value string slice maps
            let known_slice_maps: HashMap<&str, HashMap<&str, HashMap<&str, Vec<&str>>>> = {
                let mut m = HashMap::new();

                // authentication/v1
                let mut auth = HashMap::new();
                let mut v1 = HashMap::new();
                v1.insert("UserInfo", vec!["extra"]);
                auth.insert("v1", v1);
                m.insert("authentication", auth);

                // authorization/v1
                let mut authz = HashMap::new();
                let mut v1 = HashMap::new();
                v1.insert("SubjectAccessReview", vec!["extra"]);
                authz.insert("v1", v1);
                m.insert("authorization", authz);

                // certificates/v1
                let mut certs = HashMap::new();
                let mut v1 = HashMap::new();
                v1.insert("CertificateSigningRequest", vec!["extra"]);
                certs.insert("v1", v1);
                m.insert("certificates", certs);

                m
            };

            // Check if this is a string slice map
            if let Some(api_group) = known_slice_maps.get(group) {
                if let Some(api_version) = api_group.get(version) {
                    if let Some(attr_names) = api_version.get(kind) {
                        if attr_names.contains(&key_name) {
                            let mut set = Vec::new();
                            for (k, v) in map {
                                if let Value::Array(values) = v {
                                    let mut value_set = Vec::new();
                                    for val in values {
                                        if let Value::String(s) = val {
                                            value_set.push(RestrictedExpression::new_string(s.clone()));
                                        }
                                    }
                                    let record = RestrictedExpression::new_record(HashMap::from([
                                        ("key".to_string(), RestrictedExpression::new_string(k.clone())),
                                        ("value".to_string(), RestrictedExpression::new_set(value_set)),
                                    ]))?;
                                    set.push(record);
                                }
                            }
                            return Ok(RestrictedExpression::new_set(set));
                        }
                    }
                }
            }

            // Default object handling
            let mut record_map = HashMap::new();
            for (k, v) in map {
                let value = walk_value(depth - 1, group, version, kind, k, v)?;
                record_map.insert(k.clone(), value);
            }
            Ok(RestrictedExpression::new_record(record_map)?)
        }
    }
}

/// Creates a Cedar Entity from an AdmissionRequest's object
fn create_resource_entity(obj: &DynamicObject) -> Result<Entity> {
    let mut attrs = HashMap::new();

    // Add basic type information from the DynamicObject
    let type_meta = obj.types.as_ref().ok_or_else(|| anyhow!("TypeMeta is missing"))?;
    let api_version = type_meta.api_version.clone();
    let kind = type_meta.kind.clone();
    
    // attrs.insert(
    //     "apiVersion".to_string(),
    //     RestrictedExpression::new_string(api_version.clone()),
    // );
    // attrs.insert(
    //     "kind".to_string(),
    //     RestrictedExpression::new_string(kind.clone()),
    // );

    // Create the entity UID using the group, version, and kind
    let (group, version) = if let Some(idx) = api_version.find('/') {
        let (g, v) = api_version.split_at(idx);
        (g.to_string(), v[1..].to_string())  // Skip the '/' character
    } else {
        ("core".to_string(), api_version)
    };

    // Convert the entire object to a Value and walk it
    let obj_value = serde_json::to_value(obj)?;
    if let Value::Object(map) = obj_value {
        for (k, v) in map {
            if k != "types" {  // Skip the types field as we've already handled it
                attrs.insert(k.clone(), walk_value(MAX_DEPTH, &group, &version, &kind, &k, &v)?);
            }
        }
    }

    let type_name = EntityTypeName::from_str(&format!("{}::{}::{}", group, version, kind))?;
    let entity_id = EntityId::from_str(&format!("{}/{}", obj.metadata.namespace.as_deref().unwrap_or(""), obj.metadata.name.as_deref().unwrap_or("")))?;
    let uid = EntityUid::from_type_name_and_id(type_name, entity_id); 

    Entity::new(uid, attrs, Default::default())
        .map_err(|e| anyhow!("Failed to create resource entity: {}", e))
}

/// Converts a Kubernetes AdmissionReview into a SubjectAccessReview
pub fn create_subject_access_review(review: &AdmissionReview<DynamicObject>) -> Result<SubjectAccessReview> {
    let request = review.request.as_ref().ok_or_else(|| anyhow!("AdmissionReview request is missing"))?;

    let spec = SubjectAccessReviewSpec {
        // Copy over user information
        user: request.user_info.username.clone(),
        uid: request.user_info.uid.clone(),
        groups: request.user_info.groups.clone(),
        extra: request.user_info.extra.clone(),

        // Resource attributes are not used
        resource_attributes: None,
        non_resource_attributes: None,
    };

    Ok(SubjectAccessReview {
        metadata: Default::default(),
        spec,
        status: None,
    })
}

pub fn entity_id_from_request(api_group: &str, api_version: &str, kind: &str, name: &str, namespace: &str, sub_resource: &str) -> String {
    let base = match api_group.is_empty() {
        true => "/api".to_string(),
        false => format!("/apis/{}", api_group),
    };
    let namespace_part = match namespace.is_empty() {
        false => format!("/namespaces/{}/", namespace),
        true => String::new(),
    };

    let mut path = format!("{}/{}{}/{}", base, api_version, namespace_part, kind.to_lowercase());

    if !name.is_empty() {
        path.push_str(&format!("/{}", name));
    }

    if !sub_resource.is_empty() {
        path.push_str(&format!("/{}", sub_resource));
    }

    path
}

pub fn review_request(review: &AdmissionReview<DynamicObject>) -> Response {
    let principal_sar = create_subject_access_review(review).unwrap();
    let (principal_entity, group_entities) = create_user_entity(&principal_sar).unwrap();

    let mut all_entities = vec![principal_entity.clone()];
    all_entities.extend(group_entities);

    // Add the resource entity if present
    if let Some(request) = &review.request {
        if let Some(obj) = &request.object {
            if let Ok(resource_entity) = create_resource_entity(obj) {
                all_entities.push(resource_entity);
            }
        }
    }

    let entities = Entities::from_entities(all_entities, None).unwrap();
    
    let authorizer = Authorizer::new();
    let request = Request::new(
        Some(principal_entity.uid()),
        None, // TODO: Add action entity
        None, // TODO: Add resource entity UID
        Context::empty(),
        None,
    ).unwrap();
    let policy_set = PolicySet::new();
    
    authorizer.is_authorized(&request, &policy_set, &entities)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::admission::{AdmissionRequest, Operation};
    use kube::core::{GroupVersionKind, GroupVersionResource, TypeMeta};
    use k8s_openapi::api::authentication::v1::UserInfo;
    use std::collections::BTreeMap;

    struct TestCase {
        name: &'static str,
        input: AdmissionReview<DynamicObject>,
        want_err: bool,
        expected_user: Option<String>,
        expected_uid: Option<String>,
        expected_groups: Option<Vec<String>>,
        expected_extra: Option<BTreeMap<String, Vec<String>>>,
    }

    #[test]
    fn test_create_subject_access_review() {
        let test_cases = vec![
            TestCase {
                name: "valid review with all fields",
                input: AdmissionReview {
                    types: TypeMeta::default(),
                    request: Some(AdmissionRequest {
                        uid: "test-request-uid".to_string(),
                        user_info: UserInfo {
                            username: Some("test-user".to_string()),
                            uid: Some("test-uid".to_string()),
                            groups: Some(vec!["test-group".to_string()]),
                            extra: Some({
                                let mut extra = BTreeMap::new();
                                extra.insert("test-key".to_string(), vec!["test-value".to_string()]);
                                extra
                            }),
                        },
                        name: "test-name".to_string(),
                        namespace: Some("test-namespace".to_string()),
                        operation: Operation::Create,
                        kind: GroupVersionKind {
                            group: "".to_string(),
                            version: "v1".to_string(),
                            kind: "Pod".to_string(),
                        },
                        resource: GroupVersionResource::gvr("", "v1", "pods"),
                        sub_resource: None,
                        request_kind: None,
                        request_resource: None,
                        request_sub_resource: None,
                        object: None,
                        old_object: None,
                        dry_run: false,
                        options: None,
                        types: TypeMeta::default(),
                    }),
                    response: None,
                },
                want_err: false,
                expected_user: Some("test-user".to_string()),
                expected_uid: Some("test-uid".to_string()),
                expected_groups: Some(vec!["test-group".to_string()]),
                expected_extra: Some({
                    let mut extra = BTreeMap::new();
                    extra.insert("test-key".to_string(), vec!["test-value".to_string()]);
                    extra
                }),
            },
            TestCase {
                name: "missing request",
                input: AdmissionReview {
                    types: TypeMeta::default(),
                    request: None,
                    response: None,
                },
                want_err: true,
                expected_user: None,
                expected_uid: None,
                expected_groups: None,
                expected_extra: None,
            },
            TestCase {
                name: "minimal valid review",
                input: AdmissionReview {
                    types: TypeMeta::default(),
                    request: Some(AdmissionRequest {
                        uid: "test-request-uid".to_string(),
                        user_info: UserInfo {
                            username: None,
                            uid: None,
                            groups: None,
                            extra: None,
                        },
                        name: "test-name".to_string(),
                        namespace: Some("test-namespace".to_string()),
                        operation: Operation::Create,
                        kind: GroupVersionKind {
                            group: "".to_string(),
                            version: "v1".to_string(),
                            kind: "Pod".to_string(),
                        },
                        resource: GroupVersionResource::gvr("", "v1", "pods"),
                        sub_resource: None,
                        request_kind: None,
                        request_resource: None,
                        request_sub_resource: None,
                        object: None,
                        old_object: None,
                        dry_run: false,
                        options: None,
                        types: TypeMeta::default(),
                    }),
                    response: None,
                },
                want_err: false,
                expected_user: None,
                expected_uid: None,
                expected_groups: None,
                expected_extra: None,
            },
        ];

        for tc in test_cases {
            let result = create_subject_access_review(&tc.input);
            
            if tc.want_err {
                assert!(result.is_err(), "{}: expected error but got success", tc.name);
                continue;
            }
            
            let sar = result.expect(&format!("{}: unexpected error", tc.name));
            
            assert_eq!(sar.spec.user, tc.expected_user, "{}: user mismatch", tc.name);
            assert_eq!(sar.spec.uid, tc.expected_uid, "{}: uid mismatch", tc.name);
            assert_eq!(sar.spec.groups, tc.expected_groups, "{}: groups mismatch", tc.name);
            assert_eq!(sar.spec.extra, tc.expected_extra, "{}: extra mismatch", tc.name);
        }
    }
} 