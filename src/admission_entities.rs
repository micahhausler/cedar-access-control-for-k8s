use crate::k8s_entities::create_user_entity;
use crate::name_transform::gvk_to_cedar;
use anyhow::{anyhow, Result};
use cedar_policy::{
    Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, Request, RestrictedExpression,
};
use k8s_openapi::api::authorization::v1::{SubjectAccessReview, SubjectAccessReviewSpec};
use kube::core::admission::{AdmissionReview, Operation};
use kube::core::DynamicObject;
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;

const MAX_DEPTH: i32 = 32;

/// Walks a serde_json::Value and converts it to a Cedar RestrictedExpression
fn walk_value(
    depth: i32,
    group: &str,
    version: &str,
    kind: &str,
    key_name: &str,
    value: &Value,
) -> Result<RestrictedExpression> {
    if depth <= 0 {
        return Err(anyhow!("Max depth reached"));
    }

    match value {
        Value::Null => Ok(RestrictedExpression::new_string("".to_string())),
        Value::Bool(b) => Ok(RestrictedExpression::new_bool(*b)),
        Value::Number(n) => match n.as_i64() {
            Some(i) => Ok(RestrictedExpression::new_long(i)),
            None => Ok(RestrictedExpression::new_decimal(n.to_string())),
        },
        Value::String(s) => {
            // Handle IP addresses for known IP fields
            let ip_fields = [
                "podIP",
                "clusterIP",
                "loadBalancerIP",
                "hostIP",
                "ip",
                "podIPs",
                "hostIPs",
            ];
            match ip_fields.contains(&key_name) {
                true => Ok(RestrictedExpression::new_ip(s.to_string())), // Note: Cedar's IP handling might differ from Go's implementation
                false => Ok(RestrictedExpression::new_string(s.to_string())),
            }
        }
        Value::Array(arr) => {
            let mut values = Vec::new();
            for item in arr {
                values.push(walk_value(depth - 1, group, version, kind, key_name, item)?);
            }
            Ok(RestrictedExpression::new_set(values))
        }
        Value::Object(map) => {
            // Special handling for labels and annotations
            if key_name == "labels" || key_name == "annotations" {
                let mut set = Vec::new();
                for (k, v) in map {
                    if let Value::String(v) = v {
                        let record = RestrictedExpression::new_record(HashMap::from([
                            (
                                "key".to_string(),
                                RestrictedExpression::new_string(k.clone()),
                            ),
                            (
                                "value".to_string(),
                                RestrictedExpression::new_string(v.clone()),
                            ),
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
                v1.insert(
                    "PersistentVolumeClaimStatus",
                    vec!["allocatedResourceStatuses"],
                );
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
                                    let record =
                                        RestrictedExpression::new_record(HashMap::from([
                                            (
                                                "key".to_string(),
                                                RestrictedExpression::new_string(k.clone()),
                                            ),
                                            (
                                                "value".to_string(),
                                                RestrictedExpression::new_string(v.clone()),
                                            ),
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
                                            value_set
                                                .push(RestrictedExpression::new_string(s.clone()));
                                        }
                                    }
                                    let record =
                                        RestrictedExpression::new_record(HashMap::from([
                                            (
                                                "key".to_string(),
                                                RestrictedExpression::new_string(k.clone()),
                                            ),
                                            (
                                                "value".to_string(),
                                                RestrictedExpression::new_set(value_set),
                                            ),
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
pub fn create_admission_resource_entity(
    review: &AdmissionReview<DynamicObject>,
    obj: &DynamicObject,
) -> Result<Entity> {
    let req = review
        .request
        .as_ref()
        .ok_or_else(|| anyhow!("AdmissionReview request is missing"))?;

    let api_version = review.request.as_ref().unwrap().resource.version.clone();
    let resource = review.request.as_ref().unwrap().resource.resource.clone();
    let kind = review.request.as_ref().unwrap().kind.kind.clone();

    let euid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str(&gvk_to_cedar(&req.kind))?,
        EntityId::new(&entity_id_from_request(
            review.request.as_ref().unwrap().resource.group.as_str(),
            &api_version,
            &resource,
            req.name.as_str(),
            req.namespace.as_deref().unwrap_or(""),
            req.sub_resource.as_deref().unwrap_or(""),
        )),
    );

    let attrs = dyn_object_to_attrs(
        obj,
        &review.request.as_ref().unwrap().resource.group,
        &api_version,
        &kind,
    )?;
    Entity::new(euid, attrs, Default::default()).map_err(|e| anyhow!(e))
}

fn dyn_object_to_attrs(
    obj: &DynamicObject,
    group: &str,
    version: &str,
    kind: &str,
) -> Result<HashMap<String, RestrictedExpression>> {
    let mut attrs = HashMap::new();

    // Convert the entire object to a Value and walk it
    let obj_value = serde_json::to_value(obj)?;
    if let Value::Object(map) = obj_value {
        for (k, v) in map {
            if k != "types" {
                // Skip the types field as we've already handled it
                attrs.insert(
                    k.clone(),
                    walk_value(MAX_DEPTH, &group, &version, &kind, &k, &v)?,
                );
            }
        }
    }

    Ok(attrs)
}

/// Converts a Kubernetes AdmissionReview into a SubjectAccessReview
pub fn create_subject_access_review(
    review: &AdmissionReview<DynamicObject>,
) -> Result<SubjectAccessReview> {
    let request = review
        .request
        .as_ref()
        .ok_or_else(|| anyhow!("AdmissionReview request is missing"))?;

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

pub fn entity_id_from_request(
    api_group: &str,
    api_version: &str,
    resource: &str,
    name: &str,
    namespace: &str,
    sub_resource: &str,
) -> String {
    let base = match api_group.is_empty() {
        true => "/api".to_string(),
        false => format!("/apis/{}", api_group),
    };
    let namespace_part = match namespace.is_empty() {
        false => format!("/namespaces/{}", namespace),
        true => String::new(),
    };

    let mut path = format!(
        "{}/{}{}/{}",
        base,
        api_version,
        namespace_part,
        resource.to_lowercase()
    );

    if !name.is_empty() {
        path.push_str(&format!("/{}", name));
    }

    if !sub_resource.is_empty() {
        path.push_str(&format!("/{}", sub_resource));
    }

    path
}

pub fn request_from_review(review: &AdmissionReview<DynamicObject>) -> Result<(Request, Entities)> {
    let principal_sar = create_subject_access_review(review)?;
    let (principal_entity, group_entities) = create_user_entity(&principal_sar)?;

    let mut all_entities = vec![principal_entity.clone()];
    all_entities.extend(group_entities);

    let resource_euid = match review.request.as_ref().unwrap().operation {
        Operation::Delete => {
            let resource_entity = create_admission_resource_entity(
                review,
                review
                    .request
                    .as_ref()
                    .unwrap()
                    .old_object
                    .as_ref()
                    .unwrap(),
            )?;
            let euid = resource_entity.uid();
            all_entities.push(resource_entity);
            euid
        }
        Operation::Update => {
            let orig_old_resource_entity = create_admission_resource_entity(
                review,
                review
                    .request
                    .as_ref()
                    .unwrap()
                    .old_object
                    .as_ref()
                    .unwrap(),
            )?;
            let (orig_old_uid, orig_old_attrs, _) = orig_old_resource_entity.into_inner();
            let old_uid = EntityUid::from_type_name_and_id(
                orig_old_uid.type_name().clone(),
                EntityId::new(&review.request.as_ref().unwrap().uid.clone()),
            );
            let old_resource_entity =
                Entity::new(old_uid, orig_old_attrs, Default::default()).unwrap();
            all_entities.push(old_resource_entity);
            let tmp_resource_entity = create_admission_resource_entity(
                review,
                review.request.as_ref().unwrap().object.as_ref().unwrap(),
            )?;
            let (resource_uid, mut resource_attrs, _) = tmp_resource_entity.into_inner();
            resource_attrs.insert(
                "oldObject".to_string(),
                RestrictedExpression::new_entity_uid(orig_old_uid),
            );
            let euid = resource_uid.clone();
            all_entities
                .push(Entity::new(resource_uid, resource_attrs, Default::default()).unwrap());
            euid
        }
        _ => {
            let resource_entity = create_admission_resource_entity(
                review,
                review.request.as_ref().unwrap().object.as_ref().unwrap(),
            )?;
            let euid = resource_entity.uid();
            all_entities.push(resource_entity);
            euid
        }
    };

    let entities = Entities::from_entities(all_entities, None).unwrap();

    let action_str = match review.request.as_ref().unwrap().operation {
        Operation::Create => "create",
        Operation::Update => "update",
        Operation::Delete => "delete",
        Operation::Connect => "connect",
    };
    let action = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("k8s::admission::Action")?,
        EntityId::from_str(action_str)?,
    );

    let request = Request::new(
        principal_entity.uid(),
        action,
        resource_euid,
        Context::empty(),
        None,
    )?;

    Ok((request, entities))
}
