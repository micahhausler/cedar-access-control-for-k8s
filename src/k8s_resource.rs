use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use anyhow::{anyhow, Result};
use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};
use k8s_openapi::api::authorization::v1::{
    NonResourceAttributes, ResourceAttributes, SubjectAccessReview,
};

pub const RESOURCE_TYPE: &str = "k8s::Resource";
pub const NON_RESOURCE_TYPE: &str = "k8s::NonResource";
pub const USER_TYPE: &str = "k8s::User";
pub const NODE_TYPE: &str = "k8s::Node";
pub const SERVICE_ACCOUNT_TYPE: &str = "k8s::ServiceAccount";
pub const GROUP_TYPE: &str = "k8s::Group";
pub const ACTION_TYPE: &str = "k8s::Action";
pub const USER_EXTRA_TYPE: &str = "k8s::Extra";
pub const PRINCIPAL_UID_TYPE: &str = "k8s::PrincipalUID";

/// Creates a Cedar Entity representing a Kubernetes resource
pub fn create_resource_entity(review: &SubjectAccessReview) -> Result<Entity> {
    // check if it is a resource request
    match review.spec.non_resource_attributes.as_ref() {
        Some(attrs) => non_resource_to_entity(attrs),
        None => {
            match review
                .spec
                .resource_attributes
                .as_ref()
                .expect("has resource attributes")
                .verb
                .as_ref()
                .expect("SAR should have a verb")
                .as_str()
            {
                "impersonate" => impersonated_resource_to_entity(review),
                _ => resource_to_entity(
                    review
                        .spec
                        .resource_attributes
                        .as_ref()
                        .expect("has resource attributes"),
                ),
            }
        }
    }
}

pub fn non_resource_to_entity(review: &NonResourceAttributes) -> Result<Entity> {
    Ok(Entity::new(
        EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(NON_RESOURCE_TYPE)?,
            EntityId::from_str(review.path.as_ref().unwrap())?,
        ),
        HashMap::from([(
            "path".to_string(),
            RestrictedExpression::new_string(review.path.as_ref().unwrap().to_string()),
        )]),
        HashSet::new(),
    )?)
}

pub fn resource_to_entity(review: &ResourceAttributes) -> Result<Entity> {
    let mut attrs = HashMap::new();
    attrs.insert(
        "apiGroup".to_string(),
        RestrictedExpression::new_string(review.group.as_ref().unwrap().to_string()),
    );
    attrs.insert(
        "resource".to_string(),
        RestrictedExpression::new_string(review.resource.as_ref().unwrap().to_string()),
    );

    if let Some(namespace) = review.namespace.as_ref() {
        attrs.insert(
            "namespace".to_string(),
            RestrictedExpression::new_string(namespace.to_string()),
        );
    }

    if let Some(name) = review.name.as_ref() {
        attrs.insert(
            "name".to_string(),
            RestrictedExpression::new_string(name.to_string()),
        );
    }

    if let Some(subresource) = review.subresource.as_ref() {
        attrs.insert(
            "subresource".to_string(),
            RestrictedExpression::new_string(subresource.to_string()),
        );
    }
    if let Some(label_selector) = review.label_selector.as_ref() {
        if let Some(requirements) = &label_selector.requirements {
            attrs.insert(
                "labelSelector".to_string(),
                RestrictedExpression::new_set(
                    requirements
                        .iter()
                        .map(|selector| {
                            RestrictedExpression::new_record(HashMap::from([
                                (
                                    "key".to_string(),
                                    RestrictedExpression::new_string(selector.key.to_string()),
                                ),
                                (
                                    "operator".to_string(),
                                    RestrictedExpression::new_string(selector.operator.to_string()),
                                ),
                                (
                                    "values".to_string(),
                                    RestrictedExpression::new_set(
                                        selector.values.as_ref().map_or_else(Vec::new, |values| {
                                            values
                                                .iter()
                                                .map(|value| {
                                                    RestrictedExpression::new_string(
                                                        value.to_string(),
                                                    )
                                                })
                                                .collect()
                                        }),
                                    ),
                                ),
                            ]))
                            .unwrap()
                        })
                        .collect::<Vec<_>>(),
                ),
            );
        }
    }
    if let Some(field_selector) = review.field_selector.as_ref() {
        if let Some(requirements) = &field_selector.requirements {
            attrs.insert(
                "fieldSelector".to_string(),
                RestrictedExpression::new_set(
                    requirements
                        .iter()
                        .map(|selector| {
                            RestrictedExpression::new_record(HashMap::from([
                                (
                                    "field".to_string(),
                                    RestrictedExpression::new_string(selector.key.to_string()),
                                ),
                                (
                                    "operator".to_string(),
                                    RestrictedExpression::new_string(selector.operator.to_string()),
                                ),
                                (
                                    "value".to_string(),
                                    RestrictedExpression::new_string(
                                        selector.values.as_ref().map_or_else(
                                            String::new,
                                            |values| {
                                                values
                                                    .first()
                                                    .map_or_else(String::new, |v| v.to_string())
                                            },
                                        ),
                                    ),
                                ),
                            ]))
                            .unwrap()
                        })
                        .collect::<Vec<_>>(),
                ),
            );
        }
    }

    Ok(Entity::new(
        EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(RESOURCE_TYPE)?,
            EntityId::from_str(review.resource.as_ref().unwrap())?,
        ),
        attrs,
        HashSet::new(),
    )?)
}

pub fn impersonated_resource_to_entity(review: &SubjectAccessReview) -> Result<Entity> {
    let attrs = review
        .spec
        .resource_attributes
        .as_ref()
        .expect("has resource attributes");
    let mut entity_attrs = HashMap::new();

    let (entity_type, entity_id) = match attrs.resource.as_ref().expect("has resource").as_str() {
        "serviceaccounts" => {
            let name = attrs.name.as_ref().expect("has name");
            let namespace = attrs.namespace.as_ref().expect("has namespace");
            entity_attrs.insert(
                "name".to_string(),
                RestrictedExpression::new_string(name.to_string()),
            );
            entity_attrs.insert(
                "namespace".to_string(),
                RestrictedExpression::new_string(namespace.to_string()),
            );
            (
                SERVICE_ACCOUNT_TYPE,
                format!("system:serviceaccount:{}:{}", namespace, name),
            )
        }
        "uids" => {
            let name = attrs.name.as_ref().expect("has name");
            (PRINCIPAL_UID_TYPE, name.to_string())
        }
        "users" => {
            let name = attrs.name.as_ref().expect("has name");
            entity_attrs.insert(
                "name".to_string(),
                RestrictedExpression::new_string(name.clone()),
            );

            // Handle node impersonation special case
            if name.starts_with("system:node:") && name.matches(":").count() == 2 {
                let node_name = name.split(":").nth(2).unwrap();
                entity_attrs.insert(
                    "name".to_string(),
                    RestrictedExpression::new_string(node_name.to_string()),
                );
                (NODE_TYPE, name.to_string())
            } else {
                (USER_TYPE, name.to_string())
            }
        }
        "groups" => {
            let name = attrs.name.as_ref().expect("has name");
            entity_attrs.insert(
                "name".to_string(),
                RestrictedExpression::new_string(name.to_string()),
            );
            (GROUP_TYPE, name.to_string())
        }
        "userextras" => {
            let key = attrs.subresource.as_ref().expect("has subresource");
            entity_attrs.insert(
                "key".to_string(),
                RestrictedExpression::new_string(key.to_string()),
            );
            if let Some(name) = attrs.name.as_ref() {
                entity_attrs.insert(
                    "value".to_string(),
                    RestrictedExpression::new_string(name.to_string()),
                );
            }
            (USER_EXTRA_TYPE, key.to_string())
        }
        _ => return Err(anyhow!("invalid impersonation resource type")),
    };

    Ok(Entity::new(
        EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(entity_type)?,
            EntityId::from_str(&entity_id)?,
        ),
        entity_attrs,
        HashSet::new(),
    )?)
}
