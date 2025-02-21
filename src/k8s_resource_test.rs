use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use anyhow::Result;
use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SubjectAccessReview, SubjectAccessReviewSpec,
};

use crate::k8s_resource::{create_authorization_resource_entity, RESOURCE_TYPE};

#[test]
fn test_resource_entity_creation() -> Result<()> {
    struct TestCase {
        name: &'static str,
        input: SubjectAccessReview,
        expected_resource: Entity,
    }

    let test_cases = vec![
        TestCase {
            name: "pod in namespace",
            input: SubjectAccessReview {
                metadata: Default::default(),
                spec: SubjectAccessReviewSpec {
                    resource_attributes: Some(ResourceAttributes {
                        verb: Some("get".to_string()),
                        resource: Some("pods".to_string()),
                        namespace: Some("default".to_string()),
                        name: Some("nginx".to_string()),
                        group: Some("".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                status: None,
            },
            expected_resource: Entity::new(
                EntityUid::from_type_name_and_id(
                    EntityTypeName::from_str(RESOURCE_TYPE)?,
                    EntityId::from_str("pods")?,
                ),
                HashMap::from([
                    (
                        "verb".to_string(),
                        RestrictedExpression::new_string("get".to_string()),
                    ),
                    (
                        "resource".to_string(),
                        RestrictedExpression::new_string("pods".to_string()),
                    ),
                    (
                        "namespace".to_string(),
                        RestrictedExpression::new_string("default".to_string()),
                    ),
                    (
                        "name".to_string(),
                        RestrictedExpression::new_string("nginx".to_string()),
                    ),
                    (
                        "apiGroup".to_string(),
                        RestrictedExpression::new_string("".to_string()),
                    ),
                ]),
                HashSet::new(),
            )?,
        },
        TestCase {
            name: "cluster-scoped resource",
            input: SubjectAccessReview {
                metadata: Default::default(),
                spec: SubjectAccessReviewSpec {
                    resource_attributes: Some(ResourceAttributes {
                        verb: Some("update".to_string()),
                        resource: Some("nodes".to_string()),
                        name: Some("worker-1".to_string()),
                        group: Some("".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                status: None,
            },
            expected_resource: Entity::new(
                EntityUid::from_type_name_and_id(
                    EntityTypeName::from_str(RESOURCE_TYPE)?,
                    EntityId::from_str("nodes")?,
                ),
                HashMap::from([
                    (
                        "verb".to_string(),
                        RestrictedExpression::new_string("update".to_string()),
                    ),
                    (
                        "resource".to_string(),
                        RestrictedExpression::new_string("nodes".to_string()),
                    ),
                    (
                        "name".to_string(),
                        RestrictedExpression::new_string("worker-1".to_string()),
                    ),
                    (
                        "apiGroup".to_string(),
                        RestrictedExpression::new_string("".to_string()),
                    ),
                ]),
                HashSet::new(),
            )?,
        },
        TestCase {
            name: "custom resource",
            input: SubjectAccessReview {
                metadata: Default::default(),
                spec: SubjectAccessReviewSpec {
                    resource_attributes: Some(ResourceAttributes {
                        resource: Some("policies".to_string()),
                        group: Some("authorization.k8s.aws".to_string()),
                        namespace: Some("default".to_string()),
                        verb: Some("list".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                status: None,
            },
            expected_resource: Entity::new(
                EntityUid::from_type_name_and_id(
                    EntityTypeName::from_str(RESOURCE_TYPE)?,
                    EntityId::from_str("policies")?,
                ),
                HashMap::from([
                    (
                        "verb".to_string(),
                        RestrictedExpression::new_string("list".to_string()),
                    ),
                    (
                        "resource".to_string(),
                        RestrictedExpression::new_string("policies".to_string()),
                    ),
                    (
                        "apiGroup".to_string(),
                        RestrictedExpression::new_string("authorization.k8s.aws".to_string()),
                    ),
                    (
                        "namespace".to_string(),
                        RestrictedExpression::new_string("default".to_string()),
                    ),
                    (
                        "name".to_string(),
                        RestrictedExpression::new_string("allow-dev".to_string()),
                    ),
                ]),
                HashSet::new(),
            )?,
        },
    ];

    for tc in test_cases {
        let resource = create_authorization_resource_entity(&tc.input)?;
        assert_eq!(resource, tc.expected_resource, "test case: {}", tc.name);
    }

    Ok(())
}
