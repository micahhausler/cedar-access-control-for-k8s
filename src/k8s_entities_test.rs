use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;

use anyhow::Result;
use cedar_policy::{Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression};
use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SubjectAccessReview, SubjectAccessReviewSpec,
};

use crate::k8s_entities::{
    create_action_entity, create_entity_uid, create_user_entity, EntityType,
};

fn create_test_review(
    uid: &str,
    username: &str,
    groups: Vec<&str>,
    extra: Option<HashMap<String, Vec<String>>>,
) -> SubjectAccessReview {
    let extra = extra.map(|m| m.into_iter().collect::<BTreeMap<_, _>>());
    SubjectAccessReview {
        metadata: Default::default(),
        spec: SubjectAccessReviewSpec {
            user: Some(username.to_string()),
            uid: Some(uid.to_string()),
            groups: Some(groups.into_iter().map(String::from).collect()),
            extra,
            ..Default::default()
        },
        status: None,
    }
}

#[test]
fn test_user_entity_creation() -> Result<()> {
    struct TestCase {
        name: &'static str,
        input: SubjectAccessReview,
        expected_user: Entity,
        expected_groups: Vec<Entity>,
    }

    let test_cases = vec![
        TestCase {
            name: "regular user",
            input: create_test_review(
                "test-uid-alice",
                "alice",
                vec!["system:authenticated", "developers"],
                None,
            ),
            expected_user: Entity::new(
                create_entity_uid(EntityType::User, "test-uid-alice")?,
                HashMap::from([(
                    "name".to_string(),
                    RestrictedExpression::new_string("alice".to_string()),
                )]),
                HashSet::from([
                    create_entity_uid(EntityType::Group, "system:authenticated")?,
                    create_entity_uid(EntityType::Group, "developers")?,
                ]),
            )?,
            expected_groups: vec![
                Entity::new(
                    create_entity_uid(EntityType::Group, "system:authenticated")?,
                    HashMap::from([(
                        "name".to_string(),
                        RestrictedExpression::new_string("system:authenticated".to_string()),
                    )]),
                    HashSet::new(),
                )?,
                Entity::new(
                    create_entity_uid(EntityType::Group, "developers")?,
                    HashMap::from([(
                        "name".to_string(),
                        RestrictedExpression::new_string("developers".to_string()),
                    )]),
                    HashSet::new(),
                )?,
            ],
        },
        TestCase {
            name: "service account",
            input: create_test_review(
                "system:serviceaccount:kube-system:default",
                "system:serviceaccount:kube-system:default",
                vec!["system:serviceaccounts"],
                None,
            ),
            expected_user: Entity::new(
                create_entity_uid(
                    EntityType::ServiceAccount,
                    "system:serviceaccount:kube-system:default",
                )?,
                HashMap::from([
                    (
                        "namespace".to_string(),
                        RestrictedExpression::new_string("kube-system".to_string()),
                    ),
                    (
                        "name".to_string(),
                        RestrictedExpression::new_string("default".to_string()),
                    ),
                ]),
                HashSet::from([create_entity_uid(
                    EntityType::Group,
                    "system:serviceaccounts",
                )?]),
            )?,
            expected_groups: vec![Entity::new(
                create_entity_uid(EntityType::Group, "system:serviceaccounts")?,
                HashMap::from([(
                    "name".to_string(),
                    RestrictedExpression::new_string("system:serviceaccounts".to_string()),
                )]),
                HashSet::new(),
            )?],
        },
        TestCase {
            name: "node",
            input: create_test_review(
                "system:node:worker-1",
                "system:node:worker-1",
                vec!["system:nodes"],
                None,
            ),
            expected_user: Entity::new(
                create_entity_uid(EntityType::Node, "system:node:worker-1")?,
                HashMap::from([(
                    "name".to_string(),
                    RestrictedExpression::new_string("worker-1".to_string()),
                )]),
                HashSet::from([create_entity_uid(EntityType::Group, "system:nodes")?]),
            )?,
            expected_groups: vec![Entity::new(
                create_entity_uid(EntityType::Group, "system:nodes")?,
                HashMap::from([(
                    "name".to_string(),
                    RestrictedExpression::new_string("system:nodes".to_string()),
                )]),
                HashSet::new(),
            )?],
        },
        TestCase {
            name: "user with extra fields",
            input: {
                let mut extra = HashMap::new();
                extra.insert(
                    "authentication.kubernetes.io/claims".to_string(),
                    vec!["group1".to_string(), "group2".to_string()],
                );
                create_test_review("test-uid-bob", "bob", vec![], Some(extra))
            },
            expected_user: {
                let mut attrs = HashMap::new();
                attrs.insert(
                    "name".to_string(),
                    RestrictedExpression::new_string("bob".to_string()),
                );

                let extra_values = vec![RestrictedExpression::new_record(HashMap::from([
                    (
                        "key".to_string(),
                        RestrictedExpression::new_string(
                            "authentication.kubernetes.io/claims".to_string(),
                        ),
                    ),
                    (
                        "values".to_string(),
                        RestrictedExpression::new_string("group1,group2".to_string()),
                    ),
                ]))
                .unwrap()];
                attrs.insert(
                    "extra".to_string(),
                    RestrictedExpression::new_set(extra_values),
                );

                Entity::new(
                    create_entity_uid(EntityType::User, "test-uid-bob")?,
                    attrs,
                    HashSet::new(),
                )?
            },
            expected_groups: vec![],
        },
    ];

    for tc in test_cases {
        let (user, groups) = create_user_entity(&tc.input)?;
        assert_eq!(user, tc.expected_user, "test case: {}", tc.name);
        assert_eq!(groups, tc.expected_groups, "test case: {}", tc.name);
    }

    Ok(())
}

#[test]
fn test_action_entity_creation() -> Result<()> {
    struct TestCase {
        name: &'static str,
        input: SubjectAccessReview,
        expected_action: Entity,
    }

    let test_cases = vec![
        TestCase {
            name: "get pods",
            input: SubjectAccessReview {
                metadata: Default::default(),
                spec: SubjectAccessReviewSpec {
                    resource_attributes: Some(ResourceAttributes {
                        verb: Some("get".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                status: None,
            },
            expected_action: Entity::new(
                EntityUid::from_type_name_and_id(
                    EntityTypeName::from_str("k8s::Action")?,
                    EntityId::from_str("get")?,
                ),
                HashMap::new(),
                HashSet::new(),
            )?,
        },
        TestCase {
            name: "list pods",
            input: SubjectAccessReview {
                metadata: Default::default(),
                spec: SubjectAccessReviewSpec {
                    resource_attributes: Some(ResourceAttributes {
                        verb: Some("list".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                status: None,
            },
            expected_action: Entity::new(
                EntityUid::from_type_name_and_id(
                    EntityTypeName::from_str("k8s::Action")?,
                    EntityId::from_str("list")?,
                ),
                HashMap::new(),
                HashSet::new(),
            )?,
        },
        TestCase {
            name: "unknown action",
            input: SubjectAccessReview {
                metadata: Default::default(),
                spec: SubjectAccessReviewSpec {
                    resource_attributes: None,
                    ..Default::default()
                },
                status: None,
            },
            expected_action: Entity::new(
                EntityUid::from_type_name_and_id(
                    EntityTypeName::from_str("k8s::Action")?,
                    EntityId::from_str("unknown")?,
                ),
                HashMap::new(),
                HashSet::new(),
            )?,
        },
    ];

    for tc in test_cases {
        let action = create_action_entity(&tc.input)?;
        assert_eq!(action, tc.expected_action, "test case: {}", tc.name);
    }

    Ok(())
}
