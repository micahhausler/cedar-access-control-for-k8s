use crate::admission_entities::{
    create_admission_resource_entity, create_subject_access_review, entity_id_from_request,
    request_from_review,
};
use cedar_policy::{
    Context, Entity, EntityId, EntityTypeName, EntityUid, Request, RestrictedExpression,
};
use k8s_openapi::api::authentication::v1::UserInfo;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::core::admission::{AdmissionRequest, AdmissionReview, Operation};
use kube::core::{DynamicObject, GroupVersionKind, GroupVersionResource, TypeMeta};
use serde_json::{self, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;

#[test]
fn test_create_subject_access_review() {
    struct TestCase {
        name: &'static str,
        input: AdmissionReview<DynamicObject>,
        want_err: bool,
        expected_user: Option<String>,
        expected_uid: Option<String>,
        expected_groups: Option<Vec<String>>,
        expected_extra: Option<BTreeMap<String, Vec<String>>>,
    }

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
            assert!(
                result.is_err(),
                "{}: expected error but got success",
                tc.name
            );
            continue;
        }

        let sar = result.expect(&format!("{}: unexpected error", tc.name));

        assert_eq!(
            sar.spec.user, tc.expected_user,
            "{}: user mismatch",
            tc.name
        );
        assert_eq!(sar.spec.uid, tc.expected_uid, "{}: uid mismatch", tc.name);
        assert_eq!(
            sar.spec.groups, tc.expected_groups,
            "{}: groups mismatch",
            tc.name
        );
        assert_eq!(
            sar.spec.extra, tc.expected_extra,
            "{}: extra mismatch",
            tc.name
        );
    }
}

#[test]
fn test_entity_id_from_request() {
    struct TestCase {
        name: &'static str,
        api_group: &'static str,
        api_version: &'static str,
        kind: &'static str,
        resource_name: &'static str,
        namespace: &'static str,
        sub_resource: &'static str,
        expected: String,
    }

    let test_cases = vec![
        TestCase {
            name: "core api with namespace",
            api_group: "",
            api_version: "v1",
            kind: "Pod",
            resource_name: "test-pod",
            namespace: "default",
            sub_resource: "",
            expected: "/api/v1/namespaces/default/pod/test-pod".to_string(),
        },
        TestCase {
            name: "core api without namespace",
            api_group: "",
            api_version: "v1",
            kind: "Node",
            resource_name: "test-node",
            namespace: "",
            sub_resource: "",
            expected: "/api/v1/node/test-node".to_string(),
        },
        TestCase {
            name: "api group with namespace and subresource",
            api_group: "apps",
            api_version: "v1",
            kind: "Deployment",
            resource_name: "test-deploy",
            namespace: "test-ns",
            sub_resource: "scale",
            expected: "/apis/apps/v1/namespaces/test-ns/deployment/test-deploy/scale".to_string(),
        },
        TestCase {
            name: "api group without name",
            api_group: "apps",
            api_version: "v1",
            kind: "Deployment",
            resource_name: "",
            namespace: "test-ns",
            sub_resource: "",
            expected: "/apis/apps/v1/namespaces/test-ns/deployment".to_string(),
        },
        TestCase {
            name: "core api without namespace or name",
            api_group: "",
            api_version: "v1",
            kind: "Node",
            resource_name: "",
            namespace: "",
            sub_resource: "",
            expected: "/api/v1/node".to_string(),
        },
    ];

    for tc in test_cases {
        let result = entity_id_from_request(
            tc.api_group,
            tc.api_version,
            tc.kind,
            tc.resource_name,
            tc.namespace,
            tc.sub_resource,
        );
        assert_eq!(result, tc.expected, "{}: path mismatch", tc.name);
    }
}

#[test]
fn test_create_admission_resource_entity() {
    struct TestCase {
        name: &'static str,
        review: AdmissionReview<DynamicObject>,
        expected_entity: Entity,
    }

    let test_cases = vec![TestCase {
        name: "pod with labels and annotations",
        review: AdmissionReview {
            types: TypeMeta::default(),
            request: Some(AdmissionRequest {
                uid: "test-uid".to_string(),
                name: "test-pod".to_string(),
                namespace: Some("default".to_string()),
                operation: Operation::Create,
                kind: GroupVersionKind {
                    group: "".to_string(),
                    version: "v1".to_string(),
                    kind: "Pod".to_string(),
                },
                resource: GroupVersionResource::gvr("", "v1", "pods"),
                sub_resource: None,
                user_info: UserInfo::default(),
                object: Some(DynamicObject {
                    types: Some(TypeMeta {
                        api_version: "v1".to_string(),
                        kind: "Pod".to_string(),
                    }),
                    metadata: ObjectMeta {
                        name: Some("test-pod".to_string()),
                        namespace: Some("default".to_string()),
                        labels: Some(BTreeMap::from([
                            ("app".to_string(), "test".to_string()),
                            ("environment".to_string(), "dev".to_string()),
                        ])),
                        annotations: Some(BTreeMap::from([(
                            "description".to_string(),
                            "test pod".to_string(),
                        )])),
                        ..Default::default()
                    },
                    data: json!({
                        "spec": {
                            "containers": [{
                                "name": "test-container",
                                "image": "nginx:latest",
                                "ports": [{
                                    "containerPort": 80
                                }]
                            }],
                            "nodeSelector": {
                                "disktype": "ssd"
                            }
                        }
                    }),
                }),
                old_object: None,
                options: None,
                dry_run: false,
                request_kind: None,
                request_resource: None,
                request_sub_resource: None,
                types: TypeMeta::default(),
            }),
            response: None,
        },
        expected_entity: {
            let json = r#"{
                    "uid": {
                        "type": "core::v1::Pod",
                        "id": "/api/v1/namespaces/default/pods/test-pod"
                    },
                    "attrs": {
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {
                            "name": "test-pod",
                            "namespace": "default",
                            "labels": [
                                {   
                                    "key": "app",
                                    "value": "test"
                                },
                                {
                                    "key": "environment",
                                    "value": "dev"
                                }
                            ],
                            "annotations": [
                                {
                                    "key": "description",
                                    "value": "test pod"
                                }
                            ]
                        },
                        "spec": {
                            "nodeSelector": {
                                "disktype": "ssd"
                            },
                            "containers": [
                                {
                                    "name": "test-container",
                                    "image": "nginx:latest",   
                                    "ports": [
                                        {
                                            "containerPort": 80
                                        }
                                    ]
                                }
                            ]
                        }
                    },
                    "parents": []
                }"#;
            Entity::from_json_str(json, None).unwrap()
        },
    }];

    for tc in test_cases {
        let result = create_admission_resource_entity(
            &tc.review,
            tc.review.request.as_ref().unwrap().object.as_ref().unwrap(),
        );
        assert!(
            result.is_ok(),
            "{}: failed to create entity: {:?}",
            tc.name,
            result.err()
        );

        let entity = result.unwrap();
        assert_eq!(entity, tc.expected_entity, "{}: entity mismatch", tc.name);
    }
}

#[test]
fn test_request_from_review() {
    struct TestCase {
        name: &'static str,
        review: AdmissionReview<DynamicObject>,
        expected_request: Request,
        expected_entities: Vec<Entity>,
    }

    let test_cases = vec![TestCase {
        name: "create pod",
        review: AdmissionReview {
            types: TypeMeta::default(),
            request: Some(AdmissionRequest {
                uid: "test-uid".to_string(),
                name: "test-pod".to_string(),
                namespace: Some("default".to_string()),
                operation: Operation::Create,
                kind: GroupVersionKind {
                    group: "".to_string(),
                    version: "v1".to_string(),
                    kind: "Pod".to_string(),
                },
                resource: GroupVersionResource::gvr("", "v1", "pods"),
                sub_resource: None,
                user_info: UserInfo {
                    username: Some("test-user".to_string()),
                    uid: Some("test-uid".to_string()),
                    groups: Some(vec!["system:authenticated".to_string()]),
                    extra: None,
                },
                object: Some(DynamicObject {
                    types: Some(TypeMeta {
                        api_version: "v1".to_string(),
                        kind: "Pod".to_string(),
                    }),
                    metadata: ObjectMeta {
                        name: Some("test-pod".to_string()),
                        namespace: Some("default".to_string()),
                        ..Default::default()
                    },
                    data: json!({
                        "spec": {
                            "containers": [{
                                "name": "test-container",
                                "image": "nginx:latest"
                            }]
                        }
                    }),
                }),
                old_object: None,
                options: None,
                dry_run: false,
                request_kind: None,
                request_resource: None,
                request_sub_resource: None,
                types: TypeMeta::default(),
            }),
            response: None,
        },
        expected_request: {
            let principal_uid = EntityUid::from_type_name_and_id(
                EntityTypeName::from_str("k8s::User").unwrap(),
                EntityId::from_str("test-uid").unwrap(),
            );
            let action_uid = EntityUid::from_type_name_and_id(
                EntityTypeName::from_str("k8s::admission::Action").unwrap(),
                EntityId::from_str("create").unwrap(),
            );
            let resource_uid = EntityUid::from_type_name_and_id(
                EntityTypeName::from_str("core::v1::Pod").unwrap(),
                EntityId::from_str("/api/v1/namespaces/default/pods/test-pod").unwrap(),
            );
            Request::new(
                Some(principal_uid),
                Some(action_uid),
                Some(resource_uid),
                Context::empty(),
                None,
            )
            .unwrap()
        },
        expected_entities: vec![
            // Principal entity
            {
                let uid = EntityUid::from_type_name_and_id(
                    EntityTypeName::from_str("k8s::User").unwrap(),
                    EntityId::from_str("test-uid").unwrap(),
                );
                let mut attrs = HashMap::new();
                attrs.insert(
                    "name".to_string(),
                    RestrictedExpression::new_string("test-user".to_string()),
                );
                let group_uid = EntityUid::from_type_name_and_id(
                    EntityTypeName::from_str("k8s::Group").unwrap(),
                    EntityId::from_str("system:authenticated").unwrap(),
                );
                let mut parents = HashSet::new();
                parents.insert(group_uid);
                Entity::new(uid, attrs, parents).unwrap()
            },
            // Group entity
            {
                let uid = EntityUid::from_type_name_and_id(
                    EntityTypeName::from_str("k8s::Group").unwrap(),
                    EntityId::from_str("system:authenticated").unwrap(),
                );
                let mut attrs = HashMap::new();
                attrs.insert(
                    "name".to_string(),
                    RestrictedExpression::new_string("system:authenticated".to_string()),
                );
                Entity::new(uid, attrs, Default::default()).unwrap()
            },
            // Resource entity
            {
                let uid = EntityUid::from_type_name_and_id(
                    EntityTypeName::from_str("core::v1::Pod").unwrap(),
                    EntityId::from_str("/api/v1/namespaces/default/pods/test-pod").unwrap(),
                );
                let mut attrs = HashMap::new();
                attrs.insert(
                    "apiVersion".to_string(),
                    RestrictedExpression::new_string("v1".to_string()),
                );
                attrs.insert(
                    "kind".to_string(),
                    RestrictedExpression::new_string("Pod".to_string()),
                );
                attrs.insert(
                    "metadata".to_string(),
                    RestrictedExpression::new_record(HashMap::from([
                        (
                            "name".to_string(),
                            RestrictedExpression::new_string("test-pod".to_string()),
                        ),
                        (
                            "namespace".to_string(),
                            RestrictedExpression::new_string("default".to_string()),
                        ),
                    ]))
                    .unwrap(),
                );
                attrs.insert(
                    "spec".to_string(),
                    RestrictedExpression::new_record(HashMap::from([(
                        "containers".to_string(),
                        RestrictedExpression::new_set(vec![RestrictedExpression::new_record(
                            HashMap::from([
                                (
                                    "name".to_string(),
                                    RestrictedExpression::new_string("test-container".to_string()),
                                ),
                                (
                                    "image".to_string(),
                                    RestrictedExpression::new_string("nginx:latest".to_string()),
                                ),
                            ]),
                        )
                        .unwrap()]),
                    )]))
                    .unwrap(),
                );
                Entity::new(uid, attrs, Default::default()).unwrap()
            },
        ],
    }];

    for tc in test_cases {
        let (request, entities) = request_from_review(&tc.review);

        // Verify request components
        assert_eq!(
            request.principal(),
            tc.expected_request.principal(),
            "{}: principal mismatch",
            tc.name
        );
        assert_eq!(
            request.action(),
            tc.expected_request.action(),
            "{}: action mismatch",
            tc.name
        );
        assert_eq!(
            request.resource(),
            tc.expected_request.resource(),
            "{}: resource mismatch",
            tc.name
        );

        // Convert entities to a vector for comparison
        let mut actual_entities: Vec<Entity> = entities.into_iter().collect();
        let mut expected_entities = tc.expected_entities.clone();

        // Sort both vectors by entity UID for stable comparison
        actual_entities.sort_by_key(|e| e.uid().to_string());
        expected_entities.sort_by_key(|e| e.uid().to_string());

        assert_eq!(
            actual_entities.len(),
            expected_entities.len(),
            "{}: entity count mismatch",
            tc.name
        );

        for (actual, expected) in actual_entities.iter().zip(expected_entities.iter()) {
            assert_eq!(
                actual.uid(),
                expected.uid(),
                "{}: entity UID mismatch",
                tc.name
            );
            assert_eq!(
                actual.to_string(),
                expected.to_string(),
                "{}: entity mismatch",
                tc.name
            );
        }
    }
}
