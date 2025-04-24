use std::collections::HashMap;

use crate::schema::{
    doc_annotation, CedarSchema, CedarSchemaNamespace, 
    Entity, EntityAttribute, EntityAttributeElement, EntityShape,
    ActionShape, ActionAppliesTo, ActionMember,
    ALL_ACTIONS, ACTION_IMPERSONATE, ACTION_CREATE, ACTION_UPDATE,
    ACTION_DELETECOLLECTION, ACTION_USE, ACTION_BIND, ACTION_APPROVE, ACTION_SIGN, 
    ACTION_ESCALATE, ACTION_ATTEST, ACTION_PUT, ACTION_POST, ACTION_HEAD, ACTION_OPTIONS, 
    ACTION_LIST, ACTION_WATCH, ACTION_ALL,
    ACTION_DELETE, ACTION_CONNECT,
    RECORD_TYPE, SET_TYPE, STRING_TYPE, BOOL_TYPE,

};

const USER_TYPE: &str = "User";
const GROUP_TYPE: &str = "Group";
const SERVICE_ACCOUNT_TYPE: &str = "ServiceAccount";
const NODE_TYPE: &str = "Node";
const EXTRA_TYPE: &str = "Extra";
const EXTRA_VALUES_ATTRIBUTE_TYPE: &str = "ExtraAttribute";

const PRINCIPAL_UID_TYPE: &str = "PrincipalUID";
const NON_RESOURCE_URL_TYPE: &str = "NonResourceURL";
const RESOURCE_TYPE: &str = "Resource";
const FIELD_REQUIREMENT_TYPE: &str = "FieldRequirement";
const LABEL_REQUIREMENT_TYPE: &str = "LabelRequirement";



pub fn k8s_schema(namespace: &str) -> CedarSchema {
    let mut entities = get_k8s_entity_types();
    get_k8s_resource_types().into_iter().for_each(|(k, v)| {
        entities.insert(k, v);
    });

    let mut schema = HashMap::from([(
        namespace.to_string(),      
        CedarSchemaNamespace {
            annotations: None,
            entity_types: entities,
            actions: get_authorization_actions(namespace, namespace, namespace),
            common_types: Some(get_k8s_common_entity_types()),
        },
    )]);

    add_connect_entities(&mut schema);

    schema
}


pub fn get_authorization_actions(principal_ns: &str, entity_ns: &str, action_ns: &str) -> HashMap<String, ActionShape> {
    let mut actions = HashMap::new();

    let non_resource_only_actions = vec![
        ACTION_PUT,
        ACTION_POST,
        ACTION_HEAD,
        ACTION_OPTIONS,
    ];

    let resource_only_actions = vec![   
        ACTION_LIST,
        ACTION_WATCH,
        ACTION_CREATE,
        ACTION_UPDATE,
        ACTION_DELETECOLLECTION,
        ACTION_USE,
        ACTION_BIND,
        ACTION_APPROVE,
        ACTION_SIGN,
        ACTION_ESCALATE,
        ACTION_ATTEST,
    ];

    let principal_prefix = if principal_ns == action_ns { "".to_string() } else { format!("{}::", principal_ns) };
    let entity_prefix = if entity_ns == action_ns { "".to_string() } else { format!("{}::", entity_ns) };

    let principal_types = get_authz_principal_type_names("");
    for action in ALL_ACTIONS {
        if *action == ACTION_IMPERSONATE {
            continue;
        }

        let resource_types = match *action {
            r if non_resource_only_actions.contains(&r) => vec![entity_prefix.clone() + NON_RESOURCE_URL_TYPE],
            r if resource_only_actions.contains(&r) => vec![entity_prefix.clone() + RESOURCE_TYPE],
            _ => vec![entity_prefix.clone() + NON_RESOURCE_URL_TYPE,entity_prefix.clone() + RESOURCE_TYPE],
        };

        actions.insert(action.to_string(), ActionShape {
            annotations: None,
            applies_to: ActionAppliesTo {
                principal_types: principal_types.clone(),
                resource_types: resource_types.clone(),
                context: None,
            },
            member_of: None,
        });        
    }
    actions.insert(ACTION_IMPERSONATE.to_string(), ActionShape {
        annotations: None,
        applies_to: ActionAppliesTo {
            principal_types: principal_types.clone(),
            resource_types: vec![
                principal_prefix.clone() + EXTRA_TYPE,
                principal_prefix.clone() + GROUP_TYPE,
                principal_prefix.clone() + NODE_TYPE,
                principal_prefix.clone() + PRINCIPAL_UID_TYPE,
                principal_prefix.clone() + SERVICE_ACCOUNT_TYPE,
                principal_prefix.clone() + USER_TYPE,
            ],
            context: None,
        },
        member_of: None,
    });

    actions
}

pub fn get_k8s_common_entity_types() -> HashMap<String, EntityShape> {
    HashMap::from([
        (
            EXTRA_VALUES_ATTRIBUTE_TYPE.to_string(),
            EntityShape {
                annotations: Some(doc_annotation("ExtraAttribute represents a set of key-value pairs for an identity")),
                type_name: RECORD_TYPE.to_string(),
                attributes: HashMap::from([
                    (
                        "key".to_string(),
                        EntityAttribute {
                            annotations: None,
                            type_name: STRING_TYPE.to_string(),
                            name: None,
                            required: true,
                            element: None,
                            attributes: None,
                        },
                    ),
                    (
                        "values".to_string(),
                        EntityAttribute {
                            annotations: None,
                            type_name: SET_TYPE.to_string(),
                            name: None,
                            required: true,
                            element: Some(Box::new(EntityAttributeElement {
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                            })),
                            attributes: None,
                        },
                    ),
                ]),
            },
        ),
        (
            FIELD_REQUIREMENT_TYPE.to_string(),
            EntityShape {
                annotations: Some(doc_annotation("FieldRequirement represents a requirement on a field")),
                type_name: RECORD_TYPE.to_string(),
                attributes: HashMap::from([
                    (
                        "field".to_string(),
                        EntityAttribute {
                            annotations: None,
                            type_name: STRING_TYPE.to_string(),
                            name: None,
                            required: true,
                            element: None,
                            attributes: None,
                        },
                    ),
                    (
                        "operator".to_string(),
                        EntityAttribute {
                            annotations: None,
                            type_name: STRING_TYPE.to_string(),
                            name: None,
                            required: true,
                            element: None,
                            attributes: None,
                        },
                    ),
                    (
                        "value".to_string(),
                        EntityAttribute {
                            annotations: None,
                            type_name: STRING_TYPE.to_string(),
                            name: None,
                            required: true,
                            element: None,
                            attributes: None,
                        },
                    ),
                ]),
            },
        ),
        (
            LABEL_REQUIREMENT_TYPE.to_string(),
            EntityShape {
                annotations: Some(doc_annotation("LabelRequirement represents a requirement on a label")),
                type_name: RECORD_TYPE.to_string(),
                attributes: HashMap::from([
                    (
                        "key".to_string(),
                        EntityAttribute {
                            annotations: None,
                            type_name: STRING_TYPE.to_string(),
                            name: None,
                            required: true,
                            element: None,
                            attributes: None,
                        },
                    ),
                    (
                        "operator".to_string(),
                        EntityAttribute {
                            annotations: None,
                            type_name: STRING_TYPE.to_string(),
                            name: None,
                            required: true,
                            element: None,
                            attributes: None,
                        },
                    ),
                    (
                        "values".to_string(),
                        EntityAttribute {
                            annotations: None,
                            type_name: SET_TYPE.to_string(),
                            name: None,
                            required: true,
                            element: Some(Box::new(EntityAttributeElement {
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                            })),
                            attributes: None,
                        },
                    ),  
                ]),
            },
        ),  
    ])
}   

pub fn get_k8s_resource_types() -> HashMap<String, Entity> {
    HashMap::from([
        (
            PRINCIPAL_UID_TYPE.to_string(),
            Entity {
                annotations: Some(doc_annotation("PrincipalUID represents an impersonatable identifier for a principal")),
                member_of_types: None,
                shape: EntityShape {
                    annotations: None,
                    type_name: RECORD_TYPE.to_string(),
                    attributes: HashMap::new(),
                },
            },
        ),
        (
            NON_RESOURCE_URL_TYPE.to_string(),
            Entity {
                annotations: Some(doc_annotation("NonResourceURL represents a URL that is not associated with a Kubernetes resource")),
                member_of_types: None,
                shape: EntityShape {
                    annotations: None,
                    type_name: RECORD_TYPE.to_string(),
                    attributes: HashMap::from([
                        (
                            "path".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                                required: true,
                                element: None,
                                attributes: None,
                            },
                        ),
                    ]),
                },
            },
        ),
        (
            RESOURCE_TYPE.to_string(),
            Entity {
                annotations: Some(doc_annotation("Resource represents an authorizable Kubernetes resource")),
                member_of_types: None,
                shape: EntityShape {
                    annotations: None,
                    type_name: RECORD_TYPE.to_string(),
                    attributes: HashMap::from([
                        (
                            "apiGroup".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                                required: true,
                                element: None,
                                attributes: None,
                            },
                        ),
                        (
                            "resource".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                                required: true,
                                element: None,
                                attributes: None,
                            },
                        ),
                        (
                            "namespace".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                                required: false,
                                element: None,
                                attributes: None,
                            },
                        ),
                        (
                            "name".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                                required: false,
                                element: None,
                                attributes: None,
                            },
                        ),
                        (
                            "subresource".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                                required: false,
                                element: None,
                                attributes: None,
                            },
                        ),
                        (
                            "fieldSelector".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: SET_TYPE.to_string(),
                                name: None,
                                required: false,
                                element: Some(Box::new(EntityAttributeElement {
                                    type_name: FIELD_REQUIREMENT_TYPE.to_string(),
                                    name: None,
                                })),
                                attributes: None,
                            },
                        ),
                        (
                            "labelSelector".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: SET_TYPE.to_string(),
                                name: None,
                                required: false,
                                element: Some(Box::new(EntityAttributeElement {
                                    type_name: LABEL_REQUIREMENT_TYPE.to_string(),
                                    name: None,
                                })),
                                attributes: None,
                            },
                        ),
                        
                    ]),
                },
            },
        ),
    ])
}

pub fn get_authz_principal_type_names(namespace: &str) -> Vec<String> {
    let type_names = vec![
        GROUP_TYPE.to_string(),
        NODE_TYPE.to_string(),
        SERVICE_ACCOUNT_TYPE.to_string(),
        USER_TYPE.to_string(),
    ];

    if namespace == "" {
        type_names
    } else {
        type_names.iter().map(|name| format!("{}::{}", namespace, name)).collect()
    }
}

pub fn get_k8s_entity_types() -> HashMap<String, Entity> {
    let extra_attribute = EntityAttribute {
        annotations: None,
        type_name: SET_TYPE.to_string(),
        name: None,
        required: false,
        element: Some(Box::new(EntityAttributeElement {
            type_name: EXTRA_VALUES_ATTRIBUTE_TYPE.to_string(),
            name: None,
        })),
        attributes: None,
    };

    HashMap::from([
        (
            USER_TYPE.to_string(),
            Entity {
                annotations: Some(doc_annotation("User represents a Kubernetes user identity")),
                member_of_types: Some(vec![GROUP_TYPE.to_string()]),
                shape: EntityShape {
                    annotations: None,
                    type_name: RECORD_TYPE.to_string(),
                    attributes: HashMap::from([
                        (
                            "name".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                                required: true,
                                element: None,
                                attributes: None,
                            },
                        ),
                        ("extra".to_string(), extra_attribute.clone()),
                    ]),
                },
            },
        ),
        (
            GROUP_TYPE.to_string(),
            Entity {
                annotations: Some(doc_annotation("Group represents a Kubernetes group")),
                member_of_types: None,
                shape: EntityShape {
                    annotations: None,
                    type_name: RECORD_TYPE.to_string(),
                    attributes: HashMap::from([(
                        "name".to_string(),
                        EntityAttribute {
                            annotations: None,
                            type_name: STRING_TYPE.to_string(),
                            name: None,
                            required: true,
                            element: None,
                            attributes: None,
                        },
                    )]),
                },
            },
        ),
        (
            SERVICE_ACCOUNT_TYPE.to_string(),
            Entity {
                annotations: Some(doc_annotation(
                    "ServiceAccount represents a Kubernetes service account identity",
                )),
                member_of_types: Some(vec![GROUP_TYPE.to_string()]),
                shape: EntityShape {
                    annotations: None,
                    type_name: RECORD_TYPE.to_string(),
                    attributes: HashMap::from([
                        (
                            "name".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                                required: true,
                                element: None,
                                attributes: None,
                            },
                        ),
                        (
                            "namespace".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                                required: true,
                                element: None,
                                attributes: None,
                            },
                        ),
                        ("extra".to_string(), extra_attribute.clone()),
                    ]),
                },
            },
        ),
        (
            NODE_TYPE.to_string(),
            Entity {
                annotations: Some(doc_annotation("Node represents a Kubernetes node identity")),
                member_of_types: Some(vec![GROUP_TYPE.to_string()]),
                shape: EntityShape {
                    annotations: None,
                    type_name: RECORD_TYPE.to_string(),
                    attributes: HashMap::from([
                        (
                            "name".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                                required: true,
                                element: None,
                                attributes: None,
                            },
                        ),
                        ("extra".to_string(), extra_attribute.clone()),
                    ]),
                },
            },
        ),
        (
            EXTRA_TYPE.to_string(),
            Entity {
                annotations: Some(doc_annotation(
                    "Extra represents a set of key-value pairs for an identity",
                )),
                member_of_types: None,
                shape: EntityShape {
                    annotations: None,
                    type_name: RECORD_TYPE.to_string(),
                    attributes: HashMap::from([
                        (
                            "key".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                                required: true,
                                element: None,
                                attributes: None,
                            },
                        ),
                        (
                            "value".to_string(),
                            EntityAttribute {
                                annotations: None,
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                                required: false,
                                element: None,
                                attributes: None,
                            },
                        ),
                    ]),
                },
            },
        ),
    ])
}

fn proxy_option_entity_shape() -> EntityShape {
    EntityShape {
        annotations: None,
        type_name: RECORD_TYPE.to_string(),
        attributes: HashMap::from([
            (
                "kind".to_string(),
                EntityAttribute {
                    annotations: None,
                    type_name: STRING_TYPE.to_string(),
                    name: None,
                    required: true,
                    element: None,
                    attributes: None,
                },
            ),
            (
                "apiVersion".to_string(),
                EntityAttribute {
                    annotations: None,
                    type_name: STRING_TYPE.to_string(),
                    name: None,
                    required: true,
                    element: None,
                    attributes: None,
                },
            ),
            (
                "path".to_string(),
                EntityAttribute {
                    annotations: None,
                    type_name: STRING_TYPE.to_string(),
                    name: None,
                    required: true,
                    element: None,
                    attributes: None,
                },
            ),
        ]),
    }
}

fn node_proxy_options() -> Entity {
    Entity {
        annotations: Some(doc_annotation("NodeProxyOptions represents options for proxying to a Kubernetes node")),
        member_of_types: None,
        shape: proxy_option_entity_shape(),
    }
}

fn service_proxy_options() -> Entity {
    Entity {
        annotations: Some(doc_annotation("ServiceProxyOptions represents options for proxying to a Kubernetes service")),
        member_of_types: None,
        shape: proxy_option_entity_shape(),
    }
}

fn pod_proxy_options() -> Entity {
    Entity {
        annotations: Some(doc_annotation("PodProxyOptions represents options for proxying to a Kubernetes pod")),
        member_of_types: None,
        shape: proxy_option_entity_shape(),
    }
}

fn pod_port_forward_options() -> Entity {
    Entity {
        annotations: Some(doc_annotation("PodPortForwardOptions represents options for port forwarding to a Kubernetes pod")),
        member_of_types: None,
        shape: EntityShape {
            annotations: None,
            type_name: RECORD_TYPE.to_string(),
            attributes: HashMap::from([
                (
                    "kind".to_string(),
                    EntityAttribute {
                        annotations: None,
                        type_name: STRING_TYPE.to_string(),
                        name: None,
                        required: true,
                        element: None,
                        attributes: None,
                    },
                ),
                (
                    "apiVersion".to_string(),
                    EntityAttribute {
                        annotations: None,
                        type_name: STRING_TYPE.to_string(),
                        name: None,
                        required: true,
                        element: None,
                        attributes: None,
                    },
                ),
                (
                    "ports".to_string(),
                    EntityAttribute {
                        annotations: None,
                        type_name: SET_TYPE.to_string(),
                        name: None,
                        required: false,
                        element: Some(Box::new(EntityAttributeElement {
                            type_name: STRING_TYPE.to_string(),
                            name: None,
                        })),
                        attributes: None,
                    },
                ),
            ]),
        },
    }
}

fn pod_exec_attach_entity_shape() -> EntityShape {
    EntityShape {
        annotations: None,
        type_name: RECORD_TYPE.to_string(),
        attributes: HashMap::from([
            (
                "kind".to_string(),
                EntityAttribute {
                    annotations: None,
                    type_name: STRING_TYPE.to_string(),
                    name: None,
                    required: true,
                    element: None,
                    attributes: None,
                },
            ),
            (
                "apiVersion".to_string(),
                EntityAttribute {
                    annotations: None,
                    type_name: STRING_TYPE.to_string(),
                    name: None,
                    required: true,
                    element: None,
                    attributes: None,
                },
            ),
            (
                "stdin".to_string(),
                EntityAttribute {
                    annotations: None,
                    type_name: BOOL_TYPE.to_string(),
                    name: None,
                    required: true,
                    element: None,
                    attributes: None,
                },
            ),
            (
                "stdout".to_string(),
                EntityAttribute {
                    annotations: None,
                    type_name: BOOL_TYPE.to_string(),
                    name: None,
                    required: true,
                    element: None,
                    attributes: None,
                },
            ),
            (
                "stderr".to_string(),
                EntityAttribute {
                    annotations: None,
                    type_name: BOOL_TYPE.to_string(),
                    name: None,
                    required: true,
                    element: None,
                    attributes: None,
                },
            ),
            (
                "tty".to_string(),
                EntityAttribute {
                    annotations: None,
                    type_name: BOOL_TYPE.to_string(),
                    name: None,
                    required: true,
                    element: None,
                    attributes: None,
                },
            ),
            (
                "container".to_string(),
                EntityAttribute {
                    annotations: None,
                    type_name: STRING_TYPE.to_string(),
                    name: None,
                    required: true,
                    element: None,
                    attributes: None,
                },
            ),
            (
                "command".to_string(),
                EntityAttribute {
                    annotations: None,
                    type_name: SET_TYPE.to_string(),
                    name: None,
                    required: true,
                    element: Some(Box::new(EntityAttributeElement {
                        type_name: STRING_TYPE.to_string(),
                        name: None,
                    })),
                    attributes: None,
                },
            ),
        ]),
    }
}

fn pod_exec_options() -> Entity {
    Entity {
        annotations: Some(doc_annotation("PodExecOptions represents options for executing a command in a Kubernetes pod")),
        member_of_types: None,
        shape: pod_exec_attach_entity_shape(),
    }
}

fn pod_attach_options() -> Entity {
    Entity {
        annotations: Some(doc_annotation("PodAttachOptions represents options for attaching to a Kubernetes pod")),
        member_of_types: None,
        shape: pod_exec_attach_entity_shape(),
    }
}

pub fn add_connect_entities(schema: &mut CedarSchema) {
    let core_ns_name = "core::v1";
    let core_v1_ns = schema.entry(core_ns_name.to_string())
        .or_insert_with(|| CedarSchemaNamespace {
            annotations: None,
            entity_types: HashMap::new(),
            actions: HashMap::new(),
            common_types: None,
        });

    let entity_types = &mut core_v1_ns.entity_types;
    entity_types.insert("NodeProxyOptions".to_string(), node_proxy_options());
    entity_types.insert("PodProxyOptions".to_string(), pod_proxy_options());
    entity_types.insert("PodPortForwardOptions".to_string(), pod_port_forward_options());
    entity_types.insert("PodExecOptions".to_string(), pod_exec_options());
    entity_types.insert("PodAttachOptions".to_string(), pod_attach_options());
    entity_types.insert("ServiceProxyOptions".to_string(), service_proxy_options());

    let admission_ns = schema.entry("k8s::admission".to_string())
        .or_insert_with(|| CedarSchemaNamespace {
            annotations: None,
            entity_types: HashMap::new(),
            actions: HashMap::new(),
            common_types: None,
        });

    let actions = &mut admission_ns.actions;
    actions.insert(ACTION_CONNECT.to_string(), ActionShape {
        annotations: None,
        applies_to: ActionAppliesTo {
            principal_types: get_authz_principal_type_names("k8s"),
            resource_types: vec![
                format!("{}::NodeProxyOptions", core_ns_name),
                format!("{}::PodAttachOptions", core_ns_name),
                format!("{}::PodExecOptions", core_ns_name),
                format!("{}::PodPortForwardOptions", core_ns_name),
                format!("{}::PodProxyOptions", core_ns_name),
                format!("{}::ServiceProxyOptions", core_ns_name),
            ],
            context: None,
        },
        member_of: Some(vec![ActionMember { id: ACTION_ALL.to_string() }]),
    });
    actions.insert(ACTION_DELETE.to_string(), ActionShape {
        annotations: None,
        applies_to: ActionAppliesTo {
            principal_types: get_authz_principal_type_names("k8s"),
            resource_types: vec![],
            context: None,
        },
        member_of: Some(vec![ActionMember { id: ACTION_ALL.to_string() }]),
    });
    actions.insert(ACTION_UPDATE.to_string(), ActionShape {
        annotations: None,
        applies_to: ActionAppliesTo {
            principal_types: get_authz_principal_type_names("k8s"),
            resource_types: vec![],
            context: None,
        },
        member_of: Some(vec![ActionMember { id: ACTION_ALL.to_string() }]),
    }); 
    actions.insert(ACTION_CREATE.to_string(), ActionShape {
        annotations: None,
        applies_to: ActionAppliesTo {
            principal_types: get_authz_principal_type_names("k8s"),
            resource_types: vec![],
            context: None,
        },
        member_of: Some(vec![ActionMember { id: ACTION_ALL.to_string() }]),
    });
    actions.insert(ACTION_ALL.to_string(), ActionShape {
        annotations: None,
        applies_to: ActionAppliesTo {
            principal_types: get_authz_principal_type_names("k8s"),
            resource_types: vec![],
            context: None,
        },
        member_of: None,
    });
}

