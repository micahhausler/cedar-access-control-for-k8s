use cedar_k8s_webhook::schema::{
    self, ActionAppliesTo, ActionShape, CedarSchema, CedarSchemaNamespace, Entity, EntityAttribute,
    EntityShape, SchemaSorting, BOOL_TYPE, ENTITY_TYPE, RECORD_TYPE, STRING_TYPE,
};
use std::collections::HashMap;

fn main() {
    // Create a new Cedar schema
    let mut schema = schema::new_cedar_schema();

    // Create a namespace for our example
    let mut namespace = CedarSchemaNamespace {
        annotations: Some(schema::doc_annotation("PhotoFlash application schema")),
        entity_types: HashMap::new(),
        actions: HashMap::new(),
        common_types: None,
    };

    // Create a User entity type
    let user_entity = Entity {
        annotations: None,
        member_of_types: Some(vec!["UserGroup".to_string()]),
        shape: EntityShape {
            annotations: None,
            type_name: RECORD_TYPE.to_string(),
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert(
                    "department".to_string(),
                    EntityAttribute {
                        annotations: None,
                        type_name: STRING_TYPE.to_string(),
                        name: None,
                        required: true,
                        element: None,
                        attributes: None,
                    },
                );
                attrs.insert(
                    "jobLevel".to_string(),
                    EntityAttribute {
                        annotations: None,
                        type_name: schema::LONG_TYPE.to_string(),
                        name: None,
                        required: true,
                        element: None,
                        attributes: None,
                    },
                );
                attrs
            },
        },
    };

    // Create a Photo entity type
    let photo_entity = Entity {
        annotations: None,
        member_of_types: Some(vec!["Album".to_string()]),
        shape: EntityShape {
            annotations: None,
            type_name: RECORD_TYPE.to_string(),
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert(
                    "private".to_string(),
                    EntityAttribute {
                        annotations: None,
                        type_name: BOOL_TYPE.to_string(),
                        name: None,
                        required: true,
                        element: None,
                        attributes: None,
                    },
                );
                attrs.insert(
                    "account".to_string(),
                    EntityAttribute {
                        annotations: None,
                        type_name: ENTITY_TYPE.to_string(),
                        name: Some("Account".to_string()),
                        required: true,
                        element: None,
                        attributes: None,
                    },
                );
                attrs
            },
        },
    };

    // Create a UserGroup entity type (empty)
    let user_group_entity = Entity {
        annotations: None,
        member_of_types: None,
        shape: EntityShape {
            annotations: None,
            type_name: RECORD_TYPE.to_string(),
            attributes: HashMap::new(),
        },
    };

    // Add entities to the namespace
    namespace.entity_types.insert("User".to_string(), user_entity);
    namespace.entity_types.insert("Photo".to_string(), photo_entity);
    namespace.entity_types.insert("UserGroup".to_string(), user_group_entity);

    // Create a viewPhoto action
    let view_photo_action = ActionShape {
        annotations: None,
        applies_to: ActionAppliesTo {
            principal_types: vec!["User".to_string()],
            resource_types: vec!["Photo".to_string()],
            context: Some(EntityShape {
                annotations: None,
                type_name: RECORD_TYPE.to_string(),
                attributes: {
                    let mut attrs = HashMap::new();
                    attrs.insert(
                        "authenticated".to_string(),
                        EntityAttribute {
                            annotations: None,
                            type_name: BOOL_TYPE.to_string(),
                            name: None,
                            required: true,
                            element: None,
                            attributes: None,
                        },
                    );
                    attrs
                },
            }),
        },
        member_of: None,
    };

    // Add action to the namespace
    namespace.actions.insert("viewPhoto".to_string(), view_photo_action);

    // Add namespace to the schema
    schema.insert("PhotoFlash".to_string(), namespace);

    // Sort action entities
    schema.sort_action_entities();

    // Serialize the schema to JSON
    let json = serde_json::to_string_pretty(&schema).unwrap();
    println!("{}", json);
} 