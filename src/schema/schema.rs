use std::collections::HashMap;
use crate::schema::types::{CedarSchema, CedarSchemaNamespace, ActionShape, ActionAppliesTo, new_cedar_schema, doc_annotation, Entity, EntityShape};


// Authorization action constants
pub const ACTION_GET: &str = "get";
pub const ACTION_LIST: &str = "list";
pub const ACTION_WATCH: &str = "watch";
pub const ACTION_CREATE: &str = "create";
pub const ACTION_UPDATE: &str = "update";
pub const ACTION_PATCH: &str = "patch";
pub const ACTION_DELETE: &str = "delete";
pub const ACTION_DELETECOLLECTION: &str = "deletecollection";
pub const ACTION_USE: &str = "use";
pub const ACTION_BIND: &str = "bind";
pub const ACTION_IMPERSONATE: &str = "impersonate";
pub const ACTION_APPROVE: &str = "approve";
pub const ACTION_SIGN: &str = "sign";
pub const ACTION_ESCALATE: &str = "escalate";
pub const ACTION_ATTEST: &str = "attest";
pub const ACTION_PUT: &str = "put";
pub const ACTION_POST: &str = "post";
pub const ACTION_HEAD: &str = "head";
pub const ACTION_OPTIONS: &str = "options";
pub const ACTION_CONNECT: &str = "connect";
pub const ACTION_ALL: &str = "all";


// All Cedar Authorization Actions
pub const ALL_ACTIONS: &[&str] = &[
    ACTION_GET,
    ACTION_LIST,
    ACTION_WATCH,
    ACTION_CREATE,
    ACTION_UPDATE,
    ACTION_PATCH,
    ACTION_DELETE,
    ACTION_DELETECOLLECTION,
    ACTION_USE,
    ACTION_BIND,
    ACTION_IMPERSONATE,
    ACTION_APPROVE,
    ACTION_SIGN,
    ACTION_ESCALATE,
    ACTION_ATTEST,
    ACTION_PUT,
    ACTION_POST,
    ACTION_HEAD,
    ACTION_OPTIONS,
    // ACTION_CONNECT,
];

pub const ADMISSION_ACTIONS: &[&str] = &[
    ACTION_CREATE,
    ACTION_UPDATE,
    // ACTION_PATCH,
    ACTION_DELETE,
    // ACTION_DELETECOLLECTION,
    ACTION_CONNECT,
];


pub fn sort_action_entities(schema: &mut CedarSchema) {
    let cloned_schema = schema.clone();
    for (namespace, ns) in cloned_schema.iter() {
        let mut cloned_ns = ns.clone();
        let action_keys = cloned_ns.actions.keys().collect::<Vec<&String>>();

        let mut sorted_actions = HashMap::new();

        for key in action_keys {
            let mut sorted_principal_types = cloned_ns.actions.get(key).unwrap().applies_to.principal_types.clone();            
            sorted_principal_types.sort();
            let mut sorted_resource_types = cloned_ns.actions.get(key).unwrap().applies_to.resource_types.clone();
            sorted_resource_types.sort();
            sorted_actions.insert(key.clone(), ActionShape {
                annotations: cloned_ns.actions.get(key).unwrap().annotations.clone(),
                applies_to: ActionAppliesTo {
                    principal_types: sorted_principal_types,
                    resource_types: sorted_resource_types,
                    context: cloned_ns.actions.get(key).unwrap().applies_to.context.clone(),
                },
                member_of: cloned_ns.actions.get(key).unwrap().member_of.clone(),
            });
        }
        cloned_ns.actions = sorted_actions;
        schema.insert(namespace.clone(), cloned_ns);
    }
}


/// Creates a new Cedar schema with standard Kubernetes actions.
/// 
/// Returns a schema with all the standard actions defined in ALL_ACTIONS,
/// set up with empty principal and resource types. These will need to be
/// populated based on the specific resources and principals in your application.
///
/// # Examples
///
/// ```
/// use crate::schema::new_schema_with_actions;
///
/// let schema = new_schema_with_actions("k8s", "Standard Kubernetes actions");
/// ```
pub fn new_schema_with_actions(namespace: &str, docs: &str) -> CedarSchema {
    let mut schema = new_cedar_schema();
    
    // Create namespace with annotations
    let mut ns = CedarSchemaNamespace {
        annotations: Some(doc_annotation(docs)),
        entity_types: HashMap::new(),
        actions: HashMap::new(),
        common_types: None,
    };
    
    // Add all actions to the namespace
    for &action_name in ALL_ACTIONS {
        let action = ActionShape {
            annotations: Some(doc_annotation(&format!("Action: {}", action_name))),
            applies_to: ActionAppliesTo::new(),
            member_of: None,
        };
        
        ns.actions.insert(action_name.to_string(), action);
    }
    
    // Add the namespace to the schema
    schema.insert(namespace.to_string(), ns);
    
    schema
}

/// Adds an entity to a schema namespace.
///
/// # Parameters
/// * `schema` - The Cedar schema to modify
/// * `namespace` - The namespace to add the entity to
/// * `entity_name` - The name of the entity to add
/// * `entity` - The entity to add
///
/// # Returns
/// The modified schema
///
/// # Examples
/// ```
/// use crate::schema::{new_schema_with_actions, add_entity_to_schema};
/// use crate::schema::types::{Entity, EntityShape};
///
/// let mut schema = new_schema_with_actions("k8s", "Kubernetes actions");
/// let entity = Entity { /* ... */ };
/// 
/// // Add entity to the schema
/// schema = add_entity_to_schema(schema, "k8s", "Pod", entity);
/// ```
pub fn add_entity_to_schema(
    mut schema: CedarSchema,
    namespace: &str, 
    entity_name: &str,
    entity: Entity,
) -> Result<CedarSchema, String> {
    // Add entity to the namespace
    if let Some(ns) = schema.get_mut(namespace) {
        // Check if entity already exists in common types
        if let Some(common_types) = &ns.common_types {
            if common_types.contains_key(entity_name) {
                return Err(format!("Entity {} already exists in common types", entity_name));
            }
        }
        if ns.entity_types.contains_key(entity_name) {
            return Err(format!("Entity {} already exists in entity types", entity_name));
        }

        if ns.entity_types.is_empty() {
            ns.entity_types = HashMap::new();
        }
        ns.entity_types.insert(entity_name.to_string(), entity);
        return Ok(schema);
    }
    Err(format!("Namespace {} not found in schema", namespace))
}


/// Adds a common type to a schema namespace.
///
/// # Parameters
/// * `schema` - The Cedar schema to modify
/// * `namespace` - The namespace to add the common type to
/// * `common_type_name` - The name of the common type to add   
/// * `common_type` - The common type to add
///
/// # Returns
/// The modified schema
pub fn add_common_type_to_schema(
    mut schema: CedarSchema,
    namespace: &str,
    common_type_name: &str,
    common_type: EntityShape,
) -> Result<CedarSchema, String> {  
    if let Some(ns) = schema.get_mut(namespace) {
        // Check if common type name exists as an entity
        if ns.entity_types.contains_key(common_type_name) {
            return Err(format!("Common type {} already exists as an entity", common_type_name));
        }
        if ns.common_types.is_none() {
            ns.common_types = Some(HashMap::new());
        }
        if let Some(common_types) = &mut ns.common_types {
            common_types.insert(common_type_name.to_string(), common_type);
            return Ok(schema);
        }
    }
    Err(format!("Namespace {} not found in schema", namespace))
} 





#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_new_schema_with_actions() {
        let schema = new_schema_with_actions("k8s", "Kubernetes actions");
        
        // Check if the namespace was created
        assert!(schema.contains_key("k8s"));
        
        // Check if all actions were added
        let namespace = schema.get("k8s").unwrap();
        for &action in ALL_ACTIONS {
            assert!(namespace.actions.contains_key(action));
        }
        
        // Check if documentation was added
        assert_eq!(namespace.annotations.as_ref().unwrap().get("doc").unwrap(), "Kubernetes actions");
    }

}



