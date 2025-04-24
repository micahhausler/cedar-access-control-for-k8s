use std::collections::HashMap;
use serde::{Deserialize, Serialize, Serializer, ser::SerializeMap};
use serde::de::{self, Deserializer, MapAccess, Visitor};
use std::fmt;

/// Cedar schema types constants
pub const STRING_TYPE: &str = "String";
pub const LONG_TYPE: &str = "Long";
pub const BOOL_TYPE: &str = "Boolean";
pub const RECORD_TYPE: &str = "Record";
pub const SET_TYPE: &str = "Set";
pub const ENTITY_TYPE: &str = "Entity";

/// Top level schema structure
pub type CedarSchema = HashMap<String, CedarSchemaNamespace>;

/// Create a new Cedar schema
pub fn new_cedar_schema() -> CedarSchema {
    HashMap::new()
}

/// Represents a namespace within a schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarSchemaNamespace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
    #[serde(rename = "entityTypes")]
    pub entity_types: HashMap<String, Entity>,
    pub actions: HashMap<String, ActionShape>,
    #[serde(rename = "commonTypes", skip_serializing_if = "Option::is_none")]
    pub common_types: Option<HashMap<String, EntityShape>>,
}

/// Represents a Cedar entity that defines principals and resources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
    pub shape: EntityShape,
    #[serde(rename = "memberOfTypes", skip_serializing_if = "Option::is_none")]
    pub member_of_types: Option<Vec<String>>,
}

/// Represents the shape of a Cedar entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityShape {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
    #[serde(rename = "type")]
    pub type_name: String,
    pub attributes: HashMap<String, EntityAttribute>,
}

/// Represents an attribute of a Cedar entity
///
/// Element may only be used when the Type is "Set"
#[derive(Debug, Clone)]
pub struct EntityAttribute {
    pub annotations: Option<HashMap<String, String>>,
    pub type_name: String,
    pub name: Option<String>,
    pub required: bool,
    pub element: Option<Box<EntityAttributeElement>>,
    pub attributes: Option<HashMap<String, EntityAttribute>>,
}

// Custom serializer for EntityAttribute to handle the Cedar-specific JSON formatting
impl Serialize for EntityAttribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Create a map with correct capacity
        let mut capacity = 1; // For "type" field
        if self.annotations.is_some() { capacity += 1; }
        if self.name.is_some() { capacity += 1; }
        capacity += 1; // For "required" field
        if self.element.is_some() { capacity += 1; }
        if self.type_name == RECORD_TYPE { capacity += 1; } // Always include attributes for Record type

        let mut map = serializer.serialize_map(Some(capacity))?;
        
        // Add annotations if present
        if let Some(ref annotations) = self.annotations {
            map.serialize_entry("annotations", annotations)?;
        }
        
        // Add type field
        map.serialize_entry("type", &self.type_name)?;
        
        // Add name if present
        if let Some(ref name) = self.name {
            map.serialize_entry("name", name)?;
        }
        
        // Add required field
        map.serialize_entry("required", &self.required)?;
        
        // Add element if present
        if let Some(ref element) = self.element {
            map.serialize_entry("element", element)?;
        }
        
        // If type is Record, always include attributes field, even if empty
        if self.type_name == RECORD_TYPE {
            map.serialize_entry("attributes", &self.attributes.clone().unwrap_or_default())?;
        } else if let Some(ref attributes) = self.attributes {
            // For non-Record types, only include attributes if non-empty
            map.serialize_entry("attributes", attributes)?;
        }
        
        map.end()
    }
}

// Custom deserializer implementation for EntityAttribute
impl<'de> Deserialize<'de> for EntityAttribute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EntityAttributeVisitor;

        impl<'de> Visitor<'de> for EntityAttributeVisitor {
            type Value = EntityAttribute;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an EntityAttribute object")
            }

            fn visit_map<V>(self, mut map: V) -> Result<EntityAttribute, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut annotations: Option<HashMap<String, String>> = None;
                let mut type_name: Option<String> = None;
                let mut name: Option<String> = None;
                let mut required: Option<bool> = None;
                let mut element: Option<Box<EntityAttributeElement>> = None;
                let mut attributes: Option<HashMap<String, EntityAttribute>> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "annotations" => {
                            annotations = Some(map.next_value()?);
                        }
                        "type" => {
                            type_name = Some(map.next_value()?);
                        }
                        "name" => {
                            name = Some(map.next_value()?);
                        }
                        "required" => {
                            required = Some(map.next_value()?);
                        }
                        "element" => {
                            element = Some(map.next_value()?);
                        }
                        "attributes" => {
                            attributes = Some(map.next_value()?);
                        }
                        _ => {
                            return Err(de::Error::unknown_field(
                                &key,
                                &["annotations", "type", "name", "required", "element", "attributes"],
                            ));
                        }
                    }
                }

                let type_name = type_name.ok_or_else(|| de::Error::missing_field("type"))?;
                let required = required.unwrap_or(false);

                Ok(EntityAttribute {
                    annotations,
                    type_name,
                    name,
                    required,
                    element,
                    attributes,
                })
            }
        }

        deserializer.deserialize_map(EntityAttributeVisitor)
    }
}

/// Represents an element of a Cedar entity attribute (used for sets)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityAttributeElement {
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Represents the shape of a Cedar action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionShape {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
    #[serde(rename = "appliesTo")]
    pub applies_to: ActionAppliesTo,
    #[serde(rename = "memberOf", skip_serializing_if = "Option::is_none")]
    pub member_of: Option<Vec<ActionMember>>,
}

/// Represents a parent type of a Cedar action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionMember {
    pub id: String,
}

/// Contains the entity types that a Cedar action applies to
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionAppliesTo {
    #[serde(rename = "principalTypes")]
    pub principal_types: Vec<String>,
    #[serde(rename = "resourceTypes")]
    pub resource_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<EntityShape>,
}

impl ActionAppliesTo {
    /// Create a new ActionAppliesTo with empty principal and resource types
    pub fn new() -> Self {
        ActionAppliesTo {
            principal_types: Vec::new(),
            resource_types: Vec::new(),
            context: None,
        }
    }

    /// Add a principal type to the action
    pub fn add_principal_type(&mut self, principal_type: &str) {
        if !self.principal_types.contains(&principal_type.to_string()) {
            self.principal_types.push(principal_type.to_string());
        }
    }

    /// Add a resource type to the action
    pub fn add_resource_type(&mut self, resource_type: &str) {
        if !self.resource_types.contains(&resource_type.to_string()) {
            self.resource_types.push(resource_type.to_string());
        }
    }

    /// Check if a resource type is supported by the action
    pub fn supports_resource_type(&self, resource_type: &str) -> bool {
        self.resource_types.contains(&resource_type.to_string())
    }

    /// Check if a principal type is supported by the action
    pub fn supports_principal_type(&self, principal_type: &str) -> bool {
        self.principal_types.contains(&principal_type.to_string())
    }
}


/// Helper trait to sort action entities (similar to the Go SortActionEntities method)
pub trait SchemaSorting {
    fn sort_action_entities(&mut self);
}

impl SchemaSorting for CedarSchema {
    fn sort_action_entities(&mut self) {
        for (_, ns) in self.iter_mut() {
            for (_, action) in ns.actions.iter_mut() {
                action.applies_to.principal_types.sort();
                action.applies_to.resource_types.sort();
            }
        }
    }
}

/// Get the entity shape by its namespaced name
pub fn get_entity_shape(schema: &CedarSchema, name: &str) -> Option<EntityShape> {
    let parts: Vec<&str> = name.split("::").collect();
    let (namespace_name, entity_name) = if parts.len() > 1 {
        let ns = parts[0..parts.len()-1].join("::");
        let name = parts[parts.len()-1];
        (ns, name.to_string())
    } else {
        ("".to_string(), name.to_string())
    };

    // Check if namespace exists
    let namespace = schema.get(&namespace_name)?;
    
    // Check entity_types
    if let Some(entity) = namespace.entity_types.get(&entity_name) {
        return Some(entity.shape.clone());
    }
    
    // Check common_types if entities not found
    if let Some(common_types) = &namespace.common_types {
        if let Some(entity_shape) = common_types.get(&entity_name) {
            return Some(entity_shape.clone());
        }
    }
    
    None
}

/// Create a documentation annotation
pub fn doc_annotation(value: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert("doc".to_string(), value.to_string());
    map
}

/// Helper function to add a resource type to an action
pub fn add_resource_type_to_action(
    schema: &mut CedarSchema,
    action_namespace: &str,
    action_name: &str,
    resource_type: &str,
) {
    if let Some(ns) = schema.get_mut(action_namespace) {
        if let Some(action) = ns.actions.get_mut(action_name) {
            let resource_idx = action.applies_to.resource_types
                .iter()
                .position(|r| r == resource_type);
            
            if resource_idx.is_none() {
                action.applies_to.resource_types.push(resource_type.to_string());
            }
        }
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    
    #[test]
    fn test_serialize_entity_attribute_record() {
        let attr = EntityAttribute {
            annotations: None,
            type_name: RECORD_TYPE.to_string(),
            name: None,
            required: true,
            element: None,
            attributes: Some(HashMap::new()),
        };
        
        let json = serde_json::to_value(&attr).unwrap();
        assert_eq!(json["type"], RECORD_TYPE);
        assert_eq!(json["required"], true);
        assert!(json.get("attributes").is_some());
    }
    
    #[test]
    fn test_serialize_entity_attribute_string() {
        let attr = EntityAttribute {
            annotations: None,
            type_name: STRING_TYPE.to_string(),
            name: None,
            required: false,
            element: None,
            attributes: None,
        };
        
        let json = serde_json::to_value(&attr).unwrap();
        assert_eq!(json["type"], STRING_TYPE);
        assert_eq!(json["required"], false);
        assert!(json.get("attributes").is_none());
    }
    
    #[test]
    fn test_deserialize_entity_attribute() {
        let json = json!({
            "type": "String",
            "required": true
        });
        
        let attr: EntityAttribute = serde_json::from_value(json).unwrap();
        assert_eq!(attr.type_name, STRING_TYPE);
        assert_eq!(attr.required, true);
        assert!(attr.attributes.is_none());
    }
    
    #[test]
    fn test_round_trip_entity_attribute() {
        let original = EntityAttribute {
            annotations: Some(doc_annotation("Test attribute")),
            type_name: RECORD_TYPE.to_string(),
            name: Some("TestAttr".to_string()),
            required: true,
            element: None,
            attributes: Some(HashMap::new()),
        };
        
        let json = serde_json::to_value(&original).unwrap();
        let deserialized: EntityAttribute = serde_json::from_value(json).unwrap();
        
        assert_eq!(deserialized.type_name, original.type_name);
        assert_eq!(deserialized.required, original.required);
        assert_eq!(deserialized.name, original.name);
    }
    
    #[test]
    fn test_sort_action_entities() {
        let mut schema = new_cedar_schema();
        let mut namespace = CedarSchemaNamespace {
            annotations: None,
            entity_types: HashMap::new(),
            actions: HashMap::new(),
            common_types: None,
        };
        
        let mut action = ActionShape {
            annotations: None,
            applies_to: ActionAppliesTo {
                principal_types: vec!["User2".to_string(), "User1".to_string()],
                resource_types: vec!["Resource2".to_string(), "Resource1".to_string()],
                context: None,
            },
            member_of: None,
        };
        
        namespace.actions.insert("action1".to_string(), action);
        schema.insert("test".to_string(), namespace);
        
        schema.sort_action_entities();
        
        let sorted_principals = &schema["test"].actions["action1"].applies_to.principal_types;
        let sorted_resources = &schema["test"].actions["action1"].applies_to.resource_types;
        
        assert_eq!(sorted_principals, &vec!["User1".to_string(), "User2".to_string()]);
        assert_eq!(sorted_resources, &vec!["Resource1".to_string(), "Resource2".to_string()]);
    }
} 