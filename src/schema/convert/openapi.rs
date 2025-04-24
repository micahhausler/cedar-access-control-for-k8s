use std::collections::HashMap;

use anyhow::{Result, anyhow};
use k8s_openapi::apimachinery::pkg::apis::meta::v1 as metav1;
use kube::{
    // api::Api,
    client::Client,
    config::Config,
    // discovery::ApiGroup,
    // discovery::ApiResource,
    // discovery::Discovery,
    // Resource,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use http::Request;
use regex;


use crate::schema::{
    CedarSchema, CedarSchemaNamespace, Entity, EntityShape, EntityAttribute, EntityAttributeElement,
    add_resource_type_to_action,
    STRING_TYPE, RECORD_TYPE, SET_TYPE, LONG_TYPE, BOOL_TYPE, ENTITY_TYPE,
    ACTION_DELETE, ACTION_UPDATE, ACTION_CREATE, ACTION_CONNECT, ACTION_ALL
};

// Equivalent to the Path struct in Go, renamed to avoid collision with std::path::Path
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiPath {
    #[serde(rename   = "serverRelativeURL")]
    pub server_relative_url: String,
}

// Equivalent to the PathDocument struct in Go
#[derive(Debug, Serialize, Deserialize)]
pub struct PathDocument {
    pub paths: HashMap<String, ApiPath>,
}

// Equivalent to the K8sSchemaGetter struct in Go
pub struct K8sSchemaGetter {
    client: Client,
}

impl K8sSchemaGetter {
    pub async fn new(config: Config) -> Result<Self> {
        let client = Client::try_from(config)?;
        Ok(K8sSchemaGetter { client })
    }

    pub async fn get_api_schema(&self, suffix: &str) -> Result<Value>{
        let uri = format!("/openapi/v3/{}", suffix);

        let req = Request::get(uri.as_str())
            .body(Vec::<u8>::new())
            .map_err(|e| anyhow!("Failed to create request: {}", e))?;
        
        // Use the raw HTTP client to make the GET request
        let response = self.client.request(req)
            .await
            .map_err(|e| anyhow!("Failed to get openapi: {}", e))?;
        
        Ok(response)
    }

    pub async fn get_all_versioned_schemas(&self) -> Result<Vec<String>> {
        let uri = "/openapi/v3";
        let req = Request::get(uri)
            .body(Vec::<u8>::new())
            .map_err(|e| anyhow!("Failed to create request: {}", e))?;
        
        let response = self.client.request(req)
            .await
            .map_err(|e| anyhow!("Failed to get openapi: {}", e))?;
        
        // Parse the response into a PathDocument
        let path_doc: PathDocument = serde_json::from_value(response)
            .map_err(|e| anyhow!("Failed to parse openapi response: {}", e))?;
        
        // Create regex pattern for versioned APIs
        let pattern = regex::Regex::new(r"/v\d+(?:alpha\d+|beta\d+)?$")
            .map_err(|e| anyhow!("Failed to create regex pattern: {}", e))?;
        
        // Filter paths that match the version pattern
        let versioned_paths: Vec<String> = path_doc.paths
            .keys()
            .filter(|path| pattern.is_match(path))
            .cloned()
            .collect();
        
        Ok(versioned_paths)
    }

    pub async fn api_resource_list(&self, api_path: &str) -> Result<metav1::APIResourceList> {
        let api_path = format!("/{}", api_path);

        let req = Request::get(api_path)
            .body(Vec::<u8>::new())
            .map_err(|e| anyhow!("Failed to create request: {}", e))?;
        
        self.client.request(req).await
            .map_err(|e| anyhow!("Failed to get API resource list: {}", e))
    }
}

// Stub for the ModifySchemaForAPIVersion function
pub async fn modify_schema_for_api_version(
    api_resources: &metav1::APIResourceList,
    open_api_schema: &Value,
    cedar_schema: &mut CedarSchema,
    _api: &str,
    version: &str,
    action_namespace: &str,
) -> Result<()> {
    // Get the schemas component from the OpenAPI schema
    let schemas = match open_api_schema.get("components").and_then(|c| c.get("schemas")) {
        Some(s) => s,
        None => return Err(anyhow!("OpenAPI schema does not contain components.schemas")),
    };

    // Iterate through all schema definitions
    if let Value::Object(schema_objects) = schemas {
        for (schema_kind, schema_definition) in schema_objects {
            // Skip schemas from kube-aggregator
            if schema_kind.contains("io.k8s.kube-aggregator.pkg.apis") {
                continue;
            }

            // Parse the schema name into its components
            let (api_ns, api_group, s_version, s_kind) = parse_schema_name(schema_kind);

            // Skip special types
            if api_ns == "pkg.apimachinery.k8s.io" ||
               (api_group == "meta" && s_version == "v1" && (s_kind == "Time" || s_kind == "MicroTime")) {
                continue;
            }

            // Skip if not the version we're processing
            if s_version != version {
                continue;
            }

            // Convert schema name to Cedar namespace and kind
            let (ns_name, _) = schema_name_to_cedar(schema_kind);
            eprintln!("Processing: {}", schema_kind);
            // Ensure namespace exists in schema
            // Check if namespace exists, if not define it but don't insert yet
            let mut namespace = match cedar_schema.get(&ns_name) {
                Some(ns) => ns.clone(),
                None => {
                    // Define the namespace structure without inserting it
                    CedarSchemaNamespace {
                        annotations: None,
                        entity_types: HashMap::new(),
                        actions: HashMap::new(),
                        common_types: None,
                    }
                }
            };

            // Check if the entity type or common type already exists
            if namespace.entity_types.contains_key(&s_kind) || 
               (namespace.common_types.is_some() && namespace.common_types.as_ref().unwrap().contains_key(&s_kind)) {
                continue;
            }


            // Check schema type
            let schema_type = schema_definition.get("type")
                .and_then(|t| t.as_str());

            if schema_type.is_none() {
                eprintln!("Skipping unknown type: {}", schema_kind);
                continue;
            }

            
            // Process based on type
            let entity_option = match schema_type.unwrap() {
                "object" => {
                    // The full implementation would convert the object to an EntityShape
                    // For now, we'll just create a basic entity    with empty attributes
                    let shape = ref_to_entity_shape(open_api_schema, schema_kind)?;
                    
                    let entity = Entity {
                        annotations: None,
                        shape,
                        member_of_types: None,
                    };
                    
                    Some(entity)
                },
                "string" => {
                    // Create a string entity
                    let entity_shape = EntityShape {
                        annotations: None,
                        type_name: STRING_TYPE.to_string(),
                        attributes: HashMap::new(),
                    };
                    
                    // Ensure common_types exists
                    if namespace.common_types.is_none() {
                        namespace.common_types = Some(HashMap::new());
                    }
                    
                    // Add to common_types
                    if let Some(common_types) = &mut namespace.common_types {
                        common_types.insert(s_kind.clone(), entity_shape);
                    }
                    
                    None
                },
                _ => {
                    // Skip other types
                    eprintln!("Skipping unknown type: {}", schema_type.unwrap());
                    None
                }
            };

            if entity_option.is_none() {
                continue;
            }

            
            let mut entity = entity_option.unwrap();

            if is_list_entity(&entity.shape) {
                continue;
            }

            if !is_entity(&entity.shape) {
             
                eprintln!("Adding common type: {}", s_kind);
                namespace.common_types.get_or_insert_with(HashMap::new)
                    .insert(s_kind.clone(), entity.shape);
                if !namespace.entity_types.is_empty() || namespace.common_types.is_some() {
                    let namespace = namespace.clone();
                    cedar_schema.insert(ns_name.clone(), namespace);
                }
                continue;
            }


            let verbs = verbs_for_kind(&s_kind, api_resources);
            
            // Check if verbs contains delete or deletecollection
            if verbs.iter().any(|v| v == "delete" || v == "deletecollection") { 
                add_old_object_attribute(&mut entity, &s_kind);
                add_resource_type_to_action(cedar_schema, action_namespace, ACTION_DELETE, &format!("{}::{}", ns_name, s_kind));
            }

            if verbs.iter().any(|v| v == "update" || v == "patch") {
                add_old_object_attribute(&mut entity, &s_kind);
                add_resource_type_to_action(cedar_schema, action_namespace, ACTION_UPDATE, &format!("{}::{}", ns_name, s_kind))
            }

            if verbs.iter().any(|v| v == "create") {    
                add_resource_type_to_action(cedar_schema, action_namespace, ACTION_CREATE, &format!("{}::{}", ns_name, s_kind))
            }

            // We hard-code `CONNECT` elsewhere since there are only a few connectable Kinds that aren't in the OpenAPI schema.
            // add_resource_type_to_action(cedar_schema, action_namespace, ACTION_CONNECT, &format!("{}::{}", ns_name, s_kind));

            add_resource_type_to_action(cedar_schema, action_namespace, ACTION_ALL, &format!("{}::{}", ns_name, s_kind));
            eprintln!("Adding entity type: {}", s_kind);
            namespace.entity_types.insert(s_kind.clone(), entity);
             // Add the modified namespace to the schema
             if !namespace.entity_types.is_empty() || namespace.common_types.is_some() {
                let namespace = namespace.clone();
                cedar_schema.insert(ns_name.clone(), namespace);
            }


        }
    }

    Ok(())
}

fn add_old_object_attribute(entity: &mut Entity, kind: &str) {
    entity.shape.attributes.insert(
        "oldObject".to_string(),
        EntityAttribute {
            annotations: None,
            type_name: ENTITY_TYPE.to_string(),
            name: Some(kind.to_string()),
            required: false,
            element: None,
            attributes: None,
        }
    );
}

fn verbs_for_kind(kind: &str, api_resources: &metav1::APIResourceList) -> Vec<String> {
    api_resources.resources.iter()
        .filter(|resource| resource.kind == kind)
        .flat_map(|resource| resource.verbs.clone())
        .collect()
}

fn is_list_entity(shape: &EntityShape) -> bool {
    
    if shape.attributes.is_empty() {
        return false;
    }

    // Check for apiVersion attribute
    if let Some(api_version_attr) = shape.attributes.get("apiVersion") {
        if api_version_attr.type_name != STRING_TYPE {
            return false;
        }
    } else {
        return false;
    }

    // Check for kind attribute
    if let Some(kind_attr) = shape.attributes.get("kind") {
        if kind_attr.type_name != STRING_TYPE {
            return false;
        }
    } else {
        return false;
    }

    // Check for metadata attribute
    if let Some(metadata_attr) = shape.attributes.get("metadata") {
        if metadata_attr.type_name != "meta::v1::ListMeta" {
            return false;
        }
    } else {
        return false;
    }

    true
}

fn is_entity(shape: &EntityShape) -> bool {
    
    if shape.attributes.is_empty() {
        return false;
    }

    // Check for apiVersion attribute
    if let Some(api_version_attr) = shape.attributes.get("apiVersion") {
        if api_version_attr.type_name != STRING_TYPE {
            return false;
        }
    } else {
        return false;
    }

    // Check for kind attribute
    if let Some(kind_attr) = shape.attributes.get("kind") {
        if kind_attr.type_name != STRING_TYPE {
            return false;
        }
    } else {
        return false;
    }

    // Check for metadata attribute
    if let Some(metadata_attr) = shape.attributes.get("metadata") {
        if metadata_attr.type_name != "meta::v1::ObjectMeta" {
            return false;
        }
    } else {
        return false;
    }

    true
}


// Helper functions that will be implemented as needed
pub fn parse_schema_name(schema_kind: &str) -> (String, String, String, String) {
    // Replace hyphens with underscores
    let schema_kind = schema_kind.replace('-', "_");
    
    // Split into parts and reverse
    let mut parts: Vec<&str> = schema_kind.split('.').collect();
    if parts.len() < 4 {
        return (
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        );
    }
    parts.reverse();

    let mut ns = String::new();
    if schema_kind.starts_with("io.k8s.api.") {
        parts = parts[..parts.len()-3].to_vec();
    } else if schema_kind.starts_with("io.k8s.apimachinery.pkg.apis.meta.") {
        parts = parts[..parts.len()-4].to_vec();
    // TODO special case for API extensions?
    // } else if schema_kind.starts_with("io.k8s.") {
    //     parts = parts[..parts.len()-2].to_vec();
    } else {
        let mut ns_parts: Vec<&str> = parts[3..].to_vec();
        ns_parts.reverse(); // Reverse the namespace parts before joining
        ns = ns_parts.join("::");
    }

    let kind = parts[0].to_string();
    let version = parts[1].to_string();
    let api_group = parts[2].to_string();

    (ns, api_group, version, kind)
}

fn schema_name_to_cedar(schema_kind: &str) -> (String, String) {
    let (ns, api_group, version, kind) = parse_schema_name(schema_kind);
    
    let ns_name = if !ns.is_empty() {
        format!("{}::{}::{}", ns, api_group, version)
    } else {
        format!("{}::{}", api_group, version)
    };
    
    (ns_name, kind)
}

fn ref_to_relative_type_name(current: &str, ref_: &str) -> String {
    // Remove the prefix if it exists
    let cur_parsed = if let Some(stripped) = current.strip_prefix("#/components/schemas/") {
        stripped
    } else {
        current
    };
    let (current_ns, _) = schema_name_to_cedar(cur_parsed);

    let ref_parsed = if let Some(stripped) = ref_.strip_prefix("#/components/schemas/") {
        stripped
    } else {
        ref_
    };
    let (ref_ns, ref_type) = schema_name_to_cedar(ref_parsed);

    // Check for special types that should be converted to string
    if (ref_ns == "meta::v1" && ref_type == "Time") ||
       (ref_ns == "meta::v1" && ref_type == "MicroTime") ||
       (ref_ns == "io::k8s::apimachinery::pkg::util::intstr" && ref_type == "IntOrString") ||
       (ref_ns == "io::k8s::apimachinery::pkg::api::resource" && ref_type == "Quantity") ||
       (ref_ns == "io::k8s::apimachinery::pkg::runtime" && ref_type == "RawExtension") {
    
        return STRING_TYPE.to_string();
    }

    if current_ns == ref_ns {
        ref_type
    } else {
        format!("{}::{}", ref_ns, ref_type)
    }
}

fn ref_to_entity_shape(api: &Value, schema_kind: &str) -> Result<EntityShape, anyhow::Error> {
    let mut entity_shape = EntityShape {
        annotations: None,
        type_name: RECORD_TYPE.to_string(),
        attributes: HashMap::new(),
    };

    // Get the schema definition from the OpenAPI schema
    let schema_definition = api.get("components")
        .and_then(|c| c.get("schemas"))
        .and_then(|s| s.get(schema_kind))
        .ok_or_else(|| anyhow::anyhow!("schema {} not found", schema_kind))?;

    // Get properties if they exist
    let properties = match schema_definition.get("properties") {
        Some(p) => p,
        None => return Ok(entity_shape),
    };

    // Get required fields if they exist
    let required = schema_definition.get("required")
        .and_then(|r| r.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();

    // Process each property
    if let Value::Object(props) = properties {
        for (attr_name, attr_def) in props {
            let is_required = required.contains(&attr_name.as_str());

            // Handle different property types
            if let Some(attr_type) = attr_def.get("type").and_then(|t| t.as_str()) {
                match attr_type {
                    "string" => {
                        entity_shape.attributes.insert(
                            attr_name.clone(),
                            EntityAttribute {
                                annotations: None,
                                type_name: STRING_TYPE.to_string(),
                                name: None,
                                required: is_required,
                                element: None,
                                attributes: None,
                            },
                        );
                    }
                    "integer" => {
                        entity_shape.attributes.insert(
                            attr_name.clone(),
                            EntityAttribute {
                                annotations: None,
                                type_name: LONG_TYPE.to_string(),
                                name: None,
                                required: is_required,
                                element: None,
                                attributes: None,
                            },
                        );
                    }
                    "boolean" => {
                        entity_shape.attributes.insert(
                            attr_name.clone(),
                            EntityAttribute {
                                annotations: None,
                                type_name: BOOL_TYPE.to_string(),
                                name: None,
                                required: is_required,
                                element: None,
                                attributes: None,
                            },
                        );
                    }
                    "io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.JSON" => {
                        eprintln!("Skipping JSON: {}, {:?}", attr_name, attr_def);
                        continue;
                    }
                    "io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.JSONSchemaPropsOrArray" => {
                        eprintln!("Skipping JSONSchemaPropsOrArray: {}, {:?}", attr_name, attr_def);
                        continue;
                    }
                    "io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.JSONSchemaPropsOrStringArray" => {
                        eprintln!("Skipping JSONSchemaPropsOrStringArray: {}, {:?}", attr_name, attr_def);
                        continue;
                    }
                    "io.k8s.apiextensions-apiserver.pkg.apis.apiextensions.v1.JSONSchemaPropsOrBool" => {
                        eprintln!("Skipping JSONSchemaPropsOrBool: {}, {:?}", attr_name, attr_def);
                        continue;
                    }
                    "array" => {
                        if let Some(items) = attr_def.get("items") {
                            if let Some(item_type) = items.get("type").and_then(|t| t.as_str()) {
                                let element_type = match item_type {
                                    "string" => STRING_TYPE.to_string(),
                                    "integer" => LONG_TYPE.to_string(),
                                    "boolean" => BOOL_TYPE.to_string(),
                                    _ => {
                                        // For now, skip complex array types
                                        continue;
                                    }
                                };

                                entity_shape.attributes.insert(
                                    attr_name.clone(),
                                    EntityAttribute {
                                        annotations: None,
                                        type_name: SET_TYPE.to_string(),
                                        name: None,
                                        required: is_required,
                                        element: Some(Box::new(EntityAttributeElement {
                                            type_name: element_type,
                                            name: None,
                                        })),
                                        attributes: None,
                                    },
                                );
                            } else if let Some(all_of) = items.get("allOf").and_then(|a| a.as_array()) {
                                if let Some(ref_) = all_of[0].get("$ref").and_then(|r| r.as_str()) {
                                    let type_name = ref_to_relative_type_name(schema_kind, ref_);
                                    if schema_kind == &ref_[21..] {
                                        // set an entity type of a set of strings
                                        entity_shape.attributes.insert(
                                            attr_name.clone(),
                                            EntityAttribute {
                                                annotations: None,
                                                type_name: SET_TYPE.to_string(),
                                                name: None,
                                                required: is_required,
                                                element: Some(Box::new(EntityAttributeElement {
                                                    type_name: STRING_TYPE.to_string(),
                                                    name: None,
                                                })),
                                                attributes: None,
                                            },
                                        );
                                        continue;
                                    }
                                    
                                    // eprintln!("ref_to_entity_shape({}) calling ref_to_entity_shape({})", schema_kind, ref_[21..].to_string());  
                                    let attr_shape = ref_to_entity_shape(api, &ref_[21..])?;
                                    
                                    let element = EntityAttributeElement {
                                        type_name: if is_entity(&attr_shape) { 
                                            ENTITY_TYPE.to_string() 
                                        } else { 
                                            type_name.clone() 
                                        },
                                        name: if is_entity(&attr_shape) { 
                                            Some(type_name) 
                                        } else { 
                                            None 
                                        },
                                    };

                                    entity_shape.attributes.insert(
                                        attr_name.clone(),
                                        EntityAttribute {
                                            annotations: None,
                                            type_name: SET_TYPE.to_string(),
                                            name: None,
                                            required: is_required,
                                            element: Some(Box::new(element)),
                                            attributes: None,
                                        },
                                    );
                                }
                            }
                        }
                    }
                    "object" => {
                        if let Some(properties) = attr_def.get("properties") {
                            if let Some(_) = attr_def.get("additionalProperties") {
                                let attrs = parse_crd_properties(15, properties)?;
                                entity_shape.attributes.insert(
                                    attr_name.clone(),
                                    EntityAttribute {
                                        annotations: None,
                                        type_name: RECORD_TYPE.to_string(),
                                        name: None,
                                        required: is_required,
                                        element: None,
                                        attributes: Some(attrs),
                                    },
                                );
                                continue;
                            }
                        }
                        
                        if attr_def.get("additionalProperties").is_none() {
                            eprintln!("Skipping {} attr {} object with no additionalProperties", schema_kind, attr_name);
                            continue;
                        }

                        // if additionalProperties.$ref is `#/components/schemas/io.k8s.apimachinery.pkg.api.resource.Quantity`, set to string
                        if let Some(additional_props) = attr_def.get("additionalProperties") {
                            if let Some(ref_) = additional_props.get("$ref").and_then(|r| r.as_str()) {
                                if ref_ == "#/components/schemas/io.k8s.apimachinery.pkg.api.resource.Quantity" ||
                                   ref_ == "#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.Time" {
                                    entity_shape.attributes.insert(attr_name.clone(), EntityAttribute {
                                        annotations: None,
                                        type_name: STRING_TYPE.to_string(),
                                        name: None,
                                        required: is_required,
                                        element: None,
                                        attributes: None,
                                    });
                                    continue;
                                }   
                            }
                        }
                        
                        if let Some(items) = attr_def.get("items") {
                            if let Some(all_of) = items.get("allOf").and_then(|a| a.as_array()) {
                                if let Some(ref_) = all_of[0].get("$ref").and_then(|r| r.as_str()) {
                                    let url_type_name = ref_to_relative_type_name(schema_kind, ref_);
                                    // slice the URL to get the 21st character on
                                    let type_name = url_type_name[21..].to_string();
                                    let attr_shape = ref_to_entity_shape(api, &type_name).unwrap();
                                  
                                    entity_shape.attributes.insert(
                                        attr_name.clone(),
                                        EntityAttribute {
                                            annotations: None,
                                            type_name: if is_entity(&attr_shape) { 
                                                ENTITY_TYPE.to_string() 
                                            } else { 
                                                type_name.clone() 
                                            },
                                            name: if is_entity(&attr_shape) { 
                                                Some(type_name) 
                                            } else { 
                                                None 
                                            },
                                            required: is_required,
                                            element: None,
                                            attributes: None,
                                        },
                                    );
                                    continue
                                }
                            }
                       } 


                       let known_key_value_string_map_attributes = HashMap::from([
                        ("io.k8s.api.core.v1.ConfigMap".to_string(), vec!["data", "binaryData"]),
                        ("io.k8s.api.core.v1.CSIPersistentVolumeSource".to_string(), vec!["volumeAttributes"]),
                        ("io.k8s.api.core.v1.CSIVolumeSource".to_string(), vec!["volumeAttributes"]),
                        ("io.k8s.api.core.v1.FlexPersistentVolumeSource".to_string(), vec!["options"]),
                        ("io.k8s.api.core.v1.FlexVolumeSource".to_string(), vec!["options"]),
                        ("io.k8s.api.core.v1.PersistentVolumeClaimStatus".to_string(), vec!["allocatedResourceStatuses"]),
                        ("io.k8s.api.core.v1.PodSpec".to_string(), vec!["nodeSelector"]),
                        ("io.k8s.api.core.v1.ReplicationControllerSpec".to_string(), vec!["selector"]),
                        ("io.k8s.api.core.v1.Secret".to_string(), vec!["data", "stringData"]),
                        ("io.k8s.api.core.v1.ServiceSpec".to_string(), vec!["selector"]),
                        ("io.k8s.api.discovery.v1.Endpoint".to_string(), vec!["deprecatedTopology"]),
                        ("io.k8s.api.node.v1.Scheduling".to_string(), vec!["nodeSelector"]),
                        ("io.k8s.api.storage.v1.StorageClass".to_string(), vec!["parameters"]),
                        ("io.k8s.api.storage.v1.VolumeAttachmentStatus".to_string(), vec!["attachmentMetadata"]),
                        ("io.k8s.apimachinery.pkg.apis.meta.v1.LabelSelector".to_string(), vec!["matchLabels"]),
                        ("io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta".to_string(), vec!["annotations", "labels"]),
                       ]);

                        if let Some(attrs) = known_key_value_string_map_attributes.get(schema_kind) {
                            if attrs.contains(&attr_name.as_str()) {
                                if let Some(additional_props) = attr_def.get("additionalProperties") {
                                    if let Some(type_val) = additional_props.get("type") {
                                        if let Some("string") = type_val.as_str() {
                                            entity_shape.attributes.insert(
                                                attr_name.clone(),
                                                EntityAttribute {
                                                    annotations: None,
                                                    type_name: SET_TYPE.to_string(),
                                                    name: None,
                                                    required: is_required,
                                                    element: Some(Box::new(EntityAttributeElement {
                                                        type_name: ref_to_relative_type_name(schema_kind, "io.k8s.apimachinery.pkg.apis.meta.v1.KeyValue"),
                                                        name: None,
                                                    })),
                                                    attributes: None,
                                                }
                                            );
                                            continue;
                                        }
                                    }
                                
                                }
                            }
                        }
                        // TODO handle list of strings

                        let known_key_value_string_slice_attributes = HashMap::from([
                            ("io.k8s.api.authentication.v1.UserInfo".to_string(), vec!["extra"]),
                            ("io.k8s.api.authorization.v1.SubjectAccessReviewSpec".to_string(), vec!["extra"]),
                            ("io.k8s.api.certificates.v1.CertificateSigningRequestSpec".to_string(), vec!["extra"]),
                        ]);

                        if let Some(attrs) = known_key_value_string_slice_attributes.get(schema_kind) {
                            if attrs.contains(&attr_name.as_str()) {
                                if let Some(additional_props) = attr_def.get("additionalProperties") {
                                    if let Some(type_val) = additional_props.get("type") {
                                        if let Some("array") = type_val.as_str() {
                                            entity_shape.attributes.insert(
                                                attr_name.clone(),
                                                EntityAttribute {
                                                    annotations: None,
                                                    type_name: SET_TYPE.to_string(),
                                                    name: None,
                                                    required: is_required,
                                                    element: Some(Box::new(EntityAttributeElement {
                                                        type_name: ref_to_relative_type_name(schema_kind, "io.k8s.apimachinery.pkg.apis.meta.v1.KeyValueStringSlice"),  
                                                        name: None,
                                                    })),
                                                    attributes: None,
                                                }
                                            );
                                            continue;   
                                        }
                                    }
                                }
                            }
                        } 



                        eprintln!("Skipping {} attr {} type {}", schema_kind, attr_name, attr_type);                        
                        
                    }
                    "number" => {
                        eprintln!("Skipping number: {}, {:?}", attr_name, attr_def);
                        continue;
                    }
                    _ => {
                        eprintln!("Skipping unknown type: {} for {}", attr_type, attr_name);
                        continue;
                    }
                }
            } else if let Some(all_of) = attr_def.get("allOf").and_then(|a| a.as_array()) {
                if all_of.len() != 1 {
                    continue;
                }

                if let Some(ref_) = all_of[0].get("$ref").and_then(|r| r.as_str()) {
                    
                    let type_name = ref_to_relative_type_name(schema_kind, ref_);
                    
                    // eprintln!("ref_to_entity_shape({}) calling ref_to_entity_shape({})", schema_kind, ref_[21..].to_string());  

                    let attr_shape = ref_to_entity_shape(api, &ref_[21..])?;
                    
                    entity_shape.attributes.insert(
                        attr_name.clone(),
                        EntityAttribute {
                            annotations: None,
                            type_name: if is_entity(&attr_shape) { 
                                ENTITY_TYPE.to_string() 
                            } else { 
                                type_name.clone() 
                            },
                            name: if is_entity(&attr_shape) { 
                                Some(type_name) 
                            } else { 
                                None 
                            },
                            required: is_required,
                            element: None,
                            attributes: None,
                        },
                    );
                }
                
            }
        }
    }

    Ok(entity_shape)
}

pub fn modify_object_meta_maps(schema: &mut CedarSchema) {
    if let Some(ns) = schema.get_mut("meta::v1") {
        // Create KeyValue entity
        let key_val_entity = EntityShape {
            annotations: None,
            type_name: RECORD_TYPE.to_string(),
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert(
                    "key".to_string(),
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
                    "value".to_string(),
                    EntityAttribute {
                        annotations: None,
                        type_name: STRING_TYPE.to_string(),
                        name: None,
                        required: true,
                        element: None,
                        attributes: None,
                    },
                );
                attrs
            },
        };

        // Create KeyValueStringSlice entity
        let key_val_string_slice_entity = EntityShape {
            annotations: None,
            type_name: RECORD_TYPE.to_string(),
            attributes: {
                let mut attrs = HashMap::new();
                attrs.insert(
                    "key".to_string(),
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
                    "value".to_string(),
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
                );
                attrs
            },
        };

        // Ensure common_types exists
        if ns.common_types.is_none() {
            ns.common_types = Some(HashMap::new());
        }

        // Add the entities to common_types
        if let Some(common_types) = &mut ns.common_types {
            common_types.insert("KeyValue".to_string(), key_val_entity);
            common_types.insert("KeyValueStringSlice".to_string(), key_val_string_slice_entity);
        }
    }
}

fn parse_crd_properties(max_depth: u32, properties: &Value) -> Result<HashMap<String, EntityAttribute>, anyhow::Error> {
    if max_depth == 0 {
        return Err(anyhow::anyhow!("max depth reached"));
    }

    let mut attr_map = HashMap::new();
    
    if let Value::Object(props) = properties {
        for (k, v) in props {
            // Skip if no type is specified
            if v.get("type").is_none() {
                eprintln!("Skipping attr with no type: {}, {:?}", k, v);
                continue;
            }

            let required = v.get("required")
                .and_then(|r| r.as_array())
                .map(|arr| arr.contains(&Value::String(k.clone())))
                .unwrap_or(false);

            match v.get("type").and_then(|t| t.as_str()) {
                Some("string") => {
                    attr_map.insert(
                        k.clone(),
                        EntityAttribute {
                            annotations: None,
                            type_name: STRING_TYPE.to_string(),
                            name: None,
                            required,
                            element: None,
                            attributes: None,
                        },
                    );
                }
                Some("integer") => {
                    attr_map.insert(
                        k.clone(),
                        EntityAttribute {
                            annotations: None,
                            type_name: LONG_TYPE.to_string(),
                            name: None,
                            required,
                            element: None,
                            attributes: None,
                        },
                    );
                }
                Some("boolean") => {
                    attr_map.insert(
                        k.clone(),
                        EntityAttribute {
                            annotations: None,
                            type_name: BOOL_TYPE.to_string(),
                            name: None,
                            required,
                            element: None,
                            attributes: None,
                        },
                    );
                }
                Some("array") => {
                    if let Some(items) = v.get("items") {
                        if let Some(item_type) = items.get("type").and_then(|t| t.as_str()) {
                            let element_type = match item_type {
                                "string" => STRING_TYPE.to_string(),
                                "integer" => LONG_TYPE.to_string(),
                                "boolean" => BOOL_TYPE.to_string(),
                                _ => {
                                    eprintln!("Skipping attr {} array of type {}, not implemented", k, item_type);
                                    continue;
                                }
                            };

                            attr_map.insert(
                                k.clone(),
                                EntityAttribute {
                                    annotations: None,
                                    type_name: SET_TYPE.to_string(),
                                    name: None,
                                    required,
                                    element: Some(Box::new(EntityAttributeElement {
                                        type_name: element_type,
                                        name: None,
                                    })),
                                    attributes: None,
                                },
                            );
                        }
                    }
                }
                Some("object") => {
                    // Special case for podTemplate
                    if k == "podTemplate" {
                        attr_map.insert(
                            k.clone(),
                            EntityAttribute {
                                annotations: None,
                                type_name: "core::v1::PodTemplate".to_string(),
                                name: None,
                                required,
                                element: None,
                                attributes: None,
                            },
                        );
                        continue;
                    }

                    if let Some(props) = v.get("properties") {
                        let attrs = parse_crd_properties(max_depth - 1, props)?;
                        attr_map.insert(
                            k.clone(),
                            EntityAttribute {
                                annotations: None,
                                type_name: RECORD_TYPE.to_string(),
                                name: None,
                                required,
                                element: None,
                                attributes: Some(attrs),
                            },
                        );
                    }
                }
                Some(attr_type) => {
                    eprintln!("Skipping attr {} type {}", k, attr_type);
                }
                None => {
                    eprintln!("Skipping attr {} with no type", k);
                }
            }
        }
    }

    Ok(attr_map)
}