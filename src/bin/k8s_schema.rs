use anyhow::Result;
use kube::config::Config;
use cedar_k8s_webhook::schema::convert::openapi::{K8sSchemaGetter,modify_schema_for_api_version};
use rustls::crypto::ring::default_provider;
use cedar_k8s_webhook::schema::k8s::k8s_schema;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize rustls crypto provider
    default_provider().install_default().unwrap();
    
    // Load the Kubernetes configuration
    let config = Config::infer().await?;
    
    // Create a new K8sSchemaGetter instance
    let schema_getter = K8sSchemaGetter::new(config).await?;
    
    let mut api_groups = schema_getter.get_all_versioned_schemas().await?;
    api_groups.sort();
    
    // let mut cedar_schema: HashMap<String, cedar_k8s_webhook::schema::CedarSchemaNamespace> = CedarSchema::new();
    let mut cedar_schema= k8s_schema("k8s");
    let mut api_name_versions = HashMap::new();

    for api_group in api_groups.clone() {
        match api_group.as_str() {
            "api/v1" => {
                api_name_versions.insert(api_group, ("core".to_string(), "v1".to_string()));
            }
            "apis/apiextensions.k8s.io/v1" =>{
                continue
            }
            _ => {
                let parts = api_group.split('/').collect::<Vec<&str>>();
                api_name_versions.insert(api_group.clone(), (parts[1].to_string(), parts[2].to_string()));
            }
        }
    }
    let action_namespace = "k8s::admission";

    for api_group in api_groups {
        if api_group == "apis/apiextensions.k8s.io/v1" {
            continue;
        }
        let (api_name, api_version) = api_name_versions.get(&api_group).cloned().unwrap();
        eprintln!("Fetching schema for API: {}", api_group);
        let open_api_spec = schema_getter.get_api_schema(&api_group).await?;
        eprintln!("Converting schema for API: {}", api_group);
        let api_resource_list = schema_getter.api_resource_list(&api_group).await?;

        eprintln!("Modifying schema for API: {}", api_group);
        modify_schema_for_api_version(&api_resource_list, &open_api_spec, &mut cedar_schema, &api_name, &api_version, action_namespace).await?;
    }
    // TODO add connect entities

    // Sort action entities
    cedar_k8s_webhook::schema::sort_action_entities(&mut cedar_schema);

    // Modify object meta maps
    cedar_k8s_webhook::schema::convert::openapi::modify_object_meta_maps(&mut cedar_schema);
    
    // Pretty print the Cedar schema as JSON
    let schema_json = serde_json::to_string_pretty(&cedar_schema)
        .unwrap_or_else(|e| format!("Error serializing schema: {}", e));
    eprintln!("Cedar Schema:");
    println!("{}", schema_json);
    Ok(())
}
