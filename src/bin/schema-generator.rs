use anyhow::{Context, Result};
use cedar_k8s_webhook::schema::{self, convert, CedarSchema};
use kube::config::Config;
use log::{error, info};
use serde_json;
use std::env;
use std::fs;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "schema-generator",
    about = "Generate Cedar schema from Kubernetes OpenAPI"
)]
struct Opt {
    /// Namespace for authorization entities and actions
    #[structopt(long, default_value = "k8s")]
    authorization_namespace: String,

    /// Namespace for admission entities
    #[structopt(long, default_value = "k8s::admission")]
    admission_action_namespace: String,

    /// Add admission entities
    #[structopt(long)]
    admission: bool,

    /// File to read schema from
    #[structopt(long)]
    source_schema: Option<PathBuf>,

    /// File to write schema to
    #[structopt(long)]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let opt = Opt::from_args();

    // Create a new Cedar schema or load from source
    let mut cedar_schema = match &opt.source_schema {
        Some(path) => {
            let data = fs::read_to_string(path).context("Failed to read source schema")?;
            serde_json::from_str(&data).context("Failed to parse source schema")?
        }
        None => schema::new_cedar_schema(),
    };

    // Add authorization namespace
    cedar_schema.insert(
        opt.authorization_namespace.clone(),
        // TODO: Implement GetAuthorizationNamespace
        schema::CedarSchemaNamespace { 
            entity_types: Default::default(),
            actions: Default::default(),
            common_types: Default::default(),
            annotations: Default::default(),
        },
    );

    if opt.admission {
        if opt.admission_action_namespace == opt.authorization_namespace {
            error!("Admission and authorization namespaces cannot be the same");
            std::process::exit(1);
        }

        // TODO: Add admission actions
        // schema::AddAdmissionActions(
        //     &mut cedar_schema,
        //     &opt.admission_action_namespace,
        //     &opt.authorization_namespace,
        // );

        // Ensure the action namespace exists
        cedar_schema
            .entry(opt.admission_action_namespace.clone())
            .or_insert_with(|| schema::CedarSchemaNamespace {
                entity_types: Default::default(),
                actions: Default::default(),
                common_types: Default::default(),
                annotations: Default::default(),
            });

        // Load kubeconfig
        let config = Config::infer().await?;

        // Create schema getter
        let getter = convert::K8sSchemaGetter::new(config)
            .await
            .context("Failed to create schema getter")?;

        // Get all API versions
        info!("Fetching API versions");
        let api_groups = getter
            .get_all_versioned_schemas()
            .await
            .context("Failed to get API versions")?;

        // TODO: Process each API version
        // This would require implementing the rest of the getter methods
        // For now, just log the API groups
        info!("Found {} API groups", api_groups.len());
        for group in &api_groups {
            info!("API group: {}", group);
        }

        // TODO: Add connect entities
        // schema::AddConnectEntities(&mut cedar_schema);
    }

    // TODO: Implement sorting and other post-processing
    // cedar_schema.SortActionEntities();
    // schema::ModifyObjectMetaMaps(&mut cedar_schema);

    // Write schema to output
    let json = serde_json::to_string_pretty(&cedar_schema).context("Failed to serialize schema")?;

    match opt.output {
        Some(path) => {
            fs::write(path, json).context("Failed to write schema to file")?;
        }
        None => {
            println!("{}", json);
        }
    }

    Ok(())
} 