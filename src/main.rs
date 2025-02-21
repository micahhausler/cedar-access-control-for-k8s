mod authorizer;
mod k8s_entities;
mod k8s_resource;
mod policy_store;
mod admission_handler;
mod admission_entities;
mod name_transform;
mod validation_handler;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use std::fs::File;
use std::sync::Arc;
use cedar_policy::{PolicySet, Schema, Validator};
use axum::routing::{post, get};
use axum::Router;
use env_logger;
use log::*;
use axum_server;
use axum_server::tls_rustls::RustlsConfig;
use rustls;


#[tokio::main]
async fn main() {
    /*
    Rust version TODOs:
    - Add config-file based policy loading
    - Add metrics
    - Tests for failure modes (don't panic, return errors)
    - Timeout querystring handling on /authorize 
    - Set default log level to info

    Design/discussion:
    - How to think about schema for request evaluation
    - Use partial evaluation and store residuals in a local short-term cache
     */

    // Initialize logging
    env_logger::init();
    info!("Starting cedar-k8s-webhook");

    // Initialize rustls crypto provider
    let provider = rustls::crypto::ring::default_provider();
    rustls::crypto::CryptoProvider::install_default(provider).expect("failed to install crypto provider");

    // Load TLS configuration
    let cert_path = std::env::var("TLS_CERT_PATH")
        .unwrap_or_else(|_| "./cedar-authorizer-server.crt".to_string());
    let key_path = std::env::var("TLS_KEY_PATH")
        .unwrap_or_else(|_| "./cedar-authorizer-server.key".to_string());

    // check that the cert and key files exist
    if !std::path::Path::new(&cert_path).exists() {
        error!("TLS certificate file does not exist: {}", cert_path);
        std::process::exit(1);
    }
    if !std::path::Path::new(&key_path).exists() {
        error!("TLS key file does not exist: {}", key_path);
        std::process::exit(1);
    }

    let tls_config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .unwrap_or_else(|e| {
            error!("Failed to load TLS configuration: {}", e);
            std::process::exit(1);
        });

    // Load schema for validation
    let schema_path = std::env::var("CEDAR_SCHEMA")
        .unwrap_or_else(|_| "./cedarschema/k8s-full.cedarschema".to_string());
    let schema_file = File::open(&schema_path)
        .expect("Failed to open schema file");
    let (schema, _warnings) = Schema::from_cedarschema_file(schema_file)
        .expect("Failed to parse schema");
    let schema = Arc::new(schema);
    let validator = Validator::new((*schema).clone());

    // Get policy directory from env var or use default
    let policy_dir = std::env::var("POLICY_DIR")
        .unwrap_or_else(|_| "./policies".to_string());
    info!("Loading policies from directory: {}", policy_dir);


    // Initialize policy stores
    let stores = policy_store::TieredPolicyStores::new(vec![Box::new(
        policy_store::DirectoryStore::new(Path::new(&policy_dir), Duration::from_secs(300))
            .unwrap_or_else(|e| {
                error!("Failed to initialize policy directory store from {}: {}", policy_dir, e);
                std::process::exit(1);
            }),
    )]);

    let allow_all_admission_policy_raw: &str = r#"
    @id("allow-all-admission")
    permit(
        principal,
        action in [
            k8s::admission::Action::"create",
            k8s::admission::Action::"update",
            k8s::admission::Action::"delete",
            k8s::admission::Action::"connect"
        ],
        resource
    );
    "#;
    let allow_all_admission_policy: PolicySet = allow_all_admission_policy_raw.parse().unwrap();

    let admission_stores = policy_store::TieredPolicyStores::new(vec![
        Box::new(policy_store::DirectoryStore::new(Path::new(&policy_dir), Duration::from_secs(300))
            .unwrap_or_else(|e| {
                error!("Failed to initialize policy directory store from {}: {}", policy_dir, e);
                std::process::exit(1);
            })),
        Box::new(policy_store::StaticStore::from(allow_all_admission_policy)),
    ]);

    let authorizer = authorizer::AuthorizerServer::new(stores, Some(schema.clone()));
    let admit_handler = admission_handler::AdmissionServer::new(admission_stores);
    let validation_server = validation_handler::ValidationServer::new(validator);

    // Create our application router
    let app = Router::new()
        .route(
            "/authorize",
            post(move |review| {
                let auth = authorizer.clone();
                async move {
                    auth.with_logging(review, authorizer::AuthorizerServer::authorize_handler)
                        .await
                }
            }),
        )
        .route(
            "/admit",
            post(move |review| {
                let admit = admit_handler.clone();
                async move {
                    admit.handle(review).await
                }
            }),
        )
        .route(
            "/validate",
            post(move |review| {
                let validator = validation_server.clone();
                async move {
                    validator.handle(review).await
                }
            }),
        )
        .route(
            "/healthz",
            get(|| async {
                "ok"
            }),
        );

    // Bind to address
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8443);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Starting TLS server on {}", addr);

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
