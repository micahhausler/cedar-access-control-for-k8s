mod authorizer;
mod k8s_entities;
mod k8s_resource;
mod policy_store;
mod admission_handler;
mod admission_entities;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use axum::routing::post;
use axum::Router;
use env_logger;
use log::*;
use tokio::net::TcpListener;

use cedar_policy::PolicySet;

#[tokio::main]
async fn main() {
    /*
    Rust version TODOs:
    - Add a health check endpoint
    - Add config-file based policy loading
    - Add TLS
    - Add metrics
    - Add flags for port/tls certs
    - Add admission support
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

    // Initialize policy stores
    let stores = policy_store::TieredPolicyStores::new(vec![Box::new(
        policy_store::DirectoryStore::new(Path::new("./policies"), Duration::from_secs(10)),
    )]);

    let allow_all_admission_policy_raw: &str = r#"
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
        Box::new(policy_store::DirectoryStore::new(Path::new("./admission_policies"), Duration::from_secs(10))),
        Box::new(policy_store::StaticStore::from(allow_all_admission_policy)),
    ]);

    let authorizer = authorizer::AuthorizerServer::new(stores);
    let admit_handler = admission_handler::AdmissionServer::new(admission_stores);

    // Create our application router
    let mut app = Router::new().route(
        "/authorize",
        post(move |review| {
            let auth = authorizer.clone();
            async move {
                auth.with_logging(review, authorizer::AuthorizerServer::authorize_handler)
                    .await
            }
        }),
    );
    app = app.route(
        "/admit",
        post(move |review| {
            let admit = admit_handler.clone();
            async move {
                admit.handle(review)
                    .await
            }
        }),
    );

    // Bind to address
    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    let listener = TcpListener::bind(addr).await.unwrap();
    info!("Starting server on {}", addr);

    axum::serve(listener, app).await.unwrap();
}
