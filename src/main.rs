mod authorizer;
mod k8s_entities;
mod k8s_resource;
mod policy_store;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use axum::routing::post;
use axum::Router;
use env_logger;
use log::*;
use tokio::net::TcpListener;

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

    let authorizer = authorizer::AuthorizerServer::new(stores);

    // Create our application router
    let app = Router::new().route(
        "/authorize",
        post(move |review| {
            let auth = authorizer.clone();
            async move {
                auth.with_logging(review, authorizer::AuthorizerServer::authorize_handler)
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
