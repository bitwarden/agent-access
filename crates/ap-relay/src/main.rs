use ap_relay::server::RelayServer;
use ap_relay_protocol::RelayError;
use std::env;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<(), RelayError> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let bind_addr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .expect("Invalid BIND_ADDR");

    tracing::info!("Starting relay server on {}", bind_addr);

    let server = RelayServer::new(bind_addr);

    tokio::select! {
        result = server.run() => {
            tracing::info!("Server stopped");
            result
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received shutdown signal");
            Ok(())
        }
    }
}
