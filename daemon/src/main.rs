mod analytics;
mod config;
mod model;
mod policy;
mod runtime;
mod service;

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::runtime::StubRuntime;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let config = Config::parse();
    if !config.stub_runtime {
        anyhow::bail!("real libbpf runtime wiring is staged but not enabled in this session");
    }

    let runtime = Arc::new(StubRuntime);

    Server::builder()
        .add_service(service::server(runtime, config.stream_interval_ms))
        .serve(config.listen)
        .await?;

    Ok(())
}
