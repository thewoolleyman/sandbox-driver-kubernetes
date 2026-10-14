//! The Kubernetes provider served as a sandbox-driver plugin.
//!
//! Speaks the JSON-RPC plugin protocol on stdin/stdout. Configuration comes
//! from `$HOME/.config/sandbox-driver-kubernetes/config.toml`; the cluster
//! credential from the kubeconfig file it names. Stdout belongs to the
//! protocol; logs go to stderr.

use std::io::stderr;
use std::sync::Arc;

use anyhow::Context as _;
use sandbox_driver_kubernetes::{KubernetesConfig, KubernetesProvider};
use sandbox_driver_protocol::serve_stdio;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_writer(stderr))
        .try_init()
        .context("configuring kubernetes plugin diagnostics")?;
    let config = KubernetesConfig::load().context("loading the plugin configuration")?;
    tracing::info!(provider_kind = "kubernetes", namespace = %config.namespace, "kubernetes plugin starting");
    let provider = KubernetesProvider::connect(config)
        .await
        .context("connecting to the cluster")?;
    serve_stdio(Arc::new(provider))
        .await
        .context("serving the kubernetes provider plugin")
}
