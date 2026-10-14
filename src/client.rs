//! A Kubernetes client that survives credential rotation.
//!
//! The kubeconfig is read from a file, never from the environment, and is
//! re-read whenever the API answers `401`: the request is then retried once
//! on a client built from the fresh file. A second consecutive `401` is
//! returned to the caller. This carries a control-plane reboot that rotates
//! the ServiceAccount token without restarting the plugin.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config};
use tokio::sync::RwLock;

use crate::error::is_unauthorized;

/// Errors building a client from the kubeconfig file.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("reading kubeconfig {path}: {source}")]
    Read {
        path: PathBuf,
        source: kube::config::KubeconfigError,
    },
    #[error("building a client from kubeconfig {path}: {source}")]
    Build {
        path: PathBuf,
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// A reloading client over one kubeconfig file.
#[derive(Clone)]
pub struct KubeClient {
    path: PathBuf,
    context: Option<String>,
    inner: Arc<RwLock<Client>>,
    reloads: Arc<std::sync::atomic::AtomicU64>,
}

impl KubeClient {
    /// Builds a client from the kubeconfig at `path`.
    pub async fn from_file(path: PathBuf, context: Option<String>) -> Result<Self, ClientError> {
        let client = build(&path, context.as_deref()).await?;
        Ok(Self {
            path,
            context,
            inner: Arc::new(RwLock::new(client)),
            reloads: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// The current client.
    pub async fn current(&self) -> Client {
        self.inner.read().await.clone()
    }

    /// How many times the kubeconfig has been re-read since start.
    pub fn reloads(&self) -> u64 {
        self.reloads.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Re-reads the kubeconfig file and replaces the client.
    pub async fn reload(&self) -> Result<(), ClientError> {
        let client = build(&self.path, self.context.as_deref()).await?;
        *self.inner.write().await = client;
        self.reloads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(path = %self.path.display(), "reloaded kubeconfig");
        Ok(())
    }

    /// Runs `call` with the current client; on `401`, reloads the
    /// kubeconfig and runs it once more.
    pub async fn call<T, F, Fut>(&self, call: F) -> Result<T, kube::Error>
    where
        F: Fn(Client) -> Fut,
        Fut: Future<Output = Result<T, kube::Error>>,
    {
        match call(self.current().await).await {
            Err(error) if is_unauthorized(&error) => {
                tracing::warn!("the cluster answered 401; re-reading the kubeconfig");
                if let Err(reload) = self.reload().await {
                    tracing::error!(error = %reload, "re-reading the kubeconfig failed");
                    return Err(error);
                }
                call(self.current().await).await
            }
            other => other,
        }
    }
}

async fn build(path: &std::path::Path, context: Option<&str>) -> Result<Client, ClientError> {
    let kubeconfig = Kubeconfig::read_from(path).map_err(|source| ClientError::Read {
        path: path.to_owned(),
        source,
    })?;
    let options = KubeConfigOptions {
        context: context.map(str::to_owned),
        ..KubeConfigOptions::default()
    };
    let config = Config::from_custom_kubeconfig(kubeconfig, &options)
        .await
        .map_err(|source| ClientError::Build {
            path: path.to_owned(),
            source: Box::new(source),
        })?;
    Client::try_from(config).map_err(|source| ClientError::Build {
        path: path.to_owned(),
        source: Box::new(source),
    })
}
