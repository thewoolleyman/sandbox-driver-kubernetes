//! A Kubernetes client that survives credential rotation.
//!
//! The kubeconfig is read from a file, never from the environment, and is
//! re-read whenever the API answers `401`: the request is then retried once
//! on a client built from the fresh file. When a refresh command is
//! configured it runs first, so a file that is only rewritten on demand (a
//! pull-on-401 credential) is current before it is re-read. A second consecutive `401` is
//! returned to the caller. This carries a control-plane reboot that rotates
//! the ServiceAccount token without restarting the plugin.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

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
    refresh: Arc<Vec<String>>,
    refresh_timeout: Duration,
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
            refresh: Arc::new(Vec::new()),
            refresh_timeout: Duration::from_secs(60),
        })
    }

    /// Sets the command run on a `401` before the kubeconfig is re-read.
    #[must_use]
    pub fn with_refresh(mut self, command: Vec<String>, timeout: Duration) -> Self {
        self.refresh = Arc::new(command);
        self.refresh_timeout = timeout;
        self
    }

    /// Runs the refresh command, if one is configured. A failure is logged
    /// and the file is re-read anyway: the retry then reports the real state.
    async fn run_refresh(&self) {
        let Some((program, args)) = self.refresh.split_first() else {
            return;
        };
        let mut command = tokio::process::Command::new(program);
        command
            .args(args)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        match tokio::time::timeout(self.refresh_timeout, command.output()).await {
            Ok(Ok(output)) if output.status.success() => {
                tracing::info!(program = %program, "refreshed the kubeconfig");
            }
            Ok(Ok(output)) => tracing::error!(
                program = %program,
                status = %output.status,
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "the kubeconfig refresh command failed"
            ),
            Ok(Err(error)) => {
                tracing::error!(program = %program, %error, "could not run the kubeconfig refresh command");
            }
            Err(_) => tracing::error!(
                program = %program,
                timeout_secs = self.refresh_timeout.as_secs(),
                "the kubeconfig refresh command timed out"
            ),
        }
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
                self.run_refresh().await;
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

#[cfg(test)]
mod tests {
    use super::*;

    const KUBECONFIG: &str = "apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    server: https://127.0.0.1:1\ncontexts:\n- name: x\n  context:\n    cluster: c\n    user: u\ncurrent-context: x\nusers:\n- name: u\n  user:\n    token: t\n";

    #[tokio::test]
    async fn the_refresh_command_runs_and_a_failing_one_is_survived() {
        let dir = std::env::temp_dir().join(format!("sdk-refresh-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("config");
        std::fs::write(&path, KUBECONFIG).expect("write");
        let marker = dir.join("refreshed");
        let client = KubeClient::from_file(path, None)
            .await
            .expect("client")
            .with_refresh(
                vec![
                    "/bin/sh".to_owned(),
                    "-c".to_owned(),
                    format!("touch {}", marker.display()),
                ],
                Duration::from_secs(10),
            );
        client.run_refresh().await;
        assert!(marker.exists(), "the configured command ran");

        let failing = client.with_refresh(vec!["/bin/false".to_owned()], Duration::from_secs(10));
        failing.run_refresh().await;
        let silent = failing.with_refresh(Vec::new(), Duration::from_secs(10));
        silent.run_refresh().await;
        std::fs::remove_dir_all(&dir).ok();
    }
}
