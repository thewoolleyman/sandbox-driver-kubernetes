//! A Kubernetes client that survives credential rotation.
//!
//! The kubeconfig is read from a file, never from the environment, and is
//! re-read whenever the API answers `401`: the request is then retried once
//! on a client built from the fresh file. When a refresh command is
//! configured it runs first, so a file that is only rewritten on demand (a
//! pull-on-401 credential) is current before it is re-read. A second consecutive `401` is
//! returned to the caller. This carries a control-plane reboot that rotates
//! the ServiceAccount token without restarting the plugin.
//!
//! A request whose CONNECTION is refused is retried under bounded
//! exponential backoff ([`ConnectRetry`]). A connect-phase failure means no
//! request reached the API server, so nothing it would have done can have
//! happened and retrying it is safe for every verb, including an exec start
//! and a create. Measured 2026-11-02 on gmktec: a k3s server restart left the
//! API unreachable for about 15 s and every live factory run failed on its
//! next exec start with `ServiceError: client error (Connect)`. A failure
//! after the connection was established (a dropped stream, a reset mid
//! response) is NOT retried, so a command that has started is never started
//! again.

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

/// The bounded backoff a connect-phase failure is retried under.
#[derive(Clone, Copy, Debug)]
pub struct ConnectRetry {
    /// The pause before the first retry; each later pause doubles.
    pub initial_delay: Duration,
    /// The longest single pause.
    pub max_delay: Duration,
    /// The total time spent waiting before the failure is returned.
    pub budget: Duration,
}

impl Default for ConnectRetry {
    /// Two minutes of total wait: a k3s server restart (about 15 s) and a
    /// flannel panic restart (about 17 s) both fit with room to spare.
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(10),
            budget: Duration::from_secs(120),
        }
    }
}

/// A connect-phase failure that outlasted the [`ConnectRetry`] budget. It
/// travels inside `kube::Error::Service` so every call site keeps its
/// `kube::Error` signature, and `kube_error` reads it back out.
#[derive(Debug, thiserror::Error)]
#[error("gave up after {attempts} attempts over {elapsed_secs:.1}s: {source}")]
pub struct ConnectRetryExhausted {
    pub attempts: u32,
    pub elapsed_secs: f64,
    #[source]
    pub source: kube::Error,
}

/// Whether `error` failed while CONNECTING, before any request was sent.
pub(crate) fn is_connect_failure(error: &kube::Error) -> bool {
    let kube::Error::Service(service) = error else {
        return false;
    };
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(service.as_ref());
    while let Some(current) = cause {
        if let Some(client) = current.downcast_ref::<hyper_util::client::legacy::Error>() {
            if client.is_connect() {
                return true;
            }
        }
        cause = current.source();
    }
    false
}

/// A reloading client over one kubeconfig file.
#[derive(Clone)]
pub struct KubeClient {
    path: PathBuf,
    context: Option<String>,
    inner: Arc<RwLock<Client>>,
    endpoint: Arc<RwLock<String>>,
    reloads: Arc<std::sync::atomic::AtomicU64>,
    refresh: Arc<Vec<String>>,
    refresh_timeout: Duration,
    connect_retry: ConnectRetry,
}

impl KubeClient {
    /// Builds a client from the kubeconfig at `path`.
    pub async fn from_file(path: PathBuf, context: Option<String>) -> Result<Self, ClientError> {
        let (client, endpoint) = build(&path, context.as_deref()).await?;
        Ok(Self {
            path,
            context,
            inner: Arc::new(RwLock::new(client)),
            endpoint: Arc::new(RwLock::new(endpoint)),
            reloads: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            refresh: Arc::new(Vec::new()),
            refresh_timeout: Duration::from_secs(60),
            connect_retry: ConnectRetry::default(),
        })
    }

    /// Sets the command run on a `401` before the kubeconfig is re-read.
    #[must_use]
    pub fn with_refresh(mut self, command: Vec<String>, timeout: Duration) -> Self {
        self.refresh = Arc::new(command);
        self.refresh_timeout = timeout;
        self
    }

    /// Sets the backoff a connect-phase failure is retried under.
    #[must_use]
    pub fn with_connect_retry(mut self, retry: ConnectRetry) -> Self {
        self.connect_retry = retry;
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

    /// The API server URL the current client addresses: the cluster half of
    /// the backend's resource identity. Non-secret, and unchanged by a token
    /// rotation that keeps the same cluster.
    pub async fn endpoint(&self) -> String {
        self.endpoint.read().await.clone()
    }

    /// How many times the kubeconfig has been re-read since start.
    pub fn reloads(&self) -> u64 {
        self.reloads.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Re-reads the kubeconfig file and replaces the client.
    pub async fn reload(&self) -> Result<(), ClientError> {
        let (client, endpoint) = build(&self.path, self.context.as_deref()).await?;
        *self.inner.write().await = client;
        *self.endpoint.write().await = endpoint;
        self.reloads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(path = %self.path.display(), "reloaded kubeconfig");
        Ok(())
    }

    /// Runs `call` with the current client. A connect-phase failure is
    /// retried under the [`ConnectRetry`] backoff; on `401` the kubeconfig
    /// is reloaded and the call runs once more.
    pub async fn call<T, F, Fut>(&self, call: F) -> Result<T, kube::Error>
    where
        F: Fn(Client) -> Fut,
        Fut: Future<Output = Result<T, kube::Error>>,
    {
        match self.connecting(&call).await {
            Err(error) if is_unauthorized(&error) => {
                tracing::warn!("the cluster answered 401; re-reading the kubeconfig");
                self.run_refresh().await;
                if let Err(reload) = self.reload().await {
                    tracing::error!(error = %reload, "re-reading the kubeconfig failed");
                    return Err(error);
                }
                self.connecting(&call).await
            }
            other => other,
        }
    }

    /// Runs `call`, retrying only failures to CONNECT.
    async fn connecting<T, F, Fut>(&self, call: &F) -> Result<T, kube::Error>
    where
        F: Fn(Client) -> Fut,
        Fut: Future<Output = Result<T, kube::Error>>,
    {
        let retry = self.connect_retry;
        let started = std::time::Instant::now();
        let mut delay = retry.initial_delay;
        let mut attempts: u32 = 0;
        loop {
            attempts += 1;
            match call(self.current().await).await {
                Err(error) if is_connect_failure(&error) => {
                    let waited = started.elapsed();
                    if waited + delay > retry.budget {
                        tracing::error!(attempts, elapsed_secs = waited.as_secs_f64(), %error, "the Kubernetes API stayed unreachable");
                        return Err(kube::Error::Service(Box::new(ConnectRetryExhausted {
                            attempts,
                            elapsed_secs: waited.as_secs_f64(),
                            source: error,
                        })));
                    }
                    tracing::warn!(attempts, delay_ms = delay.as_millis() as u64, %error, "the Kubernetes API refused the connection; retrying");
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(retry.max_delay);
                }
                other => return other,
            }
        }
    }
}

async fn build(
    path: &std::path::Path,
    context: Option<&str>,
) -> Result<(Client, String), ClientError> {
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
    let endpoint = config.cluster_url.to_string();
    let client = Client::try_from(config).map_err(|source| ClientError::Build {
        path: path.to_owned(),
        source: Box::new(source),
    })?;
    Ok((client, endpoint))
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

    /// A stand-in API server on `port` that starts listening only after
    /// `refuse_for`, answers every request with one Pod, and counts the
    /// requests it RECEIVED. `close_without_answer` instead drops each
    /// connection after reading the request, a failure after connecting.
    fn stand_in_api(
        port: u16,
        refuse_for: Duration,
        close_without_answer: bool,
    ) -> Arc<std::sync::atomic::AtomicU32> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let received = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter = received.clone();
        tokio::spawn(async move {
            tokio::time::sleep(refuse_for).await;
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .expect("bind the stand-in API");
            loop {
                let (mut socket, _) = listener.accept().await.expect("accept");
                let counter = counter.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0_u8; 8192];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if close_without_answer {
                        return;
                    }
                    let body = r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","namespace":"ns"}}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.ok();
                    socket.shutdown().await.ok();
                });
            }
        });
        received
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("probe port")
            .local_addr()
            .expect("addr")
            .port()
    }

    async fn client_for(port: u16, tag: &str) -> KubeClient {
        let dir = std::env::temp_dir().join(format!("sdk-retry-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("config");
        std::fs::write(
            &path,
            KUBECONFIG.replace("https://127.0.0.1:1", &format!("http://127.0.0.1:{port}")),
        )
        .expect("write");
        KubeClient::from_file(path, None).await.expect("client")
    }

    async fn get_pod(
        client: &KubeClient,
        invocations: &std::sync::atomic::AtomicU32,
    ) -> Result<k8s_openapi::api::core::v1::Pod, kube::Error> {
        client
            .call(|client| {
                invocations.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    kube::Api::<k8s_openapi::api::core::v1::Pod>::namespaced(client, "ns")
                        .get("p")
                        .await
                }
            })
            .await
    }

    /// The bd-ib-cakk3c scenario: the API refuses connections for 20 s (a
    /// k3s server restart measured about 15 s) and then accepts them. The
    /// request issued during the refusal succeeds under the DEFAULT backoff,
    /// and the server receives it exactly once.
    #[tokio::test]
    async fn a_request_issued_during_a_twenty_second_refusal_reaches_the_api_exactly_once() {
        let port = free_port();
        let received = stand_in_api(port, Duration::from_secs(20), false);
        let client = client_for(port, "twenty").await;
        let invocations = std::sync::atomic::AtomicU32::new(0);
        let started = std::time::Instant::now();
        let pod = get_pod(&client, &invocations)
            .await
            .expect("the request succeeds once the API is back");
        assert_eq!(pod.metadata.name.as_deref(), Some("p"));
        assert!(
            started.elapsed() >= Duration::from_secs(20),
            "it waited out the refusal"
        );
        assert!(
            invocations.load(std::sync::atomic::Ordering::SeqCst) > 1,
            "refused attempts were retried"
        );
        assert_eq!(
            received.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the API received the request exactly once"
        );
    }

    /// A refusal that outlasts the budget is returned as a retryable provider
    /// error naming the operation, the attempts and the elapsed time.
    #[tokio::test]
    async fn a_refusal_outlasting_the_budget_is_a_retryable_error_naming_attempts_and_time() {
        let port = free_port();
        let client = client_for(port, "exhausted")
            .await
            .with_connect_retry(ConnectRetry {
                initial_delay: Duration::from_millis(50),
                max_delay: Duration::from_millis(200),
                budget: Duration::from_secs(1),
            });
        let invocations = std::sync::atomic::AtomicU32::new(0);
        let error = get_pod(&client, &invocations)
            .await
            .expect_err("the API never came back");
        let attempts = invocations.load(std::sync::atomic::Ordering::SeqCst);
        assert!(attempts > 1);
        match crate::error::kube_error("reading the sandbox pod", error) {
            sandbox_driver::Error::Provider(provider) => {
                assert!(provider.retryable, "an unreachable API is retryable");
                assert_eq!(provider.code.as_deref(), Some("api-unreachable"));
                let message = provider.to_string();
                assert!(message.contains("reading the sandbox pod"), "{message}");
                assert!(
                    message.contains(&format!("all {attempts} attempts")),
                    "{message}"
                );
                assert!(message.contains("s:"), "{message}");
            }
            other => panic!("expected a retryable provider error, got {other:?}"),
        }
    }

    /// A failure AFTER the connection was accepted is not retried: the
    /// request may already have taken effect.
    #[tokio::test]
    async fn a_failure_after_connecting_is_not_retried() {
        let port = free_port();
        let received = stand_in_api(port, Duration::ZERO, true);
        tokio::time::sleep(Duration::from_millis(200)).await;
        let client = client_for(port, "after").await;
        let invocations = std::sync::atomic::AtomicU32::new(0);
        let error = get_pod(&client, &invocations)
            .await
            .expect_err("the server dropped the connection");
        assert!(!is_connect_failure(&error), "{error}");
        assert_eq!(
            invocations.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "no retry after connecting"
        );
        assert_eq!(received.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
