//! Shared fixtures for the cluster tests.

#![allow(dead_code, reason = "each test binary uses a subset")]

use std::path::PathBuf;

use k8s_openapi::api::core::v1::Namespace;
use sandbox_driver_kubernetes::{KubernetesConfig, KubernetesProvider};

pub const TEST_IMAGE: &str = "ghcr.io/lithoscomputer/ubuntu-24.04:slim-df708f910111";
pub const NAMESPACE: &str = "livespec-factory";

/// The test kubeconfig, when a cluster is available.
pub fn kubeconfig() -> Option<PathBuf> {
    std::env::var_os("SANDBOX_DRIVER_KUBERNETES_TEST_KUBECONFIG").map(PathBuf::from)
}

/// A configuration for the throwaway test cluster with a private state dir.
pub fn config(tag: &str) -> Option<KubernetesConfig> {
    let mut config = KubernetesConfig::default();
    config.kubeconfig = kubeconfig()?;
    config.namespace = NAMESPACE.to_owned();
    config.state_dir = std::env::temp_dir().join(format!("sdk-test-{tag}-{}", std::process::id()));
    config.workspace_root = "/var/lib/sandbox-driver-kubernetes/test-workspaces".to_owned();
    config.factory = Some("ci".to_owned());
    Some(config)
}

/// A provider over the test cluster, with its namespace in place.
pub async fn provider(tag: &str) -> Option<KubernetesProvider> {
    let provider = KubernetesProvider::connect(config(tag)?)
        .await
        .expect("connects");
    ensure_namespace(provider.client().current().await).await;
    Some(provider)
}

/// Test fixture: the throwaway cluster's sandbox namespace.
pub async fn ensure_namespace(client: kube::Client) {
    let api = kube::Api::<Namespace>::all(client);
    if api
        .get_opt(NAMESPACE)
        .await
        .expect("reads namespaces")
        .is_some()
    {
        return;
    }
    let namespace: Namespace =
        serde_json::from_value(serde_json::json!({ "metadata": { "name": NAMESPACE } }))
            .expect("manifest");
    match api
        .create(&kube::api::PostParams::default(), &namespace)
        .await
    {
        Ok(_) => {}
        Err(kube::Error::Api(status)) if status.code == 409 => {}
        Err(error) => panic!("creating the test namespace: {error}"),
    }
}
