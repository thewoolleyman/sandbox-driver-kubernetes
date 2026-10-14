//! Assertion 5: a sandbox whose node goes NotReady is reported unavailable,
//! not lost, and a command against it fails retryably without creating a
//! replacement pod.
//!
//! Needs `SANDBOX_DRIVER_KUBERNETES_TEST_KIND_NODE` naming the kind node's
//! Docker container, whose kubelet the test stops and restarts. It runs last
//! (test binaries run in name order) because it takes the node down.

mod support;

use std::process::Command;
use std::time::Duration;

use k8s_openapi::api::core::v1::{Node, Pod};
use kube::api::{Api, ListParams};
use sandbox_driver::{Error, ExecSpec, SandboxProvider, SandboxSource, SandboxSpec, SandboxState};

fn kubelet(container: &str, action: &str) {
    let status = Command::new("docker")
        .args(["exec", container, "systemctl", action, "kubelet"])
        .status()
        .expect("runs docker");
    assert!(status.success(), "systemctl {action} kubelet");
}

async fn node_ready(client: kube::Client) -> bool {
    Api::<Node>::all(client)
        .list(&ListParams::default())
        .await
        .expect("lists nodes")
        .items
        .iter()
        .all(|node| {
            node.status
                .as_ref()
                .and_then(|status| status.conditions.as_ref())
                .is_some_and(|conditions| {
                    conditions
                        .iter()
                        .any(|c| c.type_ == "Ready" && c.status == "True")
                })
        })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_not_ready_node_makes_its_sandbox_unavailable_not_lost() {
    let Some(container) = std::env::var_os("SANDBOX_DRIVER_KUBERNETES_TEST_KIND_NODE") else {
        return;
    };
    let container = container.to_string_lossy().into_owned();
    let Some(provider) = support::provider("node-loss").await else {
        return;
    };
    let client = provider.client().current().await;
    let sandbox = provider
        .create(
            &SandboxSpec::new(SandboxSource::Image {
                reference: support::TEST_IMAGE.to_owned(),
            })
            .working_directory("/workspace"),
            None,
        )
        .await
        .expect("creates");
    let pods = Api::<Pod>::namespaced(client.clone(), support::NAMESPACE);
    let before = pods
        .list(&ListParams::default())
        .await
        .expect("lists")
        .items
        .len();

    kubelet(&container, "stop");
    let mut not_ready = false;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        if !node_ready(client.clone()).await {
            not_ready = true;
            break;
        }
    }
    assert!(not_ready, "the node went NotReady");

    let status = sandbox.describe().await.expect("describes");
    assert_ne!(status.state, SandboxState::Deleted);
    assert_ne!(status.state, SandboxState::Error);
    assert_eq!(status.provider_state, "unavailable", "{status:?}");

    let error = sandbox
        .exec()
        .run(&ExecSpec::new("true").timeout(Duration::from_secs(60)))
        .await
        .expect_err("exec cannot reach a NotReady node");
    match &error {
        Error::Provider(provider) => assert!(provider.retryable, "{error}"),
        other => panic!("expected a retryable provider error, got {other}"),
    }
    let start = sandbox.start().await;
    assert!(
        start.is_ok() || matches!(&start, Err(Error::Provider(p)) if p.retryable),
        "{start:?}"
    );
    let after = pods
        .list(&ListParams::default())
        .await
        .expect("lists")
        .items
        .len();
    assert_eq!(after, before, "no replacement pod was created");

    kubelet(&container, "start");
    for _ in 0..60 {
        if node_ready(client.clone()).await {
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    sandbox
        .delete()
        .await
        .expect("deletes once the node is back");
}
