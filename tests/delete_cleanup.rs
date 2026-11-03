//! Deleting a sandbox never leaves a pod holding cluster resources behind.
//! Each test is one assertion of bd-ib-3i3j3k's Definition of Done.
//!
//! Gated on `SANDBOX_DRIVER_KUBERNETES_TEST_KUBECONFIG`, like the other
//! cluster tests. The workspace-contents checks also need
//! `SANDBOX_DRIVER_KUBERNETES_TEST_KIND_NODE`, the kind node's Docker
//! container, to read the node's workspace directory. Run with
//! `--test-threads 1`.

#![allow(
    clippy::field_reassign_with_default,
    reason = "non_exhaustive driver types are built field by field"
)]

mod support;

use std::collections::BTreeSet;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, DeleteParams, ListParams, PostParams};
use sandbox_driver::{Error, SandboxFilter, SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_kubernetes::KubernetesProvider;
use tokio::sync::Mutex;

const CLEANUP_OF_LABEL: &str = "sandbox-driver-kubernetes/cleanup-of";
const CLEANUP_OWNER_ANNOTATION: &str = "sandbox-driver-kubernetes/cleanup-owner";

fn spec() -> SandboxSpec {
    let mut spec = SandboxSpec::new(SandboxSource::Image {
        reference: support::TEST_IMAGE.to_owned(),
    })
    .working_directory("/workspace");
    spec.resources.cpu_cores = Some(1);
    spec.resources.memory_mb = Some(512);
    spec
}

fn pods(client: kube::Client) -> Api<Pod> {
    Api::<Pod>::namespaced(client, support::NAMESPACE)
}

async fn cleanup_pods(client: kube::Client, id: &str) -> Vec<Pod> {
    pods(client)
        .list(&ListParams::default().labels(&format!("{CLEANUP_OF_LABEL}={id}")))
        .await
        .expect("lists cleanup pods")
        .items
        .into_iter()
        .filter(|pod| pod.metadata.deletion_timestamp.is_none())
        .collect()
}

/// The entries of `dir` on the kind node, or `None` without a kind node.
fn node_entries(dir: &str) -> Option<Vec<String>> {
    let node = std::env::var("SANDBOX_DRIVER_KUBERNETES_TEST_KIND_NODE").ok()?;
    let output = Command::new("docker")
        .args(["exec", &node, "ls", "-A", dir])
        .output()
        .expect("runs docker");
    assert!(
        output.status.success(),
        "ls {dir} on the node: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect(),
    )
}

fn workspace_dir(id: &str) -> String {
    let root = support::config("path")
        .expect("config")
        .workspace_root
        .trim_end_matches('/')
        .to_owned();
    format!("{root}/{id}")
}

fn host() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .expect("reads hostname")
        .trim()
        .to_owned()
}

/// The start ticks of `pid`, as the plugin records a cleanup pod's owner.
fn start_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("reads stat");
    let rest = &stat[stat.rfind(')').expect("comm") + 1..];
    rest.split_whitespace()
        .nth(19)
        .expect("starttime")
        .parse()
        .expect("number")
}

/// An owner string naming a plugin process on this host that has ended.
fn ended_owner() -> String {
    let mut child = Command::new("true").spawn().expect("spawns");
    let pid = child.id();
    let ticks = start_ticks(pid);
    child.wait().expect("waits");
    format!("{}/{pid}/{ticks}", host())
}

/// An owner string naming this (live) test process.
fn live_owner() -> String {
    let pid = std::process::id();
    format!("{}/{pid}/{}", host(), start_ticks(pid))
}

/// A cleanup pod as an interrupted delete would leave it: still running.
async fn leave_cleanup_pod(client: kube::Client, id: &str, owner: &str) {
    let pod: Pod = serde_json::from_value(serde_json::json!({
        "metadata": {
            "name": format!("{id}-cleanup"),
            "labels": {
                "app.kubernetes.io/managed-by": "sandbox-driver-kubernetes",
                CLEANUP_OF_LABEL: id,
            },
            "annotations": { CLEANUP_OWNER_ANNOTATION: owner },
        },
        "spec": {
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 1,
            "automountServiceAccountToken": false,
            "containers": [{
                "name": "cleanup",
                "image": support::TEST_IMAGE,
                "command": ["/bin/sh", "-c", "sleep 3600"],
                "resources": {
                    "requests": { "cpu": "100m", "memory": "128Mi" },
                    "limits": { "cpu": "100m", "memory": "128Mi" },
                },
            }],
        },
    }))
    .expect("manifest");
    pods(client)
        .create(&PostParams::default(), &pod)
        .await
        .expect("creates the leftover cleanup pod");
}

/// A stopped sandbox: its pod is gone, its record and workspace remain.
async fn stopped_sandbox(provider: &KubernetesProvider) -> String {
    let sandbox = provider.create(&spec(), None).await.expect("creates");
    sandbox
        .fs()
        .write("work/progress.txt", b"implement stage output")
        .await
        .expect("writes");
    sandbox.stop().await.expect("stops");
    sandbox.id().as_str().to_owned()
}

/// Watches the namespace while a delete runs, collecting every pod it sees.
struct Watch {
    seen: Arc<Mutex<Vec<Pod>>>,
    done: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Watch {
    fn start(client: kube::Client) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let done = Arc::new(AtomicBool::new(false));
        let task = {
            let seen = Arc::clone(&seen);
            let done = Arc::clone(&done);
            tokio::spawn(async move {
                while !done.load(Ordering::SeqCst) {
                    if let Ok(list) = pods(client.clone()).list(&ListParams::default()).await {
                        seen.lock().await.extend(list.items);
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            })
        };
        Self { seen, done, task }
    }

    async fn stop(self) -> Vec<Pod> {
        self.done.store(true, Ordering::SeqCst);
        self.task.await.expect("watch ends");
        Arc::try_unwrap(self.seen).expect("sole owner").into_inner()
    }
}

fn quantities(pod: &Pod) -> BTreeSet<(String, String, String)> {
    let mut found = BTreeSet::new();
    for container in &pod.spec.as_ref().expect("spec").containers {
        let resources = container.resources.clone().unwrap_or_default();
        for (kind, map) in [
            ("requests", resources.requests),
            ("limits", resources.limits),
        ] {
            for (name, quantity) in map.unwrap_or_default() {
                found.insert((kind.to_owned(), name, quantity.0));
            }
        }
    }
    found
}

/// Assertion 1: deleting a sandbox whose pod is absent empties its node
/// workspace through a cleanup pod that requests at most 100m CPU and 128Mi
/// memory, not through a re-creation of the full sandbox pod.
#[tokio::test(flavor = "multi_thread")]
async fn a_stopped_sandbox_is_emptied_by_a_minimal_cleanup_pod() {
    let Some(provider) = support::provider("cleanup-minimal").await else {
        return;
    };
    let client = provider.client().current().await;
    let id = stopped_sandbox(&provider).await;
    if let Some(entries) = node_entries(&workspace_dir(&id)) {
        assert!(
            !entries.is_empty(),
            "the stopped sandbox's workspace holds its work"
        );
    }

    let watch = Watch::start(client.clone());
    provider
        .delete(
            &sandbox_driver::SandboxId::try_new(id.clone()).expect("id"),
            None,
        )
        .await
        .expect("deletes");
    let seen = watch.stop().await;

    assert!(
        !seen
            .iter()
            .any(|pod| pod.metadata.name.as_deref() == Some(id.as_str())),
        "the delete re-created the full sandbox pod"
    );
    let cleanup: Vec<&Pod> = seen
        .iter()
        .filter(|pod| pod.metadata.name.as_deref() == Some(format!("{id}-cleanup").as_str()))
        .collect();
    assert!(!cleanup.is_empty(), "the delete ran no cleanup pod");
    let expected = BTreeSet::from([
        ("limits".to_owned(), "cpu".to_owned(), "100m".to_owned()),
        ("limits".to_owned(), "memory".to_owned(), "128Mi".to_owned()),
        ("requests".to_owned(), "cpu".to_owned(), "100m".to_owned()),
        (
            "requests".to_owned(),
            "memory".to_owned(),
            "128Mi".to_owned(),
        ),
    ]);
    for pod in cleanup {
        assert_eq!(quantities(pod), expected, "cleanup pod resources");
    }
    assert!(
        cleanup_pods(client.clone(), &id).await.is_empty(),
        "the cleanup pod outlived the delete"
    );
    if let Some(entries) = node_entries(&workspace_dir(&id)) {
        assert!(entries.is_empty(), "workspace still holds {entries:?}");
    }
    assert!(
        matches!(
            provider
                .attach(&sandbox_driver::SandboxId::try_new(id).expect("id"), None)
                .await,
            Err(Error::NotFound { .. })
        ),
        "the record is gone"
    );
}

/// Assertion 2: a cleanup that does not finish within its window is removed,
/// and the delete fails naming the sandbox and the time it waited.
#[tokio::test(flavor = "multi_thread")]
async fn a_cleanup_past_its_window_is_removed_and_the_delete_fails() {
    let Some(mut config) = support::config("cleanup-window") else {
        return;
    };
    let provider = KubernetesProvider::connect(config.clone())
        .await
        .expect("connects");
    support::ensure_namespace(provider.client().current().await).await;
    let client = provider.client().current().await;
    let id = stopped_sandbox(&provider).await;
    drop(provider);

    config.cleanup_timeout_secs = 0;
    let impatient = KubernetesProvider::connect(config.clone())
        .await
        .expect("connects");
    let sandbox_id = sandbox_driver::SandboxId::try_new(id.clone()).expect("id");
    let error = impatient
        .delete(&sandbox_id, None)
        .await
        .expect_err("the cleanup cannot finish in no time");
    let message = error.to_string();
    assert!(matches!(error, Error::Timeout { .. }), "{message}");
    assert!(message.contains(&id), "names the sandbox: {message}");
    assert!(
        message.contains("timed out after"),
        "names the elapsed time: {message}"
    );
    assert!(
        cleanup_pods(client.clone(), &id).await.is_empty(),
        "no pod for the sandbox exists after the failed delete"
    );
    assert!(
        pods(client.clone())
            .get_opt(&id)
            .await
            .expect("reads")
            .is_none(),
        "no sandbox pod either"
    );

    // The record survives, so a patient delete finishes the job.
    config.cleanup_timeout_secs = 300;
    let patient = KubernetesProvider::connect(config).await.expect("connects");
    patient.delete(&sandbox_id, None).await.expect("deletes");
    assert!(cleanup_pods(client, &id).await.is_empty());
}

/// Assertion 3: a cleanup pod left by a delete whose plugin process ended is
/// removed by the next list, and by the next delete of that sandbox; one a
/// live process still owns is left to it.
#[tokio::test(flavor = "multi_thread")]
async fn an_interrupted_deletes_cleanup_pod_is_removed_by_the_next_call() {
    let Some(provider) = support::provider("cleanup-interrupted").await else {
        return;
    };
    let client = provider.client().current().await;
    let id = stopped_sandbox(&provider).await;

    // A live owner's cleanup is in progress: list leaves it alone.
    leave_cleanup_pod(client.clone(), &id, &live_owner()).await;
    provider
        .list(&SandboxFilter::default())
        .await
        .expect("lists");
    assert_eq!(cleanup_pods(client.clone(), &id).await.len(), 1);
    pods(client.clone())
        .delete(&format!("{id}-cleanup"), &DeleteParams::default())
        .await
        .expect("removes the live-owner fixture");
    for _ in 0..60 {
        if pods(client.clone())
            .get_opt(&format!("{id}-cleanup"))
            .await
            .expect("reads")
            .is_none()
        {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // An ended owner's cleanup is abandoned: the next list removes it.
    leave_cleanup_pod(client.clone(), &id, &ended_owner()).await;
    provider
        .list(&SandboxFilter::default())
        .await
        .expect("lists");
    assert!(
        cleanup_pods(client.clone(), &id).await.is_empty(),
        "list left an abandoned cleanup pod"
    );
    for _ in 0..60 {
        if pods(client.clone())
            .get_opt(&format!("{id}-cleanup"))
            .await
            .expect("reads")
            .is_none()
        {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // And the next delete of the sandbox removes one too, then finishes.
    leave_cleanup_pod(client.clone(), &id, &ended_owner()).await;
    provider
        .delete(
            &sandbox_driver::SandboxId::try_new(id.clone()).expect("id"),
            None,
        )
        .await
        .expect("deletes");
    assert!(
        pods(client.clone())
            .get_opt(&format!("{id}-cleanup"))
            .await
            .expect("reads")
            .is_none(),
        "the delete left the interrupted delete's cleanup pod"
    );
    if let Some(entries) = node_entries(&workspace_dir(&id)) {
        assert!(entries.is_empty(), "workspace still holds {entries:?}");
    }
}

/// Assertion 4: deleting a sandbox whose pod is running still empties its
/// workspace and removes the pod and its record.
#[tokio::test(flavor = "multi_thread")]
async fn a_running_sandbox_delete_empties_and_removes_everything() {
    let Some(provider) = support::provider("cleanup-running").await else {
        return;
    };
    let client = provider.client().current().await;
    let sandbox = provider.create(&spec(), None).await.expect("creates");
    sandbox
        .fs()
        .write("work/progress.txt", b"implement stage output")
        .await
        .expect("writes");
    let id = sandbox.id().clone();
    sandbox.delete().await.expect("deletes");
    assert!(
        pods(client.clone())
            .get_opt(id.as_str())
            .await
            .expect("reads")
            .is_none(),
        "the pod is gone"
    );
    assert!(cleanup_pods(client, id.as_str()).await.is_empty());
    if let Some(entries) = node_entries(&workspace_dir(id.as_str())) {
        assert!(entries.is_empty(), "workspace still holds {entries:?}");
    }
    assert!(
        matches!(
            provider.attach(&id, None).await,
            Err(Error::NotFound { .. })
        ),
        "the record is gone"
    );
}
