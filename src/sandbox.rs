//! The pod-backed sandbox handle.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, Patch, PatchParams};
use sandbox_driver::{
    Action, Capabilities, Error, EventEmitter, EventSubject, Exec, ExecSpec, Filesystem,
    NetworkPolicy, PlatformInfo, Result, Sandbox, SandboxId, SandboxKind, SandboxState,
    SandboxStatus,
};
use tokio::sync::Mutex;

use crate::error::{kube_error, provider, record_io};
use crate::exec::{KubernetesExec, shell_quote};
use crate::fs::KubernetesFs;
use crate::pod::{
    Cluster, Incarnation, NodeHealth, build_network_policy, build_pod, node_unavailable,
    object_labels,
};
use crate::record::{Record, RecordStore};
use crate::{LABELS_ANNOTATION, RUNTIME_DIRECTORY};

/// Timeouts a handle applies to lifecycle operations.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timeouts {
    pub(crate) start: Duration,
    pub(crate) stop: Duration,
}

/// A sandbox backed by one pod and its host-side record.
pub struct KubernetesSandbox {
    pub(crate) id: SandboxId,
    pub(crate) capabilities: Capabilities,
    pub(crate) cluster: Cluster,
    pub(crate) store: RecordStore,
    pub(crate) record: Mutex<Record>,
    pub(crate) working_dir: String,
    pub(crate) exec: Arc<KubernetesExec>,
    pub(crate) fs: KubernetesFs,
    pub(crate) timeouts: Timeouts,
    pub(crate) events: EventEmitter,
}

impl KubernetesSandbox {
    pub(crate) fn new(
        record: Record,
        cluster: Cluster,
        store: RecordStore,
        capabilities: Capabilities,
        timeouts: Timeouts,
        events: EventEmitter,
    ) -> Result<Self> {
        let id = SandboxId::try_new(record.id.clone())
            .map_err(|error| Error::invalid_spec("id", error.to_string()))?;
        let exec = Arc::new(KubernetesExec::new(
            cluster.clone(),
            record.id.clone(),
            record.working_dir.clone(),
            record.node.clone(),
        ));
        let fs = KubernetesFs::new(Arc::clone(&exec) as Arc<dyn Exec>);
        Ok(Self {
            id,
            capabilities,
            cluster,
            store,
            working_dir: record.working_dir.clone(),
            record: Mutex::new(record),
            exec,
            fs,
            timeouts,
            events,
        })
    }

    /// Creates the pod for `record` and waits for it to run; records the
    /// node it landed on.
    pub(crate) async fn launch(&self, incarnation: Incarnation) -> Result<()> {
        let snapshot = self.record.lock().await.clone();
        let pod = build_pod(&snapshot, incarnation)?;
        self.cluster
            .apply_network_policy(&snapshot.id, build_network_policy(&snapshot)?.as_ref())
            .await?;
        self.cluster.create_pod(&pod).await?;
        let node = self
            .cluster
            .wait_running(&snapshot.id, self.timeouts.start)
            .await?;
        let mut record = self.record.lock().await;
        if record.node.as_deref() != Some(node.as_str()) {
            record.node = Some(node);
            self.store
                .save(&record)
                .map_err(|error| record_io("recording the sandbox node", error))?;
        }
        Ok(())
    }

    /// Re-creates the pod from the record; the start half of the fence.
    async fn start_inner(&self) -> Result<()> {
        if let Some(pod) = self.cluster.get_pod(self.id.as_str()).await? {
            if pod.metadata.deletion_timestamp.is_some() {
                return Err(provider(format!(
                    "pod {} is still terminating; refusing to start a second writer on its workspace",
                    self.id
                )));
            }
            let phase = pod
                .status
                .and_then(|status| status.phase)
                .unwrap_or_default();
            if phase == "Running" || phase == "Pending" {
                self.cluster
                    .wait_running(self.id.as_str(), self.timeouts.start)
                    .await?;
                return Ok(());
            }
            // A pod that ended on its own is replaced over the same workspace.
            self.cluster
                .delete_pod_and_wait(self.id.as_str(), self.timeouts.stop)
                .await?;
        }
        let node = self.record.lock().await.node.clone();
        let incarnation = match node {
            None => Incarnation::First,
            Some(node) => match self.cluster.node_ready(&node).await? {
                NodeHealth::Ready => Incarnation::Recreate,
                NodeHealth::NotReady => return Err(node_unavailable(self.id.as_str(), &node)),
                NodeHealth::Gone => {
                    return Err(provider(format!(
                        "sandbox {} is lost: its node {node} has left the cluster with its workspace",
                        self.id
                    )));
                }
            },
        };
        self.launch(incarnation).await
    }

    /// Empties the workspace through the running pod, best effort.
    async fn clear_workspace(&self) {
        let script = format!(
            "find {} -mindepth 1 -maxdepth 1 -exec rm -rf {{}} + 2>/dev/null; true",
            shell_quote(&self.working_dir)
        );
        let spec = ExecSpec::new("/bin/sh")
            .args(["-c".to_owned(), script])
            .timeout(Duration::from_secs(120));
        if let Err(error) = self.exec.run(&spec).await {
            tracing::warn!(sandbox_id = %self.id, error = %error, "emptying the workspace failed");
        }
    }

    pub(crate) async fn delete_inner(&self) -> Result<()> {
        let pod = self.cluster.get_pod(self.id.as_str()).await?;
        let running = pod
            .as_ref()
            .and_then(|pod| pod.status.as_ref())
            .and_then(|status| status.phase.as_deref())
            == Some("Running");
        if running {
            self.clear_workspace().await;
        } else {
            // The workspace lives on the node; bring a pod back over it so it
            // can be emptied, unless the node cannot run one.
            let node = self.record.lock().await.node.clone();
            if let Some(node) = node {
                if pod.is_none()
                    && self.cluster.node_ready(&node).await? == NodeHealth::Ready
                    && self.launch(Incarnation::Recreate).await.is_ok()
                {
                    self.clear_workspace().await;
                }
            }
        }
        self.cluster
            .delete_pod_and_wait(self.id.as_str(), self.timeouts.stop)
            .await?;
        self.cluster
            .apply_network_policy(self.id.as_str(), None)
            .await?;
        self.store
            .remove(self.id.as_str())
            .map_err(|error| record_io("removing the sandbox record", error))
    }

    pub(crate) async fn status(&self) -> Result<SandboxStatus> {
        let record = self.record.lock().await.clone();
        let pod = self.cluster.get_pod(self.id.as_str()).await?;
        let mut status = status_of(&self.id, &record, pod.as_ref());
        let node = pod
            .as_ref()
            .and_then(|pod| pod.spec.as_ref())
            .and_then(|spec| spec.node_name.clone())
            .or(record.node.clone());
        if let Some(node) = node {
            if self.cluster.node_ready(&node).await? == NodeHealth::NotReady {
                status.state = SandboxState::Unknown;
                status.provider_state = "unavailable".to_owned();
                status.error_reason = Some(format!(
                    "node {node} is NotReady; the workspace is unreachable but not known lost"
                ));
            }
        }
        Ok(status)
    }
}

/// The status a record and its (possibly absent) pod imply.
pub(crate) fn status_of(id: &SandboxId, record: &Record, pod: Option<&Pod>) -> SandboxStatus {
    let (state, provider_state) = match pod {
        None => (SandboxState::Stopped, "no-pod".to_owned()),
        Some(pod) if pod.metadata.deletion_timestamp.is_some() => {
            (SandboxState::Stopping, "terminating".to_owned())
        }
        Some(pod) => {
            let phase = pod
                .status
                .as_ref()
                .and_then(|status| status.phase.clone())
                .unwrap_or_else(|| "Unknown".to_owned());
            let state = match phase.as_str() {
                "Running" => SandboxState::Running,
                "Pending" => SandboxState::Starting,
                "Succeeded" => SandboxState::Stopped,
                "Failed" => SandboxState::Error,
                _ => SandboxState::Unknown,
            };
            (state, phase)
        }
    };
    let mut status = SandboxStatus::new(id.clone(), state);
    status.provider_state = provider_state;
    status.name.clone_from(&record.name);
    status.labels = record.labels.clone();
    status.resources = Some(record.resources);
    status.sandbox_kind = Some(SandboxKind::Container);
    status.image = Some(record.image.clone());
    status
}

#[async_trait]
impl Sandbox for KubernetesSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    async fn describe(&self) -> Result<SandboxStatus> {
        self.status().await
    }

    fn working_directory(&self) -> &str {
        &self.working_dir
    }

    fn runtime_directory(&self) -> Option<&str> {
        Some(RUNTIME_DIRECTORY)
    }

    async fn environment(&self) -> Result<BTreeMap<String, String>> {
        Ok(self.record.lock().await.env.clone())
    }

    async fn platform_info(&self) -> Result<PlatformInfo> {
        let result = self
            .exec
            .run(
                &ExecSpec::new("uname")
                    .args(["-s", "-r", "-m"])
                    .timeout(Duration::from_secs(30)),
            )
            .await?;
        let text = result.stdout_lossy();
        let mut parts = text.split_whitespace();
        let os = parts.next().unwrap_or("linux").to_lowercase();
        let version = parts.next().unwrap_or("").to_owned();
        let arch = parts.next().unwrap_or("").to_owned();
        Ok(PlatformInfo::new(os, arch, version))
    }

    async fn start(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Start,
                |_| self.start_inner(),
            )
            .await
    }

    async fn stop(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Stop,
                |_| async {
                    self.cluster
                        .delete_pod_and_wait(self.id.as_str(), self.timeouts.stop)
                        .await
                },
            )
            .await
    }

    async fn delete(&self) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::Delete,
                |_| self.delete_inner(),
            )
            .await
    }

    async fn set_labels(&self, labels: &BTreeMap<String, String>) -> Result<()> {
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::SetLabels,
                |_| async {
                    let mut updated = self.record.lock().await.clone();
                    updated.labels = labels.clone();
                    let new_labels = object_labels(&updated)?;
                    let previous = self.record.lock().await.clone();
                    let mut patch_labels = serde_json::Map::new();
                    for key in object_labels(&previous)?.keys() {
                        if !new_labels.contains_key(key) {
                            patch_labels.insert(key.clone(), serde_json::Value::Null);
                        }
                    }
                    for (key, value) in &new_labels {
                        patch_labels.insert(key.clone(), serde_json::Value::String(value.clone()));
                    }
                    let mut patch_annotations = serde_json::Map::new();
                    for key in previous.labels.keys() {
                        if !labels.contains_key(key) {
                            patch_annotations.insert(key.clone(), serde_json::Value::Null);
                        }
                    }
                    for (key, value) in labels {
                        patch_annotations
                            .insert(key.clone(), serde_json::Value::String(value.clone()));
                    }
                    patch_annotations.insert(
                        LABELS_ANNOTATION.to_owned(),
                        serde_json::Value::String(
                            serde_json::to_string(labels)
                                .map_err(|error| provider(error.to_string()))?,
                        ),
                    );
                    let patch = serde_json::json!({
                        "metadata": { "labels": patch_labels, "annotations": patch_annotations }
                    });
                    self.store
                        .save(&updated)
                        .map_err(|error| record_io("recording the sandbox labels", error))?;
                    *self.record.lock().await = updated;
                    if self.cluster.get_pod(self.id.as_str()).await?.is_some() {
                        let namespace = self.cluster.namespace.clone();
                        let name = self.id.as_str().to_owned();
                        self.cluster
                            .client
                            .call(|client| {
                                let namespace = namespace.clone();
                                let name = name.clone();
                                let patch = patch.clone();
                                async move {
                                    Api::<Pod>::namespaced(client, &namespace)
                                        .patch(
                                            &name,
                                            &PatchParams::default(),
                                            &Patch::Merge(&patch),
                                        )
                                        .await
                                }
                            })
                            .await
                            .map_err(|error| kube_error("relabelling the sandbox pod", error))?;
                    }
                    Ok(())
                },
            )
            .await
    }

    async fn update_network(&self, policy: &NetworkPolicy) -> Result<()> {
        policy.validate()?;
        self.events
            .run(
                EventSubject::sandbox(Some(self.id.clone())),
                Action::UpdateNetwork,
                |_| async {
                    let mut updated = self.record.lock().await.clone();
                    updated.network = policy.clone();
                    let rendered = build_network_policy(&updated)?;
                    self.cluster
                        .apply_network_policy(self.id.as_str(), rendered.as_ref())
                        .await?;
                    self.store
                        .save(&updated)
                        .map_err(|error| record_io("recording the sandbox network", error))?;
                    *self.record.lock().await = updated;
                    Ok(())
                },
            )
            .await
    }

    fn exec(&self) -> &dyn Exec {
        self.exec.as_ref()
    }

    fn fs(&self) -> &dyn Filesystem {
        &self.fs
    }
}
