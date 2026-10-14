//! Kubernetes sandbox provider for `sandbox-driver`, served as a protocol v2
//! plugin.
//!
//! The plugin runs beside the sandbox host (a Fabro worker) on the factory
//! machine and reaches a cluster remotely through the Kubernetes API. Each
//! sandbox is one pod with a single `sandbox` container running
//! `sleep infinity`; every command runs through the Kubernetes `exec`
//! subresource.
//!
//! # Identity, persistence and recovery
//!
//! A sandbox's identity is its pod name, which is the logical sandbox id:
//! the spec's `name` when it is a valid DNS label (Petri passes
//! `petri-<run>-l<lease>`), otherwise a generated one. The pod UID is never
//! used. The workspace is a node-local directory
//! (`<workspace_root>/<sandbox id>`) mounted with `hostPath`, and the pod is
//! pinned to the node that holds it.
//!
//! The plugin keeps a **host-side record** per sandbox in its state
//! directory, written before the pod is created. Every cluster object is
//! re-derivable from that record, so a control-plane rebuild that drops every
//! API object does not lose a sandbox: `start` re-creates its pod on the
//! recorded node over the surviving workspace.
//!
//! - `stop` deletes the pod and waits until it is gone from the API; the
//!   workspace and the record stay.
//! - `start` re-creates the pod from the record and refuses while a pod of
//!   that name still exists (the single-writer fence).
//! - `delete` empties the workspace, deletes the pod and its network policy,
//!   and removes the record.
//!
//! A sandbox whose node is `NotReady` is reported **unavailable**, never lost:
//! its workspace is unreachable but not known gone. Commands against it fail
//! with a retryable provider error and no replacement pod is created.
//!
//! # Credentials
//!
//! The cluster credential is read from a kubeconfig file (by default
//! `$HOME/.kube/config`) and re-read whenever the API answers `401`, so a
//! rotated credential is picked up without restarting the plugin. Nothing
//! the plugin holds is projected into a pod.

mod client;
mod config;
mod error;
mod exec;
mod fs;
mod labels;
mod pod;
mod provider;
mod record;
mod sandbox;

pub use crate::client::KubeClient;
pub use crate::config::KubernetesConfig;
pub use crate::exec::KubernetesExec;
pub use crate::fs::KubernetesFs;
pub use crate::labels::{decode_label_value, encode_label_value, is_valid_label_value};
pub use crate::provider::KubernetesProvider;
pub use crate::record::{Record, RecordStore};
pub use crate::sandbox::KubernetesSandbox;

use sandbox_driver::{Capabilities, Isolation, ProviderKind};

/// The provider kind this plugin serves.
pub const PROVIDER_KIND: &str = "kubernetes";
/// Label every managed pod and network policy carries.
pub const MANAGED_LABEL: &str = "app.kubernetes.io/managed-by";
/// Value of [`MANAGED_LABEL`].
pub const MANAGED_VALUE: &str = "sandbox-driver-kubernetes";
/// Annotation holding the sandbox's labels verbatim, as JSON.
pub const LABELS_ANNOTATION: &str = "sandbox-driver-kubernetes/labels";
/// The container name inside each sandbox pod.
pub const CONTAINER_NAME: &str = "sandbox";
/// Working directory used when the spec names none.
pub const DEFAULT_WORKING_DIRECTORY: &str = "/workspace";
/// Directory for the exec wrapper's control files inside the container.
pub const RUNTIME_DIRECTORY: &str = "/tmp/sandbox-driver/runtime";
/// Parent of [`RUNTIME_DIRECTORY`], also kept private.
pub const RUNTIME_DIRECTORY_PARENT: &str = "/tmp/sandbox-driver";

pub(crate) fn kubernetes_kind() -> ProviderKind {
    ProviderKind::try_new(PROVIDER_KIND).expect("static kind is valid")
}

/// The plugin's capability set. Everything declared works; everything else
/// is refused with `unsupported`.
pub fn kubernetes_capabilities() -> Capabilities {
    let mut caps = Capabilities::minimal(Isolation::Container);
    caps.exec.live_streaming = true;
    caps.exec.streams_separated = true;
    caps.exec.stdin = true;
    caps.exec.stdin_stream = true;
    caps.exec.stop = true;
    caps.exec.stdio_process = true;
    caps.exec.environment = true;
    caps.fs.native = false;
    caps.lifecycle.labels = true;
    caps.lifecycle.update_network = true;
    caps.network.allow_all = true;
    caps.network.block_all = true;
    caps.network.cidr_allow_list = true;
    caps
}
