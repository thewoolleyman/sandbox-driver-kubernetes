//! Building and driving a sandbox's pod and network policy.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::{
    Affinity, AppArmorProfile, Container, EnvVar, Event, HostPathVolumeSource,
    LocalObjectReference, Node, NodeAffinity, NodeSelector, NodeSelectorRequirement,
    NodeSelectorTerm, Pod, PodSecurityContext, PodSpec, ResourceRequirements, Toleration,
    TopologySpreadConstraint, Volume, VolumeMount,
};
use k8s_openapi::api::networking::v1::{
    IPBlock, NetworkPolicy as KubeNetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyPeer,
    NetworkPolicyPort, NetworkPolicySpec,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Api, DeleteParams, ListParams, PostParams};
use sandbox_driver::{Error, NetworkPolicy, Resources, Result};

use crate::client::KubeClient;
use crate::error::{is_conflict, is_not_found, kube_error, provider, unavailable};
use crate::labels::encode_labels;
use crate::record::Record;
use crate::{CONTAINER_NAME, LABELS_ANNOTATION, MANAGED_LABEL, MANAGED_VALUE};

/// Label naming the logical sandbox a pod or policy belongs to.
pub(crate) const SANDBOX_LABEL: &str = "sandbox-driver-kubernetes/sandbox";
/// Label naming the sandbox whose workspace a cleanup pod empties. A cleanup
/// pod carries no [`SANDBOX_LABEL`], so nothing mistakes it for the sandbox.
pub(crate) const CLEANUP_OF_LABEL: &str = "sandbox-driver-kubernetes/cleanup-of";
/// Annotation naming the plugin process that created a cleanup pod, as
/// `<host>/<pid>/<start-ticks>`, so another process can tell an abandoned
/// cleanup from one still in progress.
pub(crate) const CLEANUP_OWNER_ANNOTATION: &str = "sandbox-driver-kubernetes/cleanup-owner";
/// CPU a cleanup pod requests and is limited to.
pub(crate) const CLEANUP_CPU: &str = "100m";
/// Memory a cleanup pod requests and is limited to.
pub(crate) const CLEANUP_MEMORY: &str = "128Mi";
/// Label carrying the factory identity, when configured.
pub(crate) const FACTORY_LABEL: &str = "livespec.dispatch.factory";
const HOSTNAME_LABEL: &str = "kubernetes.io/hostname";
/// What [`Cluster::wait_ended`] reports for a pod whose workspace directory
/// is gone from its node, so it can never start.
pub(crate) const NO_WORKSPACE: &str = "NoWorkspace";
/// The container name of a cleanup pod.
const CLEANUP_CONTAINER_NAME: &str = "cleanup";
const POLL: Duration = Duration::from_secs(1);

/// Whether the pod is the first of its sandbox (its workspace directory may
/// be created) or a re-creation (the directory must already exist).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Incarnation {
    First,
    Recreate,
}

/// The configuration key, and the environment variable that sets it, named
/// in a refused CPU request.
const CPU_REQUEST_FIELD: &str = "cpu_request_cores (SANDBOX_DRIVER_KUBERNETES_CPU_REQUEST_CORES)";

/// Validates the spec's resources and renders them as requests equal to
/// limits, except that a configured `cpu_request` (cores, as written) is the
/// CPU request while `cpu_cores` stays the CPU limit. Memory and disk are
/// always requested at their limits. A request that does not parse as a
/// number of cores, is not positive, exceeds the limit, or has no limit to sit
/// under is refused, never clamped.
pub(crate) fn resource_requirements(
    resources: &Resources,
    cpu_request: Option<&str>,
) -> Result<Option<ResourceRequirements>> {
    if resources.gpus.is_some_and(|gpus| gpus > 0) {
        return Err(Error::invalid_spec(
            "resources.gpus",
            "the kubernetes provider serves no GPUs; refusing rather than dropping a requested \
             resource",
        ));
    }
    let request_millicores = cpu_request
        .map(|written| cpu_request_millicores(written, resources.cpu_cores))
        .transpose()?;
    let mut quantities = BTreeMap::new();
    if let Some(cpu) = resources.cpu_cores {
        quantities.insert("cpu".to_owned(), Quantity(cpu.to_string()));
    }
    if let Some(memory) = resources.memory_mb {
        quantities.insert("memory".to_owned(), Quantity(format!("{memory}Mi")));
    }
    if let Some(disk) = resources.disk_mb {
        quantities.insert(
            "ephemeral-storage".to_owned(),
            Quantity(format!("{disk}Mi")),
        );
    }
    if quantities.is_empty() {
        return Ok(None);
    }
    let mut requests = quantities.clone();
    if let Some(millicores) = request_millicores {
        requests.insert("cpu".to_owned(), Quantity(cpu_quantity(millicores)));
    }
    Ok(Some(ResourceRequirements {
        requests: Some(requests),
        limits: Some(quantities),
        ..ResourceRequirements::default()
    }))
}

/// The configured CPU request in millicores, checked against the limit.
fn cpu_request_millicores(written: &str, limit_cores: Option<u32>) -> Result<u64> {
    let refuse = |reason: String| Err(Error::invalid_spec(CPU_REQUEST_FIELD, reason));
    let Ok(cores) = written.trim().parse::<f64>() else {
        return refuse(format!(
            "{written:?} is not a number of CPU cores (for example \"3\" or \"2.5\")"
        ));
    };
    if !cores.is_finite() {
        return refuse(format!("{written:?} is not a finite number of CPU cores"));
    }
    // Kubernetes resolves CPU to whole millicores.
    let millicores = (cores * 1000.0).round();
    if millicores < 1.0 {
        return refuse(format!(
            "{written:?} is not a positive CPU request (the smallest is 0.001 cores)"
        ));
    }
    let Some(limit) = limit_cores else {
        return refuse(format!(
            "a CPU request of {written:?} needs a CPU limit to sit under, and the spec sets no \
             resources.cpu_cores"
        ));
    };
    if millicores > f64::from(limit) * 1000.0 {
        return refuse(format!(
            "a CPU request of {written:?} cores exceeds the spec's CPU limit of {limit} cores \
             (resources.cpu_cores)"
        ));
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "positive, rounded, and at most the u32 limit times 1000"
    )]
    Ok(millicores as u64)
}

/// A CPU quantity: whole cores when exact, otherwise millicores.
fn cpu_quantity(millicores: u64) -> String {
    if millicores % 1000 == 0 {
        (millicores / 1000).to_string()
    } else {
        format!("{millicores}m")
    }
}

/// The labels every object of a sandbox carries, plus the sandbox's own
/// labels encoded.
pub(crate) fn object_labels(record: &Record) -> Result<BTreeMap<String, String>> {
    let mut labels =
        encode_labels(&record.labels).map_err(|reason| Error::invalid_spec("labels", reason))?;
    labels.insert(MANAGED_LABEL.to_owned(), MANAGED_VALUE.to_owned());
    labels.insert(SANDBOX_LABEL.to_owned(), record.id.clone());
    if let Some(factory) = &record.factory {
        let value = crate::labels::encode_label_value(factory)
            .map_err(|reason| Error::invalid_spec("factory", reason))?;
        labels.insert(FACTORY_LABEL.to_owned(), value);
    }
    Ok(labels)
}

fn annotations(record: &Record) -> Result<BTreeMap<String, String>> {
    let mut annotations: BTreeMap<String, String> = record.labels.clone();
    annotations.insert(
        LABELS_ANNOTATION.to_owned(),
        serde_json::to_string(&record.labels).map_err(|error| provider(error.to_string()))?,
    );
    Ok(annotations)
}

/// The pod manifest for `record`.
fn security_context(run_as_user: Option<i64>, record: &Record) -> Option<PodSecurityContext> {
    let app_armor_profile =
        record
            .apparmor_localhost_profile
            .as_ref()
            .map(|profile| AppArmorProfile {
                type_: "Localhost".to_owned(),
                localhost_profile: Some(profile.clone()),
            });
    (run_as_user.is_some() || app_armor_profile.is_some()).then(|| PodSecurityContext {
        run_as_user,
        app_armor_profile,
        ..PodSecurityContext::default()
    })
}

/// The first pod's topology spread constraints. Each counts every pod this
/// plugin manages in the namespace, so sandboxes spread across nodes rather
/// than stacking on the one the scheduler's resource scoring happens to favour.
fn topology_spread_constraints(record: &Record) -> Option<Vec<TopologySpreadConstraint>> {
    (!record.topology_spread.is_empty()).then(|| {
        record
            .topology_spread
            .iter()
            .map(|spread| TopologySpreadConstraint {
                topology_key: spread.topology_key.clone(),
                max_skew: spread.max_skew,
                when_unsatisfiable: spread.when_unsatisfiable.clone(),
                label_selector: Some(LabelSelector {
                    match_labels: Some(BTreeMap::from([(
                        MANAGED_LABEL.to_owned(),
                        MANAGED_VALUE.to_owned(),
                    )])),
                    ..LabelSelector::default()
                }),
                ..TopologySpreadConstraint::default()
            })
            .collect()
    })
}

/// Required node affinity to exactly `node`.
fn pinned_to(node: &str) -> Affinity {
    Affinity {
        node_affinity: Some(NodeAffinity {
            required_during_scheduling_ignored_during_execution: Some(NodeSelector {
                node_selector_terms: vec![NodeSelectorTerm {
                    match_expressions: Some(vec![NodeSelectorRequirement {
                        key: HOSTNAME_LABEL.to_owned(),
                        operator: "In".to_owned(),
                        values: Some(vec![node.to_owned()]),
                    }]),
                    match_fields: None,
                }],
            }),
            ..NodeAffinity::default()
        }),
        ..Affinity::default()
    }
}

fn tolerations(record: &Record) -> Option<Vec<Toleration>> {
    (!record.tolerations.is_empty()).then(|| {
        record
            .tolerations
            .iter()
            .map(|t| Toleration {
                key: t.key.clone(),
                operator: t.operator.clone(),
                value: t.value.clone(),
                effect: t.effect.clone(),
                toleration_seconds: None,
            })
            .collect()
    })
}

fn image_pull_secrets(record: &Record) -> Option<Vec<LocalObjectReference>> {
    (!record.image_pull_secrets.is_empty()).then(|| {
        record
            .image_pull_secrets
            .iter()
            .map(|name| LocalObjectReference { name: name.clone() })
            .collect()
    })
}

/// The name of the pod that empties `id`'s workspace.
pub(crate) fn cleanup_pod_name(id: &str) -> String {
    format!("{id}-cleanup")
}

/// The pod that empties a stopped sandbox's workspace on `node`: the
/// sandbox's own image (already on that node), pinned there, mounting the
/// workspace that must already exist, and asking for no more than
/// [`CLEANUP_CPU`] and [`CLEANUP_MEMORY`] rather than the sandbox's declared
/// resources. It removes the workspace contents and exits.
pub(crate) fn build_cleanup_pod(record: &Record, node: &str, owner: &str) -> Result<Pod> {
    let quantities = BTreeMap::from([
        ("cpu".to_owned(), Quantity(CLEANUP_CPU.to_owned())),
        ("memory".to_owned(), Quantity(CLEANUP_MEMORY.to_owned())),
    ]);
    let run_as_user = record
        .user
        .as_deref()
        .and_then(|user| user.parse::<i64>().ok());
    let script = format!(
        "find {} -mindepth 1 -maxdepth 1 -exec rm -rf {{}} +",
        crate::exec::shell_quote(&record.working_dir)
    );
    let mut labels = BTreeMap::from([
        (MANAGED_LABEL.to_owned(), MANAGED_VALUE.to_owned()),
        (CLEANUP_OF_LABEL.to_owned(), record.id.clone()),
    ]);
    if let Some(factory) = &record.factory {
        let value = crate::labels::encode_label_value(factory)
            .map_err(|reason| Error::invalid_spec("factory", reason))?;
        labels.insert(FACTORY_LABEL.to_owned(), value);
    }
    Ok(Pod {
        metadata: ObjectMeta {
            name: Some(cleanup_pod_name(&record.id)),
            namespace: Some(record.namespace.clone()),
            labels: Some(labels),
            annotations: Some(BTreeMap::from([(
                CLEANUP_OWNER_ANNOTATION.to_owned(),
                owner.to_owned(),
            )])),
            ..ObjectMeta::default()
        },
        spec: Some(PodSpec {
            restart_policy: Some("Never".to_owned()),
            termination_grace_period_seconds: Some(1),
            service_account_name: record.service_account.clone(),
            automount_service_account_token: Some(false),
            enable_service_links: Some(false),
            affinity: Some(pinned_to(node)),
            tolerations: tolerations(record),
            image_pull_secrets: image_pull_secrets(record),
            security_context: security_context(run_as_user, record),
            containers: vec![Container {
                name: CLEANUP_CONTAINER_NAME.to_owned(),
                image: Some(record.image.clone()),
                command: Some(vec!["/bin/sh".to_owned(), "-c".to_owned(), script]),
                working_dir: Some("/".to_owned()),
                resources: Some(ResourceRequirements {
                    requests: Some(quantities.clone()),
                    limits: Some(quantities),
                    ..ResourceRequirements::default()
                }),
                volume_mounts: Some(vec![VolumeMount {
                    name: "workspace".to_owned(),
                    mount_path: record.working_dir.clone(),
                    ..VolumeMount::default()
                }]),
                ..Container::default()
            }],
            volumes: Some(vec![Volume {
                name: "workspace".to_owned(),
                host_path: Some(HostPathVolumeSource {
                    path: record.workspace_dir.clone(),
                    type_: Some("Directory".to_owned()),
                }),
                ..Volume::default()
            }]),
            ..PodSpec::default()
        }),
        status: None,
    })
}

/// pytest-xdist reads this before any CPU probe, for `-n auto` and `-n logical`.
const XDIST_WORKERS_ENV: &str = "PYTEST_XDIST_AUTO_NUM_WORKERS";
/// GNU `nproc` prints this when it is set.
const OMP_THREADS_ENV: &str = "OMP_NUM_THREADS";
/// The livespec repositories' own test recipes size their workers from this.
const TEST_PARALLELISM_ENV: &str = "LIVESPEC_TEST_PARALLELISM";
/// Every variable the driver sets to the pod's CPU limit, unless the spec
/// already carries it.
const CPU_SIZED_ENV: [&str; 3] = [XDIST_WORKERS_ENV, OMP_THREADS_ENV, TEST_PARALLELISM_ENV];

pub(crate) fn build_pod(record: &Record, incarnation: Incarnation) -> Result<Pod> {
    // A CPU limit is a CFS quota, not an affinity mask, so inside the pod every
    // tool that sizes itself from the CPU count sees the node's CPUs. A bare
    // `pytest -n auto` in a 6-CPU pod on a 32-CPU node started 32 workers and
    // OOM-killed the agent (bd-ib-vy75ws, 2026-11-13). Hand those tools the
    // limit instead, unless the spec already sets the variable.
    let cpu_sized = record.resources.cpu_cores.into_iter().flat_map(|cores| {
        CPU_SIZED_ENV
            .into_iter()
            .filter(|name| !record.env.contains_key(*name))
            .map(move |name| (name.to_owned(), cores.to_string()))
    });
    let env = record
        .env
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .chain(cpu_sized)
        .map(|(name, value)| EnvVar {
            name,
            value: Some(value),
            value_from: None,
        })
        .collect::<Vec<_>>();
    let host_path_type = match incarnation {
        Incarnation::First => "DirectoryOrCreate",
        Incarnation::Recreate => "Directory",
    };
    // A pod pinned to its sandbox's node has nowhere to spread to.
    let (node_selector, affinity, topology_spread) = match &record.node {
        Some(node) => (None, Some(pinned_to(node)), None),
        None => (
            (!record.node_selector.is_empty()).then(|| record.node_selector.clone()),
            None,
            topology_spread_constraints(record),
        ),
    };
    let run_as_user = record
        .user
        .as_deref()
        .and_then(|user| user.parse::<i64>().ok());
    // The idle process IGNORES TERM and INT. The kernel delivers a signal
    // sent from inside the container to the namespace's PID 1 only when PID 1
    // handles it, so a handler here let an agent's `pkill -f` or `kill 1`
    // end the sandbox (run 01M7B8BW33WQ, 2026-11-13). Ignoring rather than
    // leaving them default also stops bash, where it is /bin/sh, from
    // installing its own SIGINT handler while it waits. A pod delete then
    // ends the container with SIGKILL at the termination grace period below.
    let idle = format!(
        "mkdir -p {runtime} && chmod 0700 {parent} {runtime} && \
         trap '' TERM INT; while :; do sleep 3600 & wait $!; done",
        parent = crate::exec::shell_quote(crate::RUNTIME_DIRECTORY_PARENT),
        runtime = crate::exec::shell_quote(crate::RUNTIME_DIRECTORY),
    );
    Ok(Pod {
        metadata: ObjectMeta {
            name: Some(record.id.clone()),
            namespace: Some(record.namespace.clone()),
            labels: Some(object_labels(record)?),
            annotations: Some(annotations(record)?),
            ..ObjectMeta::default()
        },
        spec: Some(PodSpec {
            restart_policy: Some("Never".to_owned()),
            termination_grace_period_seconds: Some(5),
            service_account_name: record.service_account.clone(),
            automount_service_account_token: Some(false),
            enable_service_links: Some(false),
            node_selector,
            affinity,
            topology_spread_constraints: topology_spread,
            tolerations: tolerations(record),
            image_pull_secrets: image_pull_secrets(record),
            security_context: security_context(run_as_user, record),
            containers: vec![Container {
                name: CONTAINER_NAME.to_owned(),
                image: Some(record.image.clone()),
                command: Some(vec!["/bin/sh".to_owned(), "-c".to_owned(), idle]),
                working_dir: Some(record.working_dir.clone()),
                env: (!env.is_empty()).then_some(env),
                resources: resource_requirements(
                    &record.resources,
                    record.cpu_request_cores.as_deref(),
                )?,
                volume_mounts: Some(vec![VolumeMount {
                    name: "workspace".to_owned(),
                    mount_path: record.working_dir.clone(),
                    ..VolumeMount::default()
                }]),
                ..Container::default()
            }],
            volumes: Some(vec![Volume {
                name: "workspace".to_owned(),
                host_path: Some(HostPathVolumeSource {
                    path: record.workspace_dir.clone(),
                    type_: Some(host_path_type.to_owned()),
                }),
                ..Volume::default()
            }]),
            ..PodSpec::default()
        }),
        status: None,
    })
}

/// The egress policy for `record`, or `None` when its network is open.
pub(crate) fn build_network_policy(record: &Record) -> Result<Option<KubeNetworkPolicy>> {
    let egress = match &record.network {
        NetworkPolicy::ProviderDefault | NetworkPolicy::AllowAll => return Ok(None),
        NetworkPolicy::Block => Vec::new(),
        NetworkPolicy::CidrAllowList { cidrs } => {
            let dns_ports = ["UDP", "TCP"]
                .map(|protocol| NetworkPolicyPort {
                    port: Some(IntOrString::Int(53)),
                    protocol: Some(protocol.to_owned()),
                    end_port: None,
                })
                .to_vec();
            vec![
                NetworkPolicyEgressRule {
                    to: Some(
                        cidrs
                            .iter()
                            .map(|cidr| NetworkPolicyPeer {
                                ip_block: Some(IPBlock {
                                    cidr: cidr.clone(),
                                    except: None,
                                }),
                                ..NetworkPolicyPeer::default()
                            })
                            .collect(),
                    ),
                    ports: None,
                },
                NetworkPolicyEgressRule {
                    to: None,
                    ports: Some(dns_ports),
                },
            ]
        }
        NetworkPolicy::DomainAllowList { .. } => {
            return Err(Error::invalid_spec(
                "network",
                "the kubernetes provider cannot enforce a domain allow-list; use a CIDR allow-list",
            ));
        }
        _ => {
            return Err(Error::invalid_spec(
                "network",
                "network policy kind not supported by the kubernetes provider",
            ));
        }
    };
    Ok(Some(KubeNetworkPolicy {
        metadata: ObjectMeta {
            name: Some(record.id.clone()),
            namespace: Some(record.namespace.clone()),
            labels: Some(object_labels(record)?),
            ..ObjectMeta::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: Some(LabelSelector {
                match_labels: Some(BTreeMap::from([(
                    SANDBOX_LABEL.to_owned(),
                    record.id.clone(),
                )])),
                match_expressions: None,
            }),
            policy_types: Some(vec!["Egress".to_owned()]),
            egress: Some(egress),
            ingress: None,
        }),
    }))
}

/// Cluster operations on one namespace.
#[derive(Clone)]
pub(crate) struct Cluster {
    pub(crate) client: KubeClient,
    pub(crate) namespace: String,
}

impl Cluster {
    pub(crate) async fn get_pod(&self, name: &str) -> Result<Option<Pod>> {
        let namespace = self.namespace.clone();
        let result = self
            .client
            .call(|client| {
                let namespace = namespace.clone();
                async move { Api::<Pod>::namespaced(client, &namespace).get(name).await }
            })
            .await;
        match result {
            Ok(pod) => Ok(Some(pod)),
            Err(error) if is_not_found(&error) => Ok(None),
            Err(error) => Err(kube_error("reading the sandbox pod", error)),
        }
    }

    pub(crate) async fn list_pods(&self, selector: &str) -> Result<Vec<Pod>> {
        let namespace = self.namespace.clone();
        self.client
            .call(|client| {
                let namespace = namespace.clone();
                async move {
                    Api::<Pod>::namespaced(client, &namespace)
                        .list(&ListParams::default().labels(selector))
                        .await
                        .map(|list| list.items)
                }
            })
            .await
            .map_err(|error| kube_error("listing sandbox pods", error))
    }

    /// Creates `pod`; an existing pod of that name is refused, which is the
    /// start half of the single-writer fence.
    pub(crate) async fn create_pod(&self, pod: &Pod) -> Result<()> {
        let namespace = self.namespace.clone();
        let result = self
            .client
            .call(|client| {
                let namespace = namespace.clone();
                async move {
                    Api::<Pod>::namespaced(client, &namespace)
                        .create(&PostParams::default(), pod)
                        .await
                }
            })
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(error) if is_conflict(&error) => Err(provider(format!(
                "a pod named {} still exists; refusing to start a second writer on its workspace",
                pod.metadata.name.as_deref().unwrap_or("?")
            ))),
            Err(error) => Err(kube_error("creating the sandbox pod", error)),
        }
    }

    /// Deletes the pod and waits until it is gone from the API, not merely
    /// terminating: the stop half of the single-writer fence.
    pub(crate) async fn delete_pod_and_wait(&self, name: &str, timeout: Duration) -> Result<()> {
        if !self.delete_pod(name).await? {
            return Ok(());
        }
        let started = Instant::now();
        loop {
            if self.get_pod(name).await?.is_none() {
                return Ok(());
            }
            if started.elapsed() >= timeout {
                return Err(Error::Timeout {
                    operation: format!("waiting for pod {name} to be gone"),
                    elapsed: started.elapsed(),
                });
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Asks for the pod's deletion without waiting; `false` when it was
    /// already gone.
    pub(crate) async fn delete_pod(&self, name: &str) -> Result<bool> {
        let namespace = self.namespace.clone();
        let result = self
            .client
            .call(|client| {
                let namespace = namespace.clone();
                async move {
                    Api::<Pod>::namespaced(client, &namespace)
                        .delete(name, &DeleteParams::default().grace_period(5))
                        .await
                }
            })
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(error) if is_not_found(&error) => Ok(false),
            Err(error) => Err(kube_error("deleting the sandbox pod", error)),
        }
    }

    pub(crate) async fn apply_network_policy(
        &self,
        name: &str,
        policy: Option<&KubeNetworkPolicy>,
    ) -> Result<()> {
        let namespace = self.namespace.clone();
        let deleted = self
            .client
            .call(|client| {
                let namespace = namespace.clone();
                async move {
                    Api::<KubeNetworkPolicy>::namespaced(client, &namespace)
                        .delete(name, &DeleteParams::default())
                        .await
                }
            })
            .await;
        match deleted {
            Ok(_) => {}
            Err(error) if is_not_found(&error) => {}
            Err(error) => return Err(kube_error("removing the sandbox network policy", error)),
        }
        let Some(policy) = policy else { return Ok(()) };
        self.client
            .call(|client| {
                let namespace = namespace.clone();
                async move {
                    Api::<KubeNetworkPolicy>::namespaced(client, &namespace)
                        .create(&PostParams::default(), policy)
                        .await
                }
            })
            .await
            .map(|_| ())
            .map_err(|error| kube_error("creating the sandbox network policy", error))
    }

    /// Whether `node` reports `Ready`. A node the API no longer knows is
    /// `Some(false)` with `gone` set.
    pub(crate) async fn node_ready(&self, node: &str) -> Result<NodeHealth> {
        let result = self
            .client
            .call(|client| async move { Api::<Node>::all(client).get(node).await })
            .await;
        match result {
            Ok(node) => {
                let ready = node
                    .status
                    .and_then(|status| status.conditions)
                    .unwrap_or_default()
                    .into_iter()
                    .any(|condition| condition.type_ == "Ready" && condition.status == "True");
                Ok(if ready {
                    NodeHealth::Ready
                } else {
                    NodeHealth::NotReady
                })
            }
            Err(error) if is_not_found(&error) => Ok(NodeHealth::Gone),
            Err(error) => Err(kube_error("reading the sandbox node", error)),
        }
    }

    /// Waits for the pod to run, failing fast on a pull failure or a
    /// missing workspace. Returns the node it runs on.
    pub(crate) async fn wait_running(&self, name: &str, timeout: Duration) -> Result<String> {
        let started = Instant::now();
        loop {
            let Some(pod) = self.get_pod(name).await? else {
                return Err(provider(format!("pod {name} disappeared while starting")));
            };
            let status = pod.status.clone().unwrap_or_default();
            let node = pod.spec.as_ref().and_then(|spec| spec.node_name.clone());
            match status.phase.as_deref() {
                Some("Running") => {
                    let ready = status
                        .container_statuses
                        .clone()
                        .unwrap_or_default()
                        .iter()
                        .any(|container| container.name == CONTAINER_NAME && container.ready);
                    if ready {
                        return node.ok_or_else(|| provider(format!("pod {name} runs on no node")));
                    }
                }
                Some(phase @ ("Failed" | "Succeeded")) => {
                    return Err(provider(format!(
                        "pod {name} ended in phase {phase} while starting"
                    )));
                }
                _ => {}
            }
            for container in status.container_statuses.unwrap_or_default() {
                if let Some(waiting) = container.state.and_then(|state| state.waiting) {
                    let reason = waiting.reason.unwrap_or_default();
                    if matches!(
                        reason.as_str(),
                        "ErrImagePull"
                            | "ImagePullBackOff"
                            | "InvalidImageName"
                            | "CreateContainerConfigError"
                            | "CreateContainerError"
                    ) {
                        return Err(provider(format!(
                            "pod {name} cannot start: {reason}: {}",
                            waiting.message.unwrap_or_default()
                        )));
                    }
                }
            }
            if let Some(message) = self.failed_mount(name).await? {
                return Err(WorkspaceMissing(message).into());
            }
            if started.elapsed() >= timeout {
                return Err(Error::Timeout {
                    operation: format!("waiting for pod {name} to run"),
                    elapsed: started.elapsed(),
                });
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Waits for a run-to-completion pod to end; returns its final phase, or
    /// [`NO_WORKSPACE`] when its workspace mount can never succeed. Fails
    /// when the pod disappears first, or after `timeout`.
    pub(crate) async fn wait_ended(&self, name: &str, timeout: Duration) -> Result<String> {
        let started = Instant::now();
        loop {
            let Some(pod) = self.get_pod(name).await? else {
                return Err(provider(format!("pod {name} disappeared before it ended")));
            };
            if let Some(phase @ ("Succeeded" | "Failed")) = pod
                .status
                .as_ref()
                .and_then(|status| status.phase.as_deref())
            {
                return Ok(phase.to_owned());
            }
            if self.failed_mount(name).await?.is_some() {
                return Ok(NO_WORKSPACE.to_owned());
            }
            if started.elapsed() >= timeout {
                return Err(Error::Timeout {
                    operation: format!("waiting for pod {name} to end"),
                    elapsed: started.elapsed(),
                });
            }
            tokio::time::sleep(POLL).await;
        }
    }

    async fn failed_mount(&self, name: &str) -> Result<Option<String>> {
        let namespace = self.namespace.clone();
        let selector = format!("involvedObject.name={name},reason=FailedMount");
        let events = self
            .client
            .call(|client| {
                let namespace = namespace.clone();
                let selector = selector.clone();
                async move {
                    Api::<Event>::namespaced(client, &namespace)
                        .list(&ListParams::default().fields(&selector))
                        .await
                }
            })
            .await
            .map_err(|error| kube_error("reading pod events", error))?;
        Ok(events.items.into_iter().find_map(|event| {
            event
                .message
                .filter(|message| message.contains("hostPath type check failed"))
        }))
    }
}

/// A node's health as the sandbox sees it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NodeHealth {
    Ready,
    NotReady,
    Gone,
}

/// The recorded workspace directory is gone from its node.
#[derive(Debug)]
pub(crate) struct WorkspaceMissing(pub(crate) String);

impl From<WorkspaceMissing> for Error {
    fn from(missing: WorkspaceMissing) -> Self {
        provider(format!(
            "the sandbox's workspace directory no longer exists on its node, so the sandbox is \
             lost: {}",
            missing.0
        ))
    }
}

pub(crate) fn node_unavailable(id: &str, node: &str) -> Error {
    unavailable(format!(
        "sandbox {id} is unavailable: its node {node} is NotReady, so its workspace is \
         unreachable but not known lost; retry once the node returns"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        Record {
            id: "petri-01jabc-l1".to_owned(),
            name: None,
            namespace: "ns".to_owned(),
            node: None,
            workspace_dir: "/ws/petri-01jabc-l1".to_owned(),
            working_dir: "/workspace".to_owned(),
            image: "img".to_owned(),
            resources: Resources::default(),
            env: BTreeMap::new(),
            labels: BTreeMap::from([("petri.workspace".to_owned(), "01JABC/implement".to_owned())]),
            network: NetworkPolicy::default(),
            user: None,
            node_selector: BTreeMap::from([("factory".to_owned(), "true".to_owned())]),
            apparmor_localhost_profile: Some("ci-runner-workflow".to_owned()),
            tolerations: vec![crate::config::Toleration {
                key: Some("node-role/ci".to_owned()),
                operator: Some("Equal".to_owned()),
                value: Some("factory".to_owned()),
                effect: Some("NoSchedule".to_owned()),
            }],
            topology_spread: vec![crate::config::TopologySpread {
                topology_key: "kubernetes.io/hostname".to_owned(),
                max_skew: 1,
                when_unsatisfiable: "ScheduleAnyway".to_owned(),
            }],
            service_account: Some("sa".to_owned()),
            image_pull_secrets: Vec::new(),
            factory: Some("hp".to_owned()),
            cpu_request_cores: None,
        }
    }

    #[test]
    fn a_cleanup_pod_is_minimal_pinned_and_never_the_sandbox() {
        let mut record = record();
        record.resources.cpu_cores = Some(4);
        record.resources.memory_mb = Some(8192);
        let pod = build_cleanup_pod(&record, "node-a", "host/1/2").expect("builds");
        let meta = &pod.metadata;
        assert_eq!(meta.name.as_deref(), Some("petri-01jabc-l1-cleanup"));
        let labels = meta.labels.clone().expect("labels");
        assert_eq!(
            labels.get(CLEANUP_OF_LABEL).map(String::as_str),
            Some("petri-01jabc-l1")
        );
        assert!(
            !labels.contains_key(SANDBOX_LABEL),
            "a cleanup pod must not read as the sandbox"
        );
        assert_eq!(
            meta.annotations
                .clone()
                .expect("annotations")
                .get(CLEANUP_OWNER_ANNOTATION)
                .map(String::as_str),
            Some("host/1/2")
        );
        let spec = pod.spec.expect("spec");
        assert_eq!(spec.restart_policy.as_deref(), Some("Never"));
        let terms = spec
            .affinity
            .and_then(|a| a.node_affinity)
            .and_then(|n| n.required_during_scheduling_ignored_during_execution)
            .expect("pinned")
            .node_selector_terms;
        assert_eq!(
            terms[0].match_expressions.as_ref().expect("expressions")[0].values,
            Some(vec!["node-a".to_owned()])
        );
        let container = &spec.containers[0];
        let resources = container.resources.clone().expect("resources");
        for quantities in [
            resources.requests.expect("requests"),
            resources.limits.expect("limits"),
        ] {
            assert_eq!(
                quantities.get("cpu"),
                Some(&Quantity(CLEANUP_CPU.to_owned()))
            );
            assert_eq!(
                quantities.get("memory"),
                Some(&Quantity(CLEANUP_MEMORY.to_owned()))
            );
        }
        assert_eq!(CLEANUP_CPU, "100m");
        assert_eq!(CLEANUP_MEMORY, "128Mi");
        let volume = &spec.volumes.expect("volumes")[0];
        let host_path = volume.host_path.as_ref().expect("hostPath");
        assert_eq!(host_path.path, "/ws/petri-01jabc-l1");
        assert_eq!(
            host_path.type_.as_deref(),
            Some("Directory"),
            "a cleanup never creates a workspace"
        );
        let command = container.command.clone().expect("command").join(" ");
        assert!(command.contains("rm -rf"), "{command}");
        assert!(command.contains("/workspace"), "{command}");
    }

    fn container_env(record: &Record) -> BTreeMap<String, Option<String>> {
        let pod = build_pod(record, Incarnation::First).expect("pod");
        pod.spec.expect("spec").containers[0]
            .env
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|var| (var.name, var.value))
            .collect()
    }

    #[test]
    fn a_cpu_limit_sizes_the_tools_that_count_cpus() {
        // A CPU limit is a CFS quota, not an affinity mask: inside the pod
        // `nproc` and `pytest -n auto` see the node's CPUs. The driver hands
        // them the limit instead (bd-ib-p3g5tp).
        let mut record = record();
        record.resources.cpu_cores = Some(6);
        let env = container_env(&record);
        for name in CPU_SIZED_ENV {
            assert_eq!(
                env.get(name),
                Some(&Some("6".to_owned())),
                "{name}: {env:?}"
            );
        }
    }

    #[test]
    fn a_value_the_spec_carries_wins_over_the_cpu_limit() {
        let mut record = record();
        record.resources.cpu_cores = Some(6);
        record
            .env
            .insert(XDIST_WORKERS_ENV.to_owned(), "2".to_owned());
        record
            .env
            .insert(OMP_THREADS_ENV.to_owned(), "1".to_owned());
        record
            .env
            .insert(TEST_PARALLELISM_ENV.to_owned(), "4".to_owned());
        let env = container_env(&record);
        assert_eq!(env.get(XDIST_WORKERS_ENV), Some(&Some("2".to_owned())));
        assert_eq!(env.get(OMP_THREADS_ENV), Some(&Some("1".to_owned())));
        assert_eq!(env.get(TEST_PARALLELISM_ENV), Some(&Some("4".to_owned())));
        let pod = build_pod(&record, Incarnation::First).expect("pod");
        let names = pod.spec.expect("spec").containers[0]
            .env
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter(|var| CPU_SIZED_ENV.contains(&var.name.as_str()))
            .count();
        assert_eq!(names, 3, "each variable appears once");
    }

    #[test]
    fn no_cpu_limit_adds_no_cpu_sizing_env() {
        let mut record = record();
        record.resources.cpu_cores = None;
        let env = container_env(&record);
        for name in CPU_SIZED_ENV {
            assert!(!env.contains_key(name), "{name}: {env:?}");
        }
    }

    #[test]
    fn the_idle_pid_1_ignores_term_and_int_rather_than_handling_them() {
        // A handler on the namespace init is what lets a signal sent from
        // inside the sandbox (an agent's `pkill -f`, `kill 1`) reach it; with
        // TERM and INT ignored, the kernel drops them, and a pod delete falls
        // to SIGKILL at the termination grace period.
        let pod = build_pod(&record(), Incarnation::First).expect("pod");
        let spec = pod.spec.expect("spec");
        let command = spec.containers[0]
            .command
            .clone()
            .expect("command")
            .join(" ");
        assert!(command.contains("trap '' TERM INT"), "{command}");
        assert!(!command.contains("exit 0"), "{command}");
        assert_eq!(spec.termination_grace_period_seconds, Some(5));
    }

    #[test]
    fn requests_equal_limits_and_gpus_are_refused() {
        let mut resources = Resources::default();
        resources.cpu_cores = Some(4);
        resources.memory_mb = Some(8192);
        let rendered = resource_requirements(&resources, None)
            .expect("ok")
            .expect("some");
        assert_eq!(rendered.requests, rendered.limits);
        let limits = rendered.limits.expect("limits");
        assert_eq!(limits["cpu"], Quantity("4".to_owned()));
        assert_eq!(limits["memory"], Quantity("8192Mi".to_owned()));
        resources.gpus = Some(1);
        assert!(resource_requirements(&resources, None).is_err());
    }

    fn quantity(map: &Option<BTreeMap<String, Quantity>>, key: &str) -> String {
        map.as_ref().expect("quantities")[key].0.clone()
    }

    #[test]
    fn a_configured_cpu_request_sits_under_the_cpu_limit() {
        let mut resources = Resources::default();
        resources.cpu_cores = Some(6);
        resources.memory_mb = Some(7629);
        resources.disk_mb = Some(2048);
        let rendered = resource_requirements(&resources, Some("3"))
            .expect("ok")
            .expect("some");
        assert_eq!(quantity(&rendered.requests, "cpu"), "3");
        assert_eq!(quantity(&rendered.limits, "cpu"), "6");
        // Memory and disk stay requested at their limits.
        for key in ["memory", "ephemeral-storage"] {
            assert_eq!(
                quantity(&rendered.requests, key),
                quantity(&rendered.limits, key),
                "{key}"
            );
        }
        assert_eq!(quantity(&rendered.requests, "memory"), "7629Mi");
        // A fractional request is millicores; one equal to the limit is allowed.
        let fractional = resource_requirements(&resources, Some(" 2.5 "))
            .expect("ok")
            .expect("some");
        assert_eq!(quantity(&fractional.requests, "cpu"), "2500m");
        let equal = resource_requirements(&resources, Some("6"))
            .expect("ok")
            .expect("some");
        assert_eq!(equal.requests, equal.limits);
    }

    #[test]
    fn a_bad_cpu_request_is_refused_naming_the_setting() {
        let mut resources = Resources::default();
        resources.cpu_cores = Some(4);
        resources.memory_mb = Some(7629);
        for (written, why) in [
            ("5", "exceeds the spec's CPU limit of 4 cores"),
            ("4.001", "exceeds the spec's CPU limit of 4 cores"),
            ("0", "not a positive CPU request"),
            ("-1", "not a positive CPU request"),
            ("0.0001", "not a positive CPU request"),
            ("three", "not a number of CPU cores"),
            ("3000m", "not a number of CPU cores"),
            ("", "not a number of CPU cores"),
            ("NaN", "not a finite number"),
            ("inf", "not a finite number"),
        ] {
            let Err(Error::InvalidSpec { field, reason }) =
                resource_requirements(&resources, Some(written))
            else {
                panic!("{written:?} must be refused");
            };
            assert_eq!(field, CPU_REQUEST_FIELD, "{written:?}");
            assert!(field.contains("SANDBOX_DRIVER_KUBERNETES_CPU_REQUEST_CORES"));
            assert!(reason.contains(why), "{written:?}: {reason}");
        }
        let mut unlimited = Resources::default();
        unlimited.memory_mb = Some(7629);
        let Err(Error::InvalidSpec { reason, .. }) = resource_requirements(&unlimited, Some("3"))
        else {
            panic!("a request with no limit must be refused");
        };
        assert!(reason.contains("needs a CPU limit"), "{reason}");
    }

    #[test]
    fn a_record_with_a_cpu_request_recreates_its_pod_with_it() {
        let mut record = record();
        record.resources.cpu_cores = Some(6);
        record.resources.memory_mb = Some(7629);
        record.cpu_request_cores = Some("3".to_owned());
        for incarnation in [Incarnation::First, Incarnation::Recreate] {
            if incarnation == Incarnation::Recreate {
                record.node = Some("node-a".to_owned());
            }
            let pod = build_pod(&record, incarnation).expect("pod");
            let container = &pod.spec.expect("spec").containers[0];
            let requirements = container.resources.clone().expect("resources");
            assert_eq!(quantity(&requirements.requests, "cpu"), "3");
            assert_eq!(quantity(&requirements.limits, "cpu"), "6");
        }
    }

    #[test]
    fn a_first_pod_selects_by_label_and_a_recreated_one_is_pinned() {
        let mut record = record();
        let first = build_pod(&record, Incarnation::First).expect("pod");
        let spec = first.spec.expect("spec");
        assert!(spec.node_selector.is_some());
        assert!(spec.affinity.is_none());
        let profile = spec
            .security_context
            .as_ref()
            .and_then(|context| context.app_armor_profile.clone())
            .expect("an AppArmor profile");
        assert_eq!(profile.type_, "Localhost");
        assert_eq!(
            profile.localhost_profile.as_deref(),
            Some("ci-runner-workflow")
        );
        let tolerations = spec.tolerations.clone().expect("tolerations");
        assert_eq!(tolerations[0].key.as_deref(), Some("node-role/ci"));
        assert_eq!(tolerations[0].effect.as_deref(), Some("NoSchedule"));
        let spread = spec
            .topology_spread_constraints
            .clone()
            .expect("a first pod spreads");
        assert_eq!(spread.len(), 1);
        assert_eq!(spread[0].topology_key, "kubernetes.io/hostname");
        assert_eq!(spread[0].max_skew, 1);
        assert_eq!(spread[0].when_unsatisfiable, "ScheduleAnyway");
        let selected = spread[0]
            .label_selector
            .as_ref()
            .and_then(|selector| selector.match_labels.clone())
            .expect("the spread counts managed pods");
        assert_eq!(selected[MANAGED_LABEL], MANAGED_VALUE);
        assert_eq!(
            first.metadata.labels.as_ref().expect("labels")[MANAGED_LABEL],
            MANAGED_VALUE,
            "the pod carries the label its own spread counts"
        );
        assert_eq!(spec.automount_service_account_token, Some(false));
        let volume = &spec.volumes.expect("volumes")[0];
        assert_eq!(
            volume.host_path.as_ref().and_then(|h| h.type_.as_deref()),
            Some("DirectoryOrCreate")
        );
        let labels = first.metadata.labels.expect("labels");
        assert_eq!(labels["petri.workspace"], "x_01JABC_2fimplement");
        assert_eq!(labels[FACTORY_LABEL], "hp");
        assert_eq!(
            first.metadata.annotations.expect("ann")["petri.workspace"],
            "01JABC/implement"
        );

        record.node = Some("node-a".to_owned());
        let again = build_pod(&record, Incarnation::Recreate).expect("pod");
        let spec = again.spec.expect("spec");
        assert!(spec.node_selector.is_none());
        assert!(spec.affinity.is_some());
        assert!(
            spec.topology_spread_constraints.is_none(),
            "a pinned pod has nowhere to spread"
        );
        assert!(
            spec.tolerations.is_some(),
            "a pinned pod still tolerates the taint"
        );
        let volume = &spec.volumes.expect("volumes")[0];
        assert_eq!(
            volume.host_path.as_ref().and_then(|h| h.type_.as_deref()),
            Some("Directory")
        );
    }

    #[test]
    fn block_denies_all_egress_and_open_networks_have_no_policy() {
        let mut record = record();
        assert!(build_network_policy(&record).expect("ok").is_none());
        record.network = NetworkPolicy::Block;
        let policy = build_network_policy(&record).expect("ok").expect("some");
        assert_eq!(policy.spec.expect("spec").egress, Some(Vec::new()));
        record.network = NetworkPolicy::DomainAllowList {
            domains: vec!["x".to_owned()],
        };
        assert!(build_network_policy(&record).is_err());
    }
}
