//! Building and driving a sandbox's pod and network policy.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use k8s_openapi::api::core::v1::{
    Affinity, AppArmorProfile, Container, EnvVar, Event, HostPathVolumeSource,
    LocalObjectReference, Node, NodeAffinity, NodeSelector, NodeSelectorRequirement,
    NodeSelectorTerm, Pod, PodSecurityContext, PodSpec, ResourceRequirements, Toleration, Volume,
    VolumeMount,
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
/// Label carrying the factory identity, when configured.
pub(crate) const FACTORY_LABEL: &str = "livespec.dispatch.factory";
const HOSTNAME_LABEL: &str = "kubernetes.io/hostname";
const POLL: Duration = Duration::from_secs(1);

/// Whether the pod is the first of its sandbox (its workspace directory may
/// be created) or a re-creation (the directory must already exist).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Incarnation {
    First,
    Recreate,
}

/// Validates the spec's resources and renders them as requests equal to
/// limits.
pub(crate) fn resource_requirements(resources: &Resources) -> Result<Option<ResourceRequirements>> {
    if resources.gpus.is_some_and(|gpus| gpus > 0) {
        return Err(Error::invalid_spec(
            "resources.gpus",
            "the kubernetes provider serves no GPUs; refusing rather than dropping a requested \
             resource",
        ));
    }
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
    Ok(Some(ResourceRequirements {
        requests: Some(quantities.clone()),
        limits: Some(quantities),
        ..ResourceRequirements::default()
    }))
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

pub(crate) fn build_pod(record: &Record, incarnation: Incarnation) -> Result<Pod> {
    let env = record
        .env
        .iter()
        .map(|(name, value)| EnvVar {
            name: name.clone(),
            value: Some(value.clone()),
            value_from: None,
        })
        .collect::<Vec<_>>();
    let host_path_type = match incarnation {
        Incarnation::First => "DirectoryOrCreate",
        Incarnation::Recreate => "Directory",
    };
    let (node_selector, affinity) = match &record.node {
        Some(node) => (
            None,
            Some(Affinity {
                node_affinity: Some(NodeAffinity {
                    required_during_scheduling_ignored_during_execution: Some(NodeSelector {
                        node_selector_terms: vec![NodeSelectorTerm {
                            match_expressions: Some(vec![NodeSelectorRequirement {
                                key: HOSTNAME_LABEL.to_owned(),
                                operator: "In".to_owned(),
                                values: Some(vec![node.clone()]),
                            }]),
                            match_fields: None,
                        }],
                    }),
                    ..NodeAffinity::default()
                }),
                ..Affinity::default()
            }),
        ),
        None => (
            (!record.node_selector.is_empty()).then(|| record.node_selector.clone()),
            None,
        ),
    };
    let run_as_user = record
        .user
        .as_deref()
        .and_then(|user| user.parse::<i64>().ok());
    // The idle process ends promptly on TERM, so deleting the pod does not
    // wait out a grace period on a PID 1 that ignores signals.
    let idle = format!(
        "mkdir -p {runtime} && chmod 0700 {parent} {runtime} && \
         trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done",
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
            tolerations: (!record.tolerations.is_empty()).then(|| {
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
            }),
            image_pull_secrets: (!record.image_pull_secrets.is_empty()).then(|| {
                record
                    .image_pull_secrets
                    .iter()
                    .map(|name| LocalObjectReference { name: name.clone() })
                    .collect()
            }),
            security_context: security_context(run_as_user, record),
            containers: vec![Container {
                name: CONTAINER_NAME.to_owned(),
                image: Some(record.image.clone()),
                command: Some(vec!["/bin/sh".to_owned(), "-c".to_owned(), idle]),
                working_dir: Some(record.working_dir.clone()),
                env: (!env.is_empty()).then_some(env),
                resources: resource_requirements(&record.resources)?,
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
            Ok(_) => {}
            Err(error) if is_not_found(&error) => return Ok(()),
            Err(error) => return Err(kube_error("deleting the sandbox pod", error)),
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
            service_account: Some("sa".to_owned()),
            image_pull_secrets: Vec::new(),
            factory: Some("hp".to_owned()),
        }
    }

    #[test]
    fn requests_equal_limits_and_gpus_are_refused() {
        let mut resources = Resources::default();
        resources.cpu_cores = Some(4);
        resources.memory_mb = Some(8192);
        let rendered = resource_requirements(&resources)
            .expect("ok")
            .expect("some");
        assert_eq!(rendered.requests, rendered.limits);
        let limits = rendered.limits.expect("limits");
        assert_eq!(limits["cpu"], Quantity("4".to_owned()));
        assert_eq!(limits["memory"], Quantity("8192Mi".to_owned()));
        resources.gpus = Some(1);
        assert!(resource_requirements(&resources).is_err());
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
