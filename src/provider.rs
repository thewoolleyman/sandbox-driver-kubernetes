//! The Kubernetes provider: create, attach, list and delete sandboxes.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ListParams};
use rand::Rng as _;
use sandbox_driver::{
    Action, Capabilities, Capability, Error, EventContext, EventEmitter, EventSubject,
    HealthStatus, LifecycleTimers, ProviderHealth, ProviderKind, Result, Sandbox, SandboxFilter,
    SandboxId, SandboxProvider, SandboxSource, SandboxSpec, SandboxStatus,
};

use crate::client::KubeClient;
use crate::config::KubernetesConfig;
use crate::error::{not_found, record_io, status_code};
use crate::pod::{Cluster, Incarnation, build_network_policy, resource_requirements};
use crate::record::{Record, RecordStore};
use crate::sandbox::{KubernetesSandbox, Timeouts, status_of};
use crate::{
    DEFAULT_WORKING_DIRECTORY, MANAGED_LABEL, MANAGED_VALUE, kubernetes_capabilities,
    kubernetes_kind,
};

/// The provider. One per plugin process, sharing one reloading client.
pub struct KubernetesProvider {
    kind: ProviderKind,
    capabilities: Capabilities,
    config: KubernetesConfig,
    cluster: Cluster,
    store: RecordStore,
}

/// The backend's resource identity: the API server and the namespace,
/// neither of them secret, both unchanged by a credential rotation.
fn resource_identity(endpoint: &str, namespace: &str) -> String {
    format!("{}/{namespace}", endpoint.trim_end_matches('/'))
}

/// Whether `name` is a valid DNS label (a pod name the plugin can adopt).
fn is_dns_label(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// The logical sandbox id for `spec`: its name lowercased when that is a
/// DNS label (Petri's `petri-<run>-l<lease>`), otherwise a generated one.
pub(crate) fn sandbox_id_for(spec: &SandboxSpec) -> String {
    if let Some(name) = &spec.name {
        let lowered = name.to_lowercase();
        if is_dns_label(&lowered) {
            return lowered;
        }
    }
    let mut rng = rand::rng();
    let suffix: String = (0..12)
        .map(|_| char::from(b"0123456789abcdefghijklmnopqrstuvwxyz"[rng.random_range(0..36)]))
        .collect();
    format!("sdk-{suffix}")
}

impl KubernetesProvider {
    /// Builds the provider from `config`, reading its kubeconfig file.
    pub async fn connect(config: KubernetesConfig) -> anyhow::Result<Self> {
        let client = KubeClient::from_file(config.kubeconfig.clone(), config.context.clone())
            .await?
            .with_refresh(
                config.refresh_command.clone(),
                std::time::Duration::from_secs(config.refresh_timeout_secs),
            );
        let cluster = Cluster {
            client,
            namespace: config.namespace.clone(),
        };
        let store = RecordStore::new(config.state_dir.clone());
        Ok(Self {
            kind: kubernetes_kind(),
            capabilities: kubernetes_capabilities(),
            config,
            cluster,
            store,
        })
    }

    /// The client, for tests that rotate the credential.
    pub fn client(&self) -> &KubeClient {
        &self.cluster.client
    }

    fn timeouts(&self) -> Timeouts {
        Timeouts {
            start: Duration::from_secs(self.config.start_timeout_secs),
            stop: Duration::from_secs(self.config.stop_timeout_secs),
        }
    }

    fn handle(&self, record: Record, events: EventEmitter) -> Result<Arc<KubernetesSandbox>> {
        Ok(Arc::new(KubernetesSandbox::new(
            record,
            self.cluster.clone(),
            self.store.clone(),
            self.capabilities.clone(),
            self.timeouts(),
            events,
        )?))
    }

    /// Validates `spec` and turns it into a record.
    fn plan(&self, spec: &SandboxSpec) -> Result<Record> {
        let image = match &spec.source {
            SandboxSource::Image { reference } => reference.clone(),
            SandboxSource::Snapshot { .. } => {
                return Err(Error::unsupported(Capability::Snapshots));
            }
            SandboxSource::Dockerfile { .. } => {
                return Err(Error::unsupported(
                    Capability::SnapshotsContainerFromDockerfile,
                ));
            }
            _ => {
                return Err(Error::invalid_spec(
                    "source",
                    "the kubernetes provider runs container images only",
                ));
            }
        };
        if !spec.volumes.is_empty() {
            return Err(Error::unsupported(Capability::Volumes));
        }
        if spec.timers != LifecycleTimers::default() {
            return Err(Error::unsupported(Capability::LifecycleTimers));
        }
        spec.network.validate()?;
        resource_requirements(&spec.resources)?;
        let id = sandbox_id_for(spec);
        let working_dir = spec
            .working_directory
            .clone()
            .unwrap_or_else(|| DEFAULT_WORKING_DIRECTORY.to_owned());
        if !working_dir.starts_with('/') {
            return Err(Error::invalid_spec(
                "working_directory",
                "must be an absolute path",
            ));
        }
        let record = Record {
            workspace_dir: format!("{}/{id}", self.config.workspace_root.trim_end_matches('/')),
            id,
            name: spec.name.clone(),
            namespace: self.config.namespace.clone(),
            node: None,
            working_dir,
            image,
            resources: spec.resources,
            env: spec.env.clone(),
            labels: spec.labels.clone(),
            network: spec.network.clone(),
            user: spec.user.clone(),
            node_selector: self.config.node_selector.clone(),
            tolerations: self.config.tolerations.clone(),
            apparmor_localhost_profile: self.config.apparmor_localhost_profile.clone(),
            service_account: self.config.service_account.clone(),
            image_pull_secrets: self.config.image_pull_secrets.clone(),
            factory: self.config.factory.clone(),
        };
        build_network_policy(&record)?;
        crate::pod::build_pod(&record, Incarnation::First)?;
        Ok(record)
    }
}

#[async_trait]
impl SandboxProvider for KubernetesProvider {
    fn kind(&self) -> &ProviderKind {
        &self.kind
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "kubernetes"), err)]
    async fn create(
        &self,
        spec: &SandboxSpec,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let record = self.plan(spec)?;
        let emitter = EventEmitter::new(self.kind.clone(), events);
        let handle_emitter = emitter.clone();
        emitter
            .run(
                EventSubject::pending_sandbox(spec.name.clone()),
                Action::Create,
                |reporter| async move {
                    if self
                        .store
                        .load(&record.id)
                        .map_err(|error| record_io("checking for an existing sandbox", error))?
                        .is_some()
                    {
                        return Err(Error::invalid_spec(
                            "name",
                            format!("a sandbox named {} already exists", record.id),
                        ));
                    }
                    self.store
                        .save(&record)
                        .map_err(|error| record_io("recording the new sandbox", error))?;
                    let handle = self.handle(record, handle_emitter)?;
                    reporter.set_subject(EventSubject::sandbox(Some(handle.id.clone())));
                    if let Err(error) = handle.launch(Incarnation::First).await {
                        if let Err(cleanup) = handle.delete_inner().await {
                            tracing::warn!(error = %cleanup, "cleaning up a failed create");
                        }
                        return Err(error);
                    }
                    Ok(handle as Arc<dyn Sandbox>)
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "kubernetes", sandbox_id = %id), err)]
    async fn attach(
        &self,
        id: &SandboxId,
        events: Option<EventContext>,
    ) -> Result<Arc<dyn Sandbox>> {
        let emitter = EventEmitter::new(self.kind.clone(), events);
        let handle_emitter = emitter.clone();
        emitter
            .run(
                EventSubject::sandbox(Some(id.clone())),
                Action::Attach,
                |_| async move {
                    let record = self
                        .store
                        .load(id.as_str())
                        .map_err(|error| record_io("reading the sandbox record", error))?
                        .ok_or_else(|| not_found(id.as_str()))?;
                    Ok(self.handle(record, handle_emitter)? as Arc<dyn Sandbox>)
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "kubernetes", sandbox_id = %id), err)]
    async fn delete(&self, id: &SandboxId, events: Option<EventContext>) -> Result<()> {
        let emitter = EventEmitter::new(self.kind.clone(), events);
        let handle_emitter = emitter.clone();
        emitter
            .run(
                EventSubject::sandbox(Some(id.clone())),
                Action::Delete,
                |_| async move {
                    let Some(record) = self
                        .store
                        .load(id.as_str())
                        .map_err(|error| record_io("reading the sandbox record", error))?
                    else {
                        return Ok(());
                    };
                    self.handle(record, handle_emitter)?.delete_inner().await
                },
            )
            .await
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "kubernetes"), err)]
    async fn list(&self, filter: &SandboxFilter) -> Result<Vec<SandboxStatus>> {
        let records = self
            .store
            .list()
            .map_err(|error| record_io("listing sandbox records", error))?;
        let pods: BTreeMap<String, Pod> = self
            .cluster
            .list_pods(&format!("{MANAGED_LABEL}={MANAGED_VALUE}"))
            .await?
            .into_iter()
            .filter_map(|pod| pod.metadata.name.clone().map(|name| (name, pod)))
            .collect();
        let mut statuses = Vec::new();
        for record in records {
            if record.namespace != self.config.namespace {
                continue;
            }
            if !filter
                .labels
                .iter()
                .all(|(key, value)| record.labels.get(key) == Some(value))
            {
                continue;
            }
            let id = SandboxId::try_new(record.id.clone())
                .map_err(|error| Error::invalid_spec("id", error.to_string()))?;
            statuses.push(status_of(&id, &record, pods.get(&record.id)));
        }
        Ok(statuses)
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "kubernetes"), err)]
    async fn health(&self) -> Result<ProviderHealth> {
        let namespace = self.config.namespace.clone();
        let result = self
            .cluster
            .client
            .call(|client| {
                let namespace = namespace.clone();
                async move {
                    Api::<Pod>::namespaced(client, &namespace)
                        .list(&ListParams::default().limit(1))
                        .await
                }
            })
            .await;
        let mut health = match result {
            Ok(_) => ProviderHealth::new(HealthStatus::Ok),
            Err(error) => {
                let status = match status_code(&error) {
                    Some(401 | 403) => HealthStatus::Unauthorized,
                    _ => HealthStatus::Unreachable,
                };
                let mut health = ProviderHealth::new(status);
                health.message = Some(format!(
                    "listing pods in {}: {error}",
                    self.config.namespace
                ));
                health
            }
        };
        // The resource namespace a host binds recovery to: which cluster, and
        // which namespace in it. A host refuses to create or recover sandboxes
        // on a provider that names none.
        health.identity = Some(resource_identity(
            &self.cluster.client.endpoint().await,
            &self.config.namespace,
        ));
        Ok(health)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_resource_identity_names_the_api_server_and_the_namespace() {
        assert_eq!(
            resource_identity("https://192.168.1.4:6443/", "factory"),
            "https://192.168.1.4:6443/factory"
        );
        assert_ne!(
            resource_identity("https://a:6443", "factory"),
            resource_identity("https://b:6443", "factory"),
            "two clusters are two identities"
        );
        assert_ne!(
            resource_identity("https://a:6443", "factory"),
            resource_identity("https://a:6443", "other"),
            "two namespaces are two identities"
        );
    }

    #[test]
    fn petri_names_become_the_pod_name_and_others_are_generated() {
        let spec = SandboxSpec::new(SandboxSource::Image {
            reference: "img".to_owned(),
        })
        .name("petri-01JABCDEFGHJKMNPQRSTVWXYZ0-l3");
        assert_eq!(sandbox_id_for(&spec), "petri-01jabcdefghjkmnpqrstvwxyz0-l3");
        let unnamed = SandboxSpec::new(SandboxSource::Image {
            reference: "img".to_owned(),
        });
        let generated = sandbox_id_for(&unnamed);
        assert!(
            generated.starts_with("sdk-") && is_dns_label(&generated),
            "{generated}"
        );
    }
}
