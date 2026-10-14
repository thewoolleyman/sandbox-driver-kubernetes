//! Lifecycle behaviour against a real (throwaway) cluster. Each test is one
//! assertion of the plugin's Definition of Done; see the README.
//!
//! Gated on `SANDBOX_DRIVER_KUBERNETES_TEST_KUBECONFIG`, like the
//! conformance tests. Run with `--test-threads 1`.

#![allow(
    clippy::field_reassign_with_default,
    reason = "non_exhaustive driver types are built field by field"
)]

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;

use k8s_openapi::api::core::v1::{Pod, Secret, ServiceAccount};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::rbac::v1::{Role, RoleBinding};
use kube::api::{Api, DeleteParams, ListParams, PostParams};
use sandbox_driver::{
    Capability, Error, ExecSpec, Resources, SandboxFilter, SandboxProvider, SandboxSource,
    SandboxSpec, SandboxState,
};
use sandbox_driver_kubernetes::{KubernetesProvider, is_valid_label_value};
use sandbox_driver_protocol::{PluginConfig, file_sha256, launch_plugin};

fn spec() -> SandboxSpec {
    SandboxSpec::new(SandboxSource::Image {
        reference: support::TEST_IMAGE.to_owned(),
    })
    .working_directory("/workspace")
}

async fn pods(client: kube::Client) -> Vec<Pod> {
    Api::<Pod>::namespaced(client, support::NAMESPACE)
        .list(
            &ListParams::default().labels("app.kubernetes.io/managed-by=sandbox-driver-kubernetes"),
        )
        .await
        .expect("lists pods")
        .items
}

async fn pod(client: kube::Client, name: &str) -> Option<Pod> {
    Api::<Pod>::namespaced(client, support::NAMESPACE)
        .get_opt(name)
        .await
        .expect("reads pod")
}

/// Assertion 1: launched by a protocol v2 host, the plugin creates a pod,
/// streams stdout and stderr separately, round-trips a file, and deletes the
/// pod on destroy.
#[tokio::test(flavor = "multi_thread")]
async fn a_launched_plugin_serves_a_sandbox_end_to_end() {
    let Some(config) = support::config("launched") else {
        return;
    };
    let admin = KubernetesProvider::connect(config.clone())
        .await
        .expect("connects");
    support::ensure_namespace(admin.client().current().await).await;

    // The plugin starts from a scrubbed environment: only HOME, pointing at
    // a home whose config file names the cluster.
    let home = std::env::temp_dir().join(format!("sdk-home-{}", std::process::id()));
    let config_dir = home.join(".config/sandbox-driver-kubernetes");
    std::fs::create_dir_all(&config_dir).expect("mkdir");
    std::fs::write(
        config_dir.join("config.toml"),
        format!(
            "kubeconfig = {:?}\nnamespace = {:?}\nstate_dir = {:?}\nworkspace_root = {:?}\nfactory = \"ci\"\n",
            config.kubeconfig.display().to_string(),
            config.namespace,
            config.state_dir.display().to_string(),
            config.workspace_root,
        ),
    )
    .expect("write config");
    let binary = env!("CARGO_BIN_EXE_sandbox-driver-kubernetes");
    let checksum = file_sha256(std::path::Path::new(binary))
        .await
        .expect("checksum");
    let plugin =
        PluginConfig::new(sandbox_driver::ProviderKind::try_new("kubernetes").expect("kind"))
            .path(binary)
            .sha256(checksum)
            .env_var("HOME", home.display().to_string());
    let launch = launch_plugin("sandbox-driver", &plugin)
        .await
        .expect("plugin launches");
    assert!(launch.verified, "the plugin was launched checksum-verified");
    let provider = launch.provider;
    assert_eq!(provider.kind().as_str(), "kubernetes");

    let sandbox = provider.create(&spec(), None).await.expect("creates");
    let id = sandbox.id().as_str().to_owned();
    assert!(
        pod(admin.client().current().await, &id).await.is_some(),
        "a pod exists"
    );

    let result = sandbox
        .exec()
        .run(&ExecSpec::new("/bin/sh").args(["-c", "printf out; printf err >&2; exit 3"]))
        .await
        .expect("runs");
    assert_eq!(result.stdout, b"out");
    assert_eq!(result.stderr, b"err");
    assert_eq!(result.exit_code, Some(3));

    sandbox
        .fs()
        .write("hello.txt", b"hello from a pod")
        .await
        .expect("writes");
    assert_eq!(
        sandbox.fs().read("hello.txt").await.expect("reads"),
        b"hello from a pod"
    );

    sandbox.delete().await.expect("deletes");
    assert!(
        pod(admin.client().current().await, &id).await.is_none(),
        "the pod is gone"
    );
    let _ = std::fs::remove_dir_all(&home);
}

/// Assertion 2: requests equal limits, as declared.
#[tokio::test(flavor = "multi_thread")]
async fn requests_and_limits_equal_the_declared_resources() {
    let Some(provider) = support::provider("resources").await else {
        return;
    };
    let client = provider.client().current().await;
    // The declared factory numbers need a node with more than 4 allocatable
    // cores; a small CI node proves the same mapping with smaller ones.
    let nodes = Api::<k8s_openapi::api::core::v1::Node>::all(client.clone())
        .list(&ListParams::default())
        .await
        .expect("lists nodes");
    let cores: u32 = nodes
        .items
        .iter()
        .filter_map(|node| node.status.as_ref()?.allocatable.as_ref()?.get("cpu"))
        .filter_map(|quantity| quantity.0.parse::<u32>().ok())
        .max()
        .unwrap_or(0);
    let (cpu, memory) = if cores > 5 { (4, 8192) } else { (1, 512) };
    let mut resources = Resources::default();
    resources.cpu_cores = Some(cpu);
    resources.memory_mb = Some(memory);
    let sandbox = provider
        .create(&spec().resources(resources), None)
        .await
        .expect("creates");
    let pod = pod(client, sandbox.id().as_str()).await.expect("pod");
    let container = &pod.spec.expect("spec").containers[0];
    let requirements = container.resources.clone().expect("resources");
    let limits = requirements.limits.expect("limits");
    assert_eq!(requirements.requests.expect("requests"), limits);
    assert_eq!(limits["cpu"].0, cpu.to_string());
    assert_eq!(limits["memory"].0, format!("{memory}Mi"));
    eprintln!(
        "pod {} requests = limits = cpu {cpu}, memory {memory}Mi",
        sandbox.id()
    );
    sandbox.delete().await.expect("deletes");
}

/// Assertion 3: refused requests create nothing.
#[tokio::test(flavor = "multi_thread")]
async fn refused_requests_create_no_pod() {
    let Some(provider) = support::provider("refusals").await else {
        return;
    };
    let client = provider.client().current().await;
    let before = pods(client.clone()).await.len();

    let mut gpus = Resources::default();
    gpus.gpus = Some(1);
    assert!(matches!(
        provider.create(&spec().resources(gpus), None).await.err(),
        Some(Error::InvalidSpec { .. })
    ));
    let snapshot = SandboxSpec::new(SandboxSource::Snapshot {
        id: sandbox_driver::SnapshotId::try_new("snap").expect("id"),
    });
    assert!(matches!(
        provider.create(&snapshot, None).await.err(),
        Some(Error::Unsupported {
            capability: Capability::Snapshots
        })
    ));
    assert_eq!(
        pods(client.clone()).await.len(),
        before,
        "refusals created no pod"
    );

    let sandbox = provider.create(&spec(), None).await.expect("creates");
    assert!(sandbox.pty().is_none());
    assert!(sandbox.one_shot().is_none());
    assert!(matches!(
        sandbox
            .fork(&sandbox_driver::ForkOptions::default())
            .await
            .err(),
        Some(Error::Unsupported { .. })
    ));
    assert!(matches!(
        sandbox
            .snapshot(&sandbox_driver::SandboxSnapshotOptions::default())
            .await
            .err(),
        Some(Error::Unsupported { .. })
    ));
    assert!(matches!(
        sandbox.pause().await.err(),
        Some(Error::Unsupported { .. })
    ));
    assert_eq!(
        pods(client.clone()).await.len(),
        before + 1,
        "only the sandbox's own pod exists"
    );
    sandbox.delete().await.expect("deletes");
}

/// Assertion 4: after the cluster loses a sandbox's pod and network policy
/// (as a control-plane rebuild does), a fresh plugin process re-creates the
/// pod on the same node over the surviving workspace.
#[tokio::test(flavor = "multi_thread")]
async fn a_sandbox_survives_the_loss_of_its_cluster_objects() {
    let Some(config) = support::config("rebuild") else {
        return;
    };
    let provider = KubernetesProvider::connect(config.clone())
        .await
        .expect("connects");
    let client = provider.client().current().await;
    support::ensure_namespace(client.clone()).await;
    let sandbox = provider
        .create(&spec().network(sandbox_driver::NetworkPolicy::Block), None)
        .await
        .expect("creates");
    let id = sandbox.id().clone();
    sandbox
        .fs()
        .write("work/progress.txt", b"implement stage output")
        .await
        .expect("writes");
    let node = pod(client.clone(), id.as_str())
        .await
        .expect("pod")
        .spec
        .expect("spec")
        .node_name;

    // The control plane forgets everything about the sandbox.
    Api::<Pod>::namespaced(client.clone(), support::NAMESPACE)
        .delete(id.as_str(), &DeleteParams::default().grace_period(0))
        .await
        .expect("deletes pod");
    Api::<NetworkPolicy>::namespaced(client.clone(), support::NAMESPACE)
        .delete(id.as_str(), &DeleteParams::default())
        .await
        .expect("deletes policy");
    for _ in 0..60 {
        if pod(client.clone(), id.as_str()).await.is_none() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    drop(sandbox);
    drop(provider);

    // A new plugin process, holding only its host-side record.
    let provider = KubernetesProvider::connect(config)
        .await
        .expect("reconnects");
    let sandbox = provider.attach(&id, None).await.expect("attaches by id");
    assert_eq!(
        sandbox.describe().await.expect("describes").state,
        SandboxState::Stopped
    );
    sandbox.start().await.expect("starts again");
    let again = pod(client.clone(), id.as_str())
        .await
        .expect("pod re-created");
    assert_eq!(again.spec.expect("spec").node_name, node, "same node");
    assert_eq!(
        sandbox.fs().read("work/progress.txt").await.expect("reads"),
        b"implement stage output",
        "same workspace contents"
    );
    assert!(
        Api::<NetworkPolicy>::namespaced(client, support::NAMESPACE)
            .get_opt(id.as_str())
            .await
            .expect("reads policy")
            .is_some(),
        "the network policy came back too"
    );
    sandbox.delete().await.expect("deletes");
}

/// Assertion 6: Petri's slash-bearing reconcile key round-trips.
#[tokio::test(flavor = "multi_thread")]
async fn petri_labels_round_trip_through_the_cluster() {
    let Some(provider) = support::provider("labels").await else {
        return;
    };
    let client = provider.client().current().await;
    let workspace = "01JABCDEFGHJKMNPQRSTVWXYZ0/implement";
    let sandbox = provider
        .create(
            &spec()
                .name("petri-01JABCDEFGHJKMNPQRSTVWXYZ0-l1")
                .label("petri.run", "01JABCDEFGHJKMNPQRSTVWXYZ0")
                .label("petri.lease", "1")
                .label("petri.workspace", workspace),
            None,
        )
        .await
        .expect("creates");
    assert_eq!(sandbox.id().as_str(), "petri-01jabcdefghjkmnpqrstvwxyz0-l1");
    let pod = pod(client, sandbox.id().as_str()).await.expect("pod");
    let labels = pod.metadata.labels.expect("labels");
    for value in labels.values() {
        assert!(
            is_valid_label_value(value),
            "{value:?} is a valid label value"
        );
    }
    assert_ne!(labels["petri.workspace"], workspace);
    assert_eq!(
        pod.metadata.annotations.expect("annotations")["petri.workspace"],
        workspace
    );
    assert_eq!(
        sandbox.describe().await.expect("describes").labels["petri.workspace"],
        workspace
    );
    let mut filter = SandboxFilter::default();
    filter.labels = BTreeMap::from([("petri.workspace".to_owned(), workspace.to_owned())]);
    let found = provider.list(&filter).await.expect("lists");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, *sandbox.id());
    sandbox.delete().await.expect("deletes");
}

/// Assertion 7: a rotated credential is picked up on the next 401 without
/// restarting the plugin. Rotation here is what a control-plane rebuild
/// does: the ServiceAccount is re-created, so its old token is rejected.
#[tokio::test(flavor = "multi_thread")]
async fn a_rotated_kubeconfig_is_reread_on_401() {
    let Some(admin_config) = support::config("rotation-admin") else {
        return;
    };
    let admin = KubernetesProvider::connect(admin_config.clone())
        .await
        .expect("connects");
    let client = admin.client().current().await;
    support::ensure_namespace(client.clone()).await;
    let name = "sdk-rotation";
    install_role(client.clone(), name).await;

    let kubeconfig = std::env::temp_dir().join(format!("sdk-rotating-{}.yaml", std::process::id()));
    let token = mint_service_account(client.clone(), name).await;
    write_kubeconfig(&admin_config.kubeconfig, &kubeconfig, &token);

    let mut config = admin_config.clone();
    config.kubeconfig = kubeconfig.clone();
    config.state_dir =
        std::env::temp_dir().join(format!("sdk-test-rotation-{}", std::process::id()));
    let provider = Arc::new(
        KubernetesProvider::connect(config)
            .await
            .expect("connects with the token"),
    );
    let health = provider.health().await.expect("health");
    assert_eq!(
        health.status,
        sandbox_driver::HealthStatus::Ok,
        "{health:?}"
    );
    assert_eq!(provider.client().reloads(), 0);

    // Rotate: the ServiceAccount is re-created, the old token dies, and the
    // file is rewritten with the new one, while the plugin keeps running.
    Api::<ServiceAccount>::namespaced(client.clone(), support::NAMESPACE)
        .delete(name, &DeleteParams::default())
        .await
        .expect("deletes the service account");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let token = mint_service_account(client.clone(), name).await;
    write_kubeconfig(&admin_config.kubeconfig, &kubeconfig, &token);

    let sandbox = provider
        .create(&spec(), None)
        .await
        .expect("creates after rotation");
    assert!(
        provider.client().reloads() >= 1,
        "the kubeconfig was re-read"
    );
    sandbox.delete().await.expect("deletes");
    let _ = std::fs::remove_file(kubeconfig);
}

async fn install_role(client: kube::Client, name: &str) {
    let role: Role = serde_json::from_value(serde_json::json!({
        "metadata": { "name": name },
        "rules": [
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["create", "get", "list", "watch", "delete", "patch"] },
            { "apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create", "get"] },
            { "apiGroups": [""], "resources": ["events"], "verbs": ["list"] },
            { "apiGroups": ["networking.k8s.io"], "resources": ["networkpolicies"], "verbs": ["create", "get", "list", "delete"] }
        ]
    }))
    .expect("role");
    let binding: RoleBinding = serde_json::from_value(serde_json::json!({
        "metadata": { "name": name },
        "roleRef": { "apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name },
        "subjects": [{ "kind": "ServiceAccount", "name": name, "namespace": support::NAMESPACE }]
    }))
    .expect("binding");
    let roles = Api::<Role>::namespaced(client.clone(), support::NAMESPACE);
    let _ = roles.delete(name, &DeleteParams::default()).await;
    roles
        .create(&PostParams::default(), &role)
        .await
        .expect("creates role");
    let bindings = Api::<RoleBinding>::namespaced(client.clone(), support::NAMESPACE);
    let _ = bindings.delete(name, &DeleteParams::default()).await;
    bindings
        .create(&PostParams::default(), &binding)
        .await
        .expect("creates binding");
    // Nodes are cluster-scoped; the namespace Role cannot grant them, and the
    // plugin treats a forbidden node read as "unknown", which these flows do
    // not reach.
}

async fn mint_service_account(client: kube::Client, name: &str) -> String {
    let accounts = Api::<ServiceAccount>::namespaced(client.clone(), support::NAMESPACE);
    let account: ServiceAccount =
        serde_json::from_value(serde_json::json!({ "metadata": { "name": name } })).expect("sa");
    accounts
        .create(&PostParams::default(), &account)
        .await
        .expect("creates the service account");
    let secret: Secret = serde_json::from_value(serde_json::json!({
        "metadata": { "name": format!("{name}-token"), "annotations": { "kubernetes.io/service-account.name": name } },
        "type": "kubernetes.io/service-account-token"
    }))
    .expect("secret");
    let secrets = Api::<Secret>::namespaced(client, support::NAMESPACE);
    let _ = secrets
        .delete(&format!("{name}-token"), &DeleteParams::default())
        .await;
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    secrets
        .create(&PostParams::default(), &secret)
        .await
        .expect("creates the token secret");
    for _ in 0..60 {
        let current = secrets
            .get(&format!("{name}-token"))
            .await
            .expect("reads the token secret");
        if let Some(token) = current.data.and_then(|data| data.get("token").cloned()) {
            return String::from_utf8(token.0).expect("utf8 token");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    panic!("the token controller never filled the token");
}

/// Writes a kubeconfig for the admin file's cluster that authenticates with
/// `token`.
fn write_kubeconfig(admin: &std::path::Path, out: &std::path::Path, token: &str) {
    let mut config = kube::config::Kubeconfig::read_from(admin).expect("reads admin kubeconfig");
    for auth in &mut config.auth_infos {
        if let Some(info) = auth.auth_info.as_mut() {
            info.client_certificate_data = None;
            info.client_key_data = None;
            info.client_certificate = None;
            info.client_key = None;
            info.token = Some(token.to_owned().into());
        }
    }
    for context in &mut config.contexts {
        if let Some(context) = context.context.as_mut() {
            context.namespace = Some(support::NAMESPACE.to_owned());
        }
    }
    let staged = out.with_extension("tmp");
    std::fs::write(&staged, serde_yaml_ng_free(&config)).expect("writes kubeconfig");
    std::fs::rename(staged, out).expect("installs kubeconfig");
}

/// Kubeconfig as JSON, which is valid YAML.
fn serde_yaml_ng_free(config: &kube::config::Kubeconfig) -> Vec<u8> {
    serde_json::to_vec_pretty(config).expect("serializes kubeconfig")
}
