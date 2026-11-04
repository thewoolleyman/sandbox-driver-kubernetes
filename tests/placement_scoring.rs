//! Placement proof for a host-side pressure reconciler (orchestrator
//! bd-ib-plon2p): a `PreferNoSchedule` taint on a pressured factory node
//! outweighs the sandbox pod's hostname topology spread, and never leaves a
//! pod Pending when the untainted node cannot fit it.
//!
//! The probe pods carry the scheduling shape this plugin renders for a
//! sandbox's first pod under the fleet's configuration: the factory
//! nodeSelector, the three fleet tolerations, and a hostname topology spread
//! (maxSkew 1, ScheduleAnyway) counted over every pod carrying the managed
//! label. Only the scheduler is under test, so the pods run the kind node's
//! preloaded pause image rather than a sandbox image.
//!
//! Needs a kind cluster with two schedulable worker nodes labelled
//! `ci-runner.io/factory=true` (ci/kind-placement.yaml), and runs only when
//! `SANDBOX_DRIVER_KUBERNETES_TEST_PLACEMENT` is set, so the single-node
//! `cluster` job skips it.

#![allow(
    clippy::field_reassign_with_default,
    reason = "the shared support module builds a non_exhaustive config field by field"
)]

mod support;

use std::time::Duration;

use k8s_openapi::api::core::v1::{Namespace, Node, Pod};
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use sandbox_driver_kubernetes::{MANAGED_LABEL, MANAGED_VALUE};
use serde_json::{Value, json};

const NAMESPACE: &str = "placement-proof";
const FACTORY_LABEL: &str = "ci-runner.io/factory";
const PRESSURE_TAINT: &str = "livespec.io/factory-pressure";
const PAUSE_IMAGE: &str = "registry.k8s.io/pause:3.10";
/// Matching pods preloaded on the untainted node. A two-node spread then
/// scores the tainted node at its maximum and the untainted node at zero: the
/// largest margin the spread can ever put against the taint.
const PRELOADED: usize = 3;

fn factory_pod(name: &str, cpu: &str, pin: Option<&str>) -> Pod {
    let mut spec = json!({
        "restartPolicy": "Never",
        "terminationGracePeriodSeconds": 0,
        "nodeSelector": { FACTORY_LABEL: "true" },
        "tolerations": [
            { "key": "node-role/ci", "operator": "Equal", "value": "factory", "effect": "NoSchedule" },
            { "key": "node.kubernetes.io/not-ready", "operator": "Exists", "effect": "NoExecute" },
            { "key": "node.kubernetes.io/unreachable", "operator": "Exists", "effect": "NoExecute" }
        ],
        "topologySpreadConstraints": [{
            "topologyKey": "kubernetes.io/hostname",
            "maxSkew": 1,
            "whenUnsatisfiable": "ScheduleAnyway",
            "labelSelector": { "matchLabels": { MANAGED_LABEL: MANAGED_VALUE } }
        }],
        "containers": [{
            "name": "sandbox",
            "image": PAUSE_IMAGE,
            "imagePullPolicy": "IfNotPresent",
            "resources": {
                "requests": { "cpu": cpu, "memory": "16Mi" },
                "limits": { "cpu": cpu, "memory": "16Mi" }
            }
        }]
    });
    if let Some(node) = pin {
        spec["nodeName"] = Value::from(node);
    }
    serde_json::from_value(json!({
        "metadata": { "name": name, "labels": { MANAGED_LABEL: MANAGED_VALUE } },
        "spec": spec
    }))
    .expect("pod manifest")
}

/// A pod with no managed label that takes `millis` of `node`'s CPU, so the
/// spread does not count it.
fn filler_pod(node: &str, millis: i64) -> Pod {
    serde_json::from_value(json!({
        "metadata": { "name": "filler" },
        "spec": {
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 0,
            "nodeName": node,
            "tolerations": [{ "operator": "Exists" }],
            "containers": [{
                "name": "filler",
                "image": PAUSE_IMAGE,
                "imagePullPolicy": "IfNotPresent",
                "resources": {
                    "requests": { "cpu": format!("{millis}m"), "memory": "16Mi" },
                    "limits": { "cpu": format!("{millis}m"), "memory": "16Mi" }
                }
            }]
        }
    }))
    .expect("filler manifest")
}

fn millicores(quantity: &str) -> i64 {
    quantity.strip_suffix('m').map_or_else(
        || (quantity.parse::<f64>().expect("cpu quantity") * 1000.0).round() as i64,
        |m| m.parse().expect("millicores"),
    )
}

async fn factory_nodes(client: kube::Client) -> Vec<String> {
    let mut nodes: Vec<String> = Api::<Node>::all(client)
        .list(&ListParams::default().labels(&format!("{FACTORY_LABEL}=true")))
        .await
        .expect("lists nodes")
        .items
        .into_iter()
        .filter_map(|node| node.metadata.name)
        .collect();
    nodes.sort();
    nodes
}

/// CPU on `node` that no running or pending pod has requested.
async fn unrequested_cpu(client: kube::Client, node: &str) -> i64 {
    let allocatable = Api::<Node>::all(client.clone())
        .get(node)
        .await
        .expect("reads node")
        .status
        .and_then(|status| status.allocatable)
        .and_then(|allocatable| allocatable.get("cpu").map(|q| millicores(&q.0)))
        .expect("allocatable cpu");
    let requested: i64 = Api::<Pod>::all(client)
        .list(&ListParams::default().fields(&format!("spec.nodeName={node}")))
        .await
        .expect("lists pods")
        .items
        .iter()
        .filter(|pod| {
            !matches!(
                pod.status.as_ref().and_then(|s| s.phase.as_deref()),
                Some("Succeeded" | "Failed")
            )
        })
        .flat_map(|pod| pod.spec.iter().flat_map(|spec| spec.containers.iter()))
        .filter_map(|container| {
            container
                .resources
                .as_ref()
                .and_then(|r| r.requests.as_ref())
                .and_then(|requests| requests.get("cpu"))
                .map(|q| millicores(&q.0))
        })
        .sum();
    allocatable - requested
}

/// The node `name` was bound to, or None when it is still unscheduled at the
/// deadline.
async fn bound_node(pods: &Api<Pod>, name: &str) -> Option<String> {
    for _ in 0..60 {
        let pod = pods.get(name).await.expect("reads pod");
        if let Some(node) = pod.spec.and_then(|spec| spec.node_name) {
            return Some(node);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    None
}

async fn set_taint(client: kube::Client, node: &str, present: bool) {
    let nodes = Api::<Node>::all(client);
    let mut taints: Vec<Value> = nodes
        .get(node)
        .await
        .expect("reads node")
        .spec
        .and_then(|spec| spec.taints)
        .unwrap_or_default()
        .into_iter()
        .filter(|taint| taint.key != PRESSURE_TAINT)
        .map(|taint| serde_json::to_value(taint).expect("taint json"))
        .collect();
    if present {
        taints
            .push(json!({ "key": PRESSURE_TAINT, "value": "high", "effect": "PreferNoSchedule" }));
    }
    nodes
        .patch(
            node,
            &PatchParams::default(),
            &Patch::Merge(json!({ "spec": { "taints": taints } })),
        )
        .await
        .expect("patches taints");
}

async fn fresh_namespace(client: kube::Client) {
    let namespaces = Api::<Namespace>::all(client);
    let _ = namespaces.delete(NAMESPACE, &DeleteParams::default()).await;
    for _ in 0..120 {
        if namespaces
            .get_opt(NAMESPACE)
            .await
            .expect("reads")
            .is_none()
        {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let namespace: Namespace =
        serde_json::from_value(json!({ "metadata": { "name": NAMESPACE } })).expect("manifest");
    namespaces
        .create(&PostParams::default(), &namespace)
        .await
        .expect("creates namespace");
    // The namespace's default ServiceAccount must exist before a pod is admitted.
    tokio::time::sleep(Duration::from_secs(3)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_prefer_no_schedule_pressure_taint_outweighs_the_hostname_spread() {
    if std::env::var_os("SANDBOX_DRIVER_KUBERNETES_TEST_PLACEMENT").is_none() {
        return;
    }
    let config = kube::Config::from_custom_kubeconfig(
        kube::config::Kubeconfig::read_from(support::kubeconfig().expect("test kubeconfig"))
            .expect("reads kubeconfig"),
        &kube::config::KubeConfigOptions::default(),
    )
    .await
    .expect("kubeconfig");
    let client = kube::Client::try_from(config).expect("client");
    let nodes = factory_nodes(client.clone()).await;
    assert_eq!(nodes.len(), 2, "two factory nodes, found {nodes:?}");
    let (pressured, quiet) = (nodes[0].as_str(), nodes[1].as_str());
    fresh_namespace(client.clone()).await;
    let pods = Api::<Pod>::namespaced(client.clone(), NAMESPACE);
    let post = PostParams::default();

    // The quiet node already carries more sandbox pods, so the spread alone
    // sends the next pod to the pressured node.
    for i in 0..PRELOADED {
        pods.create(
            &post,
            &factory_pod(&format!("preload-{i}"), "100m", Some(quiet)),
        )
        .await
        .expect("preloads");
    }
    set_taint(client.clone(), pressured, false).await;

    // Control: no taint, so the spread wins and picks the pressured node.
    pods.create(&post, &factory_pod("probe-control", "100m", None))
        .await
        .expect("creates control probe");
    let control = bound_node(&pods, "probe-control").await;
    println!("control probe (no taint) bound to {control:?}; quiet={quiet} pressured={pressured}");
    assert_eq!(
        control.as_deref(),
        Some(pressured),
        "without the taint the spread picks the emptier node"
    );
    pods.delete("probe-control", &DeleteParams::default())
        .await
        .expect("deletes control probe");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Assertion 1: the pressure taint outweighs the spread.
    set_taint(client.clone(), pressured, true).await;
    pods.create(&post, &factory_pod("probe-tainted", "100m", None))
        .await
        .expect("creates tainted probe");
    let tainted = bound_node(&pods, "probe-tainted").await;
    println!("probe under taint bound to {tainted:?}");
    assert_eq!(
        tainted.as_deref(),
        Some(quiet),
        "the taint steers the pod to the quiet node"
    );

    // Assertion 2: when the quiet node cannot fit the pod, the pod goes to the
    // tainted node instead of staying Pending.
    let free = unrequested_cpu(client.clone(), quiet).await;
    println!("quiet node {quiet} has {free}m unrequested before the filler");
    pods.create(&post, &filler_pod(quiet, free - 100))
        .await
        .expect("creates filler");
    pods.create(&post, &factory_pod("probe-full", "200m", None))
        .await
        .expect("creates full probe");
    let full = bound_node(&pods, "probe-full").await;
    println!("probe with the quiet node full bound to {full:?}");
    assert_eq!(
        full.as_deref(),
        Some(pressured),
        "a full quiet node never leaves the pod Pending"
    );

    set_taint(client.clone(), pressured, false).await;
    let _ = Api::<Namespace>::all(client)
        .delete(NAMESPACE, &DeleteParams::default())
        .await;
}
