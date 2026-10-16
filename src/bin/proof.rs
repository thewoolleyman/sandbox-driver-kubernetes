//! `sandbox-driver-kubernetes-proof` — hold ONE plugin process across a
//! disruption an operator performs, and report what it observes.
//!
//! The plugin is launched exactly as a Fabro/Petri worker launches it: the
//! installed binary, verified against its pinned digest, behind a long-lived
//! protocol client. A per-command CLI cannot show that a single running
//! plugin survives a control-plane reboot or a node going `NotReady`; this
//! can. It never touches the cluster itself except through the plugin.
//!
//! ```text
//! sandbox-driver-kubernetes-proof <reboot|node-loss> --sha256 HEX --node NODE
//!     [--plugin PATH] [--image REF] [--cpu N] [--memory-mb N] [--minutes N] [--keep]
//! ```
//!
//! `reboot`: create a sandbox on NODE, write a marker into its workspace, then
//! poll health every 15 s. Once health has gone non-ok and come back ok (the
//! operator's reboot), re-attach, `start`, and read the marker back. Exit 0
//! only if the marker survived and the sandbox stayed on NODE.
//!
//! `node-loss`: create a sandbox on NODE, write a marker, then for `--minutes`
//! report the sandbox's state and an exec probe every 15 s while the operator
//! takes NODE away and brings it back.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use sandbox_driver::{
    ExecSpec, HealthStatus, ProviderKind, Resources, SandboxId, SandboxProvider, SandboxSource,
    SandboxSpec,
};
use sandbox_driver_protocol::{PluginConfig, launch_plugin};

const TICK: Duration = Duration::from_secs(15);
const MARKER: &str = ".sandbox-driver-kubernetes-proof-marker";

struct Args {
    scenario: String,
    plugin: PathBuf,
    sha256: String,
    node: String,
    image: String,
    cpu: u32,
    memory_mb: u64,
    minutes: u64,
    keep: bool,
}

fn parse() -> anyhow::Result<Args> {
    let mut raw = std::env::args().skip(1);
    let scenario = raw
        .next()
        .context("usage: proof <reboot|node-loss> --sha256 HEX --node NODE")?;
    let mut args = Args {
        scenario,
        plugin: PathBuf::from("/usr/local/bin/sandbox-driver-kubernetes"),
        sha256: String::new(),
        node: String::new(),
        image: "ghcr.io/thewoolleyman/livespec-fabro-sandbox:python-agent-v1.93.5".to_owned(),
        cpu: 1,
        memory_mb: 1024,
        minutes: 120,
        keep: false,
    };
    while let Some(flag) = raw.next() {
        let mut value = || raw.next().with_context(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--plugin" => args.plugin = PathBuf::from(value()?),
            "--sha256" => args.sha256 = value()?,
            "--node" => args.node = value()?,
            "--image" => args.image = value()?,
            "--cpu" => args.cpu = value()?.parse()?,
            "--memory-mb" => args.memory_mb = value()?.parse()?,
            "--minutes" => args.minutes = value()?.parse()?,
            "--keep" => args.keep = true,
            other => bail!("unknown flag {other}"),
        }
    }
    if args.sha256.is_empty() || args.node.is_empty() {
        bail!("--sha256 and --node are required");
    }
    Ok(args)
}

fn say(message: impl std::fmt::Display) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    println!("[{now}] {message}");
}

/// The node the plugin's host-side record holds for `id`.
fn recorded_node(id: &SandboxId) -> Option<String> {
    let home = std::env::var_os("HOME")?;
    let path = Path::new(&home)
        .join(".local/state/sandbox-driver-kubernetes")
        .join(format!("{}.json", id.as_str()));
    let record: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    record.get("node")?.as_str().map(str::to_owned)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse()?;
    let home = std::env::var("HOME").context("HOME")?;
    let mut plugin = PluginConfig::new(ProviderKind::try_new("kubernetes")?)
        .path(&args.plugin)
        .sha256(args.sha256.clone())
        .env_var("HOME", home)
        .env_var(
            "SANDBOX_DRIVER_KUBERNETES_NODE_SELECTOR",
            format!("kubernetes.io/hostname={}", args.node),
        );
    plugin.inherit_env = vec!["PATH".to_owned(), "RUST_LOG".to_owned()];
    let launch = launch_plugin("sandbox-driver", &plugin)
        .await
        .context("launching the plugin")?;
    say(format!(
        "plugin launched, checksum verified: {}",
        launch.verified
    ));
    let provider = launch.provider;

    let mut resources = Resources::default();
    resources.cpu_cores = Some(args.cpu);
    resources.memory_mb = Some(args.memory_mb);
    let spec = SandboxSpec::new(SandboxSource::Image {
        reference: args.image.clone(),
    })
    .working_directory("/workspace")
    .resources(resources)
    .label("proof", args.scenario.clone());
    let sandbox = provider.create(&spec, None).await.context("creating")?;
    let id = sandbox.id().clone();
    let token = format!("{}-{}", args.scenario, std::process::id());
    sandbox
        .exec()
        .run(&ExecSpec::new("/bin/sh").args(["-c", &format!("printf %s {token} > {MARKER}")]))
        .await
        .context("writing the marker")?;
    let node_before = recorded_node(&id);
    say(format!(
        "sandbox {} on node {node_before:?}, marker {token}",
        id.as_str()
    ));
    if node_before.as_deref() != Some(args.node.as_str()) {
        bail!("the sandbox did not land on {}", args.node);
    }

    let deadline = Instant::now() + Duration::from_secs(args.minutes * 60);
    let mut saw_unhealthy = false;
    let mut verdict = Ok(());
    loop {
        tokio::time::sleep(TICK).await;
        let health = provider.health().await;
        let healthy = matches!(&health, Ok(h) if h.status == HealthStatus::Ok);
        saw_unhealthy |= !healthy;
        let described = match provider.attach(&id, None).await {
            Ok(handle) => match handle.describe().await {
                Ok(status) => format!(
                    "state={:?} provider_state={} reason={:?}",
                    status.state, status.provider_state, status.error_reason
                ),
                Err(error) => format!("describe failed: {error}"),
            },
            Err(error) => format!("attach failed: {error}"),
        };
        let probe = sandbox
            .exec()
            .run(&ExecSpec::new("/bin/sh").args(["-c", &format!("cat {MARKER}")]))
            .await
            .map(|result| String::from_utf8_lossy(&result.stdout).into_owned())
            .map_err(|error| error.to_string());
        say(format!(
            "health={:?} {described} exec={probe:?}",
            health.map(|h| h.status)
        ));
        if args.scenario == "reboot" && saw_unhealthy && healthy {
            say("health went away and came back: starting the sandbox again");
            verdict = restart_and_verify(&provider, &id, &token, &args.node).await;
            break;
        }
        if Instant::now() >= deadline {
            if args.scenario == "reboot" {
                verdict = Err(anyhow::anyhow!(
                    "no reboot observed within {} minutes",
                    args.minutes
                ));
            }
            break;
        }
    }

    if !args.keep {
        provider.delete(&id, None).await.context("deleting")?;
        say("sandbox deleted");
    }
    let _ = provider.shutdown().await;
    match &verdict {
        Ok(()) => say("VERDICT: PASSED"),
        Err(error) => say(format!("VERDICT: FAILED: {error:#}")),
    }
    verdict
}

async fn restart_and_verify(
    provider: &sandbox_driver_protocol::PluginProvider,
    id: &SandboxId,
    token: &str,
    node: &str,
) -> anyhow::Result<()> {
    let mut last = None;
    for attempt in 1..=40 {
        match provider.attach(id, None).await {
            Ok(handle) => match handle.start().await {
                Ok(()) => {
                    let result = handle
                        .exec()
                        .run(&ExecSpec::new("/bin/sh").args(["-c", &format!("cat {MARKER}")]))
                        .await
                        .context("reading the marker after the restart")?;
                    let read = String::from_utf8_lossy(&result.stdout).into_owned();
                    let node_after = recorded_node(id);
                    say(format!(
                        "restarted on attempt {attempt}: node {node_after:?}, marker {read:?}"
                    ));
                    if read != token {
                        bail!("the workspace marker did not survive: {read:?}");
                    }
                    if node_after.as_deref() != Some(node) {
                        bail!("the sandbox moved off {node}: {node_after:?}");
                    }
                    return Ok(());
                }
                Err(error) => last = Some(error.to_string()),
            },
            Err(error) => last = Some(error.to_string()),
        }
        say(format!("start attempt {attempt} failed: {last:?}"));
        tokio::time::sleep(TICK).await;
    }
    bail!("the sandbox never started again: {last:?}")
}
