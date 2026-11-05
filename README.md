# sandbox-driver-kubernetes

A Kubernetes sandbox provider for [sandbox-driver](https://github.com/lithoscomputer/sandbox-driver),
served as a protocol v2 plugin, so a [Fabro](https://github.com/fabro-sh/fabro) /
[Petri](https://github.com/lithoscomputer/petri) worker can run its sandboxes as pods on a
self-hosted cluster.

Status: early. Built against sandbox-driver `90b0d825` (the revision Fabro `v0.382.0-nightly.0`
pins). Fabro and Petri do not yet launch a plugin backend or forward workflow resources to one
(fabro-sh/fabro#937); this plugin is the provider half of that path.

## How it works

- The plugin runs **beside the worker on the host**, speaking protocol v2 over its own stdin and
  stdout, and reaches the cluster through the Kubernetes API. It never runs in a pod.
- One sandbox is one pod (`restartPolicy: Never`, an idle PID 1) with a single `sandbox`
  container. Commands run through the `exec` subresource under a small `/bin/sh` wrapper that
  supports TERM/KILL stop requests.
- **Resources:** `cpu_cores`, `memory_mb` and `disk_mb` become pod requests **equal to** limits
  (Guaranteed QoS). A non-zero GPU request is refused, never dropped. Optionally the CPU
  request alone sits below its limit: with `cpu_request_cores` set (see Configuration), a pod
  requests that many cores and keeps `cpu_cores` as its limit (Burstable QoS). Memory and disk
  stay requested at their limits, and the workspace cleanup pod keeps its own fixed size.
- **Identity:** the sandbox id is the pod name: the spec's `name` lowercased when it is a DNS
  label (Petri's `petri-<run>-l<lease>`), otherwise generated. The pod UID is never used.
- **Workspace:** a node-local directory `<workspace_root>/<sandbox id>` mounted with `hostPath`
  at the working directory; later pods of the sandbox are pinned to that node.
- **Host-side record:** a crash-safe JSON record per sandbox (mode 0600) in the plugin's state
  directory. Every cluster object is re-derivable from it, so a control-plane rebuild that drops
  every API object does not lose a sandbox.
- **Lifecycle fence:** `stop` deletes the pod and waits until it is gone from the API; `start`
  re-creates it from the record and refuses while a pod of that name still exists; `delete`
  empties the workspace and removes pod, network policy and record.
- **Deleting a stopped sandbox:** its workspace is emptied by a short-lived cleanup pod
  `<sandbox id>-cleanup`. That pod is pinned to the workspace's node and limited to 100m CPU and
  128Mi memory, so it never re-creates the full sandbox pod with its declared resources. The
  delete always removes the cleanup pod. If the cleanup does not finish within
  `cleanup_timeout_secs`, the delete fails with a timeout naming the sandbox and keeps the record,
  so a later delete can retry. A cleanup pod carries its plugin process's identity. The next
  `list` (or the next `delete` of that sandbox) removes one whose process has ended, so an
  interrupted delete cannot leave it behind.
- **Node name:** once the pod is scheduled, `sandbox/environment` reports the node it runs on as
  `K8S_NODE_NAME`, so a caller that only sees the provider's environment map (Petri passes it
  through unchanged) can name the node, for example on its telemetry. A caller-supplied
  `K8S_NODE_NAME` is left as given.
- **Node loss:** a sandbox whose node is `NotReady` is reported unavailable, not lost; commands
  fail with a retryable error and no replacement pod is created.
- **API outage:** a request whose connection the Kubernetes API refuses (a k3s server restart,
  a flannel panic) is retried with exponential backoff for up to two minutes. Only CONNECT-phase
  failures are retried, so nothing reached the server and a command is never started twice; a
  failure after connecting is returned as before. A refusal outlasting the budget is a retryable
  error (`code: api-unreachable`) naming the operation, the attempts and the elapsed time.
- **Labels:** values Kubernetes cannot carry (Petri's `petri.workspace` contains `/`) are encoded
  injectively and reversibly (`x_` prefix, `_hh` escapes); an encoding over 63 characters is
  refused, never truncated. Verbatim values are kept in annotations.
- **Network:** `block` and CIDR allow-lists become a per-pod egress NetworkPolicy (DNS kept
  open for allow-lists). Domain allow-lists are refused.
- **Credentials:** the cluster credential is read from a kubeconfig **file** and re-read on any
  `401` (after running the optional `refresh_command`), so a rotated ServiceAccount token is
  picked up without restarting the plugin. No
  service-account token is mounted into sandbox pods.

Refused: pause/resume, archive, fork, resize, snapshots, PTY, logs, one-shot containers,
volumes, timers, and preview/SSH/terminal access.

## Configuration

A plugin starts from a scrubbed environment (`PATH`, `HOME`, `RUST_LOG`), so configuration is a
file: `$HOME/.config/sandbox-driver-kubernetes/config.toml`. Every key is optional.

```toml
kubeconfig = "/home/worker/.kube/config"   # default: $HOME/.kube/config
namespace = "livespec-factory"
node_selector = { "sandbox-driver-kubernetes/factory" = "true" }
workspace_root = "/var/lib/sandbox-driver-kubernetes/workspaces"  # on each worker node; must be persistent
state_dir = "/home/worker/.local/state/sandbox-driver-kubernetes"
service_account = "sandbox"
image_pull_secrets = ["ghcr"]
factory = "hp"                              # sets the livespec.dispatch.factory label
# Run on a 401 before the kubeconfig is re-read, for a credential that is only
# rewritten on demand (a pull-on-401 file). Empty by default.
refresh_command = ["sudo", "-n", "/usr/local/bin/refresh-factory-kubeconfig"]
refresh_timeout_secs = 60
cleanup_timeout_secs = 300                  # how long a delete waits for its workspace cleanup pod
# The CPU a sandbox pod requests, in cores, below its limit (the spec's cpu_cores).
# Unset (the default), the request equals the limit. Also set by
# SANDBOX_DRIVER_KUBERNETES_CPU_REQUEST_CORES, which a host can give each provider kind.
# Checked at sandbox create: a value that is not a decimal number of cores ("3", "2.5";
# not "3000m"), is not positive, exceeds the spec's cpu_cores, or is set while the spec
# gives no cpu_cores refuses the create with invalid_spec, and no pod is made.
cpu_request_cores = "3"

# A node-loaded AppArmor profile for sandbox pods. Needed where the kernel stacks an
# exec'd process as `<profile>//&unconfined` (e.g. Ubuntu 26.04): the runtime default
# then denies signals between a sandbox's own processes, so exec never finishes.
apparmor_localhost_profile = "ci-runner-workflow"

# Taints sandbox pods tolerate, in Kubernetes field names.
[[tolerations]]
key = "node-role/ci"
operator = "Equal"
value = "factory"
effect = "NoSchedule"

# Spread sandboxes across nodes. Applied to a sandbox's first pod only (a re-created
# pod is pinned to its workspace's node), and counted over every pod this plugin
# manages. max_skew defaults to 1 and when_unsatisfiable to ScheduleAnyway, a scoring
# preference that never leaves a pod pending. Empty (the default) leaves placement to
# the scheduler's resource scoring, which can stack every sandbox on one node.
[[topology_spread]]
topology_key = "kubernetes.io/hostname"
```

The namespace's ServiceAccount needs, namespace-scoped:

- `pods`: create, get, list, watch, delete, patch (patch relabels a live sandbox);
- `pods/exec`: create **and get** — exec streams over a WebSocket, and the API server
  authorizes the upgrade as `get`, so `create` alone fails with 403 on current Kubernetes;
- `pods/log`: get;
- `networkpolicies`: create, get, list, delete;
- `events`: list;

and, cluster-scoped, `nodes` get (the `NotReady` check). Check a subresource with
`kubectl auth can-i get pods --subresource=exec`, not `can-i get pods/exec`, which kubectl
reads as a pod named `exec`. The cluster tests run the plugin under exactly this Role.

## Lifecycle proof driver

`sandbox-driver-kubernetes-proof <reboot|node-loss> --sha256 <plugin digest> --node <node>` launches
the installed plugin exactly as a Fabro/Petri worker does (checksum-verified, one long-lived
process), creates a sandbox on `<node>`, writes a marker into its workspace, and reports health,
state and an exec probe every 15 s while an operator reboots the control plane or takes the node
away. `reboot` then starts the sandbox again and passes only if the marker survived on the same
node. It changes nothing in the cluster except through the plugin. Released beside the plugin.

## Development

```sh
cargo test --lib
# cluster tests (kind): see .github/workflows/ci.yml
SANDBOX_DRIVER_KUBERNETES_TEST_KUBECONFIG=~/.kube/kind cargo test --tests -- --test-threads 1
```

## License

MIT
