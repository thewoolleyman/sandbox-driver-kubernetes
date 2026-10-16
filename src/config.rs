//! Provider configuration.
//!
//! A plugin starts from a scrubbed environment (the host forwards only
//! `PATH`, `HOME` and `RUST_LOG`), so configuration is read from a file under
//! `HOME`: `$HOME/.config/sandbox-driver-kubernetes/config.toml`. Every field
//! has a default, and `SANDBOX_DRIVER_KUBERNETES_*` environment variables
//! override the file for development and tests.

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Where the plugin finds its cluster, where it puts sandboxes, and where it
/// keeps its host-side records.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KubernetesConfig {
    /// Kubeconfig file holding the cluster credential. Re-read on `401`.
    pub kubeconfig: PathBuf,
    /// Kubeconfig context; the file's current context when unset.
    pub context: Option<String>,
    /// Namespace sandboxes are created in.
    pub namespace: String,
    /// Node labels a sandbox's first pod must match.
    pub node_selector: BTreeMap<String, String>,
    /// Taints sandbox pods tolerate, so a tainted factory node can take them.
    pub tolerations: Vec<Toleration>,
    /// A node-loaded AppArmor profile the sandbox pods run under
    /// (`Localhost`), instead of the runtime default. On hosts whose kernel
    /// stacks an exec'd process as `<profile>//&unconfined`, the runtime
    /// default denies signals between a sandbox's own processes, so exec can
    /// neither finish nor stop; a profile whose signal peers include the
    /// stacked label fixes that without dropping confinement.
    pub apparmor_localhost_profile: Option<String>,
    /// Directory on each worker node that holds sandbox workspaces.
    pub workspace_root: String,
    /// Host directory for the per-sandbox records.
    pub state_dir: PathBuf,
    /// ServiceAccount the sandbox pods run as; the namespace default when unset.
    pub service_account: Option<String>,
    /// Image pull secrets attached to every sandbox pod.
    pub image_pull_secrets: Vec<String>,
    /// Value of the `livespec.dispatch.factory` label, when set.
    pub factory: Option<String>,
    /// Seconds a pod may take to reach `Running`.
    pub start_timeout_secs: u64,
    /// Seconds `stop` waits for a pod to be gone from the API.
    pub stop_timeout_secs: u64,
    /// A command (argv) that rewrites the kubeconfig file, run on a `401`
    /// before the file is re-read. Empty when something else keeps the file
    /// current.
    pub refresh_command: Vec<String>,
    /// Seconds the refresh command may run.
    pub refresh_timeout_secs: u64,
}

/// One pod toleration, in the Kubernetes field names.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Toleration {
    pub key: Option<String>,
    /// `Equal` or `Exists`; Kubernetes treats unset as `Equal`.
    pub operator: Option<String>,
    pub value: Option<String>,
    /// `NoSchedule`, `PreferNoSchedule` or `NoExecute`; unset matches all.
    pub effect: Option<String>,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        let home = home();
        Self {
            kubeconfig: home.join(".kube").join("config"),
            context: None,
            namespace: "livespec-factory".to_owned(),
            node_selector: BTreeMap::from([(
                "sandbox-driver-kubernetes/factory".to_owned(),
                "true".to_owned(),
            )]),
            tolerations: Vec::new(),
            apparmor_localhost_profile: None,
            workspace_root: "/var/lib/sandbox-driver-kubernetes/workspaces".to_owned(),
            state_dir: home
                .join(".local")
                .join("state")
                .join("sandbox-driver-kubernetes"),
            service_account: None,
            image_pull_secrets: Vec::new(),
            factory: None,
            start_timeout_secs: 600,
            stop_timeout_secs: 120,
            refresh_command: Vec::new(),
            refresh_timeout_secs: 60,
        }
    }
}

fn home() -> PathBuf {
    env::var_os("HOME").map_or_else(|| PathBuf::from("/"), PathBuf::from)
}

/// Errors reading the configuration file.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

impl KubernetesConfig {
    /// The default configuration file path.
    pub fn default_path() -> PathBuf {
        home()
            .join(".config")
            .join("sandbox-driver-kubernetes")
            .join("config.toml")
    }

    /// Loads the configuration: defaults, then the file at `path` when it
    /// exists, then environment overrides.
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let mut config = match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|source| ConfigError::Parse {
                path: path.to_owned(),
                source,
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(source) => {
                return Err(ConfigError::Read {
                    path: path.to_owned(),
                    source,
                });
            }
        };
        config.apply_env();
        Ok(config)
    }

    /// Loads from [`Self::default_path`].
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from(&Self::default_path())
    }

    fn apply_env(&mut self) {
        let var = |name: &str| env::var(format!("SANDBOX_DRIVER_KUBERNETES_{name}")).ok();
        if let Some(value) = var("KUBECONFIG") {
            self.kubeconfig = PathBuf::from(value);
        }
        if let Some(value) = var("CONTEXT") {
            self.context = Some(value);
        }
        if let Some(value) = var("NAMESPACE") {
            self.namespace = value;
        }
        if let Some(value) = var("WORKSPACE_ROOT") {
            self.workspace_root = value;
        }
        if let Some(value) = var("STATE_DIR") {
            self.state_dir = PathBuf::from(value);
        }
        if let Some(value) = var("SERVICE_ACCOUNT") {
            self.service_account = Some(value);
        }
        if let Some(value) = var("FACTORY") {
            self.factory = Some(value);
        }
        if let Some(value) = var("NODE_SELECTOR") {
            self.node_selector = value
                .split(',')
                .filter_map(|pair| pair.split_once('='))
                .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
                .collect();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_yields_the_defaults() {
        let config = KubernetesConfig::load_from(Path::new("/nonexistent/config.toml"))
            .expect("defaults load");
        assert_eq!(config.namespace, "livespec-factory");
        assert!(config.kubeconfig.ends_with(".kube/config"));
    }

    #[test]
    fn the_file_overrides_defaults_and_rejects_unknown_fields() {
        let parsed: KubernetesConfig =
            toml::from_str("namespace = \"x\"\nworkspace_root = \"/data/ws\"\n").expect("parses");
        assert_eq!(parsed.namespace, "x");
        assert_eq!(parsed.workspace_root, "/data/ws");
        assert!(toml::from_str::<KubernetesConfig>("bogus = 1\n").is_err());
    }

    #[test]
    fn tolerations_and_a_refresh_command_parse_from_the_file() {
        let parsed: KubernetesConfig = toml::from_str(
            "refresh_command = [\"sudo\", \"-n\", \"/usr/local/bin/refresh-factory-kubeconfig\"]\n\
             [[tolerations]]\nkey = \"node-role/ci\"\noperator = \"Equal\"\nvalue = \"factory\"\neffect = \"NoSchedule\"\n",
        )
        .expect("parses");
        assert_eq!(parsed.refresh_command.len(), 3);
        assert_eq!(parsed.tolerations[0].key.as_deref(), Some("node-role/ci"));
        assert_eq!(parsed.tolerations[0].effect.as_deref(), Some("NoSchedule"));
        assert!(toml::from_str::<KubernetesConfig>("[[tolerations]]\nbogus = 1\n").is_err());
        let profiled: KubernetesConfig =
            toml::from_str("apparmor_localhost_profile = \"ci-runner-workflow\"\n")
                .expect("parses");
        assert_eq!(
            profiled.apparmor_localhost_profile.as_deref(),
            Some("ci-runner-workflow")
        );
    }
}
