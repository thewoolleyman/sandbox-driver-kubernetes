//! The host-side record: what the plugin keeps on the factory host so every
//! cluster object of a sandbox can be re-created after the control plane has
//! lost them.
//!
//! One JSON file per sandbox, mode 0600 (it carries the sandbox environment),
//! written by staging to a temporary file, syncing it, renaming it into place
//! and syncing the directory, so a reader sees a complete record and both its
//! content and its directory entry survive a crash.

use std::collections::BTreeMap;
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use sandbox_driver::{NetworkPolicy, Resources};
use serde::{Deserialize, Serialize};

use crate::config::{Toleration, TopologySpread};

/// Everything needed to rebuild a sandbox's pod and network policy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Record {
    /// The logical sandbox id, which is also the pod name.
    pub id: String,
    /// The spec's name, when it gave one.
    pub name: Option<String>,
    pub namespace: String,
    /// The node holding the workspace; set once the first pod is scheduled.
    pub node: Option<String>,
    /// The workspace directory on that node.
    pub workspace_dir: String,
    /// The sandbox working directory inside the container.
    pub working_dir: String,
    pub image: String,
    pub resources: Resources,
    pub env: BTreeMap<String, String>,
    /// Labels as the caller gave them (verbatim).
    pub labels: BTreeMap<String, String>,
    pub network: NetworkPolicy,
    pub user: Option<String>,
    /// The node labels the first pod must match.
    pub node_selector: BTreeMap<String, String>,
    /// Taints every pod of the sandbox tolerates. Defaulted so records
    /// written before the field existed still load.
    #[serde(default)]
    pub tolerations: Vec<Toleration>,
    /// Topology spread constraints for the first pod. Defaulted so records
    /// written before the field existed still load.
    #[serde(default)]
    pub topology_spread: Vec<TopologySpread>,
    /// The Localhost AppArmor profile every pod of the sandbox runs under.
    #[serde(default)]
    pub apparmor_localhost_profile: Option<String>,
    pub service_account: Option<String>,
    pub image_pull_secrets: Vec<String>,
    pub factory: Option<String>,
    /// The configured CPU request below the limit, as written, so a pod the
    /// record re-creates requests what the first one did. Omitted when unset,
    /// so a record without it is written exactly as before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_request_cores: Option<String>,
}

/// The environment key under which [`Record::ambient_environment`] reports
/// the cluster node the sandbox's pod runs on. Petri carries a provider's
/// `sandbox/environment` map to its caller unchanged, so this is how the
/// caller (Fabro's `run_turn` telemetry) learns the node without a protocol
/// change.
pub const NODE_NAME_ENV: &str = "K8S_NODE_NAME";

impl Record {
    /// The sandbox's ambient environment: the caller's `env`, plus
    /// [`NODE_NAME_ENV`] naming the node once the pod has been scheduled.
    /// A caller-supplied value under that key is left as the caller gave it.
    pub fn ambient_environment(&self) -> BTreeMap<String, String> {
        let mut environment = self.env.clone();
        if let Some(node) = &self.node {
            environment
                .entry(NODE_NAME_ENV.to_owned())
                .or_insert_with(|| node.clone());
        }
        environment
    }
}

/// The directory of records.
#[derive(Clone, Debug)]
pub struct RecordStore {
    dir: PathBuf,
}

impl RecordStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Writes `record` crash-safely, replacing any earlier version.
    pub fn save(&self, record: &Record) -> io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        let final_path = self.path(&record.id);
        let staged = self
            .dir
            .join(format!(".{}.json.tmp-{}", record.id, std::process::id()));
        let bytes = serde_json::to_vec_pretty(record).map_err(io::Error::other)?;
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&staged)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&staged, &final_path)?;
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// The record for `id`, or `None` when there is none.
    pub fn load(&self, id: &str) -> io::Result<Option<Record>> {
        match std::fs::read(self.path(id)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(io::Error::other),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Removes the record for `id`; an absent one is success.
    pub fn remove(&self, id: &str) -> io::Result<()> {
        match std::fs::remove_file(self.path(id)) {
            Ok(()) => {
                std::fs::File::open(&self.dir)?.sync_all()?;
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Every record in the store.
    pub fn list(&self) -> io::Result<Vec<Record>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut records = Vec::new();
        for entry in entries {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.starts_with('.') || !name.ends_with(".json") {
                continue;
            }
            let bytes = std::fs::read(&path)?;
            records.push(serde_json::from_slice(&bytes).map_err(io::Error::other)?);
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str) -> Record {
        Record {
            id: id.to_owned(),
            name: None,
            namespace: "ns".to_owned(),
            node: Some("node-a".to_owned()),
            workspace_dir: format!("/ws/{id}"),
            working_dir: "/workspace".to_owned(),
            image: "img".to_owned(),
            resources: Resources::default(),
            env: BTreeMap::from([("K".to_owned(), "secret".to_owned())]),
            labels: BTreeMap::new(),
            network: NetworkPolicy::default(),
            user: None,
            node_selector: BTreeMap::new(),
            tolerations: Vec::new(),
            topology_spread: Vec::new(),
            apparmor_localhost_profile: None,
            service_account: None,
            image_pull_secrets: Vec::new(),
            factory: None,
            cpu_request_cores: None,
        }
    }

    #[test]
    fn an_unset_cpu_request_is_absent_from_the_record_and_a_set_one_round_trips() {
        let unset = record("petri-a-l1");
        let json = serde_json::to_value(&unset).expect("serializes");
        assert!(
            json.get("cpu_request_cores").is_none(),
            "an unset request leaves the record as before: {json}"
        );
        let mut legacy = json.clone();
        legacy
            .as_object_mut()
            .expect("object")
            .remove("cpu_request_cores");
        let loaded: Record = serde_json::from_value(legacy).expect("an older record loads");
        assert_eq!(loaded.cpu_request_cores, None);
        let mut set = record("petri-a-l2");
        set.cpu_request_cores = Some("3".to_owned());
        let back: Record =
            serde_json::from_value(serde_json::to_value(&set).expect("serializes")).expect("loads");
        assert_eq!(back.cpu_request_cores.as_deref(), Some("3"));
    }

    #[test]
    fn the_ambient_environment_names_the_scheduled_node() {
        let environment = record("sbx").ambient_environment();
        assert_eq!(
            environment.get(NODE_NAME_ENV).map(String::as_str),
            Some("node-a")
        );
        assert_eq!(environment.get("K").map(String::as_str), Some("secret"));
        assert_eq!(environment.len(), 2);
    }

    #[test]
    fn an_unscheduled_sandbox_reports_no_node() {
        let mut unscheduled = record("sbx");
        unscheduled.node = None;
        let environment = unscheduled.ambient_environment();
        assert!(!environment.contains_key(NODE_NAME_ENV));
        assert_eq!(environment, unscheduled.env);
    }

    #[test]
    fn a_caller_supplied_node_name_is_not_overwritten() {
        let mut supplied = record("sbx");
        supplied
            .env
            .insert(NODE_NAME_ENV.to_owned(), "caller-value".to_owned());
        let environment = supplied.ambient_environment();
        assert_eq!(
            environment.get(NODE_NAME_ENV).map(String::as_str),
            Some("caller-value")
        );
    }

    #[test]
    fn records_round_trip_privately_and_remove_idempotently() {
        let dir = std::env::temp_dir().join(format!("sdk-record-test-{}", std::process::id()));
        let store = RecordStore::new(&dir);
        store.save(&record("a")).expect("save");
        store.save(&record("b")).expect("save");
        assert_eq!(store.load("a").expect("load"), Some(record("a")));
        let mode = std::fs::metadata(dir.join("a.json"))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(store.list().expect("list").len(), 2);
        store.remove("a").expect("remove");
        store.remove("a").expect("remove twice");
        assert_eq!(store.load("a").expect("load"), None);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
