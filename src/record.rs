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

use crate::config::Toleration;

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
    /// The Localhost AppArmor profile every pod of the sandbox runs under.
    #[serde(default)]
    pub apparmor_localhost_profile: Option<String>,
    pub service_account: Option<String>,
    pub image_pull_secrets: Vec<String>,
    pub factory: Option<String>,
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
            apparmor_localhost_profile: None,
            service_account: None,
            image_pull_secrets: Vec::new(),
            factory: None,
        }
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
