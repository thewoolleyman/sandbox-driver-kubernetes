//! The sandbox filesystem.
//!
//! Built on `sandbox-driver`'s exec-derived filesystem, with two changes the
//! Kubernetes transport needs. Kubernetes `exec` carries its command in the
//! request URL, so the derived write (base64 chunks inside the command) would
//! exceed request limits; writes here stream the content through stdin
//! instead. And a read of a missing file is reported as `NotFound`, which the
//! derived read reports as a generic command failure.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sandbox_driver::{
    DerivedFs, DirEntry, Error, Exec, ExecFailure, ExecSpec, FileMetadata, Filesystem,
    ResourceKind, Result,
};

const WRITE_TIMEOUT: Duration = Duration::from_secs(300);

/// The filesystem facet of a Kubernetes sandbox.
pub struct KubernetesFs {
    exec: Arc<dyn Exec>,
    derived: DerivedFs,
}

impl KubernetesFs {
    pub(crate) fn new(exec: Arc<dyn Exec>) -> Self {
        Self {
            derived: DerivedFs::new(Arc::clone(&exec)),
            exec,
        }
    }

    /// Replaces a read failure on a path that does not exist with
    /// `NotFound`.
    async fn not_found_or(&self, path: &str, error: Error) -> Error {
        match self.derived.exists(path).await {
            Ok(false) => Error::NotFound {
                resource: ResourceKind::File,
                id: path.to_owned(),
            },
            _ => error,
        }
    }

    async fn stream_write(&self, path: &str, content: &[u8], append: bool) -> Result<()> {
        let redirect = if append { ">>" } else { ">" };
        let script =
            format!("dir=$(dirname -- \"$1\") && mkdir -p -- \"$dir\" && cat {redirect} \"$1\"");
        let spec = ExecSpec::new("/bin/sh")
            .args([
                "-c".to_owned(),
                script,
                "sandbox-driver-write".to_owned(),
                path.to_owned(),
            ])
            .stdin(content.to_vec())
            .timeout(WRITE_TIMEOUT);
        let result = self.exec.run(&spec).await?;
        if result.success() {
            return Ok(());
        }
        Err(Error::Exec(
            ExecFailure::new(
                "fs write",
                result.termination,
                result.exit_code,
                result.stdout,
                result.stderr,
            )
            .with_duration(result.duration),
        ))
    }
}

#[async_trait]
impl Filesystem for KubernetesFs {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        match self.derived.read(path).await {
            Ok(bytes) => Ok(bytes),
            Err(error) => Err(self.not_found_or(path, error).await),
        }
    }

    async fn read_range(&self, path: &str, offset: u64, length: Option<u64>) -> Result<Vec<u8>> {
        match self.derived.read_range(path, offset, length).await {
            // An empty range is also what a missing file reads as; tell
            // the two apart.
            Ok(bytes) if bytes.is_empty() && !self.derived.exists(path).await? => {
                Err(Error::NotFound {
                    resource: ResourceKind::File,
                    id: path.to_owned(),
                })
            }
            Ok(bytes) => Ok(bytes),
            Err(error) => Err(self.not_found_or(path, error).await),
        }
    }

    async fn write(&self, path: &str, content: &[u8]) -> Result<()> {
        self.stream_write(path, content, false).await
    }

    async fn write_append(&self, path: &str, content: &[u8]) -> Result<()> {
        self.stream_write(path, content, true).await
    }

    async fn delete(&self, path: &str, recursive: bool) -> Result<()> {
        self.derived.delete(path, recursive).await
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        self.derived.exists(path).await
    }

    async fn metadata(&self, path: &str) -> Result<FileMetadata> {
        self.derived.metadata(path).await
    }

    async fn list_dir(&self, path: &str, depth: usize) -> Result<Vec<DirEntry>> {
        self.derived.list_dir(path, depth).await
    }

    async fn create_dir(&self, path: &str) -> Result<()> {
        self.derived.create_dir(path).await
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.derived.rename(from, to).await
    }
}
