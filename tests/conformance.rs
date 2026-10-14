//! The kubernetes provider against the black-box conformance suite, in
//! process and served over the plugin protocol.
//!
//! Requires a cluster: set `SANDBOX_DRIVER_KUBERNETES_TEST_KUBECONFIG` to a
//! kubeconfig for a throwaway cluster whose nodes carry
//! `sandbox-driver-kubernetes/factory=true` (CI uses kind with
//! `ci/kind.yaml`). The tests pass trivially when it is unset.

#![allow(
    clippy::field_reassign_with_default,
    reason = "non_exhaustive driver types are built field by field"
)]

mod support;

use std::sync::Arc;

use sandbox_driver::{SandboxProvider, SandboxSource, SandboxSpec};
use sandbox_driver_conformance::{Conformance, SpecFactory};
use sandbox_driver_protocol::{PluginProvider, serve};
use tokio::io::{duplex, split};

fn specs() -> SpecFactory {
    SpecFactory::new(|| {
        SandboxSpec::new(SandboxSource::Image {
            reference: support::TEST_IMAGE.to_owned(),
        })
        .working_directory("/workspace/sandbox-driver-conformance")
    })
}

#[tokio::test(flavor = "multi_thread")]
#[expect(
    clippy::print_stderr,
    reason = "the per-check report is the test's evidence"
)]
async fn kubernetes_provider_passes_conformance() {
    let Some(provider) = support::provider("inproc").await else {
        return;
    };
    let report = Conformance::new(Arc::new(provider), specs()).run().await;
    eprintln!("{report}");
    report.assert_pass();
}

#[tokio::test(flavor = "multi_thread")]
#[expect(
    clippy::print_stderr,
    reason = "the per-check report is the test's evidence"
)]
async fn kubernetes_provider_passes_conformance_over_the_wire() {
    let Some(provider) = support::provider("wire").await else {
        return;
    };
    let (host_side, plugin_side) = duplex(1024 * 1024);
    let (host_read, host_write) = split(host_side);
    let (plugin_read, plugin_write) = split(plugin_side);
    tokio::spawn(serve(Arc::new(provider), plugin_read, plugin_write));
    let remote = PluginProvider::connect(host_read, host_write)
        .await
        .expect("handshake succeeds");
    assert_eq!(remote.kind().as_str(), "kubernetes");
    assert!(remote.capabilities().exec.stdin_stream);
    let report = Conformance::new(Arc::new(remote), specs()).run().await;
    eprintln!("{report}");
    report.assert_pass();
}
