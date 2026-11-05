//! A command's stdin, which reaches it through an input file in the sandbox
//! one confirmed chunk at a time, arrives whole on a real cluster. Gated on
//! `SANDBOX_DRIVER_KUBERNETES_TEST_KUBECONFIG`.

#![allow(
    clippy::field_reassign_with_default,
    reason = "non_exhaustive driver types are built field by field"
)]

mod support;

use std::time::Duration;

use sandbox_driver::{ExecSpec, SandboxProvider, SandboxSource, SandboxSpec};

#[tokio::test(flavor = "multi_thread")]
async fn a_commands_stdin_arrives_whole_on_a_cluster() {
    let Some(provider) = support::provider("stdin").await else {
        return;
    };
    let spec = SandboxSpec::new(SandboxSource::Image {
        reference: support::TEST_IMAGE.to_owned(),
    })
    .working_directory("/workspace");
    let sandbox = provider.create(&spec, None).await.expect("creates");
    // Several commands in a row, and one input larger than a chunk.
    let large: Vec<u8> = (0..=255_u8).cycle().take(300_000).collect();
    let mut failures = Vec::new();
    for input in [b"hello-0".to_vec(), b"hello-1".to_vec(), large] {
        let result = sandbox
            .exec()
            .run(
                &ExecSpec::new("cat")
                    .stdin(input.clone())
                    .timeout(Duration::from_secs(60)),
            )
            .await;
        match result {
            Ok(result) if result.stdout == input => {}
            Ok(result) => failures.push(format!(
                "{} input bytes came back as {} (exit {:?}, {:?})",
                input.len(),
                result.stdout.len(),
                result.exit_code,
                result.termination
            )),
            Err(error) => failures.push(format!("{} input bytes: {error}", input.len())),
        }
    }
    provider.delete(sandbox.id(), None).await.expect("deletes");
    assert!(failures.is_empty(), "{failures:#?}");
}
