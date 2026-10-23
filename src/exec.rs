//! Command execution inside a sandbox pod, over the Kubernetes `exec`
//! subresource.
//!
//! Kubernetes cannot signal an exec'd process, so every command runs under a
//! `/bin/sh` wrapper (the same one the Docker provider uses) that puts it in
//! its own session and pairs it with an in-container watcher. A stop is
//! requested by writing `term` or `kill` into a stop file through a second
//! exec; the watcher signals the command's process group. Escalation timing
//! belongs to the caller. Kubernetes exec takes neither a working directory
//! nor an environment, so the wrapper changes directory itself and the
//! environment reaches the command as `env` arguments, never through a shell.
//!
//! Kubernetes exec carries its command in the request URL, one `command`
//! query parameter per argument. The command's environment, program and
//! arguments therefore never ride in that command: a first exec streams them
//! through stdin into a mode-0600 spec file (shell-quoted `set --` source),
//! and the command's own exec passes only the fixed wrapper, which sources
//! and removes that file. So the request URL stays the same size whatever
//! the command carries, and the run's credentials are never part of a URL
//! that an audit log or proxy could record. Without this, a 48 KB inline
//! prepare script plus a run's 37 environment entries made a URL the
//! cluster's exec path refused (gmktec run 01M5N2W7TNBC, run_prepare_28).

use std::collections::BTreeMap;
use std::io;
use std::pin::{Pin, pin};
use std::result::Result as StdResult;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures_util::{Stream, StreamExt, stream};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Status;
use kube::api::{Api, AttachParams, AttachedProcess};
use sandbox_driver::{
    BASH_ENV_VAR, Error, Exec, ExecControls, ExecResult, ExecSpec, ExecStreamingResult,
    OutputCaptureBuffer, OutputSanitization, OutputSanitizer, OutputSink, OutputStream, Result,
    SpawnSpec, StderrTail, StdioProcess, StdioProcessHandle, StopLevel, Termination,
    TransportError, feed_stdin, finish_stdin_writer, run_with_stop_grace,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, duplex};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::CONTAINER_NAME;
use crate::error::{kube_error, not_found};
use crate::pod::{Cluster, NodeHealth, node_unavailable};

const WRAPPER_NAME: &str = "sandbox-driver";
const STOP_POLL_SLEEP_SECONDS: &str = "0.1";
/// Grace between a stdio handle's TERM and its KILL.
const TERM_GRACE: Duration = Duration::from_secs(2);
/// Output drain grace after a kill request; must exceed the watcher's poll.
const KILL_DRAIN_GRACE: Duration = Duration::from_secs(10);
/// How long to wait for the exit status once output has ended.
const STATUS_WAIT: Duration = Duration::from_secs(30);
const READ_CHUNK: usize = 64 * 1024;

/// Quotes a string for safe interpolation into POSIX shell source.
pub(crate) fn shell_quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for c in value.chars() {
        if c == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(c);
        }
    }
    quoted.push('\'');
    quoted
}

fn stop_file_contents(level: StopLevel) -> &'static str {
    match level {
        StopLevel::Term => "term",
        StopLevel::Kill => "kill",
    }
}

/// The wrapper script; see the module docs.
pub fn command_wrapper(
    working_dir: &str,
    stop_file: &str,
    pid_file: &str,
    spec_file: &str,
    forward_stdin: bool,
) -> String {
    let spec_file = shell_quote(spec_file);
    let working_dir = shell_quote(working_dir);
    let stop_file = shell_quote(stop_file);
    let pid_file = shell_quote(pid_file);
    let (save_stdin, stdin_redirect, close_stdin) = if forward_stdin {
        ("exec 3<&0\n", "<&3", "exec 3<&-\n")
    } else {
        ("", "< /dev/null", "")
    };
    format!(
        "spec_file={spec_file}\n\
         if [ ! -r \"$spec_file\" ] || ! . \"$spec_file\"; then rm -f \"$spec_file\"; echo 'sandbox-driver: cannot read the command spec' >&2; exit 126; fi\n\
         rm -f \"$spec_file\"\n\
         cd {working_dir} || {{ echo 'sandbox-driver: cannot enter the working directory' >&2; exit 126; }}\n\
         mkdir -p /tmp/.sandbox-driver\n\
         if ! command -v setsid >/dev/null 2>&1 || ! command -v env >/dev/null 2>&1; then\n\
           echo 'sandbox-driver: the container image must provide setsid and env' >&2\n\
           exit 127\n\
         fi\n\
         stop_file={stop_file}\n\
         pid_file={pid_file}\n\
         {save_stdin}rm -f \"$pid_file\"\n\
         if [ -e \"$stop_file\" ]; then\n\
           mode=$(cat \"$stop_file\" 2>/dev/null)\n\
           rm -f \"$stop_file\"\n\
           if [ \"$mode\" = kill ]; then exit 137; fi\n\
           exit 143\n\
         fi\n\
         (\n\
           while [ ! -s \"$stop_file\" ]; do sleep {STOP_POLL_SLEEP_SECONDS}; done\n\
           while [ ! -s \"$pid_file\" ]; do sleep {STOP_POLL_SLEEP_SECONDS}; done\n\
           child=$(cat \"$pid_file\")\n\
           mode=$(cat \"$stop_file\" 2>/dev/null)\n\
           if [ \"$mode\" != kill ]; then\n\
             kill -TERM \"-$child\" 2>/dev/null || kill -TERM \"$child\" 2>/dev/null || true\n\
             while kill -0 \"$child\" 2>/dev/null; do\n\
               [ \"$(cat \"$stop_file\" 2>/dev/null)\" = kill ] && break\n\
               sleep {STOP_POLL_SLEEP_SECONDS}\n\
             done\n\
             kill -0 \"$child\" 2>/dev/null || exit 0\n\
           fi\n\
           kill -KILL \"-$child\" 2>/dev/null || kill -KILL \"$child\" 2>/dev/null || true\n\
         ) >/dev/null 2>&1 & watcher=$!\n\
         setsid env \"$@\" {stdin_redirect} &\n\
         child=$!\n\
         {close_stdin}printf '%s' \"$child\" > \"$pid_file\"\n\
         wait \"$child\" 2>/dev/null\n\
         status=$?\n\
         kill \"$watcher\" 2>/dev/null || true\n\
         wait \"$watcher\" 2>/dev/null || true\n\
         rm -f \"$stop_file\" \"$pid_file\"\n\
         exit \"$status\""
    )
}

/// The exec command for one sandbox command: the fixed wrapper alone. Its
/// size depends only on the working directory and the control paths, never
/// on the command's environment, program or arguments.
fn exec_command(
    working_dir: &str,
    stop_file: &str,
    pid_file: &str,
    spec_file: &str,
    forward_stdin: bool,
) -> Vec<String> {
    vec![
        "env".to_owned(),
        format!("{BASH_ENV_VAR}="),
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        command_wrapper(working_dir, stop_file, pid_file, spec_file, forward_stdin),
        WRAPPER_NAME.to_owned(),
    ]
}

/// The exit code a remote command reported through its status channel.
pub(crate) fn exit_code_of(status: &Status) -> Option<i32> {
    if status.status.as_deref() == Some("Success") {
        return Some(0);
    }
    status
        .details
        .as_ref()?
        .causes
        .as_ref()?
        .iter()
        .find(|cause| cause.reason.as_deref() == Some("ExitCode"))
        .and_then(|cause| cause.message.as_deref())
        .and_then(|message| message.trim().parse().ok())
}

/// One chunk of a command's output.
enum Chunk {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
}

type ChunkStream = Pin<Box<dyn Stream<Item = io::Result<Chunk>> + Send>>;

/// Reads a process's stdout and stderr concurrently into one stream that
/// ends when both have reached EOF.
fn merged_output(process: &mut AttachedProcess) -> ChunkStream {
    let (sender, receiver) = mpsc::channel::<io::Result<Chunk>>(16);
    let readers: [(Option<Box<dyn AsyncRead + Unpin + Send>>, bool); 2] = [
        (
            process
                .stdout()
                .map(|reader| Box::new(reader) as Box<dyn AsyncRead + Unpin + Send>),
            true,
        ),
        (
            process
                .stderr()
                .map(|reader| Box::new(reader) as Box<dyn AsyncRead + Unpin + Send>),
            false,
        ),
    ];
    for (reader, is_stdout) in readers {
        let Some(mut reader) = reader else { continue };
        let sender = sender.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; READ_CHUNK];
            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(read) => {
                        let bytes = buffer[..read].to_vec();
                        let chunk = if is_stdout {
                            Chunk::Stdout(bytes)
                        } else {
                            Chunk::Stderr(bytes)
                        };
                        if sender.send(Ok(chunk)).await.is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error)).await;
                        break;
                    }
                }
            }
        });
    }
    drop(sender);
    Box::pin(stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    }))
}

/// Command execution inside one sandbox pod.
pub struct KubernetesExec {
    cluster: Cluster,
    pod: String,
    working_dir: String,
    node: Option<String>,
    exec_counter: AtomicU64,
}

impl KubernetesExec {
    pub(crate) fn new(
        cluster: Cluster,
        pod: String,
        working_dir: String,
        node: Option<String>,
    ) -> Self {
        Self {
            cluster,
            pod,
            working_dir,
            node,
            exec_counter: AtomicU64::new(0),
        }
    }

    fn resolve_dir(&self, dir: Option<&str>) -> String {
        match dir {
            None => self.working_dir.clone(),
            Some(dir) if dir.starts_with('/') => dir.to_owned(),
            Some(dir) => format!("{}/{}", self.working_dir.trim_end_matches('/'), dir),
        }
    }

    fn control_paths(&self) -> (String, String) {
        let count = self.exec_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let prefix = format!(
            "/tmp/.sandbox-driver/exec-{}-{nonce}-{count}",
            std::process::id()
        );
        (format!("{prefix}.stop"), format!("{prefix}.pid"))
    }

    /// The spec file a command's environment, program and arguments are
    /// staged in, beside its stop and pid files.
    fn spec_path(stop_file: &str) -> String {
        format!("{}.spec", stop_file.trim_end_matches(".stop"))
    }

    /// Shell source that sets the wrapper's positional parameters to the
    /// command's `env` entries, program and arguments.
    fn command_spec(program: &str, args: &[String], env: &BTreeMap<String, String>) -> String {
        let mut source = String::from("set --");
        for word in Self::env_entries(env)
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(program))
            .chain(args.iter().map(String::as_str))
        {
            source.push(' ');
            source.push_str(&shell_quote(word));
        }
        source.push('\n');
        source
    }

    fn env_entries(extra: &BTreeMap<String, String>) -> Vec<String> {
        let mut entries = vec![format!("{BASH_ENV_VAR}=")];
        entries.extend(extra.iter().map(|(key, value)| format!("{key}={value}")));
        entries
    }

    fn wrapped_cmd(
        &self,
        stop_file: &str,
        pid_file: &str,
        spec_file: &str,
        working_dir: Option<&str>,
        forward_stdin: bool,
    ) -> Vec<String> {
        exec_command(
            &self.resolve_dir(working_dir),
            stop_file,
            pid_file,
            spec_file,
            forward_stdin,
        )
    }

    /// Writes a command's spec file through the exec stdin stream, so its
    /// content never reaches the request URL.
    async fn stage_spec(&self, spec_file: &str, source: String) -> Result<()> {
        let cmd = vec![
            "env".to_owned(),
            format!("{BASH_ENV_VAR}="),
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "umask 077 && mkdir -p /tmp/.sandbox-driver && cat > \"$1\"".to_owned(),
            "sandbox-driver-spec".to_owned(),
            spec_file.to_owned(),
        ];
        let mut process = self.attach(cmd, true).await?;
        let status = process.take_status();
        let mut input = process.stdin().ok_or_else(|| {
            Error::io(
                "staging the command spec",
                io::Error::other("no stdin channel"),
            )
        })?;
        input
            .write_all(source.as_bytes())
            .await
            .map_err(|error| Error::io("staging the command spec", error))?;
        input
            .shutdown()
            .await
            .map_err(|error| Error::io("staging the command spec", error))?;
        drop(input);
        let mut stderr = Vec::new();
        let mut output = merged_output(&mut process);
        while let Some(chunk) = output.next().await {
            match chunk {
                Ok(Chunk::Stderr(bytes)) => stderr.extend_from_slice(&bytes),
                Ok(Chunk::Stdout(_)) => {}
                Err(error) => return Err(Error::io("staging the command spec", error)),
            }
        }
        let status = match status {
            Some(status) => tokio::time::timeout(STATUS_WAIT, status)
                .await
                .ok()
                .flatten(),
            None => None,
        };
        match status.as_ref().and_then(exit_code_of) {
            Some(0) => Ok(()),
            code => Err(Error::io(
                "staging the command spec",
                io::Error::other(format!(
                    "the spec write exited {code:?}: {}",
                    String::from_utf8_lossy(&stderr).trim()
                )),
            )),
        }
    }

    /// Starts `cmd` in the sandbox container. A failure to reach the pod is
    /// diagnosed: a `NotReady` node is reported unavailable (retryable), a
    /// missing pod as not found.
    async fn attach(&self, cmd: Vec<String>, stdin: bool) -> Result<AttachedProcess> {
        let namespace = self.cluster.namespace.clone();
        let pod = self.pod.clone();
        let result = self
            .cluster
            .client
            .call(|client| {
                let namespace = namespace.clone();
                let pod = pod.clone();
                let cmd = cmd.clone();
                let params = AttachParams::default()
                    .container(CONTAINER_NAME)
                    .stdin(stdin)
                    .stdout(true)
                    .stderr(true);
                async move {
                    Api::<Pod>::namespaced(client, &namespace)
                        .exec(&pod, cmd, &params)
                        .await
                }
            })
            .await;
        match result {
            Ok(process) => Ok(process),
            Err(error) => Err(self
                .diagnose(kube_error("starting a command in the sandbox", error))
                .await),
        }
    }

    /// Replaces a transport failure with the sandbox's real condition when
    /// that explains it.
    async fn diagnose(&self, error: Error) -> Error {
        match self.cluster.get_pod(&self.pod).await {
            Ok(None) => return not_found(&self.pod),
            Ok(Some(pod)) => {
                let node = pod
                    .spec
                    .and_then(|spec| spec.node_name)
                    .or_else(|| self.node.clone());
                if let Some(node) = node {
                    if let Ok(NodeHealth::NotReady) = self.cluster.node_ready(&node).await {
                        return node_unavailable(&self.pod, &node);
                    }
                }
            }
            Err(_) => {}
        }
        error
    }

    async fn request_stop(&self, stop_file: &str, level: StopLevel) -> Result<()> {
        let command = format!(
            "mkdir -p /tmp/.sandbox-driver && printf '%s' {} > {}",
            shell_quote(stop_file_contents(level)),
            shell_quote(stop_file)
        );
        let cmd = vec![
            "env".to_owned(),
            format!("{BASH_ENV_VAR}="),
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            command,
        ];
        let mut process = self.attach(cmd, false).await?;
        let mut output = merged_output(&mut process);
        while let Some(chunk) = output.next().await {
            if chunk.is_err() {
                break;
            }
        }
        let status = match process.take_status() {
            Some(status) => tokio::time::timeout(STATUS_WAIT, status)
                .await
                .ok()
                .flatten(),
            None => None,
        };
        match status.as_ref().and_then(exit_code_of) {
            None | Some(0) => Ok(()),
            Some(code) => Err(Error::io(
                "requesting exec stop",
                io::Error::other(format!("stop request exited {code}")),
            )),
        }
    }

    async fn run_signals(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        let started = Instant::now();
        let (stop_file, pid_file) = self.control_paths();
        let stdin_reader = controls.stdin_reader(spec);
        let spec_file = Self::spec_path(&stop_file);
        self.stage_spec(
            &spec_file,
            Self::command_spec(&spec.program, &spec.args, &spec.launch_env()),
        )
        .await?;
        let cmd = self.wrapped_cmd(
            &stop_file,
            &pid_file,
            &spec_file,
            spec.working_dir.as_deref(),
            stdin_reader.is_some(),
        );
        let mut process = self.attach(cmd, stdin_reader.is_some()).await?;
        let stdin_task = match (stdin_reader, process.stdin()) {
            (Some(reader), Some(writer)) => Some(tokio::spawn(feed_stdin(writer, reader))),
            _ => None,
        };
        let status = process.take_status();
        let output = merged_output(&mut process);

        let mut captured =
            StreamOutput::new(spec.output_sanitization, controls.retained_output_limit);
        let sink_failed = CancellationToken::new();
        let outcome = {
            let mut drain = pin!(captured.drain(output, controls.sink.as_ref(), &sink_failed));
            sandbox_driver::drain_with_stops(
                drain.as_mut(),
                &sink_failed,
                &controls,
                spec.timeout
                    .map(|timeout| timeout.saturating_sub(started.elapsed())),
                KILL_DRAIN_GRACE,
                |level| self.request_stop(&stop_file, level),
            )
            .await?
        };
        if let Some(stdin_task) = stdin_task {
            finish_stdin_writer(stdin_task).await?;
        }
        let (stream_result, truncated) = match outcome.drained {
            Some(result) => (result, false),
            None => (Ok(()), true),
        };
        stream_result.map_err(|error| Error::io("reading exec output", error))?;
        let exit_code = match status {
            Some(status) => tokio::time::timeout(STATUS_WAIT, status)
                .await
                .ok()
                .flatten()
                .as_ref()
                .and_then(exit_code_of),
            None => None,
        };
        if truncated {
            process.abort();
        }
        // A command that ran to its end always reports a status. A stream
        // that ended with none never reached the command's end: the pod or
        // its node became unreachable. Report that, never a clean exit.
        if exit_code.is_none() && !truncated && outcome.termination == Termination::Exited {
            return Err(self
                .diagnose(Error::Transport(TransportError::new(
                    "the exec stream ended without an exit status; the sandbox became unreachable",
                )))
                .await);
        }
        Ok(captured.into_result(outcome.termination, exit_code, started.elapsed(), truncated))
    }

    async fn spawn_stdio_raw(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        let (stop_file, pid_file) = self.control_paths();
        let spec_file = Self::spec_path(&stop_file);
        self.stage_spec(
            &spec_file,
            Self::command_spec(&spec.program, &spec.args, &spec.launch_env()),
        )
        .await?;
        let cmd = self.wrapped_cmd(
            &stop_file,
            &pid_file,
            &spec_file,
            spec.working_dir.as_deref(),
            true,
        );
        let mut process = self.attach(cmd, true).await?;
        let input = process.stdin().ok_or_else(|| {
            Error::io("opening stdio stdin", io::Error::other("no stdin channel"))
        })?;
        let status = process.take_status();
        let mut output = merged_output(&mut process);

        let (stdout_writer, stdout_reader) = duplex(64 * 1024);
        let stderr_tail = StderrTail::default();
        let tail = stderr_tail.clone();
        let (done_sender, done_receiver) =
            watch::channel::<Option<(Termination, Option<i32>)>>(None);
        let running = std::sync::Arc::new(AtomicBool::new(true));
        let still_running = std::sync::Arc::clone(&running);
        tokio::spawn(async move {
            let mut stdout_writer = stdout_writer;
            let mut writer_open = true;
            while let Some(chunk) = output.next().await {
                match chunk {
                    Ok(Chunk::Stdout(bytes)) if writer_open => {
                        if stdout_writer.write_all(&bytes).await.is_err() {
                            writer_open = false;
                        }
                    }
                    Ok(Chunk::Stdout(_)) => {}
                    Ok(Chunk::Stderr(bytes)) => tail.push(&bytes),
                    Err(error) => {
                        tail.push(
                            format!("sandbox-driver: stdio output stream error: {error}\n")
                                .as_bytes(),
                        );
                        break;
                    }
                }
            }
            let _ = stdout_writer.shutdown().await;
            let result = match status {
                Some(status) => match tokio::time::timeout(STATUS_WAIT, status).await {
                    Ok(Some(status)) => (Termination::Exited, exit_code_of(&status)),
                    _ => (Termination::Unknown, None),
                },
                None => (Termination::Unknown, None),
            };
            still_running.store(false, Ordering::SeqCst);
            let _ = done_sender.send(Some(result));
            drop(process);
        });

        Ok(StdioProcess {
            stdin: Box::pin(input) as Pin<Box<dyn AsyncWrite + Send>>,
            stdout: Box::pin(stdout_reader),
            stderr_tail,
            handle: Box::new(KubernetesStdioHandle {
                exec: KubernetesExec::new(
                    self.cluster.clone(),
                    self.pod.clone(),
                    self.working_dir.clone(),
                    self.node.clone(),
                ),
                stop_file,
                stop_requested: AtomicBool::new(false),
                running,
                done: done_receiver,
            }),
        })
    }
}

#[async_trait]
impl Exec for KubernetesExec {
    async fn run(&self, spec: &ExecSpec) -> Result<ExecResult> {
        let streaming = self.run_streaming(spec, ExecControls::buffered()).await?;
        streaming.into_complete()
    }

    #[tracing::instrument(skip_all, fields(provider_kind = "kubernetes", sandbox_id = %self.pod), err)]
    async fn run_streaming(
        &self,
        spec: &ExecSpec,
        controls: ExecControls,
    ) -> Result<ExecStreamingResult> {
        run_with_stop_grace(spec, controls, |spec, controls| async move {
            self.run_signals(&spec, controls).await
        })
        .await
    }

    async fn spawn_stdio(&self, spec: &SpawnSpec) -> Result<StdioProcess> {
        self.spawn_stdio_raw(spec).await
    }
}

struct KubernetesStdioHandle {
    exec: KubernetesExec,
    stop_file: String,
    stop_requested: AtomicBool,
    running: std::sync::Arc<AtomicBool>,
    done: watch::Receiver<Option<(Termination, Option<i32>)>>,
}

#[async_trait]
impl StdioProcessHandle for KubernetesStdioHandle {
    async fn terminate(&self) {
        if self.stop_requested.swap(true, Ordering::SeqCst) || !self.running.load(Ordering::SeqCst)
        {
            return;
        }
        if let Err(error) = self
            .exec
            .request_stop(&self.stop_file, StopLevel::Term)
            .await
        {
            tracing::warn!(error = %error, "stdio stop request failed");
            return;
        }
        let mut done = self.done.clone();
        if tokio::time::timeout(TERM_GRACE, done.wait_for(Option::is_some))
            .await
            .is_ok()
        {
            return;
        }
        if let Err(error) = self
            .exec
            .request_stop(&self.stop_file, StopLevel::Kill)
            .await
        {
            tracing::warn!(error = %error, "stdio kill request failed");
        }
    }

    async fn wait(&self) -> (Termination, Option<i32>) {
        let mut done = self.done.clone();
        match done.wait_for(Option::is_some).await {
            Ok(value) => value.unwrap_or((Termination::Unknown, None)),
            Err(_) => (Termination::Unknown, None),
        }
    }
}

/// Captures and sanitizes output while forwarding it to the caller's sink.
struct StreamOutput {
    streams: [(OutputStream, OutputSanitizer, OutputCaptureBuffer); 2],
}

impl StreamOutput {
    fn new(policy: OutputSanitization, limit: Option<usize>) -> Self {
        Self {
            streams: [OutputStream::Stdout, OutputStream::Stderr].map(|stream| {
                (
                    stream,
                    OutputSanitizer::new(policy),
                    OutputCaptureBuffer::new(limit),
                )
            }),
        }
    }

    async fn drain(
        &mut self,
        mut output: ChunkStream,
        sink: Option<&OutputSink>,
        sink_failed: &CancellationToken,
    ) -> StdResult<(), io::Error> {
        while let Some(chunk) = output.next().await {
            let (index, bytes) = match chunk? {
                Chunk::Stdout(bytes) => (0, bytes),
                Chunk::Stderr(bytes) => (1, bytes),
            };
            let (stream, sanitizer, capture) = &mut self.streams[index];
            let bytes = sanitizer.push(&bytes);
            capture.push(&bytes);
            Self::emit(sink, *stream, bytes, sink_failed).await;
        }
        for (stream, sanitizer, capture) in &mut self.streams {
            let bytes = sanitizer.finish();
            capture.push(&bytes);
            Self::emit(sink, *stream, bytes, sink_failed).await;
        }
        Ok(())
    }

    async fn emit(
        sink: Option<&OutputSink>,
        stream: OutputStream,
        bytes: Vec<u8>,
        sink_failed: &CancellationToken,
    ) {
        if !bytes.is_empty() && !sink_failed.is_cancelled() {
            if let Some(sink) = sink {
                if sink(stream, bytes).await.is_err() {
                    sink_failed.cancel();
                }
            }
        }
    }

    fn into_result(
        self,
        termination: Termination,
        exit_code: Option<i32>,
        duration: Duration,
        truncated: bool,
    ) -> ExecStreamingResult {
        let [(_, _, stdout), (_, _, stderr)] = self.streams;
        let (stdout, mut stdout_stats) = stdout.into_parts();
        let (stderr, mut stderr_stats) = stderr.into_parts();
        stdout_stats.truncated = truncated;
        stderr_stats.truncated = truncated;
        let mut result = ExecResult::from_shell_status(termination, exit_code, duration);
        result.stdout = stdout;
        result.stderr = stderr;
        let mut streaming = ExecStreamingResult::new(result);
        streaming.streams_separated = true;
        streaming.live_streaming = true;
        streaming.stdout_capture = stdout_stats;
        streaming.stderr_capture = stderr_stats;
        streaming
    }
}

#[cfg(test)]
mod tests {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{StatusCause, StatusDetails};

    use super::*;

    #[test]
    fn exit_codes_are_read_from_the_status_channel() {
        let success = Status {
            status: Some("Success".to_owned()),
            ..Status::default()
        };
        assert_eq!(exit_code_of(&success), Some(0));
        let failure = Status {
            status: Some("Failure".to_owned()),
            details: Some(StatusDetails {
                causes: Some(vec![StatusCause {
                    reason: Some("ExitCode".to_owned()),
                    message: Some("42".to_owned()),
                    field: None,
                }]),
                ..StatusDetails::default()
            }),
            ..Status::default()
        };
        assert_eq!(exit_code_of(&failure), Some(42));
    }

    #[test]
    fn quoting_survives_single_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    /// The request URL `kube` builds for an exec: one `command` query
    /// parameter per argument, percent-encoded.
    fn exec_query(cmd: &[String]) -> String {
        cmd.iter()
            .map(|word| {
                let encoded: String = word
                    .bytes()
                    .map(|byte| match byte {
                        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                            (byte as char).to_string()
                        }
                        _ => format!("%{byte:02X}"),
                    })
                    .collect();
                format!("command={encoded}")
            })
            .collect::<Vec<_>>()
            .join("&")
    }

    fn large_command() -> (String, Vec<String>, BTreeMap<String, String>) {
        let env = (0..40)
            .map(|index| (format!("SECRET_{index:02}"), "s".repeat(1000)))
            .collect();
        (
            "/bin/sh".to_owned(),
            vec!["-c".to_owned(), "x".repeat(200_000)],
            env,
        )
    }

    fn control_paths() -> (&'static str, &'static str, &'static str) {
        (
            "/tmp/.sandbox-driver/exec-1-2-3.stop",
            "/tmp/.sandbox-driver/exec-1-2-3.pid",
            "/tmp/.sandbox-driver/exec-1-2-3.spec",
        )
    }

    #[test]
    fn the_exec_url_does_not_carry_the_command() {
        let (program, args, env) = large_command();
        let (stop, pid, spec_file) = control_paths();
        let cmd = exec_command("/workspace", stop, pid, spec_file, true);
        let query = exec_query(&cmd);
        assert!(query.len() < 8192, "exec query is {} bytes", query.len());
        assert!(
            !query.contains("SECRET_"),
            "the environment reached the exec URL"
        );
        let spec = KubernetesExec::command_spec(&program, &args, &env);
        assert!(spec.contains(&args[1]) && spec.contains("SECRET_39="));
    }

    #[test]
    fn the_spec_file_sits_beside_the_control_files() {
        let (stop, _, spec_file) = control_paths();
        assert_eq!(KubernetesExec::spec_path(stop), spec_file);
    }

    /// Runs the wrapper under the local `/bin/sh`, as the pod's shell runs it.
    fn run_wrapper(
        dir: &std::path::Path,
        program: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        stdin: Option<&[u8]>,
    ) -> std::process::Output {
        use std::io::Write as _;
        let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
        std::fs::write(
            path("cmd.spec"),
            KubernetesExec::command_spec(program, args, env),
        )
        .expect("test io");
        let cmd = exec_command(
            &dir.to_string_lossy(),
            &path("cmd.stop"),
            &path("cmd.pid"),
            &path("cmd.spec"),
            stdin.is_some(),
        );
        let mut child = std::process::Command::new(&cmd[0])
            .args(&cmd[1..])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("test io");
        // Feed stdin from its own thread: the command's output fills its pipe
        // long before a large input is written, so writing and then reading
        // on one thread deadlocks.
        let mut input = child.stdin.take().expect("test io");
        let bytes = stdin.unwrap_or_default().to_vec();
        let writer = std::thread::spawn(move || input.write_all(&bytes));
        let pid = child.id();
        let (done, waited) = std::sync::mpsc::channel();
        std::thread::spawn(move || done.send(child.wait_with_output().expect("test io")));
        let output = waited
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap_or_else(|_| {
                let _ = std::process::Command::new("kill")
                    .arg("-9")
                    .arg(pid.to_string())
                    .status();
                panic!("the wrapper did not finish within 30s")
            });
        writer.join().expect("test io").expect("test io");
        output
    }

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sandbox-driver-kubernetes-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test io");
        dir
    }

    #[test]
    fn the_wrapper_runs_the_staged_command_with_its_environment_and_removes_the_spec() {
        let dir = scratch_dir("staged");
        let env = BTreeMap::from([
            ("QUOTED".to_owned(), "it's\nmulti line $HOME `x`".to_owned()),
            ("EMPTY".to_owned(), String::new()),
        ]);
        let args = vec![
            "-c".to_owned(),
            "printf '[%s][%s][%s][%s]' \"$QUOTED\" \"$EMPTY\" \"$1\" \"$#\"".to_owned(),
            "prog".to_owned(),
            "a 'b' \"c\"".to_owned(),
        ];
        let output = run_wrapper(&dir, "/bin/sh", &args, &env, None);
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "[it's\nmulti line $HOME `x`][][a 'b' \"c\"][1]",
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.status.code(), Some(0));
        assert!(
            !dir.join("cmd.spec").exists(),
            "the spec file was left behind"
        );
        std::fs::remove_dir_all(&dir).expect("test io");
    }

    #[test]
    fn a_forwarded_stdin_still_reaches_the_command_unchanged() {
        let dir = scratch_dir("stdin");
        let input: Vec<u8> = (0..=255_u8).cycle().take(300_000).collect();
        let output = run_wrapper(&dir, "cat", &[], &BTreeMap::new(), Some(&input));
        assert_eq!(output.status.code(), Some(0));
        assert!(
            output.stdout == input,
            "stdin did not reach the command unchanged"
        );
        std::fs::remove_dir_all(&dir).expect("test io");
    }

    #[test]
    fn a_missing_spec_fails_the_command_rather_than_running_nothing() {
        let dir = scratch_dir("missing");
        let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
        let cmd = exec_command(
            &dir.to_string_lossy(),
            &path("cmd.stop"),
            &path("cmd.pid"),
            &path("absent.spec"),
            false,
        );
        let output = std::process::Command::new(&cmd[0])
            .args(&cmd[1..])
            .output()
            .expect("test io");
        assert_eq!(output.status.code(), Some(126));
        assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read the command spec"));
        std::fs::remove_dir_all(&dir).expect("test io");
    }
}
