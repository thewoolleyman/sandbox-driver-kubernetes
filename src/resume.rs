//! Commands that outlive a dropped Kubernetes API connection.
//!
//! An exec stream is one WebSocket through the API server to the kubelet.
//! A k3s server restart (about 15 s with no API, measured 2026-11-02 on
//! gmktec) drops every open stream while the pod and its node stay Ready,
//! and the command inside keeps running. What is lost is only the driver's
//! view of it. So the command never writes to an exec stream:
//!
//! - a **launch** exec stages the command spec and starts a detached
//!   supervisor. The supervisor runs the wrapper with stdout and stderr
//!   appended to files beside the stop and pid files, and writes the exit
//!   status to a status file once the command ends. The launch is
//!   idempotent: a lock directory makes a retried launch a no-op, and the
//!   spec's byte length is checked, so a launch cut short never starts a
//!   truncated command;
//! - a **follow** exec streams the two output files from byte offsets and
//!   exits with the recorded status. The driver counts every byte it
//!   receives, so after a drop it re-attaches a follower at exactly those
//!   offsets: no output is lost or repeated, and the exit status is the
//!   command's own;
//! - for a command with stdin, each chunk the caller writes travels in its
//!   own short **input** exec at a known offset of an input file, which a
//!   feeder inside the supervisor pipes to the command. The exec reads the
//!   chunk first (as the launch reads the spec) and checks its length, and
//!   under a lock appends it only when the file ends exactly at that
//!   offset. So a chunk lost in transit is sent again, a chunk that landed
//!   but lost its status is a no-op the second time, and the driver knows
//!   exactly which bytes the sandbox holds. End of input is a marker the
//!   driver writes once the file holds every byte it sent. (A long-lived
//!   input exec that printed the file size and then ran `cat` was measured
//!   on a kind v1.32 cluster to drop its stdin entirely, while the
//!   read-first launch pattern never did.)
//!
//! Every re-attach is bounded by [`ResumePolicy`]. A connection that stays
//! down past it fails the command as before: "the exec stream ended without
//! an exit status; the sandbox became unreachable".

use std::io;
use std::time::{Duration, Instant};

use futures_util::StreamExt as _;
use sandbox_driver::{BASH_ENV_VAR, Error, Result, TransportError};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::mpsc;

use crate::exec::{Chunk, Target, exit_code_of, merged_output};

/// How long to wait for an exec's status once its output has ended.
const STATUS_WAIT: Duration = Duration::from_secs(30);
const READ_CHUNK: usize = 64 * 1024;
/// How many times the end of input is re-verified before giving up.
const CLOSE_ATTEMPTS: u32 = 10;
/// At most this many finished commands' files are removed per launch, so
/// the launch URL stays small.
pub(crate) const CLEANUP_PER_LAUNCH: usize = 16;

/// The bounded wait for a dropped exec stream to come back.
#[derive(Clone, Copy, Debug)]
pub struct ResumePolicy {
    /// How long an outage may last before the command is failed. Counted
    /// from the drop; a re-attach that reaches the command resets it.
    pub budget: Duration,
    /// The pause before the first re-attach; each later pause doubles.
    pub initial_delay: Duration,
    /// The longest single pause.
    pub max_delay: Duration,
}

impl Default for ResumePolicy {
    /// Three minutes: past the client's two-minute connect retry, so a
    /// k3s server restart (about 15 s) or a flannel panic (about 17 s)
    /// fits with room to spare.
    fn default() -> Self {
        Self {
            budget: Duration::from_secs(180),
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(5),
        }
    }
}

/// The poll schedule of the in-sandbox loops: quick at first, so a short
/// command returns promptly, then every 100 ms.
const POLL_STEP: &str = "case $d in 0.01) d=0.02 ;; 0.02) d=0.05 ;; *) d=0.1 ;; esac";

/// `$1` control dir, `$2` prefix, `$3` forward stdin (0/1), `$4` spec
/// length, `$5` supervisor, `$6` wrapper, then prefixes of finished
/// commands whose files are removed. Stdin is the spec. Exits 0 once the
/// command is running (now or by an earlier launch), 3 when the spec
/// arrived truncated.
///
/// The driver's own control files are private (`umask 077`), but the
/// command itself must run under the sandbox shell's umask, so the caller's
/// umask is saved first and handed to the supervisor, which restores it
/// right before it runs the wrapper (bd-ib-digmk2).
const LAUNCH: &str = r#"SANDBOX_DRIVER_CALLER_UMASK=$(umask); export SANDBOX_DRIVER_CALLER_UMASK
umask 077
dir=$1 p=$2 fwd=$3 len=$4 sup=$5 wrap=$6
shift 6
for old; do rm -rf "$old".* 2>/dev/null; done
mkdir -p "$dir" || exit 1
tmp="$p.spec.$$"
if ! cat > "$tmp"; then rm -f "$tmp"; exit 1; fi
got=$(wc -c < "$tmp"); got=$((got + 0))
if [ "$got" -ne "$len" ]; then rm -f "$tmp"; exit 3; fi
: >> "$p.out"; : >> "$p.err"
if [ "$fwd" = 1 ]; then : >> "$p.in"; fi
if ! mkdir "$p.lock" 2>/dev/null; then rm -f "$tmp"; exit 0; fi
mv -f "$tmp" "$p.spec"
if command -v setsid >/dev/null 2>&1; then
  setsid /bin/sh -c "$sup" sandbox-driver-supervise "$p" "$fwd" "$wrap" </dev/null >/dev/null 2>&1 &
else
  /bin/sh -c "$sup" sandbox-driver-supervise "$p" "$fwd" "$wrap" </dev/null >/dev/null 2>&1 &
fi
exit 0"#;

/// `$1` prefix, `$2` forward stdin, `$3` wrapper.
fn supervise() -> String {
    format!(
        r#"p=$1 fwd=$2 wrap=$3
cu=${{SANDBOX_DRIVER_CALLER_UMASK:-022}}; unset SANDBOX_DRIVER_CALLER_UMASK
finish() {{ printf '%s\n' "$1" > "$p.status.tmp" && mv -f "$p.status.tmp" "$p.status"; exit 0; }}
in=/dev/null feeder=
if [ "$fwd" = 1 ]; then
  rm -f "$p.fifo"
  if ! mkfifo -m 600 "$p.fifo"; then echo 'sandbox-driver: cannot create the stdin fifo' >> "$p.err"; finish 126; fi
  (
    exec 4< "$p.in"
    d=0.01
    while :; do
      if [ -e "$p.in.eof" ]; then cat <&4; break; fi
      cat <&4 || break
      sleep "$d"
      {POLL_STEP}
    done
  ) > "$p.fifo" 2>/dev/null &
  feeder=$!
  in="$p.fifo"
fi
(umask "$cu" && exec /bin/sh -c "$wrap" sandbox-driver) < "$in" >> "$p.out" 2>> "$p.err"
status=$?
if [ -n "$feeder" ]; then kill "$feeder" 2>/dev/null; fi
rm -f "$p.fifo"
finish "$status""#
    )
}

/// `$1` prefix, `$2` stdout offset, `$3` stderr offset. Prints a header
/// line (`follow`, or `gone` when the files no longer exist), then the
/// output from the offsets, and exits with the command's status.
fn follow_script() -> String {
    format!(
        r#"p=$1
if [ ! -e "$p.out" ] || [ ! -e "$p.err" ]; then echo gone; exit 0; fi
exec 4< "$p.out" 5< "$p.err"
echo follow
if [ "$2" -gt 0 ]; then head -c "$2" <&4 > /dev/null; fi
if [ "$3" -gt 0 ]; then head -c "$3" <&5 > /dev/null; fi
d=0.01
while :; do
  if [ -e "$p.status" ]; then
    cat <&4; cat <&5 >&2
    status=$(cat "$p.status")
    exit "$status"
  fi
  cat <&4; cat <&5 >&2
  sleep "$d"
  {POLL_STEP}
done"#
    )
}

/// `$1` prefix, `$2` offset, `$3` length. Stdin is one chunk of the
/// command's input, which belongs at that offset of the input file. The
/// chunk is read first, as the launch reads the spec, and its length is
/// checked (exit 3 when it arrived truncated). Under a lock, it is
/// appended only when the file ends exactly at the offset, so a retried
/// chunk that already landed is a no-op (exit 0). Exits 2 when the input
/// file is gone, 4 when the file is short of the offset.
const INPUT: &str = r#"p=$1 off=$2 len=$3
if [ ! -e "$p.in" ]; then cat > /dev/null; exit 2; fi
tmp="$p.in.$$"
if ! cat > "$tmp"; then rm -f "$tmp"; exit 1; fi
got=$(wc -c < "$tmp"); got=$((got + 0))
if [ "$got" -ne "$len" ]; then rm -f "$tmp"; exit 3; fi
tries=0
while ! mkdir "$p.in.lock" 2>/dev/null; do
  tries=$((tries + 1))
  if [ "$tries" -gt 200 ]; then rm -f "$tmp"; exit 4; fi
  sleep 0.05
done
size=$(wc -c < "$p.in"); size=$((size + 0))
status=0
if [ "$size" -eq "$off" ]; then
  cat "$tmp" >> "$p.in" || status=1
elif [ "$size" -lt "$off" ]; then
  status=4
fi
rmdir "$p.in.lock"
rm -f "$tmp"
exit "$status""#;

/// `$1` prefix, `$2` total bytes sent. Marks the end of input when the
/// file holds them all (exit 0); exits 4 when bytes are missing.
const CLOSE_INPUT: &str = r#"p=$1
size=$(wc -c < "$p.in") || exit 5
size=$((size + 0))
if [ "$size" -eq "$2" ]; then : > "$p.in.eof"; exit 0; fi
exit 4"#;

fn shell(script: &str, name: &str, args: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut cmd = vec![
        "env".to_owned(),
        format!("{BASH_ENV_VAR}="),
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        script.to_owned(),
        name.to_owned(),
    ];
    cmd.extend(args);
    cmd
}

/// The launch exec for the command whose control files start `prefix`.
pub(crate) fn launch_command(
    control_dir: &str,
    prefix: &str,
    forward_stdin: bool,
    spec_len: usize,
    wrapper: &str,
    cleanup: &[String],
) -> Vec<String> {
    shell(
        LAUNCH,
        "sandbox-driver-launch",
        [
            control_dir.to_owned(),
            prefix.to_owned(),
            if forward_stdin { "1" } else { "0" }.to_owned(),
            spec_len.to_string(),
            supervise(),
            wrapper.to_owned(),
        ]
        .into_iter()
        .chain(cleanup.iter().cloned()),
    )
}

fn follow_command(prefix: &str, offsets: [u64; 2]) -> Vec<String> {
    shell(
        &follow_script(),
        "sandbox-driver-follow",
        [
            prefix.to_owned(),
            offsets[0].to_string(),
            offsets[1].to_string(),
        ],
    )
}

fn input_command(prefix: &str, offset: u64, len: usize) -> Vec<String> {
    shell(
        INPUT,
        "sandbox-driver-input",
        [prefix.to_owned(), offset.to_string(), len.to_string()],
    )
}

fn close_input_command(prefix: &str, total: u64) -> Vec<String> {
    shell(
        CLOSE_INPUT,
        "sandbox-driver-close-input",
        [prefix.to_owned(), total.to_string()],
    )
}

/// Waits for an exec's status, bounded.
async fn exit_code(
    status: Option<
        impl Future<Output = Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Status>>,
    >,
) -> Option<i32> {
    let status = status?;
    tokio::time::timeout(STATUS_WAIT, status)
        .await
        .ok()
        .flatten()
        .as_ref()
        .and_then(exit_code_of)
}

/// The doubling pause between re-attaches.
struct Backoff {
    policy: ResumePolicy,
    delay: Duration,
    outage: Option<Instant>,
    reconnects: u32,
}

impl Backoff {
    fn new(policy: ResumePolicy) -> Self {
        Self {
            policy,
            delay: policy.initial_delay,
            outage: None,
            reconnects: 0,
        }
    }

    /// When the current outage began, or now when there is none.
    fn since(&self) -> Instant {
        self.outage.unwrap_or_else(Instant::now)
    }

    /// The command was reached again: a later drop is a new outage.
    fn reached(&mut self) {
        self.outage = None;
        self.delay = self.policy.initial_delay;
    }

    /// Records a drop. `Err` with the elapsed outage once it outlasted the
    /// budget; otherwise sleeps the next pause.
    async fn dropped(&mut self, what: &str) -> std::result::Result<(), Duration> {
        let outage = *self.outage.get_or_insert_with(Instant::now);
        self.reconnects += 1;
        let waited = outage.elapsed();
        if waited + self.delay > self.policy.budget {
            return Err(waited);
        }
        tracing::warn!(
            stream = what,
            reconnects = self.reconnects,
            delay_ms = self.delay.as_millis() as u64,
            "the exec stream dropped; re-attaching"
        );
        tokio::time::sleep(self.delay).await;
        self.delay = (self.delay * 2).min(self.policy.max_delay);
        Ok(())
    }
}

fn gone(prefix: &str) -> Error {
    Error::Transport(TransportError::new(format!(
        "the command's output files {prefix}.* are gone from the sandbox (its container restarted or /tmp was cleared); the sandbox became unreachable"
    )))
}

fn unreachable(reconnects: u32, waited: Duration) -> Error {
    Error::Transport(TransportError::new(format!(
        "the exec stream ended without an exit status; the sandbox became unreachable (it did not resume after {reconnects} re-attaches over {:.1}s)",
        waited.as_secs_f64()
    )))
}

/// Streams the command's output into `sender` from wherever it is, across
/// any number of dropped connections, and returns its exit status.
pub(crate) async fn follow(
    target: Target,
    prefix: String,
    sender: mpsc::Sender<Chunk>,
) -> Result<i32> {
    let mut offsets = [0_u64; 2];
    let mut backoff = Backoff::new(target.resume);
    loop {
        let mut process = target
            .attach_resuming(follow_command(&prefix, offsets), false, backoff.since())
            .await?;
        let status = process.take_status();
        let mut output = merged_output(&mut process);
        // `Some` until the header line has been read off stdout.
        let mut header: Option<Vec<u8>> = Some(Vec::new());
        let mut following = false;
        while let Some(item) = output.next().await {
            let chunk = match item {
                Ok(chunk) => chunk,
                Err(error) => {
                    tracing::warn!(%error, "reading the output follower failed");
                    break;
                }
            };
            let chunk = match (chunk, header.as_mut()) {
                (Chunk::Stdout(bytes), Some(line)) => {
                    line.extend_from_slice(&bytes);
                    let Some(end) = line.iter().position(|byte| *byte == b'\n') else {
                        continue;
                    };
                    match &line[..end] {
                        b"follow" => {
                            following = true;
                            backoff.reached();
                        }
                        b"gone" => return Err(target.diagnose(gone(&prefix)).await),
                        other => {
                            return Err(Error::io(
                                "following the command output",
                                io::Error::other(format!(
                                    "unexpected follower header {:?}",
                                    String::from_utf8_lossy(other)
                                )),
                            ));
                        }
                    }
                    let rest = line[end + 1..].to_vec();
                    header = None;
                    Chunk::Stdout(rest)
                }
                (chunk, _) => chunk,
            };
            let (index, len) = match &chunk {
                Chunk::Stdout(bytes) => (0, bytes.len()),
                Chunk::Stderr(bytes) => (1, bytes.len()),
            };
            if len == 0 {
                continue;
            }
            offsets[index] += len as u64;
            if sender.send(chunk).await.is_err() {
                // The caller stopped reading: nothing is left to deliver.
                return Err(Error::io(
                    "following the command output",
                    io::Error::other("the output reader went away"),
                ));
            }
        }
        drop(output);
        let code = exit_code(status).await;
        match (following, code) {
            (true, Some(code)) => return Ok(code),
            (false, Some(code)) => {
                return Err(Error::io(
                    "following the command output",
                    io::Error::other(format!(
                        "the output follower exited {code} before following"
                    )),
                ));
            }
            (_, None) => {
                if let Err(waited) = backoff.dropped("output").await {
                    return Err(target
                        .diagnose(unreachable(backoff.reconnects, waited))
                        .await);
                }
            }
        }
    }
}

/// Runs one input exec (a chunk, or the end-of-input mark) with `stdin`
/// as its input, and returns its exit status: `None` when the connection
/// dropped before it reported one.
async fn input_exec(
    target: &Target,
    cmd: Vec<String>,
    stdin: Option<&[u8]>,
    since: Instant,
) -> Result<Option<i32>> {
    let mut process = target.attach_resuming(cmd, stdin.is_some(), since).await?;
    let status = process.take_status();
    if let (Some(bytes), Some(mut writer)) = (stdin, process.stdin()) {
        // A failed write means the connection dropped; the missing status
        // says so.
        if writer.write_all(bytes).await.is_ok() {
            let _ = writer.shutdown().await;
        }
    }
    let mut output = merged_output(&mut process);
    while output.next().await.is_some() {}
    drop(output);
    Ok(exit_code(status).await)
}

/// Delivers everything read from `source` to the command's stdin, across
/// any number of dropped connections, then marks the end of input. Each
/// read is one chunk, written at its offset by its own short exec and
/// confirmed by that exec's status before the next one is sent, so the
/// driver always knows exactly which bytes the sandbox holds.
pub(crate) async fn feed_input(
    target: Target,
    prefix: String,
    mut source: impl AsyncRead + Unpin,
) -> Result<()> {
    let mut offset: u64 = 0;
    let mut backoff = Backoff::new(target.resume);
    let mut buffer = vec![0_u8; READ_CHUNK];
    loop {
        let read = source
            .read(&mut buffer)
            .await
            .map_err(|error| Error::io("reading exec stdin", error))?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        loop {
            let cmd = input_command(&prefix, offset, chunk.len());
            match input_exec(&target, cmd, Some(chunk), backoff.since()).await? {
                Some(0) => break,
                Some(2) => return Err(target.diagnose(gone(&prefix)).await),
                // Cut short in transit (3) or still settling (4): send again.
                Some(3 | 4) | None => {}
                Some(code) => {
                    return Err(Error::io(
                        "writing exec stdin",
                        io::Error::other(format!("writing an input chunk exited {code}")),
                    ));
                }
            }
            if let Err(waited) = backoff.dropped("input").await {
                return Err(target
                    .diagnose(unreachable(backoff.reconnects, waited))
                    .await);
            }
        }
        backoff.reached();
        offset += read as u64;
    }
    let mut close_attempts = 0_u32;
    loop {
        let cmd = close_input_command(&prefix, offset);
        match input_exec(&target, cmd, None, backoff.since()).await? {
            Some(0) => return Ok(()),
            Some(4) if close_attempts < CLOSE_ATTEMPTS => close_attempts += 1,
            None => {}
            Some(code) => {
                return Err(Error::io(
                    "closing exec stdin",
                    io::Error::other(format!("marking the end of input exited {code}")),
                ));
            }
        }
        if let Err(waited) = backoff.dropped("input").await {
            return Err(target
                .diagnose(unreachable(backoff.reconnects, waited))
                .await);
        }
    }
}

#[cfg(test)]
mod umask_tests {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::launch_command;

    /// Runs the real launch and supervise scripts with the local `/bin/sh`,
    /// as a sandbox shell with umask 0022 would, and returns the umask the
    /// wrapped command saw.
    fn umask_seen_by_the_command(caller_umask: &str) -> String {
        let dir =
            std::env::temp_dir().join(format!("sdk-umask-{}-{}", std::process::id(), caller_umask));
        let _ = std::fs::remove_dir_all(&dir);
        let control = dir.to_string_lossy().into_owned();
        let prefix = format!("{control}/c");
        let argv = launch_command(&control, &prefix, false, 0, "umask", &[]);
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("umask {caller_umask}; exec \"$@\" < /dev/null"))
            .arg("caller")
            .args(&argv)
            .status()
            .expect("runs the launch script");
        assert!(status.success(), "launch exited {status}");
        let deadline = Instant::now() + Duration::from_secs(10);
        let status_file = format!("{prefix}.status");
        while !std::path::Path::new(&status_file).exists() {
            assert!(Instant::now() < deadline, "the command never finished");
            std::thread::sleep(Duration::from_millis(20));
        }
        let seen = std::fs::read_to_string(format!("{prefix}.out")).expect("reads stdout");
        let _ = std::fs::remove_dir_all(&dir);
        seen.trim().to_owned()
    }

    #[test]
    fn the_wrapped_command_runs_under_the_callers_umask_not_the_drivers() {
        assert_eq!(umask_seen_by_the_command("0022"), "0022");
        assert_eq!(umask_seen_by_the_command("0002"), "0002");
    }

    #[test]
    fn the_drivers_control_files_stay_private() {
        let dir = std::env::temp_dir().join(format!("sdk-umask-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let control = dir.to_string_lossy().into_owned();
        let prefix = format!("{control}/c");
        let argv = launch_command(&control, &prefix, false, 0, "true", &[]);
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg("umask 0022; exec \"$@\" < /dev/null")
            .arg("caller")
            .args(&argv)
            .status()
            .expect("runs the launch script");
        assert!(status.success());
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(format!("{prefix}.out"))
            .expect("stdout file exists")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "control file mode {mode:o} is readable by others"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
