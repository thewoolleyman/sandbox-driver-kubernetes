//! A stand-in Kubernetes API for unit tests: it serves the pod and node
//! reads `diagnose` makes, and the `exec` WebSocket (`v5.channel.k8s.io`).
//! An exec runs its command on the test host under `/bin/sh`, so the
//! sandbox's in-container scripts run for real. [`FakeApi::sever`] drops
//! every open exec connection abruptly, as a k3s server restart does: no
//! close frame and no status, its local process killed, and the bytes it
//! had in flight lost. The pod and its node keep answering Ready.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt as _, StreamExt as _};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_util::sync::CancellationToken;

use crate::client::KubeClient;
use crate::pod::Cluster;

pub(crate) const NAMESPACE: &str = "ns";
pub(crate) const POD: &str = "p";
const NODE: &str = "n";

#[derive(Default)]
struct State {
    /// One token per open exec connection; cancelling it severs it.
    live: Mutex<HashMap<u64, CancellationToken>>,
    next_id: std::sync::atomic::AtomicU64,
    /// The name (`$0`) of every exec started, in order.
    execs: Mutex<Vec<String>>,
    /// Sever every open exec once a follower has sent this many stdout
    /// bytes; the chunk that crosses it is lost in transit.
    sever_at_followed: Mutex<Option<usize>>,
    followed: AtomicUsize,
    /// Answer this many exec upgrades with 503, as an API server coming
    /// back does.
    unavailable_execs: AtomicU32,
    /// What [`State::unavailable_execs`] becomes on each sever.
    unavailable_after_sever: AtomicU32,
    severed: AtomicU32,
    /// Drop the input exec with this ordinal (0-based) on its first stdin
    /// frame, before the bytes reach its process.
    drop_input: Mutex<Option<usize>>,
    inputs: AtomicUsize,
    dropped_inputs: AtomicU32,
}

/// The stand-in API server.
pub(crate) struct FakeApi {
    port: u16,
    state: Arc<State>,
    dir: PathBuf,
}

impl FakeApi {
    pub(crate) async fn start(tag: &str) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind the fake API");
        let port = listener.local_addr().expect("addr").port();
        let state = Arc::new(State::default());
        let serving = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(socket, Arc::clone(&serving)));
            }
        });
        let dir = std::env::temp_dir().join(format!("sdk-fake-api-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        Self { port, state, dir }
    }

    /// A scratch directory for the test: the "sandbox" working directory
    /// and control directory live under it.
    pub(crate) fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    pub(crate) async fn cluster(&self) -> Cluster {
        let path = self.dir.join("kubeconfig");
        std::fs::write(
            &path,
            format!(
                "apiVersion: v1\nkind: Config\nclusters:\n- name: c\n  cluster:\n    server: http://127.0.0.1:{}\ncontexts:\n- name: x\n  context:\n    cluster: c\n    user: u\n    namespace: {NAMESPACE}\ncurrent-context: x\nusers:\n- name: u\n  user:\n    token: t\n",
                self.port
            ),
        )
        .expect("write kubeconfig");
        Cluster {
            client: KubeClient::from_file(path, None).await.expect("client"),
            namespace: NAMESPACE.to_owned(),
        }
    }

    /// Drops every open exec connection now. Returns how many it dropped.
    pub(crate) fn sever(&self) -> u32 {
        sever(&self.state)
    }

    pub(crate) fn sever_when_followed(&self, bytes: usize) {
        *self.state.sever_at_followed.lock().expect("lock") = Some(bytes);
    }

    /// After each sever, answer the next `count` exec upgrades with 503.
    pub(crate) fn unavailable_after_sever(&self, count: u32) {
        self.state
            .unavailable_after_sever
            .store(count, Ordering::SeqCst);
    }

    /// Drops the `ordinal`th input exec (0-based) with its chunk in flight.
    pub(crate) fn drop_input_exec(&self, ordinal: usize) {
        *self.state.drop_input.lock().expect("lock") = Some(ordinal);
    }

    /// How many input execs were dropped with their chunk in flight.
    pub(crate) fn dropped_inputs(&self) -> u32 {
        self.state.dropped_inputs.load(Ordering::SeqCst)
    }

    /// How many exec connections were severed so far.
    pub(crate) fn severed(&self) -> u32 {
        self.state.severed.load(Ordering::SeqCst)
    }

    /// How many execs named `name` were started.
    pub(crate) fn execs_named(&self, name: &str) -> usize {
        self.state
            .execs
            .lock()
            .expect("lock")
            .iter()
            .filter(|started| started.as_str() == name)
            .count()
    }
}

impl Drop for FakeApi {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn sever(state: &State) -> u32 {
    let live: Vec<CancellationToken> = state
        .live
        .lock()
        .expect("lock")
        .drain()
        .map(|(_, token)| token)
        .collect();
    let count = live.len() as u32;
    state.unavailable_execs.store(
        state.unavailable_after_sever.load(Ordering::SeqCst),
        Ordering::SeqCst,
    );
    for token in live {
        token.cancel();
    }
    state.severed.fetch_add(count, Ordering::SeqCst);
    count
}

/// Decodes one `application/x-www-form-urlencoded` component.
fn decode(component: &str) -> String {
    let bytes = component.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).expect("hex");
                out.push(u8::from_str_radix(hex, 16).expect("hex"));
                index += 2;
            }
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8(out).expect("utf-8 query")
}

async fn respond(socket: &mut TcpStream, code: u16, body: &str) {
    let response = format!(
        "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = socket.write_all(response.as_bytes()).await;
    let _ = socket.shutdown().await;
}

async fn serve(mut socket: TcpStream, state: Arc<State>) {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match socket.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head.split("\r\n");
    let target = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .unwrap_or_default()
        .to_owned();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    if path == format!("/api/v1/namespaces/{NAMESPACE}/pods/{POD}/exec") {
        exec(socket, &state, query, &headers).await;
    } else if path == format!("/api/v1/namespaces/{NAMESPACE}/pods/{POD}") {
        let body = format!(
            r#"{{"apiVersion":"v1","kind":"Pod","metadata":{{"name":"{POD}","namespace":"{NAMESPACE}"}},"spec":{{"nodeName":"{NODE}","containers":[]}},"status":{{"phase":"Running"}}}}"#
        );
        respond(&mut socket, 200, &body).await;
    } else if path == format!("/api/v1/nodes/{NODE}") {
        let body = format!(
            r#"{{"apiVersion":"v1","kind":"Node","metadata":{{"name":"{NODE}"}},"status":{{"conditions":[{{"type":"Ready","status":"True"}}]}}}}"#
        );
        respond(&mut socket, 200, &body).await;
    } else {
        respond(
            &mut socket,
            404,
            r#"{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}"#,
        )
        .await;
    }
}

fn status_json(code: Option<i32>) -> String {
    match code {
        Some(0) => r#"{"metadata":{},"status":"Success"}"#.to_owned(),
        Some(code) => format!(
            r#"{{"metadata":{{}},"status":"Failure","message":"command terminated with non-zero exit code","reason":"NonZeroExitCode","details":{{"causes":[{{"reason":"ExitCode","message":"{code}"}}]}}}}"#
        ),
        None => r#"{"metadata":{},"status":"Failure","message":"killed","reason":"InternalError"}"#
            .to_owned(),
    }
}

async fn exec(
    mut socket: TcpStream,
    state: &Arc<State>,
    query: &str,
    headers: &HashMap<String, String>,
) {
    let unavailable = {
        let mut left = state.unavailable_execs.load(Ordering::SeqCst);
        loop {
            if left == 0 {
                break false;
            }
            match state.unavailable_execs.compare_exchange(
                left,
                left - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break true,
                Err(now) => left = now,
            }
        }
    };
    if unavailable {
        respond(
            &mut socket,
            503,
            r#"{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"ServiceUnavailable","code":503}"#,
        )
        .await;
        return;
    }
    let mut command = Vec::new();
    let mut stdin = false;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "command" => command.push(decode(value)),
            "stdin" => stdin = value == "true",
            _ => {}
        }
    }
    let name = command.get(5).cloned().unwrap_or_default();
    state.execs.lock().expect("lock").push(name.clone());
    let key = headers
        .get("sec-websocket-key")
        .cloned()
        .unwrap_or_default();
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: v5.channel.k8s.io\r\n\r\n",
        derive_accept_key(key.as_bytes())
    );
    if socket.write_all(response.as_bytes()).await.is_err() {
        return;
    }
    let mut ws = WebSocketStream::from_raw_socket(socket, Role::Server, None).await;
    let Some((program, args)) = command.split_first() else {
        return;
    };
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn the exec command");
    let mut child_stdin = child.stdin.take();
    let mut stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let token = CancellationToken::new();
    let id = state.next_id.fetch_add(1, Ordering::SeqCst);
    state.live.lock().expect("lock").insert(id, token.clone());
    // The stream that carries a command's output: the follower, or the
    // command's own exec where output is not resumable.
    let drop_on_stdin = name == "sandbox-driver-input" && {
        let ordinal = state.inputs.fetch_add(1, Ordering::SeqCst);
        let mut target = state.drop_input.lock().expect("lock");
        if *target == Some(ordinal) {
            *target = None;
            true
        } else {
            false
        }
    };
    let follower = matches!(name.as_str(), "sandbox-driver-follow" | "sandbox-driver");
    let (mut out_buf, mut err_buf) = (vec![0_u8; 65536], vec![0_u8; 65536]);
    let (mut out_open, mut err_open) = (true, true);
    loop {
        if !out_open && !err_open {
            break;
        }
        tokio::select! {
            () = token.cancelled() => {
                // Severed: no close frame, no status; the process dies with
                // whatever it had not yet written.
                let _ = child.start_kill();
                return;
            }
            message = ws.next() => match message {
                Some(Ok(Message::Binary(bytes))) if bytes.first() == Some(&0) => {
                    if drop_on_stdin {
                        state.dropped_inputs.fetch_add(1, Ordering::SeqCst);
                        state.live.lock().expect("lock").remove(&id);
                        let _ = child.start_kill();
                        return;
                    }
                    if let Some(input) = child_stdin.as_mut() {
                        let _ = input.write_all(&bytes[1..]).await;
                    }
                }
                Some(Ok(Message::Binary(bytes))) if bytes.as_ref() == [255, 0] => {
                    child_stdin = None;
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => {
                    let _ = child.start_kill();
                    return;
                }
            },
            read = stdout.read(&mut out_buf), if out_open => match read {
                Ok(0) | Err(_) => out_open = false,
                Ok(read) => {
                    if follower {
                        let total = state.followed.fetch_add(read, Ordering::SeqCst) + read;
                        let due = {
                            let mut at = state.sever_at_followed.lock().expect("lock");
                            match *at {
                                Some(limit) if total >= limit => at.take().is_some(),
                                _ => false,
                            }
                        };
                        if due {
                            sever(state);
                            continue;
                        }
                    }
                    let mut frame = vec![1_u8];
                    frame.extend_from_slice(&out_buf[..read]);
                    let _ = ws.send(Message::binary(frame)).await;
                }
            },
            read = stderr.read(&mut err_buf), if err_open => match read {
                Ok(0) | Err(_) => err_open = false,
                Ok(read) => {
                    let mut frame = vec![2_u8];
                    frame.extend_from_slice(&err_buf[..read]);
                    let _ = ws.send(Message::binary(frame)).await;
                }
            },
        }
    }
    let code = tokio::select! {
        () = token.cancelled() => {
            let _ = child.start_kill();
            return;
        }
        status = child.wait() => status.ok().and_then(|status| status.code()),
    };
    state.live.lock().expect("lock").remove(&id);
    let mut frame = vec![3_u8];
    frame.extend_from_slice(status_json(code).as_bytes());
    let _ = ws.send(Message::binary(frame)).await;
    let _ = ws.close(None).await;
}
