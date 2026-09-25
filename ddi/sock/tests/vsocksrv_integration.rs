// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end test: [`azihsm_ddi_sock::DdiSock`] against a real `vsocksrv`
//! process running an in-process `StdHsm`.
//!
//! `vsocksrv --socket-type unix` dials *out* to a Cloud-Hypervisor-style
//! `AF_UNIX` listener and sends `CONNECT <port>\n` before the framed
//! SQE/CQE protocol begins. `DdiSockDev` instead dials *in* to a plain
//! socket speaking that framed protocol directly. This test bridges the
//! two: it accepts the `vsocksrv` connection, strips the `CONNECT` line,
//! and splices the remaining bytes to a second listener that `DdiSockDev`
//! connects to, so the client exercises the exact wire protocol used by
//! the socket DDI transport.

#![cfg(target_os = "linux")]

use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_mbor_types::DdiApiRev;
use azihsm_ddi_mbor_types::DdiGetApiRevCmdReq;
use azihsm_ddi_mbor_types::DdiGetApiRevReq;
use azihsm_ddi_mbor_types::DdiOp;
use azihsm_ddi_mbor_types::DdiReqHdr;
use azihsm_ddi_sock::DdiSock;

/// Kills the `vsocksrv` child process when dropped, so a failing
/// assertion never leaks a background server.
struct VsocksrvGuard(Child);

impl Drop for VsocksrvGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Unique-per-test socket paths under the OS temp directory.
struct SocketPaths {
    /// Path `vsocksrv` connects out to (stands in for Cloud Hypervisor).
    ch: PathBuf,
    /// Path the socket DDI client connects to.
    ddi: PathBuf,
    /// Whether this test actually bound (and therefore created) `ch`.
    ch_owned: bool,
    /// Whether this test actually bound (and therefore created) `ddi`.
    ddi_owned: bool,
}

impl SocketPaths {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir();
        let unique = format!(
            "{tag}-{}-{:?}",
            std::process::id(),
            Instant::now().elapsed()
        );
        Self {
            ch: dir.join(format!("azihsm-ddi-sock-test-ch-{unique}.sock")),
            ddi: dir.join(format!("azihsm-ddi-sock-test-ddi-{unique}.sock")),
            ch_owned: false,
            ddi_owned: false,
        }
    }
}

impl Drop for SocketPaths {
    /// Only removes socket files this test actually created (i.e. ones
    /// whose `UnixListener::bind` succeeded), so a stale socket or
    /// another process's endpoint that happened to collide with this
    /// PID/tag-based name is never unlinked here.
    fn drop(&mut self) {
        if self.ch_owned {
            let _ = std::fs::remove_file(&self.ch);
        }
        if self.ddi_owned {
            let _ = std::fs::remove_file(&self.ddi);
        }
    }
}

/// Reads and discards the `CONNECT <port>\n` line `vsocksrv` sends first,
/// then splices the remainder of `ch` bidirectionally with `ddi`.
fn bridge_connection(mut ch: UnixStream, ddi: UnixStream) -> io::Result<()> {
    // Read the "CONNECT <port>\n" line one byte at a time so no bytes are
    // buffered past it. A `BufReader` would read ahead and its
    // `into_inner()` silently discards anything buffered beyond the
    // line, which would corrupt the framed protocol if `vsocksrv` ever
    // writes more before this line is consumed.
    let mut byte = [0u8; 1];
    loop {
        if ch.read_exact(&mut byte).is_err() || byte[0] == b'\n' {
            break;
        }
    }
    let mut ddi = ddi;

    let mut ch_clone = ch.try_clone()?;
    let mut ddi_clone = ddi.try_clone()?;

    // Each direction shuts down the *write* half of its destination as
    // soon as its source hits EOF. A plain `drop` would not be enough:
    // `try_clone` dups the fd, so the peer (whichever process is on the
    // other end of that dup'd socket) only sees EOF once every dup is
    // closed. `shutdown(Write)` acts on the shared socket state itself,
    // so it propagates a half-close to the peer immediately regardless
    // of how many dup'd fds are still open on this side, letting a
    // one-directional disconnect end the whole bridged connection.
    let to_ddi = thread::spawn(move || {
        let _ = io::copy(&mut ch_clone, &mut ddi_clone);
        let _ = ddi_clone.shutdown(std::net::Shutdown::Write);
    });
    let to_ch = thread::spawn(move || {
        let _ = io::copy(&mut ddi, &mut ch);
        let _ = ch.shutdown(std::net::Shutdown::Write);
    });

    let _ = to_ddi.join();
    let _ = to_ch.join();
    Ok(())
}

/// Spawns a background thread that accepts exactly one `vsocksrv`
/// connection on `paths.ch` and one client connection on `paths.ddi`,
/// then bridges them together.
fn spawn_bridge(paths: &mut SocketPaths) -> io::Result<thread::JoinHandle<()>> {
    spawn_bridge_loop(paths, 1)
}

/// Like [`spawn_bridge`], but accepts and bridges up to `iterations`
/// sequential `vsocksrv` reconnections. `vsocksrv --socket-type unix`
/// reconnects to `paths.ch` (and, through the bridge, `paths.ddi` gets a
/// fresh client connection too) after every disconnect, so tests that
/// exercise reconnect-after-disconnect behavior need more than one
/// accepted pair.
///
/// Takes `paths` by `&mut` so each path is only marked test-owned (and
/// therefore only removed on teardown) once its `bind` has succeeded.
fn spawn_bridge_loop(
    paths: &mut SocketPaths,
    iterations: usize,
) -> io::Result<thread::JoinHandle<()>> {
    let ch_listener = UnixListener::bind(&paths.ch)?;
    paths.ch_owned = true;
    let ddi_listener = UnixListener::bind(&paths.ddi)?;
    paths.ddi_owned = true;
    Ok(thread::spawn(move || {
        for _ in 0..iterations {
            let Ok((ch, _)) = ch_listener.accept() else {
                return;
            };
            let Ok((ddi, _)) = ddi_listener.accept() else {
                return;
            };
            let _ = bridge_connection(ch, ddi);
        }
    }))
}

/// Locates the `vsocksrv` binary built alongside this test.
///
/// `vsocksrv` has no library target, so Cargo cannot wire it up as a
/// normal dev-dependency (it would just be ignored, and
/// `CARGO_BIN_EXE_vsocksrv` is never set). Instead this resolves the
/// path the same way Cargo lays out the workspace target directory:
/// `<target-dir>/<profile>/vsocksrv`. CI builds `vsocksrv` explicitly
/// before running this test (see `.github/workflows/rust.yml`); set
/// `VSOCKSRV_BIN` to override the path directly (e.g. for local runs
/// with a non-default target directory).
fn locate_vsocksrv_bin() -> PathBuf {
    if let Ok(path) = std::env::var("VSOCKSRV_BIN") {
        return PathBuf::from(path);
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("ddi/sock is two levels below the workspace root")
        .to_path_buf();
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("target"));
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let bin = target_dir.join(profile).join("vsocksrv");
    assert!(
        bin.exists(),
        "vsocksrv binary not found at {bin:?}; build it first with \
         `cargo build -p vsocksrv` (or set VSOCKSRV_BIN)"
    );
    bin
}

/// Starts `vsocksrv` in `--socket-type unix` mode, dialing out to
/// `paths.ch`. `vsocksrv` retries the connection until the listener
/// exists, so start order relative to [`spawn_bridge`] does not matter.
fn spawn_vsocksrv(paths: &SocketPaths) -> io::Result<VsocksrvGuard> {
    let child = Command::new(locate_vsocksrv_bin())
        .args([
            "--socket-type",
            "unix",
            "--unix-socket",
            paths.ch.to_str().expect("temp path is valid UTF-8"),
            "--port",
            "5000",
            "--partition-id",
            "3",
        ])
        .env("RUST_LOG", "vsocksrv=warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(VsocksrvGuard(child))
}

/// Issues a `GetApiRev` request over `dev` and asserts it succeeds against
/// `vsocksrv`'s in-process `StdHsm`.
fn assert_get_api_rev_succeeds(dev: &azihsm_ddi_sock::DdiSockDev) {
    let req = DdiGetApiRevCmdReq {
        hdr: DdiReqHdr {
            rev: None,
            op: DdiOp::GetApiRev,
            sess_id: None,
        },
        data: DdiGetApiRevReq {},
        ext: None,
    };

    let mut cookie = None;
    let resp = dev
        .exec_op_mbor(&req, &mut cookie)
        .expect("GetApiRev should succeed against vsocksrv's StdHsm");

    assert_eq!(resp.hdr.op, DdiOp::GetApiRev);
    assert_eq!(
        resp.data.min,
        DdiApiRev { major: 1, minor: 0 },
        "StdHsm should report min api rev 1.0",
    );
    assert_eq!(
        resp.data.max,
        DdiApiRev { major: 1, minor: 1 },
        "StdHsm should report max api rev 1.1",
    );
}

/// Retries `open_dev` until it succeeds or `timeout` elapses. A fresh
/// connection through the bridge only becomes acceptable once `vsocksrv`
/// has fully processed the previous connection's end (including, after
/// this reconnection, resetting the partition), so callers that connect
/// again after disconnecting need to poll rather than connect once.
fn open_dev_with_retry(
    ddi: &DdiSock,
    paths: &SocketPaths,
    timeout: Duration,
) -> azihsm_ddi_sock::DdiSockDev {
    let deadline = Instant::now() + timeout;
    loop {
        match ddi.open_dev(paths.ddi.to_str().expect("temp path is valid UTF-8")) {
            Ok(dev) => return dev,
            Err(error) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50));
                let _ = error;
            }
            Err(error) => panic!("failed to reconnect to vsocksrv via the bridge: {error}"),
        }
    }
}

#[test]
fn get_api_rev_round_trips_through_vsocksrv() {
    let mut paths = SocketPaths::new("get-api-rev");
    // `spawn_bridge` binds both listeners synchronously before spawning
    // its worker thread, so the socket at `paths.ddi` is already
    // connectable once this call returns — a connection is queued in the
    // kernel backlog until the bridge's single `accept()` picks it up
    // after `vsocksrv` connects. Probing the socket here first would
    // consume that one-shot `accept()` and hang the real client.
    let _bridge = spawn_bridge(&mut paths).expect("failed to start test bridge");
    let _vsocksrv = spawn_vsocksrv(&paths).expect("failed to start vsocksrv");

    let ddi = DdiSock::default();
    let dev = ddi
        .open_dev(paths.ddi.to_str().expect("temp path is valid UTF-8"))
        .expect("failed to connect to vsocksrv via the bridge");

    assert_get_api_rev_succeeds(&dev);
}

/// Regression test for the shared-partition reset invariant: `vsocksrv`
/// must reset the partition and keep serving new connections after a
/// client cleanly disconnects, not just leave the partition in whatever
/// state the previous client left it in.
#[test]
fn reconnect_after_disconnect_still_serves_requests() {
    let mut paths = SocketPaths::new("reconnect-after-disconnect");
    let _bridge = spawn_bridge_loop(&mut paths, 2).expect("failed to start test bridge");
    let _vsocksrv = spawn_vsocksrv(&paths).expect("failed to start vsocksrv");

    let ddi = DdiSock::default();

    {
        let dev = ddi
            .open_dev(paths.ddi.to_str().expect("temp path is valid UTF-8"))
            .expect("failed to connect to vsocksrv via the bridge");
        assert_get_api_rev_succeeds(&dev);
        // Dropping `dev` closes the connection, which should make
        // `vsocksrv` reset the partition and reconnect to `paths.ch` so
        // the bridge can accept the next client.
    }

    let dev2 = open_dev_with_retry(&ddi, &paths, Duration::from_secs(10));
    assert_get_api_rev_succeeds(&dev2);
}

/// Regression test for `reset_partition`'s reset cycle: it must remain
/// fully usable across many repeated connect/disconnect cycles, not just
/// a single one. This guards against, e.g., accidentally reverting to a
/// session-preserving reset (`part_disable`/`part_enable`, which mirrors
/// real hardware NSSR semantics and marks sessions `NeedsRenegotiation`
/// instead of freeing their slots) or any other regression that leaks a
/// partition-scoped resource per connection until the partition itself
/// becomes unusable.
///
/// Note: `GetApiRev` never opens a session, so this alone does not drive
/// the partition's fixed-size session table toward exhaustion (the
/// concrete failure mode reported against a session-preserving reset,
/// observed after 8 accumulated sessions) - doing so would require
/// driving a stateful HSM operation (e.g. session open/close) through the
/// wire protocol. This test instead exercises the reset cycle itself well
/// past that threshold and asserts the partition keeps serving requests.
#[test]
fn many_reconnects_do_not_exhaust_partition() {
    const RECONNECTS: usize = 16;
    let mut paths = SocketPaths::new("many-reconnects");
    let _bridge = spawn_bridge_loop(&mut paths, RECONNECTS).expect("failed to start test bridge");
    let _vsocksrv = spawn_vsocksrv(&paths).expect("failed to start vsocksrv");

    let ddi = DdiSock::default();
    for i in 0..RECONNECTS {
        let dev = if i == 0 {
            ddi.open_dev(paths.ddi.to_str().expect("temp path is valid UTF-8"))
                .expect("failed to connect to vsocksrv via the bridge")
        } else {
            open_dev_with_retry(&ddi, &paths, Duration::from_secs(10))
        };
        assert_get_api_rev_succeeds(&dev);
        // Dropping `dev` here disconnects, triggering `vsocksrv`'s
        // partition reset before the next iteration reconnects.
    }
}

/// Regression test: a malformed (but fully-framed, non-EOF) request must
/// not leave `vsocksrv` stuck. This exercises the code path that
/// previously *skipped* the shared-partition reset performed for every
/// other kind of connection end (only I/O-level disconnects — EOF,
/// connection reset, timeout — reset the partition; a protocol decode
/// error returned from `serve_connection` without resetting it or
/// necessarily leaving the process able to serve the next client).
///
/// Note: this test only observes externally-visible recovery (the server
/// keeps accepting and serving connections). It does not directly assert
/// that partition/session state was cleared, since doing so would
/// require driving a stateful HSM operation (e.g. session open/close)
/// through the wire protocol.
#[test]
fn malformed_frame_recovers_and_serves_next_connection() {
    let mut paths = SocketPaths::new("malformed-frame");
    let _bridge = spawn_bridge_loop(&mut paths, 2).expect("failed to start test bridge");
    let _vsocksrv = spawn_vsocksrv(&paths).expect("failed to start vsocksrv");

    {
        let mut raw = UnixStream::connect(&paths.ddi).expect("failed to connect for raw frame");
        // A length-prefixed 8-byte body of zeros is a well-formed frame
        // header (right size, so no EOF/short-read) with an invalid
        // magic number, so `Request::read_from` returns
        // `ProtoError::BadMagic`, not an I/O error.
        let body = [0u8; 8];
        raw.write_all(&(body.len() as u32).to_le_bytes())
            .expect("failed to write frame length");
        raw.write_all(&body).expect("failed to write frame body");
        raw.flush().expect("failed to flush malformed frame");
        // Drop `raw` to close the connection once the malformed frame is
        // sent; `vsocksrv` should already have failed to decode it.
    }

    let ddi = DdiSock::default();
    let dev = open_dev_with_retry(&ddi, &paths, Duration::from_secs(10));
    assert_get_api_rev_succeeds(&dev);
}
