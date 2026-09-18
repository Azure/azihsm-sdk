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

#![cfg(unix)]

use std::io;
use std::io::Read;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::thread;
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
        }
    }
}

impl Drop for SocketPaths {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.ch);
        let _ = std::fs::remove_file(&self.ddi);
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

    let to_ddi = thread::spawn(move || io::copy(&mut ch_clone, &mut ddi_clone));
    let to_ch = thread::spawn(move || io::copy(&mut ddi, &mut ch));

    let _ = to_ddi.join();
    let _ = to_ch.join();
    Ok(())
}

/// Spawns a background thread that accepts exactly one `vsocksrv`
/// connection on `paths.ch` and one client connection on `paths.ddi`,
/// then bridges them together.
fn spawn_bridge(paths: &SocketPaths) -> io::Result<thread::JoinHandle<()>> {
    let ch_listener = UnixListener::bind(&paths.ch)?;
    let ddi_listener = UnixListener::bind(&paths.ddi)?;
    Ok(thread::spawn(move || {
        let Ok((ch, _)) = ch_listener.accept() else {
            return;
        };
        let Ok((ddi, _)) = ddi_listener.accept() else {
            return;
        };
        let _ = bridge_connection(ch, ddi);
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

#[test]
fn get_api_rev_round_trips_through_vsocksrv() {
    let paths = SocketPaths::new("get-api-rev");
    // `spawn_bridge` binds both listeners synchronously before spawning
    // its worker thread, so the socket at `paths.ddi` is already
    // connectable once this call returns — a connection is queued in the
    // kernel backlog until the bridge's single `accept()` picks it up
    // after `vsocksrv` connects. Probing the socket here first would
    // consume that one-shot `accept()` and hang the real client.
    let _bridge = spawn_bridge(&paths).expect("failed to start test bridge");
    let _vsocksrv = spawn_vsocksrv(&paths).expect("failed to start vsocksrv");

    let ddi = DdiSock::default();
    let dev = ddi
        .open_dev(paths.ddi.to_str().expect("temp path is valid UTF-8"))
        .expect("failed to connect to vsocksrv via the bridge");

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
        DdiApiRev { major: 1, minor: 0 },
        "StdHsm should report max api rev 1.0",
    );
}
