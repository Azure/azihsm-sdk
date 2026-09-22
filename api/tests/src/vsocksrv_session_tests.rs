// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Regression test: `vsocksrv` must fully reset a partition's session
//! table on every disconnect, even when the client vanishes mid-session
//! without gracefully closing it (e.g. a crash), not just when it closes
//! cleanly.
//!
//! `ddi/sock/tests/vsocksrv_integration.rs` already covers the reset
//! cycle itself across many reconnects, but only ever issues
//! `GetApiRev`, which never opens a session and so cannot catch a
//! regression to a session-preserving reset (one that frees the
//! connection but not session-table slots). This test drives real
//! `OpenSession` traffic (via `azihsm_api`'s high-level partition/session
//! APIs) across many abrupt reconnects instead, so it would fail well
//! before the fixed-size session table (`MAX_SESSIONS = 8` in
//! `fw/plat/std/pal/src/drivers/session.rs`) is exhausted.
//!
//! Each reconnect forcibly severs the OS-level socket out from under a
//! still-open `HsmSession`/`HsmPartition` (instead of dropping them
//! normally, which would send a graceful `CloseSession` first) to
//! faithfully simulate a vanished client, then waits for `vsocksrv` to
//! finish resetting before the next iteration reconnects.
//!
//! Only compiled/run with `--features sock`; nothing else in this
//! crate's test suite talks to a real `vsocksrv` process.

#![cfg(target_os = "linux")]

use std::io;
use std::io::Read;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use azihsm_api::*;
use parking_lot::Mutex;

use crate::utils::partition::APP_ID;
use crate::utils::partition::APP_PIN;
use crate::utils::partition::TEST_OBK;
use crate::utils::partition::generate_pota_endorsement;
use crate::utils::partition::test_api_rev;

/// Number of reconnects to drive, comfortably past `MAX_SESSIONS` (8) so
/// a session-preserving reset would exhaust the partition's session
/// table well before this test completes.
const RECONNECTS: usize = 16;

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

/// The environment variable `azihsm_ddi_sock::DdiSock` reads to resolve
/// the socket path it reports via `dev_info_list()` (and therefore the
/// only path `HsmPartitionManager::open_partition` will accept).
const AZIHSM_DDI_SOCK: &str = "AZIHSM_DDI_SOCK";

/// Sets `AZIHSM_DDI_SOCK` to `path`.
///
/// # Safety
///
/// `set_var` is only safe to call while no other thread might be
/// reading or writing the process environment concurrently. This test
/// is the only one in this crate that reads or writes `AZIHSM_DDI_SOCK`,
/// and it calls this before spawning any thread that reads it.
#[allow(unsafe_code)]
fn set_ddi_sock_env(path: &Path) {
    // SAFETY: see function doc comment above.
    unsafe { std::env::set_var(AZIHSM_DDI_SOCK, path) };
}

/// Picks the socket path the bridge's `ddi` listener must bind at so
/// `open_partition`'s internal `dev_info_by_path` lookup (which matches
/// against `dev_info_list()`'s reported path, not whatever path the
/// caller passes in) succeeds.
///
/// If `AZIHSM_DDI_SOCK` is already set, the caller has explicitly opted
/// into a specific path, so it is used as-is and must not already exist
/// (this test never probes or removes another process's live socket).
/// Otherwise, a unique per-test path is generated and exported via
/// `AZIHSM_DDI_SOCK` so this test always gets a test-owned endpoint
/// instead of colliding with `azihsm_ddi_sock::DEFAULT_SOCK_PATH`, which
/// a real `vsocksrv`/service could be using.
fn test_owned_ddi_sock_path(unique: &str) -> PathBuf {
    match std::env::var(AZIHSM_DDI_SOCK) {
        Ok(path) if !path.is_empty() => {
            let path = PathBuf::from(path);
            assert!(
                !path.exists(),
                "refusing to use {}: a file already exists there and this test never \
                 probes or removes another process's socket; set AZIHSM_DDI_SOCK to an \
                 unused path or unset it before running this test",
                path.display()
            );
            path
        }
        _ => {
            let path = std::env::temp_dir().join(format!("azihsm-ddi-sock-test-{unique}.sock"));
            set_ddi_sock_env(&path);
            path
        }
    }
}

impl SocketPaths {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir();
        let unique = format!(
            "{tag}-{}-{:?}",
            std::process::id(),
            Instant::now().elapsed()
        );
        let ddi = test_owned_ddi_sock_path(&unique);
        Self {
            ch: dir.join(format!("azihsm-api-sock-test-ch-{unique}.sock")),
            ddi,
        }
    }
}

impl Drop for SocketPaths {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.ch);
        let _ = std::fs::remove_file(&self.ddi);
    }
}

/// Clones of the currently-bridged connection's two sockets, kept
/// around so the test can forcibly sever them without waiting for the
/// `HsmSession`/`HsmPartition` handles that own the "real" ends to drop
/// on their own.
type CurrentConn = Arc<Mutex<Option<(UnixStream, UnixStream)>>>;

/// Reads and discards the `CONNECT <port>\n` line `vsocksrv` sends
/// first, then splices the remainder of `ch` bidirectionally with
/// `ddi`.
fn bridge_connection(mut ch: UnixStream, ddi: UnixStream) -> io::Result<()> {
    // Read the "CONNECT <port>\n" line one byte at a time so no bytes
    // are buffered past it. A `BufReader` would read ahead and its
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
    // one-directional disconnect (or a forced `sever_current_connection`
    // shutdown from the main test thread) end the whole bridged
    // connection.
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

/// Accepts and bridges up to `iterations` sequential `vsocksrv`
/// reconnections on a background thread. Returns the join handle
/// alongside a [`CurrentConn`] slot that always holds clones of the
/// most recently accepted connection's sockets, so the caller can sever
/// it on demand via [`sever_current_connection`].
fn spawn_bridge_loop(
    paths: &SocketPaths,
    iterations: usize,
) -> io::Result<(thread::JoinHandle<()>, CurrentConn)> {
    let ch_listener = UnixListener::bind(&paths.ch)?;
    let ddi_listener = UnixListener::bind(&paths.ddi)?;
    let current: CurrentConn = Arc::new(Mutex::new(None));
    let current_for_thread = Arc::clone(&current);
    let handle = thread::spawn(move || {
        for _ in 0..iterations {
            let Ok((ch, _)) = ch_listener.accept() else {
                return;
            };
            let Ok((ddi, _)) = ddi_listener.accept() else {
                return;
            };
            let Ok(ch_clone) = ch.try_clone() else {
                return;
            };
            let Ok(ddi_clone) = ddi.try_clone() else {
                return;
            };
            *current_for_thread.lock() = Some((ch_clone, ddi_clone));
            let _ = bridge_connection(ch, ddi);
        }
    });
    Ok((handle, current))
}

/// Forcibly closes both ends of the currently-bridged connection at the
/// OS level, without going through `HsmSession`/`HsmPartition`'s normal
/// drop path. This simulates a client vanishing mid-session (e.g. a
/// crash) rather than one that closes its session gracefully: any later
/// `Drop`-triggered `CloseSession` attempt on the now-severed socket
/// simply fails and is silently swallowed by `HsmSession`'s drop
/// handler, exactly as it would after a real crash.
fn sever_current_connection(current: &CurrentConn) {
    let pair = current.lock().take();
    if let Some((ch, ddi)) = pair {
        let _ = ch.shutdown(std::net::Shutdown::Both);
        let _ = ddi.shutdown(std::net::Shutdown::Both);
    }
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
        .expect("api/tests is two levels below the workspace root")
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
/// exists, so start order relative to [`spawn_bridge_loop`] does not
/// matter.
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

/// Retries [`HsmPartitionManager::open_partition`] until it succeeds or
/// `timeout` elapses. A fresh connection through the bridge only
/// becomes acceptable once `vsocksrv` has fully processed the previous
/// connection's end (including resetting the partition), so reconnects
/// need to poll rather than connect once.
fn open_partition_with_retry(path: &str, api_rev: HsmApiRev, timeout: Duration) -> HsmPartition {
    let deadline = Instant::now() + timeout;
    loop {
        match HsmPartitionManager::open_partition(path, api_rev) {
            Ok(part) => return part,
            Err(error) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50));
                let _ = error;
            }
            Err(error) => panic!("failed to reconnect to vsocksrv via the bridge: {error}"),
        }
    }
}

/// Regression test for the shared-partition reset invariant when a
/// session is left open: `vsocksrv` must free the session-table slot
/// (not just the connection) on every disconnect, even when the client
/// never sends `CloseSession`. This guards against, e.g., a
/// session-preserving reset (`part_disable`/`part_enable`, which mirrors
/// real hardware NSSR semantics and marks sessions `NeedsRenegotiation`
/// instead of freeing their slots) - a regression that would only
/// manifest once real sessions are opened and abandoned, not with
/// `GetApiRev`-only traffic.
///
/// Every reconnect performs a full, fresh partition init: `vsocksrv`'s
/// per-connection reset (`part_free`) zeroizes the identity key,
/// established credentials, and masked owner backup key, so no
/// credential state from a prior iteration is reusable.
#[test]
fn many_reconnects_with_open_sessions_do_not_exhaust_partition() {
    let paths = SocketPaths::new("many-reconnects-sessions");
    let (_bridge, current_conn) =
        spawn_bridge_loop(&paths, RECONNECTS).expect("failed to start test bridge");
    let _vsocksrv = spawn_vsocksrv(&paths).expect("failed to start vsocksrv");

    let ddi_path = paths.ddi.to_str().expect("temp path is valid UTF-8");
    let api_rev = test_api_rev();

    for i in 0..RECONNECTS {
        let part = if i == 0 {
            HsmPartitionManager::open_partition(ddi_path, api_rev)
                .expect("failed to open partition via the bridge")
        } else {
            open_partition_with_retry(ddi_path, api_rev, Duration::from_secs(10))
        };

        // Establish credentials from scratch every time (no MOBK
        // caching): `vsocksrv`'s reset wipes credential/BK state on
        // every disconnect, so each reconnect is a truly fresh device.
        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
        let (sig, pubkey) = generate_pota_endorsement(&part);
        let obk_config = HsmOwnerBackupKeyConfig::new(
            HsmOwnerBackupKeySource::Caller,
            HsmOwnerBackupKey::from_obk(&TEST_OBK),
        );
        let pota_endorsement = HsmPotaEndorsement::new(
            HsmPotaEndorsementSource::Caller,
            Some(HsmPotaEndorsementData::new(&sig, &pubkey)),
        );
        part.init(creds, None, None, obk_config, pota_endorsement, None)
            .unwrap_or_else(|error| panic!("partition init failed on reconnect {i}: {error}"));

        let session = part
            .open_session(api_rev, &creds, None)
            .unwrap_or_else(|error| panic!("failed to open session on reconnect {i}: {error}"));

        // Sever the OS-level connection before `session`/`part` drop,
        // so their graceful close attempts race against (and always
        // lose to) an already-dead socket - faithfully simulating a
        // client that vanished mid-session rather than one that closed
        // cleanly.
        sever_current_connection(&current_conn);

        drop(session);
        drop(part);
    }
}
