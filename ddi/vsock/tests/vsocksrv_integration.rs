// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end test: [`azihsm_ddi_vsock::DdiVsock`] against a real
//! `vsocksrv` process over a genuine `AF_VSOCK` loopback connection.
//!
//! Unlike [`azihsm_ddi_sock`]'s equivalent test, which bridges
//! `vsocksrv --socket-type unix`'s `AF_UNIX` connection into a plain
//! `UnixListener`, this test connects a real `AF_VSOCK` client socket to
//! `DdiVsockDev`'s own listener (bound by `Ddi::open_dev` on
//! `VMADDR_CID_ANY`), with `vsocksrv`'s `AF_UNIX` side bridged onto that
//! real `AF_VSOCK` stream. That exercises the exact bind/accept/transport
//! code path `DdiVsockDev` uses in production (including
//! `DdiVsockDev::erase`'s connection-replacement logic, which the
//! stale-session-close fix in `src/dev.rs`'s `SessionGenerationTracker`
//! depends on), not a bridged-to-`AF_UNIX` stand-in.
//!
//! `AF_VSOCK` loopback (connecting to `VMADDR_CID_LOCAL` from the same
//! host) requires the `vsock_loopback` kernel module. That module isn't
//! guaranteed to be loaded (and, per community reports, isn't loadable at
//! all on standard GitHub-hosted `ubuntu-latest` runners), so every test
//! here probes loopback availability first and skips (passes trivially,
//! printing a clear message) rather than failing or hanging when it's
//! unavailable. Run `sudo modprobe vsock_loopback` first to exercise
//! these tests for real, e.g. on a self-hosted runner or local dev box.

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
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;
use std::time::Instant;

#[cfg(feature = "real-session-tests")]
use azihsm_cred_encrypt::DeviceCredKey;
#[cfg(feature = "real-session-tests")]
use azihsm_crypto::DerEccPublicKey;
#[cfg(feature = "real-session-tests")]
use azihsm_crypto::EccPrivateKey;
#[cfg(feature = "real-session-tests")]
use azihsm_crypto::EcdsaAlgo;
#[cfg(feature = "real-session-tests")]
use azihsm_crypto::HashAlgo;
#[cfg(feature = "real-session-tests")]
use azihsm_crypto::ImportableKey;
#[cfg(feature = "real-session-tests")]
use azihsm_crypto::Signer;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
#[cfg(feature = "real-session-tests")]
use azihsm_ddi_mbor_codec::MborByteArray;
#[cfg(feature = "real-session-tests")]
use azihsm_ddi_mbor_test_helpers::helper_establish_credential;
#[cfg(feature = "real-session-tests")]
use azihsm_ddi_mbor_test_helpers::helper_get_cert_chain_info;
#[cfg(feature = "real-session-tests")]
use azihsm_ddi_mbor_test_helpers::helper_get_certificate;
#[cfg(feature = "real-session-tests")]
use azihsm_ddi_mbor_test_helpers::helper_get_establish_cred_encryption_key;
#[cfg(feature = "real-session-tests")]
use azihsm_ddi_mbor_test_helpers::helper_get_or_init_bk3;
#[cfg(feature = "real-session-tests")]
use azihsm_ddi_mbor_test_helpers::helper_get_session_encryption_key;
use azihsm_ddi_mbor_types::DdiApiRev;
use azihsm_ddi_mbor_types::DdiCloseSessionCmdReq;
use azihsm_ddi_mbor_types::DdiCloseSessionReq;
#[cfg(feature = "real-session-tests")]
use azihsm_ddi_mbor_types::DdiDerPublicKey;
use azihsm_ddi_mbor_types::DdiGetApiRevCmdReq;
use azihsm_ddi_mbor_types::DdiGetApiRevReq;
#[cfg(feature = "real-session-tests")]
use azihsm_ddi_mbor_types::DdiKeyType;
use azihsm_ddi_mbor_types::DdiOp;
#[cfg(feature = "real-session-tests")]
use azihsm_ddi_mbor_types::DdiOpenSessionCmdReq;
#[cfg(feature = "real-session-tests")]
use azihsm_ddi_mbor_types::DdiOpenSessionReq;
use azihsm_ddi_mbor_types::DdiReqHdr;
use azihsm_ddi_mbor_types::DdiStatus;
use azihsm_ddi_vsock::DdiVsock;
use nix::sys::socket::connect;
use nix::sys::socket::socket;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::MsgFlags;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockType;
use nix::sys::socket::VsockAddr;
use nix::unistd::close;
#[cfg(feature = "real-session-tests")]
use x509::X509Certificate;
#[cfg(feature = "real-session-tests")]
use x509::X509CertificateOp;

/// Kills the `vsocksrv` child process when dropped, so a failing
/// assertion never leaks a background server.
struct VsocksrvGuard(Child);

impl Drop for VsocksrvGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A raw `AF_VSOCK` client connection, wrapping the file descriptor so
/// `Read`/`Write` can drive the framed SQE/CQE protocol directly (mirrors
/// `DdiVsockDev`'s own `VsockStream` in `src/dev.rs`, which isn't public).
struct RawVsockStream(std::os::fd::RawFd);

impl Read for RawVsockStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        nix::unistd::read(self.0, buffer).map_err(nix_to_io)
    }
}

impl Write for RawVsockStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        nix::sys::socket::send(self.0, buffer, MsgFlags::MSG_NOSIGNAL).map_err(nix_to_io)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for RawVsockStream {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

fn nix_to_io(error: nix::Error) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

/// Connects to `VMADDR_CID_LOCAL:port`, returning `None` if `AF_VSOCK`
/// loopback itself is unavailable (`ENETUNREACH`/`ENODEV`, i.e. the
/// `vsock_loopback` kernel module isn't loaded) rather than failing the
/// test. Any other connect error (e.g. `ECONNRESET` because nothing is
/// listening *yet*) is returned as `Err` so callers can retry.
fn try_connect_vsock_loopback(port: u32) -> io::Result<Option<RawVsockStream>> {
    let fd = match socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    ) {
        Ok(fd) => fd,
        Err(nix::Error::EAFNOSUPPORT | nix::Error::EPROTONOSUPPORT | nix::Error::ENODEV) => {
            return Ok(None);
        }
        Err(error) => return Err(nix_to_io(error)),
    };
    match connect(fd, &VsockAddr::new(libc::VMADDR_CID_LOCAL, port)) {
        Ok(()) => Ok(Some(RawVsockStream(fd))),
        Err(nix::Error::ENETUNREACH | nix::Error::ENODEV) => {
            let _ = close(fd);
            Ok(None)
        }
        Err(error) => {
            let _ = close(fd);
            Err(nix_to_io(error))
        }
    }
}

/// Connects to `VMADDR_CID_LOCAL:port`, retrying transient failures
/// (e.g. `DdiVsockDev`'s listener not bound yet) until `deadline`.
/// Returns `Ok(None)` as soon as [`try_connect_vsock_loopback`] reports
/// loopback is unavailable at all, since retrying would not help.
fn connect_vsock_loopback_with_retry(
    port: u32,
    deadline: Instant,
) -> io::Result<Option<RawVsockStream>> {
    loop {
        match try_connect_vsock_loopback(port) {
            Ok(Some(stream)) => return Ok(Some(stream)),
            Ok(None) => return Ok(None),
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Err(error) => return Err(error),
        }
    }
}

/// Unique-per-test socket path / port under the OS temp directory.
struct TestEndpoints {
    /// AF_UNIX path `vsocksrv` connects out to (stands in for Cloud
    /// Hypervisor's real virtio-vsock passthrough socket).
    ch: PathBuf,
    /// AF_VSOCK port `DdiVsock::open_dev` binds and accepts on.
    vsock_port: u32,
    /// Whether this test actually bound (and therefore created) `ch`.
    ch_owned: bool,
}

/// Monotonic in-process counter disambiguating tests sharing a process
/// id: both the unique socket-path suffix and the per-process vsock port
/// range (`PORTS_PER_PROCESS`, below) are offset by this, since
/// `cargo test` (unlike `cargo nextest`, this repo's preferred runner)
/// can run multiple tests from this binary in one process.
static NEXT_PORT_OFFSET: AtomicU32 = AtomicU32::new(0);

impl TestEndpoints {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir();
        // Guarantee uniqueness *across concurrently running processes*,
        // not just probabilistically reduce collisions: map the full,
        // untruncated process id into the port space (process ids are
        // unique among processes alive at the same time on a host, so
        // two test binaries racing each other can never derive the same
        // base), then add a small monotonic in-process counter on top to
        // disambiguate multiple tests sharing one PID. The previous
        // `pid % 1000` reduction threw away exactly the uniqueness
        // guarantee a raw pid provides — e.g. PIDs 1234 and 2234
        // collided on the same port — which could make
        // `VsockListener::bind` fail with `EADDRINUSE` for one of two
        // concurrently running test processes, or (if a listener from an
        // unrelated, already-exited process' port happened to still be
        // bound) cross-accept a connection meant for a different test.
        //
        // `BASE_VSOCK_PORT + pid * PORTS_PER_PROCESS` cannot overflow or
        // wrap into another process's range for any realistic pid (Linux
        // caps pids well under 2^31 by default), and reserves
        // `PORTS_PER_PROCESS` ports per pid for `NEXT_PORT_OFFSET` to
        // hand out.
        const BASE_VSOCK_PORT: u32 = 10_000_000;
        const PORTS_PER_PROCESS: u32 = 100;
        let offset = NEXT_PORT_OFFSET.fetch_add(1, Ordering::Relaxed) % PORTS_PER_PROCESS;
        let unique = format!("{tag}-{}-{offset}", std::process::id());
        let vsock_port = BASE_VSOCK_PORT + std::process::id() * PORTS_PER_PROCESS + offset;
        Self {
            ch: dir.join(format!("azihsm-ddi-vsock-test-ch-{unique}.sock")),
            vsock_port,
            ch_owned: false,
        }
    }
}

impl Drop for TestEndpoints {
    /// Only removes the socket file this test actually created (i.e. one
    /// whose `UnixListener::bind` succeeded), so a stale socket or
    /// another process's endpoint that happened to collide with this
    /// PID/tag-based name is never unlinked here.
    fn drop(&mut self) {
        if self.ch_owned {
            let _ = std::fs::remove_file(&self.ch);
        }
    }
}

/// Reads the `CONNECT <port>\n` line `vsocksrv` sends first, replies with
/// the `OK <port>\n` acknowledgement `vsocksrv` now always expects (see
/// `tools/vsocksrv/src/unix.rs::read_connect_ack`), then splices the
/// remainder of `ch` bidirectionally with the real AF_VSOCK stream `ddi`.
fn bridge_connection(mut ch: UnixStream, ddi: RawVsockStream) -> io::Result<()> {
    // Read the "CONNECT <port>\n" line one byte at a time so no bytes are
    // buffered past it (see the sock-transport test's identical comment
    // for why a `BufReader` would be unsafe here).
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if ch.read_exact(&mut byte).is_err() || byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&line);
    let port = text.strip_prefix("CONNECT ").unwrap_or("0");
    writeln!(ch, "OK {port}")?;
    ch.flush()?;

    // `RawVsockStream` isn't `Clone`-able (it's a bare fd), so splice via
    // a `dup`'d fd instead, one per direction's thread.
    let ddi_fd = ddi.0;
    let ddi_dup = nix::unistd::dup(ddi_fd).map_err(nix_to_io)?;
    // Both halves now independently own (and will close) an fd referring
    // to the same underlying socket; forget the original wrapper so its
    // `Drop` doesn't additionally close `ddi_fd` out from under them.
    std::mem::forget(ddi);
    let mut ddi_reader = RawVsockStream(ddi_fd);
    let mut ddi_writer = RawVsockStream(ddi_dup);
    let mut ch_clone = ch.try_clone()?;

    let to_ddi = thread::spawn(move || {
        let _ = io::copy(&mut ch_clone, &mut ddi_writer);
        let _ = nix::sys::socket::shutdown(ddi_writer.0, nix::sys::socket::Shutdown::Write);
    });
    let to_ch = thread::spawn(move || {
        let _ = io::copy(&mut ddi_reader, &mut ch);
        let _ = ch.shutdown(std::net::Shutdown::Write);
    });

    let _ = to_ddi.join();
    let _ = to_ch.join();
    Ok(())
}

/// Spawns a background thread that repeatedly accepts `vsocksrv`
/// connections on `endpoints.ch`, connects a real `AF_VSOCK` client to
/// `endpoints.vsock_port` (retrying until `DdiVsock::open_dev`'s listener
/// is up, or until loopback itself proves unavailable), and bridges them
/// together, for as long as the process lives. Returns `Ok(None)` if
/// loopback is unavailable rather than spawning anything.
///
/// Looping (rather than accepting exactly once) matters because
/// `vsocksrv` reconnects automatically whenever its current connection
/// drops (see `tools/vsocksrv/src/unix.rs`'s "HSM client disconnected;
/// reconnecting"), which is exactly what happens when a test calls
/// [`DdiDev::erase`]: that tears down the bridged connection, and
/// `vsocksrv` immediately tries to re-establish a new one through this
/// same listener. If the listener only accepted once, it would already
/// be closed by then, leaving `vsocksrv` stuck retrying a connection
/// that can never succeed, and `erase()` waiting on a replacement
/// connection that this bridge can no longer forward.
///
/// Must be called (and must return `Some`) before the caller's own
/// `DdiVsock::open_dev` call, so the probe connection this performs is
/// accepted by `DdiVsockDev`'s *own* listener rather than by a leftover
/// instance from a previous test.
fn spawn_bridge(endpoints: &mut TestEndpoints) -> io::Result<Option<thread::JoinHandle<()>>> {
    // Probe loopback availability against the same port the real bridge
    // will use, before committing to spawning `vsocksrv` or a bridge
    // thread at all. Nothing is listening on `vsock_port` yet at this
    // point (the caller hasn't called `open_dev`), so a successful
    // connect here would mean this probe raced a *different* process's
    // listener — vanishingly unlikely for the process-id-derived port
    // range this test uses, and in that case the two would collide in
    // `DdiVsockDev`'s own listener registry if the test did go on to
    // call `open_dev`, surfacing as a loud failure rather than silently
    // passing.
    let deadline = Instant::now() + Duration::from_secs(1);
    match connect_vsock_loopback_with_retry(endpoints.vsock_port, deadline) {
        Ok(Some(_)) | Err(_) => {}
        Ok(None) => return Ok(None),
    }

    let ch_listener = UnixListener::bind(&endpoints.ch)?;
    endpoints.ch_owned = true;
    let vsock_port = endpoints.vsock_port;
    Ok(Some(thread::spawn(move || {
        loop {
            let Ok((ch, _)) = ch_listener.accept() else {
                // The listener itself is gone (e.g. the test process is
                // tearing down): nothing left to bridge.
                return;
            };
            let deadline = Instant::now() + Duration::from_secs(10);
            let Ok(Some(ddi)) = connect_vsock_loopback_with_retry(vsock_port, deadline) else {
                return;
            };
            // Bridge this connection to completion before accepting the
            // next one: `vsocksrv` only ever has one connection open at a
            // time, and serializing here keeps accept() ordering (and
            // therefore which AF_VSOCK connection a given reconnect
            // lands on) unambiguous.
            let _ = bridge_connection(ch, ddi);
        }
    })))
}

/// Locates the `vsocksrv` binary built alongside this test (see the
/// identical helper in `ddi/sock/tests/vsocksrv_integration.rs` for why
/// this can't just be a normal dev-dependency).
/// Returns `None` (rather than panicking) when `vsocksrv` hasn't been
/// built: unlike `ddi/sock`'s equivalent test, which only runs in a CI
/// job that explicitly builds `vsocksrv` first
/// (`test_ubuntu_sock_ddi`), this crate's tests are also swept up by the
/// generic `cargo nextest run --workspace` used by other CI jobs (e.g.
/// `test_ubuntu_mock`), which never build `vsocksrv` at all. Missing the
/// binary there is expected, not a failure.
fn locate_vsocksrv_bin() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("VSOCKSRV_BIN") {
        return Some(PathBuf::from(path));
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("ddi/vsock is two levels below the workspace root")
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
    bin.exists().then_some(bin)
}

/// Starts `vsocksrv` in `--socket-type unix` mode, dialing out to
/// `endpoints.ch`. `vsocksrv` retries the connection until the listener
/// exists, so start order relative to [`spawn_bridge`] does not matter.
/// Returns `Ok(None)` (rather than an error) when `vsocksrv` hasn't been
/// built, so callers can skip gracefully; see [`locate_vsocksrv_bin`].
fn spawn_vsocksrv(endpoints: &TestEndpoints) -> io::Result<Option<VsocksrvGuard>> {
    let Some(bin) = locate_vsocksrv_bin() else {
        return Ok(None);
    };
    let child = Command::new(bin)
        .args([
            "--socket-type",
            "unix",
            "--unix-socket",
            endpoints.ch.to_str().expect("temp path is valid UTF-8"),
            "--port",
            "5000",
            "--partition-id",
            "3",
        ])
        .env("RUST_LOG", "vsocksrv=warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(Some(VsocksrvGuard(child)))
}

/// Issues a `GetApiRev` request over `dev` and asserts it succeeds against
/// `vsocksrv`'s in-process `StdHsm`.
fn assert_get_api_rev_succeeds(dev: &azihsm_ddi_vsock::DdiVsockDev) {
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

/// Set by the dedicated CI job that's supposed to guarantee both
/// prerequisites (loopback module loaded, `vsocksrv` built) are present,
/// so a missing prerequisite there is a real CI misconfiguration rather
/// than an expected local-dev skip: `bridge_or_skip!`/`vsocksrv_or_skip!`
/// panic instead of skipping when this is set, so that job fails loudly
/// instead of silently reporting these tests as passed-but-skipped.
const VSOCK_CI_REQUIRED_ENV: &str = "AZIHSM_VSOCK_CI_REQUIRED";

/// Returns whether [`VSOCK_CI_REQUIRED_ENV`] is set to a *nonempty*
/// value. The CI job sets this conditionally via a GitHub Actions
/// expression (`cond && '1' || ''`), which — when the condition is
/// false — still *defines* the env var, just with an empty string
/// value; `var_os(...).is_some()` alone would treat that as "set",
/// wrongly turning a confirmed-unavailable `vsock_loopback` module into
/// a hard panic instead of the intended skip.
fn vsock_ci_required() -> bool {
    std::env::var_os(VSOCK_CI_REQUIRED_ENV).is_some_and(|value| !value.is_empty())
}

/// Skips the running test with a clear message if `bridge` is `None`
/// (i.e. `AF_VSOCK` loopback is unavailable in this environment) —
/// unless [`VSOCK_CI_REQUIRED_ENV`] is set, in which case it panics
/// instead, since that marks an environment that's supposed to
/// guarantee loopback is available.
macro_rules! bridge_or_skip {
    ($bridge:expr) => {
        match $bridge {
            Some(bridge) => bridge,
            None => {
                let msg = "AF_VSOCK loopback unavailable (vsock_loopback \
                     kernel module likely not loaded); run `sudo modprobe \
                     vsock_loopback` to exercise this test for real.";
                if vsock_ci_required() {
                    panic!("{msg}");
                }
                eprintln!("SKIP: {msg}");
                return;
            }
        }
    };
}

/// Skips the running test with a clear message if `vsocksrv` is `None`
/// (i.e. the binary hasn't been built in this environment); see
/// [`locate_vsocksrv_bin`]. Panics instead when [`VSOCK_CI_REQUIRED_ENV`]
/// is set — see [`bridge_or_skip`].
macro_rules! vsocksrv_or_skip {
    ($vsocksrv:expr) => {
        match $vsocksrv {
            Some(vsocksrv) => vsocksrv,
            None => {
                let msg = "vsocksrv binary not found; run `cargo build -p \
                     vsocksrv` (or set VSOCKSRV_BIN) to exercise this test \
                     for real.";
                if vsock_ci_required() {
                    panic!("{msg}");
                }
                eprintln!("SKIP: {msg}");
                return;
            }
        }
    };
}

#[test]
fn get_api_rev_round_trips_through_vsocksrv_over_real_vsock() {
    let mut endpoints = TestEndpoints::new("get-api-rev");
    // `spawn_bridge` probes loopback availability (and, if available,
    // binds `endpoints.ch`) synchronously before returning, so the
    // subsequent `open_dev` call below either has a real bridge racing
    // to connect to it, or loopback was never usable and nothing further
    // was spawned.
    let _bridge =
        bridge_or_skip!(spawn_bridge(&mut endpoints).expect("failed to probe/start test bridge"));
    let _vsocksrv =
        vsocksrv_or_skip!(spawn_vsocksrv(&endpoints).expect("failed to start vsocksrv"));

    let ddi = DdiVsock::default();
    let dev = ddi
        .open_dev(&endpoints.vsock_port.to_string())
        .expect("failed to accept the real AF_VSOCK connection via the bridge");

    assert_get_api_rev_succeeds(&dev);
}

/// Regression test for the stale-session-close fix in `src/dev.rs`
/// (`SessionGenerationTracker`), over a real `AF_VSOCK` connection:
/// after [`DdiDev::erase`] replaces the live connection, a
/// `Close`/`InSession` request for a session id the new generation never
/// opened must be rejected locally (`SessionNotFound`) without ever
/// reaching the (now-torn-down) stream — confirming the guard that
/// fixes the vulnerability runs over the real transport, not just in the
/// pure in-memory unit tests in `src/dev.rs`.
///
/// This doesn't reproduce the exact numeric-id-reuse scenario from the
/// original report (that would require driving a real credentialed
/// `OpenSession` handshake through `vsocksrv`'s `StdHsm`, which is out of
/// scope for this transport-level test — the generation/token behavior
/// for a session actually opened before the reset, including after its
/// numeric id is reused, is already exhaustively covered by the
/// in-memory `stale_session_after_reset_is_rejected_even_if_id_is_reused`
/// unit test in `src/dev.rs`), but it exercises the same
/// `SessionGenerationTracker::check` rejection path: any session id not
/// recorded under the *current* generation — whether never opened at all
/// or opened under a since-reset generation — is rejected identically.
#[test]
fn unrecognized_session_close_is_rejected_locally_after_erase_over_real_vsock() {
    let mut endpoints = TestEndpoints::new("stale-session-erase");
    let _bridge =
        bridge_or_skip!(spawn_bridge(&mut endpoints).expect("failed to probe/start test bridge"));
    let _vsocksrv =
        vsocksrv_or_skip!(spawn_vsocksrv(&endpoints).expect("failed to start vsocksrv"));

    let ddi = DdiVsock::default();
    let dev = ddi
        .open_dev(&endpoints.vsock_port.to_string())
        .expect("failed to accept the real AF_VSOCK connection via the bridge");

    assert_get_api_rev_succeeds(&dev);

    // `erase()` blocks on `DdiVsockDev`'s listener accepting a
    // *replacement* connection (see `src/dev.rs::erase`), so a raw
    // throwaway client (standing in for whatever reconnects after a real
    // reset — this test doesn't need it to speak the wire protocol at
    // all) connects concurrently to unblock it.
    let vsock_port = endpoints.vsock_port;
    let replacement_client = thread::spawn(move || {
        connect_vsock_loopback_with_retry(vsock_port, Instant::now() + Duration::from_secs(10))
    });

    dev.erase().expect("erase should succeed");
    let mut replacement = replacement_client
        .join()
        .expect("replacement-connect thread panicked")
        .expect("failed to connect the replacement client")
        .expect("AF_VSOCK loopback vanished mid-test");

    // Prove the rejection below happens locally in
    // `SessionGenerationTracker::check` — before any bytes reach the
    // replacement connection — rather than merely surfacing as *some*
    // I/O error against a peer that doesn't speak the wire protocol
    // (which would pass `is_err()` even with the guard removed, as long
    // as the stale request happened to fail for any reason once
    // forwarded). A background reader blocks on the replacement socket;
    // if the guard were bypassed and the stale close were forwarded to
    // the transport, this would observe the request's bytes arriving.
    let (reached_tx, reached_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut byte = [0u8; 1];
        let reached = matches!(replacement.read(&mut byte), Ok(n) if n > 0);
        let _ = reached_tx.send(reached);
    });

    // Use a real `CloseSession` request (not `GetApiRev`): `GetApiRev`
    // maps to `SessionControlKind::NoSession`, which `record` never acts
    // on and real firmware never pairs with a `sess_id`, so it wouldn't
    // exercise `check`'s actual `Close`/`InSession` rejection path.
    // `CloseSession` maps to `SessionControlKind::Close`, driving `check`
    // through the same branch a stale close would take in production.
    let close_req = DdiCloseSessionCmdReq {
        hdr: DdiReqHdr {
            rev: None,
            op: DdiOp::CloseSession,
            sess_id: Some(1),
        },
        data: DdiCloseSessionReq {},
        ext: None,
    };
    let mut cookie = None;
    let result = dev.exec_op_mbor(&close_req, &mut cookie);
    assert!(
        matches!(result, Err(DdiError::DdiStatus(DdiStatus::SessionNotFound))),
        "a session id unrecognized by the post-erase generation must be \
         rejected with SessionNotFound, not forwarded to the (torn-down) \
         stream: {result:?}",
    );

    // No bytes should ever have reached the replacement connection: the
    // rejection above must come from the local guard, not from sending
    // the request and getting back some unrelated failure.
    let reached = reached_rx
        .recv_timeout(Duration::from_millis(500))
        .unwrap_or(false);
    assert!(
        !reached,
        "the stale close must be rejected before reaching the transport, \
         but bytes arrived at the replacement connection",
    );
}

#[cfg(feature = "real-session-tests")]
mod real_session_tests {
    use super::*;

    // ── Real-session variant of the stale-close regression test ──
    //
    // `unrecognized_session_close_is_rejected_locally_after_erase_over_real_vsock`
    // above uses a synthetic `(sess_id: Some(1), cookie: None)` pair, which
    // only exercises `SessionGenerationTracker::check`'s *missing-cookie*
    // branch (`let Some(token) = cookie else { ... }`): any `None` cookie is
    // rejected immediately, regardless of generation. It never reaches the
    // branch this guard actually exists for — a session id *and* cookie that
    // were genuinely valid under a since-reset generation
    // (`session.token == token && session.generation != current`) — because
    // a real, firmware-issued `(sess_id, cookie)` pair is needed to populate
    // `open_sessions` in the first place.
    //
    // The test below drives a real `EstablishCredential` + `OpenSession`
    // handshake through `vsocksrv`'s in-process `StdHsm` (the same reference
    // firmware the `emu` backend uses, just reached over a socket instead of
    // in-process — see `ddi/emu/src/dev.rs`), over this same AF_VSOCK
    // connection, so `SessionGenerationTracker::record` stores the *real*
    // `(id, token)` pair under the pre-erase generation. After `erase()`
    // bumps the generation, closing that exact pair must fall through to
    // `check`'s final `_ => Err(SessionNotFound)` arm — the generation
    // mismatch itself, not the shortcut for an absent cookie.
    //
    // These are the same fixed test credential/key constants and crypto
    // helper patterns used by `ddi/mbor/types/tests/integration/common.rs`
    // (and duplicated similarly across other DDI test crates): the
    // credential-establishment flow needs its own local copies here since
    // `common.rs`'s versions are private to that crate's own test binary.

    // 70FCF730-B876-4238-B835-8010CE8A3F76
    const TEST_CRED_ID: [u8; 16] = [
        0x70, 0xFC, 0xF7, 0x30, 0xB8, 0x76, 0x42, 0x38, 0xB8, 0x35, 0x80, 0x10, 0xCE, 0x8A, 0x3F,
        0x76,
    ];

    // DB3DC77F-C22E-4300-80D4-1B31B6F04800
    const TEST_CRED_PIN: [u8; 16] = [
        0xDB, 0x3D, 0xC7, 0x7F, 0xC2, 0x2E, 0x43, 0x00, 0x80, 0xD4, 0x1B, 0x31, 0xB6, 0xF0, 0x48,
        0x00,
    ];

    const TEST_SESSION_SEED: [u8; 48] = [
        0xe5, 0x1b, 0x8b, 0x4b, 0xa7, 0x94, 0xc7, 0xc8, 0xa2, 0x32, 0x84, 0xec, 0xad, 0x2b, 0x6a,
        0xc, 0x37, 0xe8, 0x6a, 0x63, 0x6a, 0x9f, 0x43, 0x20, 0x95, 0xe1, 0x24, 0xd0, 0x85, 0x12,
        0xe2, 0x12, 0x95, 0x14, 0xaa, 0x0f, 0x6b, 0x05, 0x40, 0x71, 0xbf, 0x63, 0xa5, 0x87, 0xa6,
        0x25, 0x70, 0x81,
    ];

    /// Ephemeral ECDH key pair the test (acting as the caller/client) uses to
    /// derive the shared encryption key for credential/session-credential
    /// payloads; an arbitrary fixed DER key, not tied to any real identity.
    const TEST_ECC_384_PRIVATE_KEY: [u8; 185] = [
        0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b,
        0x02, 0x01, 0x01, 0x04, 0x30, 0xce, 0xbc, 0xbb, 0x90, 0x3d, 0x9a, 0x1d, 0x46, 0xd9, 0x59,
        0x15, 0x16, 0xf9, 0x7d, 0xbe, 0x6f, 0xf6, 0x44, 0xa3, 0x2d, 0xa4, 0x7b, 0x73, 0xfb, 0x6e,
        0xad, 0xa5, 0x09, 0x9a, 0x83, 0x2a, 0x67, 0x07, 0xd2, 0x25, 0xd3, 0x8e, 0x67, 0x52, 0xcd,
        0x09, 0x90, 0xa8, 0x31, 0x06, 0x66, 0xc0, 0xe4, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0xe4,
        0x20, 0x9a, 0xd7, 0x07, 0xa4, 0x88, 0x1a, 0xff, 0xf0, 0x12, 0x61, 0x92, 0xc7, 0x9d, 0x83,
        0x77, 0x49, 0x21, 0xcc, 0x5d, 0xf3, 0xb9, 0x21, 0xc4, 0x3d, 0xae, 0xaa, 0x58, 0xb8, 0x34,
        0x2b, 0x38, 0x3c, 0xda, 0xb2, 0x88, 0xf0, 0xe4, 0xb9, 0x56, 0x14, 0x11, 0x15, 0x75, 0xba,
        0xbb, 0x23, 0x7c, 0x67, 0xf7, 0xd1, 0x97, 0x63, 0xc7, 0xb8, 0x56, 0xd3, 0x22, 0xb2, 0xba,
        0xba, 0x1a, 0xc6, 0xb4, 0xea, 0x0d, 0xad, 0xa2, 0x56, 0x29, 0xd5, 0xca, 0x0f, 0x4a, 0x4e,
        0xee, 0x17, 0xb0, 0xb2, 0xf4, 0xb1, 0x58, 0xba, 0xae, 0xa1, 0x58, 0x9c, 0x10, 0x07, 0xf7,
        0x0e, 0xc7, 0x62, 0x42, 0xe0,
    ];

    /// Fixed test POTA endorsement key pair (ECC P-384): the private half
    /// signs the device's partition-identity public key to stand in for a
    /// real POTA endorsement during credential establishment, and the public
    /// half (DER) is what gets sent back to the device alongside the
    /// signature for it to verify.
    const TEST_POTA_ECC_PRIVATE_KEY: [u8; 185] = [
        0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b,
        0x02, 0x01, 0x01, 0x04, 0x30, 0x17, 0xe9, 0x1c, 0xac, 0xf7, 0xb7, 0x21, 0xd7, 0x75, 0x20,
        0x02, 0x07, 0xbc, 0xaa, 0x94, 0x2c, 0xe3, 0xb5, 0x5b, 0x78, 0x13, 0xcc, 0x8b, 0xde, 0x87,
        0x65, 0x6b, 0xe1, 0x7b, 0xc2, 0xa8, 0xcc, 0x89, 0x33, 0x4e, 0xcd, 0xaa, 0x9d, 0x1d, 0x09,
        0xf1, 0xc7, 0x01, 0x1b, 0x64, 0xeb, 0x78, 0x5b, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0x1f,
        0x42, 0x0d, 0x73, 0xeb, 0xf0, 0x67, 0xc2, 0xf9, 0x77, 0xbd, 0x51, 0xab, 0xfb, 0xe1, 0xf6,
        0x53, 0x19, 0xb7, 0x57, 0xe0, 0xa9, 0x20, 0xce, 0x4f, 0x21, 0xbb, 0xd4, 0xa7, 0x84, 0x1c,
        0x93, 0x45, 0xf1, 0xea, 0xd9, 0x5f, 0xe5, 0x90, 0xab, 0x57, 0xe1, 0xea, 0xfc, 0xd2, 0x06,
        0xef, 0x21, 0xa2, 0xad, 0x10, 0xd3, 0x17, 0x6e, 0x99, 0xc8, 0x22, 0x26, 0x23, 0x08, 0x57,
        0xa7, 0x56, 0x08, 0x45, 0xe3, 0xda, 0x12, 0xc7, 0xdc, 0x3a, 0xee, 0x01, 0xfc, 0x37, 0xab,
        0x1c, 0x8d, 0xc6, 0xd0, 0x64, 0x7a, 0x7d, 0xc2, 0x67, 0xfc, 0x02, 0x7d, 0x8d, 0xa3, 0xc8,
        0x01, 0x4b, 0xa4, 0x0d, 0x98,
    ];

    const TEST_POTA_ECC_PUB_KEY: [u8; 120] = [
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x1f, 0x42, 0x0d, 0x73, 0xeb, 0xf0,
        0x67, 0xc2, 0xf9, 0x77, 0xbd, 0x51, 0xab, 0xfb, 0xe1, 0xf6, 0x53, 0x19, 0xb7, 0x57, 0xe0,
        0xa9, 0x20, 0xce, 0x4f, 0x21, 0xbb, 0xd4, 0xa7, 0x84, 0x1c, 0x93, 0x45, 0xf1, 0xea, 0xd9,
        0x5f, 0xe5, 0x90, 0xab, 0x57, 0xe1, 0xea, 0xfc, 0xd2, 0x06, 0xef, 0x21, 0xa2, 0xad, 0x10,
        0xd3, 0x17, 0x6e, 0x99, 0xc8, 0x22, 0x26, 0x23, 0x08, 0x57, 0xa7, 0x56, 0x08, 0x45, 0xe3,
        0xda, 0x12, 0xc7, 0xdc, 0x3a, 0xee, 0x01, 0xfc, 0x37, 0xab, 0x1c, 0x8d, 0xc6, 0xd0, 0x64,
        0x7a, 0x7d, 0xc2, 0x67, 0xfc, 0x02, 0x7d, 0x8d, 0xa3, 0xc8, 0x01, 0x4b, 0xa4, 0x0d, 0x98,
    ];

    /// Signs the device's partition-identity public key (fetched via its
    /// cert chain's leaf certificate) with the fixed test POTA private key,
    /// mirroring `helper_get_pota_endorsement` in
    /// `ddi/mbor/types/tests/integration/common.rs`. Returns
    /// `(signature, pota_public_key_der)`.
    fn get_pota_endorsement(dev: &<DdiVsock as Ddi>::Dev) -> (Vec<u8>, Vec<u8>) {
        let chain_info = helper_get_cert_chain_info(dev).expect("GetCertChainInfo should succeed");
        let leaf = helper_get_certificate(dev, chain_info.data.num_certs - 1)
            .expect("GetCertificate (leaf) should succeed");
        let cert = X509Certificate::from_der(leaf.data.certificate.as_slice())
            .expect("leaf certificate should parse as DER");
        let pub_key_der = cert
            .get_public_key_der()
            .expect("leaf certificate should carry a public key");
        let pub_key =
            DerEccPublicKey::from_der(&pub_key_der).expect("public key should be ECC DER");

        let mut uncompressed_point = vec![0x04u8];
        uncompressed_point.extend_from_slice(pub_key.x());
        uncompressed_point.extend_from_slice(pub_key.y());

        let priv_key = EccPrivateKey::from_bytes(&TEST_POTA_ECC_PRIVATE_KEY)
            .expect("fixed test POTA private key should load");
        let mut ecdsa = EcdsaAlgo::new(HashAlgo::sha384());
        let sig_len = Signer::sign(&mut ecdsa, &priv_key, &uncompressed_point, None)
            .expect("signature length query should succeed");
        let mut signature = vec![0u8; sig_len];
        Signer::sign(
            &mut ecdsa,
            &priv_key,
            &uncompressed_point,
            Some(&mut signature),
        )
        .expect("POTA signing should succeed");

        (signature, TEST_POTA_ECC_PUB_KEY.to_vec())
    }

    /// Drives a full `EstablishCredential` then `OpenSession` handshake
    /// against `dev` using the fixed test credential/key constants above,
    /// returning the firmware-issued `(sess_id, cookie)` pair recorded by
    /// `SessionGenerationTracker` for this connection's current generation.
    fn establish_credential_and_open_session(dev: &<DdiVsock as Ddi>::Dev) -> (u16, u64) {
        let api_rev = Some(DdiApiRev { major: 1, minor: 0 });

        let cred_key_resp = helper_get_establish_cred_encryption_key(dev, None, api_rev)
            .expect("GetEstablishCredEncryptionKey should succeed");
        let nonce = cred_key_resp.data.nonce;
        let (establish_key, establish_pub_key) =
            DeviceCredKey::new(&cred_key_resp.data.pub_key, nonce)
                .expect("DeviceCredKey::new should succeed")
                .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
                .expect("create_credential_key_from_der should succeed");
        let encrypted_credential = establish_key
            .encrypt_establish_credential(TEST_CRED_ID, TEST_CRED_PIN, nonce)
            .expect("encrypt_establish_credential should succeed");

        let masked_bk3 = helper_get_or_init_bk3(dev);
        let (signature, pota_pub_key) = get_pota_endorsement(dev);

        helper_establish_credential(
            dev,
            None,
            api_rev,
            encrypted_credential,
            establish_pub_key,
            masked_bk3,
            MborByteArray::from_slice(&[]).expect("empty BMK should fit"),
            MborByteArray::from_slice(&[]).expect("empty masked unwrapping key should fit"),
            MborByteArray::from_slice(&signature).expect("POTA signature should fit"),
            DdiDerPublicKey {
                der: MborByteArray::from_slice(&pota_pub_key).expect("POTA public key should fit"),
                key_kind: DdiKeyType::Ecc384Public,
            },
        )
        .expect("EstablishCredential should succeed");

        let session_key_resp = helper_get_session_encryption_key(dev, None, api_rev)
            .expect("GetSessionEncryptionKey should succeed");
        let nonce = session_key_resp.data.nonce;
        let (session_key, session_pub_key) =
            DeviceCredKey::new(&session_key_resp.data.pub_key, nonce)
                .expect("DeviceCredKey::new should succeed")
                .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
                .expect("create_credential_key_from_der should succeed");
        let encrypted_session_credential = session_key
            .encrypt_session_credential(TEST_CRED_ID, TEST_CRED_PIN, TEST_SESSION_SEED, nonce)
            .expect("encrypt_session_credential should succeed");

        // `helper_open_session` doesn't expose the cookie `exec_op_mbor`
        // threads through as an out-parameter (it discards its own local
        // one), so build the request directly here to capture it —
        // `SessionGenerationTracker`'s cookie is purely local, client-side
        // state (never sent to the firmware), so this is the only way to
        // retrieve the real token `record()` assigned for this session.
        let req = DdiOpenSessionCmdReq {
            hdr: DdiReqHdr {
                op: DdiOp::OpenSession,
                sess_id: None,
                rev: api_rev,
            },
            data: DdiOpenSessionReq {
                encrypted_credential: encrypted_session_credential,
                pub_key: session_pub_key,
            },
            ext: None,
        };
        let mut cookie = None;
        let open_resp = dev
            .exec_op_mbor(&req, &mut cookie)
            .expect("OpenSession should succeed");

        let sess_id = open_resp
            .hdr
            .sess_id
            .expect("OpenSession response must carry the new sess_id");
        let cookie =
            cookie.expect("a successful OpenSession must record a SessionGenerationTracker cookie");
        (sess_id, cookie)
    }

    /// Regression test for the stale-session-close fix
    /// (`SessionGenerationTracker`), using a *real*, firmware-issued
    /// `(sess_id, cookie)` pair instead of a synthetic one — see the module
    /// comment above for why this is needed to exercise the generation-
    /// mismatch rejection branch specifically (as opposed to the missing-
    /// cookie shortcut `unrecognized_session_close_is_rejected_locally_after_erase_over_real_vsock`
    /// already covers).
    #[test]
    fn stale_real_session_close_is_rejected_by_generation_after_erase_over_real_vsock() {
        let mut endpoints = TestEndpoints::new("stale-real-session-erase");
        let _bridge = bridge_or_skip!(
            spawn_bridge(&mut endpoints).expect("failed to probe/start test bridge")
        );
        let _vsocksrv =
            vsocksrv_or_skip!(spawn_vsocksrv(&endpoints).expect("failed to start vsocksrv"));

        let ddi = DdiVsock::default();
        let dev = ddi
            .open_dev(&endpoints.vsock_port.to_string())
            .expect("failed to accept the real AF_VSOCK connection via the bridge");

        assert_get_api_rev_succeeds(&dev);

        let (sess_id, cookie) = establish_credential_and_open_session(&dev);

        // Same replacement-connection dance as the synthetic-cookie test
        // above: `erase()` blocks until a new connection is accepted.
        let vsock_port = endpoints.vsock_port;
        let replacement_client = thread::spawn(move || {
            connect_vsock_loopback_with_retry(vsock_port, Instant::now() + Duration::from_secs(10))
        });

        dev.erase().expect("erase should succeed");
        let mut replacement = replacement_client
            .join()
            .expect("replacement-connect thread panicked")
            .expect("failed to connect the replacement client")
            .expect("AF_VSOCK loopback vanished mid-test");

        // As above: prove the rejection happens locally, before any bytes
        // reach the replacement connection.
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut byte = [0u8; 1];
            let reached = matches!(replacement.read(&mut byte), Ok(n) if n > 0);
            let _ = reached_tx.send(reached);
        });

        // Close the *real* pre-erase session using its genuine sess_id and
        // cookie. `SessionGenerationTracker::check` now finds a matching
        // token under `open_sessions`, so this exercises the generation
        // comparison itself (`session.generation == current`) rather than
        // the `cookie.is_none()` shortcut: the token matches, but the
        // generation doesn't, so it must still fall through to
        // `Err(SessionNotFound)`.
        let close_req = DdiCloseSessionCmdReq {
            hdr: DdiReqHdr {
                rev: None,
                op: DdiOp::CloseSession,
                sess_id: Some(sess_id),
            },
            data: DdiCloseSessionReq {},
            ext: None,
        };
        let mut cookie = Some(cookie);
        let result = dev.exec_op_mbor(&close_req, &mut cookie);
        assert!(
            matches!(result, Err(DdiError::DdiStatus(DdiStatus::SessionNotFound))),
            "a real pre-erase session id/cookie pair must be rejected once the \
             post-erase generation no longer matches it, not forwarded to the \
             (torn-down) stream: {result:?}",
        );

        let reached = reached_rx
            .recv_timeout(Duration::from_millis(500))
            .unwrap_or(false);
        assert!(
            !reached,
            "the stale close must be rejected before reaching the transport, \
             but bytes arrived at the replacement connection",
        );
    }
}
