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
use azihsm_ddi_vsock::DdiVsock;
use nix::sys::socket::connect;
use nix::sys::socket::socket;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::MsgFlags;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockType;
use nix::sys::socket::VsockAddr;
use nix::unistd::close;

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
    let fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(nix_to_io)?;
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

impl TestEndpoints {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir();
        let unique = format!(
            "{tag}-{}-{:?}",
            std::process::id(),
            Instant::now().elapsed()
        );
        // Spread out from the crate's documented default port (and other
        // tests in this binary, each of which binds its own
        // `DdiVsockDev` listener port) by mixing in the low bits of the
        // process id.
        let vsock_port = 52000 + (std::process::id() % 1000);
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

/// Spawns a background thread that accepts exactly one `vsocksrv`
/// connection on `endpoints.ch`, connects a real `AF_VSOCK` client to
/// `endpoints.vsock_port` (retrying until `DdiVsock::open_dev`'s listener
/// is up, or until loopback itself proves unavailable), and bridges them
/// together. Returns `Ok(None)` if loopback is unavailable rather than
/// spawning anything.
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
        let Ok((ch, _)) = ch_listener.accept() else {
            return;
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let Ok(Some(ddi)) = connect_vsock_loopback_with_retry(vsock_port, deadline) else {
            return;
        };
        let _ = bridge_connection(ch, ddi);
    })))
}

/// Locates the `vsocksrv` binary built alongside this test (see the
/// identical helper in `ddi/sock/tests/vsocksrv_integration.rs` for why
/// this can't just be a normal dev-dependency).
fn locate_vsocksrv_bin() -> PathBuf {
    if let Ok(path) = std::env::var("VSOCKSRV_BIN") {
        return PathBuf::from(path);
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
    assert!(
        bin.exists(),
        "vsocksrv binary not found at {bin:?}; build it first with \
         `cargo build -p vsocksrv` (or set VSOCKSRV_BIN)"
    );
    bin
}

/// Starts `vsocksrv` in `--socket-type unix` mode, dialing out to
/// `endpoints.ch`. `vsocksrv` retries the connection until the listener
/// exists, so start order relative to [`spawn_bridge`] does not matter.
fn spawn_vsocksrv(endpoints: &TestEndpoints) -> io::Result<VsocksrvGuard> {
    let child = Command::new(locate_vsocksrv_bin())
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
    Ok(VsocksrvGuard(child))
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

/// Skips the running test with a clear message if `bridge` is `None`
/// (i.e. `AF_VSOCK` loopback is unavailable in this environment).
macro_rules! bridge_or_skip {
    ($bridge:expr) => {
        match $bridge {
            Some(bridge) => bridge,
            None => {
                eprintln!(
                    "SKIP: AF_VSOCK loopback unavailable (vsock_loopback \
                     kernel module likely not loaded); run `sudo modprobe \
                     vsock_loopback` to exercise this test for real."
                );
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
    let _vsocksrv = spawn_vsocksrv(&endpoints).expect("failed to start vsocksrv");

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
/// scope for this transport-level test), but it exercises the same
/// `SessionGenerationTracker::check` rejection path: any session id not
/// recorded under the *current* generation — whether never opened at all
/// or opened under a since-reset generation — is rejected identically.
#[test]
fn unrecognized_session_close_is_rejected_locally_after_erase_over_real_vsock() {
    let mut endpoints = TestEndpoints::new("stale-session-erase");
    let _bridge =
        bridge_or_skip!(spawn_bridge(&mut endpoints).expect("failed to probe/start test bridge"));
    let _vsocksrv = spawn_vsocksrv(&endpoints).expect("failed to start vsocksrv");

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
    let _replacement = replacement_client
        .join()
        .expect("replacement-connect thread panicked")
        .expect("failed to connect the replacement client")
        .expect("AF_VSOCK loopback vanished mid-test");

    let close_req = DdiGetApiRevCmdReq {
        hdr: DdiReqHdr {
            rev: None,
            op: DdiOp::GetApiRev,
            sess_id: Some(1),
        },
        data: DdiGetApiRevReq {},
        ext: None,
    };
    let mut cookie = None;
    let result = dev.exec_op_mbor(&close_req, &mut cookie);
    assert!(
        result.is_err(),
        "a session id unrecognized by the post-erase generation must be \
         rejected, not forwarded to the (torn-down) stream",
    );
}
