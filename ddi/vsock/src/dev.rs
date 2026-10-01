// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Vsock DDI transport — device handle and request execution.

use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::os::fd::RawFd;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::OnceLock;

use azihsm_ddi_interface::DdiAesGcmParams;
use azihsm_ddi_interface::DdiAesGcmResult;
use azihsm_ddi_interface::DdiAesXtsParams;
use azihsm_ddi_interface::DdiAesXtsResult;
use azihsm_ddi_interface::DdiCookie;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_mbor_codec::MborDecode;
use azihsm_ddi_mbor_codec::MborDecoder;
use azihsm_ddi_mbor_codec::MborEncoder;
use azihsm_ddi_mbor_types::DdiAesOp;
use azihsm_ddi_mbor_types::DdiDecoder;
use azihsm_ddi_mbor_types::DdiDeviceKind;
use azihsm_ddi_mbor_types::DdiOpReq;
use azihsm_ddi_mbor_types::DdiRespHdr;
use azihsm_ddi_mbor_types::DdiStatus;
use azihsm_ddi_mbor_types::MborError;
use azihsm_ddi_mbor_types::SessionControlKind;
use azihsm_ddi_sock_proto::ProtoError;
use azihsm_ddi_sock_proto::Request;
use azihsm_ddi_sock_proto::Response;
use azihsm_ddi_tbor_types::TborOpReq;
use azihsm_ddi_tbor_types::TborResp;
use azihsm_fw_hsm_io::CmdDword;
use azihsm_fw_hsm_io::Cqe;
use azihsm_fw_hsm_io::SessionFlags;
use azihsm_fw_hsm_io::SqeBuilder;
use azihsm_fw_hsm_io::OP_MBOR;
use azihsm_fw_hsm_io::OP_TBOR;
use nix::sys::socket::accept4;
use nix::sys::socket::bind;
use nix::sys::socket::listen;
use nix::sys::socket::send;
use nix::sys::socket::socket;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::MsgFlags;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockType;
use nix::sys::socket::VsockAddr;
use nix::unistd::close;
use nix::unistd::read;
use parking_lot::Mutex;

/// Environment variable naming the AF_VSOCK port to listen on.
pub const VSOCK_PORT_ENV: &str = "AZIHSM_DDI_VSOCK_PORT";

/// Default AF_VSOCK port when [`VSOCK_PORT_ENV`] is unset.
pub const DEFAULT_VSOCK_PORT: u32 = 5000;

/// Response buffer capacity advertised to the server. Fits MBOR and the
/// current TBOR command set; larger responses are future work.
const DST_CAP: u32 = 4096;

/// Resolve the configured AF_VSOCK port from the environment or default.
pub(crate) fn vsock_port() -> u32 {
    std::env::var(VSOCK_PORT_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_VSOCK_PORT)
}

/// Process-wide registry of AF_VSOCK listeners, keyed by port.
///
/// A listener is bound and put into the listening state at most once per
/// port: repeated [`Ddi::open_dev`](azihsm_ddi_interface::Ddi::open_dev)
/// calls each `accept` a fresh connection from the shared listener rather
/// than re-binding the same port (which would fail with `EADDRINUSE`).
static LISTENERS: OnceLock<Mutex<HashMap<u32, Arc<VsockListener>>>> = OnceLock::new();

fn listener_for(port: u32) -> DdiResult<Arc<VsockListener>> {
    let registry = LISTENERS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry.lock();
    if let Some(listener) = registry.get(&port) {
        return Ok(Arc::clone(listener));
    }
    let listener = Arc::new(VsockListener::bind(port).map_err(DdiError::IoError)?);
    registry.insert(port, Arc::clone(&listener));
    Ok(listener)
}

/// A listening AF_VSOCK socket, bound to
/// [`libc::VMADDR_CID_ANY`](libc::VMADDR_CID_ANY) on a fixed port.
struct VsockListener(RawFd);

impl VsockListener {
    fn bind(port: u32) -> std::io::Result<Self> {
        let fd = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(nix_to_io)?;
        // Wrap `fd` immediately so a `bind`/`listen` failure below still
        // closes it via `Drop` instead of leaking the descriptor: `listener_for`
        // only caches the listener once `bind` fully succeeds, so repeated
        // `open_dev` retries after a transient failure would otherwise leak
        // one fd per attempt.
        let listener = Self(fd);
        bind(fd, &VsockAddr::new(libc::VMADDR_CID_ANY, port)).map_err(nix_to_io)?;
        listen(fd, 128).map_err(nix_to_io)?;
        Ok(listener)
    }

    fn accept(&self) -> std::io::Result<VsockStream> {
        let fd = accept4(self.0, SockFlag::SOCK_CLOEXEC).map_err(nix_to_io)?;
        Ok(VsockStream(fd))
    }
}

impl Drop for VsockListener {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

/// An accepted AF_VSOCK connection from the host.
struct VsockStream(RawFd);

impl Read for VsockStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        read(self.0, buffer).map_err(nix_to_io)
    }
}

impl Write for VsockStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        send(self.0, buffer, MsgFlags::MSG_NOSIGNAL).map_err(nix_to_io)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl VsockStream {
    /// Shut down both directions of the connection without invalidating
    /// the underlying fd (the [`Drop`] impl still closes it). Used by
    /// [`DdiVsockDev::erase`] to make the host observe a disconnect
    /// without needing a placeholder/`Option` around the stream field.
    fn shutdown(&self) -> std::io::Result<()> {
        nix::sys::socket::shutdown(self.0, nix::sys::socket::Shutdown::Both).map_err(nix_to_io)
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

fn nix_to_io(error: nix::Error) -> std::io::Error {
    std::io::Error::from_raw_os_error(error as i32)
}

/// Tracks which MBOR session ids belong to the current connection
/// generation on a [`DdiVsockDev`], so a stale `HsmSession`'s `Drop`
/// impl (`api/lib/src/session.rs:508-519`, which unconditionally sends
/// `CloseSession`/`InSession`) can't reach a replacement connection
/// after [`DdiVsockDev::erase`] and tear down an unrelated, live session
/// that reused the same numeric id.
///
/// Pure in-memory bookkeeping — no I/O — so it's unit-testable in
/// isolation from the real AF_VSOCK transport (see the `tests` module
/// below).
///
/// Only covers the MBOR session path (`exec_op_mbor`): TBOR's
/// `TborResp` trait has no accessor for a response-carried session id,
/// and (per `api/lib/src/ddi/session_ex.rs`) resiliency/reopen handling
/// isn't wired up for the TBOR transport at all yet, so there's no
/// existing invariant this guard would need to preserve there.
#[derive(Default)]
struct SessionGenerationTracker {
    /// Bumped by [`reset`](Self::reset) each time the live connection is
    /// replaced (partition reset).
    generation: AtomicU64,

    /// Session ids opened over the MBOR path, each mapped to the
    /// `generation` they were opened under. Cleared by `reset`.
    open_sessions: Mutex<HashMap<u16, u64>>,
}

impl SessionGenerationTracker {
    /// Reject a `Close`/`InSession` request whose `session_id` doesn't
    /// belong to the current generation.
    ///
    /// Must be called *before* the request is sent: rejecting only after
    /// a failed round trip would be too late, since the point is to keep
    /// a stale close from ever reaching the (possibly reused) live
    /// session on the replacement connection.
    fn check(&self, session_ctrl: SessionControlKind, session_id: Option<u16>) -> DdiResult<()> {
        if session_ctrl == SessionControlKind::Open {
            // No session id to validate yet: the firmware hasn't assigned
            // one.
            return Ok(());
        }
        let Some(id) = session_id else {
            return Ok(());
        };
        let current = self.generation.load(Ordering::SeqCst);
        match self.open_sessions.lock().get(&id) {
            Some(&generation) if generation == current => Ok(()),
            _ => Err(DdiError::DdiStatus(DdiStatus::SessionNotFound)),
        }
    }

    /// Record the bookkeeping side-effect of a successful MBOR
    /// `Open`/`Close` exchange on `session_id`.
    fn record(&self, session_ctrl: SessionControlKind, session_id: Option<u16>) {
        match session_ctrl {
            SessionControlKind::Open => {
                if let Some(id) = session_id {
                    let generation = self.generation.load(Ordering::SeqCst);
                    self.open_sessions.lock().insert(id, generation);
                }
            }
            SessionControlKind::Close => {
                if let Some(id) = session_id {
                    self.open_sessions.lock().remove(&id);
                }
            }
            SessionControlKind::NoSession | SessionControlKind::InSession => {}
        }
    }

    /// Bump the generation and drop all recorded session ids: called
    /// after [`DdiVsockDev::erase`] replaces the live connection, since
    /// every previously-tracked session id is gone and any id the
    /// replacement connection's firmware hands out from here on belongs
    /// to a new generation, even if it numerically reuses a freed one.
    fn reset(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.open_sessions.lock().clear();
    }
}

/// A connected vsock DDI device.
///
/// Wraps a single accepted AF_VSOCK connection from the host. Requests
/// are serialized through a mutex, so the synchronous trait methods can be
/// shared across threads while each request/response exchange stays atomic.
pub struct DdiVsockDev {
    stream: Mutex<VsockStream>,
    cmd_counter: AtomicU16,
    device_kind: DdiDeviceKind,
    port: u32,
    sessions: SessionGenerationTracker,
}

impl std::fmt::Debug for DdiVsockDev {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DdiVsockDev")
            .field("device_kind", &self.device_kind)
            .finish_non_exhaustive()
    }
}

impl DdiVsockDev {
    /// Bind (on first use) and accept a connection on `port`.
    pub(crate) fn accept(port: u32) -> DdiResult<Self> {
        let listener = listener_for(port)?;
        let stream = listener.accept().map_err(DdiError::IoError)?;
        Ok(Self {
            stream: Mutex::new(stream),
            cmd_counter: AtomicU16::new(1),
            // The firmware reports a physical device, so the host codec
            // runs its physical-mode encode/decode hooks (matching emu
            // and sock).
            device_kind: DdiDeviceKind::Physical,
            port,
            sessions: SessionGenerationTracker::default(),
        })
    }

    fn next_cmd_id(&self) -> u16 {
        self.cmd_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Build a submission entry, exchange it with the host, and return
    /// the response body bytes.
    ///
    /// Mirrors [`azihsm_ddi_sock`]'s `DdiSockDev::submit`: the client
    /// constructs the SQE (opcode, command id, lengths, session flags) and
    /// reads the returned CQE; the host only re-homes the DMA buffers. The
    /// SQE's PRP address fields are left zero — the host assigns them.
    ///
    /// Maps a nonzero transport status (header) or device status (CQE) to
    /// [`DdiError::DdiError`].
    fn submit(
        &self,
        op: u16,
        session_ctrl: u8,
        session_id: Option<u16>,
        payload: Vec<u8>,
    ) -> DdiResult<Vec<u8>> {
        let mut stream = self.stream.lock();
        Self::submit_locked(
            &mut stream,
            self.next_cmd_id(),
            op,
            session_ctrl,
            session_id,
            payload,
        )
    }

    /// The I/O-only half of [`submit`](Self::submit): write the request and
    /// read the response over an already-locked `stream`.
    ///
    /// Split out so [`exec_op_mbor`](DdiDev::exec_op_mbor) can hold
    /// `self.stream`'s lock across its session-generation check, this
    /// exchange, *and* the resulting bookkeeping update — see that method
    /// for why those three steps must not be interleaved with
    /// [`erase`](DdiDev::erase).
    fn submit_locked(
        stream: &mut VsockStream,
        cmd_id: u16,
        op: u16,
        session_ctrl: u8,
        session_id: Option<u16>,
        payload: Vec<u8>,
    ) -> DdiResult<Vec<u8>> {
        let sqe = SqeBuilder::new()
            .cmd(CmdDword::new().with_op(op).with_id(cmd_id))
            .buf_lens(payload.len() as u32, DST_CAP)
            .session_flags(
                SessionFlags::new()
                    .with_ctrl(session_ctrl)
                    .with_id_valid(session_id.is_some()),
            )
            .session_id(session_id.unwrap_or(0))
            .build();

        let req = Request {
            sqe,
            payload,
            oob: Vec::new(),
        };

        req.write_to(&mut *stream).map_err(map_proto_err)?;
        let resp = Response::read_from(&mut *stream).map_err(map_proto_err)?;

        // Transport-level status (e.g. host DMA allocation failure).
        if resp.status != 0 {
            return Err(DdiError::DdiError(resp.status));
        }

        // Device-level status lives in the completion entry.
        let mut cqe_raw = resp.cqe;
        let cqe = Cqe::from(&mut cqe_raw);
        if cqe.status() != 0 {
            return Err(DdiError::DdiError(u32::from(cqe.status())));
        }

        // Don't trust the host's framing for the payload length: the
        // completion entry's `dst_len` is the authoritative count of bytes the
        // firmware wrote. Reject a short payload (the response can't satisfy the
        // reported length) and truncate any trailing bytes so callers never
        // decode past the firmware's output.
        let dst_len = cqe.dst_len() as usize;
        let mut payload = resp.payload;
        // The client advertised a fixed destination capacity (`DST_CAP`) in the
        // SQE, so a CQE reporting more than that is a protocol integrity failure
        // (malicious or buggy host) — reject it before touching the payload.
        if dst_len > DST_CAP as usize {
            return Err(DdiError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "CQE dst_len exceeds requested destination capacity",
            )));
        }
        if payload.len() < dst_len {
            // The host returned fewer bytes than the firmware reported
            // writing: a transport/protocol integrity failure, not a device
            // status. Surface it as malformed data rather than a `0` (success)
            // device status, matching the other protocol-shape errors here.
            return Err(DdiError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response payload shorter than CQE dst_len",
            )));
        }
        payload.truncate(dst_len);
        Ok(payload)
    }
}

impl DdiDev for DdiVsockDev {
    fn device_kind(&self) -> DdiDeviceKind {
        self.device_kind
    }

    fn exec_op_mbor<T: DdiOpReq>(
        &self,
        req: &T,
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        let (pre_encode, post_decode) = match self.device_kind {
            DdiDeviceKind::Physical => (true, true),
            _ => (false, false),
        };

        // ── 1. Encode the DDI request via host MBOR (wire-compat with fw).
        let opcode = req.get_opcode();
        let session_ctrl: SessionControlKind = opcode.into();
        let session_id = req.get_session_id();

        let mut buf = vec![0u8; DST_CAP as usize];
        let req_len = {
            let mut enc = MborEncoder::new(buf.as_mut_slice(), pre_encode);
            req.mbor_encode(&mut enc)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?;
            enc.position()
        };
        buf.truncate(req_len);

        // ── 2. Check the session generation, exchange the SQE/CQE, and
        //    record the resulting bookkeeping update, all while holding
        //    `self.stream`'s lock.
        //
        //    Holding one lock across all three steps (rather than just
        //    around the I/O, as `submit` does) is what makes them atomic
        //    with respect to a concurrent `erase()`, which holds the same
        //    lock across its own stream swap *and* `sessions.reset()`
        //    (see that method). Without this, either boundary could be
        //    sliced by an interleaved `erase()`: a stale `Close` could
        //    pass `check` just before `erase()` resets the generation and
        //    then be sent on the replacement connection, or a successful
        //    `Open`/`Close` could have its generation transition recorded
        //    *after* `erase()` already reset it, silently attributing the
        //    old connection's session id to the new generation. Either
        //    way reopens the stale-session-close bug `check`/`record`
        //    exist to close.
        let cmd_id = self.next_cmd_id();
        let resp_buf = {
            let mut stream = self.stream.lock();
            self.sessions.check(session_ctrl, session_id)?;
            let resp_buf = Self::submit_locked(
                &mut stream,
                cmd_id,
                OP_MBOR,
                u8::from(session_ctrl),
                session_id,
                buf,
            )?;
            if resp_buf.is_empty() {
                return Err(DdiError::DdiError(0));
            }

            // Decode the response header and check device status.
            let mut hdr_dec = DdiDecoder::new(&resp_buf, post_decode);
            let hdr: DdiRespHdr = hdr_dec
                .decode_hdr()
                .map_err(|_| DdiError::MborError(MborError::DecodeError))?;
            if hdr.status != DdiStatus::Success {
                return Err(DdiError::DdiStatus(hdr.status));
            }

            // `Open` responses carry the firmware-assigned session id in
            // the header; `Close` requests already know the id being
            // torn down ahead of time. Record the generation transition
            // now that the exchange is confirmed successful, still under
            // the same lock `erase()` uses.
            let recorded_session_id = session_id.or(hdr.sess_id);
            self.sessions.record(session_ctrl, recorded_session_id);
            resp_buf
        };

        // ── 4. Decode the typed response (header + body).
        let mut body_dec = MborDecoder::new(&resp_buf, post_decode);
        <T::OpResp>::mbor_decode(&mut body_dec)
            .map_err(|_| DdiError::MborError(MborError::DecodeError))
    }

    fn exec_op_tbor<T: TborOpReq>(
        &self,
        req: &T,
        oob_items: Option<&[&[u8]]>,
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        // The wire protocol has a channel for out-of-band SGL descriptor
        // pages (see `azihsm_ddi_sock_proto`'s OOB field and `vsocksrv`'s
        // SGL re-homing), but this client isn't wired to use it yet.
        if oob_items.is_some_and(|items| !items.is_empty()) {
            return Err(DdiError::UnsupportedEncoding);
        }

        // ── 1. Encode the TBOR request.
        let session_ctrl = req.session_ctrl();
        let session_id = req.get_session_id();

        let mut buf = vec![0u8; DST_CAP as usize];
        let req_len = {
            let bytes = req.encode_request(buf.as_mut_slice())?;
            bytes.len()
        };
        buf.truncate(req_len);

        // ── 2. Build the SQE and exchange it over the vsock connection.
        let resp_buf = self.submit(OP_TBOR, u8::from(session_ctrl), session_id, buf)?;
        if resp_buf.is_empty() {
            return Err(DdiError::DdiError(0));
        }

        // ── 3. Decode the typed response.
        <T::OpResp>::decode_response(&resp_buf).map_err(Into::into)
    }

    // ── Fast-path crypto ops are not supported over the vsock transport
    //    yet (v1 carries MBOR/TBOR DDI ops only). ─────────────────────

    fn exec_op_fp_gcm_slice(
        &self,
        _mode: DdiAesOp,
        _gcm_params: DdiAesGcmParams,
        _src_buf: &[u8],
        _dst_buf: &mut [u8],
        _tag: &mut Option<[u8; 16]>,
        _iv: &mut Option<[u8; 12]>,
        _fips_approved: &mut bool,
    ) -> Result<usize, DdiError> {
        Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))
    }

    fn exec_op_fp_gcm(
        &self,
        _mode: DdiAesOp,
        _gcm_params: DdiAesGcmParams,
        _src_buf: Vec<u8>,
    ) -> Result<DdiAesGcmResult, DdiError> {
        Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))
    }

    fn exec_op_fp_xts(
        &self,
        _mode: DdiAesOp,
        _xts_params: DdiAesXtsParams,
        _src_buf: Vec<u8>,
    ) -> Result<DdiAesXtsResult, DdiError> {
        Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))
    }

    fn exec_op_fp_xts_slice(
        &self,
        _mode: DdiAesOp,
        _xts_params: DdiAesXtsParams,
        _src_buf: &[u8],
        _dst_buf: &mut [u8],
        _fips_approved: &mut bool,
    ) -> Result<usize, DdiError> {
        Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))
    }

    fn erase(&self) -> Result<(), DdiError> {
        // There's no in-band SQE/CQE opcode for a factory reset over this
        // transport (unlike `DdiNix`'s NSSR ioctl or `DdiEmu`'s in-process
        // disable/enable). Instead, drop the current connection: the host
        // (`vsocksrv`) ties partition reset to connection loss, so closing
        // our end and accepting the replacement connection it re-dials
        // achieves the same effect.
        let listener = listener_for(self.port)?;
        let mut stream = self.stream.lock();
        stream.shutdown().map_err(DdiError::IoError)?;
        *stream = listener.accept().map_err(DdiError::IoError)?;

        // The replacement connection's firmware starts with a clean
        // session table, so every session id this client previously
        // tracked is gone — and any id the firmware hands out from here
        // on belongs to a new generation, even if it numerically reuses
        // an id freed by the reset. `SessionGenerationTracker::reset`
        // bumps the generation and drops the old bookkeeping, so a
        // subsequently-dropped stale `HsmSession` (see
        // `SessionGenerationTracker::check`) is rejected instead of
        // closing whatever live session now holds that id.
        //
        // Must happen *before* `stream` is unlocked (not after, as a
        // separate step): `exec_op_mbor` holds this same lock across its
        // own check/submit/record sequence, so resetting only once both
        // are released would still leave a window where a concurrent
        // `exec_op_mbor` call's check or record interleaves between this
        // swap and the reset, reintroducing the stale-session-close bug
        // this tracker exists to close.
        self.sessions.reset();
        drop(stream);
        Ok(())
    }
}

/// Map a wire-protocol error to a [`DdiError`].
fn map_proto_err(e: ProtoError) -> DdiError {
    match e {
        ProtoError::Io(io) => DdiError::IoError(io),
        other => DdiError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            other.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Baseline: an `Open` then `Close` on the same generation round-trips
    /// cleanly with no rejections, and the id is no longer tracked once
    /// closed.
    #[test]
    fn open_then_close_same_generation_is_allowed() {
        let tracker = SessionGenerationTracker::default();

        // Open never carries a known session id ahead of time.
        tracker
            .check(SessionControlKind::Open, None)
            .expect("Open is never rejected pre-send");
        tracker.record(SessionControlKind::Open, Some(7));

        // The freshly-opened id is usable in-session and closeable.
        tracker
            .check(SessionControlKind::InSession, Some(7))
            .expect("freshly-opened id should be usable in-session");
        tracker
            .check(SessionControlKind::Close, Some(7))
            .expect("freshly-opened id should be closeable");
        tracker.record(SessionControlKind::Close, Some(7));

        // Once closed, the id is no longer recognized.
        assert!(matches!(
            tracker.check(SessionControlKind::Close, Some(7)),
            Err(DdiError::DdiStatus(DdiStatus::SessionNotFound))
        ));
    }

    /// The core regression this tracker exists to prevent: a session
    /// opened before `reset()` (simulating `DdiVsockDev::erase`) must be
    /// rejected afterward, even if the replacement connection's firmware
    /// numerically reuses the same id for a brand-new, live session.
    #[test]
    fn stale_session_after_reset_is_rejected_even_if_id_is_reused() {
        let tracker = SessionGenerationTracker::default();
        tracker.record(SessionControlKind::Open, Some(3));

        // A partition reset: the old connection (and its session table)
        // is gone.
        tracker.reset();

        // The stale `HsmSession::drop`'s `CloseSession` for the old id
        // must be rejected, not forwarded to the replacement connection.
        assert!(matches!(
            tracker.check(SessionControlKind::Close, Some(3)),
            Err(DdiError::DdiStatus(DdiStatus::SessionNotFound))
        ));

        // The replacement connection's firmware reuses id 3 for an
        // unrelated, live session opened after the reset.
        tracker.record(SessionControlKind::Open, Some(3));

        // That new session's own close must still succeed: the guard
        // must distinguish generations, not just "is this id known".
        tracker
            .check(SessionControlKind::Close, Some(3))
            .expect("new session on reused id should be closeable");
    }

    /// A `Close`/`InSession` request for an id that was never opened at
    /// all (not merely stale) must also be rejected.
    #[test]
    fn unknown_session_id_is_rejected() {
        let tracker = SessionGenerationTracker::default();
        assert!(matches!(
            tracker.check(SessionControlKind::Close, Some(42)),
            Err(DdiError::DdiStatus(DdiStatus::SessionNotFound))
        ));
    }

    /// Sessionless (`NoSession`) requests never carry a meaningful id and
    /// must never be rejected by this guard.
    #[test]
    fn no_session_requests_are_never_rejected() {
        let tracker = SessionGenerationTracker::default();
        tracker
            .check(SessionControlKind::NoSession, None)
            .expect("sessionless requests are never rejected");
    }

    /// `Open` requests are never rejected on the pre-send check, even if
    /// (unusually) a caller passes a `session_id` — the firmware hasn't
    /// assigned one yet, so there's nothing to validate against.
    #[test]
    fn open_requests_are_never_rejected_regardless_of_session_id() {
        let tracker = SessionGenerationTracker::default();
        tracker
            .check(SessionControlKind::Open, Some(99))
            .expect("Open is never rejected pre-send, even with a session_id");
    }

    /// `reset()` with no sessions ever recorded is a no-op that doesn't
    /// panic and still bumps the generation (verified indirectly: a
    /// subsequent `Open`+`Close` cycle on the same id still works).
    #[test]
    fn reset_with_no_open_sessions_is_harmless() {
        let tracker = SessionGenerationTracker::default();
        tracker.reset();
        tracker.record(SessionControlKind::Open, Some(1));
        tracker
            .check(SessionControlKind::Close, Some(1))
            .expect("session opened after reset should be closeable");
    }
}
