// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Socket DDI transport — device handle and request execution.

use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;

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
#[cfg(target_os = "linux")]
use nix::sys::socket::connect;
#[cfg(target_os = "linux")]
use nix::sys::socket::socket;
#[cfg(target_os = "linux")]
use nix::sys::socket::AddressFamily;
#[cfg(target_os = "linux")]
use nix::sys::socket::SockFlag;
#[cfg(target_os = "linux")]
use nix::sys::socket::SockType;
#[cfg(target_os = "linux")]
use nix::sys::socket::VsockAddr;
use parking_lot::Mutex;

/// Environment variable naming the socket to connect to.
pub const SOCK_PATH_ENV: &str = "AZIHSM_DDI_SOCK";

/// Default socket path when [`SOCK_PATH_ENV`] is unset.
pub const DEFAULT_SOCK_PATH: &str = "/tmp/azihsm-ddi.sock";

/// Response buffer capacity advertised to the server. Fits MBOR and the
/// current TBOR command set; larger responses are future work.
const DST_CAP: u32 = 4096;

enum SocketStream {
    Unix(UnixStream),
    #[cfg(target_os = "linux")]
    Vsock(VsockStream),
}

impl Read for SocketStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Unix(stream) => stream.read(buf),
            #[cfg(target_os = "linux")]
            Self::Vsock(stream) => stream.read(buf),
        }
    }
}

impl Write for SocketStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Unix(stream) => stream.write(buf),
            #[cfg(target_os = "linux")]
            Self::Vsock(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Unix(stream) => stream.flush(),
            #[cfg(target_os = "linux")]
            Self::Vsock(stream) => stream.flush(),
        }
    }
}

#[cfg(target_os = "linux")]
struct VsockStream {
    fd: std::os::fd::RawFd,
}

#[cfg(target_os = "linux")]
impl VsockStream {
    fn connect(cid: u32, port: u32) -> std::io::Result<Self> {
        let fd = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(std::io::Error::from)?;

        if let Err(error) = connect(fd, &VsockAddr::new(cid, port)) {
            let _ = nix::unistd::close(fd);
            return Err(std::io::Error::from(error));
        }
        Ok(Self { fd })
    }
}

#[cfg(target_os = "linux")]
impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        nix::unistd::read(self.fd, buf).map_err(std::io::Error::from)
    }
}

#[cfg(target_os = "linux")]
impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        nix::unistd::write(self.fd, buf).map_err(std::io::Error::from)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for VsockStream {
    fn drop(&mut self) {
        let _ = nix::unistd::close(self.fd);
    }
}

fn parse_vsock_endpoint(path: &str) -> std::io::Result<Option<(u32, u32)>> {
    let Some(address) = path.strip_prefix("vsock://") else {
        return Ok(None);
    };
    let Some((cid, port)) = address.split_once(':') else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "vsock endpoint must have the form vsock://CID:PORT",
        ));
    };
    if cid.is_empty() || port.is_empty() || port.contains(':') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "vsock endpoint must have the form vsock://CID:PORT",
        ));
    }
    let cid = cid
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid vsock CID"))?;
    let port = port
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid vsock port"))?;
    if port == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "vsock port must be nonzero",
        ));
    }
    Ok(Some((cid, port)))
}

/// Resolve the configured socket path from the environment or default.
pub(crate) fn socket_path() -> String {
    std::env::var(SOCK_PATH_ENV).unwrap_or_else(|_| DEFAULT_SOCK_PATH.to_owned())
}

/// A connected socket DDI device.
///
/// Wraps a single Unix-domain-socket connection to the server. Requests
/// are serialized through a mutex, so the synchronous trait methods can be
/// shared across threads while each request/response exchange stays atomic.
pub struct DdiSockDev {
    stream: Mutex<SocketStream>,
    cmd_counter: AtomicU16,
    device_kind: DdiDeviceKind,
}

impl std::fmt::Debug for DdiSockDev {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DdiSockDev")
            .field("device_kind", &self.device_kind)
            .finish_non_exhaustive()
    }
}

impl DdiSockDev {
    /// Connect to the server at `path`.
    pub(crate) fn connect(path: &str) -> DdiResult<Self> {
        let stream = match parse_vsock_endpoint(path).map_err(DdiError::IoError)? {
            Some((cid, port)) => {
                #[cfg(target_os = "linux")]
                {
                    SocketStream::Vsock(VsockStream::connect(cid, port).map_err(DdiError::IoError)?)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (cid, port);
                    return Err(DdiError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "vsock endpoints require Linux",
                    )));
                }
            }
            None => SocketStream::Unix(UnixStream::connect(path).map_err(DdiError::IoError)?),
        };
        Ok(Self {
            stream: Mutex::new(stream),
            cmd_counter: AtomicU16::new(1),
            // The firmware reports a physical device, so the host codec
            // runs its physical-mode encode/decode hooks (matching emu).
            device_kind: DdiDeviceKind::Physical,
        })
    }

    fn next_cmd_id(&self) -> u16 {
        self.cmd_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Build a submission entry, exchange it with the server, and return
    /// the response body bytes.
    ///
    /// Mirrors the in-process emulator: the client constructs the SQE
    /// (opcode, command id, lengths, session flags) and reads the returned
    /// CQE; the server only re-homes the DMA buffers. The SQE's PRP
    /// address fields are left zero — the server assigns them.
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
        let cmd_id = self.next_cmd_id();
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

        let req = Request { sqe, payload };

        let resp: Response = {
            let mut stream = self.stream.lock();
            req.write_to(&mut *stream).map_err(map_proto_err)?;
            Response::read_from(&mut *stream).map_err(map_proto_err)?
        };

        // Transport-level status (e.g. server DMA allocation failure).
        if resp.status != 0 {
            return Err(DdiError::DdiError(resp.status));
        }

        // Device-level status lives in the completion entry.
        let mut cqe_raw = resp.cqe;
        let cqe = Cqe::from(&mut cqe_raw);
        if cqe.status() != 0 {
            return Err(DdiError::DdiError(u32::from(cqe.status())));
        }

        // Don't trust the server's framing for the payload length: the
        // completion entry's `dst_len` is the authoritative count of bytes the
        // firmware wrote. Reject a short payload (the response can't satisfy the
        // reported length) and truncate any trailing bytes so callers never
        // decode past the firmware's output.
        let dst_len = cqe.dst_len() as usize;
        let mut payload = resp.payload;
        // The client advertised a fixed destination capacity (`DST_CAP`) in the
        // SQE, so a CQE reporting more than that is a protocol integrity failure
        // (malicious or buggy server) — reject it before touching the payload.
        if dst_len > DST_CAP as usize {
            return Err(DdiError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "CQE dst_len exceeds requested destination capacity",
            )));
        }
        if payload.len() < dst_len {
            // The server returned fewer bytes than the firmware reported
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

impl DdiDev for DdiSockDev {
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

        // ── 2. Build the SQE and exchange it over the socket.
        let resp_buf = self.submit(OP_MBOR, u8::from(session_ctrl), session_id, buf)?;
        if resp_buf.is_empty() {
            return Err(DdiError::DdiError(0));
        }

        // ── 3. Decode the response header and check device status.
        let mut hdr_dec = DdiDecoder::new(&resp_buf, post_decode);
        let hdr: DdiRespHdr = hdr_dec
            .decode_hdr()
            .map_err(|_| DdiError::MborError(MborError::DecodeError))?;
        if hdr.status != DdiStatus::Success {
            return Err(DdiError::DdiStatus(hdr.status));
        }

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
        // The socket transport (v1) carries only the SQE body; it has no
        // channel for out-of-band SGL descriptor pages yet.
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

        // ── 2. Build the SQE and exchange it over the socket.
        let resp_buf = self.submit(OP_TBOR, u8::from(session_ctrl), session_id, buf)?;
        if resp_buf.is_empty() {
            return Err(DdiError::DdiError(0));
        }

        // ── 3. Decode the typed response.
        <T::OpResp>::decode_response(&resp_buf).map_err(Into::into)
    }

    // ── Fast-path crypto ops are not supported over the socket transport
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
        Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))
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
    use super::parse_vsock_endpoint;

    #[test]
    fn parses_vsock_endpoint() {
        assert_eq!(
            parse_vsock_endpoint("vsock://4:1234").unwrap(),
            Some((4, 1234))
        );
        assert_eq!(parse_vsock_endpoint("/tmp/ddi.sock").unwrap(), None);
    }

    #[test]
    fn rejects_invalid_vsock_endpoint() {
        for endpoint in [
            "vsock://",
            "vsock://4",
            "vsock://:1234",
            "vsock://4:",
            "vsock://x:1234",
            "vsock://4:0",
            "vsock://4:1234:5",
        ] {
            assert!(parse_vsock_endpoint(endpoint).is_err(), "{endpoint}");
        }
    }
}
