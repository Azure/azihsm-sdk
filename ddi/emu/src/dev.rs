// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI Implementation - AZIHSM Emulator - Device Module.

// Allowed because the page-aligned scratch buffer below uses the unsafe
// `std::alloc` interface and raw-pointer slice construction. The unsafe
// surface is contained to [`AlignedBuf`] and the SQE pointer encoding.
#![allow(unsafe_code)]

use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::sync::Arc;

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
use azihsm_ddi_mbor_types::DdiOp;
use azihsm_ddi_mbor_types::DdiOpReq;
use azihsm_ddi_mbor_types::DdiOpenSessionCmdResp;
use azihsm_ddi_mbor_types::DdiRespHdr;
use azihsm_ddi_mbor_types::DdiStatus;
use azihsm_ddi_mbor_types::MborError;
use azihsm_ddi_mbor_types::SessionControlKind;
use azihsm_ddi_tbor_types::TborOpReq;
use azihsm_ddi_tbor_types::TborResp;
use azihsm_fw_hsm_io::CmdDword;
use azihsm_fw_hsm_io::Cqe;
use azihsm_fw_hsm_io::SessionFlags;
use azihsm_fw_hsm_io::SqeBuilder;
use azihsm_fw_hsm_io::OP_MBOR;
use azihsm_fw_hsm_io::OP_TBOR;
use azihsm_fw_hsm_std::StdHsm;
use parking_lot::Mutex;
use tokio::runtime::Handle;

/// Path returned by [`DdiEmu::dev_info_list`](crate::DdiEmu::dev_info_list).
///
/// Pass this path to [`DdiEmu::open_dev`](crate::DdiEmu::open_dev) to open
/// the emulator device.
pub const EMU_DEVICE_PATH: &str = "/dev/azihsm-emu";

/// Hard-coded partition index used by the emulator.
///
/// All IOs submitted via [`DdiEmuDev`] target this partition. The
/// matching resource bit is set in [`EMU_PART_RES_MASK`].
const EMU_PID: u8 = 10;

/// Resource bitmask passed to [`StdHsm::part_alloc`].
const EMU_PART_RES_MASK: u128 = 1u128 << EMU_PID;

/// Size of the scratch buffers used for DDI request/response DMA.
///
/// `StdHsmPal` validates source and destination buffer lengths against a
/// 4-KiB page bound, so we allocate one full page per direction.
const SCRATCH_LEN: usize = 4096;

/// Page size enforced by the firmware platform.
const PAGE_4K: usize = 4096;

/// Process-wide rolling SQE command identifier.
///
/// The CQE echoes back the cmd_id in `DW3 [15:0]`; we use a unique value
/// per IO mostly for diagnostic correlation.
static CMD_COUNTER: AtomicU16 = AtomicU16::new(1);

/// Per-handle session bookkeeping (mirrors the mock backend).
#[derive(Debug, Default)]
struct SessionState {
    session_id: Option<u16>,
    short_app_id: Option<u8>,
}

/// DDI Implementation - AZIHSM Emulator device handle.
///
/// Each `DdiEmuDev` shares the process-global [`StdHsm`] and tokio runtime
/// instantiated by [`DdiEmu`](crate::DdiEmu). State that is unique to the
/// handle (the open session id) lives in [`SessionState`].
///
/// `Clone` matches the sibling backends (`DdiMockDev`, `DdiNixDev`,
/// `DdiWinDev`); cloning produces another handle to the same `StdHsm`
/// and shares the same session table.
#[derive(Clone, Debug)]
pub struct DdiEmuDev {
    hsm: Arc<StdHsm>,
    handle: Handle,
    session: Arc<Mutex<SessionState>>,
    device_kind: DdiDeviceKind,
}

impl DdiEmuDev {
    /// Open the emulator device.
    ///
    /// Validates the path, then performs a best-effort
    /// `part_alloc` + `part_enable` for the emulator partition. Both
    /// operations are idempotent — on a second open they return errors
    /// (already allocated / already enabled), which we deliberately
    /// ignore. Real partition failures surface on the first IO.
    pub(crate) fn open(hsm: Arc<StdHsm>, handle: Handle, path: &str) -> DdiResult<Self> {
        if path != EMU_DEVICE_PATH {
            tracing::warn!(
                ?path,
                expected = EMU_DEVICE_PATH,
                "DdiEmuDev: path mismatch"
            );
            return Err(DdiError::DeviceNotFound);
        }

        // Drive partition lifecycle on the embedded runtime. The `let _`
        // pattern matches `fw/plat/std/lib/tests/echo_test.rs::ensure_io_part`.
        handle.block_on(async {
            let _ = hsm.part_alloc(EMU_PID, EMU_PART_RES_MASK).await;
            let _ = hsm.part_enable(EMU_PID).await;
        });

        Ok(Self {
            hsm,
            handle,
            session: Arc::new(Mutex::new(SessionState::default())),
            device_kind: DdiDeviceKind::Physical,
        })
    }
}

impl DdiDev for DdiEmuDev {
    /// Returns the device kind.
    ///
    /// `DdiEmuDev` always reports [`DdiDeviceKind::Physical`] since the
    /// firmware running under [`StdHsm`] reports
    /// [`DdiDeviceKind::Physical`] and the host-side MBOR codec is
    /// configured to match.
    fn device_kind(&self) -> DdiDeviceKind {
        self.device_kind
    }

    fn exec_op_mbor<T: DdiOpReq>(
        &self,
        req: &T,
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        // `device_kind` selects the host-side MBOR codec mode. A few
        // request and response types (e.g., DER↔raw key conversions,
        // RSA blob layouts) carry `pre_encode_fn` / `post_decode_fn`
        // hooks that only run when the encoder/decoder is constructed
        // with the corresponding flag set. See `ddi/nix/src/dev.rs` for
        // the canonical mapping.
        let (pre_encode, post_decode) = match self.device_kind {
            DdiDeviceKind::Physical => (true, true),
            _ => (false, false),
        };

        // ── 1. Validate against current session state ──────────────
        let opcode = req.get_opcode();
        let req_session_id = req.get_session_id();
        let current_session_id = self.session.lock().session_id;
        validate_session_request(opcode, req_session_id, current_session_id)?;

        // ── 2. Encode DDI request via host MBOR (wire-compat with fw) ─
        let mut src = AlignedBuf::new(SCRATCH_LEN);
        let mut dst = AlignedBuf::new(SCRATCH_LEN);

        let req_len = {
            let mut enc = MborEncoder::new(src.as_mut_slice(), pre_encode);
            req.mbor_encode(&mut enc)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?;
            enc.position()
        };
        let req_buf = &src.as_slice()[..req_len];
        tracing::debug!(opcode = ?opcode, len = req_len, "DdiEmu request (in hex): {:02x?}", req_buf);

        // ── 3. Build SQE and submit on the embedded tokio runtime ─────
        let cmd_id = CMD_COUNTER.fetch_add(1, Ordering::Relaxed);
        let session_ctrl: SessionControlKind = opcode.into();
        let sqe = SqeBuilder::new()
            .cmd(CmdDword::new().with_op(OP_MBOR).with_id(cmd_id))
            .buf_lens(req_len as u32, SCRATCH_LEN as u32)
            .src_prp1(req_buf.as_ptr() as u64)
            .dst_prp1(dst.as_mut_slice().as_mut_ptr() as u64)
            .session_flags(
                SessionFlags::new()
                    .with_ctrl(u8::from(session_ctrl))
                    .with_id_valid(req_session_id.is_some()),
            )
            .session_id(req_session_id.unwrap_or(0))
            .build();

        let mut raw_cqe = self
            .handle
            .block_on(self.hsm.io(sqe, EMU_PID, 0, 0))
            .map_err(|_| DdiError::DeviceNotReady)?;
        let cqe = Cqe::from(&mut raw_cqe);

        // ── 4. Pre-decode CQE host status ──────────────────────────
        if cqe.status() != 0 {
            tracing::warn!(opcode = ?opcode, status = cqe.status(), "DdiEmu CQE pre-decode error");
            return Err(DdiError::DdiError(cqe.status() as u32));
        }

        // ── 5. Post-decode: read response header, then body ────────
        let resp_len = cqe.dst_len() as usize;
        if resp_len == 0 {
            return Err(DdiError::DdiError(0));
        }
        let resp_buf = &dst.as_slice()[..resp_len];
        tracing::trace!(opcode = ?opcode, len = resp_len, "DdiEmu response (in hex): {:02x?}", resp_buf);

        let mut hdr_dec = DdiDecoder::new(resp_buf, post_decode);
        let hdr: DdiRespHdr = hdr_dec
            .decode_hdr()
            .map_err(|_| DdiError::MborError(MborError::DecodeError))?;
        if hdr.status != DdiStatus::Success {
            return Err(DdiError::DdiStatus(hdr.status));
        }

        // ── 6. Update session state on Open / Close success ────────
        let kind: SessionControlKind = opcode.into();
        match kind {
            SessionControlKind::Open => self.session.lock().session_id = hdr.sess_id,
            SessionControlKind::Close => self.session.lock().session_id = None,
            SessionControlKind::NoSession | SessionControlKind::InSession => {}
        }

        // ── 7. Decode the typed response (whole-buffer decode — the
        //         response type wraps both the header and body, matching
        //         what the mock backend does) ────────────────────────
        let mut body_dec = MborDecoder::new(resp_buf, post_decode);
        let resp = <T::OpResp>::mbor_decode(&mut body_dec)
            .map_err(|_| DdiError::MborError(MborError::DecodeError))?;

        if opcode == DdiOp::OpenSession {
            // Sniff the short_app_id out of the OpenSession response so
            // that future fast-path calls can be validated.
            let mut sniff_dec = MborDecoder::new(resp_buf, post_decode);
            let r = DdiOpenSessionCmdResp::mbor_decode(&mut sniff_dec)
                .map_err(|_| DdiError::MborError(MborError::DecodeError))?;
            self.session.lock().short_app_id = Some(r.data.short_app_id);
        }

        Ok(resp)
    }

    /// TBOR exec path — mirrors [`Self::exec_op_mbor`] but uses the
    /// TBOR codec, sets the SQE opcode to [`OP_TBOR`], and returns a
    /// fully-decoded owned response value via [`TborResp::decode_response`].
    fn exec_op_tbor<T: TborOpReq>(
        &self,
        req: &T,
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        // ── 1. Encode the TBOR request into a 4-KiB scratch buffer ─
        let mut src = AlignedBuf::new(SCRATCH_LEN);
        let mut dst = AlignedBuf::new(SCRATCH_LEN);

        let req_len = {
            let bytes = req.encode_request(src.as_mut_slice())?;
            bytes.len()
        };
        tracing::debug!(
            opcode = T::OPCODE,
            len = req_len,
            "DdiEmu TBOR request (in hex): {:02x?}",
            &src.as_slice()[..req_len]
        );

        // ── 2. Build SQE with OP_TBOR ──────────────────────────────
        let cmd_id = CMD_COUNTER.fetch_add(1, Ordering::Relaxed);
        let req_session_id = req.get_session_id();
        let session_ctrl = req.session_ctrl();
        let sqe = SqeBuilder::new()
            .cmd(CmdDword::new().with_op(OP_TBOR).with_id(cmd_id))
            .buf_lens(req_len as u32, SCRATCH_LEN as u32)
            .src_prp1(src.as_slice().as_ptr() as u64)
            .dst_prp1(dst.as_mut_slice().as_mut_ptr() as u64)
            .session_flags(
                SessionFlags::new()
                    .with_ctrl(u8::from(session_ctrl))
                    .with_id_valid(req_session_id.is_some()),
            )
            .session_id(req_session_id.unwrap_or(0))
            .build();

        let mut raw_cqe = self
            .handle
            .block_on(self.hsm.io(sqe, EMU_PID, 0, 0))
            .map_err(|_| DdiError::DeviceNotReady)?;
        let cqe = Cqe::from(&mut raw_cqe);

        // ── 3. Pre-decode CQE host status ──────────────────────────
        if cqe.status() != 0 {
            tracing::warn!(
                opcode = T::OPCODE,
                status = cqe.status(),
                "DdiEmu TBOR CQE pre-decode error"
            );
            return Err(DdiError::DdiError(cqe.status() as u32));
        }

        // ── 4. Decode the typed response ───────────────────────────
        let resp_len = cqe.dst_len() as usize;
        if resp_len == 0 {
            return Err(DdiError::DdiError(0));
        }
        let resp_buf = &dst.as_slice()[..resp_len];
        tracing::trace!(
            opcode = T::OPCODE,
            len = resp_len,
            "DdiEmu TBOR response (in hex): {:02x?}",
            resp_buf
        );

        <T::OpResp>::decode_response(resp_buf).map_err(Into::into)
    }

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

    fn exec_op_fp_xts(
        &self,
        _mode: DdiAesOp,
        _xts_params: DdiAesXtsParams,
        _src_buf: Vec<u8>,
    ) -> Result<DdiAesXtsResult, DdiError> {
        Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))
    }

    /// Erase the device.
    ///
    /// For the emulator backend, this disables and re-enables the
    /// emulator partition (matching what real hardware does on NSSR)
    /// and clears the session state, returning the device to a clean
    /// state.
    fn erase(&self) -> Result<(), DdiError> {
        // Reset partition state: disable then re-enable. This
        // matches what real hardware does on NSSR.
        self.handle
            .block_on(async {
                self.hsm.part_disable(EMU_PID).await.map_err(|_| ())?;
                self.hsm.part_enable(EMU_PID).await.map_err(|_| ())?;
                Ok::<_, ()>(())
            })
            .map_err(|_| DdiError::DeviceNotReady)?;

        // Clear session state for this device handle.
        let mut session = self.session.lock();
        session.session_id = None;
        session.short_app_id = None;

        Ok(())
    }
}

// ── Helpers ────────────────────────────────────────────────────────

/// Validate a request against the current session state.
///
/// Mirrors `azihsm_ddi_mock::dev::validate_request`. The host driver
/// performs this check too, but doing it here means we surface mismatches
/// as `DdiError` before constructing an SQE.
fn validate_session_request(
    opcode: DdiOp,
    req_session_id: Option<u16>,
    current_session_id: Option<u16>,
) -> Result<(), DdiError> {
    let kind: SessionControlKind = opcode.into();
    match kind {
        SessionControlKind::NoSession => {
            if req_session_id.is_some() {
                Err(DdiError::DdiStatus(DdiStatus::InvalidArg))
            } else {
                Ok(())
            }
        }
        SessionControlKind::Open => match (current_session_id, req_session_id) {
            (None, None) => Ok(()),
            (None, Some(_)) => Err(DdiError::DdiStatus(DdiStatus::InvalidArg)),
            (Some(_), _) => Err(DdiError::DdiStatus(
                DdiStatus::FileHandleSessionLimitReached,
            )),
        },
        SessionControlKind::Close | SessionControlKind::InSession => {
            let Some(current) = current_session_id else {
                return Err(DdiError::DdiStatus(DdiStatus::FileHandleNoExistingSession));
            };
            if Some(current) == req_session_id {
                Ok(())
            } else {
                Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionIdDoesNotMatch,
                ))
            }
        }
    }
}

/// 4-KiB-aligned heap buffer used as DMA scratch space.
///
/// `StdHsmPal` enforces page-aligned source / destination addresses, so
/// the buffers handed to the firmware via SQE PRP fields must originate
/// from a page-aligned allocation. This mirrors the `AlignedBuf` helper
/// in `fw/plat/std/lib/tests/echo_test.rs`.
struct AlignedBuf {
    ptr: *mut u8,
    len: usize,
}

// SAFETY: `AlignedBuf` exclusively owns its allocation and never aliases.
// The pointer is only dereferenced through `as_slice` / `as_mut_slice`
// while `&self` / `&mut self` is held, so standard borrow rules apply.
unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    fn new(len: usize) -> Self {
        let layout =
            std::alloc::Layout::from_size_align(len, PAGE_4K).expect("AlignedBuf: invalid layout");
        // SAFETY: `layout` is non-zero and properly aligned; `alloc_zeroed`
        // returns a valid (or null) pointer for that layout.
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "AlignedBuf: allocation failed");
        Self { ptr, len }
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: pointer + len describe a valid, exclusively owned
        // allocation. Borrow is tied to `&self`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: see `as_slice`. Mutable borrow is tied to `&mut self`.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        let layout = std::alloc::Layout::from_size_align(self.len, PAGE_4K)
            .expect("AlignedBuf: invalid layout on drop");
        // SAFETY: `ptr` was returned by `alloc_zeroed` with the same `layout`.
        unsafe { std::alloc::dealloc(self.ptr, layout) };
    }
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_interface::Ddi;
    use azihsm_ddi_interface::DdiDev;
    use azihsm_ddi_mbor_types::DdiApiRev;
    use azihsm_ddi_mbor_types::DdiGetApiRevCmdReq;
    use azihsm_ddi_mbor_types::DdiGetApiRevReq;
    use azihsm_ddi_mbor_types::DdiOp;
    use azihsm_ddi_mbor_types::DdiReqHdr;
    use azihsm_ddi_tbor_types::TborApiRevReq;
    use azihsm_ddi_tbor_types::TborApiRevResp;

    use crate::DdiEmu;
    use crate::EMU_DEVICE_PATH;

    #[test]
    fn get_api_rev_round_trips_through_emulator() {
        let ddi = DdiEmu::default();
        let dev = ddi.open_dev(EMU_DEVICE_PATH).expect("open emu device");

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
            .expect("GetApiRev should succeed against the emulator");

        assert_eq!(resp.hdr.op, DdiOp::GetApiRev);
        assert_eq!(
            resp.data.min,
            DdiApiRev { major: 1, minor: 0 },
            "firmware should report min api rev 1.0",
        );
        assert_eq!(
            resp.data.max,
            DdiApiRev { major: 1, minor: 0 },
            "firmware should report max api rev 1.0",
        );
    }

    #[test]
    fn get_api_rev_tbor_round_trips_through_emulator() {
        let ddi = DdiEmu::default();
        let dev = ddi.open_dev(EMU_DEVICE_PATH).expect("open emu device");

        let req = TborApiRevReq::new();
        let mut cookie = None;
        let resp = dev
            .exec_op_tbor(&req, &mut cookie)
            .expect("TBOR GetApiRev should succeed against the emulator");

        assert_eq!(
            resp,
            TborApiRevResp {
                min_ver: 1,
                max_ver: 1,
            }
        );
    }
}
