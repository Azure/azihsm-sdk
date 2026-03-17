// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI Implementation - Simulator Service Client - Device Module

use std::io::{BufReader, BufWriter};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use azihsm_ddi_interface::*;
use azihsm_ddi_mbor::MborDecode;
use azihsm_ddi_mbor::MborDecoder;
use azihsm_ddi_mbor::MborEncoder;
use azihsm_ddi_sim::aesgcmxts::*;
use azihsm_ddi_sim::crypto::aes::AesMode;
use azihsm_ddi_sim_service::protocol::*;
use azihsm_ddi_types::DdiAesOp;
use azihsm_ddi_types::DdiDecoder;
use azihsm_ddi_types::DdiDeviceKind;
use azihsm_ddi_types::DdiOp;
use azihsm_ddi_types::DdiOpReq;
use azihsm_ddi_types::DdiOpenSessionCmdResp;
use azihsm_ddi_types::DdiRespHdr;
use azihsm_ddi_types::DdiStatus;
use azihsm_ddi_types::MborError;
use azihsm_ddi_types::SessionControlKind;
use azihsm_ddi_types::SessionInfoRequest;
use parking_lot::Mutex;

/// Default socket path.
const DEFAULT_SOCKET_PATH: &str = "/tmp/azihsm-sim.sock";

/// Environment variable to override the socket path.
const SOCKET_PATH_ENV: &str = "AZIHSM_SIM_SOCKET";

const AES_CHUNK_SIZE: usize = 0x1000;

#[derive(Debug)]
struct SessionIdInner {
    pub session_id: Option<u16>,
    pub short_app_id: Option<u8>,
}

/// Connection to the sim-service, protected by a mutex for thread safety.
struct ServiceConnection {
    writer: BufWriter<UnixStream>,
    reader: BufReader<UnixStream>,
}

impl std::fmt::Debug for ServiceConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceConnection").finish()
    }
}

/// DDI device implementation that communicates with an external sim-service
/// process over a Unix Domain Socket.
#[derive(Debug)]
pub struct DdiSimServiceDev {
    session_id: Arc<Mutex<SessionIdInner>>,
    connection: Arc<Mutex<ServiceConnection>>,
}

impl Clone for DdiSimServiceDev {
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id.clone(),
            connection: self.connection.clone(),
        }
    }
}

impl DdiSimServiceDev {
    /// Resolve the socket path from the environment or use default.
    pub fn socket_path() -> String {
        std::env::var(SOCKET_PATH_ENV).unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string())
    }

    /// Open a connection to the sim-service.
    ///
    /// Accepts paths of the form:
    /// - `sim-service:` — use default/env socket path
    /// - `sim-service:/path/to/socket` — use explicit path
    pub(crate) fn open(path: &str) -> DdiResult<Self> {
        tracing::debug!("Opening DdiSimServiceDev for path: {}", path);

        let socket_path = if let Some(stripped) = path.strip_prefix("sim-service:") {
            if stripped.is_empty() {
                Self::socket_path()
            } else {
                stripped.to_string()
            }
        } else {
            return Err(DdiError::DeviceNotFound);
        };

        let stream = UnixStream::connect(&socket_path).map_err(|e| {
            tracing::error!("Failed to connect to sim-service at {}: {}", socket_path, e);
            DdiError::DeviceNotFound
        })?;

        let read_stream = stream.try_clone().map_err(|e| {
            tracing::error!("Failed to clone stream: {}", e);
            DdiError::IoError(e)
        })?;

        let connection = ServiceConnection {
            writer: BufWriter::new(stream),
            reader: BufReader::new(read_stream),
        };

        tracing::info!("Connected to sim-service at {}", socket_path);

        Ok(Self {
            session_id: Arc::new(Mutex::new(SessionIdInner {
                session_id: None,
                short_app_id: None,
            })),
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Returns the device kind (Virtual).
    pub fn device_kind(&self) -> Option<DdiDeviceKind> {
        Some(DdiDeviceKind::Virtual)
    }

    /// Send a request and read the response, handling ManticoreError responses.
    fn send_and_recv(conn: &mut ServiceConnection) -> Result<Response, DdiError> {
        let resp = read_response(&mut conn.reader).map_err(|e| {
            tracing::error!("Failed to read response from sim-service: {}", e);
            DdiError::IoError(e)
        })?;

        if let Response::Error { error, .. } = &resp {
            return Err(DdiError::DdiStatus(DdiStatus::from(*error)));
        }

        Ok(resp)
    }
}

impl Drop for DdiSimServiceDev {
    fn drop(&mut self) {
        tracing::debug!("Dropping DdiSimServiceDev");
        if let Some(session_id) = self.session_id.lock().session_id {
            let mut conn = self.connection.lock();
            if let Err(e) = write_flush_session_request(&mut conn.writer, session_id) {
                tracing::warn!("Failed to send flush_session on drop: {}", e);
                return;
            }
            // Read the response but don't fail hard on errors during drop
            match read_response(&mut conn.reader) {
                Ok(Response::Ok { .. }) => {}
                Ok(Response::Error { error, .. }) => {
                    tracing::warn!("flush_session returned error on drop: {:?}", error);
                }
                Ok(_) => {
                    tracing::warn!("Unexpected response to flush_session on drop");
                }
                Err(e) => {
                    tracing::warn!("Failed to read flush_session response on drop: {}", e);
                }
            }
        } else {
            tracing::warn!("DdiSimServiceDev session_id is None during drop()");
        }
    }
}

/// Validate the request opcode against current device state.
/// Mirrors the same logic as `ddi/mock/src/dev.rs::validate_request`.
fn validate_request(
    opcode_in_req: DdiOp,
    session_id_in_req: Option<u16>,
    current_session_id: Option<u16>,
) -> Result<(), DdiError> {
    match opcode_in_req.into() {
        SessionControlKind::NoSession => {
            if session_id_in_req.is_some() {
                Err(DdiError::DdiStatus(DdiStatus::InvalidArg))
            } else {
                Ok(())
            }
        }
        SessionControlKind::Open => {
            if current_session_id.is_none() {
                if session_id_in_req.is_some() {
                    Err(DdiError::DdiStatus(DdiStatus::InvalidArg))
                } else {
                    Ok(())
                }
            } else {
                Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionLimitReached,
                ))
            }
        }
        SessionControlKind::Close | SessionControlKind::InSession => {
            if current_session_id.is_none() {
                return Err(DdiError::DdiStatus(DdiStatus::FileHandleNoExistingSession));
            }
            if current_session_id == session_id_in_req {
                Ok(())
            } else {
                Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionIdDoesNotMatch,
                ))
            }
        }
    }
}

impl DdiDev for DdiSimServiceDev {
    fn set_device_kind(&mut self, kind: DdiDeviceKind) {
        assert_eq!(kind, DdiDeviceKind::Virtual);
    }

    fn exec_op<T: DdiOpReq>(
        &self,
        req: &T,
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        const REQ_BUF_LEN: usize = 8192;

        // Validate the request against the device state
        validate_request(
            req.get_opcode(),
            req.get_session_id(),
            self.session_id.lock().session_id,
        )?;

        let session_info_request = SessionInfoRequest {
            session_control_kind: req.get_opcode().into(),
            session_id: req.get_session_id(),
        };

        // Virtual device: no pre-encode/post-decode
        let (pre_encode, post_decode) = (false, false);

        let mut req_buf = [0u8; REQ_BUF_LEN];
        let mut encoder = MborEncoder::new(&mut req_buf, pre_encode);
        req.mbor_encode(&mut encoder)
            .map_err(|_| DdiError::MborError(MborError::EncodeError))?;

        let req_buf_len = encoder.position();
        let req_buf = &req_buf[..req_buf_len];

        tracing::debug!(opcode = ?req.get_opcode(), "Request Buffer (in hex): {:02x?}", req_buf);

        // Send request over UDS
        let mut conn = self.connection.lock();
        write_slow_path_request(&mut conn.writer, &session_info_request, req_buf).map_err(|e| {
            tracing::error!("Failed to send request to sim-service: {}", e);
            DdiError::IoError(e)
        })?;

        // Read response
        let resp = Self::send_and_recv(&mut conn)?;
        drop(conn);

        let (session_info_response, resp_buf) = match resp {
            Response::SlowPath {
                session_info_response,
                resp_buf,
            } => (session_info_response, resp_buf),
            _ => {
                tracing::error!("Unexpected response type for slow-path request");
                return Err(DdiError::DdiError(0));
            }
        };

        let resp_len = session_info_response.response_length as usize;
        tracing::debug!(opcode = ?req.get_opcode(), "Response Buffer (in hex): {:02x?}", &resp_buf[..resp_len]);

        let mut decoder = DdiDecoder::new(&resp_buf[..resp_len], post_decode);
        let hdr = decoder
            .decode_hdr::<DdiRespHdr>()
            .map_err(|_| DdiError::MborError(MborError::DecodeError))?;

        if hdr.status != DdiStatus::Success {
            return Err(DdiError::DdiStatus(hdr.status));
        }

        match session_info_response.session_control_kind {
            SessionControlKind::Open => self.session_id.lock().session_id = hdr.sess_id,
            SessionControlKind::Close => {
                self.session_id.lock().session_id = None;
            }
            _ => (),
        }

        let mut decoder = MborDecoder::new(&resp_buf[..resp_len], post_decode);
        let resp = <T::OpResp>::mbor_decode(&mut decoder)
            .map_err(|_| DdiError::MborError(MborError::DecodeError))?;

        // Intercept OpenSession to capture short_app_id
        if req.get_opcode() == DdiOp::OpenSession {
            let mut open_session_decoder = MborDecoder::new(&resp_buf[..resp_len], post_decode);
            let open_resp = DdiOpenSessionCmdResp::mbor_decode(&mut open_session_decoder)
                .map_err(|_| DdiError::MborError(MborError::DecodeError))?;
            self.session_id.lock().short_app_id = Some(open_resp.data.short_app_id);
        }

        Ok(resp)
    }

    fn exec_op_fp_gcm_slice(
        &self,
        mode: DdiAesOp,
        gcm_params: DdiAesGcmParams,
        src_buf: &[u8],
        dst_buf: &mut [u8],
        tag: &mut Option<[u8; 16]>,
        iv: &mut Option<[u8; 12]>,
        fips_approved: &mut bool,
    ) -> Result<usize, DdiError> {
        let encrypt_decrypt_mode: AesMode =
            mode.try_into().map_err(|_| DdiError::InvalidParameter)?;

        // Check session id
        let current_session_id = self
            .session_id
            .lock()
            .session_id
            .ok_or(DdiError::DdiStatus(DdiStatus::FileHandleNoExistingSession))?;

        if current_session_id != gcm_params.session_id {
            return Err(DdiError::DdiStatus(
                DdiStatus::FileHandleSessionIdDoesNotMatch,
            ));
        }

        if mode == DdiAesOp::Decrypt && gcm_params.tag.is_none() {
            return Err(DdiError::DdiStatus(DdiStatus::NoTagProvided));
        }

        if dst_buf.len() < src_buf.len() {
            tracing::error!(
                "Destination buffer size ({}) is less than source buffer size ({})",
                dst_buf.len(),
                src_buf.len()
            );
            return Err(DdiError::InvalidParameter);
        }

        // Split source into chunks
        let (source_buffers, _) = if src_buf.is_empty() {
            (vec![Vec::new()], vec![Vec::new()])
        } else {
            let source_buffers: Vec<Vec<u8>> = src_buf
                .chunks(AES_CHUNK_SIZE)
                .map(|chunk| chunk.to_vec())
                .collect();
            let destination_buffers: Vec<Vec<u8>> = source_buffers
                .iter()
                .map(|inner| vec![0; inner.len()])
                .collect();
            (source_buffers, destination_buffers)
        };

        let session_aes_gcm_request = SessionAesGcmRequest {
            key_id: gcm_params.key_id,
            iv: gcm_params.iv,
            tag: gcm_params.tag,
            session_id: gcm_params.session_id,
            short_app_id: gcm_params.short_app_id,
            aad: gcm_params.aad,
        };

        // Send over UDS
        let mut conn = self.connection.lock();
        write_fp_gcm_request(
            &mut conn.writer,
            &encrypt_decrypt_mode,
            &session_aes_gcm_request,
            &source_buffers,
        )
        .map_err(|e| {
            tracing::error!("Failed to send FP GCM request: {}", e);
            DdiError::IoError(e)
        })?;

        let resp = Self::send_and_recv(&mut conn)?;
        drop(conn);

        let (result, destination_buffers) = match resp {
            Response::FpGcm {
                response,
                destination_buffers,
            } => (response, destination_buffers),
            Response::Error { error, .. } => {
                return Err(DdiError::DdiStatus(DdiStatus::from(error)));
            }
            _ => {
                tracing::error!("Unexpected response type for FP GCM request");
                return Err(DdiError::DdiError(0));
            }
        };

        let total_size = result.total_size as usize;

        if total_size > dst_buf.len() {
            if mode == DdiAesOp::Encrypt {
                tracing::error!(
                    "AES GCM Encrypt: output length ({}) > destination buffer size ({})",
                    total_size,
                    dst_buf.len()
                );
                return Err(DdiError::DdiStatus(DdiStatus::AesEncryptFailed));
            } else {
                tracing::error!(
                    "AES GCM Decrypt: output length ({}) > destination buffer size ({})",
                    total_size,
                    dst_buf.len()
                );
                return Err(DdiError::DdiStatus(DdiStatus::AesDecryptFailed));
            }
        }

        // Copy destination buffers into dst_buf
        let mut offset = 0;
        for chunk in destination_buffers {
            if offset >= total_size {
                break;
            }
            let chunk_len = chunk.len();
            let remaining = total_size - offset;
            let copy_len = std::cmp::min(chunk_len, remaining);
            dst_buf[offset..offset + copy_len].copy_from_slice(&chunk[..copy_len]);
            offset += copy_len;
        }

        *tag = result.tag;
        *iv = result.iv;
        *fips_approved = result.fips_approved;

        Ok(total_size)
    }

    fn exec_op_fp_gcm(
        &self,
        mode: DdiAesOp,
        gcm_params: DdiAesGcmParams,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesGcmResult, DdiError> {
        let mut dst_buf = vec![0u8; src_buf.len()];
        let mut fips_approved = false;
        let mut tag_out = None;
        let mut iv_out = None;

        let total_size = self.exec_op_fp_gcm_slice(
            mode,
            gcm_params,
            &src_buf,
            &mut dst_buf,
            &mut tag_out,
            &mut iv_out,
            &mut fips_approved,
        )?;

        dst_buf.truncate(total_size);

        Ok(DdiAesGcmResult {
            tag: tag_out,
            data: dst_buf,
            fips_approved,
            iv: iv_out,
        })
    }

    fn exec_op_fp_xts_slice(
        &self,
        mode: DdiAesOp,
        xts_params: DdiAesXtsParams,
        src_buf: &[u8],
        dst_buf: &mut [u8],
        fips_approved: &mut bool,
    ) -> Result<usize, DdiError> {
        let encrypt_decrypt_mode: AesMode =
            mode.try_into().map_err(|_| DdiError::InvalidParameter)?;

        if src_buf.is_empty() {
            return Err(DdiError::InvalidParameter);
        }

        // Check session id
        let current_session_id = self
            .session_id
            .lock()
            .session_id
            .ok_or(DdiError::DdiStatus(DdiStatus::FileHandleNoExistingSession))?;

        if current_session_id != xts_params.session_id {
            return Err(DdiError::DdiStatus(
                DdiStatus::FileHandleSessionIdDoesNotMatch,
            ));
        }

        // Validate data unit length
        let dul_valid = xts_params.data_unit_len == src_buf.len()
            || [512, 4096, 8192].contains(&xts_params.data_unit_len);

        if !dul_valid {
            tracing::error!(
                "FP AES XTS: Data unit length ({}) is not valid. Src buffer size: {}",
                xts_params.data_unit_len,
                src_buf.len()
            );
            return Err(DdiError::InvalidParameter);
        }

        if !src_buf.len().is_multiple_of(xts_params.data_unit_len) {
            tracing::error!(
                "Src buffer size ({}) not multiple of data unit length ({}).",
                src_buf.len(),
                xts_params.data_unit_len,
            );
            return Err(DdiError::InvalidParameter);
        }

        if dst_buf.len() < src_buf.len() {
            tracing::error!(
                "Destination buffer size ({}) is less than source buffer size ({})",
                dst_buf.len(),
                src_buf.len()
            );
            return Err(DdiError::InvalidParameter);
        }

        // Split into chunks by data unit length
        let source_buffers: Vec<Vec<u8>> = src_buf
            .chunks(xts_params.data_unit_len)
            .map(|chunk| chunk.to_vec())
            .collect();

        let session_aes_xts_request = SessionAesXtsRequest {
            data_unit_len: xts_params.data_unit_len,
            key_id1: xts_params.key_id1,
            key_id2: xts_params.key_id2,
            tweak: xts_params.tweak,
            session_id: xts_params.session_id,
            short_app_id: xts_params.short_app_id,
        };

        // Send over UDS
        let mut conn = self.connection.lock();
        write_fp_xts_request(
            &mut conn.writer,
            &encrypt_decrypt_mode,
            &session_aes_xts_request,
            &source_buffers,
        )
        .map_err(|e| {
            tracing::error!("Failed to send FP XTS request: {}", e);
            DdiError::IoError(e)
        })?;

        let resp = Self::send_and_recv(&mut conn)?;
        drop(conn);

        let (result, destination_buffers) = match resp {
            Response::FpXts {
                response,
                destination_buffers,
            } => (response, destination_buffers),
            Response::Error { error, .. } => {
                return Err(DdiError::DdiStatus(DdiStatus::from(error)));
            }
            _ => {
                tracing::error!("Unexpected response type for FP XTS request");
                return Err(DdiError::DdiError(0));
            }
        };

        let total_size = result.total_size as usize;

        if total_size > dst_buf.len() {
            if mode == DdiAesOp::Encrypt {
                tracing::error!(
                    "AES XTS Encrypt: output length ({}) > destination buffer size ({})",
                    total_size,
                    dst_buf.len()
                );
                return Err(DdiError::DdiStatus(DdiStatus::AesEncryptFailed));
            } else {
                tracing::error!(
                    "AES XTS Decrypt: output length ({}) > destination buffer size ({})",
                    total_size,
                    dst_buf.len()
                );
                return Err(DdiError::DdiStatus(DdiStatus::AesDecryptFailed));
            }
        }

        // Copy destination buffers into dst_buf
        let mut offset = 0;
        for chunk in destination_buffers {
            if offset >= total_size {
                break;
            }
            let chunk_len = chunk.len();
            let remaining = total_size - offset;
            let copy_len = std::cmp::min(chunk_len, remaining);
            dst_buf[offset..offset + copy_len].copy_from_slice(&chunk[..copy_len]);
            offset += copy_len;
        }

        *fips_approved = result.fips_approved;

        Ok(total_size)
    }

    fn exec_op_fp_xts(
        &self,
        mode: DdiAesOp,
        xts_params: DdiAesXtsParams,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesXtsResult, DdiError> {
        let mut dst_buf = vec![0u8; src_buf.len()];
        let mut fips_approved = false;

        let total_size = self.exec_op_fp_xts_slice(
            mode,
            xts_params,
            &src_buf,
            &mut dst_buf,
            &mut fips_approved,
        )?;

        dst_buf.truncate(total_size);

        Ok(DdiAesXtsResult {
            data: dst_buf,
            fips_approved,
        })
    }

    fn simulate_nssr_after_lm(&self) -> Result<(), DdiError> {
        let mut conn = self.connection.lock();
        write_migration_sim_request(&mut conn.writer).map_err(|e| {
            tracing::error!("Failed to send migration_sim request: {}", e);
            DdiError::IoError(e)
        })?;

        let resp = Self::send_and_recv(&mut conn)?;
        match resp {
            Response::Ok { .. } => Ok(()),
            Response::Error { error, .. } => Err(DdiError::DdiStatus(DdiStatus::from(error))),
            _ => {
                tracing::error!("Unexpected response type for migration_sim");
                Err(DdiError::DdiError(0))
            }
        }
    }
}
