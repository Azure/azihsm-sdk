// Copyright (C) Microsoft Corporation. All rights reserved.

//! DDI Implementation - MCR Mock Device - Device Module

use std::sync::Arc;

use azihsm_ddi_interface::*;
use azihsm_ddi_mbor::MborDecode;
use azihsm_ddi_mbor::MborDecoder;
use azihsm_ddi_mbor::MborEncoder;
use azihsm_ddi_sim::aesgcmxts::*;
use azihsm_ddi_sim::crypto::aes::AesMode;
use azihsm_ddi_sim::dispatcher::Dispatcher;
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
use lazy_static::lazy_static;
use parking_lot::Mutex;
use parking_lot::RwLock;

#[derive(Debug)]
struct SessionIdInner {
    pub session_id: Option<u16>,
    pub short_app_id: Option<u8>,
}

/// DDI Implementation - MCR Mock Device
#[derive(Debug, Clone)]
pub struct DdiMockDev {
    session_id: Arc<Mutex<SessionIdInner>>,
    // Dispatcher instance
    dispatcher: Arc<RwLock<Dispatcher>>,
}

#[cfg(feature = "table-4")]
const TABLE_COUNT: usize = 4;
#[cfg(feature = "table-64")]
const TABLE_COUNT: usize = 64;
#[cfg(not(any(feature = "table-4", feature = "table-64")))]
const TABLE_COUNT: usize = 1;

const AES_CHUNK_SIZE: usize = 0x1000;

lazy_static! {
    static ref G_DISPATCHER: Arc<RwLock<Dispatcher>> = Arc::new(RwLock::new(
        #[allow(
            clippy::expect_used,
            reason = "lazy_static G_DISPATCHER creation should not fail"
        )]
        Dispatcher::new(TABLE_COUNT).expect("Failed to create lazy_static G_DISPATCHER")
    ));
}

impl DdiMockDev {
    pub(crate) fn open(path: &str) -> DdiResult<Self> {
        tracing::debug!("Opening DdiMockDev");

        // Check if the path is "/dev/mcr-hsm-mock"
        if path != "/dev/mcr-hsm-mock" {
            return Err(DdiError::DeviceNotFound);
        }

        Ok(Self {
            session_id: Arc::new(Mutex::new(SessionIdInner {
                session_id: None,
                short_app_id: None,
            })),
            dispatcher: G_DISPATCHER.clone(),
        })
    }
}

impl Drop for DdiMockDev {
    fn drop(&mut self) {
        tracing::debug!("Dropping DdiMockDev");
        if let Some(session_id) = self.session_id.lock().session_id {
            let _resp = self.dispatcher.read().flush_session(session_id);
        } else {
            tracing::warn!("DdiMockDev session_id is None during DdiMockDev::drop()");
        }
    }
}

/// validate_request
/// Parameters :-
///   opcode_in_req. This is the opcode from
///     the DDIReqHdr
///   session_id_in_req. Session id from the
///     the DDIReqHdr
///   current_session_id. This is the session id
///     that the Mock device currently has within it.
///     This can be None indicating that there is
///     currently no session. Other values indicate a
///     valid session id
///
/// From the opcode, get its Kind (or type)
/// If type of opcode is OpenSession ensure that the device
///    has no current session.
/// If type of opcode is NoSession ensure that the caller
///    has not provided a session id as part of parameters
/// If type of code is CloseSession or InSession, ensure that the device
///    currently has a valid session and that the session in
///    the Mock Device matches the session id in the request.
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

impl DdiDev for DdiMockDev {
    /// Set Device Kind, to determine encode/decode behavior
    ///
    /// # Arguments
    /// * `type`        - Type of device
    ///
    /// # Error
    /// * `DdiError` - Error encountered?
    fn set_device_kind(&mut self, kind: DdiDeviceKind) {
        assert_eq!(kind, DdiDeviceKind::Virtual);
    }

    /// Execute Operation
    ///
    /// # Arguments
    /// * `req`         - Operation Request
    /// * `cookie`      - Cookie
    ///
    /// # Returns
    /// * `OpReq::Resp` - Operation response
    ///
    /// # Error
    /// * `DdiError` - Error encountered while executing the command
    fn exec_op<T: DdiOpReq>(
        &self,
        req: &T,
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        const REQ_BUF_LEN: usize = 8192;

        // validate the request against the device
        // state
        validate_request(
            req.get_opcode(),
            req.get_session_id(),
            self.session_id.lock().session_id,
        )?;

        // fill up the request buffer with the values
        let session_info_request: SessionInfoRequest = SessionInfoRequest {
            session_control_kind: req.get_opcode().into(),
            session_id: req.get_session_id(),
        };

        // Mock is only used with virtual device, so don't pre-encode/post-decode
        let (pre_encode, post_decode) = (false, false);

        let mut req_buf = [0u8; REQ_BUF_LEN];
        let mut encoder = MborEncoder::new(&mut req_buf, pre_encode);
        req.mbor_encode(&mut encoder)
            .map_err(|_| DdiError::MborError(MborError::EncodeError))?;

        let req_buf_len = encoder.position();
        let req_buf = &req_buf[..req_buf_len];

        tracing::debug!(opcode = ?req.get_opcode(), "Request Buffer (in hex): {:02x?}", req_buf);

        let mut resp_buf = Box::<[u8; 8192]>::new([0u8; 8192]);

        let session_info_response = self
            .dispatcher
            .read()
            .dispatch(session_info_request, req_buf, resp_buf.as_mut_slice())
            .map_err(|err| DdiError::DdiError(err as u32))?;

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

        // Intercept the OpenAppSession response from the device so
        // we can record the short app id (in addition to the session id)
        // Short app id is used for validation in all fast path operations

        if req.get_opcode() == DdiOp::OpenSession {
            let mut open_session_decoder = MborDecoder::new(&resp_buf[..resp_len], post_decode);
            let resp = DdiOpenSessionCmdResp::mbor_decode(&mut open_session_decoder)
                .map_err(|_| DdiError::MborError(MborError::DecodeError))?;
            self.session_id.lock().short_app_id = Some(resp.data.short_app_id);
        }

        Ok(resp)
    }

    /// Execute AES GCM Operation
    ///     on fast path
    /// # Arguments
    /// * `mode`        - Encryption or decryption
    /// * `gcm_params`  - Parameters for the operation
    /// * `src_buf`     - User buffer for encryption or decryption
    ///
    /// # Returns
    /// * `DdiAesGcmResult` - On success
    ///
    /// # Error
    /// * `DdiError` - Error that occurred during operation
    fn exec_op_fp_gcm(
        &self,
        mode: DdiAesOp,
        gcm_params: DdiAesGcmParams,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesGcmResult, DdiError> {
        let encrypt_decrypt_mode: AesMode =
            mode.try_into().map_err(|_| DdiError::InvalidParameter)?;
        if src_buf.is_empty() {
            return Err(DdiError::InvalidParameter);
        }

        // Check the session id in the file handle context
        let current_session_id = self
            .session_id
            .lock()
            .session_id
            .ok_or(DdiError::DdiStatus(DdiStatus::FileHandleNoExistingSession))?;

        if current_session_id != gcm_params.session_id {
            Err(DdiError::DdiStatus(
                DdiStatus::FileHandleSessionIdDoesNotMatch,
            ))?
        }

        // if decryption operation tag must be provided
        if mode == DdiAesOp::Decrypt && gcm_params.tag.is_none() {
            Err(DdiError::DdiStatus(DdiStatus::NoTagProvided))?;
        }

        // Define a closure for splitting vector into chunks given a size
        // All elements in the list of chunks will be the same size except
        // potentially the last one
        let split_vector_into_chunks = |original_vec: Vec<u8>, chunk_size: usize| -> Vec<Vec<u8>> {
            original_vec
                .chunks(chunk_size) // Split the vector into chunks
                .map(|chunk| chunk.to_vec()) // Convert each chunk into a Vec<u8>
                .collect() // Collect the chunks into a Vec<Vec<u8>>
        };

        /* break up the source buffers into chunks of AES_CHUNK_SIZE each
         *  The value of the constant is arbitrary
         */
        let source_buffers = split_vector_into_chunks(src_buf, AES_CHUNK_SIZE);
        let mut destination_buffers: Vec<Vec<u8>> = source_buffers
            .iter()
            .map(|inner| vec![0; inner.len()])
            .collect();

        let session_aes_gcm_request = SessionAesGcmRequest {
            key_id: gcm_params.key_id,
            iv: gcm_params.iv,
            tag: gcm_params.tag,
            session_id: gcm_params.session_id,
            short_app_id: gcm_params.short_app_id,
            aad: gcm_params.aad,
        };

        let result = self.dispatcher.read().dispatch_fp_aes_gcm_encrypt_decrypt(
            encrypt_decrypt_mode,
            session_aes_gcm_request,
            source_buffers,
            &mut destination_buffers,
        );

        let result = result.map_err(|err| DdiError::DdiStatus(DdiStatus::from(err)))?;

        let mut dest_buffer: Vec<u8> = destination_buffers.into_iter().flatten().collect();

        let total_size: usize = result.total_size as usize;

        if total_size > dest_buffer.len() {
            if mode == DdiAesOp::Encrypt {
                tracing::error!(
                    "AES GCM Encrypt: Device output length ({}) is greater than destination buffer size ({})",
                    total_size,
                    dest_buffer.len()
                );
                Err(DdiError::DdiStatus(DdiStatus::AesEncryptFailed))?;
            } else {
                tracing::error!(
                    "AES GCM Decrypt: Device output length ({}) is greater than destination buffer size ({})",
                    total_size,
                    dest_buffer.len()
                );
                Err(DdiError::DdiStatus(DdiStatus::AesDecryptFailed))?;
            }
        }

        if total_size < dest_buffer.len() {
            dest_buffer.truncate(result.total_size as usize);
        }

        let mcr_ddi_aes_gcm_result = DdiAesGcmResult {
            tag: result.tag,
            data: dest_buffer,
            fips_approved: result.fips_approved,
            iv: result.iv,
        };

        Ok(mcr_ddi_aes_gcm_result)
    }

    /// Execute AES XTS Operation on fast path using slice-based buffers
    ///
    /// This is the slice-based variant that writes directly into a caller-provided buffer,
    /// avoiding allocation. The caller must ensure the destination buffer is large enough.
    ///
    /// # Arguments
    /// * `mode`           - Encryption or decryption
    /// * `xts_params`     - Parameters for the operation
    /// * `src_buf`        - Source buffer for encryption or decryption
    /// * `dst_buf`        - Destination buffer to write the result (must be at least src_buf.len())
    /// * `fips_approved`  - Output parameter set to indicate if operation was FIPS approved
    ///
    /// # Returns
    /// * `usize` - Number of bytes written to dst_buf
    ///
    /// # Error
    /// * `DdiError` - Error that occurred during operation
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

        // Check the session id in the file handle context
        let current_session_id = self
            .session_id
            .lock()
            .session_id
            .ok_or(DdiError::DdiStatus(DdiStatus::FileHandleNoExistingSession))?;

        if current_session_id != xts_params.session_id {
            Err(DdiError::DdiStatus(
                DdiStatus::FileHandleSessionIdDoesNotMatch,
            ))?
        }

        // validate data unit length
        // Validate that the data unit length is a valid value
        // At this point, the only valid values are
        // equal to the source buffer length or 512, 4096 or
        // 8192
        let dul_valid = xts_params.data_unit_len == src_buf.len()
            || [512, 4096, 8192].contains(&xts_params.data_unit_len);

        if !dul_valid {
            tracing::error!(
                "FP AES XTS: Data unit length ({}) is not valid. Src buffer size: {}",
                xts_params.data_unit_len,
                src_buf.len()
            );
            Err(DdiError::InvalidParameter)?;
        }

        if !src_buf.len().is_multiple_of(xts_params.data_unit_len) {
            tracing::error!(
                "Src buffer size ({}) not multiple of data unit length ({}).",
                src_buf.len(),
                xts_params.data_unit_len,
            );

            Err(DdiError::InvalidParameter)?;
        }

        // Validate destination buffer size
        if dst_buf.len() < src_buf.len() {
            tracing::error!(
                "Destination buffer size ({}) is less than source buffer size ({})",
                dst_buf.len(),
                src_buf.len()
            );
            Err(DdiError::InvalidParameter)?;
        }

        // Define a closure for splitting slice into chunks given a size
        let split_slice_into_chunks = |slice: &[u8], chunk_size: usize| -> Vec<Vec<u8>> {
            slice
                .chunks(chunk_size) // Split the slice into chunks
                .map(|chunk| chunk.to_vec()) // Convert each chunk into a Vec<u8>
                .collect() // Collect the chunks into a Vec<Vec<u8>>
        };

        /* Break up the source buffer in chunks.
         * Each chunk is size of data unit length
         */
        let source_buffers = split_slice_into_chunks(src_buf, xts_params.data_unit_len);
        let mut destination_buffers: Vec<Vec<u8>> = source_buffers
            .iter()
            .map(|inner| vec![0; inner.len()])
            .collect();

        let session_aes_xts_request = SessionAesXtsRequest {
            data_unit_len: xts_params.data_unit_len,
            key_id1: xts_params.key_id1,
            key_id2: xts_params.key_id2,
            tweak: xts_params.tweak,
            session_id: xts_params.session_id,
            short_app_id: xts_params.short_app_id,
        };

        let result = self.dispatcher.read().dispatch_fp_aes_xts_encrypt_decrypt(
            encrypt_decrypt_mode,
            session_aes_xts_request,
            source_buffers,
            &mut destination_buffers,
        );

        let result = result.map_err(|err| DdiError::DdiStatus(DdiStatus::from(err)))?;

        let total_size: usize = result.total_size as usize;

        if total_size > dst_buf.len() {
            if mode == DdiAesOp::Encrypt {
                tracing::error!(
                "AES XTS Encrypt: Device output length ({}) is greater than destination buffer size ({})",
                total_size,
                dst_buf.len()
            );
                Err(DdiError::DdiStatus(DdiStatus::AesEncryptFailed))?;
            } else {
                tracing::error!(
                "AES XTS Decrypt: Device output length ({}) is greater than destination buffer size ({})",
                total_size,
                dst_buf.len()
            );
                Err(DdiError::DdiStatus(DdiStatus::AesDecryptFailed))?;
            }
        }

        // Copy flattened destination buffers into dst_buf
        let mut offset = 0;
        for chunk in destination_buffers {
            let chunk_len = chunk.len();
            dst_buf[offset..offset + chunk_len].copy_from_slice(&chunk);
            offset += chunk_len;
        }

        *fips_approved = result.fips_approved;

        Ok(total_size)
    }

    /// Execute AES Xts Operation on fast path
    ///
    /// # Arguments
    /// * `mode`        - Encryption or decryption
    /// * `xts_params`  - Parameters for the operation
    /// * `src_buf`     - User buffer for encryption or decryption
    ///
    /// # Returns
    /// * `DdiAesXtsParams` - On success
    ///
    /// # Error
    /// * `DdiError` - Error that occurred during operation
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

        let mcr_ddi_aes_xts_result = DdiAesXtsResult {
            data: dst_buf,
            fips_approved,
        };

        Ok(mcr_ddi_aes_xts_result)
    }

    /// Execute NVMe subsystem reset to help emulate Live Migration
    /// For mock device, we call a migration_sim function on the dispatcher
    ///
    /// # Returns
    /// * `Ok(())` - Successfully sent NSSR Reset Device command
    /// * `Err(DdiError)` - Error occurred while executing the command
    fn simulate_nssr_after_lm(&self) -> Result<(), DdiError> {
        self.dispatcher
            .write()
            .dispatch_migration_sim()
            .map_err(|err| DdiError::DdiError(err as u32))
    }
}
