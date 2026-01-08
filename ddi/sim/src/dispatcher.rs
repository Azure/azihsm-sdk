// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for handling the incoming request, processing them and sending the response back.

use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_mbor::*;
use azihsm_ddi_types::*;
use tracing::instrument;

use crate::aesgcmxts::*;
use crate::credentials::*;
use crate::crypto::aes::*;
use crate::crypto::ecc::EccOp;
use crate::crypto::ecc::EccPrivateOp;
use crate::crypto::rsa::RsaCryptoPadding;
use crate::crypto::rsa::RsaOp;
use crate::crypto::rsa::RsaPrivateOp;
use crate::crypto::sha::sha;
use crate::crypto::sha::HashAlgorithm;
use crate::errors::ManticoreError;
use crate::function::ApiRev;
use crate::function::Function;
use crate::session::RsaOpType;
use crate::sim_crypto_env::BK3_SIZE_BYTES;
use crate::sim_crypto_env::SEALED_BK3_SIZE;
use crate::table::entry::key::Key::*;
use crate::table::entry::Entry;
use crate::table::entry::EntryFlags;
use crate::table::entry::KeyClass;
use crate::table::entry::Kind;
use crate::vault::DEFAULT_VAULT_ID;

macro_rules! dispatch_handler {
    ($dispatch_call:expr, $resp_header:ident) => {
        match $dispatch_call {
            Ok(response_len) => return Ok(response_len),
            Err(err) => {
                if err == ManticoreError::CborEncodeError {
                    Err(err)?;
                } else {
                    $resp_header.status = err.into();
                }
            }
        }
    };
}

impl From<DdiApiRev> for ApiRev {
    fn from(value: DdiApiRev) -> Self {
        ApiRev {
            major: value.major,
            minor: value.minor,
        }
    }
}

/// Handling the incoming request, processing them and sending the response back.
#[derive(Debug)]
pub struct Dispatcher {
    function: Function,
}

impl Dispatcher {
    /// Creates a new instance of Dispatcher.
    ///
    /// # Arguments
    /// * `table_count` - Max number of tables (resource groups) allowed for the virtual function.
    ///
    /// # Returns
    /// * Instance of Dispatcher.
    #[instrument(name = "Dispatcher::new")]
    pub fn new(table_count: usize) -> Result<Self, ManticoreError> {
        tracing::debug!(table_count, "Creating new Dispatcher");

        if table_count == 0 {
            tracing::error!(table_count, "Invalid table count");
            Err(ManticoreError::InvalidArgument)?
        }

        Ok(Self {
            function: Function::new(table_count)?,
        })
    }

    #[instrument(skip_all, fields(sess_id = ?resp_hdr.sess_id))]
    fn send_response<D: MborEncode>(
        &self,
        resp_hdr: DdiRespHdr,
        data: D,
        short_app_id: Option<u8>,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let response = DdiEncoder::encode_parts(resp_hdr, data, out_data, false);

        if let Ok(response_len) = response {
            let session_info_response = SessionInfoResponse {
                session_control_kind: SessionControlKind::from(resp_hdr.op),
                response_length: response_len as u16,
                session_id: if resp_hdr.status == DdiStatus::Success {
                    resp_hdr.sess_id
                } else {
                    None
                },
                short_app_id,
            };
            Ok(session_info_response)
        } else {
            tracing::error!(error = ?ManticoreError::CborEncodeError, opcode = ?resp_hdr.op, sess_id = ?resp_hdr.sess_id, "Failed to encode response");
            Err(ManticoreError::CborEncodeError)
        }
    }

    /// Flushes a session
    /// Flushing means closing the session forcibly
    /// Caller does not know if the session is valid or not
    /// or what type it might be
    /// If session is valid, this function returns SessionInfoResponse
    /// else returns a ManticoreError
    #[instrument(skip(self))]
    pub fn flush_session(&self, session_id: u16) -> Result<SessionInfoResponse, ManticoreError> {
        tracing::debug!(session_id, "Flushing session");
        let mut session_info_response = SessionInfoResponse {
            ..Default::default()
        };

        // Given a valid session id we do not know what type of session it is
        // so iterate through all 3 different types of sessions
        // If session id is valid but it does not match one of the session types
        // return an error ManticoreError

        session_info_response.session_control_kind = SessionControlKind::Close;
        if self.function.get_user_session(session_id, true).is_ok() {
            if self.function.close_user_session(session_id).is_ok() {
                session_info_response.session_id = Some(session_id);
            }
            tracing::debug!(response = ?session_info_response, "flushing VaultAppSession");
            Ok(session_info_response)
        } else {
            tracing::error!(error = ?ManticoreError::InvalidArgument, session_id, "Cannot find any session related to session id");
            Err(ManticoreError::InvalidArgument)
        }
    }

    // validate_session_id
    // Function to validate if the session id carried in the
    // command payload is the same as the session id carried in
    // CBOR header.
    // Either both need to be None or both values need to match
    // else ManticoreError::InvalidArgument is thrown
    fn validate_session_id(
        &self,
        session_id_in_cmd: Option<u16>,
        session_id_in_hdr: Option<u16>,
    ) -> Result<(), ManticoreError> {
        if session_id_in_cmd == session_id_in_hdr {
            Ok(())
        } else {
            Err(ManticoreError::InvalidArgument)
        }
    }

    /// validate_session_opcode
    /// When session validation is supported in commands
    /// and completions, this function can be used
    /// to match the opcode in the session block in the
    /// command to the opcode in the CBOR header that is part
    /// of the command data
    ///
    /// Returns Result<(), ManticoreError>
    /// Parameters
    ///    kind :- Type of opcode carried in command
    ///    opcode_in_hdr :- Opcode in the CBOR header.
    ///
    fn validate_session_opcode(
        &self,
        kind: SessionControlKind,
        opcode_in_hdr: DdiOp,
    ) -> Result<(), ManticoreError> {
        if kind != SessionControlKind::from(opcode_in_hdr) {
            Err(ManticoreError::InvalidArgument)
        } else {
            Ok(())
        }
    }

    /// validate_api_rev
    /// Validates input rev against opcode and session_id.
    /// For GetApiRev, validates revision is None.
    /// For other operations, validates revision is
    /// within revision supported by Function.
    /// For in session commands, validates revision matches
    /// revision at open session.
    ///
    /// Returns Result<(), ManticoreError>
    /// Parameters
    ///    rev_in_hdr :- API rev in the CBOR header.
    ///    opcode_in_hdr :- Opcode in the CBOR header.
    ///    session_id_in_hdr :- sess_id in the CBOR header.
    ///
    fn validate_api_rev(
        &self,
        rev_in_hdr: Option<DdiApiRev>,
        opcode_in_hdr: DdiOp,
        session_id_in_hdr: Option<u16>,
    ) -> Result<(), ManticoreError> {
        // If GetApiRev OpCode, verify rev is None
        if opcode_in_hdr == DdiOp::GetApiRev {
            if rev_in_hdr.is_some() {
                tracing::error!("hdr.rev should be None for GetApiRev");
                Err(ManticoreError::UnsupportedRevision)?
            }
            return Ok(());
        }

        // Otherwise, verify rev is Some
        let rev: ApiRev = rev_in_hdr
            .ok_or_else(|| {
                tracing::error!("hdr.rev should be Some");
                ManticoreError::UnsupportedRevision
            })?
            .into();

        // Verify api revision is within function range
        let rev_range = self.function.get_api_rev_range();
        if rev > rev_range.max || rev < rev_range.min {
            tracing::error!(?rev, ?rev_range, "rev version not supported");
            Err(ManticoreError::UnsupportedRevision)?
        }

        // For in-session Op, verify it matches rev of session unless it needs renegotiation
        let control_kind = SessionControlKind::from(opcode_in_hdr);
        if control_kind == SessionControlKind::InSession
            || control_kind == SessionControlKind::Close
        {
            let session_id = session_id_in_hdr.ok_or_else(|| {
                tracing::error!("session_id should be Some");
                ManticoreError::SessionExpected
            })?;

            let allow_disabled = control_kind == SessionControlKind::Close;
            let session_api_rev = match self
                .function
                .get_user_session_api_rev(session_id, allow_disabled)
            {
                Ok(api_rev) => api_rev,
                // Session migrated, no rev info to check.
                Err(ManticoreError::SessionNeedsRenegotiation) => return Ok(()),
                Err(e) => return Err(e),
            };

            if session_api_rev != rev {
                tracing::error!(
                    ?rev,
                    ?session_api_rev,
                    "API revision doesn't match session api revision"
                );
                Err(ManticoreError::UnsupportedRevision)?
            }
        }

        Ok(())
    }

    /// fp_aes_validate_params
    ///  Validate source and destination buffers
    ///  Validate session id and short app id
    /// passed for AES GCM and XTS operations
    ///     on fast path
    /// # Arguments
    /// * `source_buffers` - Source buffer for encryption or decryption
    /// * `destination_buffers` - Output buffer of the operation
    /// * `session_id` :- Session id (part of GCM or XTS parameters)
    /// * `short_app_id` :- Short app id (GCM or XTS parameters)
    ///
    /// # Returns
    /// * `())` - On success
    ///
    /// # Error
    /// * `ManticoreError::AesGcmInvalidBufSize` - Error.
    ///   Note this function returns ManticoreError::
    ///   AesGcmInvalidBufSize for all buffer errors
    ///   even though this function is called for both GCM
    ///   and XTS flows. Caller must handle this
    ///   correctly
    fn fp_aes_validate_params(
        &self,
        source_buffers: &mut [Vec<u8>],
        destination_buffers: &mut [Vec<u8>],
        session_id: u16,
        short_app_id: u8,
    ) -> Result<(), ManticoreError> {
        if source_buffers.is_empty() {
            tracing::error!("FP AES: Empty source buffer");
            Err(ManticoreError::AesGcmInvalidBufSize)?;
        }

        if destination_buffers.is_empty() {
            tracing::error!("FP AES: Empty destination buffer");
            Err(ManticoreError::AesGcmInvalidBufSize)?;
        }

        // The number of elements in destination buffer must not be less
        // than the number of elements in the source buffer
        if source_buffers.len() > destination_buffers.len() {
            tracing::error!(
                "FP AES. Number of elements in source ({}) does not match the destination ({})",
                source_buffers.len(),
                destination_buffers.len()
            );
            Err(ManticoreError::AesGcmInvalidBufSize)?;
        }

        // verify that each element in source buffer is exactly the same length
        // as destination buffer
        for index in 0..source_buffers.len() {
            if source_buffers[index].len() != destination_buffers[index].len() {
                tracing::error!("FP AES: Elements at position {} in src ({}) and destination ({}) are not same length",
                    index,
                    source_buffers[index].len(),
                    destination_buffers[index].len()
                    );
                Err(ManticoreError::AesGcmInvalidBufSize)?;
            }
        }

        // length of the source and destination buffer must be the same
        let src_buffer_size: usize = source_buffers.iter().map(|buffer| buffer.len()).sum();
        let dst_buffer_size: usize = destination_buffers.iter().map(|buffer| buffer.len()).sum();

        if src_buffer_size > dst_buffer_size {
            tracing::error!(
                "FP AES: Length of src buffer ({}) is greater than destination buffer ({})",
                src_buffer_size,
                dst_buffer_size
            );
            Err(ManticoreError::AesGcmInvalidBufSize)?;
        }

        // validate the session id and short app id
        let app_session = self.function.get_user_session(session_id, false)?;
        if app_session.short_app_id() != short_app_id {
            tracing::error!(
                "FP AES: Input Short app id ({}) is not equal to app session ({})",
                short_app_id,
                app_session.short_app_id()
            );
            Err(ManticoreError::AesInvalidShortAppId)?;
        }

        Ok(())
    }

    fn extract_pub_key(&self, entry: &Entry) -> Result<Option<DdiDerPublicKey>, ManticoreError> {
        const DER_MAX_SIZE: usize = 768;
        let mut der = [0u8; DER_MAX_SIZE];

        let pub_key = match entry.kind() {
            Kind::Rsa2kPrivate
            | Kind::Rsa3kPrivate
            | Kind::Rsa4kPrivate
            | Kind::Rsa2kPrivateCrt
            | Kind::Rsa3kPrivateCrt
            | Kind::Rsa4kPrivateCrt => {
                if let RsaPrivate(priv_key) = entry.key() {
                    let der_vec = priv_key.extract_pub_key_der()?;
                    if der_vec.len() > der.len() {
                        tracing::error!(pub_key_len = ?der_vec.len(), max = ?DER_MAX_SIZE, "Public Key DER size exceeds maximum");
                        Err(ManticoreError::InternalError)?
                    }
                    der[..der_vec.len()].copy_from_slice(&der_vec);
                    Some(DdiDerPublicKey {
                        der: MborByteArray::new(der, der_vec.len())
                            .map_err(|_| ManticoreError::InternalError)?,
                        key_kind: entry.kind().as_pub()?.try_into()?,
                    })
                } else {
                    None
                }
            }

            Kind::Rsa2kPublic | Kind::Rsa3kPublic | Kind::Rsa4kPublic => {
                if let RsaPublic(pub_key) = entry.key() {
                    let der_vec = pub_key.to_der()?;
                    if der_vec.len() > der.len() {
                        tracing::error!(pub_key_len = ?der_vec.len(), max = ?DER_MAX_SIZE, "Public Key DER size exceeds maximum");
                        Err(ManticoreError::InternalError)?
                    }
                    der[..der_vec.len()].copy_from_slice(&der_vec);
                    Some(DdiDerPublicKey {
                        der: MborByteArray::new(der, der_vec.len())
                            .map_err(|_| ManticoreError::InternalError)?,
                        key_kind: entry.kind().as_pub()?.try_into()?,
                    })
                } else {
                    None
                }
            }

            Kind::Ecc256Private | Kind::Ecc384Private | Kind::Ecc521Private => {
                if let EccPrivate(priv_key) = entry.key() {
                    let der_vec = priv_key.extract_pub_key_der()?;
                    if der_vec.len() > der.len() {
                        tracing::error!(pub_key_len = ?der_vec.len(), max = ?DER_MAX_SIZE, "Public Key DER size exceeds maximum");
                        Err(ManticoreError::InternalError)?
                    }
                    der[..der_vec.len()].copy_from_slice(&der_vec);
                    Some(DdiDerPublicKey {
                        der: MborByteArray::new(der, der_vec.len())
                            .map_err(|_| ManticoreError::InternalError)?,
                        key_kind: entry.kind().as_pub()?.try_into()?,
                    })
                } else {
                    None
                }
            }

            Kind::Ecc256Public | Kind::Ecc384Public | Kind::Ecc521Public => {
                if let EccPublic(pub_key) = entry.key() {
                    let der_vec = pub_key.to_der()?;
                    if der_vec.len() > der.len() {
                        tracing::error!(pub_key_len = ?der_vec.len(), max = ?DER_MAX_SIZE, "Public Key DER size exceeds maximum");
                        Err(ManticoreError::InternalError)?
                    }
                    der[..der_vec.len()].copy_from_slice(&der_vec);
                    Some(DdiDerPublicKey {
                        der: MborByteArray::new(der, der_vec.len())
                            .map_err(|_| ManticoreError::InternalError)?,
                        key_kind: entry.kind().as_pub()?.try_into()?,
                    })
                } else {
                    None
                }
            }

            Kind::Aes128 | Kind::Aes192 | Kind::Aes256 => None,
            Kind::AesXtsBulk256 | Kind::AesGcmBulk256 | Kind::AesGcmBulk256Unapproved => None,
            Kind::AesHmac640 => None,
            Kind::Secret256 | Kind::Secret384 | Kind::Secret521 => None,
            Kind::HmacSha256 | Kind::HmacSha384 | Kind::HmacSha512 => None,

            Kind::Session => Err(ManticoreError::InvalidArgument)?,
        };

        Ok(pub_key)
    }

    /// Execute AES GCM Operation
    ///     on fast path
    /// Dispatcher entry point for mock
    /// and device interfaces
    /// # Arguments
    /// * `mode`        - Encryption or decryption
    /// * `gcm_request`  - Parameters for the operation
    /// * `source_buffers` - Source buffer for encryption or decryption
    /// * `destination_buffers` - Output buffer of the operation
    ///
    /// # Returns
    /// * `SessionAesGcmResponse` - On success
    ///
    /// # Error
    /// * `ManticoreError` - Error that occurred during operation
    pub fn dispatch_fp_aes_gcm_encrypt_decrypt(
        &self,
        mode: AesMode,
        gcm_request: SessionAesGcmRequest,
        mut source_buffers: Vec<Vec<u8>>,
        destination_buffers: &mut [Vec<u8>],
    ) -> Result<SessionAesGcmResponse, ManticoreError> {
        tracing::debug!("FP AES GCM {:?}", mode);

        // Perform validation on input and output buffers
        // and session id and short app id
        self.fp_aes_validate_params(
            &mut source_buffers,
            destination_buffers,
            gcm_request.session_id,
            gcm_request.short_app_id,
        )?;

        // Session id and short app id have already been
        // validated above
        let app_session = self
            .function
            .get_user_session(gcm_request.session_id, false)?;

        // verify that the key provided by the caller is valid
        // and allows encrypt/decrypt
        let entry = app_session.get_key_entry(gcm_request.key_id as u16)?;
        if !entry.allow_encrypt_decrypt() {
            tracing::error!(
                ">> Dispatcher: FP AES GCM . Key id {} does not have sufficient permissions",
                gcm_request.key_id
            );
            Err(ManticoreError::InvalidPermissions)?
        }

        tracing::debug!(
            "FP AES GCM {:?}: Invoking app_session:: AES GCM encrypt_decrypt",
            mode
        );
        let result = app_session.fp_aes_gcm_encrypt_decrypt(
            gcm_request.key_id as u16,
            mode,
            &gcm_request.iv,
            gcm_request.aad.as_ref().map(|array| &array[..]),
            gcm_request.tag.as_ref().map(|array| &array[..]),
            source_buffers,
            destination_buffers,
        );

        match result {
            Ok(x) => Ok(SessionAesGcmResponse {
                total_size: x.final_size as u32,
                tag: x.tag,
            }),
            Err(e) => Err(e),
        }
    }

    /// Execute AES XTS Operation
    ///     on fast path
    /// Dispatcher entry point for mock
    /// and device interfaces
    /// # Arguments
    /// * `mode`        - Encryption or decryption
    /// * `xts_request`  - Parameters for the operation
    /// * `source_buffers` - Source buffer for encryption or decryption
    /// * `destination_buffers` - Output buffer of the operation
    ///
    /// # Returns
    /// * `SessionAesXtsResponse` - On success
    ///
    /// # Error
    /// * `ManticoreError` - Error that occurred during operation
    pub fn dispatch_fp_aes_xts_encrypt_decrypt(
        &self,
        mode: AesMode,
        xts_request: SessionAesXtsRequest,
        mut source_buffers: Vec<Vec<u8>>,
        destination_buffers: &mut [Vec<u8>],
    ) -> Result<SessionAesXtsResponse, ManticoreError> {
        tracing::debug!("FP AES XTS {:?}", mode);
        // Perform validation on input and output buffers
        // and session id and short app id
        self.fp_aes_validate_params(
            &mut source_buffers,
            destination_buffers,
            xts_request.session_id,
            xts_request.short_app_id,
        )
        .map_err(|err| {
            if err == ManticoreError::AesGcmInvalidBufSize {
                ManticoreError::AesXtsInvalidBufSize
            } else {
                err
            }
        })?;

        let src_buffer_size: usize = source_buffers.iter().map(|buffer| buffer.len()).sum();

        // Validate that the data unit length is a valid value
        // At this point, the only valid values are
        // equal to the source buffer length or 512, 4096 or
        // 8192
        let dul_valid = xts_request.data_unit_len == src_buffer_size
            || [512, 4096, 8192].contains(&xts_request.data_unit_len);

        if !dul_valid {
            tracing::error!(
                ">> Dispatcher: FP AES XTS . Data unit length{} is not valid. Src buffer size {}",
                xts_request.data_unit_len,
                src_buffer_size
            );
            Err(ManticoreError::AesXtsInvalidDul)?;
        }

        // Session id and short app id have already been
        // validated above
        let app_session = self
            .function
            .get_user_session(xts_request.session_id, false)?;

        // verify that the keys provided by the caller is valid
        // and allows encrypt/decrypt
        let entry_key1 = app_session.get_key_entry(xts_request.key_id1 as u16)?;
        if !entry_key1.allow_encrypt_decrypt() {
            tracing::error!(
                "FP AES XTS {:?}: Key1 ID ({}) does not have sufficient permissions",
                mode,
                xts_request.key_id1
            );
            Err(ManticoreError::InvalidPermissions)?
        }

        let entry_key2 = app_session.get_key_entry(xts_request.key_id2 as u16)?;
        if !entry_key2.allow_encrypt_decrypt() {
            tracing::error!(
                "FP AES XTS {:?}: Key2 ID ({}) does not have sufficient permissions",
                mode,
                xts_request.key_id2
            );
            Err(ManticoreError::InvalidPermissions)?
        }

        tracing::debug!(
            "FP AES XTS {:?}: Invoking app_session:: AES XTS encrypt_decrypt",
            mode
        );
        let result = app_session.fp_aes_xts_encrypt_decrypt(
            mode,
            xts_request.key_id1 as u16,
            xts_request.key_id2 as u16,
            xts_request.tweak,
            xts_request.data_unit_len,
            source_buffers,
            destination_buffers,
        );

        match result {
            Ok(x) => Ok(SessionAesXtsResponse {
                total_size: x.final_size as u32,
            }),
            Err(e) => Err(e),
        }
    }

    /// Simulate live migration for testing
    ///
    /// # Returns
    /// * `Ok(())` - Successfully initiated and completed migration simulation
    /// * `ManticoreError` - Error that occurred during migration simulation
    pub fn dispatch_migration_sim(&self) -> Result<(), ManticoreError> {
        self.function.simulate_migration()
    }

    /// Dispatches the incoming request to the appropriate handler and fill the response buffer.
    ///
    /// # Arguments
    /// *`session_info_request.
    ///      Describes information about the command.
    ///      This information is used to perform session validation.
    ///      The opcode and session id are both optional.
    /// * `in_data` - Incoming request buffer.
    /// * `out_data` - Response buffer.
    ///
    /// # Returns
    /// * Length of the response buffer.
    ///
    /// # Errors
    /// * `ManticoreError::CborEncodeError` - If we were not able to encode the response in CBOR format.
    #[instrument(skip_all, fields(sess_kind = ?session_info_request.session_control_kind,
        sess_id = ?session_info_request.session_id))]
    pub fn dispatch(
        &self,
        session_info_request: SessionInfoRequest,
        in_data: &[u8],
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let mut resp_header = DdiRespHdr {
            rev: None,
            op: DdiOp::Invalid,
            sess_id: None,
            status: DdiStatus::DdiDecodeFailed,
            fips_approved: false,
        };

        let mut decoder = DdiDecoder::new(in_data, false);

        if let Ok(hdr) = decoder.decode_hdr::<DdiReqHdr>() {
            resp_header.rev = hdr.rev;
            resp_header.op = hdr.op;
            resp_header.sess_id = hdr.sess_id;

            if decoder.map_count() != 2 {
                tracing::error!(error = ?ManticoreError::CborDecodeError, "Extensions are not supported");
                Err(ManticoreError::CborDecodeError)?
            }

            // validate the opcode and session id in the cbor header with the values in
            // command payload
            // Since we have to support legacy applications (Legacy applications do not send
            // session id and all opcodes are always 0 which translate to No, check session id
            // only if opcodes are not equal to None
            self.validate_session_opcode(session_info_request.session_control_kind, hdr.op)?;
            if session_info_request.session_control_kind == SessionControlKind::NoSession
                && hdr.sess_id.is_some()
            {
                tracing::error!(error = ?ManticoreError::InvalidArgument, "SessionControlKind::NoSession and session id is not None");
                return Err(ManticoreError::InvalidArgument);
            }
            self.validate_session_id(session_info_request.session_id, hdr.sess_id)?;

            // Validate the api_rev; if there's an error, send error response
            if let Err(err) = self.validate_api_rev(hdr.rev, hdr.op, hdr.sess_id) {
                resp_header.status = err.into();
                return self.send_response(resp_header, DdiErrResp {}, None, out_data);
            }

            tracing::trace!(opcode = ?hdr.op, "Dispatching request");
            match hdr.op {
                DdiOp::GetApiRev => {
                    dispatch_handler!(
                        self.dispatch_get_api_rev(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::GetDeviceInfo => {
                    dispatch_handler!(
                        self.dispatch_get_device_info(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::DeleteKey => {
                    dispatch_handler!(
                        self.dispatch_delete_key(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::OpenKey => {
                    dispatch_handler!(
                        self.dispatch_open_key(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::AttestKey => {
                    dispatch_handler!(
                        self.dispatch_attest_key(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::RsaModExp => {
                    dispatch_handler!(
                        self.dispatch_rsa_mod_exp(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::RsaUnwrap => {
                    dispatch_handler!(
                        self.dispatch_rsa_unwrap(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::GetUnwrappingKey => {
                    dispatch_handler!(
                        self.dispatch_get_unwrapping_key(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::EccGenerateKeyPair => {
                    dispatch_handler!(
                        self.dispatch_ecc_generate_key_pair(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::EccSign => {
                    dispatch_handler!(
                        self.dispatch_ecc_sign(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::EcdhKeyExchange => {
                    dispatch_handler!(
                        self.dispatch_ecdh_key_exchange(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::HkdfDerive => {
                    dispatch_handler!(
                        self.dispatch_hkdf_derive(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::KbkdfCounterHmacDerive => {
                    dispatch_handler!(
                        self.dispatch_kbkdf_counter_hmac_derive(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::Hmac => {
                    dispatch_handler!(
                        self.dispatch_hmac(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::AesGenerateKey => {
                    dispatch_handler!(
                        self.dispatch_aes_generate_key(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::AesEncryptDecrypt => {
                    dispatch_handler!(
                        self.dispatch_aes_encrypt_decrypt(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::GetEstablishCredEncryptionKey => {
                    dispatch_handler!(
                        self.dispatch_get_establish_cred_encryption_key(
                            &mut decoder,
                            &hdr,
                            out_data
                        ),
                        resp_header
                    )
                }

                DdiOp::EstablishCredential => {
                    dispatch_handler!(
                        self.dispatch_establish_credential(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::GetSessionEncryptionKey => {
                    dispatch_handler!(
                        self.dispatch_get_session_encryption_key(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::OpenSession => {
                    dispatch_handler!(
                        self.dispatch_open_session(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::CloseSession => {
                    dispatch_handler!(
                        self.dispatch_close_session(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::ReopenSession => {
                    dispatch_handler!(
                        self.dispatch_reopen_session(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::ChangePin => {
                    dispatch_handler!(
                        self.dispatch_change_pin(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::UnmaskKey => {
                    dispatch_handler!(
                        self.dispatch_unmask_key(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::GetCertChainInfo => {
                    dispatch_handler!(
                        self.dispatch_get_cert_chain_info(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::GetCertificate => {
                    dispatch_handler!(
                        self.dispatch_get_certificate(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::ResetFunction => {
                    dispatch_handler!(
                        self.dispatch_reset_function(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::InitBk3 => {
                    dispatch_handler!(
                        self.dispatch_init_bk3(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::SetSealedBk3 => {
                    dispatch_handler!(
                        self.dispatch_set_sealed_bk3(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::GetSealedBk3 => {
                    dispatch_handler!(
                        self.dispatch_get_sealed_bk3(&mut decoder, &hdr, out_data),
                        resp_header
                    )
                }

                DdiOp::Invalid => {
                    resp_header.status = DdiStatus::UnsupportedCmd;
                }

                _ => {
                    resp_header.status = DdiStatus::UnsupportedCmd;
                }
            }
        }

        self.send_response(resp_header, DdiErrResp {}, None, out_data)
    }

    fn dispatch_get_api_rev(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        decoder
            .decode_data::<DdiGetApiRevReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let rev_range = self.function.get_api_rev_range();

        let resp = DdiGetApiRevResp {
            min: DdiApiRev {
                major: rev_range.min.major,
                minor: rev_range.min.minor,
            },
            max: DdiApiRev {
                major: rev_range.max.major,
                minor: rev_range.max.minor,
            },
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_get_device_info(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        decoder
            .decode_data::<DdiGetDeviceInfoReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let resp = DdiGetDeviceInfoResp {
            kind: DdiDeviceKind::Virtual,
            tables: self.function.tables_max() as u8,
            fips_approved: false,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_delete_key(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiDeleteKeyReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;
        let span = tracing::info_span!("AppSession", session_id = ?app_session.id());
        let _guard = span.enter();

        app_session.delete_key(req.key_id)?;
        tracing::debug!("Deleted key with ID: {}", req.key_id);

        let resp = DdiDeleteKeyResp {};

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_open_key(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiOpenKeyReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;
        let span = tracing::info_span!("AppSession", session_id = ?app_session.id());
        let _guard = span.enter();

        let key_num = app_session.get_key_num_by_tag(req.key_tag)?;
        let entry = app_session.get_key_entry(key_num)?;

        let pub_key = self.extract_pub_key(&entry)?;

        let bulk_key_id = if entry.kind().is_bulk_key() {
            Some(key_num)
        } else {
            None
        };

        let resp = DdiOpenKeyResp {
            key_id: key_num,
            key_kind: entry.kind().try_into()?,
            pub_key,
            bulk_key_id,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_attest_key(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiAttestKeyReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;
        let span = tracing::info_span!("AppSession", session_id = ?app_session.id());
        let _guard = span.enter();

        let (report, report_len) = app_session.attest_key(req.key_id, req.report_data.data())?;
        tracing::debug!("Attested key with ID: {}", req.key_id);

        let resp = DdiAttestKeyResp {
            report: MborByteArray::new(report, report_len)
                .map_err(|_| ManticoreError::InternalError)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_rsa_mod_exp(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiRsaModExpReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;
        let span = tracing::info_span!("AppSession", session_id = ?app_session.id());
        let _guard = span.enter();

        let vec_x = app_session.rsa_private(
            req.key_id,
            &req.y.data()[..req.y.len()],
            req.op_type.try_into()?,
        )?;

        let mut x = [0u8; 512];
        x[..vec_x.len()].copy_from_slice(vec_x.as_slice());

        let resp = DdiRsaModExpResp {
            x: MborByteArray::new(x, vec_x.len()).map_err(|_| ManticoreError::InternalError)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_rsa_unwrap(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiRsaUnwrapReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;
        let span = tracing::info_span!("AppSession", session_id = ?app_session.id());
        let _guard = span.enter();

        let unwrapping_key_entry = app_session.get_key_entry(req.key_id)?;

        if !unwrapping_key_entry.allow_unwrap() {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, "Key does not allow unwrap");
            Err(ManticoreError::InvalidPermissions)?
        }

        // Disallow named keys for session keys.
        if req.key_properties.key_metadata.session() && req.key_tag.is_some() {
            tracing::error!(error = ?ManticoreError::InvalidArgument, "Named keys are not allowed for session keys");
            Err(ManticoreError::InvalidArgument)?
        }

        // Make sure the provided wrapped blob data has a length field that
        // does not exceed the actual length of its internal buffer.
        let req_wrapped_blob_data = req.wrapped_blob.data();
        if req.wrapped_blob.len() > req_wrapped_blob_data.len() {
            tracing::error!(error = ?ManticoreError::RsaUnwrapInvalidReq, wrapped_blob_len = ?req.wrapped_blob.len(), "Invalid wrapped_blob_len");
            Err(ManticoreError::RsaUnwrapInvalidReq)?
        }

        // Unwrap the CKM_HSM_RSA_AES_KEY_WRAP blob which has the following format: RSA(AES)|AES(CMK_DER)
        let wrapped_blob = req_wrapped_blob_data[..req.wrapped_blob.len()].to_vec();
        let padding = req.wrapped_blob_padding;
        let hash_algorithm = Some(req.wrapped_blob_hash_algorithm.try_into()?);

        let unwrapping_key_modulus_size = match unwrapping_key_entry.kind() {
            Kind::Rsa2kPrivate => 2048 / 8,
            Kind::Rsa3kPrivate => 3072 / 8,
            Kind::Rsa4kPrivate => 4096 / 8,
            _ => {
                tracing::error!(error = ?ManticoreError::InvalidArgument, "Key type is not RSA private non crt");
                Err(ManticoreError::RsaUnwrapInvalidUnwrappingKeyLength)?
            }
        };

        // Make sure the wrapped blob data has enough bytes to cover the
        // unwrapping key's modulus size (if we don't have enough, the below
        // slice will fail).
        if wrapped_blob.len() < unwrapping_key_modulus_size {
            tracing::error!(error = ?ManticoreError::RsaUnwrapInvalidReq, wrapped_blob_len = ?req.wrapped_blob.len(), "Provided wrapped_blob data does not contain enough bytes");
            Err(ManticoreError::RsaUnwrapInvalidReq)?
        }

        let ephemeral_aes_encrypted = &wrapped_blob[..unwrapping_key_modulus_size];
        let ephemeral_aes = app_session
            .rsa_decrypt(
                req.key_id,
                ephemeral_aes_encrypted,
                padding.try_into()?,
                hash_algorithm,
            )
            .map_err(|_| ManticoreError::RsaUnwrapRsaOaepDecryptFailed)?;
        tracing::debug!(
            ephemeral_aes_len = ephemeral_aes.len(),
            "Completed app_session.rsa_decrypt()"
        );

        // Decrypt the target key with the ephemeral AES key using AES-KW2.
        let target_key_aes_encrypted = &wrapped_blob[unwrapping_key_modulus_size..];
        let key = AesKey::from_bytes(&ephemeral_aes)?;
        let result = key
            .unwrap_pad(target_key_aes_encrypted)
            .map_err(|_| ManticoreError::RsaUnwrapAesUnwrapFailed)?;

        // Save the unwrapped key (PKCS#8 DER format) to the vault.
        // TODO: there're code repeat below from dispatch_der_key_import
        tracing::debug!("Saving the unwrapped key (PKCS#8 DER format) to the vault");
        let mut flags = EntryFlags::new().with_imported(true);

        let key_class: KeyClass = req.wrapped_blob_key_class.try_into()?;

        let usage = req
            .key_properties
            .key_metadata
            .try_into()
            .map_err(|_| ManticoreError::InvalidPermissions)?;

        if !key_class.allows_usage(usage) {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, key_class = ?key_class, key_usage = ?usage, "Key type doesn't allow this key usage");
            Err(ManticoreError::InvalidPermissions)?
        }

        match usage {
            DdiKeyUsage::SignVerify => flags.set_allow_sign_verify(true),
            DdiKeyUsage::EncryptDecrypt => flags.set_allow_encrypt_decrypt(true),
            DdiKeyUsage::Unwrap => flags.set_allow_unwrap(true),
            DdiKeyUsage::Derive => flags.set_allow_derive(true),
            _ => Err(ManticoreError::InvalidArgument)?,
        }

        if req.key_properties.key_metadata.session() {
            flags.set_session_only(true);
        }

        let key_num = app_session.import_key(
            &result.plain_text,
            req.wrapped_blob_key_class.try_into()?,
            flags,
            req.key_tag,
        )?;
        tracing::debug!(key_num, "Completed app_session.import_key() in rsa_unwrap");

        let entry = app_session.get_key_entry(key_num)?;
        let public_key: Option<DdiDerPublicKey> = self.extract_pub_key(&entry)?;
        let bulk_key_id = if entry.kind().is_bulk_key() {
            Some(key_num)
        } else {
            None
        };

        let masked_key = app_session.mask_key(&entry)?;

        let resp = DdiRsaUnwrapResp {
            key_id: key_num,     // this is the imported key id
            pub_key: public_key, // this is the public key of the imported key
            bulk_key_id,
            kind: entry.kind().try_into()?,
            masked_key: MborByteArray::from_slice(&masked_key)
                .map_err(|_| ManticoreError::InvalidArgument)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_get_unwrapping_key(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let _ = decoder
            .decode_data::<DdiGetUnwrappingKeyReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;
        let key_id = self
            .function
            .get_function_state()
            .get_unwrapping_key_num()?;

        let entry = app_session.get_key_entry(key_id)?;
        let masked_key = app_session.mask_key(&entry)?;

        let pub_key = if let RsaPrivate(private_key) = entry.key() {
            let mut der = [0u8; 768];
            let der_vec = private_key.extract_pub_key_der()?;
            der[..der_vec.len()].copy_from_slice(&der_vec);
            DdiDerPublicKey {
                der: MborByteArray::new(der, der_vec.len())
                    .map_err(|_| ManticoreError::InternalError)?,
                key_kind: entry.kind().as_pub()?.try_into()?,
            }
        } else {
            // Implies unwrapping key was initialized incorrectly
            Err(ManticoreError::InternalError)?
        };

        let resp = DdiGetUnwrappingKeyResp {
            key_id,
            pub_key,
            masked_key: MborByteArray::from_slice(&masked_key)
                .map_err(|_| ManticoreError::InvalidArgument)?,
        };
        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_ecc_generate_key_pair(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiEccGenerateKeyPairReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;
        let span = tracing::info_span!("AppSession", session = ?app_session.id());
        let _guard = span.enter();

        let key_kind: Kind = req.curve.try_into()?;

        let usage = req
            .key_properties
            .key_metadata
            .try_into()
            .map_err(|_| ManticoreError::InvalidPermissions)?;

        if !key_kind.allows_usage(usage) {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, key_kind = ?key_kind, key_usage = ?usage, "Key type doesn't allow this key usage");
            Err(ManticoreError::InvalidPermissions)?
        }

        let mut flags = EntryFlags::default();
        match usage {
            DdiKeyUsage::SignVerify => flags.set_allow_sign_verify(true),
            DdiKeyUsage::EncryptDecrypt => flags.set_allow_encrypt_decrypt(true),
            DdiKeyUsage::Unwrap => flags.set_allow_unwrap(true),
            DdiKeyUsage::Derive => flags.set_allow_derive(true),
            _ => Err(ManticoreError::InvalidArgument)?,
        }

        if req.key_properties.key_metadata.session() {
            flags.set_session_only(true);
        }

        let (private_key_id, der_vec) =
            app_session.ecc_generate_key(req.curve.try_into()?, flags, req.key_tag)?;
        tracing::debug!(private_key_id, "Completed app_session.ecc_generate_key()");

        let entry = app_session.get_key_entry(private_key_id)?;
        let masked_key = app_session.mask_key(&entry)?;

        let mut der = [0u8; 768];
        der[..der_vec.len()].copy_from_slice(&der_vec);

        let resp = DdiEccGenerateKeyPairResp {
            private_key_id,
            pub_key: DdiDerPublicKey {
                der: MborByteArray::new(der, der_vec.len())
                    .map_err(|_| ManticoreError::InternalError)?,
                key_kind: key_kind.as_pub()?.try_into()?,
            },
            masked_key: MborByteArray::from_slice(&masked_key)
                .map_err(|_| ManticoreError::InvalidArgument)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_ecc_sign(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiEccSignReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;
        let span = tracing::debug_span!("AppSession", session = ?app_session.id());
        let _guard = span.enter();

        let req_digest_data = req.digest.data();
        if req.digest.len() > req_digest_data.len() {
            tracing::error!(
                digest_len = req.digest.len(),
                digest_array_len = req_digest_data.len(),
                "Digest length is too long."
            );
            Err(ManticoreError::InvalidArgument)?
        }

        let vec_signature =
            app_session.ecc_sign(req.key_id, &req_digest_data[..req.digest.len()])?;
        tracing::debug!(
            vec_signature_len = vec_signature.len(),
            "Completed app_session.ecc_sign()"
        );

        let mut signature = [0u8; 192];
        signature[..vec_signature.len()].copy_from_slice(vec_signature.as_slice());

        let resp = DdiEccSignResp {
            signature: MborByteArray::new(signature, vec_signature.len())
                .map_err(|_| ManticoreError::InternalError)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_ecdh_key_exchange(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiEcdhKeyExchangeReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;

        let output_key_type: Kind = req.key_type.try_into()?;

        let usage = req
            .key_properties
            .key_metadata
            .try_into()
            .map_err(|_| ManticoreError::InvalidPermissions)?;

        if !output_key_type.allows_usage(usage) {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, key_type = ?req.key_type, key_usage = ?usage, "Key type doesn't allow this key usage");
            Err(ManticoreError::InvalidPermissions)?
        }

        let mut flags = EntryFlags::default();
        match usage {
            DdiKeyUsage::SignVerify => flags.set_allow_sign_verify(true),
            DdiKeyUsage::EncryptDecrypt => flags.set_allow_encrypt_decrypt(true),
            DdiKeyUsage::Unwrap => flags.set_allow_unwrap(true),
            DdiKeyUsage::Derive => flags.set_allow_derive(true),
            _ => Err(ManticoreError::InvalidArgument)?,
        }

        if req.key_properties.key_metadata.session() {
            flags.set_session_only(true);
        }

        // Check if req.pub_key_der_len is valid
        let req_pub_key_der_data = req.pub_key_der.data();
        if req.pub_key_der.len() > req_pub_key_der_data.len() {
            tracing::error!(error = ?ManticoreError::InvalidArgument, pub_key_der_len = req.pub_key_der.len(), "pub_key_der_len is larger than pub_key_der's length.");
            Err(ManticoreError::InvalidArgument)?
        }

        let key_id = app_session.ecdh_key_exchange(
            req.priv_key_id,
            &req_pub_key_der_data[..req.pub_key_der.len()],
            output_key_type,
            flags,
            req.key_tag,
        )?;

        let entry = app_session.get_key_entry(key_id)?;
        let masked_key = app_session.mask_key(&entry)?;

        let resp = DdiEcdhKeyExchangeResp {
            key_id,
            masked_key: MborByteArray::from_slice(&masked_key)
                .map_err(|_| ManticoreError::InvalidArgument)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_hkdf_derive(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiHkdfDeriveReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;

        if req.key_type != DdiKeyType::Aes128
            && req.key_type != DdiKeyType::Aes192
            && req.key_type != DdiKeyType::Aes256
            && req.key_type != DdiKeyType::HmacSha256
            && req.key_type != DdiKeyType::HmacSha384
            && req.key_type != DdiKeyType::HmacSha512
        {
            tracing::error!(error = ?ManticoreError::InvalidKeyType, key_type = ?req.key_type, "Output Key type is invalid");
            Err(ManticoreError::InvalidKeyType)?
        }

        let key_kind: Kind = req.key_type.try_into()?;

        let usage = req
            .key_properties
            .key_metadata
            .try_into()
            .map_err(|_| ManticoreError::InvalidPermissions)?;

        if !key_kind.allows_usage(usage) {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, key_type = ?req.key_type, key_usage = ?usage, "Key type doesn't allow this key usage");
            Err(ManticoreError::InvalidPermissions)?
        }

        let mut flags = EntryFlags::default();
        match usage {
            DdiKeyUsage::SignVerify => flags.set_allow_sign_verify(true),
            DdiKeyUsage::EncryptDecrypt => flags.set_allow_encrypt_decrypt(true),
            DdiKeyUsage::Unwrap => flags.set_allow_unwrap(true),
            DdiKeyUsage::Derive => flags.set_allow_derive(true),
            _ => Err(ManticoreError::InvalidArgument)?,
        }

        if req.key_properties.key_metadata.session() {
            flags.set_session_only(true);
        };

        let info_slice = req
            .info
            .as_ref()
            .map(|info_array| &info_array.data()[..info_array.len()]);
        let salt_slice = req
            .salt
            .as_ref()
            .map(|salt_array| &salt_array.data()[..salt_array.len()]);

        let key_id = app_session.hkdf_derive(
            req.key_id,
            req.hash_algorithm.try_into()?,
            salt_slice,
            info_slice,
            req.key_type.try_into()?,
            flags,
            req.key_tag,
        )?;

        let entry = app_session.get_key_entry(key_id)?;
        let masked_key = app_session.mask_key(&entry)?;

        let resp = DdiHkdfDeriveResp {
            key_id,
            masked_key: MborByteArray::from_slice(&masked_key)
                .map_err(|_| ManticoreError::InvalidArgument)?,
            bulk_key_id: None,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_kbkdf_counter_hmac_derive(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiKbkdfCounterHmacDeriveReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;

        if req.key_type != DdiKeyType::Aes128
            && req.key_type != DdiKeyType::Aes192
            && req.key_type != DdiKeyType::Aes256
            && req.key_type != DdiKeyType::HmacSha256
            && req.key_type != DdiKeyType::HmacSha384
            && req.key_type != DdiKeyType::HmacSha512
        {
            tracing::error!(error = ?ManticoreError::InvalidKeyType, key_type = ?req.key_type, "Output key type is not valid");
            Err(ManticoreError::InvalidKeyType)?
        }

        let key_kind: Kind = req.key_type.try_into()?;

        let usage = req
            .key_properties
            .key_metadata
            .try_into()
            .map_err(|_| ManticoreError::InvalidPermissions)?;

        if !key_kind.allows_usage(usage) {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, key_type = ?req.key_type, key_usage = ?usage, "Key type doesn't allow this key usage");
            Err(ManticoreError::InvalidPermissions)?
        }

        let mut flags = EntryFlags::default();
        match usage {
            DdiKeyUsage::SignVerify => flags.set_allow_sign_verify(true),
            DdiKeyUsage::EncryptDecrypt => flags.set_allow_encrypt_decrypt(true),
            DdiKeyUsage::Unwrap => flags.set_allow_unwrap(true),
            DdiKeyUsage::Derive => flags.set_allow_derive(true),
            _ => Err(ManticoreError::InvalidArgument)?,
        }

        if req.key_properties.key_metadata.session() {
            flags.set_session_only(true);
        }

        // Convert option of array to option of slice
        let label_slice = req
            .label
            .as_ref()
            .map(|label_array| &label_array.data()[..label_array.len()]);
        let context_slice = req
            .context
            .as_ref()
            .map(|context_array| &context_array.data()[..context_array.len()]);

        let key_id = app_session.kbkdf_counter_hmac_derive(
            req.key_id,
            req.hash_algorithm.try_into()?,
            label_slice,
            context_slice,
            req.key_type.try_into()?,
            flags,
            req.key_tag,
        )?;

        let entry = app_session.get_key_entry(key_id)?;
        let masked_key = app_session.mask_key(&entry)?;

        let resp = DdiKbkdfCounterHmacDeriveResp {
            key_id,
            masked_key: MborByteArray::from_slice(&masked_key)
                .map_err(|_| ManticoreError::InvalidArgument)?,
            bulk_key_id: None,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_hmac(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiHmacReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;

        let tag_vec = app_session.hmac(req.key_id, &req.msg.data()[..req.msg.len()])?;

        let mut tag_array = [0u8; 64];
        tag_array[..tag_vec.len()].copy_from_slice(tag_vec.as_slice());

        let resp = DdiHmacResp {
            tag: MborByteArray::new(tag_array, tag_vec.len())
                .map_err(|_| ManticoreError::InternalError)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_aes_generate_key(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiAesGenerateKeyReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;
        let span = tracing::debug_span!("AppSession", session = ?app_session.id());
        let _guard = span.enter();

        let key_kind: Kind = req.key_size.try_into()?;

        let usage = req
            .key_properties
            .key_metadata
            .try_into()
            .map_err(|_| ManticoreError::InvalidPermissions)?;

        if !key_kind.allows_usage(usage) {
            tracing::error!(error = ?ManticoreError::InvalidPermissions, key_kind = ?key_kind, key_usage = ?usage, "Key type doesn't allow this key usage");
            Err(ManticoreError::InvalidPermissions)?
        }

        let mut flags = EntryFlags::default();
        match usage {
            DdiKeyUsage::SignVerify => flags.set_allow_sign_verify(true),
            DdiKeyUsage::EncryptDecrypt => flags.set_allow_encrypt_decrypt(true),
            DdiKeyUsage::Unwrap => flags.set_allow_unwrap(true),
            DdiKeyUsage::Derive => Err(ManticoreError::InvalidPermissions)?,
            _ => Err(ManticoreError::InvalidArgument)?,
        }

        if req.key_properties.key_metadata.session() {
            flags.set_session_only(true);
        }

        let key_id = app_session.aes_generate_key(req.key_size.try_into()?, flags, req.key_tag)?;
        tracing::debug!(key_id, "Completed app_session.aes_generate_key()");

        let entry = app_session.get_key_entry(key_id)?;
        let masked_key = app_session.mask_key(&entry)?;

        let bulk_key_id = if req.key_size.is_bulk_key() {
            Some(key_id)
        } else {
            None
        };

        let resp = DdiAesGenerateKeyResp {
            key_id,
            bulk_key_id,
            masked_key: MborByteArray::from_slice(&masked_key)
                .map_err(|_| ManticoreError::InvalidArgument)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_aes_encrypt_decrypt(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiAesEncryptDecryptReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        if req.msg.is_empty() {
            Err(ManticoreError::InvalidArgument)?
        }

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let app_session = self.function.get_user_session(session_id, false)?;
        let span = tracing::debug_span!("AppSession", session = ?app_session.id());
        let _guard = span.enter();

        let iv = req.iv.data().as_slice();
        let mode = req.op.try_into()?;

        let result = app_session.aes_encrypt_decrypt(
            req.key_id,
            mode,
            &req.msg.data()[..req.msg.len()],
            iv,
        )?;
        tracing::debug!("Completed app_session.aes_encrypt_decrypt()");

        let mut msg = [0u8; 1024];
        msg[..result.data.len()].copy_from_slice(result.data.as_slice());

        let iv = result.iv;
        let mut iv_raw = [0u8; 16];
        iv_raw.copy_from_slice(iv.as_slice());

        let resp = DdiAesEncryptDecryptResp {
            msg: MborByteArray::new(msg, result.data.len())
                .map_err(|_| ManticoreError::InternalError)?,
            iv: MborByteArray::new(iv_raw, iv_raw.len())
                .map_err(|_| ManticoreError::InternalError)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_get_establish_cred_encryption_key(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let _ = decoder
            .decode_data::<DdiGetEstablishCredEncryptionKeyReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let vault = self
            .function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)?;

        let nonce = vault.get_nonce();

        let key_id = vault.get_establish_cred_encryption_key_id()?;
        let entry = vault.get_key_entry(key_id)?;

        let pub_key = if let EccPrivate(private_key) = entry.key() {
            let mut der = [0u8; 768];
            let der_vec = private_key.extract_pub_key_der()?;
            der[..der_vec.len()].copy_from_slice(&der_vec);
            DdiDerPublicKey {
                der: MborByteArray::new(der, der_vec.len())
                    .map_err(|_| ManticoreError::InternalError)?,
                key_kind: entry.kind().as_pub()?.try_into()?,
            }
        } else {
            // Implies unwrapping key was initialized incorrectly
            Err(ManticoreError::InternalError)?
        };

        let resp = DdiGetEstablishCredEncryptionKeyResp {
            pub_key,
            nonce,
            pub_key_signature: MborByteArray::from_slice(&[])
                .map_err(|_| ManticoreError::InvalidArgument)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_establish_credential(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiEstablishCredentialReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        if hdr.sess_id.is_some() {
            tracing::error!("hdr.sess_id should be None");
            Err(ManticoreError::SessionNotExpected)?
        }
        if req.masked_bk3.is_empty() {
            tracing::error!("masked_bk3 is empty in establish_credential request.");
            Err(ManticoreError::InvalidArgument)?
        }

        let _ = hdr.rev.ok_or(ManticoreError::UnsupportedRevision)?;

        let vault = self
            .function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)?;

        let encrypted_credential = EncryptedCredential {
            id: req.encrypted_credential.encrypted_id.data_take(),
            pin: req.encrypted_credential.encrypted_pin.data_take(),
            iv: req.encrypted_credential.iv.data_take(),
            nonce: req.encrypted_credential.nonce,
            tag: req.encrypted_credential.tag,
        };
        vault.establish_credential(
            encrypted_credential,
            &req.pub_key.der.data()[..req.pub_key.der.len()],
        )?;

        let bmk_result = {
            tracing::debug!(
                masked_bk3_len = req.masked_bk3.len(),
                "Processing provision partition within establish credential"
            );

            let bmk_option = if req.bmk.is_empty() {
                None
            } else {
                Some(req.bmk.as_slice())
            };

            let masked_unwrapping_key_option = if req.masked_unwrapping_key.is_empty() {
                None
            } else {
                Some(req.masked_unwrapping_key.as_slice())
            };

            let bmk = self.function.provision(
                req.masked_bk3.as_slice(),
                bmk_option,
                masked_unwrapping_key_option,
            )?;

            tracing::debug!(bmk_size = bmk.len(), "Successfully provisioned partition");

            bmk
        };

        let resp = DdiEstablishCredentialResp {
            bmk: MborByteArray::from_slice(&bmk_result)
                .map_err(|_| ManticoreError::InternalError)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_get_session_encryption_key(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let _ = decoder
            .decode_data::<DdiGetSessionEncryptionKeyReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let vault = self
            .function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)?;

        let nonce = vault.get_nonce();

        let key_id = vault.get_session_encryption_key_id()?;
        let entry = vault.get_key_entry(key_id)?;

        let pub_key = if let EccPrivate(private_key) = entry.key() {
            let mut der = [0u8; 768];
            let der_vec = private_key.extract_pub_key_der()?;
            der[..der_vec.len()].copy_from_slice(&der_vec);
            DdiDerPublicKey {
                der: MborByteArray::new(der, der_vec.len())
                    .map_err(|_| ManticoreError::InternalError)?,
                key_kind: entry.kind().as_pub()?.try_into()?,
            }
        } else {
            // Implies unwrapping key was initialized incorrectly
            Err(ManticoreError::InternalError)?
        };

        let resp = DdiGetSessionEncryptionKeyResp {
            pub_key,
            nonce,
            pub_key_signature: MborByteArray::from_slice(&[])
                .map_err(|_| ManticoreError::InvalidArgument)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_open_session(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let mut resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiOpenSessionReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        if hdr.sess_id.is_some() {
            tracing::error!("hdr.sess_id should be None");
            Err(ManticoreError::SessionNotExpected)?
        }

        let api_rev = hdr.rev.ok_or(ManticoreError::UnsupportedRevision)?;

        let vault = self
            .function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)?;
        let partition_bk = self
            .function
            .get_function_state()
            .get_bk_partition()
            .map_err(|err| {
                tracing::error!(
                    "Converting error to CredentialsNotEstablished to match firmware behavior {:?}",
                    err
                );
                ManticoreError::CredentialsNotEstablished
            })?;

        let encrypted_credential = EncryptedSessionCredential {
            id: req.encrypted_credential.encrypted_id.data_take(),
            pin: req.encrypted_credential.encrypted_pin.data_take(),
            seed: req.encrypted_credential.encrypted_seed.data_take(),
            iv: req.encrypted_credential.iv.data_take(),
            nonce: req.encrypted_credential.nonce,
            tag: req.encrypted_credential.tag,
        };

        let session_result = vault.open_session(
            encrypted_credential,
            &req.pub_key.der.data()[..req.pub_key.der.len()],
            api_rev.into(),
            &partition_bk,
        )?;

        resp_header.sess_id = Some(session_result.session_id);
        let resp = DdiOpenSessionResp {
            sess_id: session_result.session_id,
            short_app_id: session_result.short_app_id,
            bmk_session: MborByteArray::from_slice(&session_result.bmk)
                .map_err(|_| ManticoreError::InternalError)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_close_session(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        decoder
            .decode_data::<DdiCloseSessionReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let span = tracing::debug_span!("user_session", session_id);
        let _guard = span.enter();

        self.function.close_user_session(session_id)?;

        let resp = DdiCloseSessionResp {};

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_reopen_session(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let mut resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiReopenSessionReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        // For reopen session, we need the session ID in the header
        let reopen_sess_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        let api_rev = hdr.rev.ok_or(ManticoreError::UnsupportedRevision)?;

        let vault = self
            .function
            .get_function_state()
            .get_vault(DEFAULT_VAULT_ID)?;

        let encrypted_credential = EncryptedSessionCredential {
            id: req.encrypted_credential.encrypted_id.data_take(),
            pin: req.encrypted_credential.encrypted_pin.data_take(),
            seed: req.encrypted_credential.encrypted_seed.data_take(),
            iv: req.encrypted_credential.iv.data_take(),
            nonce: req.encrypted_credential.nonce,
            tag: req.encrypted_credential.tag,
        };

        tracing::debug!(reopen_sess_id, "Reopening session");
        let partition_bk = self.function.get_function_state().get_bk_partition()?;
        let session_result = vault.reopen_session(
            encrypted_credential,
            &req.pub_key.der.data()[..req.pub_key.der.len()],
            api_rev.into(),
            reopen_sess_id,
            Some(req.bmk_session.as_slice()),
            &partition_bk,
        )?;

        resp_header.sess_id = Some(session_result.session_id);
        let resp = DdiReopenSessionResp {
            sess_id: session_result.session_id,
            short_app_id: session_result.short_app_id,
            bmk_session: MborByteArray::from_slice(&session_result.bmk)
                .map_err(|_| ManticoreError::InvalidArgument)?,
        };

        self.send_response(
            resp_header,
            resp,
            Some(session_result.short_app_id),
            out_data,
        )
    }

    #[allow(unused)]
    fn dispatch_change_pin(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiChangePinReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;
        self.function.get_user_session_api_rev(session_id, false)?;
        let span = tracing::debug_span!("user_session", session_id);
        let _guard = span.enter();

        let user_session = self.function.get_user_session(session_id, false)?;

        let encrypted_pin = EncryptedPin {
            pin: req.new_pin.encrypted_pin.data_take(),
            iv: req.new_pin.iv.data_take(),
            nonce: req.new_pin.nonce,
            tag: req.new_pin.tag,
        };

        user_session.change_pin(
            encrypted_pin,
            &req.pub_key.der.data()[..req.pub_key.der.len()],
        )?;

        let resp = DdiChangePinResp {};

        self.send_response(resp_header, resp, None, out_data)
    }

    #[allow(unused)]
    fn dispatch_unmask_key(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiUnmaskKeyReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;
        self.function.get_user_session_api_rev(session_id, false)?;
        let span = tracing::debug_span!("user_session", session_id);
        let _guard = span.enter();

        let user_session = self.function.get_user_session(session_id, false)?;

        let blob = req.masked_key.as_slice();

        let key_num = user_session.unmask_key(blob)?;
        let unmasked_entry = user_session.get_key_entry(key_num)?;

        let pub_key = self.extract_pub_key(&unmasked_entry)?;
        let bulk_key_id = if unmasked_entry.kind().is_bulk_key() {
            Some(key_num)
        } else {
            None
        };

        let resp = DdiUnmaskKeyResp {
            key_id: key_num,
            pub_key,
            bulk_key_id,
            kind: unmasked_entry.kind().try_into()?,
            masked_key: req.masked_key,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_get_cert_chain_info(
        &self,
        _decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        tracing::debug!("Getting cert chain info");

        // Compute SHA-256(certificate)
        let certificate = self.function.get_function_state().get_certificate()?;
        let hash = sha(HashAlgorithm::Sha256, &certificate)?;

        // TODO: Collateral support for virtual device is pending
        // For now just return 1 for Virtual Manticore
        let resp = DdiGetCertChainInfoResp {
            num_certs: 1,
            thumbprint: MborByteArray::from_slice(&hash)
                .map_err(|_| ManticoreError::InternalError)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_get_certificate(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        // TODO: Collateral support for virtual device is pending
        // For now, virtual manticore only accept request for AKCert
        let req = decoder
            .decode_data::<DdiGetCertificateReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;
        if !(req.slot_id == 0 && req.cert_id == 0) {
            tracing::error!(err = ?ManticoreError::InvalidArgument, slot_id = req.slot_id, cert_id = req.cert_id, "Expects slot_id = 0 and cert_id = 0");
            Err(ManticoreError::InvalidArgument)?
        }
        let certificate = self.function.get_function_state().get_certificate()?;
        tracing::debug!(
            certificate_len = certificate.len(),
            "Completed app_session.get_certificate()"
        );

        let resp = DdiGetCertificateResp {
            certificate: MborByteArray::from_slice(&certificate)
                .map_err(|_| ManticoreError::InternalError)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_reset_function(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        decoder
            .decode_data::<DdiResetFunctionReq>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let session_id = hdr.sess_id.ok_or(ManticoreError::SessionExpected)?;

        self.function.get_user_session(session_id, false)?;
        let span = tracing::debug_span!("vault_manager_session", session_id);
        let _guard = span.enter();

        self.function.reset_function()?;

        let resp = DdiResetFunctionResp {};

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_init_bk3(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiInitBk3Req>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        tracing::debug!(bk3_len = req.bk3.len(), "InitBk3 request");

        if req.bk3.len() != BK3_SIZE_BYTES {
            tracing::error!(
                expected = BK3_SIZE_BYTES,
                actual = req.bk3.len(),
                "Invalid sealed BK3 size"
            );
            return Err(ManticoreError::InvalidArgument);
        }

        let mut bk3_array = [0u8; BK3_SIZE_BYTES];
        bk3_array.copy_from_slice(req.bk3.as_slice());
        let masked_bk3 = self.function.init_bk3(bk3_array)?;

        tracing::debug!(
            masked_bk3_size = masked_bk3.len(),
            "Successfully initialized BK3"
        );

        let resp = DdiInitBk3Resp {
            masked_bk3: MborByteArray::from_slice(&masked_bk3)
                .map_err(|_| ManticoreError::InternalError)?,
            vm_launch_guid: [0u8; 16], // TODO: Generate proper VM launch GUID
        };

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_set_sealed_bk3(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let req = decoder
            .decode_data::<DdiSetSealedBk3Req>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        tracing::debug!(
            sealed_bk3_len = req.sealed_bk3.len(),
            "SetSealedBk3 request"
        );

        if req.sealed_bk3.len() > SEALED_BK3_SIZE {
            return Err(ManticoreError::SealedBk3TooLarge);
        }

        self.function.set_sealed_bk3(req.sealed_bk3.as_slice())?;

        let resp = DdiSetSealedBk3Resp {};

        self.send_response(resp_header, resp, None, out_data)
    }

    fn dispatch_get_sealed_bk3(
        &self,
        decoder: &mut DdiDecoder<'_>,
        hdr: &DdiReqHdr,
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let resp_header = DdiRespHdr {
            rev: hdr.rev,
            op: hdr.op,
            sess_id: hdr.sess_id,
            status: DdiStatus::Success,
            fips_approved: false,
        };

        let _req = decoder
            .decode_data::<DdiGetSealedBk3Req>()
            .map_err(|_| ManticoreError::CborDecodeError)?;

        let sealed_bk3_data = self.function.get_sealed_bk3()?;

        let resp = DdiGetSealedBk3Resp {
            sealed_bk3: MborByteArray::from_slice(&sealed_bk3_data)
                .map_err(|_| ManticoreError::InternalError)?,
        };

        self.send_response(resp_header, resp, None, out_data)
    }
}

impl TryFrom<DdiRsaCryptoPadding> for RsaCryptoPadding {
    type Error = ManticoreError;

    fn try_from(value: DdiRsaCryptoPadding) -> Result<Self, Self::Error> {
        match value {
            DdiRsaCryptoPadding::Oaep => Ok(RsaCryptoPadding::Oaep),
            _ => Err(ManticoreError::InvalidArgument),
        }
    }
}

impl TryFrom<DdiHashAlgorithm> for HashAlgorithm {
    type Error = ManticoreError;

    fn try_from(value: DdiHashAlgorithm) -> Result<Self, Self::Error> {
        match value {
            DdiHashAlgorithm::Sha1 => Ok(HashAlgorithm::Sha1),
            DdiHashAlgorithm::Sha256 => Ok(HashAlgorithm::Sha256),
            DdiHashAlgorithm::Sha384 => Ok(HashAlgorithm::Sha384),
            DdiHashAlgorithm::Sha512 => Ok(HashAlgorithm::Sha512),
            _ => Err(ManticoreError::InvalidArgument),
        }
    }
}

impl TryFrom<DdiRsaOpType> for RsaOpType {
    type Error = ManticoreError;

    fn try_from(value: DdiRsaOpType) -> Result<Self, Self::Error> {
        match value {
            DdiRsaOpType::Decrypt => Ok(RsaOpType::Decrypt),
            DdiRsaOpType::Sign => Ok(RsaOpType::Sign),
            _ => Err(ManticoreError::InvalidArgument),
        }
    }
}

#[cfg(test)]
mod tests {

    use test_with_tracing::test;

    use super::*;
    use crate::crypto::ecc::EccCurve;
    use crate::errors::ManticoreError;
    use crate::table::entry::EntryFlags;
    use crate::vault::tests::*;
    use crate::vault::SessionResult;
    use crate::vault::DEFAULT_VAULT_ID;

    fn create_dispatcher(table_count: usize) -> Dispatcher {
        let result = Dispatcher::new(table_count);
        assert!(result.is_ok());
        result.unwrap()
    }

    fn create_test_session(dispatcher: &Dispatcher) -> SessionResult {
        // Get function state and default vault
        let function_state = dispatcher.function.get_function_state();
        let vault = function_state
            .get_vault(DEFAULT_VAULT_ID)
            .expect("Failed to get vault");

        // Establish credential first
        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        // Open a session
        let api_rev = dispatcher.function.get_api_rev_range().max;
        helper_open_session(&vault, TEST_CRED_ID, TEST_CRED_PIN, api_rev)
            .expect("Failed to open session")
    }

    /// Helper function to dispatch SetSealedBk3 requests.
    ///
    /// # Arguments
    /// * `dispatcher` - The dispatcher instance
    /// * `sealed_bk3_data` - The sealed BK3 data to set
    /// * `out_data` - Output buffer for the response (allows caller to decode and validate)
    ///
    /// # Returns
    /// * `Result<SessionInfoResponse, ManticoreError>` - The session info response
    ///
    fn helper_dispatch_set_sealed_bk3(
        dispatcher: &Dispatcher,
        sealed_bk3_data: &[u8],
        out_data: &mut [u8],
    ) -> Result<SessionInfoResponse, ManticoreError> {
        let req = DdiSetSealedBk3Req {
            sealed_bk3: MborByteArray::from_slice(sealed_bk3_data).unwrap(),
        };

        let api_rev = dispatcher.function.get_api_rev_range().max;
        let hdr = DdiReqHdr {
            rev: Some(DdiApiRev {
                major: api_rev.major,
                minor: api_rev.minor,
            }),
            op: DdiOp::SetSealedBk3,
            sess_id: None,
        };

        let mut in_data = [0u8; 2048];
        let req_size = DdiEncoder::encode_parts(hdr, req, &mut in_data, false).unwrap();

        let session_info_request = SessionInfoRequest {
            session_control_kind: SessionControlKind::from(DdiOp::SetSealedBk3),
            session_id: None,
        };

        dispatcher.dispatch(session_info_request, &in_data[..req_size], out_data)
    }

    #[test]
    fn test_dispatcher_new() {
        {
            let result = Dispatcher::new(0);
            assert!(result.is_err(), "result {:?}", result);
        }

        {
            let result = Dispatcher::new(4);
            assert!(result.is_ok());
            let dispatcher = result.unwrap();
            assert_eq!(dispatcher.function.tables_max(), 4);
        }
    }

    #[test]
    fn test_dispatch_zero_length() {
        let session_info_request = SessionInfoRequest {
            ..Default::default()
        };
        let dispatcher = create_dispatcher(4);
        let in_data = vec![];
        let mut out_data = vec![0u8; 50];
        let res = dispatcher.dispatch(session_info_request, &in_data, &mut out_data);
        assert!(res.is_ok());

        let size = res.unwrap().response_length as usize;
        let out_slice = &out_data[0..size];

        let mut decoder = DdiDecoder::new(out_slice, false);
        let resp_header = decoder.decode_hdr::<DdiRespHdr>().unwrap();
        assert!(resp_header.rev.is_none());
        assert_eq!(resp_header.op, DdiOp::Invalid);
        assert_eq!(resp_header.sess_id, None);
        assert_eq!(resp_header.status, DdiStatus::DdiDecodeFailed);

        let _resp_data = decoder.decode_data::<DdiErrResp>().unwrap();
    }

    #[test]
    fn test_dispatch_garbage_header() {
        let session_info_request = SessionInfoRequest {
            ..Default::default()
        };
        let dispatcher = create_dispatcher(4);
        let in_data = vec![1, 2, 3, 4];
        let mut out_data = vec![0u8; 50];
        let res = dispatcher.dispatch(session_info_request, &in_data, &mut out_data);
        assert!(res.is_ok());

        let size = res.unwrap().response_length as usize;
        let out_slice = &out_data[0..size];

        let mut decoder = DdiDecoder::new(out_slice, false);
        let resp_header = decoder.decode_hdr::<DdiRespHdr>().unwrap();
        assert!(resp_header.rev.is_none());
        assert_eq!(resp_header.op, DdiOp::Invalid);
        assert_eq!(resp_header.sess_id, None);
        assert_eq!(resp_header.status, DdiStatus::DdiDecodeFailed);

        let _resp_data = decoder.decode_data::<DdiErrResp>().unwrap();
    }

    #[test]
    fn test_dispatch_garbage_data() {
        let session_info_request = SessionInfoRequest {
            ..Default::default()
        };
        let dispatcher = create_dispatcher(4);
        let mut in_data = vec![0u8; 512];
        let mut out_data = vec![0u8; 512];

        let hdr = DdiReqHdr {
            rev: None,
            op: DdiOp::GetApiRev,
            sess_id: None,
        };
        let req = DdiGetApiRevReq {};
        let req_size = DdiEncoder::encode_parts(hdr, req, &mut in_data, false).unwrap();

        let res = dispatcher.dispatch(
            session_info_request,
            &in_data[..(req_size + 1)],
            &mut out_data,
        );
        assert!(res.is_ok());

        let size = res.unwrap().response_length as usize;
        let out_slice = &out_data[0..size];

        let mut decoder = DdiDecoder::new(out_slice, false);
        let resp_header = decoder.decode_hdr::<DdiRespHdr>().unwrap();
        assert!(resp_header.rev.is_none());
        assert_eq!(resp_header.op, DdiOp::GetApiRev);
        assert_eq!(resp_header.sess_id, None);
        assert_eq!(resp_header.status, DdiStatus::DdiDecodeFailed);

        let _resp_data = decoder.decode_data::<DdiErrResp>().unwrap();
    }

    #[test]
    fn test_dispatch_get_api_rev() {
        let session_info_request = SessionInfoRequest {
            ..Default::default()
        };
        let dispatcher = create_dispatcher(4);
        let mut in_data = vec![0u8; 512];
        let mut out_data = vec![0u8; 512];

        let hdr = DdiReqHdr {
            rev: None,
            op: DdiOp::GetApiRev,
            sess_id: None,
        };
        let req = DdiGetApiRevReq {};
        let req_size = DdiEncoder::encode_parts(hdr, req, &mut in_data, false).unwrap();

        let res = dispatcher.dispatch(session_info_request, &in_data[..req_size], &mut out_data);
        assert!(res.is_ok());

        let size = res.unwrap().response_length as usize;
        let out_slice = &out_data[0..size];

        let mut decoder = DdiDecoder::new(out_slice, false);
        let resp_header = decoder.decode_hdr::<DdiRespHdr>().unwrap();
        assert!(resp_header.rev.is_none());
        assert_eq!(resp_header.op, DdiOp::GetApiRev);
        assert_eq!(resp_header.sess_id, None);
        assert_eq!(resp_header.status, DdiStatus::Success);

        let resp_data = decoder.decode_data::<DdiGetApiRevResp>().unwrap();
        assert_eq!(resp_data.min.major, 1);
        assert_eq!(resp_data.min.minor, 0);
        assert_eq!(resp_data.max.major, 1);
        assert_eq!(resp_data.max.minor, 0);
    }

    /// test_dispatch_flush_invalid_session
    /// This function flushes a random session
    /// (not created before) and verifies that the
    /// flush fails
    #[test]
    fn test_dispatch_flush_invalid_session() {
        let dispatcher = create_dispatcher(4);
        let x = 50u16;
        let res = dispatcher.flush_session(x);
        assert!(res.is_err());
    }

    #[test]
    fn test_dispatch_migration_sim_success() {
        let dispatcher = create_dispatcher(4);

        // Test successful migration simulation
        let result = dispatcher.dispatch_migration_sim();
        assert!(
            result.is_ok(),
            "Migration simulation should succeed: {:?}",
            result
        );
    }

    #[test]
    fn test_dispatch_migration_sim_session_state_after() {
        let dispatcher = create_dispatcher(4);
        let session_result = create_test_session(&dispatcher);
        let session_id = session_result.session_id;

        // Verify session works before migration
        let session_before = dispatcher.function.get_user_session(session_id, false);
        assert!(
            session_before.is_ok(),
            "Session should be valid before migration"
        );

        // Simulate migration
        let result = dispatcher.dispatch_migration_sim();
        assert!(
            result.is_ok(),
            "Migration simulation should succeed: {:?}",
            result
        );

        // After migration simulation, session should require renegotiation
        let session_after = dispatcher.function.get_user_session(session_id, false);
        assert!(
            matches!(
                session_after,
                Err(ManticoreError::SessionNeedsRenegotiation)
            ),
            "Session should require renegotiation after migration simulation"
        );
    }

    #[test]
    fn test_dispatch_migration_sim_with_keys() {
        let dispatcher = create_dispatcher(4);
        let session_result = create_test_session(&dispatcher);
        let session_id = session_result.session_id;

        // Get the session and add some keys
        let app_session = dispatcher
            .function
            .get_user_session(session_id, false)
            .unwrap();

        // Create a regular key
        let (regular_key_id, _) = app_session
            .ecc_generate_key(EccCurve::P256, EntryFlags::new(), None)
            .expect("Failed to generate regular key");

        // Create a session-only key
        let (session_key_id, _) = app_session
            .ecc_generate_key(
                EccCurve::P256,
                EntryFlags::new().with_session_only(true),
                None,
            )
            .expect("Failed to generate session key");

        // Verify keys exist before migration
        let regular_key_before = app_session.get_key_entry(regular_key_id);
        let session_key_before = app_session.get_key_entry(session_key_id);
        assert!(
            regular_key_before.is_ok(),
            "Regular key should exist before migration"
        );
        assert!(
            session_key_before.is_ok(),
            "Session key should exist before migration"
        );

        drop(app_session); // Release session reference

        // Simulate migration
        let result = dispatcher.dispatch_migration_sim();
        assert!(
            result.is_ok(),
            "Migration simulation should succeed: {:?}",
            result
        );

        // After migration simulation, the entire function state is reset
        // So all keys are cleared, including regular keys
        // This is the expected behavior of migration simulation
        let function_state = dispatcher.function.get_function_state();
        let vault = function_state
            .get_vault(DEFAULT_VAULT_ID)
            .expect("Failed to get vault");

        // Both keys should be cleared after migration simulation reset
        let regular_key_result = vault.get_key_entry(regular_key_id);
        assert!(
            regular_key_result.is_err(),
            "Regular key should be cleared after migration simulation reset: {:?}",
            regular_key_result
        );

        let session_key_result = vault.get_key_entry(session_key_id);
        assert!(
            session_key_result.is_err(),
            "Session key should be cleared after migration simulation reset: {:?}",
            session_key_result
        );
    }

    #[test]
    fn test_dispatch_migration_sim_close_session_after() {
        let dispatcher = create_dispatcher(4);
        let session_result = create_test_session(&dispatcher);
        let session_id = session_result.session_id;

        // Verify session works before migration
        let session_before = dispatcher.function.get_user_session(session_id, false);
        assert!(
            session_before.is_ok(),
            "Session should be valid before migration"
        );

        // Simulate migration
        let result = dispatcher.dispatch_migration_sim();
        assert!(
            result.is_ok(),
            "Migration simulation should succeed: {:?}",
            result
        );

        // Try to close session after migration - should succeed
        let close_result = dispatcher.function.close_user_session(session_id);
        assert!(
            close_result.is_ok(),
            "Close session should succeed after migration: {:?}",
            close_result
        );
    }

    #[test]
    fn test_dispatch_migration_sim_reopen_session_after() {
        let dispatcher = create_dispatcher(4);

        // Provision partition
        // Use a hardcoded partition_mk
        let partition_mk = [42u8; 80];
        let set_bk_result = dispatcher
            .function
            .get_function_state()
            .set_bk_partition(partition_mk);
        assert!(
            set_bk_result.is_ok(),
            "set partition bk should succeed: {:?}",
            set_bk_result
        );

        let original_session_result = create_test_session(&dispatcher);
        let original_session_id = original_session_result.session_id;

        // Verify original session works
        let original_session = dispatcher
            .function
            .get_user_session(original_session_id, false);
        assert!(
            original_session.is_ok(),
            "Original session should be valid before migration"
        );

        // Simulate migration
        let migration_result = dispatcher.dispatch_migration_sim();
        assert!(
            migration_result.is_ok(),
            "Migration simulation should succeed: {:?}",
            migration_result
        );

        // Re-provision partition
        let set_bk_result = dispatcher
            .function
            .get_function_state()
            .set_bk_partition(partition_mk);
        assert!(
            set_bk_result.is_ok(),
            "set partition bk should succeed: {:?}",
            set_bk_result
        );

        // After migration, original session should require renegotiation
        let session_after_migration = dispatcher
            .function
            .get_user_session(original_session_id, false);
        assert!(
            matches!(
                session_after_migration,
                Err(ManticoreError::SessionNeedsRenegotiation)
            ),
            "Original session should require renegotiation after migration"
        );

        // Re-establish credential with the same identities
        let function_state = dispatcher.function.get_function_state();
        let vault = function_state
            .get_vault(DEFAULT_VAULT_ID)
            .expect("Failed to get vault");

        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        // Reopen session using the new ReopenSession dispatch approach
        let api_rev = dispatcher.function.get_api_rev_range().max;
        let key_num = vault.get_session_encryption_key_id().unwrap();
        let (encrypted_credential, client_pub_key) = helper_encrypt_session_credential(
            &vault,
            key_num,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        )
        .expect("Failed to encrypt credential");

        // Create DdiReopenSessionReq
        let req = DdiReopenSessionReq {
            encrypted_credential: DdiEncryptedSessionCredential {
                encrypted_id: MborByteArray::from_slice(&encrypted_credential.id).unwrap(),
                encrypted_pin: MborByteArray::from_slice(&encrypted_credential.pin).unwrap(),
                encrypted_seed: MborByteArray::from_slice(&encrypted_credential.seed).unwrap(),
                iv: MborByteArray::from_slice(&encrypted_credential.iv).unwrap(),
                nonce: encrypted_credential.nonce,
                tag: encrypted_credential.tag,
            },
            pub_key: DdiDerPublicKey {
                der: MborByteArray::from_slice(&client_pub_key).unwrap(),
                key_kind: DdiKeyType::Ecc384Private,
            },
            bmk_session: MborByteArray::from_slice(&original_session_result.bmk).unwrap(),
        };

        let hdr = DdiReqHdr {
            rev: Some(DdiApiRev {
                major: api_rev.major,
                minor: api_rev.minor,
            }),
            op: DdiOp::ReopenSession,
            sess_id: Some(original_session_id),
        };

        // Encode request
        let mut in_data = [0u8; 2048];
        let req_size = DdiEncoder::encode_parts(hdr, req, &mut in_data, false).unwrap();

        // Dispatch reopen session
        let session_info_request = SessionInfoRequest {
            session_control_kind: SessionControlKind::from(DdiOp::ReopenSession),
            session_id: Some(original_session_id),
        };

        let mut out_data = [0u8; 2048];
        let reopen_result =
            dispatcher.dispatch(session_info_request, &in_data[..req_size], &mut out_data);

        assert!(
            reopen_result.is_ok(),
            "Should be able to reopen session with original ID after migration: {:?}",
            reopen_result
        );

        let session_info = reopen_result.unwrap();
        assert_eq!(
            session_info.session_control_kind,
            SessionControlKind::InSession
        );
        assert_eq!(session_info.session_id, Some(original_session_id));

        // Verify the response contains the expected data
        let out_slice = &out_data[0..session_info.response_length as usize];
        let mut decoder = DdiDecoder::new(out_slice, false);
        let resp_header = decoder.decode_hdr::<DdiRespHdr>().unwrap();
        assert_eq!(resp_header.status, DdiStatus::Success);
        assert_eq!(resp_header.sess_id, Some(original_session_id));

        let resp_data = decoder.decode_data::<DdiReopenSessionResp>().unwrap();
        assert_eq!(resp_data.sess_id, original_session_id);

        // Verify the reopened session works
        let reopened_session = dispatcher
            .function
            .get_user_session(original_session_id, false);
        assert!(
            reopened_session.is_ok(),
            "Reopened session should be valid and functional: {:?}",
            reopened_session
        );

        // Test that we can perform operations with the reopened session
        let app_session = reopened_session.unwrap();
        let key_result = app_session.ecc_generate_key(EccCurve::P256, EntryFlags::new(), None);
        assert!(
            key_result.is_ok(),
            "Should be able to generate keys with reopened session: {:?}",
            key_result
        );
    }

    #[test]
    fn test_dispatch_reopen_session_no_session_id() {
        let dispatcher = create_dispatcher(4);

        // Prepare reopen session request without session ID in header
        let api_rev = dispatcher.function.get_api_rev_range().max;
        let function_state = dispatcher.function.get_function_state();
        let vault = function_state
            .get_vault(DEFAULT_VAULT_ID)
            .expect("Failed to get vault");

        helper_establish_credential(&vault, TEST_CRED_ID, TEST_CRED_PIN);

        let key_num = vault.get_session_encryption_key_id().unwrap();
        let (encrypted_credential, client_pub_key) = helper_encrypt_session_credential(
            &vault,
            key_num,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        )
        .expect("Failed to encrypt credential");

        let req = DdiReopenSessionReq {
            encrypted_credential: DdiEncryptedSessionCredential {
                encrypted_id: MborByteArray::from_slice(&encrypted_credential.id).unwrap(),
                encrypted_pin: MborByteArray::from_slice(&encrypted_credential.pin).unwrap(),
                encrypted_seed: MborByteArray::from_slice(&encrypted_credential.seed).unwrap(),
                iv: MborByteArray::from_slice(&encrypted_credential.iv).unwrap(),
                nonce: encrypted_credential.nonce,
                tag: encrypted_credential.tag,
            },
            pub_key: DdiDerPublicKey {
                der: MborByteArray::from_slice(&client_pub_key).unwrap(),
                key_kind: DdiKeyType::Ecc384Private,
            },
            bmk_session: MborByteArray::from_slice(&[]).unwrap(),
        };

        let hdr = DdiReqHdr {
            rev: Some(DdiApiRev {
                major: api_rev.major,
                minor: api_rev.minor,
            }),
            op: DdiOp::ReopenSession,
            sess_id: None, // No session ID
        };

        let mut in_data = [0u8; 2048];
        let req_size = DdiEncoder::encode_parts(hdr, req, &mut in_data, false).unwrap();

        let session_info_request = SessionInfoRequest {
            session_control_kind: SessionControlKind::from(DdiOp::ReopenSession),
            session_id: None,
        };

        let mut out_data = [0u8; 2048];
        let result = dispatcher.dispatch(session_info_request, &in_data[..req_size], &mut out_data);

        // Should succeed but return error response because reopen session requires session ID
        assert!(result.is_ok(), "Dispatch should succeed: {:?}", result);
        let session_info = result.unwrap();

        // Decode the response to check the error status
        let mut decoder =
            DdiDecoder::new(&out_data[..session_info.response_length as usize], false);
        let resp_hdr = decoder
            .decode_hdr::<DdiRespHdr>()
            .expect("Failed to decode response header");

        // The response should indicate SessionExpected error
        assert_eq!(
            resp_hdr.status,
            DdiStatus::from(ManticoreError::SessionExpected)
        );
    }

    #[test]
    fn test_dispatch_set_sealed_bk3_variable_lengths() {
        let test_sizes = [48, 128, 256, 400, 512]; // Various valid sizes

        for size in test_sizes {
            tracing::info!("Testing SetSealedBk3 with {} bytes", size);

            // Create a new dispatcher for each test size since sealed BK3 can only be set once
            let dispatcher = create_dispatcher(4);

            let mut sealed_bk3_data = vec![0xAAu8; size];
            for (i, byte) in sealed_bk3_data.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }

            let mut out_data = [0u8; 2048];
            let result =
                helper_dispatch_set_sealed_bk3(&dispatcher, &sealed_bk3_data, &mut out_data);

            // Should succeed for all valid sizes
            assert!(
                result.is_ok(),
                "Dispatch should succeed for size {}: {:?}",
                size,
                result
            );
            let session_info = result.unwrap();

            // Decode and validate the successful response
            let mut decoder =
                DdiDecoder::new(&out_data[..session_info.response_length as usize], false);
            let resp_hdr = decoder
                .decode_hdr::<DdiRespHdr>()
                .expect("Failed to decode response header");

            assert_eq!(resp_hdr.status, DdiStatus::Success);
            assert_eq!(resp_hdr.op, DdiOp::SetSealedBk3);
        }
    }

    #[test]
    fn test_dispatch_set_sealed_bk3_invalid_size() {
        let dispatcher = create_dispatcher(4);

        let sealed_bk3_data = [0x42u8; 1024]; // Too large - exceeds 512 byte limit

        let mut out_data = [0u8; 2048];
        let result = helper_dispatch_set_sealed_bk3(&dispatcher, &sealed_bk3_data, &mut out_data);

        assert!(result.is_ok(), "Dispatch should succeed: {:?}", result);
        let session_info = result.unwrap();

        // Now decode the response to validate the error status
        let mut decoder =
            DdiDecoder::new(&out_data[..session_info.response_length as usize], false);
        let resp_hdr = decoder
            .decode_hdr::<DdiRespHdr>()
            .expect("Failed to decode response header");

        assert_eq!(
            resp_hdr.status,
            DdiStatus::from(ManticoreError::SealedBk3TooLarge)
        );
    }

    #[test]
    fn test_dispatch_get_sealed_bk3() {
        let dispatcher = create_dispatcher(4);

        let sealed_bk3_data = [0x42u8; 256]; // 256 bytes of test data

        // Set the sealed BK3 first using our helper
        let mut set_out_data = [0u8; 2048];
        let set_result =
            helper_dispatch_set_sealed_bk3(&dispatcher, &sealed_bk3_data, &mut set_out_data);
        assert!(
            set_result.is_ok(),
            "Set operation should succeed: {:?}",
            set_result
        );

        // Now test getting the sealed BK3
        let api_rev = dispatcher.function.get_api_rev_range().max;
        let get_req = DdiGetSealedBk3Req {};

        let get_hdr = DdiReqHdr {
            rev: Some(DdiApiRev {
                major: api_rev.major,
                minor: api_rev.minor,
            }),
            op: DdiOp::GetSealedBk3,
            sess_id: None,
        };

        let mut get_in_data = [0u8; 2048];
        let get_req_size =
            DdiEncoder::encode_parts(get_hdr, get_req, &mut get_in_data, false).unwrap();

        let get_session_info_request = SessionInfoRequest {
            session_control_kind: SessionControlKind::from(DdiOp::GetSealedBk3),
            session_id: None,
        };

        let mut get_out_data = [0u8; 2048];
        let get_result = dispatcher.dispatch(
            get_session_info_request,
            &get_in_data[..get_req_size],
            &mut get_out_data,
        );

        assert!(
            get_result.is_ok(),
            "Get dispatch should succeed: {:?}",
            get_result
        );
        let session_info = get_result.unwrap();
        assert_eq!(
            session_info.session_control_kind,
            SessionControlKind::NoSession
        );

        let mut decoder = DdiDecoder::new(
            &get_out_data[..session_info.response_length as usize],
            false,
        );
        let resp_hdr = decoder
            .decode_hdr::<DdiRespHdr>()
            .expect("Failed to decode response header");

        assert_eq!(resp_hdr.status, DdiStatus::Success);
        assert_eq!(resp_hdr.op, DdiOp::GetSealedBk3);

        let resp_data = decoder
            .decode_data::<DdiGetSealedBk3Resp>()
            .expect("Failed to decode response data");

        assert_eq!(resp_data.sealed_bk3.len(), sealed_bk3_data.len());
        assert_eq!(
            resp_data.sealed_bk3.data()[..sealed_bk3_data.len()],
            sealed_bk3_data
        );
    }

    #[test]
    fn test_dispatch_get_sealed_bk3_not_set() {
        let dispatcher = create_dispatcher(4);

        let get_req = DdiGetSealedBk3Req {};

        let api_rev = dispatcher.function.get_api_rev_range().max;
        let get_hdr = DdiReqHdr {
            rev: Some(DdiApiRev {
                major: api_rev.major,
                minor: api_rev.minor,
            }),
            op: DdiOp::GetSealedBk3,
            sess_id: None,
        };

        let mut get_in_data = [0u8; 2048];
        let get_req_size =
            DdiEncoder::encode_parts(get_hdr, get_req, &mut get_in_data, false).unwrap();

        let get_session_info_request = SessionInfoRequest {
            session_control_kind: SessionControlKind::from(DdiOp::GetSealedBk3),
            session_id: None,
        };

        let mut get_out_data = [0u8; 2048];
        let get_result = dispatcher.dispatch(
            get_session_info_request,
            &get_in_data[..get_req_size],
            &mut get_out_data,
        );

        assert!(
            get_result.is_ok(),
            "Get dispatch should succeed: {:?}",
            get_result
        );
        let session_info = get_result.unwrap();

        let mut decoder = DdiDecoder::new(
            &get_out_data[..session_info.response_length as usize],
            false,
        );
        let resp_hdr = decoder
            .decode_hdr::<DdiRespHdr>()
            .expect("Failed to decode response header");

        assert_eq!(
            resp_hdr.status,
            DdiStatus::from(ManticoreError::SealedBk3NotPresent)
        );
    }
}
