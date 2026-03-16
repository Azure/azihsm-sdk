// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire protocol for the AZIHSM simulator service.
//!
//! Defines the framing format used between the sim-service client and server
//! over a Unix Domain Socket (or future Named Pipe) transport.

use std::io::{self, Read, Write};

use azihsm_ddi_sim::aesgcmxts::{
    SessionAesGcmRequest, SessionAesGcmResponse, SessionAesXtsRequest, SessionAesXtsResponse,
};
use azihsm_ddi_sim::crypto::aes::AesMode;
use azihsm_ddi_sim::errors::ManticoreError;
use azihsm_ddi_types::{SessionControlKind, SessionInfoRequest, SessionInfoResponse};

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Message type identifiers for the wire protocol.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Slow-path generic dispatch (MBOR buffer in/out)
    SlowPath = 1,
    /// Fast-path AES-GCM encrypt/decrypt
    FpGcm = 2,
    /// Fast-path AES-XTS encrypt/decrypt
    FpXts = 3,
    /// Flush (close) a session by ID
    FlushSession = 4,
    /// Simulate NSSR after live-migration
    MigrationSim = 5,

    /// Response: success
    ResponseOk = 128,
    /// Response: ManticoreError
    ResponseManticoreErr = 129,
}

impl TryFrom<u8> for MessageType {
    type Error = io::Error;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::SlowPath),
            2 => Ok(Self::FpGcm),
            3 => Ok(Self::FpXts),
            4 => Ok(Self::FlushSession),
            5 => Ok(Self::MigrationSim),
            128 => Ok(Self::ResponseOk),
            129 => Ok(Self::ResponseManticoreErr),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown message type {v}"),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

fn write_u8(w: &mut impl Write, v: u8) -> io::Result<()> {
    w.write_all(&[v])
}

fn read_u8(r: &mut impl Read) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn write_u16(w: &mut impl Write, v: u16) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn read_u16(r: &mut impl Read) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn write_u32(w: &mut impl Write, v: u32) -> io::Result<()> {
    w.write_all(&v.to_le_bytes())
}

fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn write_bool(w: &mut impl Write, v: bool) -> io::Result<()> {
    write_u8(w, u8::from(v))
}

fn read_bool(r: &mut impl Read) -> io::Result<bool> {
    Ok(read_u8(r)? != 0)
}

fn write_option_u16(w: &mut impl Write, v: Option<u16>) -> io::Result<()> {
    match v {
        Some(val) => {
            write_u8(w, 1)?;
            write_u16(w, val)
        }
        None => write_u8(w, 0),
    }
}

fn read_option_u16(r: &mut impl Read) -> io::Result<Option<u16>> {
    let tag = read_u8(r)?;
    if tag == 0 {
        Ok(None)
    } else {
        Ok(Some(read_u16(r)?))
    }
}

fn write_option_u8(w: &mut impl Write, v: Option<u8>) -> io::Result<()> {
    match v {
        Some(val) => {
            write_u8(w, 1)?;
            write_u8(w, val)
        }
        None => write_u8(w, 0),
    }
}

fn read_option_u8(r: &mut impl Read) -> io::Result<Option<u8>> {
    let tag = read_u8(r)?;
    if tag == 0 {
        Ok(None)
    } else {
        Ok(Some(read_u8(r)?))
    }
}

fn write_bytes(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    write_u32(w, data.len() as u32)?;
    w.write_all(data)
}

fn read_bytes(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let len = read_u32(r)? as usize;
    // Protect against unreasonable allocations
    if len > 64 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message payload too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_optional_bytes(w: &mut impl Write, data: &Option<Vec<u8>>) -> io::Result<()> {
    match data {
        Some(d) => {
            write_u8(w, 1)?;
            write_bytes(w, d)
        }
        None => write_u8(w, 0),
    }
}

fn read_optional_bytes(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let tag = read_u8(r)?;
    if tag == 0 {
        Ok(None)
    } else {
        Ok(Some(read_bytes(r)?))
    }
}

fn write_fixed<const N: usize>(w: &mut impl Write, data: &[u8; N]) -> io::Result<()> {
    w.write_all(data)
}

fn read_fixed<const N: usize>(r: &mut impl Read) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_option_fixed<const N: usize>(
    w: &mut impl Write,
    data: &Option<[u8; N]>,
) -> io::Result<()> {
    match data {
        Some(d) => {
            write_u8(w, 1)?;
            write_fixed(w, d)
        }
        None => write_u8(w, 0),
    }
}

fn read_option_fixed<const N: usize>(r: &mut impl Read) -> io::Result<Option<[u8; N]>> {
    let tag = read_u8(r)?;
    if tag == 0 {
        Ok(None)
    } else {
        Ok(Some(read_fixed(r)?))
    }
}

// ---------------------------------------------------------------------------
// SessionControlKind serialization
// ---------------------------------------------------------------------------

fn session_control_kind_to_u8(k: SessionControlKind) -> u8 {
    u8::from(k)
}

fn session_control_kind_from_u8(v: u8) -> io::Result<SessionControlKind> {
    match v {
        0 => Ok(SessionControlKind::NoSession),
        1 => Ok(SessionControlKind::Open),
        2 => Ok(SessionControlKind::Close),
        3 => Ok(SessionControlKind::InSession),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid SessionControlKind {v}"),
        )),
    }
}

// ---------------------------------------------------------------------------
// AesMode serialization
// ---------------------------------------------------------------------------

fn aes_mode_to_u8(m: &AesMode) -> u8 {
    match m {
        AesMode::Encrypt => 0,
        AesMode::Decrypt => 1,
    }
}

fn aes_mode_from_u8(v: u8) -> io::Result<AesMode> {
    match v {
        0 => Ok(AesMode::Encrypt),
        1 => Ok(AesMode::Decrypt),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid AesMode {v}"),
        )),
    }
}

// ---------------------------------------------------------------------------
// ManticoreError serialization (as u16 discriminant)
// ---------------------------------------------------------------------------

/// Convert ManticoreError to a u16 discriminant for wire transmission.
pub fn manticore_error_to_u16(e: ManticoreError) -> u16 {
    e as u16
}

/// Convert a u16 discriminant back to ManticoreError.
pub fn manticore_error_from_u16(v: u16) -> io::Result<ManticoreError> {
    ALL_MANTICORE_ERRORS
        .iter()
        .find(|&&e| e as u16 == v)
        .copied()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown ManticoreError discriminant {v}"),
            )
        })
}

/// All ManticoreError variants for lookup.
static ALL_MANTICORE_ERRORS: &[ManticoreError] = &[
    ManticoreError::InvalidArgument,
    ManticoreError::InternalError,
    ManticoreError::SessionNotExpected,
    ManticoreError::SessionExpected,
    ManticoreError::NotEnoughSpace,
    ManticoreError::ReachedMaxKeys,
    ManticoreError::InvalidKeyIndex,
    ManticoreError::CannotDeleteKeyInUse,
    ManticoreError::CannotDeleteSomeKeysInUse,
    ManticoreError::CannotCloseSessionInUse,
    ManticoreError::CannotCloseSomeSessionsInUse,
    ManticoreError::CannotDeleteKeyAndCloseSessionInUse,
    ManticoreError::AppNotFound,
    ManticoreError::AppAlreadyExists,
    ManticoreError::InvalidKeyNumber,
    ManticoreError::KeyNotFound,
    ManticoreError::KeyTagAlreadyExists,
    ManticoreError::KeyAlreadyExists,
    ManticoreError::VaultNotFound,
    ManticoreError::VaultSessionLimitReached,
    ManticoreError::VaultAppLimitReached,
    ManticoreError::InvalidVaultManagerCredentials,
    ManticoreError::InvalidAppCredentials,
    ManticoreError::CannotUseDefaultCredentials,
    ManticoreError::CannotUseReservedId,
    ManticoreError::SessionNotFound,
    ManticoreError::SessionNeedsRenegotiation,
    ManticoreError::FunctionNotFound,
    ManticoreError::UnsupportedRevision,
    ManticoreError::InvalidKeyType,
    ManticoreError::DerAndKeyTypeMismatch,
    ManticoreError::RsaFromDerError,
    ManticoreError::RsaToDerError,
    ManticoreError::RsaGenerateError,
    ManticoreError::RsaEncryptError,
    ManticoreError::RsaDecryptError,
    ManticoreError::RsaSignError,
    ManticoreError::RsaVerifyError,
    ManticoreError::RsaGetModulusError,
    ManticoreError::RsaGetPublicExponentError,
    ManticoreError::RsaInvalidKeyType,
    ManticoreError::RsaInvalidKeyLength,
    ManticoreError::InvalidPermissions,
    ManticoreError::CborDecodeError,
    ManticoreError::CborEncodeError,
    ManticoreError::EccFromDerError,
    ManticoreError::EccToDerError,
    ManticoreError::EccGenerateError,
    ManticoreError::EccSignError,
    ManticoreError::EccVerifyError,
    ManticoreError::EccDeriveError,
    ManticoreError::EccGetCurveError,
    ManticoreError::EccGetCoordinatesError,
    ManticoreError::ShaError,
    ManticoreError::EccInvalidKeyType,
    ManticoreError::AesGenerateError,
    ManticoreError::AesEncryptError,
    ManticoreError::AesDecryptError,
    ManticoreError::AesInvalidKeyType,
    ManticoreError::CoseSign1UnexpectedSignature,
    ManticoreError::HkdfError,
    ManticoreError::KbkdfError,
    ManticoreError::HmacError,
    ManticoreError::PinDecryptionFailed,
    ManticoreError::RsaUnwrapInvalidReq,
    ManticoreError::RsaUnwrapInvalidUnwrappingKeyLength,
    ManticoreError::RsaUnwrapRsaOaepDecryptFailed,
    ManticoreError::RsaUnwrapAesUnwrapFailed,
    ManticoreError::AttestKeyInternalErr,
    ManticoreError::AesGcmInvalidBufSize,
    ManticoreError::AesInvalidShortAppId,
    ManticoreError::AesInvalidTag,
    ManticoreError::AesXtsInvalidBufSize,
    ManticoreError::AesXtsInvalidDul,
    ManticoreError::EccInvalidKeyLength,
    ManticoreError::AesInvalidKeyLength,
    ManticoreError::EccPubKeyCertGenerateError,
    ManticoreError::CannotDeleteInternalKeys,
    ManticoreError::RngError,
    ManticoreError::NonceMismatch,
    ManticoreError::MaskedKeyInvalidLength,
    ManticoreError::MaskedKeyPreEncodeFailed,
    ManticoreError::MaskedKeyEncodeFailed,
    ManticoreError::MaskedKeyDecodeFailed,
    ManticoreError::PartitionAlreadyProvisioned,
    ManticoreError::SealedBk3TooLarge,
    ManticoreError::SealedBk3NotPresent,
    ManticoreError::CredentialsNotEstablished,
    ManticoreError::PartitionNotProvisioned,
    ManticoreError::InvalidAlgorithm,
    ManticoreError::OutputBufferTooSmall,
    ManticoreError::InvalidKeyLength,
    ManticoreError::MborEncodeFailed,
    ManticoreError::MetadataEncodeFailed,
    ManticoreError::MetadataDecodeFailed,
    ManticoreError::AesEncryptFailed,
    ManticoreError::AesDecryptFailed,
    ManticoreError::ReportSignatureMismatch,
    ManticoreError::Bk3AlreadyInitialized,
    ManticoreError::SealedBk3AlreadySet,
    ManticoreError::PartitionIdKeyGenerationPctFailed,
];

// ---------------------------------------------------------------------------
// Chunk-list serialization (for fast-path buffers)
// ---------------------------------------------------------------------------

fn write_chunk_list(w: &mut impl Write, chunks: &[Vec<u8>]) -> io::Result<()> {
    write_u32(w, chunks.len() as u32)?;
    for chunk in chunks {
        write_bytes(w, chunk)?;
    }
    Ok(())
}

fn read_chunk_list(r: &mut impl Read) -> io::Result<Vec<Vec<u8>>> {
    let count = read_u32(r)? as usize;
    if count > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "too many chunks",
        ));
    }
    let mut chunks = Vec::with_capacity(count);
    for _ in 0..count {
        chunks.push(read_bytes(r)?);
    }
    Ok(chunks)
}

// ===========================================================================
// REQUEST ENCODING / DECODING
// ===========================================================================

// ---------------------------------------------------------------------------
// SlowPath request
// ---------------------------------------------------------------------------

/// Write a slow-path request frame.
pub fn write_slow_path_request(
    w: &mut impl Write,
    session_info: &SessionInfoRequest,
    req_buf: &[u8],
) -> io::Result<()> {
    write_u8(w, MessageType::SlowPath as u8)?;
    // SessionInfoRequest
    write_u8(w, session_control_kind_to_u8(session_info.session_control_kind))?;
    write_option_u16(w, session_info.session_id)?;
    // request buffer
    write_bytes(w, req_buf)?;
    w.flush()
}

/// Write a flush-session request.
pub fn write_flush_session_request(w: &mut impl Write, session_id: u16) -> io::Result<()> {
    write_u8(w, MessageType::FlushSession as u8)?;
    write_u16(w, session_id)?;
    w.flush()
}

/// Write a migration-sim request.
pub fn write_migration_sim_request(w: &mut impl Write) -> io::Result<()> {
    write_u8(w, MessageType::MigrationSim as u8)?;
    w.flush()
}

// ---------------------------------------------------------------------------
// FP GCM request
// ---------------------------------------------------------------------------

/// Write a fast-path GCM request frame.
pub fn write_fp_gcm_request(
    w: &mut impl Write,
    mode: &AesMode,
    req: &SessionAesGcmRequest,
    source_buffers: &[Vec<u8>],
) -> io::Result<()> {
    write_u8(w, MessageType::FpGcm as u8)?;
    write_u8(w, aes_mode_to_u8(mode))?;
    // SessionAesGcmRequest fields
    write_u32(w, req.key_id)?;
    write_fixed(w, &req.iv)?;
    write_option_fixed(w, &req.tag)?;
    write_u16(w, req.session_id)?;
    write_u8(w, req.short_app_id)?;
    write_optional_bytes(w, &req.aad)?;
    // source buffers
    write_chunk_list(w, source_buffers)?;
    w.flush()
}

// ---------------------------------------------------------------------------
// FP XTS request
// ---------------------------------------------------------------------------

/// Write a fast-path XTS request frame.
pub fn write_fp_xts_request(
    w: &mut impl Write,
    mode: &AesMode,
    req: &SessionAesXtsRequest,
    source_buffers: &[Vec<u8>],
) -> io::Result<()> {
    write_u8(w, MessageType::FpXts as u8)?;
    write_u8(w, aes_mode_to_u8(mode))?;
    // SessionAesXtsRequest fields
    write_u32(w, req.data_unit_len as u32)?;
    write_u32(w, req.key_id1)?;
    write_u32(w, req.key_id2)?;
    write_fixed(w, &req.tweak)?;
    write_u16(w, req.session_id)?;
    write_u8(w, req.short_app_id)?;
    // source buffers
    write_chunk_list(w, source_buffers)?;
    w.flush()
}

// ===========================================================================
// REQUEST READING (server-side)
// ===========================================================================

/// A decoded request from a client.
pub enum Request {
    /// Slow-path generic dispatch
    SlowPath {
        /// Session info
        session_info: SessionInfoRequest,
        /// MBOR-encoded request buffer
        req_buf: Vec<u8>,
    },
    /// Fast-path AES-GCM
    FpGcm {
        /// Encrypt or decrypt
        mode: AesMode,
        /// GCM parameters
        request: SessionAesGcmRequest,
        /// Source data chunks
        source_buffers: Vec<Vec<u8>>,
    },
    /// Fast-path AES-XTS
    FpXts {
        /// Encrypt or decrypt
        mode: AesMode,
        /// XTS parameters
        request: SessionAesXtsRequest,
        /// Source data chunks
        source_buffers: Vec<Vec<u8>>,
    },
    /// Flush (close) a session
    FlushSession {
        /// Session ID to flush
        session_id: u16,
    },
    /// Simulate NSSR after live-migration
    MigrationSim,
}

/// Read a request from the stream. Returns `None` on clean EOF.
pub fn read_request(r: &mut impl Read) -> io::Result<Option<Request>> {
    let msg_type_byte = match read_u8(r) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };

    let msg_type = MessageType::try_from(msg_type_byte)?;

    match msg_type {
        MessageType::SlowPath => {
            let sck = session_control_kind_from_u8(read_u8(r)?)?;
            let session_id = read_option_u16(r)?;
            let req_buf = read_bytes(r)?;
            Ok(Some(Request::SlowPath {
                session_info: SessionInfoRequest {
                    session_control_kind: sck,
                    session_id,
                },
                req_buf,
            }))
        }
        MessageType::FpGcm => {
            let mode = aes_mode_from_u8(read_u8(r)?)?;
            let key_id = read_u32(r)?;
            let iv = read_fixed::<12>(r)?;
            let tag = read_option_fixed::<16>(r)?;
            let session_id = read_u16(r)?;
            let short_app_id = read_u8(r)?;
            let aad = read_optional_bytes(r)?;
            let source_buffers = read_chunk_list(r)?;
            Ok(Some(Request::FpGcm {
                mode,
                request: SessionAesGcmRequest {
                    key_id,
                    iv,
                    tag,
                    session_id,
                    short_app_id,
                    aad,
                },
                source_buffers,
            }))
        }
        MessageType::FpXts => {
            let mode = aes_mode_from_u8(read_u8(r)?)?;
            let data_unit_len = read_u32(r)? as usize;
            let key_id1 = read_u32(r)?;
            let key_id2 = read_u32(r)?;
            let tweak = read_fixed::<16>(r)?;
            let session_id = read_u16(r)?;
            let short_app_id = read_u8(r)?;
            let source_buffers = read_chunk_list(r)?;
            Ok(Some(Request::FpXts {
                mode,
                request: SessionAesXtsRequest {
                    data_unit_len,
                    key_id1,
                    key_id2,
                    tweak,
                    session_id,
                    short_app_id,
                },
                source_buffers,
            }))
        }
        MessageType::FlushSession => {
            let session_id = read_u16(r)?;
            Ok(Some(Request::FlushSession { session_id }))
        }
        MessageType::MigrationSim => Ok(Some(Request::MigrationSim)),
        MessageType::ResponseOk | MessageType::ResponseManticoreErr => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "received response message type in request stream",
        )),
    }
}

// ===========================================================================
// RESPONSE ENCODING / DECODING
// ===========================================================================

// ---------------------------------------------------------------------------
// SlowPath response
// ---------------------------------------------------------------------------

/// Write a slow-path success response.
pub fn write_slow_path_response(
    w: &mut impl Write,
    session_info_response: &SessionInfoResponse,
    resp_buf: &[u8],
) -> io::Result<()> {
    write_u8(w, MessageType::ResponseOk as u8)?;
    write_u8(w, MessageType::SlowPath as u8)?;
    // SessionInfoResponse
    write_u16(w, session_info_response.response_length)?;
    write_u8(
        w,
        session_control_kind_to_u8(session_info_response.session_control_kind),
    )?;
    write_option_u16(w, session_info_response.session_id)?;
    write_option_u8(w, session_info_response.short_app_id)?;
    // response buffer
    write_bytes(w, resp_buf)?;
    w.flush()
}

/// Write a ManticoreError response.
pub fn write_error_response(
    w: &mut impl Write,
    original_msg_type: MessageType,
    err: ManticoreError,
) -> io::Result<()> {
    write_u8(w, MessageType::ResponseManticoreErr as u8)?;
    write_u8(w, original_msg_type as u8)?;
    write_u16(w, manticore_error_to_u16(err))?;
    w.flush()
}

/// Write a GCM success response.
pub fn write_fp_gcm_response(
    w: &mut impl Write,
    resp: &SessionAesGcmResponse,
    destination_buffers: &[Vec<u8>],
) -> io::Result<()> {
    write_u8(w, MessageType::ResponseOk as u8)?;
    write_u8(w, MessageType::FpGcm as u8)?;
    write_option_fixed(w, &resp.tag)?;
    write_u32(w, resp.total_size)?;
    write_option_fixed(w, &resp.iv)?;
    write_bool(w, resp.fips_approved)?;
    write_chunk_list(w, destination_buffers)?;
    w.flush()
}

/// Write an XTS success response.
pub fn write_fp_xts_response(
    w: &mut impl Write,
    resp: &SessionAesXtsResponse,
    destination_buffers: &[Vec<u8>],
) -> io::Result<()> {
    write_u8(w, MessageType::ResponseOk as u8)?;
    write_u8(w, MessageType::FpXts as u8)?;
    write_u32(w, resp.total_size)?;
    write_bool(w, resp.fips_approved)?;
    write_chunk_list(w, destination_buffers)?;
    w.flush()
}

/// Write a simple success response (for FlushSession, MigrationSim).
pub fn write_ok_response(w: &mut impl Write, original_msg_type: MessageType) -> io::Result<()> {
    write_u8(w, MessageType::ResponseOk as u8)?;
    write_u8(w, original_msg_type as u8)?;
    w.flush()
}

// ---------------------------------------------------------------------------
// Response reading (client-side)
// ---------------------------------------------------------------------------

/// A decoded response from the server.
pub enum Response {
    /// Slow-path success
    SlowPath {
        /// Session info response
        session_info_response: SessionInfoResponse,
        /// MBOR-encoded response buffer
        resp_buf: Vec<u8>,
    },
    /// Fast-path GCM success
    FpGcm {
        /// GCM response metadata
        response: SessionAesGcmResponse,
        /// Destination data chunks
        destination_buffers: Vec<Vec<u8>>,
    },
    /// Fast-path XTS success
    FpXts {
        /// XTS response metadata
        response: SessionAesXtsResponse,
        /// Destination data chunks
        destination_buffers: Vec<Vec<u8>>,
    },
    /// Simple OK (FlushSession / MigrationSim)
    Ok {
        /// Which request this acks
        for_type: MessageType,
    },
    /// ManticoreError
    Error {
        /// Which request this is for
        for_type: MessageType,
        /// The error
        error: ManticoreError,
    },
}

/// Read a response from the stream.
pub fn read_response(r: &mut impl Read) -> io::Result<Response> {
    let resp_type = MessageType::try_from(read_u8(r)?)?;
    let for_type = MessageType::try_from(read_u8(r)?)?;

    match resp_type {
        MessageType::ResponseManticoreErr => {
            let err_code = read_u16(r)?;
            let error = manticore_error_from_u16(err_code)?;
            Ok(Response::Error { for_type, error })
        }
        MessageType::ResponseOk => match for_type {
            MessageType::SlowPath => {
                let response_length = read_u16(r)?;
                let sck = session_control_kind_from_u8(read_u8(r)?)?;
                let session_id = read_option_u16(r)?;
                let short_app_id = read_option_u8(r)?;
                let resp_buf = read_bytes(r)?;
                Ok(Response::SlowPath {
                    session_info_response: SessionInfoResponse {
                        response_length,
                        session_control_kind: sck,
                        session_id,
                        short_app_id,
                    },
                    resp_buf,
                })
            }
            MessageType::FpGcm => {
                let tag = read_option_fixed::<16>(r)?;
                let total_size = read_u32(r)?;
                let iv = read_option_fixed::<12>(r)?;
                let fips_approved = read_bool(r)?;
                let destination_buffers = read_chunk_list(r)?;
                Ok(Response::FpGcm {
                    response: SessionAesGcmResponse {
                        tag,
                        total_size,
                        iv,
                        fips_approved,
                    },
                    destination_buffers,
                })
            }
            MessageType::FpXts => {
                let total_size = read_u32(r)?;
                let fips_approved = read_bool(r)?;
                let destination_buffers = read_chunk_list(r)?;
                Ok(Response::FpXts {
                    response: SessionAesXtsResponse {
                        total_size,
                        fips_approved,
                    },
                    destination_buffers,
                })
            }
            MessageType::FlushSession | MessageType::MigrationSim => {
                Ok(Response::Ok { for_type })
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected for_type {for_type:?} in ResponseOk"),
            )),
        },
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected response type {resp_type:?}"),
        )),
    }
}
