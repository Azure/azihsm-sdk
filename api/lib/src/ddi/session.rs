// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Session management operations.
//!
//! This module provides functionality for managing HSM sessions, including
//! opening, closing, and reopening authenticated sessions on partitions.

use azihsm_cred_encrypt::DeviceCredKey;
use azihsm_crypto::Rng;

use super::*;

/// Result of a successful [`open_session`] call.
///
/// Carries the session identifiers plus the material needed to reopen the
/// session after a live migration or firmware crash recovery event.
pub(crate) struct OpenSessionResult {
    /// Device-assigned session ID.
    pub(crate) sess_id: u16,
    /// Short application ID returned by the device.
    pub(crate) short_app_id: u8,
    /// The 48-byte random seed used during credential encryption.
    /// Needed for [`reopen_session`].
    pub(crate) seed: [u8; 48],
    /// Backed-up session masking key returned by the device.
    /// Needed for [`reopen_session`].
    pub(crate) bmk_session: Vec<u8>,
}

/// Result of a successful [`reopen_session`] call.
///
/// Contains the confirmed session ID and updated BMK from the device.
pub(crate) struct ReopenSessionResult {
    /// Device-confirmed session ID (must match the requested ID).
    #[allow(dead_code)]
    pub(crate) sess_id: u16,
    /// Short application ID returned by the device.
    #[allow(dead_code)]
    pub(crate) short_app_id: u8,
    /// Updated backed-up session masking key from the device.
    /// Must replace the previously cached `bmk_session`.
    pub(crate) bmk_session: Vec<u8>,
}

/// Opens a new session on an HSM partition.
///
/// Creates a new authenticated session with the specified API revision and
/// application credentials. The session provides a context for performing
/// cryptographic operations on the device.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use for the session
/// * `creds` - Application credentials for authentication
/// * `seed` - Optional seed value for session initialization
///
/// # Returns
///
/// Returns an [`OpenSessionResult`] containing the session identifiers
/// and material needed for later reopening.
///
/// # Errors
///
/// Returns an error if:
/// - Credentials are invalid or authentication fails
/// - The requested API revision is not supported
/// - Maximum number of sessions is reached
/// - Device communication fails
/// - The DDI operation returns an error
pub(crate) fn open_session(
    dev: &HsmDev,
    rev: HsmApiRev,
    creds: &HsmCredentials,
    seed: Option<&[u8]>,
) -> HsmResult<OpenSessionResult> {
    let seed: [u8; 48] = match seed {
        Some(s) => s.try_into().map_hsm_err(HsmError::InvalidArgument)?,
        None => {
            let mut seed = [0u8; 48];
            Rng::rand_bytes(&mut seed).map_hsm_err(HsmError::RngError)?;
            seed
        }
    };
    let (ecreds, pub_key) = prepare_session_credentials(dev, rev, creds, seed)?;
    let req = DdiOpenSessionCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::OpenSession, Some(rev), None),
        data: DdiOpenSessionReq {
            encrypted_credential: ecreds,
            pub_key,
        },
        ext: None,
    };
    let resp = dev.exec_op(&req, &mut None).map_err(HsmError::from)?;
    Ok(OpenSessionResult {
        sess_id: resp.data.sess_id,
        short_app_id: resp.data.short_app_id,
        seed,
        bmk_session: resp.data.bmk_session.as_slice().to_vec(),
    })
}

/// Closes an active HSM session.
///
/// Terminates the specified session, releasing any associated resources
/// and invalidating the session ID.
///
/// # Resiliency
///
/// `close_session` silently treats retryable errors as success rather than retrying.
///
/// Rationale: Every retryable error indicates that the device has
/// been through a resiliency event. Such events destroy all sessions on the device,
/// so the session this call intended to close is already gone. Retrying
/// would require restoring the partition and reopening the session
/// just to immediately close it. The caller's intent of closing the session
/// (releasing resources, invalidating the session ID) has been satisfied by the reset itself,
/// so we can skip the retry and treat it as success.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `id` - The session ID to close
/// * `rev` - The API revision to use
///
/// # Returns
///
/// Returns `Ok(())` on successful closure, or if the device has
/// undergone a resiliency event that already destroyed the session.
pub(crate) fn close_session(dev: &HsmDev, id: u16, rev: HsmApiRev) -> HsmResult<()> {
    let req = DdiCloseSessionCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::CloseSession, Some(rev), Some(id)),
        data: DdiCloseSessionReq {},
        ext: None,
    };

    let result = dev.exec_op(&req, &mut None).map_err(HsmError::from);

    match result {
        Ok(_) => Ok(()),
        Err(ref err) if crate::resiliency::is_key_op_retryable_error(err) => Ok(()),
        Err(err) => Err(err),
    }
}

/// Reopens an existing session after a resiliency event (live migration
/// or firmware crash recovery).
///
/// Re-encrypts the cached credentials using the original seed and sends
/// them along with the backed-up session masking key to the device. The
/// device re-establishes the session with the same session ID.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision used when the session was originally opened
/// * `sess_id` - The original device-assigned session ID
/// * `creds` - Application credentials for re-authentication
/// * `seed` - The 48-byte seed cached from the original [`open_session`]
/// * `bmk_session` - The backed-up session masking key from the device
///
/// # Returns
///
/// Returns a [`ReopenSessionResult`] containing the confirmed session ID
/// and an updated BMK that should replace the previously cached value.
///
/// # Errors
///
/// Returns an error if:
/// - Credentials are invalid or re-authentication fails
/// - The session ID is no longer valid
/// - The device returns a different session ID than requested
/// - Device communication fails
pub(crate) fn reopen_session(
    dev: &HsmDev,
    rev: HsmApiRev,
    sess_id: u16,
    creds: &HsmCredentials,
    seed: &[u8; 48],
    bmk_session: &[u8],
) -> HsmResult<ReopenSessionResult> {
    let (ecreds, pub_key) = prepare_session_credentials(dev, rev, creds, *seed)?;
    let req = DdiReopenSessionCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::ReopenSession, Some(rev), Some(sess_id)),
        data: DdiReopenSessionReq {
            encrypted_credential: ecreds,
            pub_key,
            bmk_session: MborByteArray::from_slice(bmk_session)
                .map_hsm_err(HsmError::InternalError)?,
        },
        ext: None,
    };
    let resp = dev.exec_op(&req, &mut None).map_err(HsmError::from)?;

    // The device must confirm the same session ID we requested.
    if resp.data.sess_id != sess_id {
        return Err(HsmError::InternalError);
    }

    Ok(ReopenSessionResult {
        sess_id: resp.data.sess_id,
        short_app_id: resp.data.short_app_id,
        bmk_session: resp.data.bmk_session.as_slice().to_vec(),
    })
}

/// Prepares encrypted session credentials for open or reopen.
///
/// Fetches the session encryption key from the device, generates an
/// ephemeral ECDH key pair, and encrypts the credentials with the
/// given seed.
fn prepare_session_credentials(
    dev: &HsmDev,
    rev: HsmApiRev,
    creds: &HsmCredentials,
    seed: [u8; 48],
) -> HsmResult<(DdiEncryptedSessionCredential, DdiDerPublicKey)> {
    let resp = get_session_encryption_key(dev, rev)?;
    let nonce = resp.data.nonce;
    let key = DeviceCredKey::new(&resp.data.pub_key, nonce).map_err(|_| HsmError::InternalError)?;
    let (priv_key, pub_key) = key
        .generate_ephemeral_encryption_key()
        .map_err(|_| HsmError::InternalError)?;
    let ecreds = priv_key
        .encrypt_session_credential(creds.id, creds.pin, seed, nonce)
        .map_err(|_| HsmError::InternalError)?;
    Ok((ecreds, pub_key))
}

/// Retrieves the encryption key for session establishment.
///
/// Obtains the public key and nonce required for encrypting session
/// credentials during the session opening process.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
///
/// # Returns
///
/// Returns the session encryption key response containing public key and nonce.
///
/// # Errors
///
/// Returns an error if the key retrieval fails or device communication fails.
fn get_session_encryption_key(
    dev: &HsmDev,
    rev: HsmApiRev,
) -> HsmResult<DdiGetSessionEncryptionKeyCmdResp> {
    let req = DdiGetSessionEncryptionKeyCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::GetSessionEncryptionKey, Some(rev), None),
        data: DdiGetSessionEncryptionKeyReq {},
        ext: None,
    };
    let resp = dev.exec_op(&req, &mut None).map_err(HsmError::from)?;
    Ok(resp)
}
