// Copyright (C) Microsoft Corporation. All rights reserved.

//! Session management operations.
//!
//! This module provides functionality for managing HSM sessions, including
//! opening and closing authenticated sessions on partitions.

use azihsm_cred_encrypt::DeviceCredKey;
use azihsm_crypto::Rng;

use super::*;

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
/// Returns a tuple containing (session ID, application ID).
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
) -> HsmResult<(u16, u8)> {
    let seed = match seed {
        Some(s) => s.to_vec(),
        None => {
            let mut seed = vec![0u8; 48];
            Rng::rand_bytes(&mut seed).map_hsm_err(HsmError::RngError)?;
            seed
        }
    };
    let resp = get_session_encryption_key(dev, rev)?;
    let nonce = resp.data.nonce;
    let key = DeviceCredKey::new(&resp.data.pub_key, nonce).map_err(|_| HsmError::InternalError)?;
    let (priv_key, pub_key) = key
        .generate_ephemeral_encryption_key()
        .map_err(|_| HsmError::InternalError)?;
    let seed = seed.try_into().map_hsm_err(HsmError::InternalError)?;
    let ecreds = priv_key
        .encrypt_session_credential(creds.id, creds.pin, seed, nonce)
        .map_err(|_| HsmError::InternalError)?;
    let req = DdiOpenSessionCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::OpenSession, Some(rev), None),
        data: DdiOpenSessionReq {
            encrypted_credential: ecreds,
            pub_key,
        },
        ext: None,
    };
    let resp = dev
        .exec_op(&req, &mut None)
        .map_hsm_err(HsmError::DdiCmdFailure)?;
    Ok((resp.data.sess_id, resp.data.short_app_id))
}

/// Closes an active HSM session.
///
/// Terminates the specified session, releasing any associated resources
/// and invalidating the session ID.
///
/// # Arguments
///
/// * `session` - The HSM session handle
/// * `sess_id` - The session ID to close
///
/// # Errors
///
/// Returns an error if:
/// - The session ID is invalid
/// - The session is already closed
/// - Device communication fails
/// - The DDI operation returns an error
pub(crate) fn close_session(dev: &HsmDev, id: u16, rev: HsmApiRev) -> HsmResult<()> {
    let req = DdiCloseSessionCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::CloseSession, Some(rev), Some(id)),
        data: DdiCloseSessionReq {},
        ext: None,
    };
    dev.exec_op(&req, &mut None)
        .map_hsm_err(HsmError::DdiCmdFailure)?;
    Ok(())
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
    let resp = dev
        .exec_op(&req, &mut None)
        .map_hsm_err(HsmError::DdiCmdFailure)?;
    Ok(resp)
}
