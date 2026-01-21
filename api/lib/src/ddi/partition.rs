// Copyright (C) Microsoft Corporation. All rights reserved.

//! Partition initialization operations.
//!
//! This module provides functionality for initializing HSM partitions with
//! application credentials and master key material.

use azihsm_cred_encrypt::DeviceCredKey;
use azihsm_ddi_mbor::*;

use super::*;

/// Initializes an HSM partition with credentials and master keys.
///
/// Configures the partition for use by setting up authentication credentials
/// and optionally providing master key material. This operation must be performed
/// before the partition can be used for cryptographic operations.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use for initialization
/// * `creds` - Application credentials (ID and PIN)
/// * `bmk` - Optional backup masking key
/// * `muk` - Optional masked unwrapping key
/// * `mobk` - Optional masked owner backup key
///
/// # Errors
///
/// Returns an error if:
/// - The device is already initialized
/// - Credentials are invalid
/// - Master key material is malformed or invalid
/// - The API revision is not supported
/// - Device communication fails
/// - The DDI operation returns an error
pub(crate) fn init_part(
    dev: &HsmDev,
    rev: HsmApiRev,
    creds: HsmCredentials,
    bmk: Option<&[u8]>,
    muk: Option<&[u8]>,
    mobk: Option<&[u8]>,
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let mobk = match mobk {
        Some(mobk) => mobk.to_vec(),
        None => init_bk3(dev, rev)?,
    };

    let resp = get_establish_cred_encryption_key(dev, rev)?;

    let nonce = resp.data.nonce;
    let key = DeviceCredKey::new(&resp.data.pub_key, nonce).map_hsm_err(HsmError::DdiCmdFailure)?;

    let (priv_key, pub_key) = key
        .generate_ephemeral_encryption_key()
        .map_hsm_err(HsmError::InternalError)?;

    let ecreds = priv_key
        .encrypt_establish_credential(creds.id, creds.pin, nonce)
        .map_hsm_err(HsmError::InternalError)?;

    let bmk = bmk.unwrap_or_default();
    let muk = muk.unwrap_or_default();
    let bmk = establish_credential(dev, rev, ecreds, pub_key, bmk, muk, &mobk)?;

    Ok((bmk, mobk))
}

/// Initializes the backup key 3 (BK3) for the partition.
///
/// Generates or initializes the third-level backup key used in the key
/// hierarchy for partition security.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
///
/// # Returns
///
/// Returns the masked BK3 value.
///
/// # Errors
///
/// Returns an error if the BK3 initialization fails.
fn init_bk3(dev: &HsmDev, rev: HsmApiRev) -> HsmResult<Vec<u8>> {
    let bk3 = [1u8; 48];
    // Rng::rand_bytes(&mut bk3).map_hsm_err(HsmError::RngError)?;
    let req = DdiInitBk3CmdReq {
        hdr: build_ddi_req_hdr_sessionless(DdiOp::InitBk3, rev),
        data: DdiInitBk3Req {
            bk3: MborByteArray::from_slice(&bk3).map_hsm_err(HsmError::InternalError)?,
        },
        ext: None,
    };
    let resp = dev
        .exec_op(&req, &mut None)
        .map_hsm_err(HsmError::DdiCmdFailure)?;
    Ok(resp.data.masked_bk3.as_slice().to_vec())
}

/// Retrieves the encryption key for establishing credentials.
///
/// Obtains the public key and nonce required for encrypting application
/// credentials during the establishment process.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
///
/// # Returns
///
/// Returns the credential encryption key response containing public key and nonce.
///
/// # Errors
///
/// Returns an error if the key retrieval fails.
fn get_establish_cred_encryption_key(
    dev: &HsmDev,
    rev: HsmApiRev,
) -> HsmResult<DdiGetEstablishCredEncryptionKeyCmdResp> {
    let req = DdiGetEstablishCredEncryptionKeyCmdReq {
        hdr: build_ddi_req_hdr_sessionless(DdiOp::GetEstablishCredEncryptionKey, rev),
        data: DdiGetEstablishCredEncryptionKeyReq {},
        ext: None,
    };
    dev.exec_op(&req, &mut None)
        .map_hsm_err(HsmError::DdiCmdFailure)
}

/// Establishes application credentials on the HSM partition.
///
/// Completes the credential establishment process by sending encrypted
/// credentials along with key material to the device.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
/// * `enc_creds` - Encrypted credential data
/// * `pub_key` - DER-encoded ephemeral public key
/// * `bmk` - Backup masking key
/// * `muk` - Masked unwrapping key
/// * `mobk` - Masked owner backup key (BK3)
///
/// # Returns
///
/// Returns the masked backup masking key (MBMK).
///
/// # Errors
///
/// Returns an error if credential establishment fails.
pub fn establish_credential(
    dev: &HsmDev,
    rev: HsmApiRev,
    enc_creds: DdiEncryptedEstablishCredential,
    pub_key: DdiDerPublicKey,
    bmk: &[u8],
    muk: &[u8],
    mobk: &[u8],
) -> HsmResult<Vec<u8>> {
    let req = DdiEstablishCredentialCmdReq {
        hdr: build_ddi_req_hdr_sessionless(DdiOp::EstablishCredential, rev),
        data: DdiEstablishCredentialReq {
            encrypted_credential: enc_creds,
            pub_key,
            masked_bk3: MborByteArray::from_slice(mobk).map_hsm_err(HsmError::InternalError)?,
            bmk: MborByteArray::from_slice(bmk).map_hsm_err(HsmError::InternalError)?,
            masked_unwrapping_key: MborByteArray::from_slice(muk)
                .map_hsm_err(HsmError::InternalError)?,
        },
        ext: None,
    };
    let resp = dev
        .exec_op(&req, &mut None)
        .map_hsm_err(HsmError::DdiCmdFailure)?;
    Ok(resp.data.bmk.as_slice().to_vec())
}
