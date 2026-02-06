// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition initialization operations.
//!
//! This module provides functionality for initializing HSM partitions with
//! application credentials and master key material.

use azihsm_cred_encrypt::DeviceCredKey;
use azihsm_crypto as crypto;
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
/// * `obk_config` - Owner backup key (OBK/BK3) source and optional OBK
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
/// - TPM unsealing fails (when obk_config source is TPM)
/// - OBK is missing when obk_config source is Caller
pub(crate) fn init_part(
    dev: &HsmDev,
    rev: HsmApiRev,
    creds: HsmCredentials,
    bmk: Option<&[u8]>,
    muk: Option<&[u8]>,
    obk_config: HsmOwnerBackupKeyConfig<'_>,
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let mobk = match obk_config.key_source() {
        HsmOwnerBackupKeySource::Caller => {
            // Caller provided the OBK
            let obk = obk_config.key().ok_or(HsmError::InvalidArgument)?;
            init_bk3(dev, rev, obk)?
        }
        HsmOwnerBackupKeySource::Tpm => {
            // Retrieve sealed BK3 from device and unseal with TPM
            let sealed_bk3 = get_sealed_bk3(dev, rev)?;
            unseal_tpm_backup_key(&sealed_bk3)?
        }
        _ => return Err(HsmError::InvalidArgument),
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
/// Sends the caller-provided BK3 to the device and returns the masked BK3.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
/// * `bk3` - The owner backup key (BK3) provided by the caller
///
/// # Returns
///
/// Returns the masked BK3 value.
///
/// # Errors
///
/// Returns an error if the BK3 initialization fails.
fn init_bk3(dev: &HsmDev, rev: HsmApiRev, bk3: &[u8]) -> HsmResult<Vec<u8>> {
    let req = DdiInitBk3CmdReq {
        hdr: build_ddi_req_hdr(DdiOp::InitBk3, Some(rev), None),
        data: DdiInitBk3Req {
            bk3: MborByteArray::from_slice(bk3).map_hsm_err(HsmError::InternalError)?,
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
        hdr: build_ddi_req_hdr(DdiOp::GetEstablishCredEncryptionKey, Some(rev), None),
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
        hdr: build_ddi_req_hdr(DdiOp::EstablishCredential, Some(rev), None),
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

/// Retrieves the certificate chain stored in the HSM device.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
/// * `slot_id` - The certificate slot number
///
/// # Returns
///
/// Returns the certificate chain in PEM format.
pub(crate) fn get_cert_chain(dev: &HsmDev, rev: HsmApiRev, slot_id: u8) -> HsmResult<String> {
    let (count, thumbprint) = get_cert_chain_info(dev, rev, slot_id)?;

    let mut cert_chain = String::new();
    for cert_id in 0..count {
        let der = get_cert(dev, rev, slot_id, cert_id)?;
        let pem = crypto::der_to_pem(&der).map_hsm_err(HsmError::InternalError)?;
        cert_chain.push_str(&pem);
    }

    let (new_count, new_thumbprint) = get_cert_chain_info(dev, rev, slot_id)?;
    if new_count != count || new_thumbprint != thumbprint {
        return Err(HsmError::CertChainChanged);
    }

    Ok(cert_chain)
}

/// Retrieves certificate chain information from the HSM device.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
/// * `slot_id` - The certificate slot number
///
/// # Returns
///
/// Returns a tuple containing the number of certificates and the thumbprint.
fn get_cert_chain_info(dev: &HsmDev, rev: HsmApiRev, slot_id: u8) -> HsmResult<(u8, Vec<u8>)> {
    let req = DdiGetCertChainInfoCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::GetCertChainInfo, Some(rev), None),
        data: DdiGetCertChainInfoReq { slot_id },
        ext: None,
    };

    let resp = dev
        .exec_op(&req, &mut None)
        .map_hsm_err(HsmError::DdiCmdFailure)?;

    let count = resp.data.num_certs;
    let thumbprint = resp.data.thumbprint.as_slice().to_vec();

    Ok((count, thumbprint))
}

/// Retrieves a certificate from the HSM device.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
/// * `slot_id` - The certificate slot number
///
/// # Returns
///
/// Returns a vector containing the certificate bytes.
fn get_cert(dev: &HsmDev, rev: HsmApiRev, slot_id: u8, cert_id: u8) -> HsmResult<Vec<u8>> {
    let req = DdiGetCertificateCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::GetCertificate, Some(rev), None),
        data: DdiGetCertificateReq { slot_id, cert_id },
        ext: None,
    };

    let resp = dev
        .exec_op(&req, &mut None)
        .map_hsm_err(HsmError::DdiCmdFailure)?;

    Ok(resp.data.certificate.as_slice().to_vec())
}

/// Retrieves the TPM-sealed backup key 3 (BK3) from the device.
///
/// This function fetches a sealed BK3 that was created by UEFI firmware
/// and sealed using the TPM.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
///
/// # Returns
///
/// Returns the sealed BK3 data that needs to be unsealed using the TPM.
///
/// # Errors
///
/// Returns an error if the operation fails.
fn get_sealed_bk3(dev: &HsmDev, rev: HsmApiRev) -> HsmResult<Vec<u8>> {
    let req = DdiGetSealedBk3CmdReq {
        hdr: build_ddi_req_hdr(DdiOp::GetSealedBk3, Some(rev), None),
        data: DdiGetSealedBk3Req {},
        ext: None,
    };

    let resp = dev
        .exec_op(&req, &mut None)
        .map_hsm_err(HsmError::DdiCmdFailure)?;

    Ok(resp.data.sealed_bk3.as_slice().to_vec())
}
