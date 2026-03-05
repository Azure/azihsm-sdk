// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition initialization operations.
//!
//! This module provides functionality for initializing HSM partitions with
//! application credentials and master key material.

use azihsm_cred_encrypt::DeviceCredKey;
use azihsm_crypto as crypto;
use azihsm_ddi_mbor::*;
use crypto::*;
use x509::*;

use super::*;

/// Gets the public key from the last certificate in the partition's certificate chain.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
///
/// # Returns
///
/// Returns the DER-encoded public key from the last certificate.
pub(crate) fn get_part_pub_key(dev: &HsmDev, rev: HsmApiRev) -> HsmResult<Vec<u8>> {
    let (cert_count, _thumbprint) = get_cert_chain_info(dev, rev, 0)?;
    if cert_count == 0 {
        return Err(HsmError::InternalError);
    }

    // Get the last certificate (partition certificate)
    let cert_der = get_cert(dev, rev, 0, cert_count - 1)?;
    let cert = X509Certificate::from_der(&cert_der).map_hsm_err(HsmError::InternalError)?;
    let pub_key_der = cert
        .get_public_key_der()
        .map_hsm_err(HsmError::InternalError)?;

    Ok(pub_key_der)
}

/// Gets the SHA-384 digest of the partition's public key in uncompressed point format.
///
/// Retrieves the public key from the partition certificate, converts it to
/// uncompressed point format (0x04 || x || y), and hashes it with SHA-384.
/// This is used for POTA endorsement signing.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
///
/// # Returns
///
/// Returns the SHA-384 digest of the uncompressed public key point (48 bytes).
fn get_part_pub_key_digest(dev: &HsmDev, rev: HsmApiRev) -> HsmResult<Vec<u8>> {
    let cert_pub_key_der = get_part_pub_key(dev, rev)?;

    // Parse the DER-encoded public key and convert to uncompressed point format
    let cert_pub_key_obj =
        DerEccPublicKey::from_der(&cert_pub_key_der).map_hsm_err(HsmError::InternalError)?;
    let mut cert_pub_uncomp = vec![0x04u8];
    cert_pub_uncomp.extend_from_slice(cert_pub_key_obj.x());
    cert_pub_uncomp.extend_from_slice(cert_pub_key_obj.y());

    // Hash the uncompressed point with SHA-384
    let mut hasher = crypto::HashAlgo::sha384();
    let hash_len = hasher
        .hash(&cert_pub_uncomp, None)
        .map_hsm_err(HsmError::InternalError)?;
    let mut pub_key_digest = vec![0u8; hash_len];
    hasher
        .hash(&cert_pub_uncomp, Some(&mut pub_key_digest))
        .map_hsm_err(HsmError::InternalError)?;

    Ok(pub_key_digest)
}

/// Gets the POTA endorsement signature and public key based on the specified source.
///
/// This function handles all three POTA endorsement sources:
/// - **Caller**: Uses the provided endorsement data directly
/// - **Tpm**: Signs the hash of the partition's certificate public key using TPM
/// - **Random**: Generates a random ECC P-384 key pair and signs the hash
///
/// For TPM and Random sources, the data being signed is the SHA-384 hash of the
/// uncompressed public key point (0x04 || x || y) from the partition's certificate.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
/// * `pota_endorsement` - The POTA endorsement configuration
///
/// # Returns
///
/// Returns a tuple of (signature, public_key) as owned vectors.
///
/// # Errors
///
/// Returns an error if:
/// - Source is Caller but no endorsement data is provided
/// - Certificate retrieval fails
/// - TPM signing fails (for TPM source)
/// - Key generation or signing fails (for Random source)
fn get_pota_endorsement(
    dev: &HsmDev,
    rev: HsmApiRev,
    pota_endorsement: &HsmPotaEndorsement<'_>,
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    match pota_endorsement.source() {
        HsmPotaEndorsementSource::Caller => {
            let data = pota_endorsement
                .endorsement()
                .ok_or(HsmError::InvalidArgument)?;
            Ok((data.signature().to_vec(), data.pub_key().to_vec()))
        }

        HsmPotaEndorsementSource::Tpm => {
            let pub_key_digest = get_part_pub_key_digest(dev, rev)?;

            // Sign with TPM
            let (signature, tpm_public_key) = tpm_ecc_sign_digest(&pub_key_digest)?;
            // Signature is in raw r||s format, TPM public key is DER-encoded
            Ok((signature, tpm_public_key))
        }

        _ => Err(HsmError::InvalidArgument),
    }
}

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
/// * `obk_config` - Owner backup key (OBK) configuration
/// * `pota_endorsement` - The partition owner trust anchor endorsement
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
    pota_endorsement: HsmPotaEndorsement<'_>,
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

    // Compute POTA endorsement based on source
    let (pota_signature, pota_public_key) = get_pota_endorsement(dev, rev, &pota_endorsement)?;
    let pota_endorsement = HsmPotaEndorsementData::new(&pota_signature, &pota_public_key);

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
    let bmk = establish_credential(
        dev,
        rev,
        ecreds,
        pub_key,
        bmk,
        muk,
        &mobk,
        &pota_endorsement,
    )?;

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
            bk3: MborByteArray::from_slice(bk3).map_hsm_err(HsmError::InvalidArgument)?,
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
/// * `pota_endorsement` - POTA endorsement data containing signature and public key
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
    pota_endorsement: &HsmPotaEndorsementData<'_>,
) -> HsmResult<Vec<u8>> {
    let pota_endorsement_pub_key = DdiDerPublicKey {
        der: MborByteArray::from_slice(pota_endorsement.pub_key())
            .map_hsm_err(HsmError::InternalError)?,
        key_kind: DdiKeyType::Ecc384Public,
    };

    let req = DdiEstablishCredentialCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::EstablishCredential, Some(rev), None),
        data: DdiEstablishCredentialReq {
            encrypted_credential: enc_creds,
            pub_key,
            masked_bk3: MborByteArray::from_slice(mobk).map_hsm_err(HsmError::InvalidArgument)?,
            bmk: MborByteArray::from_slice(bmk).map_hsm_err(HsmError::InvalidArgument)?,
            masked_unwrapping_key: MborByteArray::from_slice(muk)
                .map_hsm_err(HsmError::InvalidArgument)?,
            pota_sig: MborByteArray::from_slice(pota_endorsement.signature())
                .map_hsm_err(HsmError::InternalError)?,
            pota_pub_key: pota_endorsement_pub_key,
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
