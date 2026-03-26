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
use resiliency_macro::resiliency_init_part;
use x509::*;

use super::*;

/// Result of a successful [`init_part`] call.
///
/// Carries the key material plus the POTA endorsement that was actually
/// sent to the device. When resiliency is enabled and the POTA source is
/// Caller, this may differ from the original caller-supplied endorsement
/// because the callback re-signed over the current device's PID cert.
pub(crate) struct InitPartResult {
    /// Backup masking key returned by the device.
    pub(crate) bmk: Vec<u8>,
    /// Masked owner backup key.
    pub(crate) mobk: Vec<u8>,
    /// POTA endorsement data that was actually used.
    pub(crate) pota_endorsement_data: HsmPotaEndorsementData,
}

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
/// This function handles the two POTA endorsement sources:
/// - Caller: Uses the provided endorsement data directly. When
///   `reendorse` is `true` and resiliency is enabled, the
///   `PotaEndorsementCallback` is invoked instead to re-sign over the
///   current device's PID public key (which may have changed after a
///   resiliency event).
/// - Tpm: Signs the hash of the partition's certificate public key using TPM
///
/// For TPM source, the data being signed is the SHA-384 hash of the
/// uncompressed public key point (0x04 || x || y) from the partition's certificate.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
/// * `pota_endorsement` - The POTA endorsement configuration
/// * `resiliency_config` - Optional resiliency configuration; when `Some`
///   and source is Caller, the `pota_callback` may be invoked to generate a
///   fresh endorsement for the current device.
/// * `reendorse` - Whether to use the `PotaEndorsementCallback` (when
///   source is Caller and resiliency is enabled) instead of the caller-
///   provided endorsement data. Set to `true` when the previous retry
///   attempt failed with `EccVerifyFailed`, indicating the device's
///   attestation key changed.
///
/// # Returns
///
/// Returns a tuple of (signature, public_key) as owned vectors.
///
/// # Errors
///
/// Returns an error if:
/// - Source is Caller but no endorsement data is provided (and no callback)
/// - Certificate retrieval fails
/// - TPM signing fails (for TPM source)
fn get_pota_endorsement(
    dev: &HsmDev,
    rev: HsmApiRev,
    pota_endorsement: &HsmPotaEndorsement,
    resiliency_config: Option<&HsmResiliencyConfig>,
    reendorse: bool,
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    match pota_endorsement.source() {
        HsmPotaEndorsementSource::Caller => {
            // When re-endorsement is requested, use the callback to
            // generate a fresh endorsement. The callback is responsible
            // for retrieving the current device's PID cert public key
            // and signing it. We pass the caller's original endorsement
            // public key for identification — the callback may ignore it.
            if reendorse {
                let cfg = resiliency_config.ok_or(HsmError::InvalidArgument)?;
                let callback = cfg
                    .pota_callback
                    .as_ref()
                    .ok_or(HsmError::InvalidArgument)?;
                let data = invoke_pota_callback(callback.as_ref(), pota_endorsement)?;
                return Ok((data.signature().to_vec(), data.pub_key().to_vec()));
            }

            // Re-endorsement not requested, or no resiliency config —
            // use the caller-provided endorsement as-is.
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

/// Invokes a [`PotaEndorsementCallback`] to produce fresh endorsement data.
///
/// Passes the caller's original endorsement public key to the callback
/// for identification.
pub(crate) fn invoke_pota_callback(
    callback: &dyn PotaEndorsementCallback,
    pota_endorsement: &HsmPotaEndorsement,
) -> HsmResult<HsmPotaEndorsementData> {
    let caller_pub_key = pota_endorsement
        .endorsement()
        .map(|d| d.pub_key())
        .unwrap_or(&[]);
    callback.endorse(caller_pub_key)
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
/// * `resiliency_config` - Optional resiliency configuration; when `Some`,
///   enables retry with backoff on transient errors and invokes the `PotaEndorsementCallback` on retries.
///   The caller must hold the resiliency lock before calling;
///   this function does not acquire it internally.
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
#[resiliency_init_part]
pub(crate) fn init_part(
    dev: &HsmDev,
    rev: HsmApiRev,
    creds: HsmCredentials,
    bmk: Option<&[u8]>,
    muk: Option<&[u8]>,
    obk_config: &HsmOwnerBackupKeyConfig,
    pota_endorsement: &HsmPotaEndorsement,
    resiliency_config: Option<&HsmResiliencyConfig>,
) -> HsmResult<InitPartResult> {
    // Derive the re-endorsement flag from the macro-injected
    // `__prev_error`.  When the previous retry attempt failed with
    // `EccVerifyFailed`, the device's attestation key changed (e.g.
    // after live migration) and we need to re-sign POTA.
    let reendorse = matches!(__prev_error, Some(HsmError::EccVerifyFailed));
    init_part_raw_no_res(
        dev,
        rev,
        creds,
        bmk,
        muk,
        obk_config,
        pota_endorsement,
        resiliency_config,
        reendorse,
    )
}

/// Bare DDI partition initialization — no retry macro, no lock.
///
/// This is the core credential-establishment logic extracted from
/// [`init_part`] so that callers who manage their own serialization
/// (e.g., [`restore_partition`](crate::HsmPartition::restore_partition))
/// can invoke it without the `#[resiliency_init_part]` retry wrapper.
///
/// **Callers are responsible for acquiring the resiliency / cross-process
/// lock before calling this function.**
///
/// # Arguments
///
/// Same as [`init_part`], plus:
///
/// * `reendorse` — When `true` *and* the POTA source is `Caller` with
///   resiliency enabled, the [`PotaEndorsementCallback`] is invoked to
///   re-sign over the current device's PID public key.  Set to `true`
///   when retrying after `EccVerifyFailed`.
pub(crate) fn init_part_raw_no_res(
    dev: &HsmDev,
    rev: HsmApiRev,
    creds: HsmCredentials,
    bmk: Option<&[u8]>,
    muk: Option<&[u8]>,
    obk_config: &HsmOwnerBackupKeyConfig,
    pota_endorsement: &HsmPotaEndorsement,
    resiliency_config: Option<&HsmResiliencyConfig>,
    reendorse: bool,
) -> HsmResult<InitPartResult> {
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

    // Compute POTA endorsement based on source.
    let (pota_signature, pota_public_key) =
        get_pota_endorsement(dev, rev, pota_endorsement, resiliency_config, reendorse)?;
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

    // Resolve BMK and MUK from resiliency storage when the caller did
    // not provide cached values. BMK is persisted by
    // `try_establish_credential`; MUK is persisted by
    // `generate_key_pair` (RSA unwrapping key generation).
    let resolved_bmk = resolve_cached_key(
        bmk,
        resiliency_config,
        crate::resiliency::AZIHSM_STORAGE_BMK,
    )?;
    let resolved_muk = resolve_cached_key(
        muk,
        resiliency_config,
        crate::resiliency::AZIHSM_STORAGE_MUK,
    )?;

    let bmk = try_establish_credential(
        dev,
        rev,
        &ecreds,
        &pub_key,
        &resolved_bmk,
        &resolved_muk,
        &mobk,
        &pota_endorsement,
        resiliency_config,
    )?;

    Ok(InitPartResult {
        bmk,
        mobk,
        pota_endorsement_data: pota_endorsement,
    })
}

/// Resolves a cached key value (BMK or MUK) for credential establishment.
///
/// When the caller provides a cached value, it is returned directly.
/// When the caller passes `None` and resiliency is enabled, the value is
/// read from resiliency storage using the given `storage_key`.
///
/// Returns an owned `Vec<u8>` so the caller does not need to manage
/// borrow lifetimes for storage-backed data.
fn resolve_cached_key(
    cached: Option<&[u8]>,
    resiliency_config: Option<&HsmResiliencyConfig>,
    storage_key: &str,
) -> HsmResult<Vec<u8>> {
    let value = match (cached, resiliency_config) {
        (Some(v), _) => v.to_vec(),
        (None, Some(cfg)) => match cfg.storage.read(storage_key) {
            Ok(value) => value,
            Err(HsmError::NotFound) => Vec::new(),
            Err(e) => return Err(e),
        },
        (None, None) => Vec::new(),
    };
    Ok(value)
}

/// Tries to establish credentials, retrying once with empty BMK/MUK on
/// `MaskedKeyDecodeFailed` when resiliency is enabled.
///
/// When the device returns `MaskedKeyDecodeFailed` it means the cached
/// BMK/MUK on disk are stale (e.g. after a migration).
///
/// 1. Try `establish_credential` with the caller-supplied BMK/MUK.
/// 2. On `MaskedKeyDecodeFailed` and resiliency is enabled, clear
///    both the stale BMK and MUK from resiliency storage and retry with
///    empty BMK and MUK.
/// 3. If resiliency is not enabled, the error is returned as-is.
/// 4. On success, persist the new BMK to resiliency storage.
///
/// All other errors are returned immediately.
fn try_establish_credential(
    dev: &HsmDev,
    rev: HsmApiRev,
    ecreds: &DdiEncryptedEstablishCredential,
    pub_key: &DdiDerPublicKey,
    bmk: &[u8],
    muk: &[u8],
    mobk: &[u8],
    pota_endorsement: &HsmPotaEndorsementData,
    resiliency_config: Option<&HsmResiliencyConfig>,
) -> HsmResult<Vec<u8>> {
    let result = establish_credential(dev, rev, ecreds, pub_key, bmk, muk, mobk, pota_endorsement);

    let new_bmk = match (&result, resiliency_config) {
        (Ok(_), _) => result,
        (Err(HsmError::MaskedKeyDecodeFailed), Some(cfg)) => {
            // Cached BMK/MUK are stale (e.g. from a prior migration epoch).
            // Clear them from storage and retry with empty values so the
            // device generates fresh keys.
            cfg.storage.clear(crate::resiliency::AZIHSM_STORAGE_BMK)?;
            cfg.storage.clear(crate::resiliency::AZIHSM_STORAGE_MUK)?;

            establish_credential(dev, rev, ecreds, pub_key, &[], &[], mobk, pota_endorsement)
        }
        (Err(_), _) => result,
    }?;

    // Persist the new BMK to resiliency storage so it is available on the
    // next init retry after a migration.
    if let Some(cfg) = resiliency_config {
        cfg.storage
            .write(crate::resiliency::AZIHSM_STORAGE_BMK, &new_bmk)?;
    }

    Ok(new_bmk)
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
    let resp = dev.exec_op(&req, &mut None).map_err(HsmError::from)?;
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
    dev.exec_op(&req, &mut None).map_err(HsmError::from)
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
/// `HsmError::MaskedKeyDecodeFailed` indicates that the provided BMK/MUK
/// values are stale; callers should use `try_establish_credential`
/// for automatic retry with empty keys.
pub fn establish_credential(
    dev: &HsmDev,
    rev: HsmApiRev,
    enc_creds: &DdiEncryptedEstablishCredential,
    pub_key: &DdiDerPublicKey,
    bmk: &[u8],
    muk: &[u8],
    mobk: &[u8],
    pota_endorsement: &HsmPotaEndorsementData,
) -> HsmResult<Vec<u8>> {
    let pota_endorsement_pub_key = DdiDerPublicKey {
        der: MborByteArray::from_slice(pota_endorsement.pub_key())
            .map_hsm_err(HsmError::InternalError)?,
        key_kind: DdiKeyType::Ecc384Public,
    };

    let req = DdiEstablishCredentialCmdReq {
        hdr: build_ddi_req_hdr(DdiOp::EstablishCredential, Some(rev), None),
        data: DdiEstablishCredentialReq {
            encrypted_credential: enc_creds.clone(),
            pub_key: pub_key.clone(),
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
    let resp = dev.exec_op(&req, &mut None).map_err(HsmError::from)?;
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

    let resp = dev.exec_op(&req, &mut None).map_err(HsmError::from)?;

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

    let resp = dev.exec_op(&req, &mut None).map_err(HsmError::from)?;

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

    let resp = dev.exec_op(&req, &mut None).map_err(HsmError::from)?;

    Ok(resp.data.sealed_bk3.as_slice().to_vec())
}
