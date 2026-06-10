// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition initialization operations.
//!
//! This module provides functionality for initializing HSM partitions with
//! application credentials and master key material.

use azihsm_cred_encrypt::DeviceCredKey;
use azihsm_crypto as crypto;
use azihsm_ddi_mbor_codec::*;
use crypto::*;
use resiliency_macro::resiliency_cert_chain;
use resiliency_macro::resiliency_init_part;
use x509::*;

use super::*;

/// Result of a successful [`init_part`] call.
///
/// Carries the BMK plus the POTA endorsement that was actually sent to
/// the device. When resiliency is enabled and the POTA source is
/// Caller, this may differ from the original caller-supplied endorsement
/// because the callback re-signed over the current device's PID cert.
pub(crate) struct InitPartResult {
    /// Masked owner backup key (MOBK) derived during initialization, which the caller must persist for future credential establishment calls.
    /// This is the masked BK3 value returned by the device after successful initialization.
    pub(crate) mobk: Vec<u8>,
    /// Backup masking key returned by the device.
    pub(crate) bmk: Vec<u8>,
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

/// Fetches the certificate chain and extracts the public key from the
/// leaf certificate.
///
/// This combines the work of [`get_part_pub_key`] and [`get_cert_chain`]
/// into one function, avoiding redundant `GetCertChainInfo` and
/// `GetCertificate` DDI calls. A second `GetCertChainInfo` call is made
/// after fetching all certificates to verify the chain did not change
/// during retrieval.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
/// * `slot_id` - The certificate slot number
///
/// # Returns
///
/// Returns a tuple of (PEM cert chain ordered leaf->root, DER-encoded
/// public key from the leaf certificate).
fn get_cert_chain_and_pub_key(
    dev: &HsmDev,
    rev: HsmApiRev,
    slot_id: u8,
) -> HsmResult<(String, Vec<u8>)> {
    let (cert_chain, leaf_cert_der) = fetch_cert_chain_checked(dev, rev, slot_id)?;

    let cert = X509Certificate::from_der(&leaf_cert_der).map_hsm_err(HsmError::InternalError)?;
    let pub_key_der = cert
        .get_public_key_der()
        .map_hsm_err(HsmError::InternalError)?;

    Ok((cert_chain, pub_key_der))
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
            // When re-endorsement is requested, the SDK retrieves the
            // device's PID public key and certificate chain (PEM), then
            // invokes the callback to sign. We also pass the caller's
            // original endorsement public key for identification — the
            // callback may ignore it.
            if reendorse {
                let cfg = resiliency_config.ok_or(HsmError::InvalidArgument)?;
                let callback = cfg
                    .pota_callback
                    .as_ref()
                    .ok_or(HsmError::InvalidArgument)?;
                let (pid_cert_chain_pem, pid_pub_key_der) =
                    get_cert_chain_and_pub_key(dev, rev, 0)?;
                let data = invoke_pota_callback(
                    callback.as_ref(),
                    pota_endorsement,
                    &pid_pub_key_der,
                    pid_cert_chain_pem.as_bytes(),
                )?;
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
            // TPM source must not have caller-provided endorsement data
            if pota_endorsement.endorsement().is_some() {
                return Err(HsmError::InvalidArgument);
            }
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
/// Passes the caller's original endorsement public key, the device's
/// PID certificate public key, and the PID certificate chain to the callback.
pub(crate) fn invoke_pota_callback(
    callback: &dyn PotaEndorsementCallback,
    pota_endorsement: &HsmPotaEndorsement,
    pid_pub_key_der: &[u8],
    pid_cert_chain_pem: &[u8],
) -> HsmResult<HsmPotaEndorsementData> {
    let pota_pub_key_der = pota_endorsement
        .endorsement()
        .map(|d| d.pub_key())
        .unwrap_or(&[]);
    callback.endorse(pota_pub_key_der, pid_pub_key_der, pid_cert_chain_pem)
}

/// Initializes an HSM partition with credentials and master keys.
///
/// Configures the partition for use by setting up authentication credentials
/// and optionally providing master key material. This operation must be performed
/// before the partition can be used for cryptographic operations.
///
/// MOBK derivation runs once via [`get_mobk_from_config`]. The result
/// is stashed into the caller-supplied `cached_mobk` slot so that any
/// subsequent retry of the `#[resiliency_init_part]` loop reuses the
/// derived value and skips the DDI call. This is required for the
/// `Caller + raw OBK` path because `init_bk3` is one-shot per device
/// power cycle. The cache must be declared by the caller (e.g.
/// `let mut cached_mobk = None;`) because anything `let`-bound inside
/// the retry loop body resets on each attempt.
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use for initialization
/// * `creds` - Application credentials (ID and PIN)
/// * `bmk` - Optional backup masking key
/// * `muk` - Optional masked unwrapping key
/// * `obk_config` - Owner backup key configuration
/// * `cached_mobk` - Retry cache for the derived MOBK; pass
///   `&mut None` for a fresh init. Populated on first success.
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
#[resiliency_init_part]
pub(crate) fn init_part(
    dev: &HsmDev,
    rev: HsmApiRev,
    creds: HsmCredentials,
    bmk: Option<&[u8]>,
    muk: Option<&[u8]>,
    obk_config: &HsmOwnerBackupKeyConfig,
    cached_mobk: &mut Option<Vec<u8>>,
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
        cached_mobk,
        pota_endorsement,
        resiliency_config,
        reendorse,
    )
}

/// Resolves the masked owner backup key (MOBK) from the caller's
/// [`HsmOwnerBackupKeyConfig`].
///
/// Called by [`init_part_raw_no_res`] on the *first* attempt of an
/// init. The result is stashed by the caller into the `cached_mobk`
/// slot it passes to [`init_part`], so retry attempts inside the
/// `#[resiliency_init_part]` loop reuse the derived MOBK and do not
/// invoke `init_bk3` a second time. `init_bk3` (the `Caller` + raw
/// OBK path) is one-shot per device power cycle; a second call
/// would fail with `Bk3AlreadyInitialized`.
///
/// Resolution rules by source:
///
/// - `Caller`: exactly one of `key` (raw OBK) or `masked_key` (MOBK)
///   must be provided.
///   - `masked_key` present → returned as-is (no DDI call).
///   - `key` present → derived on the device via [`init_bk3`], which
///     returns the masked BK3 (MOBK).
/// - `Tpm`: must not carry a caller-supplied raw OBK. The sealed BK3 is
///   fetched from the device via [`get_sealed_bk3`] and unsealed with
///   the TPM via [`unseal_tpm_backup_key`].
///
/// # Arguments
///
/// * `dev` - The HSM device handle
/// * `rev` - The API revision to use
/// * `obk_config` - The owner backup key configuration supplied by the
///   caller
///
/// # Returns
///
/// Returns the resolved MOBK bytes.
///
/// # Errors
///
/// Returns `HsmError::InvalidArgument` if `obk_config` violates the
/// source-specific rules above (e.g. both/neither of `key`/`masked_key`
/// for `Caller`, or a `key` set for `Tpm`). Propagates DDI errors from
/// [`init_bk3`] / [`get_sealed_bk3`] and TPM errors from
/// [`unseal_tpm_backup_key`].
pub(crate) fn get_mobk_from_config(
    dev: &HsmDev,
    rev: HsmApiRev,
    obk_config: &HsmOwnerBackupKeyConfig,
) -> HsmResult<Vec<u8>> {
    match obk_config.key_source() {
        HsmOwnerBackupKeySource::Caller => {
            // Caller source must provide either OBK or MOBK;
            // if OBK is provided, derive MOBK by sending OBK to the device. If MOBK is provided, use it directly.
            if (obk_config.key().is_none() && obk_config.masked_key().is_none())
                || (obk_config.key().is_some() && obk_config.masked_key().is_some())
            {
                return Err(HsmError::InvalidArgument);
            }
            if let Some(mobk) = obk_config.masked_key() {
                Ok(mobk.to_vec())
            } else if let Some(obk) = obk_config.key() {
                init_bk3(dev, rev, obk)
            } else {
                Err(HsmError::InvalidArgument)
            }
        }
        HsmOwnerBackupKeySource::Tpm => {
            // TPM source must not carry a caller-provided OBK.
            if obk_config.key().is_some() {
                return Err(HsmError::InvalidArgument);
            }
            // Retrieve sealed BK3 from device and unseal with TPM
            let sealed_bk3 = get_sealed_bk3(dev, rev)?;
            unseal_tpm_backup_key(&sealed_bk3)
        }
        _ => Err(HsmError::InvalidArgument),
    }
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
    cached_mobk: &mut Option<Vec<u8>>,
    pota_endorsement: &HsmPotaEndorsement,
    resiliency_config: Option<&HsmResiliencyConfig>,
    reendorse: bool,
) -> HsmResult<InitPartResult> {
    // Resolve the MOBK from the cache, or derive it from the OBK
    // config on first call. Caching the result back into
    // `cached_mobk` is essential for retry safety: `init_bk3`
    // (Caller + raw OBK) is one-shot per device power cycle, and
    // re-running it would fail with `Bk3AlreadyInitialized` even on
    // an otherwise-recoverable transient.
    let mobk = match cached_mobk {
        Some(mobk) => mobk.clone(),
        None => {
            let mobk = ddi::get_mobk_from_config(dev, rev, obk_config)?;
            cached_mobk.replace(mobk.clone());
            mobk
        }
    };

    // Compute POTA endorsement based on source.
    let (pota_signature, pota_public_key) =
        get_pota_endorsement(dev, rev, pota_endorsement, resiliency_config, reendorse)?;
    let pota_endorsement = HsmPotaEndorsementData::new(&pota_signature, &pota_public_key);

    let resp = get_establish_cred_encryption_key(dev, rev)?;

    let nonce = resp.data.nonce;
    let key = DeviceCredKey::new(&resp.data.pub_key, nonce).map_hsm_err(HsmError::InternalError)?;

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
        mobk.as_ref(),
        &pota_endorsement,
        resiliency_config,
    )?;

    Ok(InitPartResult {
        mobk,
        bmk,
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
    let resp = dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from)?;
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
    dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from)
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
fn establish_credential(
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
    let resp = dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from)?;
    Ok(resp.data.bmk.as_slice().to_vec())
}

/// Retrieves the certificate chain stored in the HSM device.
///
/// # Arguments
///
/// * `partition` - The HSM partition; the device handle is obtained from this partition
/// * `slot_id` - The certificate slot number
///
/// # Returns
///
/// Returns the certificate chain in PEM format.
///
/// # Locking
///
/// This function acquires `partition.inner().read()` internally.
/// Callers must not hold `partition.inner().read()` or
/// `partition.inner().write()` when calling this function.
#[resiliency_cert_chain(partition = "partition")]
pub(crate) fn get_cert_chain(partition: &HsmPartition, slot_id: u8) -> HsmResult<String> {
    let inner = partition.inner().read();
    let dev = inner.dev();
    get_cert_chain_raw_no_res(dev, inner.api_rev(), slot_id)
}

/// Raw cert chain retrieval — no resiliency retry, no partition lock.
///
/// For use in contexts that already have `dev` and `rev` (e.g.,
/// `get_pota_endorsement` during `init_part_raw_no_res`).
fn get_cert_chain_raw_no_res(dev: &HsmDev, rev: HsmApiRev, slot_id: u8) -> HsmResult<String> {
    let (cert_chain, _) = fetch_cert_chain_checked(dev, rev, slot_id)?;
    Ok(cert_chain)
}

/// Fetches the certificate chain with a thumbprint stability check.
///
/// Retrieves `GetCertChainInfo` before and after fetching all certificates
/// and returns [`HsmError::CertChainChanged`] if the count or thumbprint
/// changed in between.
///
/// Returns `InternalError` if the certificate count is zero (a partition
/// must always have a provisioned cert chain).
///
/// The returned PEM chain is ordered leaf->root (the firmware returns
/// it root->leaf; this function reverses it to match the documented
/// contract). Also returns the DER bytes of the leaf certificate so
/// callers can extract the partition public key.
fn fetch_cert_chain_checked(
    dev: &HsmDev,
    rev: HsmApiRev,
    slot_id: u8,
) -> HsmResult<(String, Vec<u8>)> {
    let (count, thumbprint) = get_cert_chain_info(dev, rev, slot_id)?;
    if count == 0 {
        return Err(HsmError::InternalError);
    }

    let mut cert_chain = String::new();
    let mut leaf_cert_der = Vec::new();

    // Firmware returns chain in order root->leaf, but we want leaf->root, so reverse the chain before returning
    for cert_id in (0..count).rev() {
        let der = get_cert(dev, rev, slot_id, cert_id)?;
        let pem = crypto::der_to_pem(&der).map_hsm_err(HsmError::InternalError)?;
        cert_chain.push_str(&pem);
        if cert_id == count - 1 {
            leaf_cert_der = der;
        }
    }

    let (new_count, new_thumbprint) = get_cert_chain_info(dev, rev, slot_id)?;
    if new_count != count || new_thumbprint != thumbprint {
        return Err(HsmError::CertChainChanged);
    }

    Ok((cert_chain, leaf_cert_der))
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

    let resp = dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from)?;

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

    let resp = dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from)?;

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

    let resp = dev.exec_op_mbor(&req, &mut None).map_err(HsmError::from)?;

    Ok(resp.data.sealed_bk3.as_slice().to_vec())
}
