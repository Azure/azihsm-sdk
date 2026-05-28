// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TPM-sealed BK3 unsealing for test helpers.
//!
//! This is a self-contained copy of the BK3 unsealing logic that lives
//! inside `azihsm_api`'s private `ddi::tpm` module. It is duplicated here
//! (rather than re-exported from `azihsm_api`) so that test-helper crates
//! do not need to widen `azihsm_api`'s public surface or depend on it.
//!
//! The wire format consumed here is defined by UEFI firmware and matches
//! the layout parsed by `azihsm_api::ddi::tpm::TpmBk3Unsealer`. If the
//! firmware-defined sealed-BK3 layout changes, both copies must be
//! updated in lockstep.

use azihsm_crypto::*;
use azihsm_tpm::*;
use thiserror::Error;
use zerocopy::*;

const MIN_SEALED_BK3_SIZE: usize = 4;
const RSA_KEY_BITS: u16 = 2048;
const TPM_PRIMARY_AES_KEY_BITS: u16 = 128;
const AES_BLOCK_SIZE: usize = 16;
const BK3_AES_KEY_SIZE: usize = 32;
const AZIHSM_KEY_IV_RECORD_VERSION: u8 = 1;

/// Error returned by TPM-sealed BK3 unsealing.
///
/// A single-variant struct keeps test-helper plumbing simple. The
/// `String` carries a stage tag plus the underlying error's `Display`
/// (e.g. the `std::io::Error` from a TPM op or the [`CryptoError`]
/// from AES) so `{e}` / `.expect(...)` panic messages stay useful.
#[derive(Debug, Error)]
#[error("TPM unseal failed: {0}")]
pub(crate) struct TpmUnsealError(pub String);

/// Packed AES key/IV record matching `AZIHSM_KEY_IV_RECORD` from UEFI
/// firmware. Mirrors `azihsm_api::ddi::tpm::AzihsmKeyIvRecord`.
///
/// Wire layout (little-endian, packed, 53 bytes total):
/// `[record_size:u16][key_version:u8][key_size:u8][key:32B][iv_size:u8][iv:16B]`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, TryFromBytes, KnownLayout, Immutable)]
struct ParsedKeyIvRecord {
    /// Record size (does not include the size of this field itself).
    record_size: [u8; 2],
    /// Key version.
    key_version: u8,
    /// Length of key in bytes.
    key_size: u8,
    /// AES key (up to AES-256).
    key: [u8; BK3_AES_KEY_SIZE],
    /// Length of IV in bytes.
    iv_size: u8,
    /// AES IV.
    iv: [u8; AES_BLOCK_SIZE],
}

impl ParsedKeyIvRecord {
    /// Parses and validates an AZIHSM_KEY_IV_RECORD from a byte slice.
    ///
    /// Uses `try_ref_from_prefix` for the initial parse, then validates
    /// that `record_size` accounts for the entire input with no
    /// unexpected trailing bytes.
    fn from_bytes_validated(data: &[u8]) -> Result<&Self, TpmUnsealError> {
        let (record, _remaining) = Self::try_ref_from_prefix(data).map_err(|_| {
            TpmUnsealError(format!(
                "AES key/IV record too short: got {} bytes",
                data.len()
            ))
        })?;

        if record.key_version != AZIHSM_KEY_IV_RECORD_VERSION {
            let actual = record.key_version;
            return Err(TpmUnsealError(format!(
                "AES key/IV record version mismatch: expected {AZIHSM_KEY_IV_RECORD_VERSION}, got {actual}"
            )));
        }

        let record_size = u16::from_le_bytes(record.record_size) as usize;
        if record_size + size_of::<u16>() != data.len() {
            return Err(TpmUnsealError(
                "AES key/IV record self-declared size mismatch".into(),
            ));
        }

        if record.key_size as usize > BK3_AES_KEY_SIZE {
            let key_size = record.key_size;
            return Err(TpmUnsealError(format!(
                "AES key/IV record key_size too large: {key_size} > {BK3_AES_KEY_SIZE}"
            )));
        }

        if record.iv_size as usize != AES_BLOCK_SIZE {
            let iv_size = record.iv_size;
            return Err(TpmUnsealError(format!(
                "AES key/IV record iv_size invalid: expected {AES_BLOCK_SIZE}, got {iv_size}"
            )));
        }

        Ok(record)
    }
}

/// Helper for unsealing TPM-sealed backup keys in test code.
///
/// Mirrors `azihsm_api::ddi::tpm::TpmBk3Unsealer`. See the module-level
/// comment in this file for the duplication rationale.
pub(crate) struct TpmBk3Unsealer {
    tpm: Tpm,
}

impl TpmBk3Unsealer {
    fn open() -> Result<Self, TpmUnsealError> {
        let tpm = Tpm::open().map_err(|e| TpmUnsealError(format!("Tpm::open: {e}")))?;
        Ok(Self { tpm })
    }

    /// Unseals a TPM-sealed BK3 and returns the masked backup key.
    ///
    /// `sealed_bk3` layout: `[sealed_aes_len:u16 LE][sealed_aes_secret][encrypted_data_len:u16 LE][encrypted_data]`.
    fn unseal_bk3(&self, sealed_bk3: &[u8]) -> Result<Vec<u8>, TpmUnsealError> {
        if sealed_bk3.len() < MIN_SEALED_BK3_SIZE {
            return Err(TpmUnsealError(format!(
                "sealed BK3 too short: {} < {MIN_SEALED_BK3_SIZE}",
                sealed_bk3.len()
            )));
        }

        let mut offset = 0;
        let sealed_aes_len =
            u16::from_le_bytes([sealed_bk3[offset], sealed_bk3[offset + 1]]) as usize;
        offset += size_of::<u16>();

        if sealed_aes_len + offset + size_of::<u16>() > sealed_bk3.len() {
            return Err(TpmUnsealError(
                "sealed BK3: sealed_aes_len overruns buffer".into(),
            ));
        }
        let sealed_aes_secret = &sealed_bk3[offset..offset + sealed_aes_len];
        offset += sealed_aes_len;

        let encrypted_data_len =
            u16::from_le_bytes([sealed_bk3[offset], sealed_bk3[offset + 1]]) as usize;
        offset += size_of::<u16>();

        if encrypted_data_len + offset > sealed_bk3.len() {
            return Err(TpmUnsealError(
                "sealed BK3: encrypted_data_len overruns buffer".into(),
            ));
        }
        let encrypted_data = &sealed_bk3[offset..offset + encrypted_data_len];

        // Unseal the AES key/IV structure via TPM.
        let aes_key_struct = self.unseal_null_hierarchy(sealed_aes_secret)?;

        // Parse AZIHSM_KEY_IV_RECORD via the zero-copy view; the
        // record fields are validated against the wire layout.
        let record = ParsedKeyIvRecord::from_bytes_validated(&aes_key_struct)?;

        // Decrypt with AES-CBC. Use the actual key_size to slice the key bytes
        // since the key array is fixed at 32 bytes but the actual key may be smaller.
        let aes_key = AesKey::from_bytes(&record.key[..record.key_size as usize])
            .map_err(|e| TpmUnsealError(format!("AesKey::from_bytes: {e:?}")))?;
        let mut algo = AesCbcAlgo::with_padding(&record.iv);

        let mut output = vec![0u8; encrypted_data.len() + AES_BLOCK_SIZE];
        let len = algo
            .decrypt(&aes_key, encrypted_data, Some(&mut output))
            .map_err(|e| TpmUnsealError(format!("AES-CBC decrypt: {e:?}")))?;

        output.truncate(len);
        Ok(output)
    }

    /// Unseals data using the TPM NULL hierarchy.
    ///
    /// `sealed_data` layout: `[private_len:u16 LE][private_blob][public_len:u16 LE][public_blob]`.
    fn unseal_null_hierarchy(&self, sealed_data: &[u8]) -> Result<Vec<u8>, TpmUnsealError> {
        if sealed_data.len() < size_of::<u16>() {
            return Err(TpmUnsealError("sealed AES blob too short".into()));
        }

        let mut offset = 0;
        let private_len =
            u16::from_le_bytes([sealed_data[offset], sealed_data[offset + 1]]) as usize;
        offset += size_of::<u16>();

        if private_len + offset + size_of::<u16>() > sealed_data.len() {
            return Err(TpmUnsealError(
                "sealed AES blob: private_len overruns buffer".into(),
            ));
        }
        let private_blob = &sealed_data[offset..offset + private_len];
        offset += private_len;

        let public_len =
            u16::from_le_bytes([sealed_data[offset], sealed_data[offset + 1]]) as usize;
        offset += size_of::<u16>();

        if public_len + offset > sealed_data.len() {
            return Err(TpmUnsealError(
                "sealed AES blob: public_len overruns buffer".into(),
            ));
        }
        let public_blob = &sealed_data[offset..offset + public_len];

        let policy = Tpm2bBytes(Vec::new());
        let primary = self.create_null_primary(&policy)?;

        // Best-effort flush of the primary handle on any failure below;
        // include the original io::Error in the message for diagnostics.
        let loaded = match self
            .tpm
            .load(primary.handle, &policy.0, private_blob, public_blob)
        {
            Ok(l) => l,
            Err(e) => {
                let _ = self.tpm.flush_context(primary.handle);
                return Err(TpmUnsealError(format!("Tpm::load: {e}")));
            }
        };

        let unseal_result = self.tpm.unseal(loaded.handle, &policy.0);
        let _ = self.tpm.flush_context(loaded.handle);
        let _ = self.tpm.flush_context(primary.handle);

        unseal_result.map_err(|e| TpmUnsealError(format!("Tpm::unseal: {e}")))
    }

    /// Creates a TPM NULL hierarchy primary key for unsealing.
    fn create_null_primary(&self, policy: &Tpm2bBytes) -> Result<CreatedPrimary, TpmUnsealError> {
        let obj_attrs = TpmaObjectBits::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_no_da(true)
            .with_restricted(true)
            .with_decrypt(true);

        let public_template = TpmtPublic {
            type_alg: TpmAlgId::Rsa.into(),
            name_alg: TpmAlgId::Sha256.into(),
            object_attributes: obj_attrs.into(),
            auth_policy: policy.clone(),
            detail: TpmtPublicDetail::RsaDetail(RsaDetail {
                symmetric: SymDefObject {
                    alg: TpmAlgId::Aes.into(),
                    key_bits: TPM_PRIMARY_AES_KEY_BITS,
                    mode: TpmAlgId::Cfb.into(),
                },
                scheme: RsaScheme::Null,
                key_bits: RSA_KEY_BITS,
                exponent: 0, // 0 means default: 65537
            }),
            unique: Tpm2bBytes(Vec::new()),
        };

        self.tpm
            .create_primary(Hierarchy::Null, Tpm2b::new(public_template), &[])
            .map_err(|e| TpmUnsealError(format!("Tpm::create_primary: {e}")))
    }
}

/// Unseals a TPM-sealed backup key (BK3) and returns the masked backup key.
///
/// On failure the returned [`TpmUnsealError`] embeds the underlying
/// `std::io::Error` (for TPM ops) or [`CryptoError`] (for AES) in its
/// message so `{e}` / `.expect(...)` panic output stays useful.
pub(crate) fn unseal_tpm_backup_key(sealed_bk3: &[u8]) -> Result<Vec<u8>, TpmUnsealError> {
    TpmBk3Unsealer::open()?.unseal_bk3(sealed_bk3)
}

/// Returns `true` when the `AZIHSM_USE_TPM` environment variable is set,
/// indicating we are running against real hardware with TPM-sourced keys.
pub(crate) fn is_tpm_enabled() -> bool {
    std::env::var("AZIHSM_USE_TPM").is_ok()
}
