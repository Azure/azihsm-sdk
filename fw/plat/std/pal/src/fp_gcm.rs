// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fast-path AES-256-GCM for the standard (host-native) PAL.
//!
//! On hardware, AES-GCM bulk encrypt/decrypt runs on the fast-path (FP)
//! engine addressed by a `bulk_key_id`, not through the CP HSM DDI
//! command pipeline.  The host stack surfaces it via the dedicated
//! `exec_op_fp_gcm` device entry point rather than an MBOR/TBOR op.
//!
//! The emulator has no separate FP engine, so this module reproduces
//! the FP GCM behavior against the same partition key vault the DDI
//! handlers use: the `bulk_key_id` is the vault `key_id` of the bulk
//! GCM key created by [`AesGenerateKey`], and the transform is performed
//! with the OpenSSL-backed AES driver.
//!
//! ## Approved vs unapproved
//!
//! - [`AesGcmBulk256`](HsmVaultKeyKind::AesGcmBulk256) — FIPS-approved:
//!   the device generates the 96-bit IV internally on encrypt and
//!   returns it; the caller-supplied IV is ignored.
//! - [`AesGcmBulk256Unapproved`](HsmVaultKeyKind::AesGcmBulk256Unapproved)
//!   — the caller-supplied IV is used as-is.
//!
//! Decrypt always uses the caller-supplied IV and requires the tag.

use azihsm_crypto::Rng;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

use crate::StdHsmPal;

/// GCM IV length in bytes (96 bits).
const GCM_IV_LEN: usize = 12;

/// One simulated fast-path (FP) bulk key.
///
/// On hardware the raw bulk key lives in the FP engine, addressed by a
/// `bulk_key_id`; the std PAL keeps it here instead.
pub(crate) struct FpBulkEntry {
    /// FP-assigned bulk key id handed back to the host.
    pub(crate) id: u16,

    /// Bulk key kind (selects approved vs unapproved GCM behavior).
    pub(crate) kind: HsmVaultKeyKind,

    /// Raw 32-byte AES-256 key material.
    pub(crate) key: Vec<u8>,
}

/// Result of a fast-path AES-GCM operation.
#[derive(Debug, Clone)]
pub struct FpGcmOutput {
    /// Transformed data (ciphertext on encrypt, plaintext on decrypt).
    pub data: Vec<u8>,

    /// Authentication tag — `Some` on encrypt, `None` on decrypt.
    pub tag: Option<[u8; 16]>,

    /// IV used for the operation — `Some` on encrypt (the device-
    /// generated IV for approved keys, the caller IV otherwise),
    /// `None` on decrypt.
    pub iv: Option<[u8; GCM_IV_LEN]>,

    /// Whether the operation ran under a FIPS-approved key.
    pub fips_approved: bool,
}

impl StdHsmPal {
    /// Register a freshly generated bulk key with the simulated FP
    /// engine, returning its `bulk_key_id`.
    pub(crate) fn fp_bulk_create(
        &self,
        pid: u8,
        kind: HsmVaultKeyKind,
        key: &[u8],
    ) -> HsmResult<u16> {
        let entry = self.active_part_mut(HsmPartId::from(pid))?;
        let id = entry.fp_bulk_next_id;
        entry.fp_bulk_next_id = entry.fp_bulk_next_id.wrapping_add(1);
        entry.fp_bulk.push(FpBulkEntry {
            id,
            kind,
            key: key.to_vec(),
        });
        Ok(id)
    }

    /// Delete a simulated FP bulk key by id.
    pub(crate) fn fp_bulk_delete(&self, pid: u8, bulk_key_id: u16) -> HsmResult<()> {
        let entry = self.active_part_mut(HsmPartId::from(pid))?;
        let before = entry.fp_bulk.len();
        entry.fp_bulk.retain(|e| e.id != bulk_key_id);
        if entry.fp_bulk.len() == before {
            return Err(HsmError::KeyNotFound);
        }
        Ok(())
    }

    /// Perform a fast-path AES-256-GCM encrypt or decrypt using the
    /// simulated FP bulk key identified by `key_id` in partition `pid`.
    ///
    /// `encrypt` selects the direction.  On decrypt, `tag_in` must
    /// carry the 16-byte authentication tag; a missing tag returns
    /// [`HsmError::NoTagProvided`] and a mismatched tag surfaces as
    /// [`HsmError::AesGcmDecryptTagDoesNotMatch`].
    ///
    /// The key must be an AES-GCM bulk key, else
    /// [`HsmError::InvalidKeyType`] is returned; an unknown id returns
    /// [`HsmError::KeyNotFound`].
    #[allow(clippy::too_many_arguments)]
    pub async fn fp_gcm_internal(
        &self,
        pid: u8,
        encrypt: bool,
        key_id: u16,
        host_iv: [u8; GCM_IV_LEN],
        aad: Option<Vec<u8>>,
        tag_in: Option<[u8; 16]>,
        input: Vec<u8>,
    ) -> HsmResult<FpGcmOutput> {
        // Resolve the bulk key material and its FIPS posture from the
        // simulated FP store, copying the key out so the partition-table
        // borrow is dropped before the async AES call below.
        let (key, approved) = {
            let entry = self.active_part(HsmPartId::from(pid))?;
            let bulk = entry
                .fp_bulk
                .iter()
                .find(|e| e.id == key_id)
                .ok_or(HsmError::KeyNotFound)?;
            let approved = match bulk.kind {
                HsmVaultKeyKind::AesGcmBulk256 => true,
                HsmVaultKeyKind::AesGcmBulk256Unapproved => false,
                _ => return Err(HsmError::InvalidKeyType),
            };
            (bulk.key.clone(), approved)
        };

        let mut data = vec![0u8; input.len()];

        if encrypt {
            // FIPS-approved keys generate the IV on-device and ignore
            // the caller's IV; unapproved keys use the caller IV.
            let mut iv = host_iv;
            if approved {
                Rng::rand_bytes(&mut iv).map_err(|_| HsmError::InternalError)?;
            }
            let mut tag = [0u8; 16];
            self.aes
                .gcm_encrypt(&key, &iv, aad.as_deref(), &input, &mut data, &mut tag)
                .await?;
            Ok(FpGcmOutput {
                data,
                tag: Some(tag),
                iv: Some(iv),
                fips_approved: approved,
            })
        } else {
            let tag = tag_in.ok_or(HsmError::NoTagProvided)?;
            self.aes
                .gcm_decrypt(&key, &host_iv, aad.as_deref(), &tag, &input, &mut data)
                .await?;
            Ok(FpGcmOutput {
                data,
                tag: None,
                iv: None,
                fips_approved: approved,
            })
        }
    }
}
