// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmCertStore`] for the Uno PAL — partition-id (PID) leaf generation.
//!
//! The served slot-0 chain is the device-id chain (from the DTCM CBLOB) +
//! the CP alias certificate (from GSRAM) + a partition-id (PID) leaf that
//! is generated on demand here. The PID leaf's subject public key is the
//! partition identity key; it is signed by the CP alias key using the
//! firmware's *deterministic* (RFC 6979) ECDSA-P384 so the leaf is
//! byte-stable across regenerations (cacheable).
//!
//! Work in progress: the [`HsmCertStore`] trait methods are still stubs;
//! [`UnoHsmPal::generate_pid_cert`] builds the leaf but a couple of fields
//! (issuer DN / AKI, and the GSRAM alias-key byte order) are pending
//! hardware confirmation — see the `TODO(cert-chain hw)` notes.

#![allow(clippy::unused_async)]

use azihsm_fw_core_crypto_x509_builder::cert_builder::build_leaf_cert_with_signer;
use azihsm_fw_core_crypto_x509_builder::cert_builder::LeafCertParams;
use azihsm_fw_core_crypto_x509_builder::cert_builder::TbsSigner;
use azihsm_fw_hsm_pal_traits::CertChainInfo;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmCertStore;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHash;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_uno_drivers_part_store::PartStore;
use azihsm_fw_uno_drivers_upka::UpkaEccCurve;

use crate::gsram_alias;
use crate::UnoHsmPal;

/// P-384 field-element / operand width (bytes).
const P384_FIELD: usize = 48;
/// Raw P-384 public point `X ‖ Y` width (bytes).
const P384_PUB_XY_LEN: usize = 96;
/// Uncompressed P-384 public key `0x04 ‖ X ‖ Y` width (bytes).
const P384_UNCOMPRESSED_LEN: usize = 97;
/// Subject/Authority Key Identifier width (SHA-1, bytes).
const SKI_LEN: usize = 20;
/// Issuer commonName value width in the AZIHSM leaf profile (bytes).
const ISSUER_CN_LEN: usize = 64;
/// Subject commonName value width in the AZIHSM leaf profile (bytes).
const SUBJECT_CN_LEN: usize = 32;
/// Partition identifier width (bytes); its uppercase hex is the subject CN.
const PART_ID_LEN: usize = 16;
/// DER serial-number width (bytes).
const SERIAL_LEN: usize = 20;

/// Leaf validity window (dev values). TODO(cert-chain hw): align with policy.
const NOT_BEFORE: &[u8; 15] = b"20250101000000Z";
const NOT_AFTER: &[u8; 15] = b"20350101000000Z";

/// [`TbsSigner`] that signs a leaf TBS with the CP alias key via the firmware's
/// deterministic (RFC 6979) ECDSA-P384, yielding a byte-stable signature.
struct AliasSigner<'a> {
    pal: &'a UnoHsmPal,
    /// CP alias private key bytes from GSRAM.
    alias_key: &'a [u8],
}

impl TbsSigner for AliasSigner<'_> {
    async fn sign_digest(
        &self,
        io: &impl HsmIo,
        digest: &DmaBuf,
        sig: &mut DmaBuf,
    ) -> HsmResult<()> {
        if self.alias_key.len() < P384_FIELD
            || digest.len() < P384_FIELD
            || sig.len() < 2 * P384_FIELD
        {
            return Err(HsmError::InvalidArg);
        }

        self.pal
            .alloc_scoped_async(io, async |scope| {
                // `ecc_sign_deterministic` operands are PKA little-endian: the
                // private key `d` and the message hash `e` (both 48 B).
                //
                // TODO(cert-chain hw): the GSRAM alias key is assumed to be in
                // PKA/LE order already; confirm against a real provisioned key
                // (reverse here if it turns out to be big-endian).
                let d = scope.dma_alloc(P384_FIELD)?;
                d[..P384_FIELD].copy_from_slice(&self.alias_key[..P384_FIELD]);

                // `digest` is the standard (big-endian) SHA-384 output; reverse
                // it to the little-endian scalar the signer expects.
                let e = scope.dma_alloc(P384_FIELD)?;
                for i in 0..P384_FIELD {
                    e[i] = digest[P384_FIELD - 1 - i];
                }

                // Sign into the r‖s halves (each LE, matching the assembler's
                // `sig_le` convention).
                let (r, s) = sig.split_at_mut(P384_FIELD);
                let res = self
                    .pal
                    .ecc_sign_deterministic(io, UpkaEccCurve::P384, e, d, r, s)
                    .await;
                d.zeroize();
                res
            })
            .await
    }
}

/// Deterministic 20-byte DER serial derived from the 16-byte partition id
/// (positive INTEGER: leading byte non-zero with bit 7 clear).
fn pid_serial(part_id: &[u8]) -> [u8; SERIAL_LEN] {
    let mut serial = [0u8; SERIAL_LEN];
    // Leading byte is a fixed non-zero, top-bit-clear tag; the remaining 16
    // bytes carry the partition id, and the low 3 bytes stay zero.
    serial[0] = 0x40;
    let n = part_id.len().min(PART_ID_LEN);
    serial[1..1 + n].copy_from_slice(&part_id[..n]);
    serial
}

/// Uppercase-hex of a 16-byte partition id into a 32-byte subject CN value.
fn subject_cn_hex(part_id: &[u8]) -> [u8; SUBJECT_CN_LEN] {
    let nib = |n: u8| if n < 10 { b'0' + n } else { b'A' + n - 10 };
    let mut out = [0u8; SUBJECT_CN_LEN];
    for (i, &b) in part_id.iter().take(PART_ID_LEN).enumerate() {
        out[2 * i] = nib(b >> 4);
        out[2 * i + 1] = nib(b & 0x0f);
    }
    out
}

impl UnoHsmPal {
    /// Generate the partition-id (PID) leaf certificate for `part_id`.
    ///
    /// Query/copy: `out = None` returns the worst-case DER size; `Some(buf)`
    /// writes the cert and returns its length. The subject public key is the
    /// partition identity key; the leaf is signed by the CP alias key via
    /// deterministic ECDSA-P384.
    #[allow(dead_code)] // consumed by get_cert / cert-chain wiring (later commit)
    async fn generate_pid_cert(
        &self,
        io: &impl HsmIo,
        part_id: HsmPartId,
        out: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        // Partition identity public key (X ‖ Y) — must be provisioned.
        let part = PartStore::partition(part_id)?;
        if part.id_key_id().is_none() {
            return Err(HsmError::InvalidArg);
        }
        let id_pub = part.id_pub_key();
        if id_pub.len() < P384_PUB_XY_LEN {
            return Err(HsmError::InternalError);
        }
        let mut uncompressed = [0u8; P384_UNCOMPRESSED_LEN];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&id_pub[..P384_PUB_XY_LEN]);

        // Subject Key Identifier = SHA-1(uncompressed public key).
        let ski = self.sha1_20(io, &uncompressed).await?;

        // Partition identifier → subject CN (uppercase hex) and serial number.
        let id = part.id();
        if id.len() < PART_ID_LEN {
            return Err(HsmError::InternalError);
        }
        let subject_cn = subject_cn_hex(&id[..PART_ID_LEN]);
        let serial = pid_serial(&id[..PART_ID_LEN]);

        // Issuer DN and Authority Key Identifier come from the alias cert so the
        // PID leaf chains to the CP alias certificate (subject CN → issuer CN,
        // alias SKI → leaf AKI).
        let alias_cert = gsram_alias::alias_cert();
        let mut issuer_cn = [0u8; ISSUER_CN_LEN];
        let cn = der::get_subject_cn(alias_cert).ok_or(HsmError::InternalError)?;
        if cn.len() != ISSUER_CN_LEN {
            return Err(HsmError::InternalError);
        }
        issuer_cn.copy_from_slice(cn);

        let mut authority_key_id = [0u8; SKI_LEN];
        if let Some(aki) = der::get_subject_key_identifier(alias_cert) {
            if aki.len() != SKI_LEN {
                return Err(HsmError::InternalError);
            }
            authority_key_id.copy_from_slice(aki);
        }

        // Alias signing key from GSRAM.
        let alias_key = gsram_alias::alias_key();
        if alias_key.is_empty() {
            return Err(HsmError::InvalidArg);
        }

        let params = LeafCertParams {
            public_key: &uncompressed,
            serial_number: &serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            issuer_cn: &issuer_cn,
            subject_cn: &subject_cn,
            subject_key_id: &ski,
            authority_key_id: &authority_key_id,
        };

        let signer = AliasSigner {
            pal: self,
            alias_key,
        };
        self.alloc_scoped_async(io, async |scope| {
            build_leaf_cert_with_signer(self, io, scope, &params, &signer, out).await
        })
        .await
    }

    /// SHA-1 over `data`, returning the 20-byte digest.
    async fn sha1_20(&self, io: &impl HsmIo, data: &[u8]) -> HsmResult<[u8; SKI_LEN]> {
        self.alloc_scoped_async(io, async |scope| {
            let inp = scope.dma_alloc(data.len())?;
            inp.copy_from_slice(data);
            let outd = scope.dma_alloc(SKI_LEN)?;
            self.hash(io, HsmHashAlgo::Sha1, inp, outd, false).await?;
            let mut out = [0u8; SKI_LEN];
            out.copy_from_slice(&outd[..SKI_LEN]);
            Ok(out)
        })
        .await
    }
}

/// Minimal DER helpers for extracting fields from the alias certificate.
///
/// Ported from the mcr-hsm reference (`cp/hsm/hsm/src/der/mod.rs`): no-alloc,
/// no_std byte scanners over a DER blob.
mod der {
    /// Parse a DER length at `offset`; returns `(length, header_bytes)` where
    /// `header_bytes` counts the length octets (excludes the tag).
    fn parse_der_length(data: &[u8], offset: usize) -> Option<(usize, usize)> {
        let byte0 = *data.get(offset)?;
        if byte0 & 0x80 == 0 {
            // short form
            Some((byte0 as usize, 1))
        } else {
            // long form: lower 7 bits = number of following length bytes
            let n = (byte0 & 0x7F) as usize;
            if n == 0 || offset + 1 + n > data.len() {
                return None;
            }
            let mut val = 0usize;
            for i in 0..n {
                val = (val << 8) | (data[offset + 1 + i] as usize);
            }
            Some((val, n + 1))
        }
    }

    /// Return the Subject Common Name (OID 2.5.4.3) value bytes. When two CN
    /// RDNs are present (issuer then subject), the second (subject) is chosen.
    pub(super) fn get_subject_cn(der: &[u8]) -> Option<&[u8]> {
        // OID TLV for 2.5.4.3 = 06 03 55 04 03
        const CN_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x03];

        let mut first_pos = None;
        let mut second_pos = None;
        let wnd = CN_OID.len();
        let max = der.len().saturating_sub(wnd);

        for i in 0..=max {
            if der[i..i + wnd] == CN_OID {
                if first_pos.is_none() {
                    first_pos = Some(i);
                } else {
                    second_pos = Some(i);
                    break;
                }
            }
        }

        let pos = second_pos.or(first_pos)?;

        // Skip past the OID TLV header + value.
        let (oid_len, oid_len_bytes) = parse_der_length(der, pos + 1)?;
        let idx = pos + 1 + oid_len_bytes + oid_len;

        // At idx: the string tag; its length follows at idx + 1.
        let (val_len, val_len_bytes) = parse_der_length(der, idx + 1)?;
        let start = idx + 1 + val_len_bytes;
        let end = start + val_len;

        der.get(start..end)
            .and_then(|bytes| if bytes.is_empty() { None } else { Some(bytes) })
    }

    /// Return the Subject Key Identifier (OID 2.5.29.14) keyIdentifier bytes.
    pub(super) fn get_subject_key_identifier(der: &[u8]) -> Option<&[u8]> {
        // DER for OID 2.5.29.14 is: 06 03 55 1D 0E
        const SKI_OID_TLV: &[u8; 5] = &[0x06, 0x03, 0x55, 0x1D, 0x0E];

        // 1) locate the OID TLV
        let pos = der
            .windows(SKI_OID_TLV.len())
            .position(|w| w == SKI_OID_TLV)?;

        // 2) skip past the OID's length + value
        let (oid_len, oid_len_bytes) = parse_der_length(der, pos + 1)?;
        let mut idx = pos + 1 + oid_len_bytes + oid_len;

        // 3) skip OPTIONAL critical BOOLEAN (tag 0x01)
        if der.get(idx) == Some(&0x01) {
            let (bool_len, bool_len_bytes) = parse_der_length(der, idx + 1)?;
            idx += 1 + bool_len_bytes + bool_len;
        }

        // 4) next must be the OCTET STRING (tag 0x04) wrapping the SKI
        if der.get(idx) != Some(&0x04) {
            return None;
        }
        let (ext_len, ext_len_bytes) = parse_der_length(der, idx + 1)?;
        let ext_start = idx + 1 + ext_len_bytes;
        let ext_end = ext_start + ext_len;
        let ext_bytes = der.get(ext_start..ext_end)?;

        // 5) ext_bytes is DER of SubjectKeyIdentifier ::= OCTET STRING, so
        //    ext_bytes[0] == 0x04, then length, then the keyIdentifier.
        if ext_bytes.first() != Some(&0x04) {
            return None;
        }
        let (ki_len, ki_len_bytes) = parse_der_length(ext_bytes, 1)?;
        let ki_start = 1 + ki_len_bytes;
        let ki_end = ki_start + ki_len;
        ext_bytes.get(ki_start..ki_end)
    }
}

impl HsmCertStore for UnoHsmPal {
    /// Not implemented.
    ///
    /// # Parameters
    /// * `_io` — operation-scoped I/O context (ignored).
    /// * `_part_id` — partition whose chain is queried (ignored).
    /// * `_slot_id` — chain slot identifier (ignored).
    ///
    /// # Returns
    /// * Always `Err(HsmError::UnsupportedCmd)`.
    async fn get_cert_chain_info(
        &self,
        _io: &impl HsmIo,
        _part_id: HsmPartId,
        _slot_id: u8,
    ) -> HsmResult<CertChainInfo> {
        Err(HsmError::UnsupportedCmd)
    }

    /// Not implemented.
    ///
    /// # Parameters
    /// * `_io` — operation-scoped I/O context (ignored).
    /// * `_part_id` — partition whose chain is queried (ignored).
    /// * `_slot_id` — chain slot identifier (ignored).
    /// * `_idx` — certificate index within the chain (ignored).
    /// * `_cert` — destination buffer; `None` would normally request the
    ///   required size (ignored).
    ///
    /// # Returns
    /// * Always `Err(HsmError::UnsupportedCmd)`.
    async fn get_cert(
        &self,
        _io: &impl HsmIo,
        _part_id: HsmPartId,
        _slot_id: u8,
        _idx: u8,
        _cert: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        Err(HsmError::UnsupportedCmd)
    }
}
