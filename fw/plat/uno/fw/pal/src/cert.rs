// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmCertStore`] for the Uno PAL — partition-id (PID) leaf generation.
//!
//! The served slot-0 chain is the device-id chain (from the DTCM CBLOB) +
//! the CP alias certificate (from GSRAM) + a partition-id (PID) leaf that
//! is generated on demand here. The PID leaf's subject public key is the
//! partition identity key; it is signed by the CP alias key using the
//! firmware's *deterministic* (RFC 6979) ECDSA-P384 so the leaf is
//! byte-stable across regenerations (cacheable). The GSRAM alias key is a
//! SEC1 `ECPrivateKey` DER blob; [`AliasSigner`] parses out the scalar and
//! converts it to the PKA little-endian operand order.

#![allow(clippy::unused_async)]

use azihsm_fw_core_crypto_x509_builder::cert_builder::LeafCertParams;
use azihsm_fw_core_crypto_x509_builder::cert_builder::TbsSigner;
use azihsm_fw_core_crypto_x509_builder::cert_builder::build_leaf_cert_with_signer;
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

use crate::UnoHsmPal;
use crate::dev_id_cblob;
use crate::gsram_alias;

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

/// SHA-256 digest width (bytes) — cert thumbprint / chain hash component.
const SHA256_LEN: usize = 32;

/// Worst-case DER size of the PID leaf certificate (single-CN 422-byte TBS plus
/// the ECDSA-P384 signature/algorithm/wrapper overhead). Used to size the
/// scratch buffer for thumbprint hashing; the builder rejects an undersized
/// buffer, so this is a safe upper bound with headroom.
const MAX_PID_CERT_DER: usize = 640;

/// Certificates appended after the device-id chain: the GSRAM alias cert and
/// the generated PID leaf.
const TRAILING_CERTS: u8 = 2;

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
        // The GSRAM alias key is a SEC1 `ECPrivateKey` DER blob
        // (`ECC_DER_P384_PRIVATE_NO_PUB_LENGTH`), not a raw scalar: the private
        // key is the OCTET STRING value, stored big-endian.
        let priv_be = der::get_ec_private_key(self.alias_key).ok_or(HsmError::InvalidArg)?;
        // Enforce exact lengths: the TbsSigner contract is a 48-byte SHA-384
        // digest and a 96-byte `r || s` output. An oversized `sig` would make
        // `sig.split_at_mut(P384_FIELD)` hand an oversized `s` to the signer.
        if priv_be.len() != P384_FIELD || digest.len() != P384_FIELD || sig.len() != 2 * P384_FIELD
        {
            return Err(HsmError::InvalidArg);
        }

        self.pal
            .alloc_scoped_async(io, async |scope| {
                // `ecc_sign_deterministic` operands are PKA little-endian. The
                // DER private key is big-endian, so reverse it into `d`.
                let d = scope.dma_alloc(P384_FIELD)?;
                for i in 0..P384_FIELD {
                    d[i] = priv_be[P384_FIELD - 1 - i];
                }

                // `build_signed_from_template` hashes the TBS as a natural
                // big-endian SHA-384 digest. `ecc_sign_deterministic` consumes
                // the PKA little-endian message hash — the FULL byte reversal of
                // the natural digest (not the per-word `big_endian = false`
                // swap). This mirrors the est-cred POTA verify and matches the
                // validated deterministic-sign KAT.
                let e = scope.dma_alloc(P384_FIELD)?;
                for i in 0..P384_FIELD {
                    e[i] = digest[P384_FIELD - 1 - i];
                }
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
        // P-384-only path: require an exact `X ‖ Y` length. A longer key would
        // silently ignore trailing bytes and could yield an invalid cert.
        if id_pub.len() != P384_PUB_XY_LEN {
            return Err(HsmError::InternalError);
        }
        // `id_pub` is the identity point in natural big-endian (`X_be ‖ Y_be`),
        // normalized at the PAL; build the SEC1 uncompressed point directly.
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
        // Missing alias material (bring-up / provisioning failure) is a caller-
        // facing `InvalidArg`, not an internal error — match the HsmCertStore docs
        // and fail before attempting to parse an empty buffer.
        if alias_cert.is_empty() {
            return Err(HsmError::InvalidArg);
        }
        let mut issuer_cn = [0u8; ISSUER_CN_LEN];
        let cn = der::get_subject_cn(alias_cert).ok_or(HsmError::InternalError)?;
        if cn.len() != ISSUER_CN_LEN {
            return Err(HsmError::InternalError);
        }
        issuer_cn.copy_from_slice(cn);

        let mut authority_key_id = [0u8; SKI_LEN];
        // The leaf's AKI must be the alias cert's SKI; fail rather than emit a
        // leaf with an all-zero AKI if the alias cert lacks the extension.
        let aki = der::get_subject_key_identifier(alias_cert).ok_or(HsmError::InternalError)?;
        if aki.len() != SKI_LEN {
            return Err(HsmError::InternalError);
        }
        authority_key_id.copy_from_slice(aki);

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
            // `big_endian = true`: the SKI is the standard NIST byte-order SHA-1
            // of the key (RFC 5280). `big_endian = false` would per-word swap the
            // digest and encode an incorrect Subject Key Identifier.
            self.hash(io, HsmHashAlgo::Sha1, inp, outd, true).await?;
            let mut out = [0u8; SKI_LEN];
            out.copy_from_slice(&outd[..SKI_LEN]);
            Ok(out)
        })
        .await
    }

    /// SHA-256 over `data`, returning the 32-byte digest.
    async fn sha256_32(&self, io: &impl HsmIo, data: &[u8]) -> HsmResult<[u8; SHA256_LEN]> {
        self.alloc_scoped_async(io, async |scope| {
            let inp = scope.dma_alloc(data.len())?;
            inp.copy_from_slice(data);
            let outd = scope.dma_alloc(SHA256_LEN)?;
            // `big_endian = true`: emit the standard (natural byte order) SHA-256
            // digest. The host and SP compute cert thumbprints over natural
            // SHA-256; `false` here would per-word byte-swap the digest (the PKA
            // operand order) and the chain thumbprint would never match.
            self.hash(io, HsmHashAlgo::Sha256, inp, outd, true).await?;
            let mut out = [0u8; SHA256_LEN];
            out.copy_from_slice(&outd[..SHA256_LEN]);
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
            // long form: lower 7 bits = number of following length bytes.
            let n = (byte0 & 0x7F) as usize;
            // Reject oversized encodings: `n` length octets must fit in `usize`
            // so the shift-accumulate below cannot overflow/wrap on a corrupt or
            // adversarial DER blob.
            if n == 0 || n > core::mem::size_of::<usize>() {
                return None;
            }
            let value_start = offset.checked_add(1)?;
            let value_end = value_start.checked_add(n)?;
            if value_end > data.len() {
                return None;
            }
            let mut val = 0usize;
            for i in 0..n {
                val = (val << 8) | (data[value_start + i] as usize);
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

        for (i, w) in der.windows(CN_OID.len()).enumerate() {
            if w == CN_OID {
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
        let idx = (pos + 1).checked_add(oid_len_bytes)?.checked_add(oid_len)?;

        // At idx: the string tag; its length follows at idx + 1.
        let (val_len, val_len_bytes) = parse_der_length(der, idx.checked_add(1)?)?;
        let start = idx.checked_add(1)?.checked_add(val_len_bytes)?;
        let end = start.checked_add(val_len)?;

        der.get(start..end).filter(|bytes| !bytes.is_empty())
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
        let mut idx = (pos + 1).checked_add(oid_len_bytes)?.checked_add(oid_len)?;

        // 3) skip OPTIONAL critical BOOLEAN (tag 0x01)
        if der.get(idx) == Some(&0x01) {
            let (bool_len, bool_len_bytes) = parse_der_length(der, idx.checked_add(1)?)?;
            idx = idx
                .checked_add(1)?
                .checked_add(bool_len_bytes)?
                .checked_add(bool_len)?;
        }

        // 4) next must be the OCTET STRING (tag 0x04) wrapping the SKI
        if der.get(idx) != Some(&0x04) {
            return None;
        }
        let (ext_len, ext_len_bytes) = parse_der_length(der, idx.checked_add(1)?)?;
        let ext_start = idx.checked_add(1)?.checked_add(ext_len_bytes)?;
        let ext_end = ext_start.checked_add(ext_len)?;
        let ext_bytes = der.get(ext_start..ext_end)?;

        // 5) ext_bytes is DER of SubjectKeyIdentifier ::= OCTET STRING, so
        //    ext_bytes[0] == 0x04, then length, then the keyIdentifier.
        if ext_bytes.first() != Some(&0x04) {
            return None;
        }
        let (ki_len, ki_len_bytes) = parse_der_length(ext_bytes, 1)?;
        let ki_start = 1 + ki_len_bytes;
        let ki_end = ki_start.checked_add(ki_len)?;
        ext_bytes.get(ki_start..ki_end)
    }

    /// Return the raw EC private-key scalar bytes (big-endian) from a SEC1
    /// `ECPrivateKey` DER blob:
    ///
    /// ```text
    /// ECPrivateKey ::= SEQUENCE {
    ///     version    INTEGER,          -- 02 01 01
    ///     privateKey OCTET STRING,     -- 04 30 <48-byte big-endian scalar>
    ///     parameters [0] ... OPTIONAL,
    ///     publicKey  [1] ... OPTIONAL
    /// }
    /// ```
    ///
    /// The HSP provisions the CP alias key into GSRAM in this form (64 bytes,
    /// `ECC_DER_P384_PRIVATE_NO_PUB_LENGTH`), so the raw scalar is the OCTET
    /// STRING value — not the first bytes of the blob.
    pub(super) fn get_ec_private_key(der: &[u8]) -> Option<&[u8]> {
        // Outer SEQUENCE.
        if *der.first()? != 0x30 {
            return None;
        }
        let (_seq_len, seq_hdr) = parse_der_length(der, 1)?;
        let mut idx = 1 + seq_hdr;

        // version INTEGER — skip tag + length + value.
        if *der.get(idx)? != 0x02 {
            return None;
        }
        let (ver_len, ver_hdr) = parse_der_length(der, idx.checked_add(1)?)?;
        idx = idx
            .checked_add(1)?
            .checked_add(ver_hdr)?
            .checked_add(ver_len)?;

        // privateKey OCTET STRING — its value is the raw scalar (big-endian).
        if *der.get(idx)? != 0x04 {
            return None;
        }
        let (key_len, key_hdr) = parse_der_length(der, idx.checked_add(1)?)?;
        let start = idx.checked_add(1)?.checked_add(key_hdr)?;
        der.get(start..start.checked_add(key_len)?)
    }
}

impl HsmCertStore for UnoHsmPal {
    /// Certificate-chain metadata for `(part_id, slot_id)`.
    ///
    /// Returns the served chain length (`device-id chain + alias + PID leaf`)
    /// and the chain thumbprint
    /// `SHA-256(dev_id_chain_hash ‖ SHA-256(alias_cert) ‖ SHA-256(pid_leaf))`,
    /// matching the reference firmware. `dev_id_chain_hash` and the device-id
    /// chain length come from the boot-time DTCM CBLOB. The PID leaf is
    /// regenerated deterministically to hash it, so the thumbprint is stable and
    /// matches the bytes [`get_cert`] serves.
    ///
    /// # Parameters
    /// * `io` — operation-scoped I/O context.
    /// * `part_id` — partition whose chain is queried.
    /// * `slot_id` — chain slot; only slot 0 is supported.
    ///
    /// # Returns
    /// * `Ok(CertChainInfo)` — chain length + thumbprint.
    /// * `Err(HsmError::InvalidArg)` — non-zero slot, missing/invalid device-id
    ///   CBLOB, missing GSRAM alias certificate, or unprovisioned partition.
    async fn get_cert_chain_info(
        &self,
        io: &impl HsmIo,
        part_id: HsmPartId,
        slot_id: u8,
    ) -> HsmResult<CertChainInfo> {
        if slot_id != 0 {
            return Err(HsmError::InvalidArg);
        }

        let cblob = dev_id_cblob::dev_id_cert_blob().ok_or(HsmError::InvalidArg)?;
        let alias = gsram_alias::alias_cert();
        if alias.is_empty() {
            return Err(HsmError::InvalidArg);
        }

        // count = device-id chain certs + alias + PID leaf.
        let count = u8::try_from(cblob.cert_count())
            .ok()
            .and_then(|k| k.checked_add(TRAILING_CERTS))
            .ok_or(HsmError::InternalError)?;

        self.alloc_scoped_async(io, async |scope| {
            let leaf = scope.dma_alloc(MAX_PID_CERT_DER)?;
            let leaf_len = self.generate_pid_cert(io, part_id, Some(leaf)).await?;

            let alias_hash = self.sha256_32(io, alias).await?;
            let leaf_hash = self.sha256_32(io, &leaf[..leaf_len]).await?;

            // Thumbprint = SHA-256(dev_id_chain_hash ‖ H(alias) ‖ H(leaf)).
            // `dev_id_chain_hash` is taken straight from the HSP-provisioned
            // CBLOB header (SHA-256 over the device-id chain, alias excluded),
            // exactly as the reference firmware does — the CP is a dumb reader
            // and does not recompute it.
            let mut combined = [0u8; 3 * SHA256_LEN];
            combined[..SHA256_LEN].copy_from_slice(cblob.dev_id_chain_hash());
            combined[SHA256_LEN..2 * SHA256_LEN].copy_from_slice(&alias_hash);
            combined[2 * SHA256_LEN..].copy_from_slice(&leaf_hash);
            let thumbprint = self.sha256_32(io, &combined).await?;

            Ok(CertChainInfo { count, thumbprint })
        })
        .await
    }

    /// Read one certificate from the chain (standard query/copy pattern).
    ///
    /// Chain order (leaf last): `idx 0..k-1` are the device-id chain certs from
    /// the boot-time DTCM CBLOB (`k = CertBlob::cert_count`), `idx k` is the
    /// GSRAM alias cert, and `idx k+1` is the generated PID leaf. `cert = None`
    /// returns the size; `Some(buf)` copies the DER into `buf`.
    ///
    /// # Parameters
    /// * `io` — operation-scoped I/O context.
    /// * `part_id` — partition whose chain is read.
    /// * `slot_id` — chain slot; only slot 0 is supported.
    /// * `idx` — zero-based certificate index (`< count`).
    /// * `cert` — `None` to query size, `Some(buf)` to copy.
    ///
    /// # Returns
    /// * `Ok(size)` — DER length that was (or would be) written.
    /// * `Err(HsmError::InvalidArg)` — bad slot/index, small buffer, missing
    ///   CBLOB/alias cert, or unprovisioned partition.
    async fn get_cert(
        &self,
        io: &impl HsmIo,
        part_id: HsmPartId,
        slot_id: u8,
        idx: u8,
        cert: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        if slot_id != 0 {
            return Err(HsmError::InvalidArg);
        }

        let cblob = dev_id_cblob::dev_id_cert_blob().ok_or(HsmError::InvalidArg)?;
        let devid_count = cblob.cert_count();
        let idx = idx as usize;
        let count = devid_count + TRAILING_CERTS as usize;
        if idx >= count {
            return Err(HsmError::InvalidArg);
        }

        // Device-id chain certs occupy the first `devid_count` indices.
        if idx < devid_count {
            let src = cblob.cert_der(idx).ok_or(HsmError::InvalidArg)?;
            return copy_or_size(src, cert);
        }

        // Then the GSRAM alias certificate.
        if idx == devid_count {
            let alias = gsram_alias::alias_cert();
            if alias.is_empty() {
                return Err(HsmError::InvalidArg);
            }
            return copy_or_size(alias, cert);
        }

        // Last index is the generated PID leaf. Build it deterministically into
        // a worst-case-sized scratch buffer (the builder requires that), then
        // copy the exact DER out. Because generation is deterministic, the query
        // and copy passes produce the same length — satisfying the DDI
        // query/copy contract without caching.
        self.alloc_scoped_async(io, async |scope| {
            let scratch = scope.dma_alloc(MAX_PID_CERT_DER)?;
            let n = self.generate_pid_cert(io, part_id, Some(scratch)).await?;
            copy_or_size(&scratch[..n], cert)
        })
        .await
    }
}

/// Query/copy helper: with `dst = None` return `src.len()`; with `Some(buf)`
/// copy `src` into `buf` (requiring `buf.len() >= src.len()`) and return the
/// length.
fn copy_or_size(src: &[u8], dst: Option<&mut [u8]>) -> HsmResult<usize> {
    if let Some(buf) = dst {
        if buf.len() < src.len() {
            return Err(HsmError::InvalidArg);
        }
        buf[..src.len()].copy_from_slice(src);
    }
    Ok(src.len())
}
