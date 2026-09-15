// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate Blob (CBLOB) container for the boot-time device-id certificate chain.
//!
//! The SP/HSP packs the device-id cert chain into a CBLOB in CP1/HSM DTCM at boot, so the
//! CP serves GetCertChainInfo (1108) / GetCertificate (1109) from local DTCM with no IPC.
//! It is a versioned multi-chain container: a 16-byte header, a whole-container `integrity_hash`,
//! then one self-contained variable-length `cert_chain_desc` per attestation slot (device-id =
//! slot 0 today, device-owner = slot 1 in future), followed by the packed DER.  Each descriptor
//! carries its own `desc_size`, so chains are walked without an offset table.  `CertBlobHdr`,
//! `CertChainDesc` and `CertBlobMeta` are a byte-for-byte ABI mirror of the SP-side structs in
//! `sp/src/dc_scm/soc_shared.h`; all fields little-endian. See `docs/cert_chain_hsm_dtcm.md`.

#![cfg_attr(not(test), no_std)]

use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

/// CBLOB magic: ASCII `"CERT"`.
pub const CBLOB_MAGIC: [u8; 4] = *b"CERT";

/// Container format version.
pub const CBLOB_VERSION: u8 = 1;

/// Per-chain descriptor version.
pub const CBLOB_DESC_VERSION: u8 = 1;

/// `digest_algo` value for SHA-256.
pub const CBLOB_DIGEST_SHA256: u8 = 0x01;

/// Length of the whole-container `integrity_hash` (SHA-256).
pub const CBLOB_INTEGRITY_LEN: usize = 32;

/// Container header size; the `integrity_hash` follows it.
pub const CBLOB_HDR_SIZE: usize = 16;

/// Fixed head of a `cert_chain_desc`; the inline cert metadata follows.
pub const CBLOB_DESC_HEAD_SIZE: usize = 40;

/// Byte offset of `chain_hash` within a `cert_chain_desc`.
pub const CBLOB_CHAIN_HASH_OFF: usize = 8;

/// Per-cert metadata size (one per certificate).
pub const CBLOB_META_SIZE: usize = 8;

/// Required alignment for the container base, offsets, and `total_size`.
pub const CBLOB_ALIGN: usize = 4;

/// Hard upper bound on `total_size`.
pub const CBLOB_MAX_SIZE: usize = 16_384;

/// Attestation slot for the device-id chain.
pub const CBLOB_SLOT_DEV_ID: u8 = 0;

/// Length of a chain thumbprint (SHA-256).
pub const DEV_ID_CHAIN_HASH_LEN: usize = 32;

/// Maximum number of device-id chain certificates (root + intermediate + device-id).
pub const MAX_DEVID_CERTS: usize = 5;

/// Maximum DER length of a single device-id chain certificate
/// (= HSP `MAX_FIPS_DEVID_CERT_LENGTH`).
pub const MAX_DEVID_CERT_LEN: usize = 2048;

/// Size of the reserved CP1/HSM DTCM region that holds the CBLOB (16 KB).
pub const DEV_ID_CERT_BLOB_REGION_SIZE: usize = 0x4000;

/// CBLOB container header (16 bytes). Byte-for-byte ABI mirror of the SP-side `struct cert_blob_hdr`.
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct CertBlobHdr {
    /// 0x00  magic `{ 'C','E','R','T' }`.
    pub magic: [u8; 4],
    /// 0x04  container format version.
    pub version: u8,
    /// 0x05  header size (= 16); the `integrity_hash` follows.
    pub hdr_size: u8,
    /// 0x06  digest algorithm (`0x01` = SHA-256).
    pub digest_algo: u8,
    /// 0x07  number of `cert_chain_desc` blocks (>= 1).
    pub num_slots: u8,
    /// 0x08  whole container incl. `integrity_hash`; `% 4 == 0`, `<= 16384`.
    pub total_size: u16,
    /// 0x0A  reserved, must be 0.
    pub reserved: [u8; 6],
}

/// CBLOB per-chain descriptor head (40 bytes); `cert_cnt` inline `CertBlobMeta` follow at 0x28.
/// Byte-for-byte ABI mirror of the SP-side `struct cert_chain_desc`.
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct CertChainDesc {
    /// 0x00  per-chain descriptor version.
    pub version: u8,
    /// 0x01  attestation slot this chain answers.
    pub slot_id: u8,
    /// 0x02  total bytes of this descriptor (head + metadata); locates the next chain.
    pub desc_size: u16,
    /// 0x04  number of certificates in this chain.
    pub cert_cnt: u8,
    /// 0x05  reserved, must be 0.
    pub reserved: [u8; 3],
    /// 0x08  SHA-256 chain thumbprint.
    pub chain_hash: [u8; DEV_ID_CHAIN_HASH_LEN],
}

/// CBLOB per-cert metadata (8 bytes), inline in the chain descriptor. Byte-for-byte ABI mirror of
/// the SP-side `struct cert_blob_meta`.
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct CertBlobMeta {
    /// +0x00  4-byte-aligned offset of the cert DER from the container base.
    pub offset: u32,
    /// +0x04  true DER length (excludes padding).
    pub length: u32,
}

// Lock the ABI: these fail to compile if the layout drifts from the SP-side C structs.
static_assertions::const_assert_eq!(core::mem::size_of::<CertBlobHdr>(), CBLOB_HDR_SIZE);
static_assertions::const_assert_eq!(core::mem::align_of::<CertBlobHdr>(), CBLOB_ALIGN);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertBlobHdr, version), 0x04);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertBlobHdr, hdr_size), 0x05);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertBlobHdr, digest_algo), 0x06);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertBlobHdr, num_slots), 0x07);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertBlobHdr, total_size), 0x08);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertBlobHdr, reserved), 0x0A);
static_assertions::const_assert_eq!(core::mem::size_of::<CertChainDesc>(), CBLOB_DESC_HEAD_SIZE);
static_assertions::const_assert_eq!(core::mem::align_of::<CertChainDesc>(), CBLOB_ALIGN);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertChainDesc, slot_id), 0x01);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertChainDesc, desc_size), 0x02);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertChainDesc, cert_cnt), 0x04);
static_assertions::const_assert_eq!(
    core::mem::offset_of!(CertChainDesc, chain_hash),
    CBLOB_CHAIN_HASH_OFF
);
static_assertions::const_assert_eq!(core::mem::size_of::<CertBlobMeta>(), CBLOB_META_SIZE);
static_assertions::const_assert_eq!(core::mem::align_of::<CertBlobMeta>(), CBLOB_ALIGN);
// The 16 KB region holds the worst-case single chain (header + integrity + descriptor + max certs).
static_assertions::const_assert!(
    CBLOB_HDR_SIZE
        + CBLOB_INTEGRITY_LEN
        + CBLOB_DESC_HEAD_SIZE
        + MAX_DEVID_CERTS * CBLOB_META_SIZE
        + MAX_DEVID_CERTS * MAX_DEVID_CERT_LEN
        <= DEV_ID_CERT_BLOB_REGION_SIZE
);

/// Bounds-checked read-only view over a single chain in a CBLOB DTCM region. Construct with
/// [`CertBlob::parse`] (device-id / slot 0) or [`CertBlob::parse_slot`]; all accessors are
/// panic-free even on a corrupt region.
pub struct CertBlob<'a> {
    /// The container bytes, trimmed to `total_size`.
    bytes: &'a [u8],
    /// Offset of this chain's inline metadata array (`cert_cnt` x 8 B).
    meta_base: usize,
    /// Validated certificate count for this chain.
    cert_count: usize,
    /// This chain's thumbprint (copied from the descriptor in `parse_slot`).
    chain_hash: [u8; DEV_ID_CHAIN_HASH_LEN],
}

impl<'a> CertBlob<'a> {
    /// Validate a CBLOB and overlay the device-id chain (slot 0). See [`Self::parse_slot`].
    pub fn parse(region: &'a [u8]) -> Option<Self> {
        Self::parse_slot(region, CBLOB_SLOT_DEV_ID)
    }

    /// Validate a CBLOB at the start of `region` and overlay the chain for `slot_id`, or `None`
    /// on any structural check failure (bad magic/version/sizes, unknown/absent slot, or an
    /// out-of-range/overlapping cert). Does NOT verify the `integrity_hash` -- the CP is a dumb
    /// reader; integrity is the host's job.
    pub fn parse_slot(region: &'a [u8], slot_id: u8) -> Option<Self> {
        let hdr = CertBlobHdr::read_from_bytes(region.get(0..CBLOB_HDR_SIZE)?).ok()?;

        if hdr.magic != CBLOB_MAGIC {
            return None;
        }
        if hdr.version != CBLOB_VERSION {
            return None;
        }
        if hdr.digest_algo != CBLOB_DIGEST_SHA256 {
            return None;
        }
        if hdr.reserved != [0u8; 6] {
            return None;
        }

        let hdr_size = hdr.hdr_size as usize;
        let total_size = hdr.total_size as usize;
        let num_slots = hdr.num_slots as usize;

        // hdr_size >= 16 (lenient): everything after is located via hdr_size, so a grown header
        // still parses on an older reader.
        if hdr_size < CBLOB_HDR_SIZE || !hdr_size.is_multiple_of(CBLOB_ALIGN) {
            return None;
        }
        if !total_size.is_multiple_of(CBLOB_ALIGN)
            || total_size > CBLOB_MAX_SIZE
            || total_size > region.len()
        {
            return None;
        }
        if num_slots == 0 {
            return None;
        }

        let bytes = region.get(..total_size)?;

        // Descriptors start after the header + integrity_hash; walk them by `desc_size`.
        let mut desc_base = hdr_size.checked_add(CBLOB_INTEGRITY_LEN)?;
        for _ in 0..num_slots {
            let head = CertChainDesc::read_from_bytes(
                bytes.get(desc_base..desc_base.checked_add(CBLOB_DESC_HEAD_SIZE)?)?,
            )
            .ok()?;

            // Minimal, version-agnostic bounds so any chain -- including a future unknown-version
            // one -- can be skipped by `desc_size` without imposing this version's field rules on
            // it. This preserves forward compatibility: an older reader still serves the slots it
            // understands and skips the rest.
            let desc_size = head.desc_size as usize;
            if desc_size < CBLOB_DESC_HEAD_SIZE {
                return None;
            }
            let desc_end = desc_base.checked_add(desc_size)?;
            if desc_end > total_size {
                return None;
            }

            if head.slot_id != slot_id {
                desc_base = desc_end;
                continue;
            }
            // Matched the requested slot: it must be a version we understand to parse its body.
            if head.version != CBLOB_DESC_VERSION {
                return None;
            }

            // Apply this version's structural rules only to the matched chain.
            let cert_count = head.cert_cnt as usize;
            if cert_count == 0 || cert_count > MAX_DEVID_CERTS {
                return None;
            }
            if head.reserved != [0u8; 3] {
                return None;
            }
            if desc_size != CBLOB_DESC_HEAD_SIZE + cert_count * CBLOB_META_SIZE {
                return None;
            }

            // Validate this chain's inline metadata + cert DER ranges (ascending, non-overlapping,
            // in range). Certs live past this descriptor in the DER pool.
            let meta_base = desc_base + CBLOB_DESC_HEAD_SIZE;
            let mut prev_end = desc_end;
            for i in 0..cert_count {
                let m = meta_base + i * CBLOB_META_SIZE;
                let meta =
                    CertBlobMeta::read_from_bytes(bytes.get(m..m + CBLOB_META_SIZE)?).ok()?;
                let offset = meta.offset as usize;
                let length = meta.length as usize;
                if !offset.is_multiple_of(CBLOB_ALIGN) || offset < prev_end || offset > total_size {
                    return None;
                }
                if length > MAX_DEVID_CERT_LEN || length > total_size - offset {
                    return None;
                }
                prev_end = offset.checked_add(length)?;
            }

            return Some(CertBlob {
                bytes,
                meta_base,
                cert_count,
                chain_hash: head.chain_hash,
            });
        }

        None
    }

    /// Number of certificates in the chain.
    pub fn cert_count(&self) -> usize {
        self.cert_count
    }

    /// The 32-byte chain thumbprint (returned, combined with alias/PID, in GetCertChainInfo).
    pub fn dev_id_chain_hash(&self) -> &[u8; DEV_ID_CHAIN_HASH_LEN] {
        &self.chain_hash
    }

    /// Read metadata entry `i` (ranges already validated in `parse_slot`).
    fn meta(&self, i: usize) -> Option<CertBlobMeta> {
        if i >= self.cert_count {
            return None;
        }
        let m = self.meta_base + i * CBLOB_META_SIZE;
        CertBlobMeta::read_from_bytes(self.bytes.get(m..m + CBLOB_META_SIZE)?).ok()
    }

    /// DER length of certificate `i`, or `None` if `i >= cert_count`.
    pub fn cert_len(&self, i: usize) -> Option<u16> {
        Some(self.meta(i)?.length as u16)
    }

    /// Borrow the packed DER bytes of certificate `i`, or `None` if `i >= cert_count`.
    pub fn cert_der(&self, i: usize) -> Option<&'a [u8]> {
        let meta = self.meta(i)?;
        let offset = meta.offset as usize;
        let length = meta.length as usize;
        self.bytes.get(offset..offset.checked_add(length)?)
    }

    /// Build a single-chain (slot 0) CBLOB into `out` from `certs` (+ `chain_hash`). Cert id is
    /// the index; the `integrity_hash` is left zeroed (the CP does not verify it). Returns the
    /// `total_size` written, or `None` if it doesn't fit. Used by tests/tools.
    pub fn build(
        out: &mut [u8],
        certs: &[&[u8]],
        chain_hash: &[u8; DEV_ID_CHAIN_HASH_LEN],
    ) -> Option<usize> {
        let cert_count = certs.len();
        if cert_count == 0 || cert_count > MAX_DEVID_CERTS {
            return None;
        }
        let body_off = CBLOB_HDR_SIZE + CBLOB_INTEGRITY_LEN;
        let desc_size = CBLOB_DESC_HEAD_SIZE + cert_count * CBLOB_META_SIZE;
        let meta_base = body_off + CBLOB_DESC_HEAD_SIZE;

        // Lay out the certs (4-byte aligned) to compute total_size up front.
        let mut offsets = [0usize; MAX_DEVID_CERTS];
        let mut cursor = body_off + desc_size;
        for (i, c) in certs.iter().enumerate() {
            offsets[i] = cursor;
            cursor = cursor.checked_add(c.len())?;
            cursor = (cursor + CBLOB_ALIGN - 1) & !(CBLOB_ALIGN - 1);
        }
        let total_size = cursor;
        if !total_size.is_multiple_of(CBLOB_ALIGN)
            || total_size > CBLOB_MAX_SIZE
            || total_size > out.len()
        {
            return None;
        }

        for b in out[..total_size].iter_mut() {
            *b = 0;
        }

        let hdr = CertBlobHdr {
            magic: CBLOB_MAGIC,
            version: CBLOB_VERSION,
            hdr_size: CBLOB_HDR_SIZE as u8,
            digest_algo: CBLOB_DIGEST_SHA256,
            num_slots: 1,
            total_size: total_size as u16,
            reserved: [0u8; 6],
        };
        out.get_mut(0..CBLOB_HDR_SIZE)?
            .copy_from_slice(hdr.as_bytes());

        let desc = CertChainDesc {
            version: CBLOB_DESC_VERSION,
            slot_id: CBLOB_SLOT_DEV_ID,
            desc_size: desc_size as u16,
            cert_cnt: cert_count as u8,
            reserved: [0u8; 3],
            chain_hash: *chain_hash,
        };
        out.get_mut(body_off..body_off + CBLOB_DESC_HEAD_SIZE)?
            .copy_from_slice(desc.as_bytes());

        for (i, c) in certs.iter().enumerate() {
            let meta = CertBlobMeta {
                offset: offsets[i] as u32,
                length: c.len() as u32,
            };
            let m = meta_base + i * CBLOB_META_SIZE;
            out.get_mut(m..m + CBLOB_META_SIZE)?
                .copy_from_slice(meta.as_bytes());
            out.get_mut(offsets[i]..offsets[i] + c.len())?
                .copy_from_slice(c);
        }
        Some(total_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_thumb() -> [u8; 32] {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = i as u8;
        }
        h
    }

    #[test]
    fn build_parse_roundtrip() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let root = [0xA1u8; 40];
        let inter = [0xB2u8; 33];
        let devid = [0xC3u8; 50];
        let certs: [&[u8]; 3] = [&root, &inter, &devid];
        let thumb = sample_thumb();

        let total = CertBlob::build(&mut buf, &certs, &thumb).unwrap();
        assert!(total <= DEV_ID_CERT_BLOB_REGION_SIZE);

        let blob = CertBlob::parse(&buf).unwrap();
        assert_eq!(blob.cert_count(), 3);
        assert_eq!(blob.dev_id_chain_hash(), &thumb);
        assert_eq!(blob.cert_len(0), Some(40));
        assert_eq!(blob.cert_len(1), Some(33));
        assert_eq!(blob.cert_len(2), Some(50));
        assert_eq!(blob.cert_der(0), Some(&root[..]));
        assert_eq!(blob.cert_der(1), Some(&inter[..]));
        assert_eq!(blob.cert_der(2), Some(&devid[..]));
        assert_eq!(blob.cert_len(3), None);
        assert_eq!(blob.cert_der(3), None);
    }

    #[test]
    fn certs_are_4byte_aligned() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let a = [1u8; 37];
        let b = [2u8; 41];
        let certs: [&[u8]; 2] = [&a, &b];
        CertBlob::build(&mut buf, &certs, &sample_thumb()).unwrap();
        let blob = CertBlob::parse(&buf).unwrap();
        // Offsets are recovered via cert_der; verify each starts 4-byte aligned in the container.
        for i in 0..blob.cert_count() {
            let der = blob.cert_der(i).unwrap();
            let off = der.as_ptr() as usize - buf.as_ptr() as usize;
            assert_eq!(off % CBLOB_ALIGN, 0);
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        buf[0] = b'X';
        assert!(CertBlob::parse(&buf).is_none());
    }

    #[test]
    fn rejects_bad_version() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        buf[4] = CBLOB_VERSION + 1; // container version
        assert!(CertBlob::parse(&buf).is_none());
    }

    #[test]
    fn rejects_short_region() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        let total = CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        assert!(CertBlob::parse(&buf[..total - 1]).is_none());
        assert!(CertBlob::parse(&buf[..CBLOB_HDR_SIZE - 1]).is_none());
    }

    #[test]
    fn rejects_zero_and_unpopulated() {
        let buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        assert!(CertBlob::parse(&buf).is_none());
    }

    #[test]
    fn rejects_absent_slot() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        // Only slot 0 exists; asking for slot 1 must fail.
        assert!(CertBlob::parse_slot(&buf, 1).is_none());
    }

    #[test]
    fn rejects_nonzero_reserved() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        buf[0x0A] = 1; // header reserved
        assert!(CertBlob::parse(&buf).is_none());
    }

    #[test]
    fn rejects_bad_desc_size() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        // Corrupt desc_size (offset 0x02 within the descriptor at body_off).
        let body_off = CBLOB_HDR_SIZE + CBLOB_INTEGRITY_LEN;
        buf[body_off + 0x02] = 0xFF;
        assert!(CertBlob::parse(&buf).is_none());
    }

    #[test]
    fn build_rejects_too_many() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [0u8; 8];
        let certs: [&[u8]; 6] = [&c, &c, &c, &c, &c, &c];
        assert!(CertBlob::build(&mut buf, &certs, &sample_thumb()).is_none());
        assert!(CertBlob::build(&mut buf, &[], &sample_thumb()).is_none());
    }

    #[test]
    fn build_rejects_oversized_output() {
        let mut small = [0u8; 32];
        let c = [1u8; 20];
        assert!(CertBlob::build(&mut small, &[&c], &sample_thumb()).is_none());
    }

    #[test]
    fn skips_unknown_version_slot_and_serves_known() {
        // Hand-build a 2-slot container: an unknown-version slot 1 FIRST, then the V1 device-id
        // slot 0. An older reader must skip slot 1 by `desc_size` (without applying V1 field rules
        // to it) and still serve slot 0.
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let body_off = CBLOB_HDR_SIZE + CBLOB_INTEGRITY_LEN;

        // slot 1: future descriptor version 2, head-only (desc_size = 40), with reserved bytes
        // deliberately non-zero -- a V1 reader must NOT reject the container on account of it.
        let s1 = CertChainDesc {
            version: 2,
            slot_id: 1,
            desc_size: CBLOB_DESC_HEAD_SIZE as u16,
            cert_cnt: 0,
            reserved: [0xFF; 3],
            chain_hash: [0x55; 32],
        };
        let s1_off = body_off;
        buf[s1_off..s1_off + CBLOB_DESC_HEAD_SIZE].copy_from_slice(s1.as_bytes());

        // slot 0 (V1) after slot 1, one cert.
        let cert = [0xC3u8; 20];
        let s0_off = s1_off + CBLOB_DESC_HEAD_SIZE;
        let s0_desc_size = CBLOB_DESC_HEAD_SIZE + CBLOB_META_SIZE;
        let cert_off = s0_off + s0_desc_size;
        let thumb = sample_thumb();
        let s0 = CertChainDesc {
            version: CBLOB_DESC_VERSION,
            slot_id: CBLOB_SLOT_DEV_ID,
            desc_size: s0_desc_size as u16,
            cert_cnt: 1,
            reserved: [0; 3],
            chain_hash: thumb,
        };
        buf[s0_off..s0_off + CBLOB_DESC_HEAD_SIZE].copy_from_slice(s0.as_bytes());
        let meta = CertBlobMeta {
            offset: cert_off as u32,
            length: cert.len() as u32,
        };
        buf[s0_off + CBLOB_DESC_HEAD_SIZE..s0_off + CBLOB_DESC_HEAD_SIZE + CBLOB_META_SIZE]
            .copy_from_slice(meta.as_bytes());
        buf[cert_off..cert_off + cert.len()].copy_from_slice(&cert);

        let total_size = (cert_off + cert.len() + CBLOB_ALIGN - 1) & !(CBLOB_ALIGN - 1);
        let hdr = CertBlobHdr {
            magic: CBLOB_MAGIC,
            version: CBLOB_VERSION,
            hdr_size: CBLOB_HDR_SIZE as u8,
            digest_algo: CBLOB_DIGEST_SHA256,
            num_slots: 2,
            total_size: total_size as u16,
            reserved: [0; 6],
        };
        buf[0..CBLOB_HDR_SIZE].copy_from_slice(hdr.as_bytes());

        // slot 0 is served despite the unknown-version slot 1 preceding it.
        let blob = CertBlob::parse(&buf).unwrap();
        assert_eq!(blob.cert_count(), 1);
        assert_eq!(blob.dev_id_chain_hash(), &thumb);
        assert_eq!(blob.cert_der(0), Some(&cert[..]));

        // Requesting the unknown-version slot itself fails (can't parse a version we don't know).
        assert!(CertBlob::parse_slot(&buf, 1).is_none());
    }

    // Byte offset of slot 0's first `CertBlobMeta` in a single-slot container built by `build`.
    const META0_OFF: usize = CBLOB_HDR_SIZE + CBLOB_INTEGRITY_LEN + CBLOB_DESC_HEAD_SIZE;

    // The dirty magic `INVL` marks an in-flight rewrite; a concurrent read must reject it.
    #[test]
    fn rejects_dirty_magic() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        buf[0..4].copy_from_slice(b"INVL");
        assert!(CertBlob::parse(&buf).is_none());
    }

    // An unknown digest algorithm is rejected (the reader only understands SHA-256).
    #[test]
    fn rejects_bad_digest_algo() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        buf[0x06] = CBLOB_DIGEST_SHA256 + 1;
        assert!(CertBlob::parse(&buf).is_none());
    }

    // A grown header (larger hdr_size) still parses: the reader locates the body via hdr_size.
    #[test]
    fn accepts_grown_header() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        // Simulate a 20-byte header (4 extra bytes) followed by integrity_hash then the descriptor.
        let hdr_size = CBLOB_HDR_SIZE + CBLOB_ALIGN; // 20, still 4-byte aligned
        let body_off = hdr_size + CBLOB_INTEGRITY_LEN;
        let desc_size = CBLOB_DESC_HEAD_SIZE + CBLOB_META_SIZE;
        let cert_off = body_off + desc_size;
        let cert = [0xC3u8; 24];
        let thumb = sample_thumb();

        let desc = CertChainDesc {
            version: CBLOB_DESC_VERSION,
            slot_id: CBLOB_SLOT_DEV_ID,
            desc_size: desc_size as u16,
            cert_cnt: 1,
            reserved: [0; 3],
            chain_hash: thumb,
        };
        buf[body_off..body_off + CBLOB_DESC_HEAD_SIZE].copy_from_slice(desc.as_bytes());
        let meta = CertBlobMeta {
            offset: cert_off as u32,
            length: cert.len() as u32,
        };
        buf[body_off + CBLOB_DESC_HEAD_SIZE..body_off + CBLOB_DESC_HEAD_SIZE + CBLOB_META_SIZE]
            .copy_from_slice(meta.as_bytes());
        buf[cert_off..cert_off + cert.len()].copy_from_slice(&cert);

        let total_size = (cert_off + cert.len() + CBLOB_ALIGN - 1) & !(CBLOB_ALIGN - 1);
        let hdr = CertBlobHdr {
            magic: CBLOB_MAGIC,
            version: CBLOB_VERSION,
            hdr_size: hdr_size as u8,
            digest_algo: CBLOB_DIGEST_SHA256,
            num_slots: 1,
            total_size: total_size as u16,
            reserved: [0; 6],
        };
        buf[0..CBLOB_HDR_SIZE].copy_from_slice(hdr.as_bytes());

        let blob = CertBlob::parse(&buf).unwrap();
        assert_eq!(blob.cert_count(), 1);
        assert_eq!(blob.dev_id_chain_hash(), &thumb);
        assert_eq!(blob.cert_der(0), Some(&cert[..]));
    }

    // hdr_size must be 4-byte aligned.
    #[test]
    fn rejects_unaligned_hdr_size() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        buf[0x05] = (CBLOB_HDR_SIZE + 1) as u8; // 17, not a multiple of 4
        assert!(CertBlob::parse(&buf).is_none());
    }

    // total_size above the hard cap is rejected.
    #[test]
    fn rejects_oversize_total_size() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        // 4-byte aligned but larger than CBLOB_MAX_SIZE (and the region).
        buf[0x08..0x0A]
            .copy_from_slice(&((CBLOB_MAX_SIZE as u16) + CBLOB_ALIGN as u16).to_le_bytes());
        assert!(CertBlob::parse(&buf).is_none());
    }

    // total_size must be 4-byte aligned.
    #[test]
    fn rejects_unaligned_total_size() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        let total = CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        buf[0x08..0x0A].copy_from_slice(&((total as u16) + 1).to_le_bytes());
        assert!(CertBlob::parse(&buf).is_none());
    }

    // A container must advertise at least one chain.
    #[test]
    fn rejects_zero_num_slots() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        buf[0x07] = 0;
        assert!(CertBlob::parse(&buf).is_none());
    }

    // A cert offset pointing back inside the descriptor is rejected.
    #[test]
    fn rejects_cert_offset_inside_descriptor() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        // Point cert 0 at the descriptor head (well before desc_end).
        let body_off = CBLOB_HDR_SIZE + CBLOB_INTEGRITY_LEN;
        buf[META0_OFF..META0_OFF + 4].copy_from_slice(&(body_off as u32).to_le_bytes());
        assert!(CertBlob::parse(&buf).is_none());
    }

    // Overlapping cert ranges are rejected; offsets must be strictly ascending.
    #[test]
    fn rejects_overlapping_cert_offsets() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c0 = [1u8; 64];
        let c1 = [2u8; 64];
        CertBlob::build(&mut buf, &[&c0, &c1], &sample_thumb()).unwrap();
        // meta[1].offset lives one CBLOB_META_SIZE past meta[0]; rewrite it to alias meta[0].offset.
        let meta0_offset = u32::from_le_bytes(buf[META0_OFF..META0_OFF + 4].try_into().unwrap());
        let meta1_off_field = META0_OFF + CBLOB_META_SIZE;
        buf[meta1_off_field..meta1_off_field + 4].copy_from_slice(&meta0_offset.to_le_bytes());
        assert!(CertBlob::parse(&buf).is_none());
    }

    // A cert whose length runs past total_size is rejected.
    #[test]
    fn rejects_cert_length_past_total_size() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        // Inflate cert 0's length to overrun the container (but stay under MAX_DEVID_CERT_LEN so the
        // total_size bound is what trips, not the per-cert cap).
        buf[META0_OFF + 4..META0_OFF + 8].copy_from_slice(&512u32.to_le_bytes());
        assert!(CertBlob::parse(&buf).is_none());
    }

    // A single cert longer than MAX_DEVID_CERT_LEN is rejected even when it fits the region.
    #[test]
    fn rejects_cert_over_max_len() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [7u8; MAX_DEVID_CERT_LEN + 1];
        // Fits the 16 KB region, so `build` succeeds; the per-cert cap must reject it on parse.
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        assert!(CertBlob::parse(&buf).is_none());
    }

    // A cert offset that is not 4-byte aligned is rejected.
    #[test]
    fn rejects_unaligned_cert_offset() {
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        let c = [9u8; 20];
        CertBlob::build(&mut buf, &[&c], &sample_thumb()).unwrap();
        let meta0_offset = u32::from_le_bytes(buf[META0_OFF..META0_OFF + 4].try_into().unwrap());
        buf[META0_OFF..META0_OFF + 4].copy_from_slice(&(meta0_offset + 1).to_le_bytes());
        assert!(CertBlob::parse(&buf).is_none());
    }
}
