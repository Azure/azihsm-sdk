// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate Blob (CBLOB) container for the boot-time device-id certificate chain.
//!
//! The SP/HSP packs the device-id cert chain into a CBLOB in CP1/HSM DTCM at boot, so the
//! CP serves GetCertChainInfo (1108) / GetCertificate (1109) from local DTCM with no IPC.
//! Layout: header + descriptor table + packed DER + trailing SHA-256 digest (see
//! `cp/hsm/docs/CertChainStoreOnHsmDtcm.md`). `CertBlobHdr` / `CertBlobDesc` are a byte-for-byte
//! ABI mirror of the SP-side structs in `sp/src/dc_scm/soc_shared.h`; all fields little-endian.

#![cfg_attr(not(test), no_std)]

use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

/// CBLOB magic: ASCII `"CERT"`.
pub const CBLOB_MAGIC: [u8; 4] = *b"CERT";

/// Major version (format identifier only; not gated on for field presence).
pub const CBLOB_VER_MAJOR: u8 = 1;

/// Minor version (format identifier only).
pub const CBLOB_VER_MINOR: u8 = 1;

/// `digest_alg` value for SHA-256.
pub const CBLOB_DIGEST_SHA256: u8 = 0x01;

/// Trailing integrity digest length (SHA-256).
pub const CBLOB_DIGEST_LEN: usize = 32;

/// Header size: base 16 B + 32 B `dev_id_chain_hash`.
pub const CBLOB_HDR_SIZE: usize = 48;

/// Byte offset of `dev_id_chain_hash` within the header.
pub const CBLOB_DEV_ID_CHAIN_HASH_OFF: usize = 16;

/// Descriptor size (one per certificate).
pub const CBLOB_DESC_SIZE: usize = 8;

/// Required alignment for the blob base, offsets, and `total_size`.
pub const CBLOB_ALIGN: usize = 4;

/// Hard upper bound on `total_size` (incl. digest).
pub const CBLOB_MAX_SIZE: usize = 16_384;

/// Length of the dev-id chain thumbprint (SHA-256).
pub const DEV_ID_CHAIN_HASH_LEN: usize = 32;

/// Maximum number of device-id chain certificates (root + intermediate + device-id).
pub const MAX_DEVID_CERTS: usize = 5;

/// Maximum DER length of a single device-id chain certificate
/// (= HSP `MAX_FIPS_DEVID_CERT_LENGTH`).
pub const MAX_DEVID_CERT_LEN: usize = 2048;

/// Size of the reserved CP1/HSM DTCM region that holds the CBLOB (16 KB).
pub const DEV_ID_CERT_BLOB_REGION_SIZE: usize = 0x4000;

/// CBLOB header (48 bytes). Byte-for-byte ABI mirror of the SP-side `struct cert_blob_hdr`.
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct CertBlobHdr {
    /// 0x00  magic `{ 'C','E','R','T' }`.
    pub magic: [u8; 4],
    /// 0x04  major version (format identifier).
    pub ver_major: u8,
    /// 0x05  minor version (format identifier).
    pub ver_minor: u8,
    /// 0x06  number of certificates in the chain.
    pub cert_count: u16,
    /// 0x08  whole blob incl. digest; `% 4 == 0`, `<= 16384`.
    pub total_size: u16,
    /// 0x0A  digest algorithm (`0x01` = SHA-256).
    pub digest_alg: u8,
    /// 0x0B  header size; the descriptor table starts here (= 48).
    pub hdr_size: u8,
    /// 0x0C  reserved, must be 0.
    pub reserved: u32,
    /// 0x10  dev-id chain hash returned (combined with alias/PID) in GetCertChainInfo.
    pub dev_id_chain_hash: [u8; DEV_ID_CHAIN_HASH_LEN],
}

/// CBLOB descriptor (8 bytes, one per certificate). Byte-for-byte ABI mirror of the
/// SP-side `struct cert_blob_desc`.
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub struct CertBlobDesc {
    /// +0x00  4-byte-aligned offset of the cert DER from the blob base.
    pub offset: u32,
    /// +0x04  true DER length (excludes padding).
    pub length: u32,
}

// Lock the ABI: these fail to compile if the layout drifts from the SP-side C structs.
static_assertions::const_assert_eq!(core::mem::size_of::<CertBlobHdr>(), CBLOB_HDR_SIZE);
static_assertions::const_assert_eq!(core::mem::align_of::<CertBlobHdr>(), CBLOB_ALIGN);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertBlobHdr, ver_major), 0x04);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertBlobHdr, ver_minor), 0x05);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertBlobHdr, cert_count), 0x06);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertBlobHdr, total_size), 0x08);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertBlobHdr, digest_alg), 0x0A);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertBlobHdr, hdr_size), 0x0B);
static_assertions::const_assert_eq!(core::mem::offset_of!(CertBlobHdr, reserved), 0x0C);
static_assertions::const_assert_eq!(
    core::mem::offset_of!(CertBlobHdr, dev_id_chain_hash),
    CBLOB_DEV_ID_CHAIN_HASH_OFF
);
static_assertions::const_assert_eq!(core::mem::size_of::<CertBlobDesc>(), CBLOB_DESC_SIZE);
static_assertions::const_assert_eq!(core::mem::align_of::<CertBlobDesc>(), CBLOB_ALIGN);
// The 16 KB region holds the worst-case chain (header + table + max certs + digest).
static_assertions::const_assert!(
    CBLOB_HDR_SIZE
        + MAX_DEVID_CERTS * CBLOB_DESC_SIZE
        + MAX_DEVID_CERTS * MAX_DEVID_CERT_LEN
        + CBLOB_DIGEST_LEN
        <= DEV_ID_CERT_BLOB_REGION_SIZE
);

/// Bounds-checked read-only view over a CBLOB in a DTCM byte region. Construct with
/// [`CertBlob::parse`]; all accessors are panic-free even on a corrupt region.
pub struct CertBlob<'a> {
    /// The blob bytes, trimmed to `total_size`.
    bytes: &'a [u8],
    /// Validated certificate count.
    cert_count: usize,
    /// Validated header size (descriptor table base).
    hdr_size: usize,
    /// Dev-id chain hash (copied from the header in `parse`).
    dev_id_chain_hash: [u8; DEV_ID_CHAIN_HASH_LEN],
}

impl<'a> CertBlob<'a> {
    /// Validate and overlay a CBLOB at the start of `region`, or `None` on any structural
    /// check failure (bad magic/version/sizes, or an out-of-range/overlapping descriptor).
    /// Does NOT verify the integrity digest -- the CP is a dumb reader; integrity is the host's job.
    pub fn parse(region: &'a [u8]) -> Option<Self> {
        let hdr = CertBlobHdr::read_from_bytes(region.get(0..CBLOB_HDR_SIZE)?).ok()?;

        if hdr.magic != CBLOB_MAGIC {
            return None;
        }
        if hdr.ver_major != CBLOB_VER_MAJOR {
            return None;
        }
        if hdr.digest_alg != CBLOB_DIGEST_SHA256 {
            return None;
        }
        if hdr.reserved != 0 {
            return None;
        }

        let cert_count = hdr.cert_count as usize;
        let total_size = hdr.total_size as usize;
        let hdr_size = hdr.hdr_size as usize;

        // hdr_size >= 48 (lenient): the table is located via hdr_size, so a grown header still parses.
        if hdr_size < CBLOB_HDR_SIZE || !hdr_size.is_multiple_of(CBLOB_ALIGN) {
            return None;
        }
        if !total_size.is_multiple_of(CBLOB_ALIGN)
            || total_size > CBLOB_MAX_SIZE
            || total_size > region.len()
        {
            return None;
        }
        if cert_count == 0 || cert_count > MAX_DEVID_CERTS {
            return None;
        }

        // Cert data occupies [table_end .. data_end); the digest is the last 32 B.
        let data_end = total_size.checked_sub(CBLOB_DIGEST_LEN)?;
        let table_end = hdr_size.checked_add(cert_count.checked_mul(CBLOB_DESC_SIZE)?)?;
        if table_end > data_end {
            return None;
        }

        // Each descriptor: aligned, in range, capped, and ascending + non-overlapping.
        let mut prev_end = table_end;
        for i in 0..cert_count {
            let base = hdr_size + i * CBLOB_DESC_SIZE;
            let desc =
                CertBlobDesc::read_from_bytes(region.get(base..base + CBLOB_DESC_SIZE)?).ok()?;
            let offset = desc.offset as usize;
            let length = desc.length as usize;
            if !offset.is_multiple_of(CBLOB_ALIGN) || offset < prev_end || offset > data_end {
                return None;
            }
            if length == 0 || length > MAX_DEVID_CERT_LEN || length > data_end - offset {
                return None;
            }
            prev_end = offset.checked_add(length)?;
        }

        Some(CertBlob {
            bytes: region.get(..total_size)?,
            cert_count,
            hdr_size,
            dev_id_chain_hash: hdr.dev_id_chain_hash,
        })
    }

    /// Number of certificates in the chain.
    pub fn cert_count(&self) -> usize {
        self.cert_count
    }

    /// The 32-byte dev-id chain hash (header extension).
    pub fn dev_id_chain_hash(&self) -> &[u8; DEV_ID_CHAIN_HASH_LEN] {
        &self.dev_id_chain_hash
    }

    /// Read descriptor `i` (ranges already validated in `parse`).
    fn desc(&self, i: usize) -> Option<CertBlobDesc> {
        if i >= self.cert_count {
            return None;
        }
        let base = self.hdr_size + i * CBLOB_DESC_SIZE;
        CertBlobDesc::read_from_bytes(self.bytes.get(base..base + CBLOB_DESC_SIZE)?).ok()
    }

    /// DER length of certificate `i`, or `None` if `i >= cert_count`.
    pub fn cert_len(&self, i: usize) -> Option<u16> {
        Some(self.desc(i)?.length as u16)
    }

    /// Borrow the packed DER bytes of certificate `i`, or `None` if `i >= cert_count`.
    pub fn cert_der(&self, i: usize) -> Option<&'a [u8]> {
        let desc = self.desc(i)?;
        let offset = desc.offset as usize;
        let length = desc.length as usize;
        self.bytes.get(offset..offset.checked_add(length)?)
    }

    /// Build a CBLOB into `out` from `certs` (+ `dev_id_chain_hash`). Cert id is the index.
    /// Returns the `total_size` written (digest trailer left zeroed), or `None` if it
    /// doesn't fit. No firmware caller, so the linker dead-strips it; used by tests/tools.
    pub fn build(
        out: &mut [u8],
        certs: &[&[u8]],
        dev_id_chain_hash: &[u8; DEV_ID_CHAIN_HASH_LEN],
    ) -> Option<usize> {
        let cert_count = certs.len();
        if cert_count == 0 || cert_count > MAX_DEVID_CERTS {
            return None;
        }
        let table_end = CBLOB_HDR_SIZE + cert_count * CBLOB_DESC_SIZE;

        // Lay out the certs (4-byte aligned) to compute total_size up front.
        let mut offsets = [0usize; MAX_DEVID_CERTS];
        let mut cursor = table_end;
        for (i, c) in certs.iter().enumerate() {
            offsets[i] = cursor;
            cursor = cursor.checked_add(c.len())?;
            cursor = (cursor + CBLOB_ALIGN - 1) & !(CBLOB_ALIGN - 1);
        }
        let digest_off = cursor; // already 4-byte aligned
        let total_size = digest_off.checked_add(CBLOB_DIGEST_LEN)?;
        if total_size > CBLOB_MAX_SIZE || total_size > out.len() {
            return None;
        }

        for b in out[..total_size].iter_mut() {
            *b = 0;
        }

        let hdr = CertBlobHdr {
            magic: CBLOB_MAGIC,
            ver_major: CBLOB_VER_MAJOR,
            ver_minor: CBLOB_VER_MINOR,
            cert_count: cert_count as u16,
            total_size: total_size as u16,
            digest_alg: CBLOB_DIGEST_SHA256,
            hdr_size: CBLOB_HDR_SIZE as u8,
            reserved: 0,
            dev_id_chain_hash: *dev_id_chain_hash,
        };
        out.get_mut(0..CBLOB_HDR_SIZE)?
            .copy_from_slice(hdr.as_bytes());

        for (i, c) in certs.iter().enumerate() {
            let desc = CertBlobDesc {
                offset: offsets[i] as u32,
                length: c.len() as u32,
            };
            let d = CBLOB_HDR_SIZE + i * CBLOB_DESC_SIZE;
            out.get_mut(d..d + CBLOB_DESC_SIZE)?
                .copy_from_slice(desc.as_bytes());
            out.get_mut(offsets[i]..offsets[i] + c.len())?
                .copy_from_slice(c);
        }
        // Digest trailer [total_size-32 .. total_size) left zeroed.
        Some(total_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_thumb() -> [u8; 32] {
        let mut t = [0u8; 32];
        for (i, b) in t.iter_mut().enumerate() {
            *b = i as u8;
        }
        t
    }

    #[test]
    fn build_parse_roundtrip() {
        let c0 = [0x30u8, 0x03, 0x01, 0x02, 0x03]; // 5 bytes
        let c1 = [0x30u8, 0x01, 0xAA]; // 3 bytes
        let c2 = [0x30u8; 100];
        let thumb = sample_thumb();
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];

        let total = CertBlob::build(&mut buf, &[&c0, &c1, &c2], &thumb).unwrap();
        assert_eq!(total % CBLOB_ALIGN, 0);

        let blob = CertBlob::parse(&buf).unwrap();
        assert_eq!(blob.cert_count(), 3);
        assert_eq!(blob.dev_id_chain_hash(), &thumb);
        assert_eq!(blob.cert_len(0), Some(5));
        assert_eq!(blob.cert_len(1), Some(3));
        assert_eq!(blob.cert_len(2), Some(100));
        assert_eq!(blob.cert_len(3), None);
        assert_eq!(blob.cert_der(0), Some(&c0[..]));
        assert_eq!(blob.cert_der(1), Some(&c1[..]));
        assert_eq!(blob.cert_der(2), Some(&c2[..]));
        assert_eq!(blob.cert_der(3), None);
    }

    #[test]
    fn certs_are_4byte_aligned() {
        let c0 = [0x30u8; 5];
        let c1 = [0x30u8; 7];
        let thumb = sample_thumb();
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        CertBlob::build(&mut buf, &[&c0, &c1], &thumb).unwrap();
        let blob = CertBlob::parse(&buf).unwrap();
        // Read each descriptor's offset and require 4-byte alignment.
        for i in 0..blob.cert_count() {
            let base = CBLOB_HDR_SIZE + i * CBLOB_DESC_SIZE;
            let desc = CertBlobDesc::read_from_bytes(&buf[base..base + CBLOB_DESC_SIZE]).unwrap();
            assert_eq!(desc.offset as usize % CBLOB_ALIGN, 0);
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let c0 = [0x30u8; 8];
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        CertBlob::build(&mut buf, &[&c0], &sample_thumb()).unwrap();
        buf[0] = b'X';
        assert!(CertBlob::parse(&buf).is_none());
    }

    #[test]
    fn rejects_bad_major() {
        let c0 = [0x30u8; 8];
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        CertBlob::build(&mut buf, &[&c0], &sample_thumb()).unwrap();
        buf[0x04] = 0x02; // ver_major = 2
        assert!(CertBlob::parse(&buf).is_none());
    }

    #[test]
    fn rejects_short_region() {
        let buf = [0u8; CBLOB_HDR_SIZE - 1];
        assert!(CertBlob::parse(&buf).is_none());
    }

    #[test]
    fn rejects_zero_and_unpopulated() {
        let buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        assert!(CertBlob::parse(&buf).is_none());
    }

    #[test]
    fn rejects_descriptor_out_of_range() {
        let c0 = [0x30u8; 8];
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        CertBlob::build(&mut buf, &[&c0], &sample_thumb()).unwrap();
        buf[CBLOB_HDR_SIZE + 4..CBLOB_HDR_SIZE + 8].copy_from_slice(&0xFFFFu32.to_le_bytes());
        assert!(CertBlob::parse(&buf).is_none());
    }

    #[test]
    fn rejects_nonzero_reserved() {
        let c0 = [0x30u8; 8];
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        CertBlob::build(&mut buf, &[&c0], &sample_thumb()).unwrap();
        buf[0x0C] = 0x01; // reserved != 0
        assert!(CertBlob::parse(&buf).is_none());
    }

    #[test]
    fn rejects_cert_too_long() {
        let c0 = [0x30u8; 8];
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        CertBlob::build(&mut buf, &[&c0], &sample_thumb()).unwrap();
        let bad = (MAX_DEVID_CERT_LEN as u32) + 1;
        buf[CBLOB_HDR_SIZE + 4..CBLOB_HDR_SIZE + 8].copy_from_slice(&bad.to_le_bytes());
        assert!(CertBlob::parse(&buf).is_none());
    }

    #[test]
    fn rejects_overlapping_descriptors() {
        let c0 = [0x30u8; 64];
        let c1 = [0x30u8; 64];
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        CertBlob::build(&mut buf, &[&c0, &c1], &sample_thumb()).unwrap();
        let d0 =
            CertBlobDesc::read_from_bytes(&buf[CBLOB_HDR_SIZE..CBLOB_HDR_SIZE + CBLOB_DESC_SIZE])
                .unwrap();
        buf[CBLOB_HDR_SIZE + CBLOB_DESC_SIZE..CBLOB_HDR_SIZE + CBLOB_DESC_SIZE + 4]
            .copy_from_slice(&d0.offset.to_le_bytes());
        assert!(CertBlob::parse(&buf).is_none());
    }

    #[test]
    fn build_rejects_too_many() {
        let c = [0x30u8; 4];
        let many: [&[u8]; MAX_DEVID_CERTS + 1] = [&c; MAX_DEVID_CERTS + 1];
        let mut buf = [0u8; DEV_ID_CERT_BLOB_REGION_SIZE];
        assert!(CertBlob::build(&mut buf, &many, &sample_thumb()).is_none());
    }
}
