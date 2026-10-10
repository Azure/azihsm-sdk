// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-built PKCS#8 private keys for import tests, including malformed
//! encodings that the firmware must reject.

use azihsm_crypto::EccCurve;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::ExportableHsmKey;
use azihsm_crypto::ExportableHsmRsaKey;
use azihsm_crypto::Key;
use azihsm_crypto::KeyGenerationOp;
use azihsm_crypto::PrivateKey;
use azihsm_crypto::RsaPrivateKey;

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// A DER tag-length-value with a definite length, for bodies up to 64 KiB.
pub fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match body.len() {
        len @ 0..=0x7F => out.push(len as u8),
        len @ 0x80..=0xFF => out.extend([0x81, len as u8]),
        len => out.extend([0x82, (len >> 8) as u8, len as u8]),
    }
    out.extend_from_slice(body);
    out
}

/// A DER INTEGER for an unsigned big-endian value.
pub fn der_uint(be: &[u8]) -> Vec<u8> {
    let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let mut body = Vec::new();
    if be[first] & 0x80 != 0 {
        body.push(0);
    }
    body.extend_from_slice(&be[first..]);
    der_tlv(0x02, &body)
}

/// Adds 2 to a big-endian value, keeping its width and parity.
pub fn plus_two(be: &[u8]) -> Vec<u8> {
    let mut out = be.to_vec();
    let mut carry = 2u16;
    for byte in out.iter_mut().rev() {
        let sum = *byte as u16 + carry;
        *byte = sum as u8;
        carry = sum >> 8;
        if carry == 0 {
            break;
        }
    }
    out
}

/// An ECC curve's parameters for building test keys.
#[derive(Clone, Copy, Debug)]
pub struct EccTestCurve {
    /// The curve, for host key generation.
    pub host: EccCurve,
    /// The length of the private value and of each coordinate, in bytes.
    pub raw: usize,
    /// The length of each coordinate in the device's wire format, in bytes.
    pub wire_coord: usize,
    /// The DER contents of the curve's `namedCurve` OID.
    pub oid: &'static [u8],
    /// The curve order `n`, big-endian and `raw` bytes long.
    pub order: &'static [u8],
}

/// NIST P-256.
pub const ECC_TEST_P256: EccTestCurve = EccTestCurve {
    host: EccCurve::P256,
    raw: 32,
    wire_coord: 32,
    oid: &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
    order: &[
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ],
};

/// NIST P-384.
pub const ECC_TEST_P384: EccTestCurve = EccTestCurve {
    host: EccCurve::P384,
    raw: 48,
    wire_coord: 48,
    oid: &[0x2b, 0x81, 0x04, 0x00, 0x22],
    order: &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37,
        0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc,
        0xc5, 0x29, 0x73,
    ],
};

/// NIST P-521. Its wire coordinates are padded from 66 to 68 bytes.
pub const ECC_TEST_P521: EccTestCurve = EccTestCurve {
    host: EccCurve::P521,
    raw: 66,
    wire_coord: 68,
    oid: &[0x2b, 0x81, 0x04, 0x00, 0x23],
    order: &[
        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01,
        0x48, 0xf7, 0x09, 0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f,
        0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09,
    ],
};

/// A PKCS#8 `PrivateKeyInfo` that wraps a SEC1 `ECPrivateKey` holding the
/// big-endian private value `d_be`. With `params`, the `ECPrivateKey` also
/// carries `[0]` curve parameters; with `point`, it carries that exact
/// `[1] publicKey` encoding.
pub fn ecc_pkcs8(curve_oid: &[u8], d_be: &[u8], params: bool, point: Option<&[u8]>) -> Vec<u8> {
    let mut ec = der_tlv(0x02, &[1]);
    ec.extend(der_tlv(0x04, d_be));
    if params {
        ec.extend(der_tlv(0xA0, &der_tlv(0x06, curve_oid)));
    }
    if let Some(point) = point {
        let mut bits = vec![0u8];
        bits.extend_from_slice(point);
        ec.extend(der_tlv(0xA1, &der_tlv(0x03, &bits)));
    }
    let algorithm = [der_tlv(0x06, OID_EC_PUBLIC_KEY), der_tlv(0x06, curve_oid)].concat();
    private_key_info(&algorithm, &ec)
}

/// A PKCS#8 `PrivateKeyInfo` (version 0) from the DER contents of its
/// `AlgorithmIdentifier` and of the private key's SEQUENCE.
fn private_key_info(algorithm: &[u8], private_key: &[u8]) -> Vec<u8> {
    let info = [
        der_tlv(0x02, &[0]),
        der_tlv(0x30, algorithm),
        der_tlv(0x04, &der_tlv(0x30, private_key)),
    ]
    .concat();
    der_tlv(0x30, &info)
}

/// A host-generated ECC key: its private value and coordinates, big-endian,
/// each `curve.raw` bytes.
pub struct HostEcc {
    pub curve: EccTestCurve,
    pub d: Vec<u8>,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

impl HostEcc {
    /// Generates a key on `curve`.
    pub fn generate(curve: EccTestCurve) -> Self {
        let key = EccPrivateKey::from_curve(curve.host).expect("generate host ECC key");
        let scalar = key.to_hsm_bytes_vec().expect("ECC scalar export");
        let d = scalar[scalar.len() - curve.raw..].to_vec();
        // The HSM public bytes are `x ‖ y`, each big-endian and left-padded
        // to the same length.
        let point = key
            .public_key()
            .expect("host public key")
            .to_hsm_bytes_vec()
            .expect("host public key export");
        let coord = point.len() / 2;
        let (xp, yp) = point.split_at(coord);
        let x = xp[coord - curve.raw..].to_vec();
        let y = yp[coord - curve.raw..].to_vec();
        Self { curve, d, x, y }
    }

    /// `marker ‖ X ‖ Y`; `04` is the valid uncompressed form.
    pub fn point(&self, marker: u8) -> Vec<u8> {
        [vec![marker], self.x.clone(), self.y.clone()].concat()
    }

    /// `marker ‖ X`, a compressed point.
    pub fn compressed(&self, marker: u8) -> Vec<u8> {
        [vec![marker], self.x.clone()].concat()
    }

    /// A valid PKCS#8 encoding that carries the uncompressed public key.
    pub fn pkcs8(&self) -> Vec<u8> {
        ecc_pkcs8(self.curve.oid, &self.d, false, Some(&self.point(0x04)))
    }

    /// The device's public key for this key: each coordinate little-endian,
    /// padded to the curve's wire coordinate length.
    pub fn wire_pub(&self) -> Vec<u8> {
        let coord = self.curve.wire_coord;
        let mut out = vec![0u8; 2 * coord];
        for (i, b) in self.x.iter().rev().enumerate() {
            out[i] = *b;
        }
        for (i, b) in self.y.iter().rev().enumerate() {
            out[coord + i] = *b;
        }
        out
    }
}

/// RSA private key components, big-endian.
#[derive(Clone)]
pub struct RsaParts {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub d: Vec<u8>,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub dp: Vec<u8>,
    pub dq: Vec<u8>,
    pub qinv: Vec<u8>,
}

impl RsaParts {
    /// Splits `key`'s CRT HSM layout `n ‖ e(4) ‖ d ‖ p ‖ q ‖ dp ‖ dq ‖ qinv`.
    pub fn from_key(key: &RsaPrivateKey) -> Self {
        let k = key.size();
        let raw = key.to_hsm_crt_bytes_vec().expect("CRT export");
        let h = k / 2;
        let mut at = 0;
        let mut take = |len: usize| {
            let part = raw[at..at + len].to_vec();
            at += len;
            part
        };
        Self {
            n: take(k),
            e: take(4),
            d: take(k),
            p: take(h),
            q: take(h),
            dp: take(h),
            dq: take(h),
            qinv: take(h),
        }
    }

    /// Generates a `k`-byte key and splits it.
    pub fn generate(k: usize) -> Self {
        Self::from_key(&RsaPrivateKey::generate(k).expect("generate host RSA key"))
    }

    /// A PKCS#8 `PrivateKeyInfo` that wraps a PKCS#1 `RSAPrivateKey`.
    pub fn pkcs8(&self) -> Vec<u8> {
        let fields = [
            der_tlv(0x02, &[0]),
            der_uint(&self.n),
            der_uint(&self.e),
            der_uint(&self.d),
            der_uint(&self.p),
            der_uint(&self.q),
            der_uint(&self.dp),
            der_uint(&self.dq),
            der_uint(&self.qinv),
        ]
        .concat();
        let algorithm = [der_tlv(0x06, OID_RSA_ENCRYPTION), der_tlv(0x05, &[])].concat();
        private_key_info(&algorithm, &fields)
    }

    /// The PKCS#8 encoding of a copy that `corrupt` changes.
    pub fn with(&self, corrupt: impl Fn(&mut Self)) -> Vec<u8> {
        let mut bad = self.clone();
        corrupt(&mut bad);
        bad.pkcs8()
    }

    /// The device's RSA public key for these parts: `n_le ‖ e_le(4)`.
    pub fn wire_pub(&self) -> Vec<u8> {
        let mut out: Vec<u8> = self.n.iter().rev().copied().collect();
        out.extend(self.e.iter().rev());
        out
    }
}
