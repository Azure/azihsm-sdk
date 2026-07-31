// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE_Key encoding for the attested public key (RFC 9052 §7).
//!
//! Dispatches on the attested key type:
//! * ECC  → EC2 `COSE_Key` map `{ 1: 2, -1: crv, -2: x, -3: y }`.
//! * RSA  → RSA `COSE_Key` map `{ 1: 3, -1: n, -2: e }`.
//! * Symmetric → no public component (empty; `public_key_size == 0`).
//!
//! Coordinates / modulus / exponent are big-endian raw bytes, matching
//! the reference `~/mcr-hsm` builder.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use minicbor::Decoder;
use minicbor::Encoder;

use crate::consts::RSA_EXPONENT_MAX_LEN;
use crate::consts::RSA_MODULUS_MAX_LEN;
use crate::decode::bytes_span;
use crate::decode::map_decode_err;

// COSE key-type and key-type-parameter identifiers (IANA COSE registry).
const COSE_KTY: u8 = 1;
const COSE_KTY_EC2: u8 = 2;
const COSE_KTY_RSA: u8 = 3;
const COSE_EC2_CRV: i8 = -1;
const COSE_EC2_X: i8 = -2;
const COSE_EC2_Y: i8 = -3;
const COSE_RSA_N: i8 = -1;
const COSE_RSA_E: i8 = -2;

// COSE elliptic-curve identifiers (RFC 9053 Table 18).
const COSE_CRV_P256: i8 = 1;
const COSE_CRV_P384: i8 = 2;
const COSE_CRV_P521: i8 = 3;

/// Public-key material for the attested key.
///
/// All byte buffers are big-endian raw values.
pub enum AttestedPubKey<'a> {
    /// ECC public key; `x` / `y` are big-endian affine coordinates,
    /// each `curve.priv_key_len()` bytes.
    Ecc {
        /// NIST curve the key is on.
        curve: HsmEccCurve,
        /// Big-endian X coordinate.
        x: &'a DmaBuf,
        /// Big-endian Y coordinate.
        y: &'a DmaBuf,
    },
    /// RSA public key; `n` / `e` are big-endian.
    Rsa {
        /// Big-endian modulus.
        n: &'a DmaBuf,
        /// Big-endian public exponent.
        e: &'a DmaBuf,
    },
    /// Symmetric key — no public component (empty COSE_Key).
    Symmetric,
}

impl AttestedPubKey<'_> {
    /// Validate the key material's field lengths.
    pub(crate) fn validate(&self) -> HsmResult<()> {
        match self {
            AttestedPubKey::Ecc { curve, x, y } => {
                let coord = curve.priv_key_len();
                if x.len() != coord || y.len() != coord {
                    return Err(HsmError::InvalidArg);
                }
            }
            AttestedPubKey::Rsa { n, e } => {
                if n.is_empty() || e.is_empty() {
                    return Err(HsmError::InvalidArg);
                }
                // The fixed 525-byte `public_key` field only holds a
                // COSE_Key up to a 4096-bit modulus / 4-byte exponent;
                // reject oversized material here (InvalidArg) rather
                // than letting COSE encoding overflow into InternalError.
                if n.len() > RSA_MODULUS_MAX_LEN || e.len() > RSA_EXPONENT_MAX_LEN {
                    return Err(HsmError::InvalidArg);
                }
            }
            AttestedPubKey::Symmetric => {}
        }
        Ok(())
    }
}

fn cose_crv(curve: HsmEccCurve) -> i8 {
    match curve {
        HsmEccCurve::P256 => COSE_CRV_P256,
        HsmEccCurve::P384 => COSE_CRV_P384,
        HsmEccCurve::P521 => COSE_CRV_P521,
    }
}

fn map_encode_err<T, E>(result: Result<T, E>) -> HsmResult<T> {
    result.map_err(|_| HsmError::InternalError)
}

fn encode_ecc_key(
    enc: &mut Encoder<&mut [u8]>,
    curve: HsmEccCurve,
    x: &[u8],
    y: &[u8],
) -> HsmResult<()> {
    map_encode_err(enc.map(4))?;
    map_encode_err(enc.u8(COSE_KTY))?;
    map_encode_err(enc.u8(COSE_KTY_EC2))?;
    map_encode_err(enc.i8(COSE_EC2_CRV))?;
    map_encode_err(enc.i8(cose_crv(curve)))?;
    map_encode_err(enc.i8(COSE_EC2_X))?;
    map_encode_err(enc.bytes(x))?;
    map_encode_err(enc.i8(COSE_EC2_Y))?;
    map_encode_err(enc.bytes(y))?;
    Ok(())
}

fn encode_rsa_key(enc: &mut Encoder<&mut [u8]>, n: &[u8], e: &[u8]) -> HsmResult<()> {
    map_encode_err(enc.map(3))?;
    map_encode_err(enc.u8(COSE_KTY))?;
    map_encode_err(enc.u8(COSE_KTY_RSA))?;
    map_encode_err(enc.i8(COSE_RSA_N))?;
    map_encode_err(enc.bytes(n))?;
    map_encode_err(enc.i8(COSE_RSA_E))?;
    map_encode_err(enc.bytes(e))?;
    Ok(())
}

/// Encode `key` as a COSE_Key map into `out`, returning the number of
/// bytes written. A symmetric key writes nothing and returns `0`.
///
/// # Errors
/// * [`HsmError::InternalError`] — CBOR encoding failed (e.g. `out` is
///   too small to hold the COSE_Key).
pub(crate) fn to_cose_key(key: &AttestedPubKey<'_>, out: &mut [u8]) -> HsmResult<usize> {
    let out_len = out.len();
    let mut enc = Encoder::new(out);

    match key {
        AttestedPubKey::Symmetric => return Ok(0),
        AttestedPubKey::Ecc { curve, x, y } => {
            encode_ecc_key(&mut enc, *curve, x, y)?;
        }
        AttestedPubKey::Rsa { n, e } => {
            encode_rsa_key(&mut enc, n, e)?;
        }
    }

    // The encoder writes into `out` and advances a cursor; the number
    // of bytes consumed is the original length minus what remains.
    Ok(out_len - enc.writer().len())
}

/// Map a COSE elliptic-curve identifier back to its [`HsmEccCurve`].
fn curve_from_cose_crv(crv: i8) -> HsmResult<HsmEccCurve> {
    match crv {
        COSE_CRV_P256 => Ok(HsmEccCurve::P256),
        COSE_CRV_P384 => Ok(HsmEccCurve::P384),
        COSE_CRV_P521 => Ok(HsmEccCurve::P521),
        _ => Err(HsmError::InvalidArg),
    }
}

/// A parsed EC2 `COSE_Key`: the curve plus zero-copy big-endian affine
/// coordinates borrowing from the input buffer.
pub struct Ec2CoseKey<'a> {
    /// NIST curve the key is on.
    pub curve: HsmEccCurve,
    /// Big-endian X coordinate (`curve.priv_key_len()` bytes).
    pub x: &'a DmaBuf,
    /// Big-endian Y coordinate (`curve.priv_key_len()` bytes).
    pub y: &'a DmaBuf,
}

/// Decode an EC2 `COSE_Key` map `{ 1: 2, -1: crv, -2: x, -3: y }`
/// (RFC 9052 §7), returning a zero-copy [`Ec2CoseKey`] borrowing the
/// coordinates from `cose_key`. This is the inverse of the encoder's EC2
/// branch (see `to_cose_key`).
///
/// It is **no-panic** across the trust boundary: every malformed input
/// (wrong map arity, unknown / duplicate label, non-EC2 key type, unknown
/// curve, wrong coordinate length, or trailing bytes) returns
/// [`HsmError::InvalidArg`].
///
/// Only the four canonical EC2 labels are accepted, each exactly once;
/// the coordinate lengths must equal the curve's field size.
pub fn parse_ec2_cose_key(cose_key: &DmaBuf) -> HsmResult<Ec2CoseKey<'_>> {
    let mut kty_seen = false;
    let mut crv: Option<i8> = None;
    let mut x_span: Option<(usize, usize)> = None;
    let mut y_span: Option<(usize, usize)> = None;

    {
        let mut d = Decoder::new(cose_key);
        if map_decode_err(d.map())? != Some(4) {
            return Err(HsmError::InvalidArg);
        }
        for _ in 0..4 {
            // All four labels (1, -1, -2, -3) fit in an `i8`.
            match map_decode_err(d.i8())? {
                k if k == COSE_KTY as i8 => {
                    if kty_seen {
                        return Err(HsmError::InvalidArg);
                    }
                    kty_seen = true;
                    if map_decode_err(d.u8())? != COSE_KTY_EC2 {
                        return Err(HsmError::InvalidArg);
                    }
                }
                COSE_EC2_CRV => {
                    if crv.is_some() {
                        return Err(HsmError::InvalidArg);
                    }
                    crv = Some(map_decode_err(d.i8())?);
                }
                COSE_EC2_X => {
                    if x_span.is_some() {
                        return Err(HsmError::InvalidArg);
                    }
                    x_span = Some(bytes_span(&mut d)?);
                }
                COSE_EC2_Y => {
                    if y_span.is_some() {
                        return Err(HsmError::InvalidArg);
                    }
                    y_span = Some(bytes_span(&mut d)?);
                }
                _ => return Err(HsmError::InvalidArg),
            }
        }
        // Reject trailing bytes after the COSE_Key map.
        if d.position() != cose_key.len() {
            return Err(HsmError::InvalidArg);
        }
    }

    if !kty_seen {
        return Err(HsmError::InvalidArg);
    }
    let curve = curve_from_cose_crv(crv.ok_or(HsmError::InvalidArg)?)?;
    let (x0, x1) = x_span.ok_or(HsmError::InvalidArg)?;
    let (y0, y1) = y_span.ok_or(HsmError::InvalidArg)?;

    // Coordinates must be exactly the curve's field size (big-endian, no
    // leading-zero trimming) so `x ‖ y` forms a valid uncompressed point.
    let coord = curve.priv_key_len();
    if x1 - x0 != coord || y1 - y0 != coord {
        return Err(HsmError::InvalidArg);
    }

    Ok(Ec2CoseKey {
        curve,
        x: &cose_key[x0..x1],
        y: &cose_key[y0..y1],
    })
}
