// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_uno_error::HsmResult;

use crate::UpkaEccCurve;
use crate::UpkaError;
use crate::UpkaRsaKeyType;

pub(crate) const ECC_VERIFY_256: u32 = 0x1000_0000;
pub(crate) const ECC_VERIFY_384: u32 = 0x1000_0001;
pub(crate) const ECC_VERIFY_521: u32 = 0x1000_0008;
pub(crate) const ECC_SIGN_256: u32 = 0x1001_0000;
pub(crate) const ECC_SIGN_384: u32 = 0x1001_0001;
pub(crate) const ECC_SIGN_521: u32 = 0x1001_0008;
pub(crate) const ECC_POINT_MUL_256: u32 = 0x1002_0000;
pub(crate) const ECC_POINT_MUL_384: u32 = 0x1002_0001;
pub(crate) const ECC_POINT_MUL_521: u32 = 0x1002_0008;
pub(crate) const ECC_POINT_VALIDATE_256: u32 = 0x1005_0000;
pub(crate) const ECC_POINT_VALIDATE_384: u32 = 0x1005_0001;
pub(crate) const ECC_POINT_VALIDATE_521: u32 = 0x1005_0008;
pub(crate) const ECC_KEY_GEN_256: u32 = 0x1006_0000;
pub(crate) const ECC_KEY_GEN_384: u32 = 0x1006_0001;
pub(crate) const ECC_KEY_GEN_521: u32 = 0x1006_0008;
pub(crate) const MONT_CONST_CALC_256: u32 = 0x500c_0000;
pub(crate) const MONT_CONST_CALC_384: u32 = 0x500c_0001;
pub(crate) const MONT_CONST_CALC_521: u32 = 0x500c_0008;
pub(crate) const RSA_PRIV_2K: u32 = 0x5000_0003;
pub(crate) const RSA_PRIV_3K: u32 = 0x5000_0004;
pub(crate) const RSA_PRIV_4K: u32 = 0x5000_0005;
pub(crate) const RSA_PUB_2K: u32 = 0x5001_0003;
pub(crate) const RSA_PUB_3K: u32 = 0x5001_0004;
pub(crate) const RSA_PUB_4K: u32 = 0x5001_0005;
pub(crate) const RSA_CRT_2K: u32 = 0x500E_0003;
pub(crate) const RSA_CRT_3K: u32 = 0x500E_0004;
pub(crate) const RSA_CRT_4K: u32 = 0x500E_0005;
pub(crate) const UPKA_MEM_WIPE: u32 = 0x500F_0000;

const RSA_OPCODES: [(u32, u32, u32); 3] = [
    (RSA_PRIV_2K, RSA_PUB_2K, RSA_CRT_2K),
    (RSA_PRIV_3K, RSA_PUB_3K, RSA_CRT_3K),
    (RSA_PRIV_4K, RSA_PUB_4K, RSA_CRT_4K),
];

/// Map raw PKA status flags into the driver error model.
///
/// # Parameters
///
/// - `status`: Raw completion/error status bits captured from hardware.
///
/// # Returns
///
/// - `Ok(())`: Success bit is set.
/// - `Err(UpkaError::CMD_ERROR)`: Command decode error bit is set.
/// - `Err(UpkaError::BUS_ERROR)`: Bus error bit is set.
/// - `Err(UpkaError::FAULT_ERROR)`: Fault bit is set or no known bit is set.
pub(crate) fn map_status(status: u8) -> HsmResult<()> {
    if status & (1 << 1) != 0 {
        return Ok(());
    }
    if status & (1 << 2) != 0 {
        return Err(UpkaError::CMD_ERROR);
    }
    if status & (1 << 3) != 0 {
        return Err(UpkaError::BUS_ERROR);
    }
    if status & (1 << 4) != 0 {
        return Err(UpkaError::FAULT_ERROR);
    }
    Err(UpkaError::FAULT_ERROR)
}

/// Return the ECC sign opcode for the selected curve.
///
/// # Parameters
///
/// - `curve`: ECC curve selector.
///
/// # Returns
///
/// - Hardware opcode for ECDSA sign.
pub(crate) fn ecc_sign_opcode(curve: UpkaEccCurve) -> u32 {
    match curve {
        UpkaEccCurve::P256 => ECC_SIGN_256,
        UpkaEccCurve::P384 => ECC_SIGN_384,
        UpkaEccCurve::P521 => ECC_SIGN_521,
    }
}

/// Return the ECC verify opcode for the selected curve.
///
/// # Parameters
///
/// - `curve`: ECC curve selector.
///
/// # Returns
///
/// - Hardware opcode for ECDSA verify.
pub(crate) fn ecc_verify_opcode(curve: UpkaEccCurve) -> u32 {
    match curve {
        UpkaEccCurve::P256 => ECC_VERIFY_256,
        UpkaEccCurve::P384 => ECC_VERIFY_384,
        UpkaEccCurve::P521 => ECC_VERIFY_521,
    }
}

/// Return the ECC key-generation opcode for the selected curve.
///
/// # Parameters
///
/// - `curve`: ECC curve selector.
///
/// # Returns
///
/// - Hardware opcode for ECC key generation.
pub(crate) fn ecc_key_gen_opcode(curve: UpkaEccCurve) -> u32 {
    match curve {
        UpkaEccCurve::P256 => ECC_KEY_GEN_256,
        UpkaEccCurve::P384 => ECC_KEY_GEN_384,
        UpkaEccCurve::P521 => ECC_KEY_GEN_521,
    }
}

/// Return the Montgomery-constant-calculation opcode for the selected curve.
///
/// The PKA engine requires a per-call `mont_const_calc(curve_prime)` before an
/// ECC point-multiplication / verify; it leaves engine state that the subsequent
/// command consumes (same engine acquisition).
pub(crate) fn mont_const_calc_opcode(curve: UpkaEccCurve) -> u32 {
    match curve {
        UpkaEccCurve::P256 => MONT_CONST_CALC_256,
        UpkaEccCurve::P384 => MONT_CONST_CALC_384,
        UpkaEccCurve::P521 => MONT_CONST_CALC_521,
    }
}

/// Return the ECC point-multiplication opcode for the selected curve.
///
/// # Parameters
///
/// - `curve`: ECC curve selector.
///
/// # Returns
///
/// - Hardware opcode for point multiplication.
pub(crate) fn ecc_point_mul_opcode(curve: UpkaEccCurve) -> u32 {
    match curve {
        UpkaEccCurve::P256 => ECC_POINT_MUL_256,
        UpkaEccCurve::P384 => ECC_POINT_MUL_384,
        UpkaEccCurve::P521 => ECC_POINT_MUL_521,
    }
}

/// Return the ECC point-validation opcode for the selected curve.
///
/// # Parameters
///
/// - `curve`: ECC curve selector.
///
/// # Returns
///
/// - Hardware opcode for point validation.
pub(crate) fn ecc_point_validate_opcode(curve: UpkaEccCurve) -> u32 {
    match curve {
        UpkaEccCurve::P256 => ECC_POINT_VALIDATE_256,
        UpkaEccCurve::P384 => ECC_POINT_VALIDATE_384,
        UpkaEccCurve::P521 => ECC_POINT_VALIDATE_521,
    }
}

/// Return the digest size expected by the selected ECC curve.
///
/// # Parameters
///
/// - `curve`: ECC curve selector.
///
/// # Returns
///
/// - Digest size in bytes.
pub fn hash_size(curve: UpkaEccCurve) -> usize {
    match curve {
        UpkaEccCurve::P256 => 32,
        UpkaEccCurve::P384 => 48,
        UpkaEccCurve::P521 => 64,
    }
}

/// Return the affine point coordinate size for the selected ECC curve.
///
/// # Parameters
///
/// - `curve`: ECC curve selector.
///
/// # Returns
///
/// - Affine coordinate size in bytes.
pub(crate) fn point_size(curve: UpkaEccCurve) -> usize {
    match curve {
        UpkaEccCurve::P256 => 32,
        UpkaEccCurve::P384 => 48,
        UpkaEccCurve::P521 => 66,
    }
}

/// Return the HSM wire-format coordinate size for the selected ECC curve.
///
/// # Parameters
///
/// - `curve`: ECC curve selector.
///
/// # Returns
///
/// - Coordinate width in bytes expected by HSM wire format.
///   - P256: 32
///   - P384: 48
///   - P521: 68
pub const fn hsm_point_size(curve: UpkaEccCurve) -> usize {
    match curve {
        UpkaEccCurve::P256 => 32,
        UpkaEccCurve::P384 => 48,
        UpkaEccCurve::P521 => 68,
    }
}

/// Return the encoded signature size for the selected ECC curve.
///
/// # Parameters
///
/// - `curve`: ECC curve selector.
///
/// # Returns
///
/// - Signature size in bytes (`2 * point_size(curve)`).
pub(crate) fn signature_size(curve: UpkaEccCurve) -> usize {
    point_size(curve) * 2
}

fn rsa_opcode_index(key_type: UpkaRsaKeyType) -> usize {
    match key_type {
        UpkaRsaKeyType::Rsa2048 | UpkaRsaKeyType::Rsa2048Crt => 0,
        UpkaRsaKeyType::Rsa3072 | UpkaRsaKeyType::Rsa3072Crt => 1,
        UpkaRsaKeyType::Rsa4096 | UpkaRsaKeyType::Rsa4096Crt => 2,
    }
}

/// Return the RSA private-key exponentiation opcode for the selected key type.
///
/// # Parameters
///
/// - `key_type`: RSA key type selector.
///
/// # Returns
///
/// - Hardware opcode for RSA private exponentiation (CRT or standard).
pub(crate) fn rsa_priv_opcode(key_type: UpkaRsaKeyType) -> u32 {
    let index = rsa_opcode_index(key_type);
    let is_crt = matches!(
        key_type,
        UpkaRsaKeyType::Rsa2048Crt | UpkaRsaKeyType::Rsa3072Crt | UpkaRsaKeyType::Rsa4096Crt
    );
    if is_crt {
        RSA_OPCODES[index].2
    } else {
        RSA_OPCODES[index].0
    }
}

/// Return the RSA public-key exponentiation opcode for the selected key type.
///
/// # Parameters
///
/// - `key_type`: RSA key type selector.
///
/// # Returns
///
/// - Hardware opcode for RSA public exponentiation.
pub(crate) fn rsa_pub_opcode(key_type: UpkaRsaKeyType) -> u32 {
    let index = rsa_opcode_index(key_type);
    RSA_OPCODES[index].1
}

/// Return the modulus size in bytes for the selected RSA key type.
///
/// # Parameters
///
/// - `key_type`: RSA key type selector.
///
/// # Returns
///
/// - Modulus size in bytes.
pub(crate) fn rsa_mod_size(key_type: UpkaRsaKeyType) -> usize {
    match key_type {
        UpkaRsaKeyType::Rsa2048 | UpkaRsaKeyType::Rsa2048Crt => 256,
        UpkaRsaKeyType::Rsa3072 | UpkaRsaKeyType::Rsa3072Crt => 384,
        UpkaRsaKeyType::Rsa4096 | UpkaRsaKeyType::Rsa4096Crt => 512,
    }
}
