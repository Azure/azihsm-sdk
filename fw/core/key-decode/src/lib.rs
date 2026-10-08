// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

//! Protocol-neutral decoding of a recovered key into its vault form.
//!
//! Given key material recovered from the wire — a raw AES key, or a
//! DER-encoded RSA / ECC private key — this crate classifies it into its
//! vault kind, converts it into the PAL's vault representation (a no-op for
//! AES, a PAL-defined conversion for RSA / ECC), and derives the wire
//! public key for the asymmetric classes.  *Persisting* the key (the
//! `vault_key_create`) is left to the caller.
//!
//! For RSA / ECC, the crate also picks, from the key's usage, the pairwise
//! consistency test (PCT) that it passes to the PAL's conversion
//! ([`rsa_pct_for`], [`ecc_pct_for`]).
//!
//! The material can come from any source: today the MBOR `RsaUnwrap`
//! handler (after OAEP + AES-KWP unwrap, via `azihsm_fw_hsm_key_unwrap`)
//! and, in future, a `DerKeyImport` handler that receives the DER directly.
//! The crate speaks only [`azihsm_fw_hsm_pal_traits`], so it is reusable
//! across wire protocols and import paths.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEccPct;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmRsaPct;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

mod aes;
mod ecc;
mod hmac;
mod rsa;

/// Class of a recovered key — selects the decode path.
///
/// (`#[non_exhaustive]` so adding classes is not a breaking change.)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum KeyClass {
    /// A raw 16 / 24 / 32-byte AES key.
    Aes,
    /// A DER-encoded RSA private key, stored in the non-CRT vault kind.
    Rsa,
    /// A DER-encoded RSA private key, stored in the CRT vault kind.
    RsaCrt,
    /// A PKCS#8 DER-encoded ECC private key.
    Ecc,
    /// A raw variable-length HMAC-SHA-256 key (`VarLenHmacSha256`).
    HmacSha256,
    /// A raw variable-length HMAC-SHA-384 key (`VarLenHmacSha384`).
    HmacSha384,
    /// A raw variable-length HMAC-SHA-512 key (`VarLenHmacSha512`).
    HmacSha512,
}

/// A decoded key in vault-ready form, for the caller to persist.
///
/// `material` is the key in the PAL's vault representation — hand it to
/// [`vault_key_create`](azihsm_fw_hsm_pal_traits::HsmVault::vault_key_create)
/// with the caller-derived attributes.  `pub_key` is the wire public key
/// for the asymmetric (RSA / ECC) classes (raw `n_le || e_le` for RSA,
/// `x || y` for ECC) and `None` for symmetric (AES) keys.
pub struct DecodedKey<'p> {
    /// Vault kind of the decoded key (e.g. [`HsmVaultKeyKind::Aes256`]).
    pub kind: HsmVaultKeyKind,
    /// The key in the PAL's vault representation, ready for
    /// `vault_key_create`.
    pub material: &'p DmaBuf,
    /// Wire-format public key for asymmetric keys; `None` for symmetric
    /// keys.  Mutable so the caller can frame it into a response slot
    /// without a copy.
    pub pub_key: Option<&'p mut DmaBuf>,
}

/// Decode recovered key material into vault-ready form.
///
/// `material` is the recovered key: a raw AES key (16 / 24 / 32 B), or a
/// DER-encoded RSA / ECC private key.  It is taken by `&mut` so the RSA
/// path can convert it into the vault representation *in place* (avoiding a
/// second large DMA buffer).  Its lifetime `'p` flows into the result for
/// AES (the material itself) and RSA (the in-place converted prefix); the
/// ECC path allocates a fresh converted buffer.
///
/// `attrs` are the attributes the caller stores the key with.  For RSA /
/// ECC, their usage selects the PCT that `decode` passes to the PAL's
/// conversion.
///
/// # Errors
/// - [`HsmError::InvalidArg`](azihsm_fw_hsm_pal_traits::HsmError::InvalidArg)
///   — the AES key is not 16 / 24 / 32 B, or the RSA / ECC DER fails to
///   parse.
/// - Propagated PAL conversion / public-key derivation failures, including
///   a key that the PAL's key assurance rejects.
pub async fn decode<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    material: &'p mut DmaBuf,
    class: KeyClass,
    attrs: HsmVaultKeyAttrs,
) -> HsmResult<DecodedKey<'p>> {
    match class {
        KeyClass::Aes => aes::decode(material),
        KeyClass::Rsa => rsa::decode(pal, io, material, false, rsa_pct_for(attrs)).await,
        KeyClass::RsaCrt => rsa::decode(pal, io, material, true, rsa_pct_for(attrs)).await,
        KeyClass::Ecc => ecc::decode(pal, io, material, ecc_pct_for(attrs)).await,
        KeyClass::HmacSha256 => hmac::decode(material, HsmVaultKeyKind::VarLenHmacSha256),
        KeyClass::HmacSha384 => hmac::decode(material, HsmVaultKeyKind::VarLenHmacSha384),
        KeyClass::HmacSha512 => hmac::decode(material, HsmVaultKeyKind::VarLenHmacSha512),
    }
}

/// Returns the PCT for an ECC key pair with usage `attrs`.
///
/// A signing key gets a sign/verify PCT.  Any other ECC key is a
/// key-agreement key and gets an ECDH PCT.
pub fn ecc_pct_for(attrs: HsmVaultKeyAttrs) -> HsmEccPct {
    if attrs.sign() {
        HsmEccPct::SignVerify
    } else {
        HsmEccPct::KeyAgreement
    }
}

/// Returns the PCT for an RSA key pair with usage `attrs`.
///
/// A signing key gets a sign/verify PCT.  Any other RSA key decrypts or
/// unwraps, and gets an encrypt/decrypt PCT.
pub fn rsa_pct_for(attrs: HsmVaultKeyAttrs) -> HsmRsaPct {
    if attrs.sign() {
        HsmRsaPct::SignVerify
    } else {
        HsmRsaPct::EncryptDecrypt
    }
}
