// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA private-key decode path.
//!
//! Converts a DER-encoded RSA private key into the PAL's vault
//! representation, classifies it by modulus size and the requested CRT
//! variant, derives its wire public key, and returns the
//! [`DecodedKey`](super::DecodedKey) the caller persists.
//!
//! The crate is `no_std` and cannot parse DER, so the parse + conversion +
//! modulus classification is delegated to the PAL via
//! [`HsmRsa::rsa_priv_der_to_vault`](azihsm_fw_hsm_pal_traits::HsmRsa::rsa_priv_der_to_vault).
//! The vault representation is PAL-defined and depends on `crt`: real
//! hardware uses its own raw non-CRT / custom CRT layouts, while the
//! std/OpenSSL PAL uses the crypto crate's fixed-size HSM byte layout.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::DecodedKey;

/// Convert a DER-encoded RSA private key into the vault representation
/// (in place) and derive its wire public key.  `crt` selects the CRT vault
/// kind (and, on real hardware, the CRT vault layout).
pub(super) async fn decode<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    material: &'p mut DmaBuf,
    crt: bool,
) -> HsmResult<DecodedKey<'p>> {
    // Convert the recovered DER into the PAL's vault representation in place
    // and classify it by modulus size (the PAL parses the DER — the crate
    // cannot).  In place avoids duplicating the large RSA material: the PAL
    // rewrites `material` into its `crt`-dependent vault layout, which is
    // smaller than the source DER.
    let (vault_len, modulus_len) = pal.rsa_priv_der_to_vault(io, material, crt)?;
    // Done mutating — reborrow the converted prefix as the shared vault key.
    let material: &'p DmaBuf = material;
    let vault = &material[..vault_len];

    let kind = vault_kind(modulus_len, crt)?;

    // Derive the wire public key (`n_le || e_le`) from the vault-format
    // private key, following the PAL's query/alloc/use convention.
    let pub_len = pal.rsa_priv_pub_key(io, vault, None)?;
    let pub_key = pal.dma_alloc(io, pub_len)?;
    pal.rsa_priv_pub_key(io, vault, Some(&mut *pub_key))?;

    Ok(DecodedKey {
        kind,
        material: vault,
        pub_key: Some(pub_key),
    })
}

/// Map an RSA modulus length (bytes) and CRT flag to the vault key kind.
fn vault_kind(modulus_len: usize, crt: bool) -> HsmResult<HsmVaultKeyKind> {
    Ok(match (modulus_len, crt) {
        (256, false) => HsmVaultKeyKind::Rsa2kPrivate,
        (384, false) => HsmVaultKeyKind::Rsa3kPrivate,
        (512, false) => HsmVaultKeyKind::Rsa4kPrivate,
        (256, true) => HsmVaultKeyKind::Rsa2kPrivateCrt,
        (384, true) => HsmVaultKeyKind::Rsa3kPrivateCrt,
        (512, true) => HsmVaultKeyKind::Rsa4kPrivateCrt,
        _ => return Err(HsmError::InvalidArg),
    })
}
