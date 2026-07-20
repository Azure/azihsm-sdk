// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HMAC-key decode path.
//!
//! Wraps a raw HMAC key into the caller-selected variable-length HMAC
//! vault kind ([`VarLenHmacSha256`](HsmVaultKeyKind::VarLenHmacSha256) /
//! `384` / `512`) and returns the [`DecodedKey`](super::DecodedKey) the
//! caller persists / masks.  HMAC keys are variable-length by
//! construction (any non-empty byte string is a valid key), so the SHA
//! variant is selected by the caller (from the wire key class), **not**
//! inferred from the key length — the vault enforces per-kind length
//! bounds at `vault_key_create`.  The raw key is itself the vault
//! material.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::DecodedKey;

/// Wrap a raw HMAC key into the caller-selected variable-length HMAC
/// vault `kind`.
///
/// `kind` must be one of the `VarLenHmacSha*` kinds (chosen from the wire
/// key class); any other kind is a caller contract violation. The key
/// material is passed through verbatim — its length is validated against
/// the kind's bounds later, by `vault_key_create`.
pub(super) fn decode(material: &DmaBuf, kind: HsmVaultKeyKind) -> HsmResult<DecodedKey<'_>> {
    match kind {
        HsmVaultKeyKind::VarLenHmacSha256
        | HsmVaultKeyKind::VarLenHmacSha384
        | HsmVaultKeyKind::VarLenHmacSha512 => {}
        _ => return Err(HsmError::InvalidArg),
    }

    // An HMAC key must be non-empty; the vault enforces the per-kind
    // maximum at create time.
    if material.is_empty() {
        return Err(HsmError::InvalidArg);
    }

    // Symmetric — no public key.
    Ok(DecodedKey {
        kind,
        material,
        pub_key: None,
    })
}
