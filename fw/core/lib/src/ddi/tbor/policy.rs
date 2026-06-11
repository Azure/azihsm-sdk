// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Firmware-side parser for the partition policy ([`PartPolicy`]).
//!
//! The canonical byte layout — structs, derives, layout asserts — is
//! defined in [`azihsm_fw_ddi_tbor_types::policy`].  That crate must
//! stay free of firmware deps (`DmaBuf`, `HsmError`), so the
//! validation/parser surface that consumes those primitives lives
//! here as a thin free function over the canonical type.
//!
//! Validation rules (any failure returns [`HsmError::InvalidArg`]):
//!
//! * Buffer length equals [`PART_POLICY_LEN`].
//! * `try_ref_from_bytes` succeeds — automatically rejects any
//!   non-canonical `bool` byte in `include_fmc_cdi` (needed for
//!   canonical hashing into `PartPolicyHash`).
//! * `version.major == POLICY_VERSION_MAJOR`; any `version.minor`
//!   accepted (forward-compat).
//! * `pota_pub_key.kind` decodes to a known [`PolicyKeyKind`].
//! * For [`PolicyKeyKind::Ecc384`]:
//!   `pota_pub_key.len == POLICY_MAX_KEY_LEN` and
//!   `pota_pub_key.data[0] == 0x04` (SEC1 uncompressed point tag).
//!
//! `info` is opaque caller payload and is not validated.

use azihsm_fw_ddi_tbor_types::policy::PartPolicy;
use azihsm_fw_ddi_tbor_types::policy::PolicyKeyKind;
use azihsm_fw_ddi_tbor_types::policy::PART_POLICY_LEN;
use azihsm_fw_ddi_tbor_types::policy::POLICY_MAX_KEY_LEN;
use azihsm_fw_ddi_tbor_types::policy::POLICY_VERSION_MAJOR;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use zerocopy::TryFromBytes;

// Compile-time pin: the `PART_POLICY_LEN` re-exported from
// `azihsm_fw_hsm_pal_traits` (which has no dependency on
// `azihsm_fw_ddi_tbor_types`) must match the canonical
// `azihsm_fw_ddi_tbor_types::policy::PART_POLICY_LEN` byte for byte;
// a mismatch would surface as a runtime `InvalidArg` from
// `HsmPartitionManager::part_set_policy`.
const _: () = assert!(azihsm_fw_hsm_pal_traits::PART_POLICY_LEN == PART_POLICY_LEN);

/// First byte of an uncompressed SEC1 ECC point.
const ECC_UNCOMPRESSED_POINT_TAG: u8 = 0x04;

/// Active prefix length of `PolicyPubKey::data` when `kind` decodes
/// to [`PolicyKeyKind::Ecc384`].
const ECC384_KEY_LEN: usize = POLICY_MAX_KEY_LEN;

/// Parse and validate a [`PART_POLICY_LEN`]-byte `PartPolicy`
/// resident in DMA-eligible memory.
///
/// Zero-copy: the returned reference aliases `buf` (lifetime tied to
/// the caller's [`DmaBuf`]).  Downstream code that needs the raw
/// bytes for hashing or persistence keeps the original `&DmaBuf` and
/// threads it into the next DMA primitive.
pub fn from_bytes(buf: &DmaBuf) -> HsmResult<&PartPolicy> {
    if buf.len() != PART_POLICY_LEN {
        return Err(HsmError::InvalidArg);
    }

    let this = PartPolicy::try_ref_from_bytes(buf).map_err(|_| HsmError::InvalidArg)?;

    if this.version.major != POLICY_VERSION_MAJOR {
        return Err(HsmError::InvalidArg);
    }

    let kind = PolicyKeyKind(u16::from_le_bytes(this.pota_pub_key.kind));
    let key_len = u16::from_le_bytes(this.pota_pub_key.len) as usize;

    match kind {
        PolicyKeyKind::Ecc384 => {
            if key_len != ECC384_KEY_LEN {
                return Err(HsmError::InvalidArg);
            }
            if this.pota_pub_key.data[0] != ECC_UNCOMPRESSED_POINT_TAG {
                return Err(HsmError::InvalidArg);
            }
        }
        _ => return Err(HsmError::InvalidArg),
    }

    Ok(this)
}
