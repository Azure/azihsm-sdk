// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod aes;
mod aes_xts_key;
mod descriptor_utils;
mod dev;
mod ecc;
mod hkdf;
mod hmac;
mod kbkdf;
mod key;
mod masked_key;
mod partition;
mod partition_ex;
mod rsa;
mod sd_create_peer_backup;
mod sd_create_remote_backup;
mod sd_evidence;
mod sd_reseal_remote_backup;
mod sd_restore_local_backup;
mod sd_restore_peer_backup;
mod sd_restore_remote_backup;
mod sd_sealing_key_gen;
mod session;
mod session_ex;
mod tpm;

pub(crate) use aes::*;
pub(crate) use aes_xts_key::*;
use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::*;
use azihsm_ddi_mbor_types::*;
/// Maximum number of certificates in one SD-evidence certificate chain.
pub use azihsm_ddi_tbor_types::EVIDENCE_CHAIN_MAX_CERTS;
/// Size, in bytes, of the `part_final` `local_mk_backup` envelope.
pub use azihsm_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
/// Exact length of the local (masked) security-domain backup.
pub use azihsm_ddi_tbor_types::MASKED_SD_LEN;
/// Maximum number of certificates in a `part_final` PTA chain.
pub use azihsm_ddi_tbor_types::MAX_CERTS;
/// Exact length of the remote partition-owner-key backup (`SdCreate`/`SdReseal`).
pub use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
/// Maximum size, in bytes, of the `part_init` `pta_csr` buffer.
pub use azihsm_ddi_tbor_types::PTA_CSR_MAX_LEN;
/// Maximum size, in bytes, of the `part_init` `pta_report` buffer.
pub use azihsm_ddi_tbor_types::PTA_REPORT_MAX_LEN;
/// Exact length of the security-domain masking-key backup envelope.
pub use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;
use azihsm_ddi_tbor_types::TborStatus;
pub(crate) use descriptor_utils::*;
pub(crate) use dev::*;
pub(crate) use ecc::*;
pub(crate) use hkdf::*;
pub(crate) use hmac::*;
pub(crate) use kbkdf::*;
pub(crate) use key::*;
pub(crate) use masked_key::*;
pub(crate) use partition::*;
pub(crate) use partition_ex::*;
pub(crate) use rsa::*;
pub(crate) use sd_create_peer_backup::*;
pub(crate) use sd_create_remote_backup::*;
pub(crate) use sd_evidence::*;
pub(crate) use sd_reseal_remote_backup::*;
pub(crate) use sd_restore_local_backup::*;
pub(crate) use sd_restore_peer_backup::*;
pub(crate) use sd_restore_remote_backup::*;
pub(crate) use sd_sealing_key_gen::*;
pub(crate) use session::*;
pub(crate) use session_ex::*;
pub(crate) use tpm::*;

use super::*;

// Pin the shared-module `PSK_LEN` (defined in `shared_types`, which is
// shared with the native crate) to the wire-schema value so the two
// cannot drift.
const _: () = assert!(crate::PSK_LEN == azihsm_ddi_tbor_types::PSK_LEN);

/// Converts a DDI error into the corresponding `HsmError`.
///
/// `DriverError::IoAborted` and `DriverError::IoAbortInProgress` are mapped
/// to their dedicated `HsmError` variants so that higher layers (e.g., the
/// `open_partition` retry loop) can distinguish transient IO-abort conditions
/// from other DDI failures.
///
/// `DdiStatus::CredentialsNotEstablished`, `DdiStatus::NonceMismatch`,
/// `DdiStatus::PartitionNotProvisioned`, `DdiStatus::MaskedKeyDecodeFailed`,
/// `DdiStatus::EccVerifyFailed`, `DdiStatus::SessionNeedsRenegotiation`,
/// `DdiStatus::PendingKeyGeneration`, `DdiStatus::KeyNotFound`,
/// `DdiStatus::PartitionAlreadyProvisioned`, and
/// `DdiStatus::VaultAppLimitReached` are surfaced as distinct
/// `HsmError` variants to enable targeted retry logic during partition
/// initialization and key operations.
///
/// All remaining `DdiError` variants are logged and collapsed into
/// `HsmError::DdiCmdFailure`.
impl From<DdiError> for HsmError {
    fn from(err: DdiError) -> Self {
        match err {
            DdiError::DriverError(DriverError::IoAborted) => HsmError::IoAborted,
            DdiError::DriverError(DriverError::IoAbortInProgress) => HsmError::IoAbortInProgress,
            DdiError::DeviceNotReady => HsmError::DeviceNotReady,
            DdiError::DdiStatus(DdiStatus::CredentialsNotEstablished) => {
                HsmError::CredentialsNotEstablished
            }
            DdiError::DdiStatus(DdiStatus::NonceMismatch) => HsmError::NonceMismatch,
            DdiError::DdiStatus(DdiStatus::PartitionNotProvisioned) => {
                HsmError::PartitionNotProvisioned
            }
            DdiError::DdiStatus(DdiStatus::MaskedKeyDecodeFailed) => {
                HsmError::MaskedKeyDecodeFailed
            }
            DdiError::DdiStatus(DdiStatus::EccVerifyFailed) => HsmError::EccVerifyFailed,
            DdiError::DdiStatus(DdiStatus::Bk3AlreadyInitialized) => {
                HsmError::Bk3AlreadyInitialized
            }
            DdiError::DdiStatus(DdiStatus::SessionNeedsRenegotiation) => {
                HsmError::SessionNeedsRenegotiation
            }
            DdiError::DdiStatus(DdiStatus::PendingKeyGeneration) => HsmError::PendingKeyGeneration,
            DdiError::DdiStatus(DdiStatus::KeyNotFound) => HsmError::KeyNotFound,
            DdiError::DdiStatus(DdiStatus::PartitionAlreadyProvisioned) => {
                HsmError::PartitionAlreadyProvisioned
            }
            DdiError::DdiStatus(DdiStatus::VaultAppLimitReached) => HsmError::VaultAppLimitReached,
            DdiError::DdiStatus(DdiStatus::CannotDeleteInternalKeys) => {
                HsmError::CannotDeleteInternalKeys
            }
            DdiError::TborStatus(TborStatus::SdAlreadyInitialized) => {
                HsmError::SdAlreadyInitialized
            }
            DdiError::TborStatus(TborStatus::SdPeerCloningNotAllowed) => {
                HsmError::SdPeerCloningNotAllowed
            }
            // Map the firmware's contract-level `InvalidArg` to the same
            // `InvalidArgument` the host guards return, so callers see a
            // consistent argument-rejection error across transports.
            DdiError::TborStatus(TborStatus::InvalidArg) => HsmError::InvalidArgument,
            _ => {
                tracing::error!(?err, hsm_error = ?HsmError::DdiCmdFailure, "Unmapped DDI error");
                HsmError::DdiCmdFailure
            }
        }
    }
}

/// Handle to a key managed by the API layer.
///
/// The key's material always lives (masked) in its [`HsmKeyProps`]; this
/// only tracks whether the device *also* holds a resident copy.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum HsmKeyHandle {
    /// MBOR: device-resident vault key id, packed `key_id` (low 16 bits)
    /// `| bulk_key_id` (high 16 bits).
    VaultKeyId(u32),
    /// Non-resident key: material lives only as the masked blob in its
    /// props (e.g. TBOR keys, security-domain sealing keys). There is
    /// nothing device-side to address or delete.
    NoKeyId,
}

/// Extracts the key ID from a packed HSM key handle.
///
/// The key ID is stored in the low 16 bits of the handle.
///
/// Returns [`HsmError::InvalidKey`] for a non-resident key.
pub(crate) fn get_key_id(handle: HsmKeyHandle) -> HsmResult<u16> {
    match handle {
        HsmKeyHandle::VaultKeyId(id) => Ok((id & 0xFFFF) as u16),
        HsmKeyHandle::NoKeyId => Err(HsmError::InvalidKey),
    }
}

/// Extracts the optional bulk key ID from a packed HSM key handle.
///
/// Returns `None` when the bulk ID field is set to `0xFFFF`.
pub(crate) fn get_bulk_key_id(handle: HsmKeyHandle) -> Option<u16> {
    match handle {
        HsmKeyHandle::VaultKeyId(id) => {
            let bulk_id = (id >> 16) as u16;
            if bulk_id == 0xFFFF {
                None
            } else {
                Some(bulk_id)
            }
        }
        HsmKeyHandle::NoKeyId => None,
    }
}

/// Packs a key ID and optional bulk key ID into an HSM key handle.
///
/// When `bulk_key_id` is `None`, the bulk field is set to `0xFFFF`.
pub(crate) fn to_key_handle(key_id: u16, bulk_key_id: Option<u16>) -> HsmKeyHandle {
    let bulk_part = (bulk_key_id.unwrap_or(0xFFFF) as u32) << 16;
    HsmKeyHandle::VaultKeyId(bulk_part | (key_id as u32))
}

/// Builds a DDI request header with optional session ID and API revision.
///
/// Creates a `DdiReqHdr` for various types of DDI operations:
/// - Device-level operations: neither `rev` nor `sess_id` (e.g., `GetApiRev`)
/// - Session-less operations: `rev` only (e.g., `OpenSession`, `GetSessionEncryptionKey`)
/// - Operations with explicit session: both `rev` and `sess_id` (e.g., `CloseSession`)
///
/// # Arguments
///
/// * `op` - The DDI operation to include in the header
/// * `rev` - Optional API revision to use
/// * `sess_id` - Optional session ID to include
///
/// # Returns
///
/// A `DdiReqHdr` configured for the specified operation and parameters.
pub(crate) fn build_ddi_req_hdr(
    op: DdiOp,
    rev: Option<HsmApiRev>,
    sess_id: Option<u16>,
) -> DdiReqHdr {
    DdiReqHdr {
        op,
        rev: rev.map(|r| r.into()),
        sess_id,
    }
}

/// Builds a DDI request header using the provided session.
///
/// # Arguments
///
/// * `op` - The DDI operation to include in the header
/// * `sess` - The HSM session context
///
/// # Returns
///
/// A `DdiReqHdr` configured for the specified operation and session.
pub(crate) fn build_ddi_req_hdr_sess(op: DdiOp, sess: &HsmSession) -> DdiReqHdr {
    build_ddi_req_hdr(op, Some(sess.api_rev()), Some(sess.id()))
}

impl TryFrom<&HsmKeyProps> for DdiTargetKeyProperties {
    type Error = HsmError;
    fn try_from(props: &HsmKeyProps) -> Result<Self, Self::Error> {
        Ok(Self {
            key_metadata: props.flags().into(),
            key_label: MborByteArray::from_slice(props.label())
                .map_hsm_err(HsmError::InternalError)?,
        })
    }
}

impl From<HsmKeyFlags> for DdiTargetKeyMetadata {
    fn from(flags: HsmKeyFlags) -> Self {
        let mut meta = Self::default()
            .with_session(flags.is_session())
            .with_wrap(flags.can_wrap())
            .with_unwrap(flags.can_unwrap())
            .with_derive(flags.can_derive())
            .with_sign(flags.can_sign())
            .with_verify(flags.can_verify())
            .with_encrypt(flags.can_encrypt())
            .with_decrypt(flags.can_decrypt());

        if meta.encrypt() || meta.decrypt() {
            meta.set_encrypt(true);
            meta.set_decrypt(true);
        }

        if meta.sign() || meta.verify() {
            meta.set_sign(true);
            meta.set_verify(true);
        }

        if meta.wrap() || meta.unwrap() {
            meta.set_wrap(true);
            meta.set_unwrap(true);
        }

        meta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_key_id_rejects_non_resident_handle() {
        assert!(matches!(
            get_key_id(HsmKeyHandle::NoKeyId),
            Err(HsmError::InvalidKey)
        ));
    }
}
