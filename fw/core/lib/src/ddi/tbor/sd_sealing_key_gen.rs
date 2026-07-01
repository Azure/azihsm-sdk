// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdSealingKeyGen` handler.
//!
//! Generates a fresh security-domain sealing key — a P-384 ECC keypair
//! for ECDH key agreement (ECIES-style seal / unseal) — under the active
//! session's partition, and returns the **masked** private key plus the
//! public key.
//!
//! The private key is **not** stored on the device.  Instead it is masked
//! (AEAD-GCM-256) under the masking key associated with the requested
//! [`scope`](HsmKeyScope) and the masked blob is returned to the caller,
//! which re-imports it (unmask-on-use) when the key is later needed.
//! Because nothing is persisted, the command records no rollback on the
//! undo log.
//!
//! Scope → masking key:
//!
//! * [`Ephemeral`](HsmKeyScope::Ephemeral) → the partition
//!   [`PartitionEphemeralMaskingKey`](HsmVaultKeyKind::PartitionEphemeralMaskingKey).
//! * [`Local`](HsmKeyScope::Local) → the partition
//!   [`PartitionLocalMaskingKey`](HsmVaultKeyKind::PartitionLocalMaskingKey).
//!
//! Both masking keys are provisioned by `PartFinal`, so this command
//! requires a partition in the [`Initialized`](PartState::Initialized)
//! lifecycle state.  The [`Session`](HsmKeyScope::Session) and
//! [`SecurityDomain`](HsmKeyScope::SecurityDomain) scopes (and any other)
//! are rejected with [`HsmError::UnsupportedKeyScope`] until their
//! masking keys exist (session-key masking / `CreateSD`'s `SDKMK`).
//!
//! This command is **Crypto-Officer-only**: a Crypto-User session is
//! rejected with [`HsmError::InvalidPermissions`].

use azihsm_fw_core_crypto_key_masking::aead::mask;
use azihsm_fw_core_crypto_key_masking::aead::AeadAlg;
use azihsm_fw_core_crypto_key_masking::aead::MaskParams;
use azihsm_fw_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_fw_ddi_tbor_types::TborSdSealingKeyGenResp;
use azihsm_fw_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmEccPct;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmKeyScope;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmSessionState;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartState;
use azihsm_fw_hsm_pal_traits::SessionRole;

use crate::part_state;

/// NIST curve for security-domain sealing keys.  Fixed at P-384 to match
/// the SD / session / establish-cred key material elsewhere in the
/// firmware.
const SD_SEALING_CURVE: HsmEccCurve = HsmEccCurve::P384;

/// Envelope key-label recorded in the masked blob's `MaskedKeyMetadata`.
const SEALING_KEY_LABEL: &[u8] = b"SDSealingKey";

fn validate_crypto_officer_active_session<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    sess_id: HsmSessId,
) -> HsmResult<()> {
    // SdSealingKeyGen is Crypto-Officer-only.
    if sess_id.role() != SessionRole::CryptoOfficer {
        return Err(HsmError::InvalidPermissions);
    }

    // The dispatcher validates only SQE/body consistency; the slot must
    // still be checked for liveness at the handler boundary.
    if !matches!(pal.session_state(io, sess_id), HsmSessionState::Active) {
        return Err(HsmError::SessionNotFound);
    }

    Ok(())
}

/// Attributes recorded in the masked blob's metadata (restored on
/// re-import).  Per the SD-sealing-key contract the only usage attribute
/// is `derive`; `local`/`private`/`never_extractable` are HSM-internal
/// flags, and `scope` records the lifecycle / visibility domain.
fn sealing_key_attrs(scope: HsmKeyScope) -> HsmVaultKeyAttrs {
    HsmVaultKeyAttrs::new()
        .with_local(true)
        .with_private(true)
        .with_never_extractable(true)
        .with_derive(true)
        .with_scope(scope)
}

/// Resolve the vault id of the masking key associated with `scope`.
///
/// Only [`Ephemeral`](HsmKeyScope::Ephemeral) and
/// [`Local`](HsmKeyScope::Local) are supported for now (their masking
/// keys are provisioned by `PartFinal`).  Every other scope —
/// [`Session`](HsmKeyScope::Session),
/// [`SecurityDomain`](HsmKeyScope::SecurityDomain), or an unrecognized
/// discriminant — is rejected with [`HsmError::UnsupportedKeyScope`].
fn masking_key_id_for_scope<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    scope: HsmKeyScope,
) -> HsmResult<HsmKeyId> {
    match scope {
        HsmKeyScope::Ephemeral => part_state::part_ephemeral_mk_key_id(pal, io),
        HsmKeyScope::Local => part_state::part_local_mk_key_id(pal, io),
        _ => Err(HsmError::UnsupportedKeyScope),
    }
}

/// Handle a TBOR `SdSealingKeyGen` request.
///
/// No partition lock is needed: DDI commands run on a single-threaded
/// cooperative executor with one command in flight per partition, so no
/// concurrent handler can interleave with this one.  Nothing is
/// persisted, so no undo log is required.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborSdSealingKeyGenReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));

    // Losslessly map the wire `KeyScope` onto the PAL `HsmKeyScope`
    // (byte-identical 3-bit discriminants; unknown values round-trip).
    let scope = HsmKeyScope(req.scope().0);
    validate_crypto_officer_active_session(pal, io, sess_id)?;

    // The scope's masking key is provisioned by `PartFinal`, so the
    // partition must be finalized (`Initialized`).
    if part_state::part_state(pal, io)? != PartState::Initialized {
        return Err(HsmError::InvalidArg);
    }

    // Resolve (and validate) the masking key before generating anything,
    // so an unsupported scope fails cheaply.
    let mk_key_id = masking_key_id_for_scope(pal, io, scope)?;

    // Platform identity that binds the masked blob (anti-rollback on
    // re-import): SVN (BKS1 lineage) and owner-seed id (BKS2 lineage).
    let svn = part_state::part_mfgr_svn(pal);
    let owner = u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;

    // Generate the P-384 keypair for ECDH.  Follows the trait's query →
    // alloc → use flow: the priv/pub buffers must outlive the scoped
    // keygen-scratch allocator (whose `Drop` resets the DMA bump-mark),
    // so allocate them *between* the two scoped blocks rather than inside
    // one.
    let (priv_key_size, pub_key_size) = pal
        .alloc_scoped_async(io, async |a| {
            pal.ecc_gen_keypair(io, a, SD_SEALING_CURVE, None, HsmEccPct::KeyAgreement)
                .await
        })
        .await?;
    let priv_key = pal.dma_alloc(io, priv_key_size)?;
    let pub_key = pal.dma_alloc(io, pub_key_size)?;
    let (priv_key_len, pub_key_len) = pal
        .alloc_scoped_async(io, async |a| -> HsmResult<_> {
            pal.ecc_gen_keypair(
                io,
                a,
                SD_SEALING_CURVE,
                Some((&mut *priv_key, &mut *pub_key)),
                HsmEccPct::KeyAgreement,
            )
            .await
        })
        .await?;

    // Mask the private key under the scope's masking key.  The masked
    // blob lives in an IO-scoped buffer allocated *before* the masking
    // scope so it survives the scratch allocator's reset.
    let masked_key = pal.dma_alloc(io, MASKED_SEALING_KEY_LEN)?;
    let attrs = sealing_key_attrs(scope);
    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
        let masking_key = pal.vault_key(io, mk_key_id)?;
        let key_label = alloc.dma_alloc(SEALING_KEY_LABEL.len())?;
        key_label.copy_from_slice(SEALING_KEY_LABEL);
        let params = MaskParams {
            key_kind: HsmVaultKeyKind::SdSealing,
            key_attrs: attrs,
            svn,
            owner_seed_id: owner,
            key_label,
        };
        mask(
            pal,
            io,
            alloc,
            AeadAlg::AesGcm256,
            masking_key,
            &params,
            &priv_key[..priv_key_len],
            Some(masked_key),
        )
        .await?;
        Ok(())
    })
    .await?;

    // Encode the response: the masked private key plus the public key.
    // The PAL already emitted the public key in wire format
    // (little-endian), so copy it through unchanged.
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborSdSealingKeyGenResp::encode(buf, 0, true)?
            .masked_key(&masked_key[..])?
            .pub_key(&pub_key[..pub_key_len])?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
