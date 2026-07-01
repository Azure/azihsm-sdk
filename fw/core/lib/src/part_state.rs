// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed, property-routed partition state accessors.
//!
//! This module is the canonical core-side view of per-partition state.
//! Every public function here is a thin, typed wrapper over the generic
//! property API on [`HsmPartitionManager`]
//! ([`part_prop_get_*`](HsmPartitionManager::part_prop_get_u8) /
//! [`part_prop_set_*`](HsmPartitionManager::part_prop_set_u8) /
//! [`part_prop_clear`](HsmPartitionManager::part_prop_clear)) and
//! mirrors the legacy typed `part_*` methods on `HsmPartitionManager`
//! one-for-one in name and behaviour.
//!
//! # Position in the stack
//!
//! ```text
//!     core call site
//!         │
//!         ▼
//!   crate::part_state::part_*   ← you are here
//!         │
//!         ▼
//!   HsmPartitionManager::part_prop_get_* / set_* / clear   (PAL trait)
//!         │
//!         ▼
//!     PAL impl backing storage (flat region + presence bitmap + undo log)
//! ```
//!
//! Two views back the same storage in the PAL: the typed `part_*`
//! methods on [`HsmPartitionManager`] and the generic `part_prop_*`
//! methods.  Readers of one observe writes from the other.  Core
//! logic uses *only* this module so that:
//!
//! - The full set of partition state read or written by the firmware
//!   is enumerable from a single place (the [`PartPropId`] catalogue
//!   in the PAL traits crate).  New partition state is added there
//!   first; new accessors get added here second; existing call sites
//!   do not move.
//! - State-rollback / undo-log emission can hang off the property
//!   layer in the PAL without core ever caring.  The PAL is free to
//!   intercept `part_prop_set_*` / `part_prop_clear` and journal an
//!   inverse operation; core call sites stay shape-stable.
//! - Future PAL refactors that retire the typed `part_*` methods (or
//!   rearrange the storage layout) touch zero core call sites — only
//!   the bodies of the wrappers in this file move.
//!
//! # Conventions
//!
//! ## Arguments
//!
//! Every accessor takes `pal: &impl HsmPartitionManager` and
//! `io: &impl HsmIo`, in that order.  The PAL resolves the target
//! partition from `io.pid()`; this module never names a partition
//! id directly.
//!
//! ## Byte-valued properties use [`DmaBuf`]
//!
//! All byte-valued accessors take or return `&DmaBuf` instead of the
//! legacy `Option<&mut [u8]>` query/copy pattern.  This keeps data
//! flowing through PAL crypto primitives zero-copy and avoids the
//! two-pass length/copy idiom at every caller.
//!
//! Setters accept any `&DmaBuf` whose length matches the property's
//! [`PartPropKind`]; the PAL impl validates length and returns
//! [`HsmError::InvalidArg`] on a mismatch.  Getters return a borrow
//! tied to the PAL impl's storage; callers must not assume the
//! lifetime extends past the next PAL mutation against the same
//! partition.
//!
//! ## Presence semantics
//!
//! Property getters return [`HsmError::PartPropNotFound`] when the
//! addressed slot has not yet been written (or was last cleared).
//! Wrappers here propagate that error unchanged; callers that want
//! to treat absence as a non-error condition must match on
//! [`HsmError::PartPropNotFound`] explicitly.  **No `Option` wrapper
//! is layered on top — the error variant *is* the presence signal.**
//!
//! For properties whose PAL meta marks them as
//! [`PartPropDefault::RequiredPresent`] the error is unreachable in
//! well-formed builds (the PAL guarantees the slot is initialised on
//! partition allocation) and callers may treat the result as
//! infallible w.r.t. presence — PAL transport / storage errors still
//! propagate.  The doc comment on each accessor calls out which
//! presence class applies.
//!
//! ## Sensitivity
//!
//! Properties whose PAL meta marks them as `sensitive` (PSKs,
//! credentials, nonce, sealed / masked BK_BOOT,
//! firmware seed) are zeroised by the PAL when overwritten or
//! cleared.  Callers in this module never log the value of those
//! properties; downstream code that takes a `&DmaBuf` of sensitive
//! material is expected to honour the same rule.
//!
//! ## Type-narrowed views over the property kind
//!
//! Two property categories store wider scalars than their typed view
//! exposes:
//!
//! - **Lifecycle state** ([`PartPropId::STATE`]) is stored as `U8` but
//!   exposed here as [`PartState`].  The mapping is the
//!   `#[repr(u8)]` discriminant on the enum.  An unknown byte
//!   coming back from storage is treated as PAL corruption and
//!   surfaces as [`HsmError::InternalError`] from [`part_state`].
//! - **Vault key references** (the `*_KEY_ID` ids) are stored as
//!   `U16` and exposed here as [`HsmKeyId`] (a `u16` newtype) via the
//!   `key_id_get` / `key_id_set` helpers below.  Conversion is
//!   loss-less because both representations are `u16`.
//!
//! ## Naming
//!
//! Every accessor uses the `part_` prefix so that, when re-exported
//! through `super::*` into the rest of the crate, the names stay
//! self-describing without a `part_state::` qualifier at the call site.
//! Setters are `part_set_<name>`; clear operations are
//! `part_clear_<name>`.

use super::*;

// ─── Identity, lifecycle, and platform state ──────────────────────────────
//
// Properties that name *what* this partition is and *where* it is in
// its lifecycle.  These are the first things every DDI handler reads
// to decide whether to accept a request.

/// Lifecycle state of the calling partition.
///
/// Wraps [`PartPropId::STATE`] (`U8` decoded into [`PartState`]).  The
/// slot is `RequiredPresent`, so this never returns
/// [`HsmError::PartPropNotFound`].  A stored byte that does not name
/// a known [`PartState`] is treated as PAL-side corruption and
/// surfaces as [`HsmError::InternalError`].
pub fn part_state(pal: &impl HsmPartitionManager, io: &impl HsmIo) -> HsmResult<PartState> {
    let raw = pal.part_prop_get_u8(io, PartPropId::STATE)?;
    PartState::from_u8(raw).ok_or(HsmError::InternalError)
}

/// Set the partition lifecycle state.
///
/// Wraps [`PartPropId::STATE`].  The PAL impl is responsible for
/// rejecting any state byte that violates the partition's allowed
/// transition graph — this wrapper performs no validation of its
/// own and serialises the discriminant directly.
pub fn part_set_state(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    s: PartState,
) -> HsmResult<()> {
    pal.part_prop_set_u8(io, PartPropId::STATE, s as u8)
}

/// [`PartPropId`] backing [`part_state`] / [`part_set_state`].
#[inline]
pub const fn part_state_prop_id() -> PartPropId {
    PartPropId::STATE
}

/// Monotonic partition generation counter.
///
/// Wraps [`PartPropId::GEN`] (`U32`, `RequiredPresent`, **read-only**).
/// Incremented by the PAL on every allocate/free cycle; used by
/// lifetime guards (e.g. session handles) to detect partition reuse
/// across a free/realloc and refuse to operate on a stale generation.
pub fn part_gen(pal: &impl HsmPartitionManager, io: &impl HsmIo) -> HsmResult<u32> {
    pal.part_prop_get_u32(io, PartPropId::GEN)
}

/// [`PartPropId`] backing [`part_gen`].
#[inline]
pub const fn part_gen_prop_id() -> PartPropId {
    PartPropId::GEN
}

/// Security version number bound into this partition's derivation
/// lineage.
///
/// Current firmware SVN — the manufacturer-seed (BKS1) selector.
///
/// Device-global (not per-partition); served by
/// [`HsmSeedStore::mfgr_svn`](azihsm_fw_hsm_pal_traits::HsmSeedStore::mfgr_svn).
/// Used as a tweak input to partition-bound key derivations so that
/// material derived under firmware version N is not reachable from
/// firmware version N-1.
pub fn part_mfgr_svn(pal: &impl HsmSeedStore) -> u64 {
    pal.mfgr_svn()
}

/// Number of host-allocated SQ/CQ resource pairs.
///
/// Wraps [`PartPropId::RES_COUNT`] (`U8`, `RequiredPresent`,
/// read-only).  Read-only from the caller's perspective; set by the
/// PAL at partition allocation time from the resource grant.
pub fn part_res_count(pal: &impl HsmPartitionManager, io: &impl HsmIo) -> HsmResult<u8> {
    pal.part_prop_get_u8(io, PartPropId::RES_COUNT)
}

/// [`PartPropId`] backing [`part_res_count`].
#[inline]
pub const fn part_res_count_prop_id() -> PartPropId {
    PartPropId::RES_COUNT
}

/// Opaque 16-byte partition identity blob.
///
/// Wraps [`PartPropId::ID`] (`FixedBytes { len: 16 }`,
/// `AbsentUntilSet`, **read-only**).  Returns
/// [`HsmError::PartPropNotFound`] before the PAL has populated it
/// for this partition.  The bytes are opaque to core; only the host
/// management layer interprets them.
pub fn part_id<'a>(pal: &'a impl HsmPartitionManager, io: &impl HsmIo) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::ID)
}

/// [`PartPropId`] backing [`part_id`].
#[inline]
pub const fn part_id_prop_id() -> PartPropId {
    PartPropId::ID
}

/// Unique Device Secret (32 B).  **Sensitive.**
///
/// Device-global (not per-partition); served by
/// [`HsmSeedStore::uds`](azihsm_fw_hsm_pal_traits::HsmSeedStore::uds).
/// The UDS is the device root secret used as the KBKDF key for
/// partition-bound derivations (the partition-distinguishing inputs are
/// the KBKDF context); the returned borrow must not be logged or copied
/// outside crypto primitives.
pub fn part_uds(pal: &impl HsmSeedStore) -> &[u8] {
    pal.uds()
}

/// Firmware-supplied secret seed (48 B).  **Sensitive.**
///
/// Device-global (not per-partition); served by
/// [`HsmSeedStore::fw_seed`](azihsm_fw_hsm_pal_traits::HsmSeedStore::fw_seed).
/// Used as the KBKDF key in boot-key (`BKx`) derivations.
pub fn part_fw_seed(pal: &impl HsmSeedStore) -> &[u8] {
    pal.fw_seed()
}

// ─── Vault references ─────────────────────────────────────────────────────
//
// All vault-ref properties are stored in the property table as `U16`
// (matching today's [`HsmKeyId`] width).  The typed core view here
// re-exposes them as [`HsmKeyId`] (a `u16` newtype) for call-site
// ergonomics; conversion is loss-less.  If the catalogue ever grows
// to a wider scalar kind, the `key_id_get` helper is the single
// point at which narrowing happens, and an out-of-range stored value
// will surface as [`HsmError::InternalError`].

/// Read a vault key reference as an [`HsmKeyId`] (`u16`).
///
/// Returns [`HsmError::PartPropNotFound`] if the slot is absent;
/// callers handle the absence/error split per the presence
/// semantics in the module docs.
#[inline]
fn key_id_get(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    id: PartPropId,
) -> HsmResult<HsmKeyId> {
    let raw = pal.part_prop_get_u16(io, id)?;
    Ok(HsmKeyId::from(raw))
}

/// Write a vault key reference (`HsmKeyId` is a `u16`).
#[inline]
fn key_id_set(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    id: PartPropId,
    key_id: HsmKeyId,
) -> HsmResult<()> {
    pal.part_prop_set_u16(io, id, u16::from(key_id))
}

/// Vault id of the partition identity (ECC-P384) key.
///
/// Wraps [`PartPropId::ID_KEY_ID`] (`U16 → HsmKeyId`,
/// `AbsentUntilSet`, **read-only**).
pub fn part_id_key_id(pal: &impl HsmPartitionManager, io: &impl HsmIo) -> HsmResult<HsmKeyId> {
    key_id_get(pal, io, PartPropId::ID_KEY_ID)
}

/// [`PartPropId`] backing [`part_id_key_id`].
#[inline]
pub const fn part_id_key_id_prop_id() -> PartPropId {
    PartPropId::ID_KEY_ID
}

/// Vault id of the partition masking key.
///
/// Wraps [`PartPropId::MK_KEY_ID`] (`U16 → HsmKeyId`,
/// `AbsentUntilSet`).
pub fn part_mk_key_id(pal: &impl HsmPartitionManager, io: &impl HsmIo) -> HsmResult<HsmKeyId> {
    key_id_get(pal, io, PartPropId::MK_KEY_ID)
}

/// Set the partition masking key id.
pub fn part_set_mk_key_id(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    key_id: HsmKeyId,
) -> HsmResult<()> {
    key_id_set(pal, io, PartPropId::MK_KEY_ID, key_id)
}

/// [`PartPropId`] backing [`part_mk_key_id`] / [`part_set_mk_key_id`].
#[inline]
pub const fn part_mk_key_id_prop_id() -> PartPropId {
    PartPropId::MK_KEY_ID
}

/// Whether the partition has been fully provisioned.
///
/// A partition is provisioned once its masking key (MK) has been
/// imported into the vault and recorded via
/// [`part_set_mk_key_id`].  This is the gate
/// `EstablishCredential` uses to prevent double-provisioning, and
/// `OpenSession` uses to require provisioning before a session can
/// be opened.  Derived from [`PartPropId::MK_KEY_ID`] presence
/// (`AbsentUntilSet`).
pub fn part_is_provisioned(pal: &impl HsmPartitionManager, io: &impl HsmIo) -> HsmResult<bool> {
    match part_mk_key_id(pal, io) {
        Ok(_) => Ok(true),
        Err(HsmError::PartPropNotFound) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Vault id of the partition Unique Machine Secret derived key.
///
/// Wraps [`PartPropId::UPS_KEY_ID`] (`U16 → HsmKeyId`,
/// `AbsentUntilSet`).
pub fn part_ups_key_id(pal: &impl HsmPartitionManager, io: &impl HsmIo) -> HsmResult<HsmKeyId> {
    key_id_get(pal, io, PartPropId::UPS_KEY_ID)
}

/// Set the partition UPS-derived key id.
pub fn part_set_ups_key_id(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    key_id: HsmKeyId,
) -> HsmResult<()> {
    key_id_set(pal, io, PartPropId::UPS_KEY_ID, key_id)
}

/// [`PartPropId`] backing [`part_ups_key_id`] / [`part_set_ups_key_id`].
#[inline]
pub const fn part_ups_key_id_prop_id() -> PartPropId {
    PartPropId::UPS_KEY_ID
}

/// Vault id of the Partition Trust Anchor (PTA) key.
///
/// Wraps [`PartPropId::PTA_KEY_ID`] (`U16 → HsmKeyId`,
/// `AbsentUntilSet`).  Bound by the TBOR `PartInit` handler.
pub fn part_pta_key_id(pal: &impl HsmPartitionManager, io: &impl HsmIo) -> HsmResult<HsmKeyId> {
    key_id_get(pal, io, PartPropId::PTA_KEY_ID)
}

/// Set the PTA key id.
pub fn part_set_pta_key_id(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    key_id: HsmKeyId,
) -> HsmResult<()> {
    key_id_set(pal, io, PartPropId::PTA_KEY_ID, key_id)
}

/// [`PartPropId`] backing [`part_pta_key_id`] / [`part_set_pta_key_id`].
#[inline]
pub const fn part_pta_key_id_prop_id() -> PartPropId {
    PartPropId::PTA_KEY_ID
}

/// Vault id of the partition's unwrapping key.
///
/// Wraps [`PartPropId::RSA_UNWRAPPING_KEY_ID`] (`U16 → HsmKeyId`,
/// `AbsentUntilSet`, **read-only**).
pub fn part_unwrapping_key_id(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<HsmKeyId> {
    key_id_get(pal, io, PartPropId::RSA_UNWRAPPING_KEY_ID)
}

/// [`PartPropId`] backing [`part_unwrapping_key_id`].
#[inline]
pub const fn part_unwrapping_key_id_prop_id() -> PartPropId {
    PartPropId::RSA_UNWRAPPING_KEY_ID
}

/// Vault id of the long-lived session-encryption (ECDH) key.
///
/// Wraps [`PartPropId::SESSION_ENC_KEY_ID`] (`U16 → HsmKeyId`,
/// `AbsentUntilSet`).
pub fn part_session_enc_key_id(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<HsmKeyId> {
    key_id_get(pal, io, PartPropId::SESSION_ENC_KEY_ID)
}

/// Set the session-encryption key id.
pub fn part_set_session_enc_key_id(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    key_id: HsmKeyId,
) -> HsmResult<()> {
    key_id_set(pal, io, PartPropId::SESSION_ENC_KEY_ID, key_id)
}

/// [`PartPropId`] backing [`part_session_enc_key_id`] /
/// [`part_set_session_enc_key_id`].
#[inline]
pub const fn part_session_enc_key_id_prop_id() -> PartPropId {
    PartPropId::SESSION_ENC_KEY_ID
}

/// Vault id of the one-shot establish-credential RSA-OAEP key.
///
/// Wraps [`PartPropId::ESTABLISH_CRED_KEY_ID`] (`U16 → HsmKeyId`,
/// `AbsentUntilSet`).  This is a one-shot key: the establish-cred
/// handler clears the slot with [`part_clear_establish_cred_key`] as
/// soon as the credential has been unwrapped, so a successful return
/// here means the key is still consumable.
pub fn part_establish_cred_key_id(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<HsmKeyId> {
    key_id_get(pal, io, PartPropId::ESTABLISH_CRED_KEY_ID)
}

/// Set the establish-credential key id.
pub fn part_set_establish_cred_key_id(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    key_id: HsmKeyId,
) -> HsmResult<()> {
    key_id_set(pal, io, PartPropId::ESTABLISH_CRED_KEY_ID, key_id)
}

/// Clear the establish-credential key id (one-shot consumed).
///
/// Wraps [`HsmPartitionManager::part_prop_clear`] for
/// [`PartPropId::ESTABLISH_CRED_KEY_ID`].  Idempotent on an already
/// absent slot (returns `Ok(())`).  After this call,
/// [`part_establish_cred_key_id`] returns
/// [`HsmError::PartPropNotFound`].
pub fn part_clear_establish_cred_key(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<()> {
    pal.part_prop_clear(io, PartPropId::ESTABLISH_CRED_KEY_ID)
}

/// [`PartPropId`] backing [`part_establish_cred_key_id`] /
/// [`part_set_establish_cred_key_id`] /
/// [`part_clear_establish_cred_key`].
#[inline]
pub const fn part_establish_cred_key_id_prop_id() -> PartPropId {
    PartPropId::ESTABLISH_CRED_KEY_ID
}

// ─── Caller-presented secrets ─────────────────────────────────────────────
//
// Material that the host or the management plane hands the partition
// to authenticate or key sessions.  All sensitive; the PAL zeroises
// previous values on overwrite or clear.

/// Read a pre-shared key.
///
/// `psk_id` selects between PSK slots, matching the legacy
/// [`HsmPartitionManager::part_psk`] enumeration:
///
/// | `psk_id` | Slot               | Property                 |
/// |----------|--------------------|--------------------------|
/// | `0`      | Crypto Officer PSK | [`PartPropId::PSK_CO`]   |
/// | `1`      | Crypto User PSK    | [`PartPropId::PSK_CU`]   |
///
/// Any other value returns [`HsmError::InvalidPskId`].  Both slots are
/// `RequiredPresent` (default-baked at allocation time from
/// [`DEFAULT_PSK_CO`] / [`DEFAULT_PSK_CU`]) so a successful call
/// always yields exactly [`PSK_LEN`] bytes.
pub fn part_psk<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
    psk_id: u8,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, part_psk_prop_id(psk_id)?)
}

/// Write a pre-shared key.
///
/// `data` must be exactly [`PSK_LEN`] bytes; see [`part_psk`] for the
/// `psk_id → slot` mapping.  Rotating from the default PSK is required
/// before exposing the partition to untrusted traffic.
pub fn part_set_psk(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    psk_id: u8,
    data: &DmaBuf,
) -> HsmResult<()> {
    pal.part_prop_set_bytes(io, part_psk_prop_id(psk_id)?, data)
}

/// Translate the `0/1` PSK selector into the backing
/// [`PartPropId`].  Returns [`HsmError::InvalidPskId`] for any other
/// selector.
///
/// Exposed so upper-layer undo-log emitters can name the slot they
/// are about to mutate without re-encoding the selector mapping.
#[inline]
pub fn part_psk_prop_id(psk_id: u8) -> HsmResult<PartPropId> {
    match psk_id {
        0 => Ok(PartPropId::PSK_CO),
        1 => Ok(PartPropId::PSK_CU),
        _ => Err(HsmError::InvalidPskId),
    }
}

/// Caller-presented credential blob (32 B).  **Sensitive.**
///
/// Wraps [`PartPropId::CREDENTIAL`] (`FixedBytes { len: 32 }`,
/// `AbsentUntilSet`, sensitive).  Returns
/// [`HsmError::PartPropNotFound`] before [`part_set_credential`] has
/// been called.  Verified by the upper layer via constant-time
/// compare against the returned bytes — callers must not branch on
/// the contents themselves.
pub fn part_credential<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::CREDENTIAL)
}

/// Write the caller-presented credential blob.  **Sensitive.**
///
/// `data` must be exactly 32 bytes (`id ‖ pin`, 16 + 16).  Write-once
/// per credential lifecycle: re-setting without an intervening
/// [`PartPropId::CREDENTIAL`] clear returns
/// [`HsmError::VaultAppLimitReached`]; an all-zero `id` or `pin` half
/// is rejected with [`HsmError::InvalidAppCredentials`].
pub fn part_set_credential(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    data: &DmaBuf,
) -> HsmResult<()> {
    pal.part_prop_set_bytes(io, PartPropId::CREDENTIAL, data)
}

/// Constant-time-compare the supplied `id` and `pin` (16 B each)
/// against the partition's stored credential.
///
/// Returns `Ok(())` on match.  Returns:
///
/// - [`HsmError::InvalidArg`] if `id` or `pin` is not exactly 16 B
///   (caller bug — the wire shape is fixed).
/// - [`HsmError::InvalidAppCredentials`] when the credential has not
///   been set yet, or when either half differs from the stored
///   value.  The comparison runs over the full 32-byte width so a
///   timing side-channel cannot distinguish "wrong id" from "wrong
///   pin".
/// - [`HsmError::InternalError`] if the stored credential blob has
///   a length other than 32 bytes — that signals a property
///   catalogue / PAL storage corruption bug, not an authentication
///   failure, and must not be masked as one.
pub fn part_verify_credential(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    id: &[u8],
    pin: &[u8],
) -> HsmResult<()> {
    if id.len() != 16 || pin.len() != 16 {
        return Err(HsmError::InvalidArg);
    }
    let stored = match part_credential(pal, io) {
        Ok(buf) => buf,
        Err(HsmError::PartPropNotFound) => return Err(HsmError::InvalidAppCredentials),
        Err(e) => return Err(e),
    };
    if stored.len() != 32 {
        return Err(HsmError::InternalError);
    }
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= stored[i] ^ id[i];
        diff |= stored[16 + i] ^ pin[i];
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(HsmError::InvalidAppCredentials)
    }
}

/// [`PartPropId`] backing [`part_credential`] / [`part_set_credential`].
#[inline]
pub const fn part_credential_prop_id() -> PartPropId {
    PartPropId::CREDENTIAL
}

/// Wire length of [`PartPropId::NONCE`] (matches the catalogue
/// `FixedBytes { len: 32 }`).
pub const NONCE_LEN: usize = 32;

/// 32-byte partition nonce, refreshed per credential / session event.
/// **Sensitive.**
///
/// Wraps [`PartPropId::NONCE`] (`FixedBytes { len: 32 }`,
/// `RequiredPresent`, sensitive).  Always present; the PAL
/// initialises it on partition allocation.  Refresh by writing fresh
/// PAL-RNG bytes via [`part_set_nonce`].
pub fn part_nonce<'a>(pal: &'a impl HsmPartitionManager, io: &impl HsmIo) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::NONCE)
}

/// Overwrite the partition nonce with the supplied 32-byte buffer.
///
/// Wraps [`PartPropId::NONCE`] setter.  Callers must source the
/// bytes from the PAL RNG (e.g. [`HsmRng::rng_fill_bytes`]) so the
/// new nonce is unpredictable to the host.
pub fn part_set_nonce(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    nonce: &DmaBuf,
) -> HsmResult<()> {
    pal.part_prop_set_bytes(io, PartPropId::NONCE, nonce)
}

/// [`PartPropId`] backing [`part_nonce`].
#[inline]
pub const fn part_nonce_prop_id() -> PartPropId {
    PartPropId::NONCE
}

/// Constant-time-compare `nonce` against the partition's current
/// stored nonce.
///
/// Returns `Ok(())` on match, [`HsmError::NonceMismatch`] otherwise.
/// The comparison runs over the full 32-byte width regardless of
/// where bytes first diverge, so a timing side-channel cannot
/// localize the mismatch.  Length mismatch is also a mismatch.
pub fn part_verify_nonce(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    nonce: &[u8],
) -> HsmResult<()> {
    let stored = part_nonce(pal, io)?;
    if stored.len() != nonce.len() {
        return Err(HsmError::NonceMismatch);
    }
    let mut diff = 0u8;
    for (a, b) in stored.iter().zip(nonce.iter()) {
        diff |= a ^ b;
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(HsmError::NonceMismatch)
    }
}

// ─── PAL-private root-of-trust seed rows ──────────────────────────────────
//
// Indexed properties exposing the manufacturer-provisioned and
// device-owner-provisioned seed tables that anchor the masking-key
// derivation in `derive_masking_key` (see `ddi::mbor::establish_credential`).
// Only rows actually provisioned by the current PAL are present;
// unprovisioned rows return [`HsmError::PartPropNotFound`].

/// Manufacturer-provisioned 32 B seed (BKS1) for a specific `svn`.
/// **Sensitive** device-global root-of-trust material.
///
/// Device-global (not per-partition); served by
/// [`HsmSeedStore::mfgr_seed`](azihsm_fw_hsm_pal_traits::HsmSeedStore::mfgr_seed).
/// Returns [`HsmError::SeedNotFound`] when the PAL has not provisioned
/// a row for that SVN.
pub fn part_mfgr_seed(pal: &impl HsmSeedStore, svn: u64) -> HsmResult<&[u8]> {
    pal.mfgr_seed(svn)
}

/// Device-owner-provisioned 32 B seed (BKS2) for a specific owner
/// selector `svn`.  **Sensitive** device-global root-of-trust material.
///
/// Device-global (not per-partition); served by
/// [`HsmSeedStore::owner_seed`](azihsm_fw_hsm_pal_traits::HsmSeedStore::owner_seed).
/// Returns [`HsmError::SeedNotFound`] when the PAL has not provisioned
/// a row for that selector.
pub fn part_owner_seed(pal: &impl HsmSeedStore, svn: u64) -> HsmResult<&[u8]> {
    pal.owner_seed(svn)
}

// ─── Boot / launch-time bound material ────────────────────────────────────
//
// Material bound to a single boot / VM-launch incarnation.  Set once
// per power cycle (or once per VM launch) and either consumed by the
// session-establishment flow or used as inputs into derivations whose
// outputs are themselves boot-bound.

/// Sealed BK3 blob.  **Sensitive.**
///
/// Wraps [`PartPropId::SEALED_BK3`]
/// (`VarBytes { max: SEALED_BK3_MAX_LEN }`, `AbsentUntilSet`,
/// sensitive).  Returns [`HsmError::PartPropNotFound`] before the
/// host has supplied it this power cycle.  Set at most once per
/// power cycle.
pub fn part_sealed_bk3<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::SEALED_BK3)
}

/// Write the sealed BK3 blob.  **Sensitive.**
///
/// `data` must be ≤ [`SEALED_BK3_MAX_LEN`] bytes; the PAL setter
/// is write-once per power cycle and returns
/// [`HsmError::SealedBk3AlreadySet`] if invoked a second time
/// without an intervening clear (free / NSSR).
pub fn part_set_sealed_bk3(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    data: &DmaBuf,
) -> HsmResult<()> {
    pal.part_prop_set_bytes(io, PartPropId::SEALED_BK3, data)
}

/// [`PartPropId`] backing [`part_sealed_bk3`] / [`part_set_sealed_bk3`].
#[inline]
pub const fn part_sealed_bk3_prop_id() -> PartPropId {
    PartPropId::SEALED_BK3
}

/// Masked BK_BOOT blob (variable, ≤ [`MASKED_BK_BOOT_LEN`]).
/// **Sensitive.**
///
/// Wraps [`PartPropId::MASKED_BK_BOOT`]
/// (`VarBytes { max: MASKED_BK_BOOT_LEN }`, `AbsentUntilSet`,
/// sensitive).
pub fn part_masked_bk_boot<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::MASKED_BK_BOOT)
}

/// Write the masked BK_BOOT blob.  **Sensitive.**
///
/// `data` must be ≤ [`MASKED_BK_BOOT_LEN`] bytes.
pub fn part_set_masked_bk_boot(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    data: &DmaBuf,
) -> HsmResult<()> {
    pal.part_prop_set_bytes(io, PartPropId::MASKED_BK_BOOT, data)
}

/// [`PartPropId`] backing [`part_masked_bk_boot`] /
/// [`part_set_masked_bk_boot`].
#[inline]
pub const fn part_masked_bk_boot_prop_id() -> PartPropId {
    PartPropId::MASKED_BK_BOOT
}

/// VM-launch GUID (16 B), bound at session-establishment time.
///
/// Wraps [`PartPropId::VM_LAUNCH_GUID`] (`FixedBytes { len: 16 }`,
/// `AbsentUntilSet`, **read-only**).  Returns
/// [`HsmError::PartPropNotFound`] before session establishment has
/// bound the value for the current launch.  Populated by the PAL.
pub fn part_vm_launch_guid<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::VM_LAUNCH_GUID)
}

/// [`PartPropId`] backing [`part_vm_launch_guid`].
#[inline]
pub const fn part_vm_launch_guid_prop_id() -> PartPropId {
    PartPropId::VM_LAUNCH_GUID
}

/// Partition policy hash — the SHA-384 digest (48 bytes) of the
/// partition's PartPolicy blob.
///
/// Wraps [`PartPropId::POLICY_HASH`] (fixed 48 bytes, `AbsentUntilSet`).
/// Set by the TBOR `PartInit` handler from the hash of the request's
/// `part_policy`, and consulted by DDI handlers that gate on policy
/// identity.
pub fn part_policy_hash<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::POLICY_HASH)
}

/// Write the partition policy hash.
///
/// `data` must be exactly the 48-byte SHA-384 digest of the PartPolicy
/// blob.
pub fn part_set_policy_hash(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    data: &DmaBuf,
) -> HsmResult<()> {
    pal.part_prop_set_bytes(io, PartPropId::POLICY_HASH, data)
}

/// [`PartPropId`] backing [`part_policy_hash`] / [`part_set_policy_hash`].
#[inline]
pub const fn part_policy_hash_prop_id() -> PartPropId {
    PartPropId::POLICY_HASH
}

/// POTA thumbprint (48 B).  Set by `PartInit`.
///
/// Wraps [`PartPropId::POTA_THUMBPRINT`] (`FixedBytes { len: 48 }`,
/// `AbsentUntilSet`).
pub fn part_pota_thumbprint<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::POTA_THUMBPRINT)
}

/// Write the POTA thumbprint.
///
/// `data` must be exactly 48 bytes.
pub fn part_set_pota_thumbprint(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    data: &DmaBuf,
) -> HsmResult<()> {
    pal.part_prop_set_bytes(io, PartPropId::POTA_THUMBPRINT, data)
}

/// [`PartPropId`] backing [`part_pota_thumbprint`] /
/// [`part_set_pota_thumbprint`].
#[inline]
pub const fn part_pota_thumbprint_prop_id() -> PartPropId {
    PartPropId::POTA_THUMBPRINT
}

/// Read the SATA (Sealing Authority Trust Anchor) thumbprint.
pub fn part_sata_thumbprint<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::SATA_THUMBPRINT)
}

/// Write the SATA thumbprint.  `data` must be exactly 48 bytes.
pub fn part_set_sata_thumbprint(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    data: &DmaBuf,
) -> HsmResult<()> {
    pal.part_prop_set_bytes(io, PartPropId::SATA_THUMBPRINT, data)
}

/// Read the SAPOTA (Sealing Authority's POTA) thumbprint.
pub fn part_sapota_thumbprint<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::SAPOTA_THUMBPRINT)
}

/// Write the SAPOTA thumbprint.  `data` must be exactly 48 bytes.
pub fn part_set_sapota_thumbprint(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    data: &DmaBuf,
) -> HsmResult<()> {
    pal.part_prop_set_bytes(io, PartPropId::SAPOTA_THUMBPRINT, data)
}

/// Whether the PSK selected by `psk_id` is still the well-known
/// default value.
///
/// Reads the PSK via [`part_psk`] and compares against
/// [`DEFAULT_PSK_CO`] / [`DEFAULT_PSK_CU`] in constant time.  Returns
/// `Ok(true)` only when the stored bytes match the default.
pub fn part_psk_is_default(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    psk_id: u8,
) -> HsmResult<bool> {
    let stored = part_psk(pal, io, psk_id)?;
    let default = match psk_id {
        0 => DEFAULT_PSK_CO.as_slice(),
        1 => DEFAULT_PSK_CU.as_slice(),
        // Unreachable: `part_psk` above already rejected any other
        // selector with `InvalidPskId`.  Returned here for defence in
        // depth so the match stays exhaustive.
        _ => return Err(HsmError::InvalidPskId),
    };
    if stored.len() != default.len() {
        return Ok(false);
    }
    let mut diff = 0u8;
    for (a, b) in stored.iter().zip(default.iter()) {
        diff |= a ^ b;
    }
    Ok(diff == 0)
}

/// Whether the partition's caller-presented credential blob has been
/// set for the current incarnation.
///
/// Wraps `part_prop_get_bytes(CREDENTIAL)` and maps
/// [`HsmError::PartPropNotFound`] to `Ok(false)`; any other PAL error
/// propagates.
pub fn part_is_credential_set(pal: &impl HsmPartitionManager, io: &impl HsmIo) -> HsmResult<bool> {
    match pal.part_prop_get_bytes(io, PartPropId::CREDENTIAL) {
        Ok(_) => Ok(true),
        Err(HsmError::PartPropNotFound) => Ok(false),
        Err(e) => Err(e),
    }
}

// ─── Public keys, BKS2, BK3 session (Phase A property additions) ─────

/// Raw ECC-P384 public key (x ∥ y, 96 B) for the partition identity key.
pub fn part_id_pub_key<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::ID_PUB_KEY)
}

/// Raw ECC-P384 public key (x ∥ y, 96 B) for the session encryption key.
pub fn part_session_enc_pub_key<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::SESSION_ENC_PUB_KEY)
}

/// Raw ECC-P384 public key (x ∥ y, 96 B) for the establish-credential key.
pub fn part_establish_cred_pub_key<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::ESTABLISH_CRED_PUB_KEY)
}

/// Raw ECC-P384 public-key coordinates (x ∥ y, 96 B) of the Partition
/// Trust Anchor.
pub fn part_pta_pub_key<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::PTA_PUB_KEY)
}

/// Validates a host-supplied SEC1-uncompressed P-384 PTA key (`0x04 ‖ x
/// ‖ y`, 97 B) and returns a view of the 96-byte raw `x ‖ y`
/// coordinates (the constant `0x04` prefix is dropped before storage).
fn pta_sec1_to_raw(sec1: &DmaBuf) -> HsmResult<&DmaBuf> {
    const PTA_SEC1_LEN: usize = 97;
    if sec1.len() != PTA_SEC1_LEN || sec1[0] != 0x04 {
        return Err(HsmError::InvalidArg);
    }
    Ok(sec1.split_at(1).1)
}

/// Store the PTA public key from its host-supplied SEC1 form: validates
/// the `0x04` prefix and persists the 96-byte raw coordinates.
pub fn part_set_pta_pub_key(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    sec1: &DmaBuf,
) -> HsmResult<()> {
    let raw = pta_sec1_to_raw(sec1)?;
    pal.part_prop_set_bytes(io, PartPropId::PTA_PUB_KEY, raw)
}

/// Bind both halves of the Partition Trust Anchor — the vault key id
/// and the public key — in a single composite write.  `pub_sec1` is the
/// host-supplied SEC1 form; its raw coordinates are stored.
pub fn part_set_pta_key(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    key_id: HsmKeyId,
    pub_sec1: &DmaBuf,
) -> HsmResult<()> {
    let raw = pta_sec1_to_raw(pub_sec1)?;
    key_id_set(pal, io, PartPropId::PTA_KEY_ID, key_id)?;
    pal.part_prop_set_bytes(io, PartPropId::PTA_PUB_KEY, raw)
}

/// BK3 session key (48 B). **Sensitive.**
pub fn part_bk3_session<'a>(
    pal: &'a impl HsmPartitionManager,
    io: &impl HsmIo,
) -> HsmResult<&'a DmaBuf> {
    pal.part_prop_get_bytes(io, PartPropId::BK3_SESSION)
}

/// Set the BK3 session key (48 B).
pub fn part_set_bk3_session(
    pal: &impl HsmPartitionManager,
    io: &impl HsmIo,
    data: &DmaBuf,
) -> HsmResult<()> {
    pal.part_prop_set_bytes(io, PartPropId::BK3_SESSION, data)
}

/// Whether the partition has completed one-shot BK3 initialization.
pub fn part_is_bk3_initialized(pal: &impl HsmPartitionManager, io: &impl HsmIo) -> HsmResult<bool> {
    pal.part_prop_get_bool(io, PartPropId::BK3_INITIALIZED)
}

/// Atomically commit the partition's one-shot BK3 init state to
/// `true`.  Returns [`HsmError::Bk3AlreadyInitialized`] if the flag
/// was already set in the current partition incarnation.  This is the
/// authoritative race-winner gate for `DdiInitBk3`.
pub fn part_mark_bk3_initialized(pal: &impl HsmPartitionManager, io: &impl HsmIo) -> HsmResult<()> {
    pal.part_prop_set_bool(io, PartPropId::BK3_INITIALIZED, true)
}

/// Current owner-seed (BKS2) selector (BKS2 lineage; always 0 today).
///
/// Device-global (not per-partition); served by
/// [`HsmSeedStore::owner_svn`](azihsm_fw_hsm_pal_traits::HsmSeedStore::owner_svn).
pub fn part_owner_svn(pal: &impl HsmSeedStore) -> u64 {
    pal.owner_svn()
}
