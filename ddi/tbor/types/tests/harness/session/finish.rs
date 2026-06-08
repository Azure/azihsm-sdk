// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 2 of the TBOR session handshake — `OpenSessionFinish`.
//!
//! Generates a fresh 32-byte `seed`, derives `param_key` from the
//! HPKE export, AEAD-seals the seed under `param_key`, computes the
//! Phase-2 confirm MAC from the [`PendingHandshake`] produced by
//! [`super::init::open_session_init`], ships both to the FW, and
//! folds the response into a [`SessionHandshake`] carrier that
//! downstream tests use to drive in-session commands.
//!
//! Negative-path tests reach for [`build_mac_fin`] +
//! [`open_session_finish_with_mac`] to ship a tampered or otherwise
//! caller-controlled `mac_fin`.

use azihsm_crypto::AesKey;
use azihsm_crypto::Rng;
use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborOpenSessionFinishReq;
use azihsm_ddi_tbor_types::TborOpenSessionFinishResp;
use azihsm_ddi_tbor_types::SEED_ENVELOPE_LEN;
use azihsm_ddi_tbor_types::SESSION_SEED_LEN;

use super::crypto;
use super::init::PendingHandshake;

/// Active session state carried through downstream in-session tests.
///
/// `param_key` is the per-session AES-256 key the host uses to seal
/// per-command parameter blobs as `aead_envelope` envelopes (e.g.,
/// the new PSK in `ChangePsk`). `bmk_session` is the FW's wrapped
/// masking-key envelope returned by `OpenSessionFinish`; it is
/// opaque to the host today (MBOR `ReopenSession` consumes it).
///
/// `exported` is retained so tests that need to re-derive
/// authenticated-session MAC keys (or any other label-derived
/// material) can do so via the [`derive_mac_tx_key`] /
/// [`derive_mac_rx_key`] accessors.
pub struct SessionHandshake {
    /// Active session identifier.
    pub session_id: u16,
    /// PSK id used for the handshake (0 = CO, 1 = CU).
    pub psk_id: u8,
    /// Channel integrity profile pinned at handshake time.
    pub session_type: SessionType,
    /// HPKE exported secret (`Nh = 48`) used to derive `param_key`
    /// and (for authenticated sessions) the MAC keys. Retained so
    /// tests can re-derive labelled material on demand.
    pub exported: Vec<u8>,
    /// Per-session AES-256 wrap key derived from the HPKE export.
    pub param_key: AesKey,
    /// FW-emitted wrapped masking-key blob — opaque to the host.
    pub bmk_session: Vec<u8>,
}

impl SessionHandshake {
    /// Re-derive the authenticated-session MAC TX key
    /// (`SESSION_MAC_TX_LABEL`). Callable for any session type;
    /// returns the bytes regardless of whether the FW actually
    /// installed them — `PlainText` sessions discard them.
    pub fn derive_mac_tx_key(&self) -> Result<Vec<u8>, DdiError> {
        crypto::derive_mac_tx_key(&self.exported)
    }

    /// Re-derive the authenticated-session MAC RX key
    /// (`SESSION_MAC_RX_LABEL`). See [`Self::derive_mac_tx_key`].
    pub fn derive_mac_rx_key(&self) -> Result<Vec<u8>, DdiError> {
        crypto::derive_mac_rx_key(&self.exported)
    }
}

impl core::fmt::Debug for SessionHandshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `param_key` deliberately omitted — it contains key material
        // and `AesKey` does not implement Debug.
        f.debug_struct("SessionHandshake")
            .field("session_id", &self.session_id)
            .field("psk_id", &self.psk_id)
            .field("session_type", &self.session_type)
            .field("exported_len", &self.exported.len())
            .field("bmk_session_len", &self.bmk_session.len())
            .finish_non_exhaustive()
    }
}

/// Compute the Phase-2 confirm MAC the host normally ships in
/// `mac_fin`. Exposed so negative-path tests can compute the canonical
/// MAC, tamper with it, and ship the result via
/// [`open_session_finish_with_mac`].
pub fn build_mac_fin(pending: &PendingHandshake) -> Result<[u8; 48], DdiError> {
    crypto::build_phase2_mac(
        &pending.exported,
        pending.session_id,
        &pending.pk_init,
        &pending.pk_hsm,
        &pending.pk_resp,
    )
}

/// Generate a fresh 32-byte handshake seed.
fn fresh_seed() -> Result<[u8; SESSION_SEED_LEN], DdiError> {
    let mut seed = [0u8; SESSION_SEED_LEN];
    Rng::rand_bytes(&mut seed).map_err(|_| DdiError::InvalidParameter)?;
    Ok(seed)
}

/// Run Phase 2 of the handshake. Consumes the [`PendingHandshake`]
/// so callers cannot accidentally reuse stale state for a second
/// `OpenSessionFinish` against the same Pending slot.
pub fn open_session_finish(
    dev: &<AzihsmDdi as Ddi>::Dev,
    pending: PendingHandshake,
) -> Result<SessionHandshake, DdiError> {
    let mac_fin = build_mac_fin(&pending)?;
    open_session_finish_with_mac(dev, pending, mac_fin)
}

/// Ship a caller-supplied `mac_fin` in `OpenSessionFinish`. The
/// `PendingHandshake` is still consumed.
///
/// On Phase-2 MAC mismatch the FW returns an error that surfaces here
/// as a [`DdiError`] from `exec_op_tbor`.
pub fn open_session_finish_with_mac(
    dev: &<AzihsmDdi as Ddi>::Dev,
    pending: PendingHandshake,
    mac_fin: [u8; 48],
) -> Result<SessionHandshake, DdiError> {
    let param_key = crypto::derive_param_key(&pending.exported)?;
    let seed = fresh_seed()?;
    let envelope = crypto::seal_seed_envelope(&param_key, &seed)?;
    let seed_envelope: [u8; SEED_ENVELOPE_LEN] = envelope
        .as_slice()
        .try_into()
        .map_err(|_| DdiError::TborDecodeError)?;

    let req = TborOpenSessionFinishReq {
        session_id: pending.session_id,
        mac_fin,
        seed_envelope,
    };
    let mut cookie = None;
    let resp: TborOpenSessionFinishResp = dev.exec_op_tbor(&req, &mut cookie)?;

    Ok(SessionHandshake {
        session_id: pending.session_id,
        psk_id: pending.psk_id,
        session_type: pending.session_type,
        exported: pending.exported,
        param_key,
        bmk_session: resp.bmk_session,
    })
}
