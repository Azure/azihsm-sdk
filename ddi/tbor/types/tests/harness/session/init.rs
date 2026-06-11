// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 1 of the TBOR session handshake — `OpenSessionInit`.
//!
//! Generates the VM's per-handshake ephemeral keypair, ships the
//! request, runs HPKE `receive_export` on the FW response, and
//! verifies the Phase-1 confirm MAC. Returns a [`PendingHandshake`]
//! that [`super::finish::open_session_finish`] consumes to complete
//! Phase 2.
//!
//! The convenience entry point [`open_session_init`] runs the happy
//! path with fresh ephemeral and the canonical default PSK. Negative
//! -path tests reach for [`OpenSessionInitOptions`] +
//! [`open_session_init_with_options`] to override individual knobs
//! (PSK, ephemeral keypair).

use azihsm_crypto::EccPrivateKey;
use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborOpenSessionInitReq;
use azihsm_ddi_tbor_types::TborOpenSessionInitResp;
use azihsm_ddi_tbor_types::PK_INIT_LEN;
use azihsm_ddi_tbor_types::SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256;

use super::crypto;
use super::crypto::VmEphemeralKey;

/// State carried between Phase 1 and Phase 2 of the handshake.
/// The caller may construct this directly to drive negative-path
/// tests (e.g., tamper `exported` to force a Phase-2 MAC mismatch);
/// the happy-path helper [`open_session_init`] populates it from a
/// real round-trip.
#[derive(Debug)]
pub struct PendingHandshake {
    /// Reserved session identifier returned by the FW.
    pub session_id: u16,
    /// Caller-selected PSK id (0 = CO, 1 = CU).
    pub psk_id: u8,
    /// Caller-selected channel integrity profile.
    pub session_type: SessionType,
    /// HPKE export secret (`Nh = 48`) derived by HPKE
    /// `receive_export` after Phase 1 completes.
    pub exported: Vec<u8>,
    /// Wire `pk_init` (SEC1 uncompressed, 97 B).
    pub pk_init: [u8; PK_INIT_LEN],
    /// Wire `pk_resp` (SEC1 uncompressed, 97 B).
    pub pk_resp: [u8; PK_INIT_LEN],
    /// Wire `pk_hsm` (SEC1 uncompressed, 97 B) — partition identity
    /// public key fetched out-of-band via the MBOR cert chain.
    pub pk_hsm: [u8; PK_INIT_LEN],
}

/// Override knobs for [`open_session_init_with_options`].
///
/// `None` fields use the happy-path default (fresh ephemeral,
/// partition default PSK). Tests set only the fields they need to
/// override.
pub struct OpenSessionInitOptions<'a> {
    /// PSK id (0 = CO, 1 = CU). Required.
    pub psk_id: u8,
    /// Channel integrity profile. Required.
    pub session_type: SessionType,
    /// Cryptographic suite identifier sent on the wire and mixed into
    /// the HPKE info string.  Defaults to
    /// `SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256` (`0x01`) — today's
    /// only supported suite.  Tests that exercise the unsupported-suite
    /// negative path set this to a non-`0x01` value.
    pub suite_id: u8,
    /// Override the VM ephemeral keypair. Both `sk_init` and the
    /// matching `pk_init` SEC1 bytes must be supplied together.
    /// Default: freshly generated P-384 ephemeral.
    pub ephemeral: Option<(EccPrivateKey, [u8; PK_INIT_LEN])>,
    /// Override the PSK bytes fed into the HPKE auth-psk schedule.
    /// Default: `DEFAULT_PSK_CO` for `psk_id=0`, `DEFAULT_PSK_CU` for
    /// `psk_id=1`. Tests that exercise a rotated PSK pass the
    /// rotated bytes here.
    pub psk: Option<&'a [u8]>,
}

impl<'a> OpenSessionInitOptions<'a> {
    /// Construct an options block with happy-path defaults for the
    /// given `psk_id` and `session_type`.
    pub fn new(psk_id: u8, session_type: SessionType) -> Self {
        Self {
            psk_id,
            session_type,
            suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
            ephemeral: None,
            psk: None,
        }
    }

    /// Builder shortcut: override the PSK bytes.
    pub fn with_psk(mut self, psk: &'a [u8]) -> Self {
        self.psk = Some(psk);
        self
    }

    /// Builder shortcut: override the VM ephemeral keypair.
    pub fn with_ephemeral(mut self, sk: EccPrivateKey, pk_sec1: [u8; PK_INIT_LEN]) -> Self {
        self.ephemeral = Some((sk, pk_sec1));
        self
    }

    /// Builder shortcut: override the wire `suite_id`.  Used by
    /// negative tests that exercise the unsupported-suite path.
    pub fn with_suite_id(mut self, suite_id: u8) -> Self {
        self.suite_id = suite_id;
        self
    }
}

/// Convenience wrapper: happy-path `OpenSessionInit` with fresh
/// ephemeral and partition default PSK.
///
/// Equivalent to
/// `open_session_init_with_options(dev, OpenSessionInitOptions::new(psk_id, session_type))`.
pub fn open_session_init(
    dev: &<AzihsmDdi as Ddi>::Dev,
    psk_id: u8,
    session_type: SessionType,
) -> Result<PendingHandshake, DdiError> {
    open_session_init_with_options(dev, OpenSessionInitOptions::new(psk_id, session_type))
}

/// Full-control entry point. Honours every override in `opts`;
/// fills in happy-path defaults for the rest.
pub fn open_session_init_with_options(
    dev: &<AzihsmDdi as Ddi>::Dev,
    opts: OpenSessionInitOptions<'_>,
) -> Result<PendingHandshake, DdiError> {
    let (sk_init, pk_init_sec1, pk_init_key) = match opts.ephemeral {
        Some((sk, pk_sec1)) => {
            let pk = crypto::ec_pub_from_sec1(&pk_sec1)?;
            (sk, pk_sec1, pk)
        }
        None => {
            let VmEphemeralKey { sk, pk_sec1, pk } = crypto::generate_vm_ephemeral()?;
            (sk, pk_sec1, pk)
        }
    };

    let (pk_hsm_key, pk_hsm_sec1) = crypto::fetch_pk_hsm(dev)?;

    let req = TborOpenSessionInitReq {
        psk_id: opts.psk_id,
        session_type: opts.session_type.to_u8(),
        suite_id: opts.suite_id,
        pk_init: pk_init_sec1,
    };
    let mut cookie = None;
    let resp: TborOpenSessionInitResp = dev.exec_op_tbor(&req, &mut cookie)?;

    let info = crypto::build_hpke_info(opts.psk_id, opts.session_type.to_u8(), opts.suite_id);
    let default_psk = crypto::default_psk(opts.psk_id)?;
    let psk: &[u8] = opts.psk.unwrap_or(default_psk.as_slice());
    let exported = crypto::receive_exported(
        &sk_init,
        &pk_init_key,
        &pk_hsm_key,
        &resp.pk_resp,
        &info,
        psk,
        &[opts.psk_id],
    )?;

    crypto::verify_phase1_mac(
        &exported,
        resp.session_id,
        &pk_init_sec1,
        &pk_hsm_sec1,
        &resp.pk_resp,
        &resp.mac_resp,
    )?;

    Ok(PendingHandshake {
        session_id: resp.session_id,
        psk_id: opts.psk_id,
        session_type: opts.session_type,
        exported,
        pk_init: pk_init_sec1,
        pk_resp: resp.pk_resp,
        pk_hsm: pk_hsm_sec1,
    })
}
