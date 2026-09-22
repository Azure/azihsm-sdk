// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_emu::DdiEmu;
use azihsm_ddi_tbor_types::MAC_FIN_LEN;
use azihsm_ddi_tbor_types::PK_INIT_LEN;
use azihsm_ddi_tbor_types::SEED_ENVELOPE_LEN;
use azihsm_ddi_tbor_types::SESSION_SEED_LEN;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256;
use azihsm_ddi_tbor_types::TborGetCertChainInfoReq;
use azihsm_ddi_tbor_types::TborGetCertReq;
use azihsm_ddi_tbor_types::TborSessionCloseReq;
use azihsm_ddi_tbor_types::TborSessionCloseResp;
use azihsm_ddi_tbor_types::TborSessionOpenFinishReq;
use azihsm_ddi_tbor_types::TborSessionOpenInitReq;
use azihsm_ddi_tbor_types::TborSessionOpenInitResp;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_crypto::aead_envelope;
use azihsm_crypto::aead_envelope::AeadAlg;
use azihsm_crypto::AesKey;
use azihsm_crypto::EccCurve;
use azihsm_crypto::EccPrivateKey;
use azihsm_crypto::EccPublicKey;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::PrivateKey;
use azihsm_session_ex_crypto::build_hpke_info;
use azihsm_session_ex_crypto::build_phase2_mac;
use azihsm_session_ex_crypto::default_psk;
use azihsm_session_ex_crypto::derive_param_key;
use azihsm_session_ex_crypto::ec_pub_to_sec1;
use azihsm_session_ex_crypto::receive_exported;
use azihsm_session_ex_crypto::SessionExCryptoError;
use azihsm_session_ex_crypto::SessionExCryptoResult;
use azihsm_session_ex_crypto::VmEphemeralKey;
use x509::X509CertificateOp;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// P-384 coordinate length in bytes.
const P384_COORD_LEN: usize = 48;

/// AEAD-GCM IV length in bytes.
const AES_GCM_IV_LEN: usize = 12;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // input for SessionOpenInit
    valid_open_init: bool,
    psk_id: u8,
    session_type: u8,
    suite_id: u8,
    pk_init: [u8; PK_INIT_LEN],
    pk_init_scalar: [u8; P384_COORD_LEN],
    // When building a valid request, pick the CO/`Authenticated` psk_id +
    // session_type combo instead of CU/`PlainText`, so the mac_tx/mac_rx
    // key-derivation branch in `derive_remaining_keys` gets exercised.
    valid_use_authenticated: bool,

    // input for SessionOpenFinish
    valid_open_finish: bool,
    mac_fin: [u8; MAC_FIN_LEN],
    seed_envelope: [u8; SEED_ENVELOPE_LEN],
    seed_iv: [u8; AES_GCM_IV_LEN],
    // When `valid_open_finish` is true, corrupt the otherwise-valid
    // `seed_envelope` so the Phase-2 MAC still verifies but the AEAD-open
    // of the envelope fails, exercising that distinct failure path.
    corrupt_seed_envelope: bool,
}

/// Build a deterministic P-384 keypair from a fixed scalar, so the
/// fuzzer's mutations to `pk_init_scalar` reproduce the same keypair.
fn generate_deterministic_ephemeral(
    scalar: &[u8; P384_COORD_LEN],
) -> SessionExCryptoResult<VmEphemeralKey> {
    let sk = EccPrivateKey::from_scalar(EccCurve::P384, scalar)
        .map_err(|_| SessionExCryptoError::Crypto)?;
    let pk = sk.public_key().map_err(|_| SessionExCryptoError::Crypto)?;
    let pk_sec1 = ec_pub_to_sec1(&pk)?;
    Ok(VmEphemeralKey { sk, pk_sec1, pk })
}

/// Same as `session_ex_crypto::seal_seed_envelope`, but takes the
/// 12-byte AEAD-GCM IV as an input rather than generating it randomly.
fn seal_seed_envelope_with_iv(
    param_key: &AesKey,
    seed: &[u8],
    iv: &[u8; AES_GCM_IV_LEN],
) -> SessionExCryptoResult<Vec<u8>> {
    if seed.len() != SESSION_SEED_LEN {
        return Err(SessionExCryptoError::InvalidInput);
    }

    let total = aead_envelope::seal(AeadAlg::AesGcm256, param_key, iv, &[], seed, None)
        .map_err(|_| SessionExCryptoError::Crypto)?;
    if total != SEED_ENVELOPE_LEN {
        return Err(SessionExCryptoError::Crypto);
    }
    let mut envelope = vec![0u8; SEED_ENVELOPE_LEN];
    let written = aead_envelope::seal(
        AeadAlg::AesGcm256,
        param_key,
        iv,
        &[],
        seed,
        Some(&mut envelope),
    )
    .map_err(|_| SessionExCryptoError::Crypto)?;
    if written != SEED_ENVELOPE_LEN {
        return Err(SessionExCryptoError::Crypto);
    }
    Ok(envelope)
}

fuzz_target!(|input: FuzzInput| {
    let Ok(dev) = common::open_emu_dev() else { return; };

    let (req, ephemeral) = if input.valid_open_init || input.valid_open_finish {
        let Ok(ephemeral) = generate_deterministic_ephemeral(&input.pk_init_scalar) else { return; };
        let (psk_id, session_type) = if input.valid_use_authenticated {
            (0, SessionType::Authenticated.to_u8())
        } else {
            (1, SessionType::PlainText.to_u8())
        };
        let req = TborSessionOpenInitReq {
            psk_id,
            session_type,
            suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
            pk_init: ephemeral.pk_sec1,
        };
        (req, Some(ephemeral))
    } else {
        let req = TborSessionOpenInitReq {
            psk_id: input.psk_id,
            session_type: input.session_type,
            suite_id: input.suite_id,
            pk_init: input.pk_init,
        };
        (req, None)
    };

    let mut cookie = None;

    // If session open succeeds, finish then close it afterwards.
    let init_result = dev.exec_op_tbor::<TborSessionOpenInitReq>(&req, None, &mut cookie);

    // assert open init success if expected
    if input.valid_open_init || input.valid_open_finish {
        assert!(init_result.is_ok(), "SessionOpenInit with valid input must succeed");
    }

    if let Ok(resp) = init_result {
        // if init succeeded, attempt SessionOpenFinish
        let valid_finish_req = if input.valid_open_finish {
            // `valid_open_finish` forces the valid-handshake branch above,
            // which always populates `ephemeral`
            let ephemeral = ephemeral
                .as_ref()
                .expect("ephemeral is Some whenever valid_open_finish is true");
            build_valid_finish_req(&dev, &req, &resp, ephemeral, &input)
        } else {
            None
        };

        let built_valid_finish = valid_finish_req.is_some();
        let open_finish_req = match valid_finish_req {
            Some(r) => r,
            None if input.valid_open_finish => {
                // Cleanup path: known-invalid request so FW destroys the
                // Pending slot we just allocated
                TborSessionOpenFinishReq {
                    session_id: resp.session_id,
                    mac_fin: [0u8; MAC_FIN_LEN],
                    seed_envelope: [0u8; SEED_ENVELOPE_LEN],
                }
            }
            None => TborSessionOpenFinishReq {
                session_id: resp.session_id,
                mac_fin: input.mac_fin,
                seed_envelope: input.seed_envelope,
            },
        };

        let mut open_finish_cookie = None;
        let finish_result = dev.exec_op_tbor::<TborSessionOpenFinishReq>(&open_finish_req, None, &mut open_finish_cookie);

        // assert open finish success only when we actually built a valid request
        if input.valid_open_finish {
            if !input.corrupt_seed_envelope {
                assert!(built_valid_finish, "a valid finish request must be built with valid input");
                assert!(finish_result.is_ok(), "SessionOpenFinish with valid input must succeed");
            }
            else {
                // If the seed envelope is corrupt, we expect the finish to fail
                assert!(finish_result.is_err(), "SessionOpenFinish with corrupt seed envelope must fail");
            }
        }

        // SessionClose afterwards to clean up
        let close_req = TborSessionCloseReq {
            session_id: resp.session_id,
        };
        let mut close_cookie = None;
        let close_result: Result<TborSessionCloseResp, _> =
            dev.exec_op_tbor(&close_req, None, &mut close_cookie);

        // if session open finish succeeded, the session should be closable
        if finish_result.is_ok() {
            assert!(
                close_result.is_ok(),
                "SessionClose on a session opened this iteration must succeed"
            );
        }
        else {
            // Any SessionOpenFinish failure eagerly destroys the Pending slot in FW,
            // so a follow-up SessionClose on the same id must be rejected with
            // SessionNotFound (0x08700004)
            assert!(
                matches!(
                    close_result.as_ref(),
                    Err(DdiError::TborStatus(status)) if *status == TborStatus::SessionNotFound
                ),
                "SessionClose on a session that failed to open must fail with SessionNotFound"
            );
        }
    }
});

/// Build a fully valid `TborSessionOpenFinishReq` for the handshake
/// started by `resp`. Returns `None` on any crypto/emulator failure so
/// the caller can substitute a known-invalid request that forces
/// firmware to destroy the Pending slot (dropping `DdiEmuDev` cannot).
fn build_valid_finish_req(
    dev: &<DdiEmu as Ddi>::Dev,
    req: &TborSessionOpenInitReq,
    resp: &TborSessionOpenInitResp,
    ephemeral: &VmEphemeralKey,
    input: &FuzzInput,
) -> Option<TborSessionOpenFinishReq> {
    let (pk_hsm_key, pk_hsm_sec1) = fetch_pk_hsm(dev).ok()?;
    let info = build_hpke_info(req.psk_id, req.session_type, req.suite_id);
    let psk = default_psk(req.psk_id).ok()?;
    let exported = receive_exported(
        &ephemeral.sk,
        &ephemeral.pk,
        &pk_hsm_key,
        &resp.pk_resp,
        &info,
        psk,
        &[req.psk_id],
    )
    .ok()?;

    // Verify phase 1 MAC to ensure exported key material matches firmware before Phase 2
    azihsm_session_ex_crypto::verify_phase1_mac(
        &exported,
        resp.session_id,
        &req.pk_init,
        &pk_hsm_sec1,
        &resp.pk_resp,
        &resp.mac_resp,
    )
    .ok()?;

    let mac_fin = build_phase2_mac(
        &exported,
        resp.session_id,
        &req.pk_init,
        &pk_hsm_sec1,
        &resp.pk_resp,
    )
    .ok()?;

    let param_key = derive_param_key(&exported).ok()?;
    let seed = [0u8; SESSION_SEED_LEN];
    let mut seed_envelope_vec = seal_seed_envelope_with_iv(&param_key, &seed, &input.seed_iv).ok()?;
    if input.corrupt_seed_envelope {
        // Flip a byte in the ciphertext/tag so the Phase-2 MAC (computed
        // from `exported`/`pk_*`, not the envelope) still verifies, but the
        // AEAD-open of `seed_envelope` fails.
        let idx = seed_envelope_vec.len() - 1;
        seed_envelope_vec[idx] ^= 0x01;
    }
    let seed_envelope = seed_envelope_vec.as_slice().try_into().ok()?;

    Some(TborSessionOpenFinishReq {
        session_id: resp.session_id,
        mac_fin,
        seed_envelope,
    })
}

/// Fetches the HSM's leaf certificate (last entry in slot 0's chain) and
/// returns its public key in both parsed and raw SEC1 form; all failure
/// modes collapse to `()` since callers only need to bail out via `?`.
fn fetch_pk_hsm(
    dev: &<DdiEmu as Ddi>::Dev,
) -> Result<(EccPublicKey, [u8; PK_INIT_LEN]), ()> {
    let info_req = TborGetCertChainInfoReq::new(0);
    let mut info_cookie = None;
    let info = dev
        .exec_op_tbor(&info_req, None, &mut info_cookie)
        .map_err(|_| ())?;
    if info.num_certs == 0 {
        return Err(());
    }
    let cert_req = TborGetCertReq::new(0, info.num_certs - 1);
    let mut cert_cookie = None;
    let leaf = dev
        .exec_op_tbor(&cert_req, None, &mut cert_cookie)
        .map_err(|_| ())?;
    let cert = x509::X509Certificate::from_der(leaf.certificate.as_slice()).map_err(|_| ())?;
    let pk_der = cert.get_public_key_der().map_err(|_| ())?;
    let pk = EccPublicKey::from_bytes(&pk_der).map_err(|_| ())?;
    let sec1 = ec_pub_to_sec1(&pk).map_err(|_| ())?;
    Ok((pk, sec1))
}
