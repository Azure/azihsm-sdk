// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_emu::DdiEmu;
use azihsm_ddi_mbor_types::*;
use azihsm_ddi_tbor_types::MAC_FIN_LEN;
use azihsm_ddi_tbor_types::PK_INIT_LEN;
use azihsm_ddi_tbor_types::SEED_ENVELOPE_LEN;
use azihsm_ddi_tbor_types::SESSION_SEED_LEN;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256;
use azihsm_ddi_tbor_types::TborSessionCloseReq;
use azihsm_ddi_tbor_types::TborSessionOpenFinishReq;
use azihsm_ddi_tbor_types::TborSessionOpenInitReq;
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
    pk_init_scalar: [u8; P384_COORD_LEN],

    // input for SessionOpenFinish
    valid_open_finish: bool,
    mac_fin: [u8; MAC_FIN_LEN],
    seed_envelope: [u8; SEED_ENVELOPE_LEN],
    seed_iv: [u8; AES_GCM_IV_LEN],
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
    let Ok(ephemeral) = generate_deterministic_ephemeral(&input.pk_init_scalar) else { return; };
    let Ok((pk_hsm_key, pk_hsm_sec1)) = fetch_pk_hsm(&dev) else { return; };

    let req = if input.valid_open_init || input.valid_open_finish {
        TborSessionOpenInitReq {
            psk_id: 1,
            session_type: SessionType::PlainText.to_u8(),
            suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
            pk_init: ephemeral.pk_sec1,
        }
    } else {
        TborSessionOpenInitReq {
            psk_id: input.psk_id,
            session_type: input.session_type,
            suite_id: input.suite_id,
            pk_init: ephemeral.pk_sec1,
        }
    };

    let mut cookie = None;
    let init_result = dev.exec_op_tbor::<TborSessionOpenInitReq>(&req, None, &mut cookie);
    println!("TborSessionOpenInitReq result: {:?}", init_result);

    if let Ok(resp) = init_result {
        let open_finish_req = if input.valid_open_finish {
            let info = build_hpke_info(req.psk_id, req.session_type, req.suite_id);
            let Ok(psk) = default_psk(req.psk_id) else { return; };
            let Ok(exported) = receive_exported(
                &ephemeral.sk,
                &ephemeral.pk,
                &pk_hsm_key,
                &resp.pk_resp,
                &info,
                psk,
                &[req.psk_id],
            ) else { return; };

            // Verify phase 1 MAC to ensure exported key material matches firmware before Phase 2
            if azihsm_session_ex_crypto::verify_phase1_mac(
                &exported,
                resp.session_id,
                &req.pk_init,
                &pk_hsm_sec1,
                &resp.pk_resp,
                &resp.mac_resp,
            ).is_err() {
                return;
            }

            let Ok(mac_fin) = build_phase2_mac(
                &exported,
                resp.session_id,
                &req.pk_init,
                &pk_hsm_sec1,
                &resp.pk_resp,
            ) else { return; };

            let Ok(param_key) = derive_param_key(&exported) else { return; };
            let seed = [0u8; SESSION_SEED_LEN];
            let Ok(seed_envelope_vec) = seal_seed_envelope_with_iv(&param_key, &seed, &input.seed_iv) else { return; };
            let Ok(seed_envelope) = seed_envelope_vec.as_slice().try_into() else { return; };

            TborSessionOpenFinishReq {
                session_id: resp.session_id,
                mac_fin,
                seed_envelope,
            }
        } else {
            TborSessionOpenFinishReq {
                session_id: resp.session_id,
                mac_fin: input.mac_fin,
                seed_envelope: input.seed_envelope,
            }
        };

        let mut open_finish_cookie = None;
        let finish_result = dev.exec_op_tbor::<TborSessionOpenFinishReq>(
            &open_finish_req,
            None,
            &mut open_finish_cookie,
        );
        println!("TborSessionOpenFinishReq result: {:?}", finish_result);

        let close_req = TborSessionCloseReq {
            session_id: resp.session_id,
        };
        let mut close_cookie = None;
        let _ = dev.exec_op_tbor(&close_req, None, &mut close_cookie);
    }
});

fn fetch_pk_hsm(
    dev: &<DdiEmu as Ddi>::Dev,
) -> Result<(EccPublicKey, [u8; PK_INIT_LEN]), ()> {
    let info_req = DdiGetCertChainInfoCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetCertChainInfo,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetCertChainInfoReq { slot_id: 0 },
        ext: None,
    };
    let mut info_cookie = None;
    let info = dev.exec_op_mbor(&info_req, &mut info_cookie).map_err(|_| ())?;
    if info.data.num_certs == 0 {
        return Err(());
    }
    let cert_req = DdiGetCertificateCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetCertificate,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetCertificateReq {
            slot_id: 0,
            cert_id: info.data.num_certs - 1,
        },
        ext: None,
    };
    let mut cert_cookie = None;
    let leaf = dev
        .exec_op_mbor(&cert_req, &mut cert_cookie)
        .map_err(|_| ())?;
    let cert = x509::X509Certificate::from_der(leaf.data.certificate.as_slice()).map_err(|_| ())?;
    let pk_der = cert.get_public_key_der().map_err(|_| ())?;
    let pk = EccPublicKey::from_bytes(&pk_der).map_err(|_| ())?;
    let sec1 = ec_pub_to_sec1(&pk).map_err(|_| ())?;
    Ok((pk, sec1))
}
