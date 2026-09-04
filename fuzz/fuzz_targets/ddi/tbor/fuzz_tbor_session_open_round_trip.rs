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
use azihsm_crypto::EccPublicKey;
use azihsm_crypto::Rng;
use azihsm_session_ex_crypto::build_hpke_info;
use azihsm_session_ex_crypto::build_phase2_mac;
use azihsm_session_ex_crypto::default_psk;
use azihsm_session_ex_crypto::derive_param_key;
use azihsm_session_ex_crypto::ec_pub_to_sec1;
use azihsm_session_ex_crypto::generate_vm_ephemeral;
use azihsm_session_ex_crypto::receive_exported;
use azihsm_session_ex_crypto::seal_seed_envelope;
use azihsm_crypto::ImportableKey;
use x509::X509CertificateOp;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    // input for SessionOpenInit
    valid_open_init: bool,
    psk_id: u8,
    session_type: u8,
    suite_id: u8,
    pk_init: [u8; PK_INIT_LEN],

    // input for SessionOpenFinish
    valid_open_finish: bool,
    mac_fin: [u8; MAC_FIN_LEN],
    seed_envelope: [u8; SEED_ENVELOPE_LEN],
}

fuzz_target!(|input: FuzzInput| {
    let dev = common::open_emu_dev();
    let use_valid_init = input.valid_open_init || input.valid_open_finish;
    let (req, ephemeral, pk_hsm) = if use_valid_init {
        let ephemeral = match generate_vm_ephemeral() {
            Ok(ephemeral) => ephemeral,
            Err(error) => {
                println!("Failed to generate VM ephemeral key: {error}");
                return;
            }
        };
        let pk_hsm = match fetch_pk_hsm(&dev) {
            Ok(pk_hsm) => pk_hsm,
            Err(()) => {
                println!("Failed to fetch HSM public key");
                return;
            }
        };

        (
            TborSessionOpenInitReq {
                psk_id: 1,
                session_type: SessionType::PlainText.to_u8(),
                suite_id: SESSION_SUITE_P384_HKDF_SHA384_AES_GCM_256,
                pk_init: ephemeral.pk_sec1,
            },
            Some(ephemeral),
            Some(pk_hsm),
        )
    } else {
        (
            TborSessionOpenInitReq {
                psk_id: input.psk_id,
                session_type: input.session_type,
                suite_id: input.suite_id,
                pk_init: input.pk_init,
            },
            None,
            None,
        )
    };
    let mut cookie = None;

    // If session open succeeds, finish then close it afterwards.
    let init_result = dev.exec_op_tbor::<TborSessionOpenInitReq>(&req, None, &mut cookie);
    if let Ok(resp) = init_result {
        println!("SessionOpenInit succeeded with session_id: {}", resp.session_id);

        // if init succeeded, attempt SessionOpenFinish
        let open_finish_req = if input.valid_open_finish {
            let (ephemeral, (pk_hsm, pk_hsm_sec1)) = match (ephemeral.as_ref(), pk_hsm.as_ref()) {
                (Some(ephemeral), Some(pk_hsm)) => (ephemeral, pk_hsm),
                _ => return,
            };
            let info = build_hpke_info(
                req.psk_id,
                req.session_type,
                req.suite_id,
            );
            let psk = match default_psk(req.psk_id) {
                Ok(psk) => psk,
                Err(_) => return,
            };
            let exported = match receive_exported(
                &ephemeral.sk,
                &ephemeral.pk,
                pk_hsm,
                &resp.pk_resp,
                &info,
                psk,
                &[req.psk_id],
            ) {
                Ok(exported) => exported,
                Err(_) => return,
            };
            let mac_fin = match build_phase2_mac(
                &exported,
                resp.session_id,
                &req.pk_init,
                pk_hsm_sec1,
                &resp.pk_resp,
            ) {
                Ok(mac_fin) => mac_fin,
                Err(_) => return,
            };
            let param_key = match derive_param_key(&exported) {
                Ok(param_key) => param_key,
                Err(_) => return,
            };
            let mut seed = [0u8; SESSION_SEED_LEN];
            if Rng::rand_bytes(&mut seed).is_err() {
                return;
            }
            let seed_envelope = match seal_seed_envelope(&param_key, &seed)
                .and_then(|envelope| {
                    envelope
                        .as_slice()
                        .try_into()
                        .map_err(|_| azihsm_session_ex_crypto::SessionExCryptoError::InvalidInput)
                }) {
                Ok(seed_envelope) => seed_envelope,
                Err(_) => return,
            };

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
        if let Err(error) =
            dev.exec_op_tbor::<TborSessionOpenFinishReq>(&open_finish_req, None, &mut open_finish_cookie)
        {
            println!("SessionOpenFinish failed with error code: {error}");
        } else {
            println!("SessionOpenFinish succeeded for session_id: {}", resp.session_id);
        }

        // SessionClose afterwards to clean up
        let close_req = TborSessionCloseReq {
            session_id: resp.session_id,
        };
        let mut close_cookie = None;
        if let Err(error) = dev.exec_op_tbor(&close_req, None, &mut close_cookie) {
            println!("SessionClose failed with error code: {error}");
        } else {
            println!("SessionClose succeeded for session_id: {}", resp.session_id);
        }
    } else if let Err(error) = init_result {
        println!("SessionOpenInit failed with error code: {error}");
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
