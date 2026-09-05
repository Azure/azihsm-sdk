// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdCreatePeerBackup` command.
//!
//! `SdCreatePeerBackup` recovers BKS3 from the caller's device-local
//! backup (`pok_local_backup`) and HPKE-Auth-seals it to a destination
//! peer named by `dst_evidence` — authenticated by the sender's own masked
//! SD-sealing key — returning the peer backup (`pok_peer_backup`, a 161-byte
//! HPKE seal).  It is **stateless** and gated by the security domain's
//! `allow_peer_cloning` policy flag.
//!
//! These tests run a **self-peer** backup (sender == receiver): one
//! partition mints an SD sealing key, attests it via `KeyReport`, creates
//! its security domain, and then re-seals the recovered BKS3 to its own
//! attested public key.
//!
//! Coverage:
//! * Round-trip — non-zero 161-byte `pok_peer_backup`.
//! * Policy without `allow_peer_cloning` → `SdPeerCloningNotAllowed`.
//! * Not finalized → `InvalidArg`.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdCreatePeerBackupReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use zerocopy::TryFromBytes;

use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::sd_create_remote_backup::backing_part_policy;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::masked_key_and_report;
use crate::commands::sd_create_remote_backup::ReceiverEvidence;
use crate::harness::bootstrap_rotated_co;
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::x509_fixture::RAW_PUB_LEN;
use crate::harness::SessionHandshake;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;

/// Byte offset of the `flags` field in the 484-byte `PartPolicy` image.
const OFF_FLAGS: usize = 418;

/// `PolicyFlags::ALLOW_PEER_CLONING` (bit 2) — mirror of the firmware
/// policy flag that gates the peer-backup commands.
const ALLOW_PEER_CLONING: u8 = 1 << 2;

/// A finalized backing partition ready for the peer-backup commands: the
/// live CO session, its exact policy image, its PID public key (every
/// evidence leaf certifies it), and `PartFinal`'s `local_mk_backup`
/// (replayed on a rebooted peer to restore `PartLocalMK`).
pub(crate) struct PeerPartition {
    pub(crate) session: SessionHandshake,
    pub(crate) policy: [u8; PART_POLICY_LEN],
    pub(crate) pid_pub: [u8; RAW_PUB_LEN],
    pub(crate) local_mk_backup: Vec<u8>,
}

/// Drive `PartInit → PartFinal` on `ctx` with a backing-partition policy
/// anchored to `sata`/`pota`, optionally opting the security domain into
/// peer cloning.  The same policy image must be replayed verbatim by the
/// peer-backup commands (for the `policy_hash` re-check).
pub(crate) fn finalize_peer_partition(
    ctx: &TestCtx,
    seed: &[u8],
    sata: &CaKey,
    pota: &CaKey,
    allow_cloning: bool,
) -> PeerPartition {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

    let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&info.pid_pub_key);

    let mut policy = backing_part_policy(
        &info.pid,
        &info.pid_pub_key,
        &sata.raw_pub(),
        &pota.raw_pub(),
    );
    if allow_cloning {
        policy[OFF_FLAGS] |= ALLOW_PEER_CLONING;
    }

    let init = ctx
        .part_init(&session, seed, &policy, &pota_thumbprint())
        .expect("PartInit");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    let local_mk_backup = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal")
        .local_mk_backup;

    PeerPartition {
        session,
        policy,
        pid_pub,
        local_mk_backup,
    }
}

/// Assemble a `SdCreatePeerBackup` request from a masked sealing key,
/// destination evidence, policy, and the local backup to re-seal.
pub(crate) fn create_peer_req(
    session_id: u16,
    masked_sealing_key: &[u8],
    evidence: &ReceiverEvidence,
    policy: &[u8; PART_POLICY_LEN],
    pok_local_backup: &[u8; MASKED_SD_LEN],
) -> TborSdCreatePeerBackupReq {
    TborSdCreatePeerBackupReq {
        session_id,
        masked_sealing_key: masked_sealing_key
            .try_into()
            .expect("masked sealing key is exactly MASKED_SEALING_KEY_LEN bytes"),
        policy: PartPolicy::try_read_from_bytes(policy).expect("policy image is canonical"),
        dst_mfgr_cert_chain: evidence.mfgr.clone(),
        dst_owner_cert_chain: evidence.owner.clone(),
        dst_part_owner_cert_chain: evidence.part_owner.clone(),
        dst_report: evidence.report,
        pok_local_backup: *pok_local_backup,
    }
}

#[test]
fn sd_create_peer_backup_roundtrip_emu() {
    let ctx = TestCtx::new();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let part = finalize_peer_partition(&ctx, &mach_seed(), &sata, &pota, true);
    let session_id = part.session.session_id;

    // Mint + attest a sealing key, then create the security domain to
    // obtain the device-local backup this command re-seals.
    let (masked, report) = masked_key_and_report(&ctx, session_id, &part.policy);
    let evidence = build_receiver_evidence(&part.pid_pub, &sata, &report);
    let created = ctx
        .tbor_oob(
            &backup_request(session_id, masked.clone(), &evidence, &part.policy),
            &evidence.oob(),
        )
        .expect("SdCreateRemoteBackup");

    let req = create_peer_req(
        session_id,
        &masked,
        &evidence,
        &part.policy,
        &created.pok_local_backup,
    );
    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("SdCreatePeerBackup roundtrip");

    assert_eq!(resp.pok_peer_backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        resp.pok_peer_backup.iter().any(|&b| b != 0),
        "pok_peer_backup must not be all-zero",
    );
}

#[test]
fn sd_create_peer_backup_rejects_without_peer_cloning_emu() {
    let ctx = TestCtx::new();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Finalize with a policy that does NOT opt into peer cloning.
    let part = finalize_peer_partition(&ctx, &mach_seed(), &sata, &pota, false);
    let session_id = part.session.session_id;

    // A real sealing key + evidence so the request reaches the policy gate;
    // the peer-cloning check fires before any local backup is unmasked, so
    // a zero `pok_local_backup` is sufficient.
    let (masked, report) = masked_key_and_report(&ctx, session_id, &part.policy);
    let evidence = build_receiver_evidence(&part.pid_pub, &sata, &report);
    let req = create_peer_req(
        session_id,
        &masked,
        &evidence,
        &part.policy,
        &[0u8; MASKED_SD_LEN],
    );
    ctx.expect_fw_reject_oob(&req, &evidence.oob(), TborStatus::SdPeerCloningNotAllowed);
}

#[test]
fn sd_create_peer_backup_rejects_before_finalize_emu() {
    // A partition that has not been finalized is rejected at the lifecycle
    // gate before any evidence or crypto work.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let req = TborSdCreatePeerBackupReq {
        session_id: session.session_id,
        masked_sealing_key: [0u8; 180],
        policy: PartPolicy::zeroed(),
        dst_mfgr_cert_chain: Vec::new(),
        dst_owner_cert_chain: Vec::new(),
        dst_part_owner_cert_chain: Vec::new(),
        dst_report: Default::default(),
        pok_local_backup: [0u8; MASKED_SD_LEN],
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}
