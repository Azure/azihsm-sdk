// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_test_harness::SessionOpenInitOptions;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_test_harness::x509_fixture::PtaChain;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POLICY_INFO_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::POLICY_VERSION_MAJOR;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::PolicyPubKey;
use azihsm_ddi_tbor_types::PolicyVer;
use azihsm_ddi_tbor_types::SessionType;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

const CO: u8 = 0;

/// Non-default CO PSK used to clear the default-PSK gate before `PartInit`.
const ROTATED_CO_PSK: [u8; PSK_LEN] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
];

/// Upper bound on a fuzzed per-cert DER: `MAX_CERT_DER_LEN` in the crypto
/// crate is 1024, so 2× that still exercises oversized rejects without
/// letting a single input eat the fuzzer's byte pool.
const FUZZ_MAX_CERT_LEN: usize = 2048;

/// Upper bound on the number of certs the fuzzer may synthesize for the
/// `Replace` mutation. Real chains are 2 (root → PTA); a small headroom is
/// enough to hit chain-length and per-item parse rejects without blowing
/// throughput.
const FUZZ_MAX_CHAIN_ITEMS: usize = 4;

fn bounded_prev_local_mk_backup(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    // Keep allocations bounded to improve fuzz throughput while still exercising invalid lengths.
    let max = azihsm_ddi_tbor_types::LOCAL_MK_BACKUP_LEN * 4;
    let len = usize::arbitrary(u)? % (max + 1);
    Ok(u.bytes(len)?.to_vec())
}

fn bounded_appended_bytes(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = usize::arbitrary(u)? % (FUZZ_MAX_CERT_LEN + 1);
    Ok(u.bytes(len)?.to_vec())
}

fn bounded_fuzzed_chain(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Vec<Vec<u8>>> {
    let n = usize::arbitrary(u)? % (FUZZ_MAX_CHAIN_ITEMS + 1);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let len = usize::arbitrary(u)? % (FUZZ_MAX_CERT_LEN + 1);
        out.push(u.bytes(len)?.to_vec());
    }
    Ok(out)
}

/// Which slot of the valid root → PTA chain a mutation targets.
#[derive(Arbitrary, Debug)]
enum ChainItem {
    Root,
    Pta,
}

/// Post-generation mutation applied to the wire-valid PTA cert chain.
///
/// `None` ships the valid root → PTA chain untouched so the handler
/// advances past cert-chain validation into the `prev_local_mk_backup`
/// / policy-hash pipeline. The other variants exercise chain-reject
/// paths (signature tamper, truncation, over-length, and arbitrary
/// chains) without leaving them buried under negligible-probability
/// arbitrary-byte inputs.
#[derive(Arbitrary, Debug)]
enum ChainMutation {
    /// Ship the valid root → PTA chain unchanged.
    None,
    /// XOR a fuzzed mask into a fuzzed offset of the chosen chain item
    /// (offset wrapped modulo item length). Exercises signature and
    /// TBS-tampering rejects in the X.509 validator.
    FlipByte {
        item: ChainItem,
        offset: u16,
        mask: u8,
    },
    /// Truncate the chosen chain item to `len % (item.len() + 1)` bytes.
    /// Exercises short-DER and length-mismatch rejects.
    Truncate { item: ChainItem, len: u16 },
    /// Append fuzzed trailing bytes to the chosen chain item.
    /// Exercises over-length rejects.
    Append {
        item: ChainItem,
        #[arbitrary(with = bounded_appended_bytes)]
        extra: Vec<u8>,
    },
    /// Replace the entire chain with a caller-supplied list of
    /// arbitrary-byte certs. Exercises chain-length and per-item parse
    /// rejects.
    Replace(#[arbitrary(with = bounded_fuzzed_chain)] Vec<Vec<u8>>),
}

impl ChainMutation {
    /// Apply the mutation to the valid chain, returning the DER items in
    /// the root → PTA order `PartFinal` expects (or a fully synthetic
    /// chain for `Replace`).
    fn apply(&self, valid: PtaChain) -> Vec<Vec<u8>> {
        let PtaChain {
            mut root_der,
            mut pta_der,
        } = valid;
        match self {
            ChainMutation::None => vec![root_der, pta_der],
            ChainMutation::FlipByte { item, offset, mask } => {
                let target = match item {
                    ChainItem::Root => &mut root_der,
                    ChainItem::Pta => &mut pta_der,
                };
                if !target.is_empty() && *mask != 0 {
                    let idx = (*offset as usize) % target.len();
                    target[idx] ^= *mask;
                }
                vec![root_der, pta_der]
            }
            ChainMutation::Truncate { item, len } => {
                let target = match item {
                    ChainItem::Root => &mut root_der,
                    ChainItem::Pta => &mut pta_der,
                };
                let cap = target.len() + 1;
                target.truncate((*len as usize) % cap);
                vec![root_der, pta_der]
            }
            ChainMutation::Append { item, extra } => {
                let target = match item {
                    ChainItem::Root => &mut root_der,
                    ChainItem::Pta => &mut pta_der,
                };
                target.extend_from_slice(extra);
                vec![root_der, pta_der]
            }
            ChainMutation::Replace(items) => items.clone(),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Fuzzed prior local_mk backup (empty = first-instantiation path).
    #[arbitrary(with = bounded_prev_local_mk_backup)]
    prev_local_mk_backup: Vec<u8>,
    /// Fuzzed mutation applied to the PTA cert chain (`None` ships the
    /// valid chain so the handler advances past chain validation).
    chain_mutation: ChainMutation,
}

/// Build a `PartPolicy` with `pota_raw` (raw P-384 `X ‖ Y`) as the POTA
/// trust anchor so `PartFinal` can validate the cert chain against it.
///
/// Uses the shared [`PartPolicy`] struct + typed [`PolicyPubKey`] /
/// [`PolicyVer`] constructors so the on-wire byte layout tracks whatever
/// the policy crate declares (no hand-computed field offsets here).
fn part_policy_with_pota(pota_raw: &[u8; POLICY_MAX_KEY_LEN]) -> [u8; PART_POLICY_LEN] {
    use zerocopy::IntoBytes;

    let mut sata_data = [0u8; POLICY_MAX_KEY_LEN];
    for (i, b) in sata_data.iter_mut().enumerate() {
        *b = (0x20u8.wrapping_add(i as u8)) | 0x80;
    }

    let policy = PartPolicy {
        version: PolicyVer {
            major: POLICY_VERSION_MAJOR,
            minor: 0,
        },
        pota_pub_key: PolicyPubKey::new(
            PolicyKeyKind::Ecc384,
            POLICY_MAX_KEY_LEN as u16,
            *pota_raw,
        ),
        sata_pub_key: PolicyPubKey::new(
            PolicyKeyKind::Ecc384,
            POLICY_MAX_KEY_LEN as u16,
            sata_data,
        ),
        info: [0xAB; POLICY_INFO_LEN],
        ..PartPolicy::zeroed()
    };

    let mut bytes = [0u8; PART_POLICY_LEN];
    bytes.copy_from_slice(policy.as_bytes());
    bytes
}

fn mach_seed() -> [u8; MACH_SEED_LEN] {
    let mut v = [0u8; MACH_SEED_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x40 + i as u8;
    }
    v
}

fn pota_thumbprint() -> [u8; POTA_THUMBPRINT_LEN] {
    let mut v = [0u8; POTA_THUMBPRINT_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x80 ^ i as u8;
    }
    v
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        ctx.erase().expect("erase should succeed");

        // Rotate the CO PSK to clear the default-PSK gate before PartInit.
        let bootstrap = ctx
            .open_session(CO, SessionType::Authenticated)
            .expect("bootstrap session open should succeed");
        ctx.psk_change(bootstrap.handshake(), &ROTATED_CO_PSK)
            .expect("PSK rotation should succeed");
        bootstrap
            .close()
            .expect("bootstrap session close should succeed");

        // Open a CO session under the rotated PSK.
        let opts =
            SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(&ROTATED_CO_PSK);
        let pending = ctx
            .session_open_init_with_options(opts)
            .expect("session_open_init should succeed");
        let session = ctx
            .session_open_finish(pending)
            .expect("session_open_finish should succeed");

        // Generate a POTA trust anchor and embed its public key in the policy.
        let pota = CaKey::generate();
        let policy = part_policy_with_pota(&pota.raw_pub());

        // PartInit: transition the partition to PartState::Initializing.
        let init = ctx
            .part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
            .expect("PartInit should succeed");

        // Build the valid PTA chain anchored to the POTA key, then apply
        // the fuzzed mutation. The `None` variant ships the chain
        // untouched so `PartFinal` reaches the handler logic past cert
        // validation; the other variants exercise chain-reject paths.
        let pta_pub = pta_pub_from_csr(&init.pta_csr);
        let valid_chain = make_pta_chain(&pota, &pta_pub);
        let chain_items = input.chain_mutation.apply(valid_chain);
        let cert_slices: Vec<&[u8]> = chain_items.iter().map(|v| v.as_slice()).collect();

        let _ = ctx.part_final(&session, &policy, &input.prev_local_mk_backup, &cert_slices);

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
