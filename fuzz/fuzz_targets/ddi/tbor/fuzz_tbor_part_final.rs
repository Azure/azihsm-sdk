// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_test_harness::x509_fixture::PtaChain;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::MAX_CERTS;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POLICY_INFO_LEN;
use azihsm_ddi_tbor_types::POLICY_MAX_KEY_LEN;
use azihsm_ddi_tbor_types::POLICY_VERSION_MAJOR;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::PolicyPubKey;
use azihsm_ddi_tbor_types::PolicyVer;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

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
    let max = LOCAL_MK_BACKUP_LEN * 4;
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

    /// `true` iff this mutation would leave the valid chain unchanged
    /// (matches the `None` variant, or a no-op offset/mask/len/extra
    /// choice inside a mutation variant). Drives the "expect success"
    /// classification for the result assertion.
    fn is_noop(&self, valid: &PtaChain) -> bool {
        match self {
            ChainMutation::None => true,
            ChainMutation::FlipByte { item, mask, .. } => {
                if *mask == 0 {
                    return true;
                }
                let target = match item {
                    ChainItem::Root => &valid.root_der,
                    ChainItem::Pta => &valid.pta_der,
                };
                target.is_empty()
            }
            ChainMutation::Truncate { item, len } => {
                let target = match item {
                    ChainItem::Root => &valid.root_der,
                    ChainItem::Pta => &valid.pta_der,
                };
                // `Vec::truncate(new_len)` only shrinks when `new_len <
                // target.len()`; `apply` computes `len % (target.len() + 1)`
                // so a no-op requires the modulo to land on `target.len()`.
                (*len as usize) % (target.len() + 1) == target.len()
            }
            ChainMutation::Append { extra, .. } => extra.is_empty(),
            ChainMutation::Replace(_) => false,
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
        // Fresh-slate CO session under a rotated (non-default) PSK — the
        // gate `PartInit` / `PartFinal` need cleared before the fuzzed
        // opcode can fire.
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

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
        // Snapshot noop-ness against the pre-mutation chain; `apply`
        // consumes the chain immediately after.
        let chain_is_noop = input.chain_mutation.is_noop(&valid_chain);
        let chain_items = input.chain_mutation.apply(valid_chain);
        let cert_slices: Vec<&[u8]> = chain_items.iter().map(|v| v.as_slice()).collect();

        // Classify the fuzzed inputs by deterministic outcome so we can
        // catch bugs where a valid input is rejected or an invalid input
        // is accepted (silent regressions the `let _` discard would hide).
        //
        // * expect_success: chain is unchanged from the valid root → PTA
        //   pair AND the backup is empty (first-instantiation path) — the
        //   only combination whose success does not depend on AEAD /
        //   signature outcomes over fuzzed bytes.
        // * expect_failure: the request violates the wire schema before
        //   the FW can act on it — `cert_descriptors` outside
        //   `1..=MAX_CERTS` (0 certs → placeholder + no OOB, > MAX_CERTS
        //   → encoder over-length reject), or a backup that overflows
        //   `LOCAL_MK_BACKUP_LEN`. Any other combination has a
        //   probabilistic outcome (arbitrary bytes could occasionally
        //   parse) and is left unasserted.
        let expect_success = chain_is_noop && input.prev_local_mk_backup.is_empty();
        let expect_failure = input.prev_local_mk_backup.len() > LOCAL_MK_BACKUP_LEN
            || chain_items.is_empty()
            || chain_items.len() > MAX_CERTS;

        let result = ctx.part_final(&session, &policy, &input.prev_local_mk_backup, &cert_slices);

        if expect_success {
            result.expect("PartFinal should succeed for a valid chain with an empty backup");
        } else if expect_failure {
            assert!(
                result.is_err(),
                "PartFinal should reject wire-schema-invalid input"
            );
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
