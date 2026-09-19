// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Reference values for the FP1 wolfCrypt ML-DSA-87 implementation.
//!
//! FP1 runs wolfCrypt, the host and the emulator run RustCrypto, and the DDI
//! test `ml_dsa_sign_verifies_on_host` asserts the two agree **byte for
//! byte**. Part 12 only ever established that FP1's signature *verified*,
//! which is a much weaker claim: many valid signatures exist for one key and
//! message, so a signature can verify and still not be the one the host
//! computes.
//!
//! This prints what FP1 must reproduce. FP1 cannot return kilobytes through
//! its debug log, so the comparison is on length plus a 64-bit FNV-1a digest,
//! which is a few lines of identical arithmetic on both sides and needs no
//! dependency the firmware does not already have.
//!
//! Run with:
//!
//! ```text
//! cargo test -p azihsm_fw_core_crypto_ml_dsa --test fp_reference -- --nocapture
//! ```
//!
//! The inputs match the FP1 probe exactly: seed `0,1,..,31` and a 32-byte
//! message `0xA5 + i`.

use ml_dsa::signature::Keypair;
use ml_dsa::MlDsa87;
use ml_dsa::SigningKey;

/// Seed the FP1 probe generates its key from.
const SEED: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

/// FNV-1a, 64-bit. Chosen because the same eight lines compile unchanged in
/// the firmware's C, so neither side can be "the one with the clever hash".
fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn report(label: &str, data: &[u8]) {
    let h = fnv1a64(data);
    println!(
        "{label:<14} len={:<5} fnv64={:016x}  hi={:08x} lo={:08x}  first8={:08x}{:08x} last8={:02x?}",
        data.len(),
        h,
        (h >> 32) as u32,
        h as u32,
        u32::from_le_bytes(data[0..4].try_into().unwrap()),
        u32::from_le_bytes(data[4..8].try_into().unwrap()),
        &data[data.len() - 8..],
    );
}

#[test]
fn ml_dsa_87_reference_values() {
    let msg: Vec<u8> = (0..32u8).map(|i| 0xA5u8.wrapping_add(i)).collect();

    let sk = SigningKey::<MlDsa87>::from_seed(&SEED.into());

    // The encoded verifying key, as `wc_MlDsaKey_ExportPubRaw` should produce.
    let vk = sk.verifying_key().encode().to_vec();

    // The *expanded* signing key, as `wc_MlDsaKey_ExportPrivRaw` should
    // produce. Whether wolfCrypt's raw private encoding matches RustCrypto's
    // expanded form is precisely what is unproven -- a mismatch here would
    // have surfaced much later as a signature that verifies on device and
    // nowhere else.
    #[allow(deprecated)]
    let sk_enc = sk.expanded_key().to_expanded().to_vec();

    // FIPS 204 deterministic signing: rnd = 0^32, empty context. FP1 has been
    // passing the signing key itself as the seed, which is valid but produces
    // a different signature.
    let sig = sk
        .expanded_key()
        .sign_deterministic(&msg, &[])
        .expect("host ML-DSA-87 sign")
        .encode()
        .to_vec();

    println!("\n=== ML-DSA-87 reference (seed 0..31, msg 0xA5+i) ===");
    report("verifying_key", &vk);
    report("signing_key", &sk_enc);
    report("signature", &sig);
    println!("=== end ===\n");

    // Lock the shapes so a vendored-crate change cannot quietly move the
    // target FP1 is being compared against.
    assert_eq!(vk.len(), 2592);
    assert_eq!(sk_enc.len(), 4896);
    assert_eq!(sig.len(), 4627);
}
