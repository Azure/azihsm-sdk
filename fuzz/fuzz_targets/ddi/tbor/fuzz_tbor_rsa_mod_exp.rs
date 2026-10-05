// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_crypto::AesKey;
use azihsm_crypto::AesKeyWrapPadAlgo;
use azihsm_crypto::Encrypter;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::KeyGenerationOp;
use azihsm_crypto::RsaEncryptAlgo;
use azihsm_crypto::RsaPrivateKey;
use azihsm_crypto::RsaPublicKey;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_test_harness::SessionHandshake;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_types::*;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// MBOR key availability. TBOR key-import responses are masked blobs, not
/// persistent key IDs, so only session-scoped valid keys are generated
/// (mirrors `fuzz_tbor_ecc_sign`'s treatment of the same legacy field).
#[derive(Arbitrary, Debug)]
enum KeyAvailability {
    App,
    Session,
}

/// RSA modulus size for host-generated keys, mirroring the MBOR
/// `RsaKeySize` selector used to pick the modulus length (2048 / 3072 /
/// 4096 bits == 256 / 384 / 512 bytes).
#[derive(Arbitrary, Debug, Clone, Copy)]
enum RsaKeySize {
    Rsa2k,
    Rsa3k,
    Rsa4k,
}

impl RsaKeySize {
    fn modulus_bytes(self) -> usize {
        match self {
            Self::Rsa2k => 256,
            Self::Rsa3k => 384,
            Self::Rsa4k => 512,
        }
    }
}

/// TBOR `RsaModExp` `op_type` discriminant. `Unknown` carries a raw byte so
/// out-of-range discriminants are exercised too.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum RsaOpType {
    Sign,
    Decrypt,
    Unknown(u8),
}

impl RsaOpType {
    fn to_tbor(self) -> u8 {
        match self {
            Self::Sign => RSA_OP_SIGN,
            Self::Decrypt => RSA_OP_DECRYPT,
            Self::Unknown(value) => value,
        }
    }
}

/// Fuzzed fields corresponding to the MBOR `DdiRsaModExpReq` structure
/// (key id + op type); TBOR carries the masked key itself instead of a key
/// id, so `masked_key` substitutes for the legacy `key_id` field when a
/// valid key is not generated.
#[derive(Arbitrary, Debug)]
struct FuzzRsaModExpReq {
    /// Arbitrary masked-key bytes used when a valid key is not generated.
    masked_key: Vec<u8>,
    /// The private-key operation requested of `RsaModExp`.
    op_type: RsaOpType,
}

/// Fuzz input corresponding to the MBOR `RsaModExp` target.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Seed for deterministic generation of the `y` operand.
    rand_seed: u64,
    /// If `true`, the fuzz test will generate a valid RSA key for modular
    /// exponentiation.
    use_valid_key_id: bool,
    /// Legacy key availability; TBOR's caller-held masked keys have no App
    /// key-ID lifecycle equivalent, so only `Session` generates a valid key.
    key_availability: KeyAvailability,
    /// Size of the RSA key to generate.
    key_size: RsaKeySize,
    /// Selects the CRT vs non-CRT `KeyClass` used to import the generated
    /// key through `UnwrapKey`.
    crt: bool,
    /// Request parameters corresponding to the MBOR request.
    cmdreq_data: FuzzRsaModExpReq,
}

/// `KeyScope::Session` discriminant — masked keys generated here only need
/// to outlive the fuzzed `RsaModExp` call.
const KEY_SCOPE_SESSION: u8 = 0b001;
/// `HashAlgo::Sha256` discriminant used to OAEP-wrap the KEK in `UnwrapKey`.
const RSA_OAEP_SHA256: u8 = 1;

/// Drive `PartInit` → `PartFinal` so the partition is `Initialized`: the
/// built-in RSA unwrapping key that `GetUnwrappingKey` / `UnwrapKey`
/// depend on is only provisioned once the partition is finalized.
fn finalize_partition(ctx: &TestCtx, session: &SessionHandshake) {
    let pota = CaKey::generate();
    let policy = common::known_good_part_policy(pota.raw_pub());
    let init = ctx
        .part_init(
            session,
            &common::mach_seed(),
            &policy,
            &common::pota_thumbprint(),
        )
        .expect("PartInit should succeed");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(session, &policy, &[], &chain.der_items())
        .expect("PartFinal should succeed");
}

/// Deterministic xorshift64* fill used to materialize the fuzzed `y`
/// operand from `rand_seed`, avoiding a dependency on the `rand` crate.
fn fill_rand(seed: u64, buf: &mut [u8]) {
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    if state == 0 {
        state = 0x9E37_79B9_7F4A_7C15;
    }
    for chunk in buf.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

/// Generate a host RSA private key of `modulus_bytes`, import it on-device
/// via `UnwrapKey` under the given CRT / non-CRT class and usage, and
/// return the resulting masked key. Mirrors `import_rsa_key` in
/// `fuzz_tbor_attest_key`, generalized over modulus size, key class, and
/// key usage.
fn import_rsa_key(
    ctx: &TestCtx,
    session_id: u16,
    modulus_bytes: usize,
    crt: bool,
    key_usage: u64,
) -> Vec<u8> {
    let key = RsaPrivateKey::generate(modulus_bytes).expect("generate host RSA key");
    let private_der = key.to_vec().expect("export host RSA private key");
    let unwrapping_key = ctx
        .tbor(&TborGetUnwrappingKeyReq { session_id })
        .expect("get built-in unwrapping public key")
        .pub_key;

    // Convert HSM little-endian (n_le(256) ‖ e_le(4)) to the crypto crate's
    // big-endian form; the built-in unwrapping key is a fixed RSA-2048 key
    // regardless of the modulus size being imported.
    assert_eq!(
        unwrapping_key.len(),
        260,
        "built-in unwrapping key is a fixed-size RSA-2048 (n_le(256) ‖ e_le(4))",
    );
    let mut public_key_be = Vec::with_capacity(unwrapping_key.len());
    public_key_be.extend(unwrapping_key[..256].iter().rev());
    public_key_be.extend(unwrapping_key[256..].iter().rev());
    let public_key =
        RsaPublicKey::from_hsm_bytes(&public_key_be).expect("parse unwrapping public key");

    let kek = [0xA7u8; 32];
    let mut encrypted_kek = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None),
        &public_key,
        &kek,
    )
    .expect("RSA-OAEP wrap AES key");
    encrypted_kek.reverse();

    let kek = AesKey::from_bytes(&kek).expect("construct AES key-encryption key");
    let encrypted_private_key =
        Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, &private_der)
            .expect("AES-KWP wrap RSA private key");
    let mut wrapped_blob = encrypted_kek;
    wrapped_blob.extend(encrypted_private_key);

    let key_class = if crt { KEY_CLASS_RSA_CRT } else { KEY_CLASS_RSA };

    ctx.tbor(&TborUnwrapKeyReq {
        session_id,
        scope: KEY_SCOPE_SESSION,
        key_class,
        key_usage,
        oaep_hash_algo: RSA_OAEP_SHA256,
        wrapped_blob,
        key_label: Vec::new(),
    })
    .expect("import host RSA key through UnwrapKey")
    .masked_key
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

        let generate_valid_key =
            input.use_valid_key_id && matches!(input.key_availability, KeyAvailability::Session);

        let op_type = input.cmdreq_data.op_type.to_tbor();
        // `UnwrapKey` requires exactly one matched usage-group pair
        // (sign+verify xor encrypt+decrypt); an unknown op still needs a
        // valid key imported so the fuzzed `RsaModExp` call can reach the
        // op-type check, so it reuses the sign+verify pair.
        let key_usage = match op_type {
            RSA_OP_DECRYPT => KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
            _ => KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
        };

        let (masked_key, modulus_len) = if generate_valid_key {
            finalize_partition(ctx, &session);
            let modulus_len = input.key_size.modulus_bytes();
            let masked_key =
                import_rsa_key(ctx, session.session_id, modulus_len, input.crt, key_usage);
            (masked_key, Some(modulus_len))
        } else {
            (input.cmdreq_data.masked_key.clone(), None)
        };

        let mut y = vec![0u8; modulus_len.unwrap_or(RSA_MOD_EXP_MAX_LEN)];
        fill_rand(input.rand_seed, &mut y);

        // Only a generated key and a known Sign/Decrypt op can succeed;
        // aliases carried by `Unknown` are classified by their encoded value.
        let expect_success = generate_valid_key
            && matches!(op_type, RSA_OP_SIGN | RSA_OP_DECRYPT)
            && modulus_len == Some(y.len());

        if expect_success {
            // The driver also enforces NIST ACVP's `1 < y < n-1` before
            // exponentiating. The generated modulus always has its top bit
            // set, so forcing `y`'s most-significant byte (the last byte,
            // since `y` is wire little-endian) low guarantees `y < n`
            // regardless of the fuzzed low-order bytes.
            if let Some(top) = y.last_mut() {
                *top = 0x01;
            }
        }

        let req = TborRsaModExpReq {
            session_id: session.session_id,
            masked_key,
            op_type,
            y,
        };

        let result = ctx.tbor(&req);

        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(resp), true) => assert_eq!(
                resp.x.len(),
                modulus_len.expect("a successful request always carries a known modulus length"),
                "result length must match the key's modulus length",
            ),
            (Ok(_), false) => panic!("invalid RsaModExp request unexpectedly succeeded"),
            (Err(err), true) => panic!("valid RsaModExp request failed: {err}"),
            (Err(_), false) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
