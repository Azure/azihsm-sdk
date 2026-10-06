// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_crypto::AesKey;
use azihsm_crypto::AesKeyWrapPadAlgo;
use azihsm_crypto::EccPrivateKey;
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
use common::EccCurve;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// `KeyScope` wire discriminants. `Session`, `Ephemeral`, and `Local` have
/// provisioned masking keys after `PartFinal`; `SecurityDomain` requires
/// `CreateSD` and exercises the `UnsupportedKeyScope` reject path.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum KeyScope {
    Session,
    Ephemeral,
    Local,
    SecurityDomain,
}

impl KeyScope {
    fn to_tbor(self) -> u8 {
        match self {
            Self::Session => KEY_SCOPE_SESSION,
            Self::Ephemeral => KEY_SCOPE_EPHEMERAL,
            Self::Local => KEY_SCOPE_LOCAL,
            Self::SecurityDomain => KEY_SCOPE_SECURITY_DOMAIN,
        }
    }
}

/// RSA modulus sizes (in bytes) supported by `UnwrapKey`'s `Rsa` /
/// `RsaCrt` classes, mirroring `RsaKeySize` from the MBOR `RsaUnwrap`
/// fuzz target.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum RsaKeySize {
    Rsa2k = 256,
    Rsa3k = 384,
    Rsa4k = 512,
}

/// Class of the host key wrapped for import, mirroring the TBOR
/// `KeyClass` wire discriminants (see `KEY_CLASS_*`).
#[derive(Arbitrary, Debug, Clone, Copy)]
enum KeyClass {
    Aes,
    Rsa,
    RsaCrt,
    Ecc,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl KeyClass {
    fn to_tbor(self) -> u8 {
        match self {
            Self::Aes => KEY_CLASS_AES,
            Self::Rsa => KEY_CLASS_RSA,
            Self::RsaCrt => KEY_CLASS_RSA_CRT,
            Self::Ecc => KEY_CLASS_ECC,
            Self::HmacSha256 => KEY_CLASS_HMAC_SHA256,
            Self::HmacSha384 => KEY_CLASS_HMAC_SHA384,
            Self::HmacSha512 => KEY_CLASS_HMAC_SHA512,
        }
    }

    /// Canonical valid `KeyUsage` bitfield for this class, mirroring the
    /// firmware's `attrs_for_class` permission policy.
    fn valid_usage(self) -> u64 {
        match self {
            Self::Aes => KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
            Self::Rsa | Self::RsaCrt | Self::Ecc => KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
            Self::HmacSha256 | Self::HmacSha384 | Self::HmacSha512 => {
                KEY_USAGE_SIGN | KEY_USAGE_VERIFY
            }
        }
    }

    /// Whether the requested usage is one of the exact permission groups
    /// accepted by `UnwrapKey` for this class. Undefined bits are ignored,
    /// matching firmware's `attrs_for_class`, which checks only the seven
    /// known usage flags.
    fn accepts_usage(self, usage: u64) -> bool {
        let known_usage = usage
            & (KEY_USAGE_ENCRYPT
                | KEY_USAGE_DECRYPT
                | KEY_USAGE_SIGN
                | KEY_USAGE_VERIFY
                | KEY_USAGE_DERIVE
                | KEY_USAGE_WRAP
                | KEY_USAGE_UNWRAP);
        match self {
            Self::Aes => known_usage == (KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT),
            Self::Rsa | Self::RsaCrt => {
                known_usage == (KEY_USAGE_SIGN | KEY_USAGE_VERIFY)
                    || known_usage == (KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT)
            }
            Self::Ecc => {
                known_usage == (KEY_USAGE_SIGN | KEY_USAGE_VERIFY)
                    || known_usage == KEY_USAGE_DERIVE
            }
            Self::HmacSha256 | Self::HmacSha384 | Self::HmacSha512 => {
                known_usage == (KEY_USAGE_SIGN | KEY_USAGE_VERIFY)
            }
        }
    }

    /// Whether the recovered key for this class carries a wire public key
    /// (the asymmetric classes) or not (the symmetric classes).
    fn is_asymmetric(self) -> bool {
        matches!(self, Self::Rsa | Self::RsaCrt | Self::Ecc)
    }

    /// Generate host-side key material (DER for RSA / ECC, raw bytes for
    /// AES / HMAC) suitable for this class, to be RSA-AES-wrapped and
    /// imported via `UnwrapKey`.
    fn generate_key_material(self, rsa_key_size: RsaKeySize, curve: EccCurve) -> Vec<u8> {
        match self {
            Self::Aes => alloc_vec(0x42, 32),
            Self::Rsa | Self::RsaCrt => RsaPrivateKey::generate(rsa_key_size as usize)
                .expect("generate RSA private key")
                .to_vec()
                .expect("RSA private key DER export"),
            Self::Ecc => EccPrivateKey::generate(curve.coord_len())
                .expect("generate ECC private key")
                .to_vec()
                .expect("ECC PKCS#8 DER export"),
            Self::HmacSha256 => alloc_vec(0x37, 32),
            Self::HmacSha384 => alloc_vec(0x37, 48),
            Self::HmacSha512 => alloc_vec(0x37, 64),
        }
    }
}

/// Requested `KeyUsage` for the import: either the class's canonical valid
/// usage, or an arbitrary (likely invalid) bitfield.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum KeyUsageChoice {
    Valid,
    Fuzzed(u64),
}

impl KeyUsageChoice {
    fn resolve(self, class: KeyClass) -> u64 {
        match self {
            Self::Valid => class.valid_usage(),
            Self::Fuzzed(usage) => usage,
        }
    }
}

/// OAEP hash requested on the wire. Wrapping always uses SHA-256 on the
/// host (see `rsa_aes_wrap`), so anything but `Sha256` should fail to
/// OAEP-decrypt the KEK on-device.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum OaepHash {
    Sha256,
    Sha384,
    Sha512,
    Fuzzed(u8),
}

impl OaepHash {
    fn to_tbor(self) -> u8 {
        match self {
            Self::Sha256 => OAEP_SHA256,
            Self::Sha384 => 2,
            Self::Sha512 => 3,
            Self::Fuzzed(algo) => algo,
        }
    }
}

/// Fuzz input for the TBOR `UnwrapKey` command — the TBOR analogue of the
/// MBOR `RsaUnwrap` command, which re-masks the recovered key instead of
/// vaulting it under a key handle (so there is no key id to validate).
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// If `true`, wrap real host-generated key material (sized/typed by
    /// `key_class` / `rsa_key_size` / `curve`) so the device can
    /// successfully decode and mask it. If `false`, send deterministically
    /// fuzzed bytes seeded by `wrapped_blob_seed` (mirrors
    /// `use_valid_wrapped_blob` / `wrapped_blob_seed`).
    use_valid_wrapped_blob: bool,
    /// Seed used to deterministically generate an invalid wrapped blob
    /// when `use_valid_wrapped_blob` is `false`.
    wrapped_blob_seed: u64,
    /// Class of the wrapped key (selects the decode path).
    key_class: KeyClass,
    /// RSA modulus size used when `key_class` is `Rsa` / `RsaCrt`.
    rsa_key_size: RsaKeySize,
    /// ECC curve used when `key_class` is `Ecc`.
    curve: EccCurve,
    /// Requested key scope for the recovered key (mirrors
    /// `key_availability`).
    key_scope: KeyScope,
    /// Requested usage permissions (mirrors `key_usage`).
    key_usage: KeyUsageChoice,
    /// OAEP hash algorithm requested on the wire.
    oaep_hash_algo: OaepHash,
    /// A fuzzed payload providing the remaining base request parameters
    /// (mirrors `cmdreq_data`).
    cmdreq_data: FuzzUnwrapKeyReq,
}

/// Fuzzed fields layered onto the base `UnwrapKey` request.
#[derive(Arbitrary, Debug)]
struct FuzzUnwrapKeyReq {
    /// Caller-supplied key label recorded in the masked blob's metadata.
    key_label: Vec<u8>,
}

/// `KeyScope::Session` wire discriminant.
const KEY_SCOPE_SESSION: u8 = 0b001;
/// `KeyScope::Ephemeral` wire discriminant.
const KEY_SCOPE_EPHEMERAL: u8 = 0b010;
/// `KeyScope::Local` wire discriminant.
const KEY_SCOPE_LOCAL: u8 = 0b011;
/// `KeyScope::SecurityDomain` wire discriminant.
const KEY_SCOPE_SECURITY_DOMAIN: u8 = 0b100;
/// `HashAlgo::Sha256` OAEP wire discriminant — the only hash `rsa_aes_wrap`
/// wraps with below.
const OAEP_SHA256: u8 = 1;

/// Drive `PartInit` → `PartFinal` to provision the built-in RSA unwrapping
/// key required by `GetUnwrappingKey` and `UnwrapKey`.
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

/// Build a fixed-byte-pattern buffer (`fill` repeated `len` times), used
/// for the AES / HMAC symmetric key material.
fn alloc_vec(fill: u8, len: usize) -> Vec<u8> {
    core::iter::repeat_n(fill, len).collect()
}

/// Deterministically fill a buffer of `len` bytes from `seed` using a
/// small splitmix64-style generator (no external `rand` dependency).
fn seeded_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed;
    let mut buf = Vec::with_capacity(len);
    while buf.len() < len {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        buf.extend_from_slice(&z.to_le_bytes());
    }
    buf.truncate(len);
    buf
}

/// RSA-AES-wrap `data` against the HSM-format unwrapping public key
/// (`n_le ‖ e_le`) returned by `GetUnwrappingKey`: RSA-OAEP(SHA-256) an
/// ephemeral 32-byte KEK, then AES-KWP the data under it, and concatenate.
fn rsa_aes_wrap(hsm_pub: &[u8], data: &[u8]) -> Vec<u8> {
    // `GetUnwrappingKey` returns the modulus / exponent little-endian
    // (`n_le(256) ‖ e_le(4)`), but `RsaPublicKey::from_hsm_bytes` parses
    // each component big-endian — reverse them per-component.
    assert_eq!(hsm_pub.len(), 260, "RSA-2048 HSM pubkey is 260 bytes");
    let mut be = Vec::with_capacity(260);
    be.extend(hsm_pub[..256].iter().rev());
    be.extend(hsm_pub[256..260].iter().rev());

    let ephemeral_kek = [0xA7u8; 32];
    let pub_key = RsaPublicKey::from_hsm_bytes(&be).expect("from_hsm_bytes");
    let mut enc_kek = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None),
        &pub_key,
        &ephemeral_kek,
    )
    .expect("RSA-OAEP wrap KEK");
    // The device expects the OAEP ciphertext in wire-LE (it flips it to
    // big-endian internally); OpenSSL emits big-endian, so reverse the
    // modulus-sized RSA ciphertext.
    enc_kek.reverse();

    let kek = AesKey::from_bytes(&ephemeral_kek).expect("AES KEK");
    let mut enc_data = Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, data)
        .expect("AES-KWP wrap data");

    let mut wrapped = Vec::with_capacity(enc_kek.len() + enc_data.len());
    wrapped.append(&mut enc_kek);
    wrapped.append(&mut enc_data);
    wrapped
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        finalize_partition(ctx, &session);

        let hsm_pub = ctx
            .tbor(&TborGetUnwrappingKeyReq {
                session_id: session.session_id,
            })
            .expect("GetUnwrappingKey should succeed")
            .pub_key;

        let wrapped_blob = if input.use_valid_wrapped_blob {
            let material = input
                .key_class
                .generate_key_material(input.rsa_key_size, input.curve);
            rsa_aes_wrap(&hsm_pub, &material)
        } else {
            seeded_bytes(input.wrapped_blob_seed, UNWRAP_WRAPPED_BLOB_MAX_LEN)
        };

        let key_usage = input.key_usage.resolve(input.key_class);
        let oaep_hash_algo = input.oaep_hash_algo.to_tbor();
        let scope = input.key_scope.to_tbor();
        let key_label = input.cmdreq_data.key_label.clone();

        let req = TborUnwrapKeyReq {
            session_id: session.session_id,
            scope,
            key_class: input.key_class.to_tbor(),
            key_usage,
            oaep_hash_algo,
            wrapped_blob: wrapped_blob.clone(),
            key_label: key_label.clone(),
        };
        let result = ctx.tbor(&req);

        // Everything but the scope being provisioned must line up for the
        // import to succeed: real wrapped material, a usage group accepted
        // for the class, the hash actually used to wrap, and an encodable label.
        let valid_except_scope = input.use_valid_wrapped_blob
            && input.key_class.accepts_usage(key_usage)
            && oaep_hash_algo == OAEP_SHA256
            && key_label.len() <= TBOR_KEY_LABEL_MAX_LEN;
        let expect_success = valid_except_scope
            && matches!(
                input.key_scope,
                KeyScope::Session | KeyScope::Ephemeral | KeyScope::Local
            );

        match (&result, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(resp), true) => {
                assert!(
                    !resp.masked_key.is_empty(),
                    "masked key must not be empty"
                );
                assert_eq!(
                    !resp.pub_key.is_empty(),
                    input.key_class.is_asymmetric(),
                    "pub_key presence must match the recovered key's class"
                );
            }
            (Ok(_), false) => panic!("invalid UnwrapKey request unexpectedly succeeded"),
            (Err(err), true) => panic!("valid UnwrapKey request failed: {err}"),
            (Err(err), false)
                if valid_except_scope && matches!(input.key_scope, KeyScope::SecurityDomain) =>
            {
                assert!(
                    matches!(err, DdiError::TborStatus(TborStatus::UnsupportedKeyScope)),
                    "unprovisioned scope must be rejected with UnsupportedKeyScope, got {err}"
                );
            }
            (Err(_), false) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
