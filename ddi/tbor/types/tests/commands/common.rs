// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Common constants and helpers for TBOR command tests.
//!
//! Unlike most command modules, this one also builds without `emu`, so the
//! hardware-eligible tests share these helpers too.

#![cfg_attr(not(feature = "emu"), allow(dead_code))]

use azihsm_crypto::AesKey;
use azihsm_crypto::AesKeyWrapPadAlgo;
use azihsm_crypto::EccAlgo;
use azihsm_crypto::EccPublicKey;
use azihsm_crypto::Encrypter;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::RsaEncryptAlgo;
use azihsm_crypto::RsaPublicKey;
use azihsm_crypto::RsaSignAlgo;
use azihsm_crypto::Verifier;
use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_types::TborEccGenerateKeyReq;
use azihsm_ddi_tbor_types::TborEccSignReq;
use azihsm_ddi_tbor_types::TborEcdhDeriveReq;
use azihsm_ddi_tbor_types::TborRsaModExpReq;
use azihsm_ddi_tbor_types::TborUnwrapKeyReq;
use azihsm_ddi_tbor_types::TborUnwrapKeyResp;
use azihsm_ddi_tbor_types::HASH_ALGO_SHA256;
use azihsm_ddi_tbor_types::KEY_USAGE_SIGN;
use azihsm_ddi_tbor_types::RSA_OP_DECRYPT;
use azihsm_ddi_tbor_types::RSA_OP_SIGN;

/// `KeyScope::Session` discriminant.
pub(crate) const SCOPE_SESSION: u8 = 0b001;

/// `KeyScope::Ephemeral` discriminant.
pub(crate) const SCOPE_EPHEMERAL: u8 = 0b010;

/// `KeyScope::Local` discriminant.
pub(crate) const SCOPE_LOCAL: u8 = 0b011;

/// `KeyScope::SecurityDomain` discriminant.
pub(crate) const SCOPE_SECURITY_DOMAIN: u8 = 0b100;

/// `SessionType` role identifier for Crypto-Officer sessions.
pub(crate) const CO: u8 = 0;

/// `SessionType` role identifier for Crypto-User sessions.
pub(crate) const CU: u8 = 1;

/// Creates a Crypto-Officer session, generates a session-scoped ECC signing key,
/// and keeps the session alive while `test` runs.
pub(crate) fn with_generated_ecc_key(
    curve: u8,
    test: impl FnOnce(&TestCtx, u16, Vec<u8>, Vec<u8>),
) {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let resp = ctx
        .tbor(&TborEccGenerateKeyReq {
            session_id: session.session_id,
            scope: SCOPE_SESSION,
            curve,
            key_usage: KEY_USAGE_SIGN,
            key_label: Vec::new(),
        })
        .expect("EccGenerateKey");

    test(&ctx, session.session_id, resp.masked_key, resp.pub_key);
}

/// RSA-AES-wrap `data` against the HSM-format unwrapping public key
/// (`n_le ‖ e_le`): RSA-OAEP an ephemeral 32-byte KEK with `oaep_hash`, then
/// AES-KWP the data under it, and concatenate.
pub(crate) fn rsa_aes_wrap(hsm_pub: &[u8], data: &[u8], oaep_hash: HashAlgo) -> Vec<u8> {
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
        &mut RsaEncryptAlgo::with_oaep_padding(oaep_hash, None),
        &pub_key,
        &ephemeral_kek,
    )
    .expect("RSA-OAEP wrap KEK");
    // The device expects the OAEP ciphertext in wire-LE (it flips it to
    // big-endian internally for OpenSSL); OpenSSL emits big-endian, so
    // reverse the modulus-sized RSA ciphertext.
    enc_kek.reverse();

    let kek = AesKey::from_bytes(&ephemeral_kek).expect("AES KEK");
    let mut enc_data = Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, data)
        .expect("AES-KWP wrap data");

    let mut wrapped = Vec::with_capacity(enc_kek.len() + enc_data.len());
    wrapped.append(&mut enc_kek);
    wrapped.append(&mut enc_data);
    wrapped
}

/// Builds an `UnwrapKey` request that imports `key` under the `Local` scope,
/// RSA-AES-wrapped against `hsm_pub` with SHA-256 OAEP.
pub(crate) fn unwrap_req(
    session_id: u16,
    hsm_pub: &[u8],
    class: u8,
    usage: u64,
    key: &[u8],
) -> TborUnwrapKeyReq {
    TborUnwrapKeyReq {
        session_id,
        scope: SCOPE_LOCAL,
        key_class: class,
        key_usage: usage,
        oaep_hash_algo: HASH_ALGO_SHA256,
        wrapped_blob: rsa_aes_wrap(hsm_pub, key, HashAlgo::sha256()),
        key_label: b"imported-key".to_vec(),
    }
}

/// Imports `key` with [`unwrap_req`], expecting success.
pub(crate) fn import_ok(
    ctx: &TestCtx,
    session_id: u16,
    hsm_pub: &[u8],
    class: u8,
    usage: u64,
    key: &[u8],
) -> TborUnwrapKeyResp {
    ctx.tbor(&unwrap_req(session_id, hsm_pub, class, usage, key))
        .expect("UnwrapKey")
}

/// Reverse `bytes` into a fresh vec (wire-LE ↔ OpenSSL-BE conversion).
pub(crate) fn rev(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().rev().copied().collect()
}

/// A non-palindrome big-endian integer of `modulus_len` bytes that stays
/// below the modulus (leading byte `0x01`, so `m < n`).  The non-symmetry
/// exercises the wire little-endian operand handling.
pub(crate) fn test_integer(modulus_len: usize) -> Vec<u8> {
    let mut m = vec![0x02u8; modulus_len];
    m[0] = 0x01;
    m
}

/// Run `RsaModExp` and return the wire-LE `x` result.
pub(crate) fn mod_exp(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: Vec<u8>,
    op_type: u8,
    y_le: Vec<u8>,
) -> Vec<u8> {
    ctx.tbor(&TborRsaModExpReq {
        session_id,
        masked_key,
        op_type,
        y: y_le,
    })
    .expect("RsaModExp")
    .x
}

/// Raw-signs a test integer with `masked_key` through `RsaModExp`, and
/// verifies the signature on the host with `pubkey`.
pub(crate) fn assert_rsa_signs(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: Vec<u8>,
    pubkey: &RsaPublicKey,
    modulus_len: usize,
) {
    let m = test_integer(modulus_len);

    // Device consumes wire-LE `y`, returns wire-LE `x`.
    let x_le = mod_exp(ctx, session_id, masked_key, RSA_OP_SIGN, rev(&m));
    assert_eq!(
        x_le.len(),
        modulus_len,
        "result length equals the modulus length"
    );
    let verified = Verifier::verify(&mut RsaSignAlgo::with_no_padding(), pubkey, &m, &rev(&x_le))
        .expect("raw RSA verify");
    assert!(
        verified,
        "RsaModExp Sign must produce a signature verifying over the message (k={modulus_len})",
    );
}

/// Raw-encrypts a test integer on the host with `pubkey`, and checks that
/// `RsaModExp` decrypts it with `masked_key`.
pub(crate) fn assert_rsa_decrypts(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: Vec<u8>,
    pubkey: &RsaPublicKey,
    modulus_len: usize,
) {
    let m = test_integer(modulus_len);

    // c = m^e mod n (big-endian), then fed to the device as wire-LE `y`.
    let ciphertext = Encrypter::encrypt_vec(&mut RsaEncryptAlgo::with_no_padding(), pubkey, &m)
        .expect("raw RSA encrypt");
    let x_le = mod_exp(
        ctx,
        session_id,
        masked_key,
        RSA_OP_DECRYPT,
        rev(&ciphertext),
    );
    assert_eq!(
        rev(&x_le),
        m,
        "RsaModExp Decrypt must recover the original message (k={modulus_len})"
    );
}

/// Sign `digest` with a caller-held masked key.
pub(crate) fn sign(ctx: &TestCtx, session_id: u16, masked_key: Vec<u8>, digest: &[u8]) -> Vec<u8> {
    ctx.tbor(&TborEccSignReq {
        session_id,
        masked_key,
        digest: digest.to_vec(),
    })
    .expect("EccSign")
    .signature
}

/// Per-curve wire sizes: `(wire_coord_len, raw_coord_len)`.
///
/// `wire_coord_len` is the padded on-wire component size (P-521 → 68);
/// `raw_coord_len` is the cryptographic component size (P-521 → 66).
fn coord_sizes(pub_len: usize) -> (usize, usize) {
    match pub_len {
        64 => (32, 32),
        96 => (48, 48),
        136 => (68, 66),
        _ => panic!("unexpected public-key length {pub_len}"),
    }
}

/// Verify a wire-LE ECDSA signature on the host with `azihsm_crypto`.
///
/// * `pub_le` — `x_le ‖ y_le`, each `wire_coord_len` bytes.
/// * `sig_le` — `r_le ‖ s_le`, each `wire_coord_len` bytes.
/// * `digest_le` — the wire-LE digest that was handed to `EccSign`.
pub(crate) fn verify_wire_ecdsa(pub_le: &[u8], sig_le: &[u8], digest_le: &[u8]) -> bool {
    let (wire_coord, raw_coord) = coord_sizes(pub_le.len());
    assert_eq!(sig_le.len(), wire_coord * 2, "signature length mismatch");

    // Public key: reverse each full padded wire coordinate → big-endian
    // `hsm_point_size` coordinates. Trailing LE pad becomes leading BE
    // zeros, which `from_hsm_bytes` tolerates.
    let (x_le, y_le) = pub_le.split_at(wire_coord);
    let mut pub_be = rev(x_le);
    pub_be.extend(rev(y_le));
    let pubkey = EccPublicKey::from_hsm_bytes(&pub_be).expect("import public key");

    // Signature: reverse the meaningful `raw_coord` bytes of each component
    // → big-endian `r ‖ s`.
    let (r_le, s_le) = sig_le.split_at(wire_coord);
    let mut sig_be = rev(&r_le[..raw_coord]);
    sig_be.extend(rev(&s_le[..raw_coord]));

    // Verify the full big-endian digest; host ECDSA applies the same
    // most-significant-bit truncation as the firmware.
    let digest_be = rev(digest_le);

    Verifier::verify(&mut EccAlgo::default(), &pubkey, &digest_be, &sig_be)
        .expect("host ECDSA verify")
}

/// Signs a `digest_len`-byte test digest with `masked_key` on the device, and
/// verifies the signature on the host against `pub_le`.
pub(crate) fn assert_ecc_signs(
    ctx: &TestCtx,
    session_id: u16,
    masked_key: Vec<u8>,
    pub_le: &[u8],
    digest_len: usize,
) {
    let digest: Vec<u8> = (0..digest_len)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(0x11))
        .collect();
    let signature = sign(ctx, session_id, masked_key, &digest);
    assert_eq!(
        signature.len(),
        pub_le.len(),
        "wire signature length equals wire public-key length ({}-byte public key)",
        pub_le.len(),
    );
    assert!(
        verify_wire_ecdsa(pub_le, &signature, &digest),
        "ECDSA signature must verify against the public key ({}-byte public key)",
        pub_le.len(),
    );
}

/// Derive a shared secret from local key `masked_key` against `peer_pub`
/// under `scope`.
pub(crate) fn derive(
    ctx: &TestCtx,
    session_id: u16,
    scope: u8,
    masked_key: Vec<u8>,
    peer_pub: Vec<u8>,
) -> Vec<u8> {
    ctx.tbor(&TborEcdhDeriveReq {
        session_id,
        scope,
        masked_key,
        peer_pub_key: peer_pub,
        key_label: Vec::new(),
    })
    .expect("EcdhDerive")
    .masked_secret
}
