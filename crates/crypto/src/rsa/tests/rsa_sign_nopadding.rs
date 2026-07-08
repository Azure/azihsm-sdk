// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use super::*;

/// Round-trips the raw (no padding) RSA sign/verify primitive: sign computes
/// `s = m^d mod n` and verify checks `s^e mod n == m`.
///
/// This exercises the `Padding::None` verify path on both backends — OpenSSL's
/// `EVP_PKEY_verify` and Windows CNG, whose `BCryptVerifySignature` rejects
/// `BCRYPT_PAD_NONE` and so must fall back to a raw public-key operation.
#[test]
fn rsa_no_padding_sign_verify_roundtrip() {
    for modulus_size in [256, 384, 512] {
        let private_key =
            RsaPrivateKey::generate(modulus_size).expect("Failed to generate RSA private key");
        let public_key = private_key
            .public_key()
            .expect("Failed to get RSA public key");

        // A raw message strictly below the modulus (leading byte 0x01).
        let mut message = vec![0x02u8; modulus_size];
        message[0] = 0x01;

        let mut algo = RsaSignAlgo::with_no_padding();
        let signature =
            Signer::sign_vec(&mut algo, &private_key, &message).expect("Signing failed");

        let mut algo = RsaSignAlgo::with_no_padding();
        let verified = Verifier::verify(&mut algo, &public_key, &message, &signature)
            .expect("Verification failed");
        assert!(verified, "raw no-padding signature must verify");

        // A modified message must not verify.
        let mut tampered = message.clone();
        tampered[modulus_size - 1] ^= 0x01;
        let mut algo = RsaSignAlgo::with_no_padding();
        let verified = Verifier::verify(&mut algo, &public_key, &tampered, &signature)
            .expect("Verification must not error");
        assert!(
            !verified,
            "raw no-padding verify must reject a modified message"
        );

        let mut algo = RsaSignAlgo::with_no_padding();
        let verified = Verifier::verify(
            &mut algo,
            &public_key,
            &message[..modulus_size - 1],
            &signature,
        )
        .expect("Verification must not error");
        assert!(
            !verified,
            "raw no-padding verify must reject a short message"
        );

        let mut algo = RsaSignAlgo::with_no_padding();
        let verified = Verifier::verify(
            &mut algo,
            &public_key,
            &message,
            &signature[..modulus_size - 1],
        )
        .expect("Verification must not error");
        assert!(
            !verified,
            "raw no-padding verify must reject a short signature"
        );
    }
}
