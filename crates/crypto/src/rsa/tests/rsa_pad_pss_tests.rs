// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[test]
pub fn rsa_pss_sign_pad() {
    for modulus_size in [256, 384, 512] {
        let private_key =
            RsaPrivateKey::generate(modulus_size).expect("Failed to generate RSA private key");
        let public_key = private_key
            .public_key()
            .expect("Failed to get RSA public key");

        let message = b"hello";
        let mut hash_algo = HashAlgo::sha256();
        let hash = Hasher::hash_vec(&mut hash_algo, message).expect("Hashing failed");
        let mut encoder = RsaPadPssAlgo::with_mgf1(
            public_key.size(),
            hash_algo.clone(),
            &hash,
            32, // salt length
        );
        let block = Encoder::encode_vec(&mut encoder).expect("Failed to pad message");
        let mut algo = RsaSignAlgo::with_no_padding();
        let signature = Signer::sign_vec(&mut algo, &private_key, &block).expect("Signing failed");

        let mut algo = RsaHashSignAlgo::with_pss_padding(hash_algo.clone(), 32);
        let verified = Verifier::verify(&mut algo, &public_key, message, &signature)
            .expect("Verification failed");
        assert!(verified);
    }
}

#[test]
pub fn rsa_pss_sign_unpad() {
    for modulus_size in [256, 384, 512] {
        let private_key =
            RsaPrivateKey::generate(modulus_size).expect("Failed to generate RSA private key");
        let public_key = private_key
            .public_key()
            .expect("Failed to get RSA public key");
        let message = b"hello";
        let mut hash_algo = HashAlgo::sha256();
        let hash = Hasher::hash_vec(&mut hash_algo, message).expect("Hashing failed");

        let mut algo = RsaHashSignAlgo::with_pss_padding(hash_algo.clone(), 32);
        let signature = Signer::sign_vec(&mut algo, &private_key, message).expect("Signing failed");
        let mut algo = RsaSignAlgo::with_no_padding();
        let dec_block = Verifier::verify_recover_vec(&mut algo, &public_key, &signature)
            .expect("Failed to recover signed block");
        let params = RsaPadPssAlgoParams::new(modulus_size, hash_algo.clone(), &hash);
        let pad = Decoder::decode::<RsaPadPssAlgo>(&dec_block, params)
            .expect("Failed to deced signature");
        assert_eq!(pad.modulus_size(), modulus_size);
        assert_eq!(pad.salt_len(), 32);
        assert_eq!(pad.hash(), hash);
    }
}
