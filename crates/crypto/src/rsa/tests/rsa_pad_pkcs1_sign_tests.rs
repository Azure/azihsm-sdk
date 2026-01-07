// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

#[test]
pub fn rsa_pkcs1v15_sign_pad() {
    for modulus_size in [256, 384, 512] {
        let private_key =
            RsaPrivateKey::generate(modulus_size).expect("Failed to generate RSA private key");
        let public_key = private_key
            .public_key()
            .expect("Failed to get RSA public key");

        let message = b"hello";
        let mut hash_algo = HashAlgo::sha256();
        let hash = Hasher::hash_vec(&mut hash_algo, message).expect("Hashing failed");
        let mut encoder = RsaPadPkcs1SignAlgo::new(public_key.size(), hash_algo.clone(), &hash);
        let block = Encoder::encode_vec(&mut encoder).expect("Failed to pad message");

        let mut algo = RsaSignAlgo::with_no_padding();
        let signature = Signer::sign_vec(&mut algo, &private_key, &block).expect("Signing failed");

        let mut algo = RsaHashSignAlgo::with_pkcs1_padding(hash_algo.clone());
        let signature2 =
            Signer::sign_vec(&mut algo, &private_key, message).expect("Signing failed");
        assert_eq!(&signature, &signature2);

        let verified = Verifier::verify(&mut algo, &public_key, message, &signature)
            .expect("Verification failed");
        assert!(verified);
    }
}

#[test]
pub fn rsa_pkcs1v15_sign_unpad() {
    for modulus_size in [256, 384, 512] {
        let private_key =
            RsaPrivateKey::generate(modulus_size).expect("Failed to generate RSA private key");
        let public_key = private_key
            .public_key()
            .expect("Failed to get RSA public key");
        let message = b"hello";
        let mut hash_algo = HashAlgo::sha256();
        let hash = Hasher::hash_vec(&mut hash_algo, message).expect("Hashing failed");

        let mut algo = RsaHashSignAlgo::with_pkcs1_padding(hash_algo.clone());
        let signature = Signer::sign_vec(&mut algo, &private_key, message).expect("Signing failed");

        let mut algo = RsaSignAlgo::with_no_padding();
        let dec_block = Verifier::verify_recover_vec(&mut algo, &public_key, &signature)
            .expect("Failed to recover signed block");

        let params = RsaPadPkcs1SignAlgoParams::new(modulus_size, hash_algo.clone());
        let pad = Decoder::decode::<RsaPadPkcs1SignAlgo>(&dec_block, params)
            .expect("Failed to deced signature");

        assert_eq!(pad.modulus_size(), modulus_size);
        assert_eq!(pad.hash(), hash);
    }
}
