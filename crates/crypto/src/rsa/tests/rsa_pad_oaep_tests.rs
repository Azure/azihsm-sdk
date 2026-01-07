// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

#[test]
pub fn rsa_oaep_enc_pad() {
    for modulus_size in [256, 384, 512] {
        let private_key =
            RsaPrivateKey::generate(modulus_size).expect("Failed to generate RSA private key");
        let public_key = private_key
            .public_key()
            .expect("Failed to get RSA public key");

        let plain_text = b"hello";
        let hash_algo = HashAlgo::sha256();
        let label = None;
        let mut encoder =
            RsaPadOaepAlgo::with_mgf1(public_key.size(), hash_algo.clone(), label, plain_text);
        let block = Encoder::encode_vec(&mut encoder).expect("Failed to pad plaintext");

        let mut algo = RsaEncryptAlgo::with_no_padding();
        let cipher_text =
            Encrypter::encrypt_vec(&mut algo, &public_key, &block).expect("Encryption failed");

        let mut algo = RsaEncryptAlgo::with_oaep_padding(hash_algo.clone(), label);
        let decrypted = Decrypter::decrypt_vec(&mut algo, &private_key, &cipher_text)
            .expect("Decryption failed");

        assert_eq!(&decrypted, plain_text);
    }
}

#[test]
pub fn rsa_oaep_enc_unpad() {
    for modulus_size in [256, 384, 512] {
        let private_key =
            RsaPrivateKey::generate(modulus_size).expect("Failed to generate RSA private key");
        let public_key = private_key
            .public_key()
            .expect("Failed to get RSA public key");
        let plain_text = b"hello";
        let hash_algo = HashAlgo::sha256();
        let label = None;

        let mut algo = RsaEncryptAlgo::with_oaep_padding(hash_algo.clone(), label);
        let cipher_text =
            Encrypter::encrypt_vec(&mut algo, &public_key, plain_text).expect("Encryption failed");

        let mut algo = RsaEncryptAlgo::with_no_padding();
        let decrypted_block = Decrypter::decrypt_vec(&mut algo, &private_key, &cipher_text)
            .expect("Decryption failed");

        let params = RsaPadOaepAlgoParams::new(public_key.size(), hash_algo.clone(), label);
        let decrypted = Decoder::decode::<RsaPadOaepAlgo>(&decrypted_block, params)
            .expect("Failed to unpad decrypted block");

        assert_eq!(decrypted.message(), plain_text);
    }
}
