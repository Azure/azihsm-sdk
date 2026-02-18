// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[test]
pub fn rsa_pkcs1v15_enc_pad() {
    for modulus_size in [256, 384, 512] {
        let private_key =
            RsaPrivateKey::generate(modulus_size).expect("Failed to generate RSA private key");
        let public_key = private_key
            .public_key()
            .expect("Failed to get RSA public key");

        let plain_text = b"hello";
        let mut encoder = RsaPadPkcs1EncryptAlgo::new(public_key.size(), plain_text);
        let block = Encoder::encode_vec(&mut encoder).expect("Failed to pad plaintext");

        let mut algo = RsaEncryptAlgo::with_no_padding();
        let cipher_text =
            Encrypter::encrypt_vec(&mut algo, &public_key, &block).expect("Encryption failed");

        let mut algo = RsaEncryptAlgo::with_pkcs1_padding();
        let decrypted = Decrypter::decrypt_vec(&mut algo, &private_key, &cipher_text)
            .expect("Decryption failed");

        assert_eq!(&decrypted, plain_text);
    }
}

#[test]
pub fn rsa_pkcs1v15_enc_unpad() {
    for modulus_size in [256, 384, 512] {
        let private_key =
            RsaPrivateKey::generate(modulus_size).expect("Failed to generate RSA private key");
        let public_key = private_key
            .public_key()
            .expect("Failed to get RSA public key");
        let plain_text = b"hello";

        let mut algo = RsaEncryptAlgo::with_pkcs1_padding();
        let cipher_text =
            Encrypter::encrypt_vec(&mut algo, &public_key, plain_text).expect("Encryption failed");

        let mut algo = RsaEncryptAlgo::with_no_padding();
        let decrypted_block = Decrypter::decrypt_vec(&mut algo, &private_key, &cipher_text)
            .expect("Decryption failed");

        let decrypted = Decoder::decode::<RsaPadPkcs1EncryptAlgo>(&decrypted_block, ())
            .expect("Failed to unpad decrypted block");

        assert_eq!(decrypted.message(), plain_text);
    }
}
