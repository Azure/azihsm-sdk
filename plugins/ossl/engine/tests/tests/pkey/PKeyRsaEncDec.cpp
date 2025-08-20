// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmCiphers.hpp"
#include "AziHsmHash.hpp"
#include "AziHsmPKeyRsa.hpp"
#include "AziHsmTestEngine.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include "AziHsmTestPKey.hpp"
#include "AziHsmTestHash.hpp"
#include "AziHsmTestFlags.hpp"
#include "AziHsmTestRsa.hpp"
#include <catch2/catch_test_macros.hpp>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <memory>
#include <stdexcept>
#include "../../../api-interface/azihsm_engine.h"

static void test_encrypt_decrypt(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmShaHashType hash_type,
    size_t data_size = 32,
    unsigned int flags = AziHsmRsaTestFlag::RSA_TEST_NORMAL)
{
    AziHsmPKeyRsaCtx crypt_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT);

    std::vector<unsigned char> plain_data(data_size);
    REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

    std::vector<unsigned char> encrypted_data;
    int ret = crypt_ctx.encryptRsa(encrypted_data, plain_data, hash_type);
    if (IS_INVALID_SIZE(flags))
    {
        REQUIRE(ret == 0);
        return;
    }
    else
    {
        REQUIRE(ret > 0);
    }

    size_t encrypt_len;
    switch (key)
    {
    case AziHsmRsaDefaultKey::RSA2048:
        encrypt_len = 256;
        break;
    case AziHsmRsaDefaultKey::RSA3072:
        encrypt_len = 384;
        break;
    case AziHsmRsaDefaultKey::RSA4096:
        encrypt_len = 512;
        break;
    }

    REQUIRE(encrypt_len == encrypted_data.size());

    std::vector<unsigned char> decrypted_data(data_size);

    if (IS_NON_MATCH_HASH(flags))
    {
        AziHsmShaHashType decrypt_hash_type = AziHsmShaHashType::SHA512;
        int ret = crypt_ctx.decryptRsa(decrypted_data, encrypted_data, decrypt_hash_type);

        if (decrypt_hash_type != hash_type)
            REQUIRE(ret == 0);
        else
            REQUIRE(ret > 0);
        return;
    }

    if (IS_TAMPER_CIPHER(flags))
    {
        // Tamper with the encrypted data
        encrypted_data[0] ^= 0xFF;
        REQUIRE(crypt_ctx.decryptRsa(decrypted_data, encrypted_data, hash_type) == 0);
        return;
    }

    if (IS_NEW_KEY(flags))
    {
        AziHsmPKeyRsaCtx crypt_new_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT);
        REQUIRE(crypt_new_ctx.decryptRsa(decrypted_data, encrypted_data, hash_type) > 0);

        if (IS_VERIFY_TWICE(flags))
        {
            REQUIRE(crypt_new_ctx.decryptRsa(decrypted_data, encrypted_data, hash_type) > 0);
        }
    }
    else if (IS_COPY_CTX(flags))
    {
        AziHsmPKeyRsaCtx crypt_ctx_copy = crypt_ctx.copyRsaCtx();
        REQUIRE(crypt_ctx_copy.decryptRsa(decrypted_data, encrypted_data, hash_type) > 0);
    }
    else
    {
        REQUIRE(crypt_ctx.decryptRsa(decrypted_data, encrypted_data, hash_type) > 0);

        if (IS_VERIFY_TWICE(flags))
        {
            REQUIRE(crypt_ctx.decryptRsa(decrypted_data, encrypted_data, hash_type) > 0);
        }
    }

    REQUIRE(plain_data == decrypted_data);
}

static int test_rsa_encrypt_aes_decrypt(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmShaHashType hash_type)
{
    // Unwrap RSA key for encryption
    AziHsmPKeyRsaCtx rsa_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT);
    REQUIRE(rsa_ctx.getCtx() != nullptr);

    // Encrypt data with RSA key
    std::vector<unsigned char> plain_data(32);
    REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);
    std::vector<unsigned char> encrypted_data;
    REQUIRE(rsa_ctx.encryptRsa(encrypted_data, plain_data, hash_type) > 0);

    // Attempt to decrypt with AES key (should fail)

    // Initialize AES context
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    const EVP_CIPHER *cipher;
    // Allocate CTX

    AziHsmAesCipherCtx aes_ctx = AziHsmAesCipherCtx();
    REQUIRE(aes_ctx.init(e, NID_aes_192_cbc, 0, nullptr, nullptr) == 1);

    // Attempt to decrypt with AES key (should fail)
    std::vector<unsigned char> decrypted_data(32);
    REQUIRE(aes_ctx.decrypt(encrypted_data.data(), encrypted_data.size(), nullptr, decrypted_data) <= 0);

    return 1;
}

static int test_encrypt_decrypt_invalid_key(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmShaHashType hash_type)
{
    // Unwrap key with Sign/Verify usage
    AziHsmPKeyRsaCtx sign_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_SIGN_VERIFY);
    REQUIRE(sign_ctx.getCtx() != nullptr);

    // Attempt to encrypt
    std::vector<unsigned char> plain_data(32);
    REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);
    std::vector<unsigned char> encrypted_data;

    REQUIRE(sign_ctx.encryptRsa(encrypted_data, plain_data, hash_type) > 0);

    // Attempt to decrypt
    std::vector<unsigned char> decrypted_data(32);
    REQUIRE(sign_ctx.decryptRsa(decrypted_data, encrypted_data, hash_type) == 0);

    return 1;
}

static int test_encrypt_decrypt_wrong_usage_copy_ctx(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmShaHashType hash_type,
    size_t data_size = 32)
{
    AziHsmPKeyRsaCtx enc_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT);
    REQUIRE(enc_ctx.getCtx() != nullptr);

    std::vector<unsigned char> plain_data(data_size);
    REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

    std::vector<unsigned char> encrypted_data;
    REQUIRE(enc_ctx.encryptRsa(encrypted_data, plain_data, hash_type) > 0);
    REQUIRE(encrypted_data.size() > 0);

    std::vector<unsigned char> decrypted_data(data_size);
    REQUIRE(enc_ctx.decryptRsa(decrypted_data, encrypted_data, hash_type) > 0);

    REQUIRE(plain_data == decrypted_data);

    AziHsmPKeyRsaCtx enc_ctx_copy = enc_ctx.copyRsaCtx();

    AziHsmShaHash hash(hash_type);
    std::vector<unsigned char> digest(hash.getSize());
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);

    std::vector<unsigned char> signature;

    REQUIRE(enc_ctx.signRsa(signature, digest, hash_type, AziHsmPaddingType::PKCS1_5) != 1);

    return 1;
}

// Common PKey test cases
TEST_CASE("AZIHSM PKEY RSA encrypt/decrypt", "[AziHsmPKeyRsaEncDec]")
{
    AziHsmEngine azihsm_engine = get_test_engine();

    SECTION("Get RSA PKey method by NID")
    {
        REQUIRE(AziHsmPKeyMethod(azihsm_engine.getEngine(), NID_rsaEncryption).getPKeyMethod() != nullptr);
    }

    SECTION("RSA encryption and decryption, normal (2048)")
    {
        // Minimum encryption sizes
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, 1);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, 1);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, 1);

        // different size

        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, 32);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, 32);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, 32);

        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, 48);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, 48);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, 48);

        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, 64);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, 64);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, 64);

        // Maximum encryption sizes
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, 190);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, 158);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, 126);
    }

    SECTION("RSA encryption and decryption, verify twice (2048)")
    {
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, 1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, 1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, 1, AziHsmRsaTestFlag::VERIFY_TWICE);

        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, 190, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, 158, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, 126, AziHsmRsaTestFlag::VERIFY_TWICE);
    }

    SECTION("RSA encryption and decryption, copy ctx (2048)")
    {
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, 1, AziHsmRsaTestFlag::COPY_CTX);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, 1, AziHsmRsaTestFlag::COPY_CTX);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, 1, AziHsmRsaTestFlag::COPY_CTX);

        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, 190, AziHsmRsaTestFlag::COPY_CTX);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, 158, AziHsmRsaTestFlag::COPY_CTX);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, 126, AziHsmRsaTestFlag::COPY_CTX);
    }

    SECTION("RSA encryption and decryption invalid_data_size (2048)")
    {
        // invalid encryption sizes
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, 191, AziHsmRsaTestFlag::INVALID_SIZE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, 159, AziHsmRsaTestFlag::INVALID_SIZE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, 127, AziHsmRsaTestFlag::INVALID_SIZE);
    }

    SECTION("RSA encryption and decryption, normal (3072)")
    {
        // Minimum encryption sizes
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, 1);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, 1);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, 1);

        // different size
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, 32);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, 32);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, 32);

        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, 48);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, 48);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, 48);

        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, 64);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, 64);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, 64);

        // Maximum encryption sizes
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, 318);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, 286);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, 254);
    }

    SECTION("RSA encryption and decryption, verify twice (3072)")
    {
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, 1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, 1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, 1, AziHsmRsaTestFlag::VERIFY_TWICE);

        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, 318, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, 286, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, 254, AziHsmRsaTestFlag::VERIFY_TWICE);
    }

    SECTION("RSA encryption and decryption, copy ctx (3072)")
    {
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, 1, AziHsmRsaTestFlag::COPY_CTX);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, 1, AziHsmRsaTestFlag::COPY_CTX);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, 1, AziHsmRsaTestFlag::COPY_CTX);

        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, 318, AziHsmRsaTestFlag::COPY_CTX);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, 286, AziHsmRsaTestFlag::COPY_CTX);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, 254, AziHsmRsaTestFlag::COPY_CTX);
    }

    SECTION("RSA encryption and decryption invalid_data_size (3072)")
    {
        // invalid encryption sizes
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, 319, AziHsmRsaTestFlag::INVALID_SIZE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, 287, AziHsmRsaTestFlag::INVALID_SIZE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, 255, AziHsmRsaTestFlag::INVALID_SIZE);
    }

    SECTION("RSA encryption and decryption, (size:  1, 32, 48) (4096)")
    {
        // Minimum encryption sizes
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, 1);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, 1);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, 1);

        // different size
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, 32);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, 32);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, 32);

        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, 48);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, 48);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, 48);
    }

    SECTION("RSA encryption and decryption, (size: 64, max) (4096)")
    {
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, 64);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, 64);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, 64);

        // Maximum encryption sizes
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, 446);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, 414);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, 382);
    }

    SECTION("RSA encryption and decryption, verify twice (4096)")
    {
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, 1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, 1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, 1, AziHsmRsaTestFlag::VERIFY_TWICE);

        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, 446, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, 414, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, 382, AziHsmRsaTestFlag::VERIFY_TWICE);
    }

    SECTION("RSA encryption and decryption, copy ctx (4096)")
    {
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, 1, AziHsmRsaTestFlag::COPY_CTX);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, 1, AziHsmRsaTestFlag::COPY_CTX);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, 1, AziHsmRsaTestFlag::COPY_CTX);

        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, 446, AziHsmRsaTestFlag::COPY_CTX);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, 414, AziHsmRsaTestFlag::COPY_CTX);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, 382, AziHsmRsaTestFlag::COPY_CTX);
    }

    SECTION("RSA encryption and decryption invalid_data_size (4096)")
    {
        // invalid encryption sizes
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, 447, AziHsmRsaTestFlag::INVALID_SIZE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, 415, AziHsmRsaTestFlag::INVALID_SIZE);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, 383, AziHsmRsaTestFlag::INVALID_SIZE);
    }

    SECTION("RSA encryption and decryption non matching hash key")
    {
        // non match_hash type
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, 32, AziHsmRsaTestFlag::NON_MATCH_HASH);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, 32, AziHsmRsaTestFlag::NON_MATCH_HASH);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, 32, AziHsmRsaTestFlag::NON_MATCH_HASH);
    }

    SECTION("RSA encryption and decryption tampering (2048)")
    {
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, 1, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, 1, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, 1, AziHsmRsaTestFlag::TAMPER_CIPHER);
    }

    SECTION("RSA encryption and decryption  tampering(3072)")
    {
        // Minimum encryption sizes
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, 1, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, 1, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, 1, AziHsmRsaTestFlag::TAMPER_CIPHER);
    }

    SECTION("RSA encryption and decryption tampering (4096)")
    {
        // Minimum encryption sizes
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, 1, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, 1, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_encrypt_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, 1, AziHsmRsaTestFlag::TAMPER_CIPHER);
    }

    SECTION("SignVerify key  Encrypt/Decrypt for different RSA key sizes")
    {
        REQUIRE(test_encrypt_decrypt_invalid_key(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256) == 1);
        REQUIRE(test_encrypt_decrypt_invalid_key(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256) == 1);
        REQUIRE(test_encrypt_decrypt_invalid_key(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256) == 1);
    }

    SECTION("Mismatched encryption/decryption algorithm ")
    {
        REQUIRE(test_rsa_encrypt_aes_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256) == 1);
        REQUIRE(test_rsa_encrypt_aes_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256) == 1);
        REQUIRE(test_rsa_encrypt_aes_decrypt(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256) == 1);
    }
}

TEST_CASE("AZIHSM PKEY RSA Copy ctx Enc/Dec wrong usage", "[AziHsmPKeyRsaCopyCtxEncDecWrongUsage]")
{
    AziHsmEngine azihsm_engine = get_test_engine();

    SECTION("RSA encryption/decryption wrong use (2048)")
    {
        test_encrypt_decrypt_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256);
        test_encrypt_decrypt_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384);
        test_encrypt_decrypt_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512);
    }

    SECTION("RSA encryption/decryption wrong use (3072)")
    {
        test_encrypt_decrypt_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256);
        test_encrypt_decrypt_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384);
        test_encrypt_decrypt_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512);
    }

    SECTION("RSA encryption/decryption wrong use (4096)")
    {
        test_encrypt_decrypt_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256);
        test_encrypt_decrypt_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384);
        test_encrypt_decrypt_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512);
    }
}