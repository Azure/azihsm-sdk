// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestRsa.hpp"
#include "AziHsmTestHash.hpp"
#include "../../../api-interface/azihsm_engine.h"
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <memory>
#include <catch2/catch_test_macros.hpp>

static void test_private_key_encryption_fail(AziHsmEngine &azihsm_engine, AziHsmRsaDefaultKey key)
{
    AziHsmRsa rsa = unwrap_test_rsa_key(azihsm_engine, key, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT);

    std::vector<unsigned char> plain_data = generate_random_vector(32);
    std::vector<unsigned char> encrypted_data(RSA_size(rsa.getKey()));

    // Ensure it fails for all padding types

    REQUIRE(RSA_private_encrypt(
                plain_data.size(),
                plain_data.data(),
                encrypted_data.data(),
                rsa.getKey(),
                RSA_NO_PADDING) < 1);

    REQUIRE(RSA_private_encrypt(
                plain_data.size(),
                plain_data.data(),
                encrypted_data.data(),
                rsa.getKey(),
                RSA_PKCS1_PADDING) < 1);

    REQUIRE(RSA_private_encrypt(
                plain_data.size(),
                plain_data.data(),
                encrypted_data.data(),
                rsa.getKey(),
                RSA_PKCS1_PSS_PADDING) < 1);
}

static void test_public_key_decryption_fail(AziHsmEngine &azihsm_engine, AziHsmRsaDefaultKey key)
{
    // This should create a RSA key structure without ENGINE reference
    AziHsmRsa rsa_ossl(get_default_rsa_key(key));
    const int encrypted_size = RSA_size(rsa_ossl.getKey());
    const int decrypted_size = 2;
    std::vector<unsigned char> encrypted_data(encrypted_size);
    std::vector<unsigned char> plain_data(decrypted_size, 0xAA);

    // Encrypt with private key
    int len = RSA_private_encrypt(
        plain_data.size(),
        plain_data.data(),
        encrypted_data.data(),
        rsa_ossl.getKey(),
        RSA_PKCS1_PADDING);
    REQUIRE(len > 0);

    AziHsmRsa rsa = unwrap_test_rsa_key(azihsm_engine, key, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT);

    std::vector<unsigned char> decrypted_data(decrypted_size);

    // Ensure decryption fails
    REQUIRE(RSA_public_decrypt(
                encrypted_data.size(),
                encrypted_data.data(),
                decrypted_data.data(),
                rsa.getKey(),
                RSA_PKCS1_PADDING) < 1);
}

TEST_CASE("AZIHSM RSA enc/dec", "[AziHsmRsaEncDec]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("Encrypt with empty plaintext (RSA 2048)")
    {
        std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
        std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, RSA_PRIV_KEY_2048);
        REQUIRE(wrapped_blob.size() > 0);

        AziHsmRsa rsa(e);
        REQUIRE(azihsm_engine.unwrapRsa(
                    rsa.getKey(),
                    AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT,
                    wrapped_blob,
                    AZIHSM_DIGEST_SHA1,
                    nullptr,
                    AZIHSM_AVAILABILITY_SESSION) > 0);

        std::vector<unsigned char> plain_data;
        std::vector<unsigned char> encrypted_data;

        REQUIRE(rsa.encrypt(encrypted_data, plain_data) == 0);
    }

    SECTION("Decrypt with empty ciphertext (RSA 2048)")
    {
        std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
        std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, RSA_PRIV_KEY_2048);
        REQUIRE(wrapped_blob.size() > 0);

        AziHsmRsa rsa(e);
        REQUIRE(azihsm_engine.unwrapRsa(
                    rsa.getKey(),
                    AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT,
                    wrapped_blob,
                    AZIHSM_DIGEST_SHA1,
                    nullptr,
                    AZIHSM_AVAILABILITY_SESSION) > 0);

        std::vector<unsigned char> decrypted_data;
        std::vector<unsigned char> encrypted_data;

        REQUIRE(rsa.decrypt(decrypted_data, encrypted_data) == 0);
    }

    SECTION("Encrypt/decrypt with a wrapped key (RSA 2048)")
    {
        AziHsmRsa rsa = unwrap_test_rsa_key(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT);

        std::vector<unsigned char> plain_data(32);
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

        std::vector<unsigned char> encrypted_data;
        std::vector<unsigned char> decrypted_data(32);
        REQUIRE(rsa.encrypt(encrypted_data, plain_data) > 0);
        REQUIRE(rsa.decrypt(decrypted_data, encrypted_data) > 0);

        REQUIRE(plain_data == decrypted_data);
    }

    SECTION("Encrypt with empty plaintext (RSA 3072)")
    {
        std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
        std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, RSA_PRIV_KEY_3072);
        REQUIRE(wrapped_blob.size() > 0);

        AziHsmRsa rsa(e);
        REQUIRE(azihsm_engine.unwrapRsa(
                    rsa.getKey(),
                    AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT,
                    wrapped_blob,
                    AZIHSM_DIGEST_SHA1,
                    nullptr,
                    AZIHSM_AVAILABILITY_SESSION) > 0);

        std::vector<unsigned char> plain_data;
        std::vector<unsigned char> encrypted_data;

        REQUIRE(rsa.encrypt(encrypted_data, plain_data) == 0);
    }

    SECTION("Decrypt with empty ciphertext (RSA 3072)")
    {
        std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
        std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, RSA_PRIV_KEY_3072);
        REQUIRE(wrapped_blob.size() > 0);

        AziHsmRsa rsa(e);
        REQUIRE(azihsm_engine.unwrapRsa(
                    rsa.getKey(),
                    AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT,
                    wrapped_blob,
                    AZIHSM_DIGEST_SHA1,
                    nullptr,
                    AZIHSM_AVAILABILITY_SESSION) > 0);

        std::vector<unsigned char> decrypted_data;
        std::vector<unsigned char> encrypted_data;

        REQUIRE(rsa.decrypt(decrypted_data, encrypted_data) == 0);
    }

    SECTION("Encrypt/decrypt with a wrapped key (RSA 3072)")
    {
        AziHsmRsa rsa = unwrap_test_rsa_key(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT);

        std::vector<unsigned char> plain_data(32);
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

        std::vector<unsigned char> encrypted_data;
        std::vector<unsigned char> decrypted_data(32);
        REQUIRE(rsa.encrypt(encrypted_data, plain_data) > 0);
        REQUIRE(rsa.decrypt(decrypted_data, encrypted_data) > 0);

        REQUIRE(plain_data == decrypted_data);
    }

    SECTION("Encrypt with empty plaintext (RSA 4096)")
    {
        std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
        std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, RSA_PRIV_KEY_4096);
        REQUIRE(wrapped_blob.size() > 0);

        AziHsmRsa rsa(e);
        REQUIRE(azihsm_engine.unwrapRsa(
                    rsa.getKey(),
                    AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT,
                    wrapped_blob,
                    AZIHSM_DIGEST_SHA1,
                    nullptr,
                    AZIHSM_AVAILABILITY_SESSION) > 0);

        std::vector<unsigned char> plain_data;
        std::vector<unsigned char> encrypted_data;

        REQUIRE(rsa.encrypt(encrypted_data, plain_data) == 0);
    }

    SECTION("Decrypt with empty ciphertext (RSA 4096)")
    {
        std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
        std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, RSA_PRIV_KEY_4096);
        REQUIRE(wrapped_blob.size() > 0);

        AziHsmRsa rsa(e);
        REQUIRE(azihsm_engine.unwrapRsa(
                    rsa.getKey(),
                    AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT,
                    wrapped_blob,
                    AZIHSM_DIGEST_SHA1,
                    nullptr,
                    AZIHSM_AVAILABILITY_SESSION) > 0);

        std::vector<unsigned char> decrypted_data;
        std::vector<unsigned char> encrypted_data;

        REQUIRE(rsa.decrypt(decrypted_data, encrypted_data) == 0);
    }

    SECTION("Encrypt/decrypt with a wrapped key (RSA 4096)")
    {
        AziHsmRsa rsa = unwrap_test_rsa_key(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT);

        std::vector<unsigned char> plain_data(32);
        REQUIRE(RAND_bytes(plain_data.data(), plain_data.size()) == 1);

        std::vector<unsigned char> encrypted_data;
        std::vector<unsigned char> decrypted_data(32);
        REQUIRE(rsa.encrypt(encrypted_data, plain_data) > 0);
        REQUIRE(rsa.decrypt(decrypted_data, encrypted_data) > 0);

        REQUIRE(plain_data == decrypted_data);
    }
}

TEST_CASE("AZIHSM RSA private key encryption (unimplemented)", "[AziHsmRsaPrivKeyEnc]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("Test RSA private key encryption 2048 bits")
    {
        test_private_key_encryption_fail(azihsm_engine, AziHsmRsaDefaultKey::RSA2048);
    }

    SECTION("Test RSA private key encryption 3072 bits")
    {
        test_private_key_encryption_fail(azihsm_engine, AziHsmRsaDefaultKey::RSA3072);
    }

    SECTION("Test RSA private key encryption 4096 bits")
    {
        test_private_key_encryption_fail(azihsm_engine, AziHsmRsaDefaultKey::RSA4096);
    }
}

TEST_CASE("AZIHSM RSA public key decryption (unimplemented)", "[AziHsmRsaPubKeyDec]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("Test RSA public key decryption 2048 bits")
    {
        test_public_key_decryption_fail(azihsm_engine, AziHsmRsaDefaultKey::RSA2048);
    }

    SECTION("Test RSA public key decryption 3072 bits")
    {
        test_public_key_decryption_fail(azihsm_engine, AziHsmRsaDefaultKey::RSA3072);
    }

    SECTION("Test RSA public key decryption 4096 bits")
    {
        test_public_key_decryption_fail(azihsm_engine, AziHsmRsaDefaultKey::RSA4096);
    }
}
