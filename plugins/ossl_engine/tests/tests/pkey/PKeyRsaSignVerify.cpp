// Copyright (c) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include "AziHsmTestPKey.hpp"
#include "AziHsmPKeyRsa.hpp"
#include "AziHsmRsa.hpp"
#include "AziHsmTestHash.hpp"
#include "AziHsmTestFlags.hpp"
#include "../../../api-interface/azihsm_engine.h"

static int ossl_verify(AziHsmRsaDefaultKey key, const std::vector<unsigned char> &signature, const std::vector<unsigned char> &digest, AziHsmShaHashType hash_type, AziHsmPaddingType padding_type, int salt_len)
{
    // OpenSSL compatibility check
    // Verify with OpenSSL API
    AziHsmPKey evp_rsa_ossl(EVP_PKEY_RSA, get_default_rsa_key(key));
    REQUIRE(evp_rsa_ossl.getPKey() != nullptr);

    AziHsmPKeyRsaCtx ossl_ctx(evp_rsa_ossl.getPKey(), nullptr);
    REQUIRE(ossl_ctx.getCtx() != nullptr);
    REQUIRE(ossl_ctx.verifyRsa(signature, digest, hash_type, padding_type, salt_len) == 1);
    return 1;
}

static int test_ossl_compat_sign_verify(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmShaHashType hash_type,
    AziHsmPaddingType padding_type,
    int salt_len = 0)
{
    AziHsmPKeyRsaCtx sig_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_SIGN_VERIFY);
    AziHsmShaHash hash(hash_type);
    std::vector<unsigned char> digest(hash.getSize());
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);

    std::vector<unsigned char> signature;
    if (sig_ctx.signRsa(signature, digest, hash_type, padding_type, salt_len) == 0)
    {
        return 0;
    }

    size_t signature_len;
    switch (key)
    {
    case AziHsmRsaDefaultKey::RSA2048:
        signature_len = 256;
        break;
    case AziHsmRsaDefaultKey::RSA3072:
        signature_len = 384;
        break;
    case AziHsmRsaDefaultKey::RSA4096:
        signature_len = 512;
        break;
    }
    REQUIRE(signature_len == signature.size());
    return ossl_verify(key, signature, digest, hash_type, padding_type, salt_len);
}

static void test_sign_verify(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmShaHashType hash_type,
    AziHsmPaddingType padding_type,
    int salt_len = 0,
    unsigned int flags = AziHsmRsaTestFlag::RSA_TEST_NORMAL)
{
    AziHsmPKeyRsaCtx sig_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_SIGN_VERIFY);

    AziHsmShaHash hash(hash_type);

    if (IS_INVALID_SIZE(flags))
    {
        std::vector<unsigned char> invalid_digest(hash.getSize() + 10); // Incorrect size
        REQUIRE(RAND_bytes(invalid_digest.data(), invalid_digest.size()) == 1);
        std::vector<unsigned char> signature;
        REQUIRE(sig_ctx.signRsa(signature, invalid_digest, hash_type, padding_type, salt_len) != 1); // Should fail

        return;
    }

    std::vector<unsigned char> digest(hash.getSize());
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);

    std::vector<unsigned char> signature;
    REQUIRE(sig_ctx.signRsa(signature, digest, hash_type, padding_type, salt_len) == 1);

    size_t signature_len;
    switch (key)
    {
    case AziHsmRsaDefaultKey::RSA2048:
        signature_len = 256;
        break;
    case AziHsmRsaDefaultKey::RSA3072:
        signature_len = 384;
        break;
    case AziHsmRsaDefaultKey::RSA4096:
        signature_len = 512;
        break;
    }

    REQUIRE(signature_len == signature.size());

    int expected;
    if (IS_TAMPER_CIPHER(flags))
    {
        expected = 0;
        digest[0] ^= 0x1;
    }
    else
    {
        expected = 1;
    }

    if (IS_NEW_KEY(flags))
    {
        AziHsmPKeyRsaCtx sig_new_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_SIGN_VERIFY);
        REQUIRE(sig_new_ctx.verifyRsa(signature, digest, hash_type, padding_type, salt_len) == expected);

        if (IS_VERIFY_TWICE(flags))
        {
            REQUIRE(sig_new_ctx.verifyRsa(signature, digest, hash_type, padding_type, salt_len) == expected);
        }
    }
    else if (IS_COPY_CTX(flags))
    {
        AziHsmPKeyRsaCtx sig_ctx_copy = sig_ctx.copyRsaCtx();
        REQUIRE(sig_ctx_copy.verifyRsa(signature, digest, hash_type, padding_type, salt_len) == expected);
    }
    else
    {
        REQUIRE(sig_ctx.verifyRsa(signature, digest, hash_type, padding_type, salt_len) == expected);

        if (IS_VERIFY_TWICE(flags))
        {
            REQUIRE(sig_ctx.verifyRsa(signature, digest, hash_type, padding_type, salt_len) == expected);
        }
    }
}

static void test_sign_verify_mismatched_padding(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmShaHashType hash_type)
{
    AziHsmPKeyRsaCtx sign_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_SIGN_VERIFY);
    REQUIRE(sign_ctx.getCtx() != nullptr);

    AziHsmShaHash hash(hash_type);
    std::vector<unsigned char> digest(hash.getSize());
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);

    std::vector<unsigned char> signature;
    REQUIRE(sign_ctx.signRsa(signature, digest, hash_type, AziHsmPaddingType::PSS) > 0);
    REQUIRE(signature.size() > 0);

    // Attempt verification with mismatched padding (PKCS1_5)
    REQUIRE(sign_ctx.verifyRsa(signature, digest, hash_type, AziHsmPaddingType::PKCS1_5) == 0);

    return;
}

static void test_sign_verify_non_matching_hash(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmShaHashType sign_hash_type,
    AziHsmShaHashType verify_hash_type,
    AziHsmPaddingType padding_type,
    int salt_len = 0)
{
    AziHsmPKeyRsaCtx sig_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_SIGN_VERIFY);

    AziHsmShaHash sign_hash(sign_hash_type);
    std::vector<unsigned char> digest(sign_hash.getSize());
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);

    std::vector<unsigned char> signature;
    REQUIRE(sig_ctx.signRsa(signature, digest, sign_hash_type, padding_type, salt_len) == 1);
    REQUIRE(signature.size() > 0);

    AziHsmPKeyRsaCtx verify_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_SIGN_VERIFY);

    // Verify with a different hash type, should fail
    REQUIRE(verify_ctx.verifyRsa(signature, digest, verify_hash_type, padding_type, salt_len) == 0);
}

static void test_sign_with_encrypt_decrypt_key(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmShaHashType hash_type,
    AziHsmPaddingType padding_type,
    uint16_t salt_len = 0)
{
    // Unwrap the key with Encrypt/Decrypt usage instead of Sign/Verify
    AziHsmPKeyRsaCtx enc_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT);

    AziHsmShaHash hash(hash_type);
    std::vector<unsigned char> digest(hash.getSize());
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);

    std::vector<unsigned char> signature;

    // Attempting to sign with an Encrypt/Decrypt key should fail
    REQUIRE(enc_ctx.signRsa(signature, digest, hash_type, padding_type, salt_len) == 0);
}

static void test_verify_with_tampered_digest(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmShaHashType hash_type,
    AziHsmPaddingType padding_type,
    uint16_t salt_len = 0)
{
    // Unwrap the key for signing
    AziHsmPKeyRsaCtx sign_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_SIGN_VERIFY);
    REQUIRE(sign_ctx.getCtx() != nullptr);

    // Generate a valid digest
    AziHsmShaHash hash(hash_type);
    std::vector<unsigned char> digest(hash.getSize());
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);

    // Sign the digest
    std::vector<unsigned char> signature;
    REQUIRE(sign_ctx.signRsa(signature, digest, hash_type, padding_type, salt_len) == 1);

    // Flip a bit in the digest to simulate tampering
    digest[0] ^= 0x01;

    // Verify with tampered digest (should fail)
    REQUIRE(sign_ctx.verifyRsa(signature, digest, hash_type, padding_type, salt_len) == 0);
}

static int test_sign_verify_wrong_usage_copy_ctx(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmShaHashType hash_type,
    AziHsmPaddingType padding_type,
    uint16_t salt_len = 0)
{
    AziHsmPKeyRsaCtx sign_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key, AziHsmKeyUsage::AZIHSM_KEY_USAGE_SIGN_VERIFY);
    REQUIRE(sign_ctx.getCtx() != nullptr);

    AziHsmShaHash hash(hash_type);
    std::vector<unsigned char> digest(hash.getSize());
    REQUIRE(RAND_bytes(digest.data(), digest.size()) == 1);

    std::vector<unsigned char> signature;
    REQUIRE(sign_ctx.signRsa(signature, digest, hash_type, padding_type, salt_len) > 0);
    REQUIRE(signature.size() > 0);

    REQUIRE(sign_ctx.verifyRsa(signature, digest, hash_type, padding_type, salt_len) == 1);

    AziHsmPKeyRsaCtx sign_ctx_copy = sign_ctx.copyRsaCtx();

    // Decrypt uses private key, so this should fail with wrong usage
    std::vector<unsigned char> encrypted_data(signature.size());
    std::vector<unsigned char> decrypted_data(digest.size());
    REQUIRE(sign_ctx_copy.decryptRsa(decrypted_data, encrypted_data, hash_type) <= 0);

    return 1;
}

TEST_CASE("AZIHSM PKEY RSA sign/verify OpenSSL compatibility", "[AziHsmPkeyRsaSignVerifyOssl]")
{
    AziHsmEngine azihsm_engine = get_test_engine();

    SECTION("RSA sign/verify (2048, SHA256)")
    {
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 20) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 32) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -1) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -2) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -3) == 0);
    }
    SECTION("RSA sign/verify (2048, SHA384)")
    {
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 20) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 32) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 48) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -1) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -2) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -3) == 0);
    }
    SECTION("RSA sign/verify (2048, SHA512)")
    {
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 20) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 32) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 48) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -1) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -2) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -3) == 0);
    }

    SECTION("RSA sign/verify (3072, SHA256)")
    {
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 20) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 32) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -1) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -2) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -3) == 0);
    }

    SECTION("RSA sign/verify (3072, SHA384)")
    {
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 20) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 32) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 48) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -1) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -2) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -3) == 0);
    }
    SECTION("RSA sign/verify (3072, SHA512)")
    {
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 20) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 32) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 48) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -1) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -2) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -3) == 0);
    }

    SECTION("RSA sign/verify (4096, SHA256)")
    {
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 20) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 32) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -1) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -2) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -3) == 0);
    }

    SECTION("RSA sign/verify (4096, SHA384)")
    {
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 20) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 32) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 48) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -1) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -2) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -3) == 0);
    }

    SECTION("RSA sign/verify (4096, SHA512)")
    {
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 20) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 32) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 48) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -1) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -2) == 1);
        REQUIRE(test_ossl_compat_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -3) == 0);
    }
}

TEST_CASE("AZIHSM PKEY RSA sign/verify", "[AziHsmPkeyRsaSignVerify]")
{
    AziHsmEngine azihsm_engine = get_test_engine();

    SECTION("RSA signing and verifying, normal (2048, SHA256)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 32);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -1);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -2);
    }

    SECTION("RSA signing and verifying, normal (2048, SHA384)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 48);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -1);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -2);
    }

    SECTION("RSA signing and verifying, normal (2048, SHA512)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -1);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -2);
    }

    SECTION("RSA signing and verifying, verify twice (2048, SHA256)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 32, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::VERIFY_TWICE);
    }

    SECTION("RSA signing and verifying, verify twice (2048, SHA384)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 48, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::VERIFY_TWICE);
    }

    SECTION("RSA signing and verifying, verify twice (2048, SHA512)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::VERIFY_TWICE);
    }

    SECTION("RSA signing and verifying, copy context (2048, SHA256)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 32, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::COPY_CTX);
    }

    SECTION("RSA signing and verifying, copy context (2048, SHA384)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 48, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::COPY_CTX);
    }

    SECTION("RSA signing and verifying, copy context (2048, SHA512)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::COPY_CTX);
    }

    SECTION("RSA signing and verifying, normal (3072, SHA256)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 32);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -1);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -2);
    }

    SECTION("RSA signing and verifying, normal (3072, SHA384)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 48);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -1);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -2);
    }

    SECTION("RSA signing and verifying, normal (3072, SHA512)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -1);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -2);
    }

    SECTION("RSA signing and verifying, verify twice (3072, SHA256)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 32, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::VERIFY_TWICE);
    }

    SECTION("RSA signing and verifying, verify twice (3072, SHA384)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 48, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::VERIFY_TWICE);
    }

    SECTION("RSA signing and verifying, verify twice (3072, SHA512)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::VERIFY_TWICE);
    }

    SECTION("RSA signing and verifying, copy ctx (3072, SHA256)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 32, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::COPY_CTX);
    }

    SECTION("RSA signing and verifying, copy ctx (3072, SHA384)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 48, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::COPY_CTX);
    }

    SECTION("RSA signing and verifying, copy ctx (3072, SHA512)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::COPY_CTX);
    }

    SECTION("RSA signing and verifying, normal (4096, SHA256)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 32);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -1);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -2);
    }

    SECTION("RSA signing and verifying, normal (4096, SHA384)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 48);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -1);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -2);
    }

    SECTION("RSA signing and verifying, normal (4096, SHA512)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -1);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -2);
    }

    SECTION("RSA signing and verifying, verify twice (4096, SHA256)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 32, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::VERIFY_TWICE);
    }

    SECTION("RSA signing and verifying, verify twice (4096, SHA384)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 48, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::VERIFY_TWICE);
    }

    SECTION("RSA signing and verifying, verify twice (4096, SHA512)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::VERIFY_TWICE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::VERIFY_TWICE);
    }

    SECTION("RSA signing and verifying, copy ctx (4096, SHA256)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 32, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::COPY_CTX);
    }

    SECTION("RSA signing and verifying, copy ctx (4096, SHA384)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 48, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::COPY_CTX);
    }

    SECTION("RSA signing and verifying, copy ctx (4096, SHA512)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -1, AziHsmRsaTestFlag::COPY_CTX);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, -2, AziHsmRsaTestFlag::COPY_CTX);
    }

    SECTION("RSA signature data tampering (2048, SHA256)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::TAMPER_CIPHER);
    }

    SECTION("RSA signature data tampering (2048, SHA384)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::TAMPER_CIPHER);
    }

    SECTION("RSA signature data tampering (2048, SHA512)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::TAMPER_CIPHER);
    }

    SECTION("RSA signature data tampering (3072, SHA256)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::TAMPER_CIPHER);
    }

    SECTION("RSA signature data tampering (3072, SHA384)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::TAMPER_CIPHER);
    }

    SECTION("RSA signature data tampering (3072, SHA512)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::TAMPER_CIPHER);
    }

    SECTION("RSA signature data tampering (4096, SHA256)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::TAMPER_CIPHER);
    }

    SECTION("RSA signature data tampering (4096, SHA384)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::TAMPER_CIPHER);
    }

    SECTION("RSA signature data tampering (4096, SHA512)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD, 0, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5, 0, AziHsmRsaTestFlag::TAMPER_CIPHER);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 0, AziHsmRsaTestFlag::TAMPER_CIPHER);
    }

    SECTION("RSA sign/verify with invalid data size (2048)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, 32, AziHsmRsaTestFlag::INVALID_SIZE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, UINT16_MAX, AziHsmRsaTestFlag::INVALID_SIZE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64, AziHsmRsaTestFlag::INVALID_SIZE);
    }

    SECTION("RSA sign/verify with invalid data size (3072)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, 32, AziHsmRsaTestFlag::INVALID_SIZE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, UINT16_MAX, AziHsmRsaTestFlag::INVALID_SIZE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64, AziHsmRsaTestFlag::INVALID_SIZE);
    }

    SECTION("RSA sign/verify with invalid data size (4096)")
    {
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, 32, AziHsmRsaTestFlag::INVALID_SIZE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, UINT16_MAX, AziHsmRsaTestFlag::INVALID_SIZE);
        test_sign_verify(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS, 64, AziHsmRsaTestFlag::INVALID_SIZE);
    }

    SECTION("RSA 2048 Sign with PSS, Verify with PKCS1_5 ")
    {
        test_sign_verify_mismatched_padding(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256);
        test_sign_verify_mismatched_padding(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384);
        test_sign_verify_mismatched_padding(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512);
    }

    SECTION("RSA 3072 Sign with PSS, Verify with PKCS1_5 ")
    {
        test_sign_verify_mismatched_padding(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256);
        test_sign_verify_mismatched_padding(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384);
        test_sign_verify_mismatched_padding(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512);
    }

    SECTION("RSA 4096 Sign with PSS, Verify with PKCS1_5 ")
    {
        test_sign_verify_mismatched_padding(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256);
        test_sign_verify_mismatched_padding(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384);
        test_sign_verify_mismatched_padding(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512);
    }

    SECTION("RSA 2048 sign with Encrypt/Decrypt key ")
    {
        test_sign_with_encrypt_decrypt_key(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS);
        test_sign_with_encrypt_decrypt_key(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5);
        test_sign_with_encrypt_decrypt_key(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5);
    }

    SECTION("RSA 3072 sign with Encrypt/Decrypt key ")
    {
        test_sign_with_encrypt_decrypt_key(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS);
        test_sign_with_encrypt_decrypt_key(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5);
        test_sign_with_encrypt_decrypt_key(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5);
    }

    SECTION("RSA 4096 sign with Encrypt/Decrypt key ")
    {
        test_sign_with_encrypt_decrypt_key(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS);
        test_sign_with_encrypt_decrypt_key(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5);
        test_sign_with_encrypt_decrypt_key(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5);
    }

    SECTION("RSA 2048 verify with tampered digest - SHA256")
    {
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS);
    }

    SECTION("RSA 2048 verify with tampered digest - SHA384")
    {
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS);
    }

    SECTION("RSA 2048 verify with tampered digest - SHA512")
    {
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS);
    }

    SECTION("RSA 3072 verify with tampered digest SHA256")
    {
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS);
    }

    SECTION("RSA 3072 verify with tampered digest SHA384")
    {
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS);
    }

    SECTION("RSA 3072 verify with tampered digest SHA512")
    {
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS);
    }

    SECTION("RSA 4096 verify with tampered digest SHA256")
    {
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS);
    }

    SECTION("RSA 4096 verify with tampered digest SHA384")
    {
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS);
    }

    SECTION("RSA 4096 verify with tampered digest SHA512")
    {
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5);
        test_verify_with_tampered_digest(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS);
    }
}

TEST_CASE("AZIHSM PKEY RSA Copy ctx Sign/Verify wrong usage", "[AziHsmPKeyRsaCopyCtxSignVerifyWrongUsage]")
{
    AziHsmEngine azihsm_engine = get_test_engine();

    SECTION("RSA sign/verify wrong use (2048, SHA256)")
    {
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, UINT16_MAX);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS);
    }

    SECTION("RSA sign/verify wrong use (2048, SHA384)")
    {
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, UINT16_MAX);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS);
    }

    SECTION("RSA sign/verify wrong use (2048, SHA512)")
    {
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5, UINT16_MAX);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS);
    }

    SECTION("RSA sign/verify wrong use (3072, SHA256)")
    {
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, UINT16_MAX);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS);
    }

    SECTION("RSA sign/verify wrong use (3072, SHA384)")
    {
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, UINT16_MAX);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS);
    }

    SECTION("RSA sign/verify wrong use (3072, SHA512)")
    {
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5, UINT16_MAX);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS);
    }

    SECTION("RSA sign/verify wrong use (4096, SHA256)")
    {
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::NO_PAD);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PKCS1_5, UINT16_MAX);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256, AziHsmPaddingType::PSS);
    }

    SECTION("RSA sign/verify wrong use (4096, SHA384)")
    {
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::NO_PAD);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PKCS1_5, UINT16_MAX);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384, AziHsmPaddingType::PSS);
    }

    SECTION("RSA sign/verify wrong use (4096, SHA512)")
    {
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::NO_PAD);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PKCS1_5, UINT16_MAX);
        test_sign_verify_wrong_usage_copy_ctx(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512, AziHsmPaddingType::PSS);
    }
}
