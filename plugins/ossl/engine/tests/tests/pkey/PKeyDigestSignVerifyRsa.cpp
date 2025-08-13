// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestPKey.hpp"
#include "AziHsmDigestSignVerify.hpp"
#include "AziHsmPKeyRsa.hpp"
#include "AziHsmHash.hpp"
#include "AziHsmPKeys.hpp"

static void verify_rsa(AziHsmEngine &azihsm_engine, AziHsmRsaDefaultKey key_type, AziHsmShaHashType hash_type)
{
    std::string test_text = "Please ensure no body tampers this message";
    std::vector<unsigned char> message(test_text.begin(), test_text.end());

    AziHsmPKeyRsaCtx pkey_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key_type, AZIHSM_KEY_USAGE_SIGN_VERIFY);
    EVP_PKEY *pkey = pkey_ctx.getPKey();
    AziHsmDigestSignVerify sign_verify(azihsm_engine.getEngine(), pkey, hash_type);

    std::vector<unsigned char> sig;

    REQUIRE(sign_verify.sign(sig, message) == 1);
    REQUIRE(sign_verify.verify(sig, message) == 1);
}

static void verify_rsa_tampered_data(AziHsmEngine &azihsm_engine, AziHsmRsaDefaultKey key_type, AziHsmShaHashType hash_type)
{
    std::string test_text = "Please ensure no body tampers this message";
    std::vector<unsigned char> message(test_text.begin(), test_text.end());

    AziHsmPKeyRsaCtx pkey_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key_type, AZIHSM_KEY_USAGE_SIGN_VERIFY);
    EVP_PKEY *pkey = pkey_ctx.getPKey();
    AziHsmDigestSignVerify sign_verify(azihsm_engine.getEngine(), pkey, hash_type);

    std::vector<unsigned char> sig;

    REQUIRE(sign_verify.sign(sig, message) == 1);

    // Tamper with the message
    message[0] ^= 0x01;

    REQUIRE(sign_verify.verify(sig, message) == 0);
}

static void verify_rsa_tampered_signature(AziHsmEngine &azihsm_engine, AziHsmRsaDefaultKey key_type, AziHsmShaHashType hash_type)
{
    std::string test_text = "Please ensure no body tampers this message";
    std::vector<unsigned char> message(test_text.begin(), test_text.end());

    AziHsmPKeyRsaCtx pkey_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key_type, AZIHSM_KEY_USAGE_SIGN_VERIFY);
    EVP_PKEY *pkey = pkey_ctx.getPKey();
    AziHsmDigestSignVerify sign_verify(azihsm_engine.getEngine(), pkey, hash_type);

    std::vector<unsigned char> sig;

    REQUIRE(sign_verify.sign(sig, message) == 1);

    // Tamper with the signature
    sig[0] ^= 0x01;

    REQUIRE(sign_verify.verify(sig, message) == 0);
}

static void verify_rsa_copy(AziHsmEngine &azihsm_engine, AziHsmRsaDefaultKey key_type, AziHsmShaHashType hash_type)
{
    std::string test_text = "Please ensure no body tampers this message";
    std::vector<unsigned char> message(test_text.begin(), test_text.end());

    AziHsmPKeyRsaCtx pkey_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key_type, AZIHSM_KEY_USAGE_SIGN_VERIFY);
    EVP_PKEY *pkey = pkey_ctx.getPKey();
    AziHsmDigestSignVerify sign_verify(azihsm_engine.getEngine(), pkey, hash_type);

    std::vector<unsigned char> sig;

    REQUIRE(sign_verify.sign(sig, message) == 1);

    AziHsmPKeyRsaCtx pkey_copy_ctx = pkey_ctx.copyRsaCtx();
    EVP_PKEY *pkey_copy = pkey_copy_ctx.getPKey();
    AziHsmDigestSignVerify sign_verify_copy(azihsm_engine.getEngine(), pkey_copy, hash_type);

    REQUIRE(sign_verify_copy.verify(sig, message) == 1);
}

static void verify_rsa_tampered_data_copy(AziHsmEngine &azihsm_engine, AziHsmRsaDefaultKey key_type, AziHsmShaHashType hash_type)
{
    std::string test_text = "Please ensure no body tampers this message";
    std::vector<unsigned char> message(test_text.begin(), test_text.end());

    AziHsmPKeyRsaCtx pkey_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key_type, AZIHSM_KEY_USAGE_SIGN_VERIFY);
    EVP_PKEY *pkey = pkey_ctx.getPKey();
    AziHsmDigestSignVerify sign_verify(azihsm_engine.getEngine(), pkey, hash_type);

    std::vector<unsigned char> sig;

    REQUIRE(sign_verify.sign(sig, message) == 1);

    // Tamper with the message
    message[0] ^= 0x01;

    AziHsmPKeyRsaCtx pkey_copy_ctx = pkey_ctx.copyRsaCtx();
    EVP_PKEY *pkey_copy = pkey_copy_ctx.getPKey();
    AziHsmDigestSignVerify sign_verify_copy(azihsm_engine.getEngine(), pkey_copy, hash_type);

    REQUIRE(sign_verify_copy.verify(sig, message) == 0);
}

static void verify_rsa_tampered_signature_copy(AziHsmEngine &azihsm_engine, AziHsmRsaDefaultKey key_type, AziHsmShaHashType hash_type)
{
    std::string test_text = "Please ensure no body tampers this message";
    std::vector<unsigned char> message(test_text.begin(), test_text.end());

    AziHsmPKeyRsaCtx pkey_ctx = unwrap_test_rsa_pkey_ctx_key(azihsm_engine, key_type, AZIHSM_KEY_USAGE_SIGN_VERIFY);
    EVP_PKEY *pkey = pkey_ctx.getPKey();
    AziHsmDigestSignVerify sign_verify(azihsm_engine.getEngine(), pkey, hash_type);

    std::vector<unsigned char> sig;

    REQUIRE(sign_verify.sign(sig, message) == 1);

    // Tamper with the signature
    sig[0] ^= 0x01;

    AziHsmPKeyRsaCtx pkey_copy_ctx = pkey_ctx.copyRsaCtx();
    EVP_PKEY *pkey_copy = pkey_copy_ctx.getPKey();
    AziHsmDigestSignVerify sign_verify_copy(azihsm_engine.getEngine(), pkey_copy, hash_type);

    REQUIRE(sign_verify_copy.verify(sig, message) == 0);
}

TEST_CASE("AZIHSM PKEY RSA signctx/verifyctx", "[AziHsmPkeyRsaSignVerifyCtx]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("RSA sign/verifyctx")
    {
        verify_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256);
        verify_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384);
        verify_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512);

        verify_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256);
        verify_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384);
        verify_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512);

        verify_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256);
        verify_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384);
        verify_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512);
    }

    SECTION("RSA sign/verifyctx with copied key")
    {
        verify_rsa_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256);
        verify_rsa_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384);
        verify_rsa_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512);

        verify_rsa_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256);
        verify_rsa_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384);
        verify_rsa_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512);

        verify_rsa_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256);
        verify_rsa_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384);
        verify_rsa_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512);
    }

    SECTION("RSA sign/verifyctx tampered data")
    {
        verify_rsa_tampered_data(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256);
        verify_rsa_tampered_data(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384);
        verify_rsa_tampered_data(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512);

        verify_rsa_tampered_data(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256);
        verify_rsa_tampered_data(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384);
        verify_rsa_tampered_data(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512);

        verify_rsa_tampered_data(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256);
        verify_rsa_tampered_data(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384);
        verify_rsa_tampered_data(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512);
    }

    SECTION("RSA sign/verifyctx tampered data with copied key")
    {
        verify_rsa_tampered_data_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256);
        verify_rsa_tampered_data_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384);
        verify_rsa_tampered_data_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512);

        verify_rsa_tampered_data_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256);
        verify_rsa_tampered_data_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384);
        verify_rsa_tampered_data_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512);

        verify_rsa_tampered_data_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256);
        verify_rsa_tampered_data_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384);
        verify_rsa_tampered_data_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512);
    }

    SECTION("RSA sign/verifyctx tampered signature")
    {
        verify_rsa_tampered_signature(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256);
        verify_rsa_tampered_signature(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384);
        verify_rsa_tampered_signature(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512);

        verify_rsa_tampered_signature(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256);
        verify_rsa_tampered_signature(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384);
        verify_rsa_tampered_signature(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512);

        verify_rsa_tampered_signature(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256);
        verify_rsa_tampered_signature(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384);
        verify_rsa_tampered_signature(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512);
    }

    SECTION("RSA sign/verifyctx tampered signature with copied key")
    {
        verify_rsa_tampered_signature_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA256);
        verify_rsa_tampered_signature_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA384);
        verify_rsa_tampered_signature_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AziHsmShaHashType::SHA512);

        verify_rsa_tampered_signature_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA256);
        verify_rsa_tampered_signature_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA384);
        verify_rsa_tampered_signature_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AziHsmShaHashType::SHA512);

        verify_rsa_tampered_signature_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA256);
        verify_rsa_tampered_signature_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA384);
        verify_rsa_tampered_signature_copy(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AziHsmShaHashType::SHA512);
    }
}
