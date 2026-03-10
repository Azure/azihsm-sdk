// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestPKey.hpp"
#include "AziHsmDigestSignVerify.hpp"
#include "AziHsmPKeyEc.hpp"
#include "AziHsmHash.hpp"
#include "AziHsmPKeys.hpp"

static AziHsmPKey generate_ec_key(AziHsmEngine &azihsm_engine, int curve_name)
{
    AziHsmPKeyEcCtx azihsm_ec_keygen(azihsm_engine.getEngine(), curve_name);
    EVP_PKEY *pkey = azihsm_ec_keygen.keygen();
    REQUIRE(pkey != nullptr);

    AziHsmPKey pkey_ec(pkey);
    return pkey_ec;
}

static AziHsmPKey unwrap_test_ec_key(AziHsmEngine &azihsm_engine, int curve_name)
{
    AziHsmPKeyEcCtx ec_test_key = unwrap_test_ec_pkey_ctx_key(azihsm_engine, curve_name, false);
    EVP_PKEY *pkey = ec_test_key.getPKey();
    REQUIRE(pkey != nullptr);

    // We are keeping this pkey longer than the context will live
    EVP_PKEY_up_ref(pkey);

    AziHsmPKey pkey_ec(pkey);
    return pkey_ec;
}

static AziHsmPKey get_ec_key(KeyType key_type, AziHsmEngine &azihsm_engine, int curve_name)
{
    return (key_type == KeyType::KEYGEN) ? generate_ec_key(azihsm_engine, curve_name) : unwrap_test_ec_key(azihsm_engine, curve_name);
}

static void verify_ecdsa(
    KeyType key_type,
    AziHsmEngine &azihsm_engine,
    int curve_name,
    AziHsmShaHashType hash_type,
    bool expect_sign_fail = false)
{
    std::string test_text = "Please ensure no body tampers this message";
    std::vector<unsigned char> message(test_text.begin(), test_text.end());

    AziHsmPKey key = get_ec_key(key_type, azihsm_engine, curve_name);
    AziHsmDigestSignVerify sign_verify(azihsm_engine.getEngine(), key.getPKey(), hash_type);

    std::vector<unsigned char> sig;

    REQUIRE(sign_verify.sign(sig, message) == (expect_sign_fail ? 0 : 1));
    if (!expect_sign_fail)
    {
        REQUIRE(sign_verify.verify(sig, message) == 1);
    }
}

static void verify_ecdsa_tampered_data(KeyType key_type, AziHsmEngine &azihsm_engine, int curve_name, AziHsmShaHashType hash_type)
{
    std::string test_text = "Please ensure no body tampers this message";
    std::vector<unsigned char> message(test_text.begin(), test_text.end());

    AziHsmPKey key = get_ec_key(key_type, azihsm_engine, curve_name);
    AziHsmDigestSignVerify sign_verify(azihsm_engine.getEngine(), key.getPKey(), hash_type);

    std::vector<unsigned char> sig;

    REQUIRE(sign_verify.sign(sig, message) == 1);

    // Tamper with the message
    message[0] ^= 0x01;

    REQUIRE(sign_verify.verify(sig, message) == 0);
}

static void verify_ecdsa_tampered_signature(KeyType key_type, AziHsmEngine &azihsm_engine, int curve_name, AziHsmShaHashType hash_type)
{
    std::string test_text = "Please ensure no body tampers this message";
    std::vector<unsigned char> message(test_text.begin(), test_text.end());

    AziHsmPKey key = get_ec_key(key_type, azihsm_engine, curve_name);
    AziHsmDigestSignVerify sign_verify(azihsm_engine.getEngine(), key.getPKey(), hash_type);

    std::vector<unsigned char> sig;

    REQUIRE(sign_verify.sign(sig, message) == 1);

    // Tamper with the signature
    sig[0] ^= 0x01;

    REQUIRE(sign_verify.verify(sig, message) == 0);
}

TEST_CASE("AZIHSM PKEY ECDSA signctx/verifyctx", "[AziHsmPkeyEcdsaCtx]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("ECDSA sign/verifyctx")
    {
        verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1);
        verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1);
        verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256);
        verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256);

        verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA1);
        verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA1);
        verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA256);
        verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA256);
        verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA384);
        verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA384);

        verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA1);
        verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA1);
        verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA256);
        verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA256);
        verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA384);
        verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA384);
        verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA512);
        verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA512);
    }

    SECTION("ECDSA sign/verifyctx invalid hashes")
    {
        verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA384, true);
        verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA384, true);
        verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA512, true);
        verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA512, true);

        verify_ecdsa(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA512, true);
        verify_ecdsa(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA512, true);
    }

    SECTION("ECDSA sign/verifyctx tampered data")
    {
        verify_ecdsa_tampered_data(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1);
        verify_ecdsa_tampered_data(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1);
        verify_ecdsa_tampered_data(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256);
        verify_ecdsa_tampered_data(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256);

        verify_ecdsa_tampered_data(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA1);
        verify_ecdsa_tampered_data(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA1);
        verify_ecdsa_tampered_data(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA256);
        verify_ecdsa_tampered_data(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA256);
        verify_ecdsa_tampered_data(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA384);
        verify_ecdsa_tampered_data(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA384);

        verify_ecdsa_tampered_data(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA1);
        verify_ecdsa_tampered_data(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA1);
        verify_ecdsa_tampered_data(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA256);
        verify_ecdsa_tampered_data(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA256);
        verify_ecdsa_tampered_data(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA384);
        verify_ecdsa_tampered_data(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA384);
        verify_ecdsa_tampered_data(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA512);
        verify_ecdsa_tampered_data(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA512);
    }

    SECTION("ECDSA sign/verifyctx tampered signature")
    {
        verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1);
        verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA1);
        verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256);
        verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_X9_62_prime256v1, AziHsmShaHashType::SHA256);

        verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA1);
        verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA1);
        verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA256);
        verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA256);
        verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA384);
        verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp384r1, AziHsmShaHashType::SHA384);

        verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA1);
        verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA1);
        verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA256);
        verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA256);
        verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA384);
        verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA384);
        verify_ecdsa_tampered_signature(KeyType::KEYGEN, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA512);
        verify_ecdsa_tampered_signature(KeyType::UNWRAP, azihsm_engine, NID_secp521r1, AziHsmShaHashType::SHA512);
    }
}
