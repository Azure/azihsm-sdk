// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include "AziHsmPKeys.hpp"
#include "../../../api-interface/azihsm_engine.h"
#include <catch2/catch_test_macros.hpp>

static void validate_evp_pkey_rsa_unwrap(
    AziHsmEngine &azihsm_engine,
    AziHsmKeyUsage key_usage,
    const std::vector<unsigned char> &target_key,
    AziHsmDigestKind digest_kind)
{
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
    REQUIRE(unwrapping_key.size() > 0);

    std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, target_key, digest_kind);
    REQUIRE(wrapped_blob.size() > 0);

    AziHsmPKey pkey(EVP_PKEY_RSA);
    EVP_PKEY *key = pkey.getPKey();
    REQUIRE(key != nullptr);
    AziHsmPKeyCtx priv_key_ctx(key, e);

    EVP_PKEY_CTX *ctx = priv_key_ctx.getCtx();
    REQUIRE(ctx != nullptr);

    REQUIRE(azihsm_engine.unwrapPKeyRsa(ctx, key_usage, wrapped_blob, digest_kind) == 1);
}

TEST_CASE("AZIHSM PKEY RSA Unwrap", "[AziHsmPkeyRsaUnWrap]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("Test EVP PKey RSA key Unwrap with AZIHSM_DIGEST_SHA1")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1;

        // Sign/verify
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_2048, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_3072, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_4096, digest_kind);

        // Encrypt/Decrypt
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_2048, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_3072, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_4096, digest_kind);
    }

    SECTION("Test EVP PKey RSA key Unwrap with AZIHSM_DIGEST_SHA256")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA256;

        // Sign/verify
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_2048, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_3072, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_4096, digest_kind);

        // Encrypt/Decrypt
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_2048, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_3072, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_4096, digest_kind);
    }

    SECTION("Test EVP PKey RSA key Unwrap with AZIHSM_DIGEST_SHA384")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA384;

        // Sign/verify
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_2048, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_3072, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_4096, digest_kind);

        // Encrypt/Decrypt
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_2048, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_3072, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_4096, digest_kind);
    }

    SECTION("Test EVP PKey RSA key Unwrap with AZIHSM_DIGEST_SHA512")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA512;

        // Sign/verify
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_2048, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_3072, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_4096, digest_kind);

        // Encrypt/Decrypt
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_2048, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_3072, digest_kind);
        validate_evp_pkey_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_4096, digest_kind);
    }
}
