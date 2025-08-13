// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include "AziHsmRsa.hpp"
#include "../../../api-interface/azihsm_engine.h"
#include <catch2/catch_test_macros.hpp>

static void validate_rsa_unwrap(AziHsmEngine &azihsm_engine, AziHsmKeyUsage key_usage, const std::vector<unsigned char> &target_key, AziHsmDigestKind digest_kind)
{
    std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
    REQUIRE(unwrapping_key.size() > 0);

    std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, target_key, digest_kind);
    REQUIRE(wrapped_blob.size() > 0);

    AziHsmRsa rsa(azihsm_engine.getEngine());
    RSA *rsaKey = rsa.getKey();
    REQUIRE(rsaKey != nullptr);

    REQUIRE(azihsm_engine.unwrapRsa(rsaKey, key_usage, wrapped_blob, digest_kind) == 1);
}

TEST_CASE("AZIHSM RSA Unwrap", "[AziHsmRsaUnWrap]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("Test RSA key Unwrap with AZIHSM_DIGEST_SHA1")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1;

        // Sign/verify
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_2048, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_3072, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_4096, digest_kind);

        // Encrypt/Decrypt
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_2048, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_3072, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_4096, digest_kind);
    }

    SECTION("Test RSA key Unwrap with AZIHSM_DIGEST_SHA256")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA256;

        // Sign/verify
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_2048, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_3072, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_4096, digest_kind);

        // Encrypt/Decrypt
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_2048, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_3072, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_4096, digest_kind);
    }

    SECTION("Test RSA key Unwrap with AZIHSM_DIGEST_SHA384")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA384;

        // Sign/verify
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_2048, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_3072, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_4096, digest_kind);

        // Encrypt/Decrypt
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_2048, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_3072, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_4096, digest_kind);
    }

    SECTION("Test RSA key Unwrap with AZIHSM_DIGEST_SHA512")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA512;

        // Sign/verify
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_2048, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_3072, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_SIGN_VERIFY, RSA_PRIV_KEY_4096, digest_kind);

        // Encrypt/Decrypt
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_2048, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_3072, digest_kind);
        validate_rsa_unwrap(azihsm_engine, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT, RSA_PRIV_KEY_4096, digest_kind);
    }
}
