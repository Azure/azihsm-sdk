// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestPKey.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include "AziHsmEc.hpp"
#include "AziHsmPKeyEc.hpp"
#include <catch2/catch_test_macros.hpp>
#include "../../../api-interface/azihsm_engine.h"

static void validate_evp_pkey_ec_unwrap(AziHsmEngine &azihsm_engine, int curve_name, bool ecdh, AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1)
{
    AziHsmPKeyEcCtx ec_unwrap_ctx = unwrap_test_ec_pkey_ctx_key(azihsm_engine, curve_name, ecdh, digest_kind);

    EVP_PKEY *pkey = ec_unwrap_ctx.getPKey();
    REQUIRE(pkey != nullptr);
}

TEST_CASE("AZIHSM PKEY EC Unwrap", "[AziHsmPkeyEcUnWrap]")
{
    AziHsmEngine azihsm_engine = get_test_engine();

    SECTION("Test pkey EC key unwrap with AZIHSM_DIGEST_SHA1")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1;

        // Derive
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, true, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp384r1, true, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp521r1, true, digest_kind);

        // Sign/verify
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, false, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp384r1, false, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp521r1, false, digest_kind);
    }

    SECTION("Test pkey EC key unwrap with AZIHSM_DIGEST_SHA256")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA256;

        // Derive
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, true, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp384r1, true, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp521r1, true, digest_kind);

        // Sign/verify
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, false, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp384r1, false, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp521r1, false, digest_kind);
    }

    SECTION("Test pkey EC key unwrap with AZIHSM_DIGEST_SHA384")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA384;

        // Derive
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, true, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp384r1, true, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp521r1, true, digest_kind);

        // Sign/verify
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, false, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp384r1, false, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp521r1, false, digest_kind);
    }

    SECTION("Test pkey EC key unwrap with AZIHSM_DIGEST_SHA512")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA512;

        // Derive
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, true, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp384r1, true, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp521r1, true, digest_kind);

        // Sign/verify
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, false, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp384r1, false, digest_kind);
        validate_evp_pkey_ec_unwrap(azihsm_engine, NID_secp521r1, false, digest_kind);
    }
}
