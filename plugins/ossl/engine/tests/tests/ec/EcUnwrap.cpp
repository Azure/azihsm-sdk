// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestEc.hpp"
#include "AziHsmTestKeyConsts.hpp"

static void validate_ec_unwrap(AziHsmEngine &azihsm_engine, int curve_name, bool ecdh, AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1)
{
    EC_KEY *ec_key = unwrap_test_ec_key(azihsm_engine, curve_name, ecdh, digest_kind);
    REQUIRE(ec_key != nullptr);
    EC_KEY_free(ec_key);
}

TEST_CASE("AZIHSM EC Unwrap", "[AziHsmEcUnwrap]")
{
    AziHsmEngine azihsm_engine = get_test_engine();

    SECTION("Test EC key Unwrap with AZIHSM_DIGEST_SHA1")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1;

        // Derive
        validate_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, true, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp384r1, true, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp521r1, true, digest_kind);

        // Sign/verify
        validate_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, false, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp384r1, false, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp521r1, false, digest_kind);
    }

    SECTION("Test EC key Unwrap with AZIHSM_DIGEST_SHA256")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA256;

        // Derive
        validate_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, true, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp384r1, true, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp521r1, true, digest_kind);

        // Sign/verify
        validate_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, false, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp384r1, false, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp521r1, false, digest_kind);
    }

    SECTION("Test EC key Unwrap with AZIHSM_DIGEST_SHA384")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA384;

        // Derive
        validate_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, true, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp384r1, true, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp521r1, true, digest_kind);

        // Sign/verify
        validate_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, false, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp384r1, false, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp521r1, false, digest_kind);
    }

    SECTION("Test EC key Unwrap with AZIHSM_DIGEST_SHA512")
    {
        AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA512;

        // Derive
        validate_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, true, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp384r1, true, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp521r1, true, digest_kind);

        // Sign/verify
        validate_ec_unwrap(azihsm_engine, NID_X9_62_prime256v1, false, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp384r1, false, digest_kind);
        validate_ec_unwrap(azihsm_engine, NID_secp521r1, false, digest_kind);
    }
}
