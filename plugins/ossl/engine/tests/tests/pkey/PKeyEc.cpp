// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestPKey.hpp"
#include "AziHsmTestEc.hpp"
#include "AziHsmPKeyEc.hpp"
#include <memory>
#include <stdexcept>

// Helper functions

AziHsmPKeyEcCtx unwrap_test_ec_pkey_ctx_key(
    AziHsmEngine &azihsm_engine,
    int curve_name,
    bool ecdh,
    AziHsmDigestKind digest_kind,
    const char *name,
    AziHsmKeyAvailability availability,
    int test_key_num)
{
    AziHsmPKeyEcCtx pkey_ctx(azihsm_engine.getEngine(), curve_name);
    EVP_PKEY *params_ptr = pkey_ctx.paramgen();
    if (params_ptr == nullptr)
    {
        throw std::runtime_error("Could not generate EC key params");
    }
    AziHsmPKey params(params_ptr);

    AziHsmPKeyEcCtx ec_unwrap_ctx(azihsm_engine.getEngine(), params.getPKey(), true);

    std::vector<unsigned char> wrapped_blob =
        wrap_test_ec_key(azihsm_engine, test_key_num, curve_name, digest_kind);
    if (wrapped_blob.size() <= 0)
    {
        throw std::runtime_error("Wrapped blob size <= 0");
    }

    AziHsmKeyUsage key_usage = get_azihsm_key_usage(ecdh);

    if (azihsm_engine.unwrapPKeyEc(
            ec_unwrap_ctx.getCtx(),
            curve_name,
            key_usage,
            wrapped_blob,
            digest_kind,
            name,
            availability) != 1)
    {
        throw std::runtime_error("Could not unwrap EC key");
    }

    EVP_PKEY *pkey = ec_unwrap_ctx.getPKey();
    if (pkey == nullptr)
    {
        throw std::runtime_error("EC unwrap ctx pkey is null");
    }

    pkey_ctx.validateEcPKey(pkey);
    ec_unwrap_ctx.setCurveName(curve_name);

    return ec_unwrap_ctx;
}

static int validate_keygen(ENGINE *e, int curve_name, bool from_param, bool ecdh)
{
    AziHsmPKeyEcCtx azihsm_ec_key_ctx(e, curve_name);
    EVP_PKEY *azihsm_ec_key = azihsm_ec_key_ctx.keygen(from_param, ecdh);
    if (azihsm_ec_key == nullptr)
    {
        return 0;
    }

    EVP_PKEY_free(azihsm_ec_key);

    return 1;
}

TEST_CASE("AZIHSM PKEY EC keygen", "[AziHsmPkeyEcKeygen]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("Keygen for ECDSA ")
    {
        // Without parameters
        REQUIRE(validate_keygen(e, NID_X9_62_prime256v1, false, false) == 1);
        REQUIRE(validate_keygen(e, NID_secp384r1, false, false) == 1);
        REQUIRE(validate_keygen(e, NID_secp521r1, false, false) == 1);

        // With parameters
        REQUIRE(validate_keygen(e, NID_X9_62_prime256v1, true, false) == 1);
        REQUIRE(validate_keygen(e, NID_secp384r1, true, false) == 1);
        REQUIRE(validate_keygen(e, NID_secp521r1, true, false) == 1);
    }

    SECTION("Keygen for ECDH")
    {
        // Without parameters
        REQUIRE(validate_keygen(e, NID_X9_62_prime256v1, false, true) == 1);
        REQUIRE(validate_keygen(e, NID_secp384r1, false, true) == 1);
        REQUIRE(validate_keygen(e, NID_secp521r1, false, true) == 1);

        // // With parameters
        REQUIRE(validate_keygen(e, NID_X9_62_prime256v1, true, true) == 1);
        REQUIRE(validate_keygen(e, NID_secp384r1, true, true) == 1);
        REQUIRE(validate_keygen(e, NID_secp521r1, true, true) == 1);
    }

    SECTION("KEYGEN Unsupported curve")
    {
        REQUIRE_THROWS(AziHsmPKeyEcCtx(e, NID_secp112r1));
    }
}
