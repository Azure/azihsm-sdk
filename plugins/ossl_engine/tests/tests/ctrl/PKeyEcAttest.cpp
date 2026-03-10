// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestEc.hpp"
#include "AziHsmTestPKey.hpp"
#include "AziHsmPKeyEc.hpp"
#include <catch2/catch_test_macros.hpp>

static int validate_ec_pkey_attest_unwrap(AziHsmEngine &azihsm_engine, int curve_name, bool ecdh)
{
    AziHsmPKeyEcCtx ec_unwrap_ctx = unwrap_test_ec_pkey_ctx_key(azihsm_engine, curve_name, ecdh);

    std::vector<unsigned char> report_data(REPORT_DATA_SIZE);
    RAND_bytes(report_data.data(), report_data.size());
    std::vector<unsigned char> claim;

    REQUIRE(azihsm_engine.attestEcPKey(ec_unwrap_ctx.getPKey(), report_data, claim) == 1);
    return 1;
}

static int validate_keygen_pkey_ec_attest(AziHsmEngine &azihsm_engine, int curve_name, bool ecdh)
{
    std::vector<unsigned char> report_data(REPORT_DATA_SIZE);
    RAND_bytes(report_data.data(), report_data.size());
    std::vector<unsigned char> claim;

    AziHsmPKeyEcCtx ec_keygen_ctx(azihsm_engine.getEngine(), curve_name);
    EVP_PKEY *ec_key = ec_keygen_ctx.keygen(true, ecdh);
    REQUIRE(ec_key != nullptr);

    AziHsmPKey pkey_ec(ec_key);

    REQUIRE(azihsm_engine.attestEcPKey(pkey_ec.getPKey(), report_data, claim) == 1);
    return 1;
}

TEST_CASE("AZIHSM PKEY EC Key Attest", "[AziHsmPkeyEcKeyAttest]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    AziHsmPKeyMethod azihsm_pkey_key_method(e);

    SECTION("Unwrapped EC EVP_PKEY attest")
    {
        REQUIRE(validate_ec_pkey_attest_unwrap(azihsm_engine, NID_X9_62_prime256v1, false) == 1);
        REQUIRE(validate_ec_pkey_attest_unwrap(azihsm_engine, NID_X9_62_prime256v1, true) == 1);
        REQUIRE(validate_ec_pkey_attest_unwrap(azihsm_engine, NID_secp384r1, false) == 1);
        REQUIRE(validate_ec_pkey_attest_unwrap(azihsm_engine, NID_secp384r1, true) == 1);
        REQUIRE(validate_ec_pkey_attest_unwrap(azihsm_engine, NID_secp521r1, false) == 1);
        REQUIRE(validate_ec_pkey_attest_unwrap(azihsm_engine, NID_secp521r1, true) == 1);
    }

    SECTION("Keygen EC EVP_PKEY attest")
    {
        REQUIRE(validate_keygen_pkey_ec_attest(azihsm_engine, NID_X9_62_prime256v1, false) == 1);
        REQUIRE(validate_keygen_pkey_ec_attest(azihsm_engine, NID_X9_62_prime256v1, true) == 1);
        REQUIRE(validate_keygen_pkey_ec_attest(azihsm_engine, NID_secp384r1, false) == 1);
        REQUIRE(validate_keygen_pkey_ec_attest(azihsm_engine, NID_secp384r1, true) == 1);
        REQUIRE(validate_keygen_pkey_ec_attest(azihsm_engine, NID_secp521r1, false) == 1);
        REQUIRE(validate_keygen_pkey_ec_attest(azihsm_engine, NID_secp521r1, true) == 1);
    }
}