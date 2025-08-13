// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestEc.hpp"
#include "AziHsmEc.hpp"

static int validate_ec_key_attest(AziHsmEngine &azihsm_engine, AziHsmEcKey &ec_key)
{
    std::vector<unsigned char> report_data(REPORT_DATA_SIZE);
    RAND_bytes(report_data.data(), report_data.size());
    std::vector<unsigned char> claim;

    REQUIRE(azihsm_engine.attestEcKey(ec_key.getKey(), report_data, claim) == 1);
    return 1;
}

static int validate_ec_key_attest_unwrap(AziHsmEngine &azihsm_engine, int curve_name, bool ecdh)
{
    EC_KEY *unwrapped_ec_key = unwrap_test_ec_key(azihsm_engine, curve_name, ecdh);
    REQUIRE(unwrapped_ec_key != nullptr);
    AziHsmEcKey ec_key(unwrapped_ec_key);
    ec_key.validate();
    REQUIRE(validate_ec_key_attest(azihsm_engine, ec_key) == 1);
    return 1;
}

int validate_ec_key_attest_keygen(AziHsmEngine &azihsm_engine, int curve_name, bool ecdh)
{
    AziHsmEcKey ec_key(azihsm_engine.getEngine());
    REQUIRE(ec_key.keygen(curve_name, ecdh) == 1);
    REQUIRE(validate_ec_key_attest(azihsm_engine, ec_key) == 1);
    return 1;
}

TEST_CASE("AZIHSM EC Key Attest", "[AziHsmEcKeyAttest]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    AziHsmEcKeyMethod azihsm_ec_key_method(e);

    SECTION("Unwrapped EC_KEY attest")
    {
        REQUIRE(validate_ec_key_attest_unwrap(azihsm_engine, NID_X9_62_prime256v1, false) == 1);
        REQUIRE(validate_ec_key_attest_unwrap(azihsm_engine, NID_X9_62_prime256v1, true) == 1);
        REQUIRE(validate_ec_key_attest_unwrap(azihsm_engine, NID_secp384r1, false) == 1);
        REQUIRE(validate_ec_key_attest_unwrap(azihsm_engine, NID_secp384r1, true) == 1);
        REQUIRE(validate_ec_key_attest_unwrap(azihsm_engine, NID_secp521r1, false) == 1);
        REQUIRE(validate_ec_key_attest_unwrap(azihsm_engine, NID_secp521r1, true) == 1);
    }

    SECTION("Keygen EC_KEY attest")
    {
        REQUIRE(validate_ec_key_attest_keygen(azihsm_engine, NID_X9_62_prime256v1, false) == 1);
        REQUIRE(validate_ec_key_attest_keygen(azihsm_engine, NID_X9_62_prime256v1, true) == 1);
        REQUIRE(validate_ec_key_attest_keygen(azihsm_engine, NID_secp384r1, false) == 1);
        REQUIRE(validate_ec_key_attest_keygen(azihsm_engine, NID_secp384r1, true) == 1);
        REQUIRE(validate_ec_key_attest_keygen(azihsm_engine, NID_secp521r1, false) == 1);
        REQUIRE(validate_ec_key_attest_keygen(azihsm_engine, NID_secp521r1, true) == 1);
    }
}