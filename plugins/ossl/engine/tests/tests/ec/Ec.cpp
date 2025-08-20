// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmEc.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include <openssl/ec.h>
#include <catch2/catch_test_macros.hpp>
#include <vector>

TEST_CASE("AZIHSM EC Keygen", "[AziHsmEcKeygen]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    AziHsmEcKeyMethod azihsm_ec_key_method(e);

    SECTION("Verify methods are in use")
    {
        const EC_KEY_METHOD *default_meth = EC_KEY_get_default_method();
        const EC_KEY_METHOD *current_meth = ENGINE_get_EC(e);
        REQUIRE(default_meth != current_meth);
    }

    SECTION("Prime256v1 key generation for sign/verify")
    {
        AziHsmEcKey key(e);
        REQUIRE(key.keygen(NID_X9_62_prime256v1, false) == 1);
    }

    SECTION("Prime256v1 key generation for ecdh")
    {
        AziHsmEcKey key(e);
        REQUIRE(key.keygen(NID_X9_62_prime256v1, true) == 1);
    }

    SECTION("Secp384r1 key generation for sign/verify")
    {
        AziHsmEcKey key(e);
        REQUIRE(key.keygen(NID_secp384r1, false) == 1);
    }

    SECTION("Secp384r1 key generation for ecdh")
    {
        AziHsmEcKey key(e);
        REQUIRE(key.keygen(NID_secp384r1, true) == 1);
    }

    SECTION("Secp521r1 key generation for sign/verify")
    {
        AziHsmEcKey key(e);
        REQUIRE(key.keygen(NID_secp521r1, false) == 1);
    }

    SECTION("Secp521r1 key generation for ecdh")
    {
        AziHsmEcKey key(e);
        REQUIRE(key.keygen(NID_secp521r1, false) == 1);
    }

    SECTION("Unknown key type generation for sign/verify")
    {
        AziHsmEcKey key(e);
        REQUIRE(key.keygen(NID_secp112r1, false) == 0);
    }

    SECTION("Unknown key type generation for ecdh")
    {
        AziHsmEcKey key(e);
        REQUIRE(key.keygen(NID_secp112r1, false) == 0);
    }
}
