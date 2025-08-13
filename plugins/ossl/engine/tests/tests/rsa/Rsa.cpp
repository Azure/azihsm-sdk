// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestRsa.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include <catch2/catch_test_macros.hpp>
#include <stdexcept>
#include <vector>
#include <memory>

TEST_CASE("AZIHSM RSA", "[AziHsmRSA]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    AziHsmRsaMethod azihsm_rsa_method(e);

    SECTION("Verify methods are in use")
    {
        const RSA_METHOD *default_meth = RSA_get_default_method();
        const RSA_METHOD *current_meth = ENGINE_get_RSA(e);
        REQUIRE(default_meth != current_meth);
    }
}

static void test_keygen_fail(ENGINE *e, int length)
{
    auto bn_deleter = [](BIGNUM *b)
    { BN_free(b); };
    auto rsa_deleter = [](RSA *r)
    { RSA_free(r); };

    std::unique_ptr<BIGNUM, decltype(bn_deleter)> bne(BN_new(), bn_deleter);
    REQUIRE(BN_set_word(bne.get(), RSA_F4) == 1);

    std::unique_ptr<RSA, decltype(rsa_deleter)> key(RSA_new_method(e), rsa_deleter);
    REQUIRE(RSA_generate_key_ex(key.get(), length, bne.get(), nullptr) < 1);
}

TEST_CASE("AZIHSM RSA keygen", "[AziHsmRsaKeygen]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("Test RSA keygen 2048 bits")
    {
        test_keygen_fail(e, 2048);
    }

    SECTION("Test RSA keygen 3072 bits")
    {
        test_keygen_fail(e, 3072);
    }

    SECTION("Test RSA keygen 4096 bits")
    {
        test_keygen_fail(e, 4096);
    }
}
