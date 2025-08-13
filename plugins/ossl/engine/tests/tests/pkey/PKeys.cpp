// Copyright (c) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestPKey.hpp"
#include <catch2/catch_test_macros.hpp>

TEST_CASE("AZIHSM PKEYs", "[AziHsmPKeys]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    AziHsmPKeyMethod pkey_method(e);

    EVP_PKEY_METHOD *pkey_method_ptr;

    SECTION("Query Supported NIDs of PKeys")
    {
        const int *nids;
        ENGINE_PKEY_METHS_PTR pkeys_fn = ENGINE_get_pkey_meths(e);
        REQUIRE(pkeys_fn != nullptr);

        REQUIRE(pkeys_fn(e, nullptr, nullptr, 0) == -1);
        REQUIRE(pkeys_fn(e, nullptr, &nids, 0) == 3);
        REQUIRE(nids[0] == NID_rsaEncryption);
        REQUIRE(nids[1] == NID_hkdf);
        REQUIRE(nids[2] == NID_X9_62_id_ecPublicKey);
        REQUIRE(pkeys_fn(e, &pkey_method_ptr, nullptr, 0) == -1);
        REQUIRE(pkeys_fn(e, &pkey_method_ptr, nullptr, -1) == 0);
    }
}
