// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include <catch2/catch_test_macros.hpp>
#include <cstring>
#include "../../../api-interface/azihsm_engine.h"

TEST_CASE("AZIHSM Get Builtin Unwrapping Key", "[AziHsmGetBuiltinUnwrapKey]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("Get the builtin unwrapping key")
    {
        AziHsmUnwrappingKey key;
        std::memset(&key, 0, sizeof(AziHsmUnwrappingKey));
        REQUIRE(azihsm_get_builtin_unwrap_key(e, &key) == 1);
        REQUIRE(key.key_len > 0);
        key.key = (unsigned char *)calloc(key.key_len, 1);
        REQUIRE(key.key != nullptr);
        REQUIRE(azihsm_get_builtin_unwrap_key(e, &key) == 1);
    }

    SECTION("Verify initial unwrapping key is the same as builtin")
    {
        AziHsmUnwrappingKey current_key;
        std::memset(&current_key, 0, sizeof(AziHsmUnwrappingKey));
        REQUIRE(azihsm_get_unwrap_key(e, &current_key) == 1);
        REQUIRE(current_key.key_len > 0);
        current_key.key = (unsigned char *)calloc(current_key.key_len, 1);
        REQUIRE(current_key.key != nullptr);
        REQUIRE(azihsm_get_unwrap_key(e, &current_key) == 1);

        AziHsmUnwrappingKey builtin_key;
        std::memset(&builtin_key, 0, sizeof(AziHsmUnwrappingKey));
        REQUIRE(azihsm_get_builtin_unwrap_key(e, &builtin_key) == 1);
        REQUIRE(builtin_key.key_len > 0);
        builtin_key.key = (unsigned char *)calloc(builtin_key.key_len, 1);
        REQUIRE(builtin_key.key != nullptr);
        REQUIRE(azihsm_get_builtin_unwrap_key(e, &builtin_key) == 1);

        REQUIRE(current_key.key_len == builtin_key.key_len);
        REQUIRE(std::memcmp(current_key.key, builtin_key.key, current_key.key_len) == 0);
    }
}
