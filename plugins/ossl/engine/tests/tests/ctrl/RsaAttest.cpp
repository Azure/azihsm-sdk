// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include "AziHsmTestRsa.hpp"
#include "../../../api-interface/azihsm_engine.h"
#include <catch2/catch_test_macros.hpp>

static int validate_attest_rsa(AziHsmEngine &azihsm_engine, AziHsmRsaDefaultKey key_type, AziHsmKeyUsage key_usage)
{
    ENGINE *e = azihsm_engine.getEngine();
    std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
    REQUIRE(unwrapping_key.size() > 0);

    std::vector<unsigned char> wrapped_key_blob = azihsm_engine.wrapTargetKey(unwrapping_key, get_default_rsa_key(key_type));
    REQUIRE(wrapped_key_blob.size() > 0);

    AziHsmRsa rsa(e);
    RSA *rsaKey = rsa.getKey();
    REQUIRE(rsaKey != nullptr);

    REQUIRE(azihsm_engine.unwrapRsa(rsaKey, key_usage, wrapped_key_blob) == 1);

    std::vector<unsigned char> report_data(REPORT_DATA_SIZE);
    RAND_bytes(report_data.data(), report_data.size());
    std::vector<unsigned char> claim;

    REQUIRE(azihsm_engine.attestRsa(rsaKey, report_data, claim) == 1);
    return 1;
}

TEST_CASE("AZIHSM RSA Key Attest", "[AziHsmRsaKeyAttest]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    SECTION("Unwrapped RSA attest")
    {
        REQUIRE(validate_attest_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT) == 1);
        REQUIRE(validate_attest_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AZIHSM_KEY_USAGE_SIGN_VERIFY) == 1);
        REQUIRE(validate_attest_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT) == 1);
        REQUIRE(validate_attest_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AZIHSM_KEY_USAGE_SIGN_VERIFY) == 1);
        REQUIRE(validate_attest_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT) == 1);
        REQUIRE(validate_attest_rsa(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AZIHSM_KEY_USAGE_SIGN_VERIFY) == 1);
    }
}
