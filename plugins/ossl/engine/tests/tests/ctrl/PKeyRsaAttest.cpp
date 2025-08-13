// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestEngine.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include "AziHsmPKeys.hpp"
#include "AziHsmTestRsa.hpp"
#include "../../../api-interface/azihsm_engine.h"

static int validate_attest_rsa_pkey(AziHsmEngine &azihsm_engine, AziHsmRsaDefaultKey key_type, AziHsmKeyUsage key_usage)
{
    ENGINE *e = azihsm_engine.getEngine();
    std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
    REQUIRE(unwrapping_key.size() > 0);

    std::vector<unsigned char> wrapped_key_blob = azihsm_engine.wrapTargetKey(unwrapping_key, get_default_rsa_key(key_type));
    REQUIRE(wrapped_key_blob.size() > 0);

    AziHsmPKey pkey(EVP_PKEY_RSA);
    AziHsmPKeyCtx rsa_key_ctx(pkey.getPKey(), e);
    REQUIRE(azihsm_engine.unwrapPKeyRsa(rsa_key_ctx.getCtx(), key_usage, wrapped_key_blob) == 1);

    std::vector<unsigned char> report_data(REPORT_DATA_SIZE);
    RAND_bytes(report_data.data(), report_data.size());
    std::vector<unsigned char> claim;

    REQUIRE(azihsm_engine.attestRsaPKey(rsa_key_ctx.getPKey(), report_data, claim) == 1);
    return 1;
}

TEST_CASE("AZIHSM PKEY RSA Key Attest", "[AziHsmPkeyRsaKeyAttest]")
{
    AziHsmEngine azihsm_engine = get_test_engine();
    ENGINE *e = azihsm_engine.getEngine();
    REQUIRE(e != nullptr);

    AziHsmPKeyMethod azihsm_pkey_key_method(e);

    SECTION("Unwrapped RSA EVP_PKEY attest")
    {
        REQUIRE(validate_attest_rsa_pkey(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT) == 1);
        REQUIRE(validate_attest_rsa_pkey(azihsm_engine, AziHsmRsaDefaultKey::RSA2048, AZIHSM_KEY_USAGE_SIGN_VERIFY) == 1);
        REQUIRE(validate_attest_rsa_pkey(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT) == 1);
        REQUIRE(validate_attest_rsa_pkey(azihsm_engine, AziHsmRsaDefaultKey::RSA3072, AZIHSM_KEY_USAGE_SIGN_VERIFY) == 1);
        REQUIRE(validate_attest_rsa_pkey(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AZIHSM_KEY_USAGE_ENCRYPT_DECRYPT) == 1);
        REQUIRE(validate_attest_rsa_pkey(azihsm_engine, AziHsmRsaDefaultKey::RSA4096, AZIHSM_KEY_USAGE_SIGN_VERIFY) == 1);
    }
}
