// Copyright (C) Microsoft Corporation. All rights reserved.

#include "AziHsmTestRsa.hpp"
#include <catch2/catch_test_macros.hpp>
#include <vector>

std::vector<unsigned char> get_default_rsa_key(AziHsmRsaDefaultKey key)
{
    switch (key)
    {
    case AziHsmRsaDefaultKey::RSA2048:
        return RSA_PRIV_KEY_2048;
    case AziHsmRsaDefaultKey::RSA3072:
        return RSA_PRIV_KEY_3072;
    case AziHsmRsaDefaultKey::RSA4096:
        return RSA_PRIV_KEY_4096;
    }

    return std::vector<unsigned char>();
}

std::vector<unsigned char> wrap_test_rsa_key(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmDigestKind digest_kind,
    const char *name,
    AziHsmKeyAvailability availability)
{
    std::vector<unsigned char> target_key = get_default_rsa_key(key);
    REQUIRE(target_key.size() > 0);

    std::vector<unsigned char> unwrapping_key = azihsm_engine.getBuiltinUnwrappingKey();
    REQUIRE(unwrapping_key.size() > 0);

    std::vector<unsigned char> wrapped_blob = azihsm_engine.wrapTargetKey(unwrapping_key, target_key, digest_kind);
    REQUIRE(wrapped_blob.size() > 0);

    return wrapped_blob;
}

AziHsmRsa unwrap_test_rsa_key(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmKeyUsage key_usage,
    AziHsmDigestKind digest_kind,
    const char *name,
    AziHsmKeyAvailability availability)
{
    AziHsmRsa rsa(azihsm_engine.getEngine());
    REQUIRE(rsa.getKey() != nullptr);

    if (azihsm_engine.unwrapRsa(
            rsa.getKey(),
            key_usage,
            wrap_test_rsa_key(azihsm_engine, key, digest_kind),
            digest_kind,
            name,
            availability) != 1)
    {
        throw std::runtime_error("Could not unwrap RSA key");
    }

    return rsa;
}