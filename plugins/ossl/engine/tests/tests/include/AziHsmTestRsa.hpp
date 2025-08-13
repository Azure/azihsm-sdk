// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_TEST_RSA_HPP
#define AZIHSM_TEST_RSA_HPP

#include "AziHsmEngine.hpp"
#include "AziHsmTestKeyConsts.hpp"
#include "AziHsmRsa.hpp"
#include <openssl/rsa.h>
#include <vector>

enum class AziHsmRsaDefaultKey
{
    RSA2048,
    RSA3072,
    RSA4096,
};

std::vector<unsigned char> get_default_rsa_key(AziHsmRsaDefaultKey key);
std::vector<unsigned char> wrap_test_rsa_key(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1,
    const char *name = nullptr,
    AziHsmKeyAvailability availability = AZIHSM_AVAILABILITY_SESSION);
AziHsmRsa unwrap_test_rsa_key(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey key,
    AziHsmKeyUsage key_usage,
    AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1,
    const char *name = nullptr,
    AziHsmKeyAvailability availability = AZIHSM_AVAILABILITY_SESSION);

#endif // AZIHSM_TEST_RSA_HPP
