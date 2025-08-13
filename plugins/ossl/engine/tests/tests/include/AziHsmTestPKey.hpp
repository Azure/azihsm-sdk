// Copyright (C) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_TEST_PKEY_HPP
#define AZIHSM_TEST_PKEY_HPP

#include "AziHsmTestRsa.hpp"
#include "AziHsmPKeyRsa.hpp"
#include "AziHsmPKeyEc.hpp"

AziHsmPKeyRsaCtx unwrap_test_rsa_pkey_ctx_key(
    AziHsmEngine &azihsm_engine,
    AziHsmRsaDefaultKey target_key,
    AziHsmKeyUsage key_usage,
    AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1,
    const char *name = nullptr,
    AziHsmKeyAvailability availability = AZIHSM_AVAILABILITY_SESSION);
AziHsmPKeyEcCtx unwrap_test_ec_pkey_ctx_key(
    AziHsmEngine &azihsm_engine,
    int curve_name,
    bool ecdh,
    AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1,
    const char *name = nullptr,
    AziHsmKeyAvailability availability = AZIHSM_AVAILABILITY_SESSION,
    int test_key_num = 0);

#endif // AZIHSM_TEST_PKEY_HPP