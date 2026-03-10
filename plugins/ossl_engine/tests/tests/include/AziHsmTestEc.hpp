// Copyright (c) Microsoft Corporation. All rights reserved.

#ifndef AZIHSM_TEST_EC_HPP
#define AZIHSM_TEST_EC_HPP

#include "AziHsmEngine.hpp"
#include "AziHsmEc.hpp"
#include "../../../api-interface/azihsm_engine.h"
#include <openssl/ec.h>
#include <vector>

// Common helper functions
std::vector<unsigned char> get_test_ec_key(int key_num, int curve_name);
std::vector<unsigned char> wrap_test_ec_key(
    AziHsmEngine &azihsm_engine,
    int test_key_num,
    int curve_name,
    AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1);
EC_KEY *unwrap_test_ec_key(
    AziHsmEngine &azihsm_engine,
    int curve_name,
    bool ecdh,
    AziHsmDigestKind digest_kind = AZIHSM_DIGEST_SHA1,
    const char *name = nullptr,
    AziHsmKeyAvailability availability = AZIHSM_AVAILABILITY_SESSION,
    int test_key_num = 0);

int curve_raw_signature_size(int curve_name);
int curve_dgst_len(int curve_name);
int next_allowed_curve(int curve_name);
int compute_digest(int nid, std::vector<unsigned char> message, std::vector<unsigned char> &digest);

void ec_verify_with_ossl(int curve_name, const EC_POINT *public_point, const std::vector<unsigned char> &signature, const std::vector<unsigned char> &digest);

#endif // AZIHSM_TEST_EC_HPP
