// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <gtest/gtest.h>
#include <vector>

#include "algo/aes/helpers.hpp"
#include "utils/auto_key.hpp"
#include "utils/key_props.hpp"
#include "utils/shared_secret.hpp"

const char *get_hmac_algo_name(azihsm_algo_id hmac_algo_id);

static const std::vector<azihsm_algo_id> &supported_hkdf_hash_algos()
{
    static const std::vector<azihsm_algo_id> algos = {
        AZIHSM_ALGO_ID_HMAC_SHA1,
        AZIHSM_ALGO_ID_HMAC_SHA256,
        AZIHSM_ALGO_ID_HMAC_SHA384,
        AZIHSM_ALGO_ID_HMAC_SHA512,
    };
    return algos;
}

// Builds an azihsm_algo for HKDF with the given HMAC algo ID and optional salt/info.
void build_hkdf_algo(
    azihsm_algo_hkdf_params &hkdf_params,
    azihsm_algo &hkdf_algo,
    azihsm_algo_id hmac_algo_id,
    azihsm_buffer *salt,
    azihsm_buffer *info
);

void derive_ecdh_shared_secrets(
    azihsm_handle session,
    azihsm_ecc_curve curve,
    auto_key &shared_secret_a,
    auto_key &shared_secret_b
);

void derive_aes_key_from_shared_secret(
    azihsm_handle session,
    azihsm_algo *hkdf_algo,
    azihsm_handle shared_secret,
    uint32_t bits,
    auto_key &out_key
);

void assert_aes_cbc_roundtrip(
    azihsm_handle enc_key,
    azihsm_handle dec_key,
    const uint8_t *plaintext,
    size_t plaintext_len
);

void run_hkdf_matrix_for_curve(azihsm_handle session, azihsm_ecc_curve curve);

void hkdf_derive_fails_common(
    azihsm_handle session,
    azihsm_algo_id hmac_algo_id,
    key_props &props,
    azihsm_status expected_status
);
