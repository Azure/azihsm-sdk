// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "handle/key_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "utils/auto_key.hpp"
#include <azihsm_api.h>
#include <functional>
#include <vector>

enum class CryptOperation
{
    Encrypt,
    Decrypt,
};

struct AesKeyTestParams
{
    uint32_t bits;
    const char *test_name;
};

struct DataSizeTestParams
{
    size_t data_size;
    size_t expected_output_size_no_pad;
    size_t expected_output_size_with_pad;
    const char *test_name;
};

struct StreamingRoundtripCase
{
    size_t plaintext_len;
    size_t chunk_size;
    size_t expected_ciphertext_len;
    uint8_t plaintext_fill;
    const char *test_name;
};

azihsm_status crypt_call(
    CryptOperation operation,
    azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_buffer *input,
    azihsm_buffer *output
);

azihsm_status crypt_init_call(
    CryptOperation operation,
    azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_handle *ctx
);

azihsm_status crypt_update_call(
    CryptOperation operation,
    azihsm_handle ctx,
    azihsm_buffer *input,
    azihsm_buffer *output
);

azihsm_status crypt_finish_call(CryptOperation operation, azihsm_handle ctx, azihsm_buffer *output);

azihsm_status single_shot_status_with_sizing(
    CryptOperation operation,
    azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_buffer *input
);

azihsm_status streaming_update_status_with_sizing(
    CryptOperation operation,
    azihsm_handle ctx,
    azihsm_buffer *input
);

azihsm_status streaming_finish_status_with_sizing(CryptOperation operation, azihsm_handle ctx);

azihsm_status single_shot_crypt(
    CryptOperation operation,
    azihsm_handle key_handle,
    azihsm_algo *algo,
    const uint8_t *input_data,
    size_t input_len,
    std::vector<uint8_t> &output
);

azihsm_status streaming_crypt(
    CryptOperation operation,
    azihsm_handle key_handle,
    azihsm_algo *algo,
    const uint8_t *input_data,
    size_t input_len,
    size_t chunk_size,
    std::vector<uint8_t> &output
);

// Builds deterministic incrementing bytes: 0x00, 0x01, 0x02, ...
std::vector<uint8_t> make_incrementing_bytes(size_t len);

const std::vector<AesKeyTestParams> &aes_key_sizes();

const std::vector<size_t> &padding_sweep_plaintext_sizes();

const std::vector<size_t> &padding_sweep_chunk_sizes();

void run_single_shot_key_size(
    PartitionListHandle &part_list,
    azihsm_algo_id algo_id,
    const std::vector<DataSizeTestParams> &data_sizes,
    uint8_t plaintext_fill,
    const std::function<void(azihsm_handle, azihsm_algo_id, const uint8_t *, size_t, size_t)>
        &roundtrip_runner,
    const std::function<KeyHandle(azihsm_handle, uint32_t)> &key_generator
);

void run_streaming_case_list(
    PartitionListHandle &part_list,
    azihsm_algo_id algo_id,
    const std::function<
        void(azihsm_handle, azihsm_algo_id, const uint8_t *, size_t, size_t, size_t)>
        &roundtrip_runner,
    const std::vector<StreamingRoundtripCase> &test_cases,
    const std::function<KeyHandle(azihsm_handle, uint32_t)> &key_generator
);

// Generate an AES key for testing.
KeyHandle generate_aes_key(azihsm_handle session, uint32_t bits);
KeyHandle generate_aes_gcm_key(azihsm_handle session, uint32_t bits);
KeyHandle generate_aes_xts_key(azihsm_handle session, uint32_t bits);
