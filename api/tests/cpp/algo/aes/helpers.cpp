// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "helpers.hpp"
#include "utils/auto_ctx.hpp"
#include "utils/rsa_keygen.hpp"
#include <algorithm>
#include <string>
#include <gtest/gtest.h>

namespace {
KeyHandle generate_aes_key_of_kind(
    azihsm_handle session,
    azihsm_algo_id keygen_algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    azihsm_algo keygen_algo{};
    keygen_algo.id = keygen_algo_id;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    key_gen_props props;
    props.key_kind = key_kind;
    props.key_class = AZIHSM_KEY_CLASS_SECRET;
    props.bits = bits;
    props.is_session = true;
    props.can_encrypt = true;
    props.can_decrypt = true;

    return KeyHandle(session, &keygen_algo, props);
}
}

azihsm_status crypt_call(
    CryptOperation operation,
    azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_buffer *input,
    azihsm_buffer *output
)
{
    if (operation == CryptOperation::Encrypt)
    {
        return azihsm_crypt_encrypt(algo, key_handle, input, output);
    }
    return azihsm_crypt_decrypt(algo, key_handle, input, output);
}

azihsm_status crypt_init_call(
    CryptOperation operation,
    azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_handle *ctx
)
{
    if (operation == CryptOperation::Encrypt)
    {
        return azihsm_crypt_encrypt_init(algo, key_handle, ctx);
    }
    return azihsm_crypt_decrypt_init(algo, key_handle, ctx);
}

azihsm_status crypt_update_call(
    CryptOperation operation,
    azihsm_handle ctx,
    azihsm_buffer *input,
    azihsm_buffer *output
)
{
    if (operation == CryptOperation::Encrypt)
    {
        return azihsm_crypt_encrypt_update(ctx, input, output);
    }
    return azihsm_crypt_decrypt_update(ctx, input, output);
}

azihsm_status crypt_finish_call(
    CryptOperation operation,
    azihsm_handle ctx,
    azihsm_buffer *output
)
{
    if (operation == CryptOperation::Encrypt)
    {
        return azihsm_crypt_encrypt_finish(ctx, output);
    }
    return azihsm_crypt_decrypt_finish(ctx, output);
}

azihsm_status single_shot_status_with_sizing(
    CryptOperation operation,
    azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_buffer *input
)
{
    azihsm_buffer output{ nullptr, 0 };
    auto err = crypt_call(operation, algo, key_handle, input, &output);
    if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        std::vector<uint8_t> candidate(output.len);
        output.ptr = candidate.data();
        err = crypt_call(operation, algo, key_handle, input, &output);
    }
    return err;
}

azihsm_status streaming_update_status_with_sizing(
    CryptOperation operation,
    azihsm_handle ctx,
    azihsm_buffer *input
)
{
    azihsm_buffer output{ nullptr, 0 };
    auto err = crypt_update_call(operation, ctx, input, &output);
    if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        std::vector<uint8_t> out_buf(output.len);
        output.ptr = out_buf.data();
        err = crypt_update_call(operation, ctx, input, &output);
    }
    return err;
}

azihsm_status streaming_finish_status_with_sizing(CryptOperation operation, azihsm_handle ctx)
{
    azihsm_buffer output{ nullptr, 0 };
    auto err = crypt_finish_call(operation, ctx, &output);
    if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        std::vector<uint8_t> out_buf(output.len);
        output.ptr = out_buf.data();
        err = crypt_finish_call(operation, ctx, &output);
    }
    return err;
}

azihsm_status single_shot_crypt(
    CryptOperation operation,
    azihsm_handle key_handle,
    azihsm_algo *algo,
    const uint8_t *input_data,
    size_t input_len,
    std::vector<uint8_t> &output_data
)
{
    output_data.clear();

    azihsm_buffer input{ const_cast<uint8_t *>(input_data), static_cast<uint32_t>(input_len) };
    azihsm_buffer output{ nullptr, 0 };
    auto err = crypt_call(operation, algo, key_handle, &input, &output);
    if (err == AZIHSM_STATUS_SUCCESS)
    {
        if (output.len != 0)
        {
            return AZIHSM_STATUS_INTERNAL_ERROR;
        }

        return AZIHSM_STATUS_SUCCESS;
    }

    if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        return err;
    }

    output_data.resize(output.len);
    output.ptr = output_data.data();
    err = crypt_call(operation, algo, key_handle, &input, &output);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }

    output_data.resize(output.len);
    return AZIHSM_STATUS_SUCCESS;
}

azihsm_status streaming_crypt(
    CryptOperation operation,
    azihsm_handle key_handle,
    azihsm_algo *algo,
    const uint8_t *input_data,
    size_t input_len,
    size_t chunk_size,
    std::vector<uint8_t> &output
)
{
    output.clear();

    if (chunk_size == 0)
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    auto_ctx ctx;
    auto err = crypt_init_call(operation, algo, key_handle, ctx.get_ptr());
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return err;
    }
    if (ctx.get() == 0)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    size_t offset = 0;

    while (offset < input_len)
    {
        size_t current_chunk = std::min(chunk_size, input_len - offset);
        azihsm_buffer input{ const_cast<uint8_t *>(input_data + offset),
                             static_cast<uint32_t>(current_chunk) };
        azihsm_buffer out_buf{ nullptr, 0 };

        err = crypt_update_call(operation, ctx.get(), &input, &out_buf);
        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            if (out_buf.len == 0)
            {
                return AZIHSM_STATUS_INTERNAL_ERROR;
            }
            size_t current_pos = output.size();
            output.resize(current_pos + out_buf.len);
            out_buf.ptr = output.data() + current_pos;

            err = crypt_update_call(operation, ctx.get(), &input, &out_buf);
            if (err != AZIHSM_STATUS_SUCCESS)
            {
                return err;
            }
            output.resize(current_pos + out_buf.len);
        }
        else if (err == AZIHSM_STATUS_SUCCESS)
        {
        }
        else
        {
            return err;
        }

        offset += current_chunk;
    }

    azihsm_buffer final_out{ nullptr, 0 };
    err = crypt_finish_call(operation, ctx.get(), &final_out);

    if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        if (final_out.len == 0)
        {
            return AZIHSM_STATUS_INTERNAL_ERROR;
        }
        size_t current_pos = output.size();
        output.resize(current_pos + final_out.len);
        final_out.ptr = output.data() + current_pos;
        err = crypt_finish_call(operation, ctx.get(), &final_out);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            return err;
        }
        output.resize(current_pos + final_out.len);
    }
    else
    {
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            return err;
        }
    }

    return AZIHSM_STATUS_SUCCESS;
}

std::vector<uint8_t> make_incrementing_bytes(size_t len)
{
    std::vector<uint8_t> bytes(len);
    for (size_t i = 0; i < len; ++i)
    {
        bytes[i] = static_cast<uint8_t>(i & 0xFF);
    }

    return bytes;
}

const std::vector<AesKeyTestParams> &aes_key_sizes()
{
    static const std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };

    return key_sizes;
}

const std::vector<size_t> &padding_sweep_plaintext_sizes()
{
    static const std::vector<size_t> sizes = [] {
        std::vector<size_t> values;
        for (size_t value = 0; value <= 32; ++value)
        {
            values.push_back(value);
        }
        values.push_back(63);
        values.push_back(64);
        values.push_back(65);
        values.push_back(127);
        values.push_back(128);
        values.push_back(129);
        return values;
    }();

    return sizes;
}

const std::vector<size_t> &padding_sweep_chunk_sizes()
{
    static const std::vector<size_t> sizes = {
        1, 2, 3, 5, 7, 8, 15, 16, 17, 31, 32, 33, 64, 256
    };

    return sizes;
}

void run_single_shot_key_size(
    PartitionListHandle &part_list,
    azihsm_algo_id algo_id,
    const std::vector<DataSizeTestParams> &data_sizes,
    uint8_t plaintext_fill,
    const std::function<void(azihsm_handle, azihsm_algo_id, const uint8_t *, size_t, size_t)> &
        roundtrip_runner,
    const std::function<KeyHandle(azihsm_handle, uint32_t)> &key_generator
)
{
    for (const auto &key_param : aes_key_sizes())
    {
        for (const auto &data_param : data_sizes)
        {
            SCOPED_TRACE(std::string(key_param.test_name) + " " + data_param.test_name);

            part_list.for_each_session([&](azihsm_handle session) {
                auto key = key_generator(session, key_param.bits);

                std::vector<uint8_t> plaintext(data_param.data_size, plaintext_fill);
                size_t expected_ciphertext_len = (algo_id == AZIHSM_ALGO_ID_AES_CBC_PAD)
                    ? data_param.expected_output_size_with_pad
                    : data_param.expected_output_size_no_pad;

                roundtrip_runner(
                    key.get(),
                    algo_id,
                    plaintext.data(),
                    plaintext.size(),
                    expected_ciphertext_len
                );
            });
        }
    }
}

void run_streaming_case_list(
    PartitionListHandle &part_list,
    azihsm_algo_id algo_id,
    const std::function<
        void(azihsm_handle, azihsm_algo_id, const uint8_t *, size_t, size_t, size_t)> &
        roundtrip_runner,
    const std::vector<StreamingRoundtripCase> &test_cases,
    const std::function<KeyHandle(azihsm_handle, uint32_t)> &key_generator
)
{
    for (const auto &key_param : aes_key_sizes())
    {
        for (const auto &test_case : test_cases)
        {
            SCOPED_TRACE(std::string(key_param.test_name) + " " + test_case.test_name);

            part_list.for_each_session([&](azihsm_handle session) {
                auto key = key_generator(session, key_param.bits);

                std::vector<uint8_t> plaintext(test_case.plaintext_len, test_case.plaintext_fill);

                roundtrip_runner(
                    key.get(),
                    algo_id,
                    plaintext.data(),
                    plaintext.size(),
                    test_case.chunk_size,
                    test_case.expected_ciphertext_len
                );
            });
        }
    }
}

KeyHandle generate_aes_key(azihsm_handle session, uint32_t bits)
{
    return generate_aes_key_of_kind(
        session,
        AZIHSM_ALGO_ID_AES_KEY_GEN,
        AZIHSM_KEY_KIND_AES,
        bits
    );
}

KeyHandle generate_aes_gcm_key(azihsm_handle session, uint32_t bits)
{
    return generate_aes_key_of_kind(
        session,
        AZIHSM_ALGO_ID_AES_KEY_GEN,
        AZIHSM_KEY_KIND_AES_GCM,
        bits
    );
}

KeyHandle generate_aes_xts_key(azihsm_handle session, uint32_t bits)
{
    return generate_aes_key_of_kind(
        session,
        AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        AZIHSM_KEY_KIND_AES_XTS,
        bits
    );
}
