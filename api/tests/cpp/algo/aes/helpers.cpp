// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "helpers.hpp"
#include "utils/auto_ctx.hpp"
#include "utils/rsa_keygen.hpp"
#include <algorithm>
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

    key_props key_props;
    key_props.key_kind = key_kind;
    key_props.key_class = AZIHSM_KEY_CLASS_SECRET;
    key_props.bits = bits;
    key_props.is_session = true;
    key_props.can_encrypt = true;
    key_props.can_decrypt = true;

    return KeyHandle(session, &keygen_algo, key_props);
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

std::vector<uint8_t> single_shot_crypt(
    CryptOperation operation,
    azihsm_handle key_handle,
    azihsm_algo *algo,
    const uint8_t *input_data,
    size_t input_len
)
{
    azihsm_buffer input{ const_cast<uint8_t *>(input_data), static_cast<uint32_t>(input_len) };
    azihsm_buffer output{ nullptr, 0 };
    auto err = crypt_call(operation, algo, key_handle, &input, &output);
    if (err == AZIHSM_STATUS_SUCCESS)
    {
        EXPECT_EQ(output.len, 0u);
        return {};
    }

    EXPECT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        return {};
    }

    std::vector<uint8_t> result(output.len);
    output.ptr = result.data();
    err = crypt_call(operation, algo, key_handle, &input, &output);
    EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return {};
    }
    result.resize(output.len);
    return result;
}

std::vector<uint8_t> streaming_crypt(
    CryptOperation operation,
    azihsm_handle key_handle,
    azihsm_algo *algo,
    const uint8_t *input_data,
    size_t input_len,
    size_t chunk_size
)
{
    auto_ctx ctx;
    auto err = crypt_init_call(operation, algo, key_handle, ctx.get_ptr());
    EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
    EXPECT_NE(ctx.get(), 0);
    if ((err != AZIHSM_STATUS_SUCCESS) || (ctx.get() == 0))
    {
        return {};
    }

    std::vector<uint8_t> output;
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
            EXPECT_GT(out_buf.len, 0);
            size_t current_pos = output.size();
            output.resize(current_pos + out_buf.len);
            out_buf.ptr = output.data() + current_pos;

            err = crypt_update_call(operation, ctx.get(), &input, &out_buf);
            EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
            if (err != AZIHSM_STATUS_SUCCESS)
            {
                return {};
            }
            output.resize(current_pos + out_buf.len);
        }
        else if (err == AZIHSM_STATUS_SUCCESS)
        {
        }
        else
        {
            ADD_FAILURE() << "Unexpected error: " << err;
            return {};
        }

        offset += current_chunk;
    }

    azihsm_buffer final_out{ nullptr, 0 };
    err = crypt_finish_call(operation, ctx.get(), &final_out);

    if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        EXPECT_GT(final_out.len, 0);
        size_t current_pos = output.size();
        output.resize(current_pos + final_out.len);
        final_out.ptr = output.data() + current_pos;
        err = crypt_finish_call(operation, ctx.get(), &final_out);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            return {};
        }
        output.resize(current_pos + final_out.len);
    }
    else
    {
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            return {};
        }
    }

    return output;
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

KeyHandle generate_aes_cbc_key(azihsm_handle session, uint32_t bits)
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

auto_key import_local_aes_key_for_kat(
    azihsm_handle session,
    const uint8_t *local_key_data,
    size_t local_key_len,
    uint32_t aes_key_bits,
    azihsm_key_kind key_kind
)
{
    auto_key wrapping_priv_key;
    auto_key wrapping_pub_key;
    auto err = generate_rsa_unwrapping_keypair(
        session,
        wrapping_priv_key.get_ptr(),
        wrapping_pub_key.get_ptr()
    );
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return {};
    }

    azihsm_algo_rsa_pkcs_oaep_params oaep_params{};
    oaep_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
    oaep_params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256;
    oaep_params.label = nullptr;

    azihsm_algo_rsa_aes_wrap_params wrap_params{};
    wrap_params.oaep_params = &oaep_params;
    wrap_params.aes_key_bits = aes_key_bits;

    azihsm_algo wrap_algo{};
    wrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_WRAP;
    wrap_algo.params = &wrap_params;
    wrap_algo.len = sizeof(wrap_params);

    azihsm_buffer local_key_buf{};
    local_key_buf.ptr = const_cast<uint8_t *>(local_key_data);
    local_key_buf.len = static_cast<uint32_t>(local_key_len);

    azihsm_buffer wrapped_buf{};
    wrapped_buf.ptr = nullptr;
    wrapped_buf.len = 0;

    err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key.get(), &local_key_buf, &wrapped_buf);
    if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        return {};
    }

    std::vector<uint8_t> wrapped_data(wrapped_buf.len);
    wrapped_buf.ptr = wrapped_data.data();

    err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key.get(), &local_key_buf, &wrapped_buf);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return {};
    }

    azihsm_algo_rsa_aes_key_wrap_params unwrap_params{};
    unwrap_params.oaep_params = &oaep_params;

    azihsm_algo unwrap_algo{};
    unwrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP;
    unwrap_algo.params = &unwrap_params;
    unwrap_algo.len = sizeof(unwrap_params);

    azihsm_key_kind aes_kind = key_kind;
    azihsm_key_class aes_class = AZIHSM_KEY_CLASS_SECRET;
    bool aes_is_session = true;
    bool can_encrypt = true;
    bool can_decrypt = true;

    std::vector<azihsm_key_prop> unwrap_props_vec;
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &aes_kind, sizeof(aes_kind) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &aes_class, sizeof(aes_class) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &aes_key_bits, sizeof(aes_key_bits) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_SESSION, &aes_is_session, sizeof(aes_is_session) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) });

    azihsm_key_prop_list unwrap_prop_list{
        unwrap_props_vec.data(),
        static_cast<uint32_t>(unwrap_props_vec.size())
    };

    azihsm_buffer wrapped_key_buf{};
    wrapped_key_buf.ptr = wrapped_data.data();
    wrapped_key_buf.len = static_cast<uint32_t>(wrapped_data.size());

    auto_key unwrapped_key;
    err = azihsm_key_unwrap(
        &unwrap_algo,
        wrapping_priv_key.get(),
        &wrapped_key_buf,
        &unwrap_prop_list,
        unwrapped_key.get_ptr()
    );
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return {};
    }

    return unwrapped_key;
}
