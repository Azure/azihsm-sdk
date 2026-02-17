// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include <vector>

#include "handle/key_handle.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_ctx.hpp"
#include "utils/known_answer_tests.hpp"
#include <functional>

// High-level suite map and matrix: see cbc_test_coverage.md in this folder.
class azihsm_aes_cbc : public ::testing::Test
{
  protected:
    enum class CryptOperation
    {
            Encrypt,
            Decrypt,
    };

    static constexpr size_t AES_BLOCK_SIZE = 16;

    PartitionListHandle part_list_ = PartitionListHandle{};

    static void init_cbc_algo(
        azihsm_algo &algo,
        azihsm_algo_aes_cbc_params &params,
        azihsm_algo_id algo_id,
        uint8_t iv_fill
    )
    {
        uint8_t iv[AES_BLOCK_SIZE] = { 0 };
        iv[0] = iv_fill;
        std::memcpy(params.iv, iv, sizeof(iv));

        algo.id = algo_id;
        algo.params = &params;
        algo.len = sizeof(params);
    }

    static azihsm_status crypt_call(
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

    static azihsm_status crypt_init_call(
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

    static azihsm_status crypt_update_call(
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

    static azihsm_status crypt_final_call(
        CryptOperation operation,
        azihsm_handle ctx,
        azihsm_buffer *output
    )
    {
        if (operation == CryptOperation::Encrypt)
        {
            return azihsm_crypt_encrypt_final(ctx, output);
        }

        return azihsm_crypt_decrypt_final(ctx, output);
    }

    static size_t padded_ciphertext_len(size_t plaintext_len)
    {
        return ((plaintext_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    }

    // Helper function for single-shot encryption/decryption
    static std::vector<uint8_t> single_shot_crypt(
        azihsm_handle key_handle,
        azihsm_algo *algo,
        const uint8_t *input_data,
        size_t input_len,
        CryptOperation operation
    )
    {
        azihsm_buffer input{ const_cast<uint8_t *>(input_data), static_cast<uint32_t>(input_len) };
        azihsm_buffer output{ nullptr, 0 };
        azihsm_status err;

        // Query required buffer size
        if (operation == CryptOperation::Encrypt)
        {
            err = azihsm_crypt_encrypt(algo, key_handle, &input, &output);
        }
        else
        {
            err = azihsm_crypt_decrypt(algo, key_handle, &input, &output);
        }
        EXPECT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        EXPECT_GT(output.len, 0);

        // Allocate buffer and perform operation
        std::vector<uint8_t> result(output.len);
        output.ptr = result.data();

        if (operation == CryptOperation::Encrypt)
        {
            err = azihsm_crypt_encrypt(algo, key_handle, &input, &output);
        }
        else
        {
            err = azihsm_crypt_decrypt(algo, key_handle, &input, &output);
        }
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Resize to actual bytes written
        result.resize(output.len);
        return result;
    }

    // Helper function for streaming encryption/decryption
    static std::vector<uint8_t> streaming_crypt(
        azihsm_handle key_handle,
        azihsm_algo *algo,
        const uint8_t *input_data,
        size_t input_len,
        size_t chunk_size,
        CryptOperation operation
    )
    {
        auto_ctx ctx;
        azihsm_status err;

        // Initialize context
        if (operation == CryptOperation::Encrypt)
        {
            err = azihsm_crypt_encrypt_init(algo, key_handle, ctx.get_ptr());
        }
        else
        {
            err = azihsm_crypt_decrypt_init(algo, key_handle, ctx.get_ptr());
        }
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_NE(ctx.get(), 0);

        std::vector<uint8_t> output;
        size_t offset = 0;

        // Process in chunks
        while (offset < input_len)
        {
            size_t current_chunk = std::min(chunk_size, input_len - offset);
            azihsm_buffer input{ const_cast<uint8_t *>(input_data + offset),
                                 static_cast<uint32_t>(current_chunk) };
            azihsm_buffer out_buf{ nullptr, 0 };

            if (operation == CryptOperation::Encrypt)
            {
                err = azihsm_crypt_encrypt_update(ctx, &input, &out_buf);
            }
            else
            {
                err = azihsm_crypt_decrypt_update(ctx, &input, &out_buf);
            }

            if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
            {
                // Buffer too small, allocate and retry with same input
                EXPECT_GT(out_buf.len, 0);
                size_t current_pos = output.size();
                output.resize(current_pos + out_buf.len);
                out_buf.ptr = output.data() + current_pos;

                if (operation == CryptOperation::Encrypt)
                {
                    err = azihsm_crypt_encrypt_update(ctx, &input, &out_buf);
                }
                else
                {
                    err = azihsm_crypt_decrypt_update(ctx, &input, &out_buf);
                }
                EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
                // Adjust output size to actual bytes written
                output.resize(current_pos + out_buf.len);
            }
            else if (err == AZIHSM_STATUS_SUCCESS)
            {
                // Success - data may or may not have been produced
                // out_buf.len tells us how much data, but we didn't provide a buffer
                // so we don't copy anything
            }
            else
            {
                ADD_FAILURE() << "Unexpected error: " << err;
                break;
            }

            // Move to next chunk regardless of whether output was produced
            offset += current_chunk;
        }

        // Finish
        azihsm_buffer final_out{ nullptr, 0 };
        if (operation == CryptOperation::Encrypt)
        {
            err = azihsm_crypt_encrypt_finish(ctx, &final_out);
        }
        else
        {
            err = azihsm_crypt_decrypt_finish(ctx, &final_out);
        }

        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            EXPECT_GT(final_out.len, 0);
            size_t current_pos = output.size();
            output.resize(current_pos + final_out.len);
            final_out.ptr = output.data() + current_pos;

            if (operation == CryptOperation::Encrypt)
            {
                err = azihsm_crypt_encrypt_finish(ctx, &final_out);
            }
            else
            {
                err = azihsm_crypt_decrypt_finish(ctx, &final_out);
            }
            EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
            // Adjust output size to actual bytes written
            output.resize(current_pos + final_out.len);
        }
        else
        {
            EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        }

        return output;
    }

    // Helper to test single-shot encrypt/decrypt roundtrip
    void test_single_shot_roundtrip(
        azihsm_handle key_handle,
        azihsm_algo_id algo_id,
        const uint8_t *plaintext,
        size_t plaintext_len,
        size_t expected_ciphertext_len
    )
    {
        uint8_t iv[16] = { 0xCC };
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        azihsm_algo crypt_algo{};
        crypt_algo.id = algo_id;
        crypt_algo.params = &cbc_params;
        crypt_algo.len = sizeof(cbc_params);

        // Encrypt
        auto ciphertext = single_shot_crypt(
            key_handle,
            &crypt_algo,
            plaintext,
            plaintext_len,
            CryptOperation::Encrypt
        );
        ASSERT_EQ(ciphertext.size(), expected_ciphertext_len);

        // Reset IV for decryption
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        // Decrypt
        auto decrypted = single_shot_crypt(
            key_handle,
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            CryptOperation::Decrypt
        );

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, plaintext_len), 0);
    }

    // Helper to test streaming encrypt/decrypt roundtrip
    void test_streaming_roundtrip(
        azihsm_handle key_handle,
        azihsm_algo_id algo_id,
        const uint8_t *plaintext,
        size_t plaintext_len,
        size_t chunk_size,
        size_t expected_ciphertext_len
    )
    {
        uint8_t iv[16] = { 0xAA };
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        azihsm_algo crypt_algo{};
        crypt_algo.id = algo_id;
        crypt_algo.params = &cbc_params;
        crypt_algo.len = sizeof(cbc_params);

        // Encrypt
        auto ciphertext = streaming_crypt(
            key_handle,
            &crypt_algo,
            plaintext,
            plaintext_len,
            chunk_size,
            CryptOperation::Encrypt
        );
        ASSERT_EQ(ciphertext.size(), expected_ciphertext_len);

        // Reset IV for decryption
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        // Decrypt
        auto decrypted = streaming_crypt(
            key_handle,
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            chunk_size,
            CryptOperation::Decrypt
        );

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, plaintext_len), 0);
    }
};

// Test data structures
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

// ==================== Single-Shot Tests ====================

TEST_F(azihsm_aes_cbc, single_shot_no_padding_all_key_sizes)
{
    std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };

    std::vector<DataSizeTestParams> data_sizes = {
        { 16, 16, 32, "1_block" },  // Exactly 1 block
        { 32, 32, 48, "2_blocks" }, // Exactly 2 blocks
        { 48, 48, 64, "3_blocks" }, // Exactly 3 blocks
        { 64, 64, 80, "4_blocks" }, // Exactly 4 blocks
    };

    for (const auto &key_param : key_sizes)
    {
        for (const auto &data_param : data_sizes)
        {
            SCOPED_TRACE(std::string(key_param.test_name) + " no_padding " + data_param.test_name);

            part_list_.for_each_session([&](azihsm_handle session) {
                auto key = generate_aes_key(session, key_param.bits);

                std::vector<uint8_t> plaintext(data_param.data_size, 0xAB);

                test_single_shot_roundtrip(
                    key.get(),
                    AZIHSM_ALGO_ID_AES_CBC,
                    plaintext.data(),
                    plaintext.size(),
                    data_param.expected_output_size_no_pad
                );
            });
        }
    }
}

TEST_F(azihsm_aes_cbc, single_shot_with_padding_all_key_sizes)
{
    std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };

    std::vector<DataSizeTestParams> data_sizes = {
        { 1, 16, 16, "1_byte" },    // Much smaller than block
        { 13, 16, 16, "13_bytes" }, // Just under 1 block
        { 15, 16, 16, "15_bytes" }, // 1 byte short of block
        { 16, 16, 32, "16_bytes" }, // Exactly 1 block (needs full padding block)
        { 17, 32, 32, "17_bytes" }, // 1 byte over 1 block
        { 27, 32, 32, "27_bytes" }, // Between 1 and 2 blocks
        { 32, 32, 48, "32_bytes" }, // Exactly 2 blocks
        { 63, 64, 64, "63_bytes" }, // 1 byte short of 4 blocks
    };

    for (const auto &key_param : key_sizes)
    {
        for (const auto &data_param : data_sizes)
        {
            SCOPED_TRACE(
                std::string(key_param.test_name) + " with_padding " + data_param.test_name
            );

            part_list_.for_each_session([&](azihsm_handle session) {
                auto key = generate_aes_key(session, key_param.bits);

                std::vector<uint8_t> plaintext(data_param.data_size, 0xCD);

                test_single_shot_roundtrip(
                    key.get(),
                    AZIHSM_ALGO_ID_AES_CBC_PAD,
                    plaintext.data(),
                    plaintext.size(),
                    data_param.expected_output_size_with_pad
                );
            });
        }
    }
}

// ==================== Streaming Tests - No Padding ====================

TEST_F(azihsm_aes_cbc, streaming_no_padding_exact_blocks)
{
    std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };

    for (const auto &key_param : key_sizes)
    {
        SCOPED_TRACE("Testing " + std::string(key_param.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto key = generate_aes_key(session, key_param.bits);

            std::vector<uint8_t> plaintext(32, 0xEF);

            test_streaming_roundtrip(
                key.get(),
                AZIHSM_ALGO_ID_AES_CBC,
                plaintext.data(),
                plaintext.size(),
                16, // Process in exact blocks
                32
            );
        });
    }
}

TEST_F(azihsm_aes_cbc, streaming_no_padding_multiple_blocks)
{
    std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };

    for (const auto &key_param : key_sizes)
    {
        SCOPED_TRACE("Testing " + std::string(key_param.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto key = generate_aes_key(session, key_param.bits);

            std::vector<uint8_t> plaintext(64, 0xEF);

            test_streaming_roundtrip(
                key.get(),
                AZIHSM_ALGO_ID_AES_CBC,
                plaintext.data(),
                plaintext.size(),
                16, // Multiple blocks
                64
            );
        });
    }
}

TEST_F(azihsm_aes_cbc, streaming_no_padding_larger_chunks)
{
    std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };

    for (const auto &key_param : key_sizes)
    {
        SCOPED_TRACE("Testing " + std::string(key_param.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto key = generate_aes_key(session, key_param.bits);

            std::vector<uint8_t> plaintext(64, 0xEF);

            test_streaming_roundtrip(
                key.get(),
                AZIHSM_ALGO_ID_AES_CBC,
                plaintext.data(),
                plaintext.size(),
                32, // Larger chunks
                64
            );
        });
    }
}

TEST_F(azihsm_aes_cbc, streaming_no_padding_non_aligned_chunks)
{
    std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };

    for (const auto &key_param : key_sizes)
    {
        SCOPED_TRACE("Testing " + std::string(key_param.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto key = generate_aes_key(session, key_param.bits);

            std::vector<uint8_t> plaintext(48, 0xEF);

            test_streaming_roundtrip(
                key.get(),
                AZIHSM_ALGO_ID_AES_CBC,
                plaintext.data(),
                plaintext.size(),
                10, // Non-aligned chunks
                48
            );
        });
    }
}

// ==================== Streaming Tests - With Padding ====================

TEST_F(azihsm_aes_cbc, streaming_with_padding_small_data_small_chunks)
{
    std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };

    for (const auto &key_param : key_sizes)
    {
        SCOPED_TRACE("Testing " + std::string(key_param.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto key = generate_aes_key(session, key_param.bits);

            std::vector<uint8_t> plaintext(13, 0x12);

            test_streaming_roundtrip(
                key.get(),
                AZIHSM_ALGO_ID_AES_CBC_PAD,
                plaintext.data(),
                plaintext.size(),
                5, // Small chunks
                16
            );
        });
    }
}

TEST_F(azihsm_aes_cbc, streaming_with_padding_non_aligned_data_and_chunks)
{
    std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };

    for (const auto &key_param : key_sizes)
    {
        SCOPED_TRACE("Testing " + std::string(key_param.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto key = generate_aes_key(session, key_param.bits);

            std::vector<uint8_t> plaintext(27, 0x12);

            test_streaming_roundtrip(
                key.get(),
                AZIHSM_ALGO_ID_AES_CBC_PAD,
                plaintext.data(),
                plaintext.size(),
                10, // Non-aligned chunks
                32
            );
        });
    }
}

TEST_F(azihsm_aes_cbc, streaming_with_padding_almost_two_blocks)
{
    std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };

    for (const auto &key_param : key_sizes)
    {
        SCOPED_TRACE("Testing " + std::string(key_param.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto key = generate_aes_key(session, key_param.bits);

            std::vector<uint8_t> plaintext(31, 0x12);

            test_streaming_roundtrip(
                key.get(),
                AZIHSM_ALGO_ID_AES_CBC_PAD,
                plaintext.data(),
                plaintext.size(),
                16, // Block-sized chunks
                32
            );
        });
    }
}

TEST_F(azihsm_aes_cbc, streaming_with_padding_odd_chunk_size)
{
    std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };

    for (const auto &key_param : key_sizes)
    {
        SCOPED_TRACE("Testing " + std::string(key_param.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto key = generate_aes_key(session, key_param.bits);

            std::vector<uint8_t> plaintext(50, 0x12);

            test_streaming_roundtrip(
                key.get(),
                AZIHSM_ALGO_ID_AES_CBC_PAD,
                plaintext.data(),
                plaintext.size(),
                15, // Odd chunk size
                64
            );
        });
    }
}

TEST_F(azihsm_aes_cbc, streaming_with_padding_larger_data_odd_chunks)
{
    std::vector<AesKeyTestParams> key_sizes = {
        { 128, "AES-128" },
        { 192, "AES-192" },
        { 256, "AES-256" },
    };

    for (const auto &key_param : key_sizes)
    {
        SCOPED_TRACE("Testing " + std::string(key_param.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto key = generate_aes_key(session, key_param.bits);

            std::vector<uint8_t> plaintext(100, 0x12);

            test_streaming_roundtrip(
                key.get(),
                AZIHSM_ALGO_ID_AES_CBC_PAD,
                plaintext.data(),
                plaintext.size(),
                33, // Odd chunk size
                112
            );
        });
    }
}

// Verifies AES-CBC output matches standard known-answer vectors for all key sizes.
TEST_F(azihsm_aes_cbc, single_shot_known_answer_vectors_match)
{
    const auto &vectors = cbc_known_answer_vectors();

    part_list_.for_each_session([&](azihsm_handle session) {
        for (const auto &vector : vectors)
        {
            SCOPED_TRACE(vector.test_name);

            auto key =
                import_local_aes_key_for_kat(session, vector.key, vector.key_len, vector.bits);
            ASSERT_NE(key.get(), 0);

            azihsm_algo_aes_cbc_params cbc_params{};
            std::memcpy(cbc_params.iv, vector.iv, vector.iv_len);

            azihsm_algo crypt_algo{};
            crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC;
            crypt_algo.params = &cbc_params;
            crypt_algo.len = sizeof(cbc_params);

            auto ciphertext = single_shot_crypt(
                key.get(),
                &crypt_algo,
                vector.plaintext,
                vector.plaintext_len,
                CryptOperation::Encrypt
            );
            ASSERT_EQ(ciphertext.size(), vector.ciphertext_len);
            ASSERT_EQ(std::memcmp(ciphertext.data(), vector.ciphertext, vector.ciphertext_len), 0);

            std::memcpy(cbc_params.iv, vector.iv, vector.iv_len);
            auto plaintext = single_shot_crypt(
                key.get(),
                &crypt_algo,
                vector.ciphertext,
                vector.ciphertext_len,
                CryptOperation::Decrypt
            );
            ASSERT_EQ(plaintext.size(), vector.plaintext_len);
            ASSERT_EQ(std::memcmp(plaintext.data(), vector.plaintext, vector.plaintext_len), 0);
        }
    });
}

// Verifies streaming AES-CBC matches known-answer vectors across varied chunk sizes.
TEST_F(azihsm_aes_cbc, streaming_known_answer_vectors_match)
{
    std::vector<size_t> chunk_sizes = { 1, 16, 17, 64 };
    const auto &vectors = cbc_known_answer_vectors();

    part_list_.for_each_session([&](azihsm_handle session) {
        for (const auto &vector : vectors)
        {
            for (auto chunk_size : chunk_sizes)
            {
                SCOPED_TRACE(
                    std::string(vector.test_name) + " chunk_size=" + std::to_string(chunk_size)
                );

                auto key = import_local_aes_key_for_kat(
                    session,
                    vector.key,
                    vector.key_len,
                    vector.bits
                );
                ASSERT_NE(key.get(), 0);

                azihsm_algo_aes_cbc_params cbc_params{};
                std::memcpy(cbc_params.iv, vector.iv, vector.iv_len);

                azihsm_algo crypt_algo{};
                crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC;
                crypt_algo.params = &cbc_params;
                crypt_algo.len = sizeof(cbc_params);

                auto ciphertext = streaming_crypt(
                    key.get(),
                    &crypt_algo,
                    vector.plaintext,
                    vector.plaintext_len,
                    chunk_size,
                    CryptOperation::Encrypt
                );
                ASSERT_EQ(ciphertext.size(), vector.ciphertext_len);
                ASSERT_EQ(
                    std::memcmp(ciphertext.data(), vector.ciphertext, vector.ciphertext_len),
                    0
                );

                std::memcpy(cbc_params.iv, vector.iv, vector.iv_len);
                auto plaintext = streaming_crypt(
                    key.get(),
                    &crypt_algo,
                    vector.ciphertext,
                    vector.ciphertext_len,
                    chunk_size,
                    CryptOperation::Decrypt
                );
                ASSERT_EQ(plaintext.size(), vector.plaintext_len);
                ASSERT_EQ(
                    std::memcmp(plaintext.data(), vector.plaintext, vector.plaintext_len),
                    0
                );
            }
        }
    });
}

// Verifies CBC-PAD produces fixed expected ciphertext on 15-byte and 16-byte boundaries.
TEST_F(azihsm_aes_cbc, single_shot_with_padding_known_answer_boundary_vectors_match)
{
    const auto &vectors = cbc_pad_boundary_known_answer_vectors();

    part_list_.for_each_session([&](azihsm_handle session) {
        for (const auto &vector : vectors)
        {
            SCOPED_TRACE(vector.test_name);

            auto key =
                import_local_aes_key_for_kat(session, vector.key, vector.key_len, vector.bits);
            ASSERT_NE(key.get(), 0);

            azihsm_algo_aes_cbc_params cbc_params{};
            std::memcpy(cbc_params.iv, vector.iv, vector.iv_len);

            azihsm_algo crypt_algo{};
            crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC_PAD;
            crypt_algo.params = &cbc_params;
            crypt_algo.len = sizeof(cbc_params);

            auto ciphertext = single_shot_crypt(
                key.get(),
                &crypt_algo,
                vector.plaintext,
                vector.plaintext_len,
                CryptOperation::Encrypt
            );
            ASSERT_EQ(ciphertext.size(), vector.ciphertext_len);
            ASSERT_EQ(std::memcmp(ciphertext.data(), vector.ciphertext, vector.ciphertext_len), 0);

            std::memcpy(cbc_params.iv, vector.iv, vector.iv_len);
            auto plaintext = single_shot_crypt(
                key.get(),
                &crypt_algo,
                vector.ciphertext,
                vector.ciphertext_len,
                CryptOperation::Decrypt
            );
            ASSERT_EQ(plaintext.size(), vector.plaintext_len);
            ASSERT_EQ(std::memcmp(plaintext.data(), vector.plaintext, vector.plaintext_len), 0);
        }
    });
}

// Verifies streaming CBC-PAD boundary vectors match fixed expected ciphertext across chunking.
TEST_F(azihsm_aes_cbc, streaming_with_padding_known_answer_boundary_vectors_match)
{
    const auto &vectors = cbc_pad_boundary_known_answer_vectors();
    std::vector<size_t> chunk_sizes = { 1, 15, 16, 17 };

    part_list_.for_each_session([&](azihsm_handle session) {
        for (const auto &vector : vectors)
        {
            for (auto chunk_size : chunk_sizes)
            {
                SCOPED_TRACE(
                    std::string(vector.test_name) + " chunk_size=" + std::to_string(chunk_size)
                );

                auto key =
                    import_local_aes_key_for_kat(session, vector.key, vector.key_len, vector.bits);
                ASSERT_NE(key.get(), 0);

                azihsm_algo_aes_cbc_params cbc_params{};
                std::memcpy(cbc_params.iv, vector.iv, vector.iv_len);

                azihsm_algo crypt_algo{};
                crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC_PAD;
                crypt_algo.params = &cbc_params;
                crypt_algo.len = sizeof(cbc_params);

                auto ciphertext = streaming_crypt(
                    key.get(),
                    &crypt_algo,
                    vector.plaintext,
                    vector.plaintext_len,
                    chunk_size,
                    CryptOperation::Encrypt
                );
                ASSERT_EQ(ciphertext.size(), vector.ciphertext_len);
                ASSERT_EQ(
                    std::memcmp(ciphertext.data(), vector.ciphertext, vector.ciphertext_len),
                    0
                );

                std::memcpy(cbc_params.iv, vector.iv, vector.iv_len);
                auto plaintext = streaming_crypt(
                    key.get(),
                    &crypt_algo,
                    vector.ciphertext,
                    vector.ciphertext_len,
                    chunk_size,
                    CryptOperation::Decrypt
                );
                ASSERT_EQ(plaintext.size(), vector.plaintext_len);
                ASSERT_EQ(std::memcmp(plaintext.data(), vector.plaintext, vector.plaintext_len), 0);
            }
        }
    });
}

// ==================== Edge Case Tests ====================

TEST_F(azihsm_aes_cbc, empty_data_with_padding)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        uint8_t iv[16] = { 0xFF };
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC_PAD;
        crypt_algo.params = &cbc_params;
        crypt_algo.len = sizeof(cbc_params);

        // Encrypt empty data - should produce one block of padding
        uint8_t empty[1] = { 0 };
        azihsm_buffer input{ empty, 0 };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(output.len, 16u); // One block of padding

        std::vector<uint8_t> ciphertext(output.len);
        output.ptr = ciphertext.data();
        err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Decrypt should return empty data
        std::memcpy(cbc_params.iv, iv, sizeof(iv));
        azihsm_buffer cipher_buf{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        azihsm_buffer plain_buf{ nullptr, 0 };

        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_buf, &plain_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

        std::vector<uint8_t> plaintext(plain_buf.len);
        plain_buf.ptr = plaintext.data();
        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_buf, &plain_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(plain_buf.len, 0u);
    });
}

TEST_F(azihsm_aes_cbc, null_iv)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());
        auto key = generate_aes_key(session.get(), 128);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC;
        crypt_algo.params = nullptr; // No IV provided
        crypt_algo.len = 0;

        uint8_t plaintext[16] = { 0xAA };
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_cbc, non_block_aligned_no_padding)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        uint8_t iv[16] = { 0xBB };
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC; // No padding
        crypt_algo.params = &cbc_params;
        crypt_algo.len = sizeof(cbc_params);

        // Try to encrypt non-block-aligned data without padding
        uint8_t plaintext[13] = { 0xCC }; // Not a multiple of 16
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_aes_cbc, invalid_key_handle)
{
    uint8_t iv[16] = { 0xDD };
    azihsm_algo_aes_cbc_params cbc_params{};
    std::memcpy(cbc_params.iv, iv, sizeof(iv));

    azihsm_algo crypt_algo{};
    crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC;
    crypt_algo.params = &cbc_params;
    crypt_algo.len = sizeof(cbc_params);

    uint8_t plaintext[16] = { 0xEE };
    azihsm_buffer input{ plaintext, sizeof(plaintext) };
    azihsm_buffer output{ nullptr, 0 };

    auto err = azihsm_crypt_encrypt(&crypt_algo, 0xDEADBEEF, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST_F(azihsm_aes_cbc, streaming_consistency_with_single_shot)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        uint8_t iv[16] = { 0xFF };
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC_PAD;
        crypt_algo.params = &cbc_params;
        crypt_algo.len = sizeof(cbc_params);

        std::vector<uint8_t> plaintext(100, 0x55);

        // Single-shot encrypt
        auto single_shot_ciphertext = single_shot_crypt(
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            CryptOperation::Encrypt
        );

        // Reset IV for streaming
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        // Streaming encrypt
        auto streaming_ciphertext = streaming_crypt(
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            17,
            CryptOperation::Encrypt
        );

        // Results should be identical
        ASSERT_EQ(single_shot_ciphertext.size(), streaming_ciphertext.size());
        ASSERT_EQ(
            std::memcmp(
                single_shot_ciphertext.data(),
                streaming_ciphertext.data(),
                single_shot_ciphertext.size()
            ),
            0
        );
    });
}

TEST_F(azihsm_aes_cbc, large_data_streaming)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        uint8_t iv[16] = { 0x11 };
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC_PAD;
        crypt_algo.params = &cbc_params;
        crypt_algo.len = sizeof(cbc_params);

        // Test with larger data (4KB)
        std::vector<uint8_t> plaintext(4096);
        for (size_t i = 0; i < plaintext.size(); ++i)
        {
            plaintext[i] = static_cast<uint8_t>(i & 0xFF);
        }

        // Encrypt
        auto ciphertext = streaming_crypt(
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            256,
            CryptOperation::Encrypt
        );

        // Reset IV for decryption
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        // Decrypt
        auto decrypted = streaming_crypt(
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            256,
            CryptOperation::Decrypt
        );

        ASSERT_EQ(decrypted.size(), plaintext.size());
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
    });
}

// Verifies single-shot CBC-PAD preserves content for larger payloads.
TEST_F(azihsm_aes_cbc, large_data_single_shot)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        uint8_t iv[16] = { 0x21 };
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC_PAD;
        crypt_algo.params = &cbc_params;
        crypt_algo.len = sizeof(cbc_params);

        std::vector<uint8_t> plaintext(4096);
        for (size_t i = 0; i < plaintext.size(); ++i)
        {
            plaintext[i] = static_cast<uint8_t>(i & 0xFF);
        }

        auto ciphertext = single_shot_crypt(
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            CryptOperation::Encrypt
        );
        ASSERT_EQ(ciphertext.size(), padded_ciphertext_len(plaintext.size()));

        std::memcpy(cbc_params.iv, iv, sizeof(iv));
        auto decrypted = single_shot_crypt(
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            CryptOperation::Decrypt
        );

        ASSERT_EQ(decrypted.size(), plaintext.size());
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
    });
}

// Verifies streaming no-padding rejects partial final blocks for both encrypt and decrypt flows.
TEST_F(azihsm_aes_cbc, streaming_no_padding_partial_block_input_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        auto run_expect_failure = [&](CryptOperation operation, std::vector<uint8_t> input_bytes) {
            azihsm_algo_aes_cbc_params cbc_params{};
            azihsm_algo crypt_algo{};
            init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x22);

            azihsm_handle ctx = 0;
            auto err = crypt_init_call(operation, &crypt_algo, key.get(), &ctx);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            azihsm_buffer input{ input_bytes.data(), static_cast<uint32_t>(input_bytes.size()) };
            azihsm_buffer output{ nullptr, 0 };

            bool saw_failure = false;
            err = crypt_update_call(operation, ctx, &input, &output);
            if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
            {
                std::vector<uint8_t> out_buf(output.len);
                output.ptr = out_buf.data();
                err = crypt_update_call(operation, ctx, &input, &output);
            }

            if (err != AZIHSM_STATUS_SUCCESS)
            {
                saw_failure = true;
            }

            if (!saw_failure)
            {
                azihsm_buffer final_out{ nullptr, 0 };
                err = crypt_final_call(operation, ctx, &final_out);
                if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
                {
                    std::vector<uint8_t> out_buf(final_out.len);
                    final_out.ptr = out_buf.data();
                    err = crypt_final_call(operation, ctx, &final_out);
                }
                ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
            }
        };

        std::vector<uint8_t> bad_plaintext(17, 0xA1);
        run_expect_failure(CryptOperation::Encrypt, std::move(bad_plaintext));

        std::vector<uint8_t> bad_ciphertext(17, 0xA2);
        run_expect_failure(CryptOperation::Decrypt, std::move(bad_ciphertext));
    });
}

TEST_F(azihsm_aes_cbc, different_ivs_produce_different_ciphertexts)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        uint8_t plaintext[16] = { 0x42 };

        // Encrypt with IV1
        uint8_t iv1[16] = { 0xAA };
        azihsm_algo_aes_cbc_params cbc_params1{};
        std::memcpy(cbc_params1.iv, iv1, sizeof(iv1));

        azihsm_algo crypt_algo1{};
        crypt_algo1.id = AZIHSM_ALGO_ID_AES_CBC;
        crypt_algo1.params = &cbc_params1;
        crypt_algo1.len = sizeof(cbc_params1);

        auto ciphertext1 = single_shot_crypt(
            key.get(),
            &crypt_algo1,
            plaintext,
            sizeof(plaintext),
            CryptOperation::Encrypt
        );

        // Encrypt with IV2
        uint8_t iv2[16] = { 0xBB };
        azihsm_algo_aes_cbc_params cbc_params2{};
        std::memcpy(cbc_params2.iv, iv2, sizeof(iv2));

        azihsm_algo crypt_algo2{};
        crypt_algo2.id = AZIHSM_ALGO_ID_AES_CBC;
        crypt_algo2.params = &cbc_params2;
        crypt_algo2.len = sizeof(cbc_params2);

        auto ciphertext2 = single_shot_crypt(
            key.get(),
            &crypt_algo2,
            plaintext,
            sizeof(plaintext),
            CryptOperation::Encrypt
        );

        // Ciphertexts should be different
        ASSERT_EQ(ciphertext1.size(), ciphertext2.size());
        ASSERT_NE(std::memcmp(ciphertext1.data(), ciphertext2.data(), ciphertext1.size()), 0);
    });
}

// ==================== Invalid Argument Tests ====================

// -------------------- Single-Shot --------------------

TEST_F(azihsm_aes_cbc, single_shot_null_pointers_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x12);

        uint8_t plaintext[AES_BLOCK_SIZE] = { 0xAA };
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = crypt_call(CryptOperation::Encrypt, nullptr, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), nullptr, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_cbc, single_shot_invalid_buffer_shapes_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x23);

        uint8_t plaintext[AES_BLOCK_SIZE] = { 0xAB };
        azihsm_buffer bad_input{ nullptr, 1 };
        azihsm_buffer output{ nullptr, 0 };

        auto err =
            crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &bad_input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer bad_output{ nullptr, 1 };
        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_cbc, single_shot_invalid_algo_param_len_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x34);

        uint8_t plaintext[AES_BLOCK_SIZE] = { 0xCC };
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        crypt_algo.len = sizeof(cbc_params) - 1;
        auto err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        crypt_algo.len = sizeof(cbc_params) + 1;
        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// -------------------- Streaming --------------------

// Validates streaming init rejects null mandatory pointers.
TEST_F(azihsm_aes_cbc, streaming_init_null_pointers_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x35);

        azihsm_handle ctx = 0;

        auto err = crypt_init_call(CryptOperation::Encrypt, nullptr, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_init_call(CryptOperation::Decrypt, nullptr, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_init_call(CryptOperation::Decrypt, &crypt_algo, key.get(), nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Validates streaming init rejects malformed algorithm parameter layouts.
TEST_F(azihsm_aes_cbc, streaming_init_invalid_algo_params_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x36);

        azihsm_handle ctx = 0;

        crypt_algo.params = nullptr;
        crypt_algo.len = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x36);
        crypt_algo.params = nullptr;
        crypt_algo.len = 0;
        err = crypt_init_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Validates streaming init rejects incorrect CBC parameter size values.
TEST_F(azihsm_aes_cbc, streaming_init_invalid_algo_param_len_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x37);

        azihsm_handle ctx = 0;

        crypt_algo.len = sizeof(cbc_params) - 1;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        crypt_algo.len = sizeof(cbc_params) + 1;
        err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Validates streaming init rejects invalid key handles.
TEST_F(azihsm_aes_cbc, streaming_init_invalid_key_handle_is_rejected)
{
    azihsm_algo_aes_cbc_params cbc_params{};
    azihsm_algo crypt_algo{};
    init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x38);

    azihsm_handle ctx = 0;
    auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, 0xDEADBEEF, &ctx);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = crypt_init_call(CryptOperation::Decrypt, &crypt_algo, 0xDEADBEEF, &ctx);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

// Validates streaming update/final reject null buffers.
TEST_F(azihsm_aes_cbc, streaming_update_and_final_null_pointers_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x39);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t data[AES_BLOCK_SIZE] = { 0x44 };
        azihsm_buffer input{ data, sizeof(data) };
        azihsm_buffer output{ nullptr, 0 };

        err = crypt_update_call(CryptOperation::Encrypt, ctx, nullptr, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_update_call(CryptOperation::Encrypt, ctx, &input, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_final_call(CryptOperation::Encrypt, ctx, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Validates update/final reject malformed buffer shapes (null pointer with non-zero len).
TEST_F(azihsm_aes_cbc, streaming_update_and_final_invalid_buffer_shapes_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x3A);

        azihsm_handle enc_ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &enc_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_handle dec_ctx = 0;
        err = crypt_init_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &dec_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t byte = 0x01;
        azihsm_buffer bad_input{ nullptr, 1 };
        azihsm_buffer bad_output{ nullptr, 1 };
        azihsm_buffer good_output{ &byte, 1 };
        azihsm_buffer good_input{ &byte, 1 };

        err = crypt_update_call(CryptOperation::Encrypt, enc_ctx, &bad_input, &good_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_update_call(CryptOperation::Encrypt, enc_ctx, &good_input, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_update_call(CryptOperation::Decrypt, dec_ctx, &bad_input, &good_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_update_call(CryptOperation::Decrypt, dec_ctx, &good_input, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_final_call(CryptOperation::Encrypt, enc_ctx, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_final_call(CryptOperation::Decrypt, dec_ctx, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Validates single-shot output-buffer contract for no-padding mode (query/exact/too-small).
TEST_F(azihsm_aes_cbc, single_shot_output_buffer_contract_no_padding)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x45);

        std::vector<uint8_t> plaintext(2 * AES_BLOCK_SIZE, 0x99);
        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(output.len, plaintext.size());

        std::vector<uint8_t> exact_output(output.len);
        output.ptr = exact_output.data();
        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(output.len, plaintext.size());

        std::vector<uint8_t> small_output(plaintext.size() - 1);
        azihsm_buffer too_small{ small_output.data(), static_cast<uint32_t>(small_output.size()) };
        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &too_small);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(too_small.len, plaintext.size());
    });
}

// Validates single-shot output-buffer contract for padding mode across boundary lengths.
TEST_F(azihsm_aes_cbc, single_shot_output_buffer_contract_with_padding)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x46);

        std::vector<size_t> plaintext_lens = { 0, 15, 16, 17 };
        for (auto plaintext_len : plaintext_lens)
        {
            SCOPED_TRACE("plaintext_len=" + std::to_string(plaintext_len));

            std::vector<uint8_t> plaintext(plaintext_len, 0xA3);
            uint8_t dummy = 0;
            azihsm_buffer input{
                plaintext_len == 0 ? &dummy : plaintext.data(),
                static_cast<uint32_t>(plaintext_len)
            };
            azihsm_buffer output{ nullptr, 0 };

            auto expected_len = padded_ciphertext_len(plaintext_len);

            auto err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
            ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_EQ(output.len, expected_len);

            std::vector<uint8_t> exact_output(output.len);
            output.ptr = exact_output.data();
            err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(output.len, expected_len);

            std::vector<uint8_t> small_output(expected_len - 1);
            azihsm_buffer too_small{ small_output.data(), static_cast<uint32_t>(small_output.size()) };
            err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &too_small);
            ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_EQ(too_small.len, expected_len);
        }
    });
}

// Ensures CBC decrypt rejects ciphertext lengths that are not multiples of the block size.
TEST_F(azihsm_aes_cbc, decrypt_non_block_aligned_ciphertext_fails)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        std::vector<uint8_t> bad_ciphertext(17, 0xA5);
        azihsm_buffer input{ bad_ciphertext.data(), static_cast<uint32_t>(bad_ciphertext.size()) };
        azihsm_buffer output{ nullptr, 0 };

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};

        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x56);
        auto err = crypt_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);

        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x56);
        err = crypt_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Ensures CBC-PAD decrypt rejects tampered ciphertext with invalid PKCS#7 padding.
TEST_F(azihsm_aes_cbc, decrypt_invalid_padding_fails)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x67);

        std::vector<uint8_t> plaintext(31, 0x44);
        auto ciphertext = single_shot_crypt(
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            CryptOperation::Encrypt
        );

        ciphertext.back() ^= 0xFF;

        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x67);
        azihsm_buffer input{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = crypt_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &input, &output);
        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            std::vector<uint8_t> candidate(output.len);
            output.ptr = candidate.data();
            err = crypt_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &input, &output);
        }

        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Sweeps PKCS#7 malformed cases (zero pad byte and inconsistent pad bytes) across pad lengths.
TEST_F(azihsm_aes_cbc, decrypt_invalid_padding_variants_fail)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        for (size_t pad_len = 1; pad_len <= AES_BLOCK_SIZE; ++pad_len)
        {
            // Build plaintext so PKCS#7 pad length in the final block is exactly `pad_len`.
            const size_t plaintext_len = (2 * AES_BLOCK_SIZE) - pad_len;
            std::vector<uint8_t> plaintext(plaintext_len, 0x2A);

            azihsm_algo_aes_cbc_params cbc_params{};
            azihsm_algo crypt_algo{};
            init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x68);

            auto ciphertext = single_shot_crypt(
                key.get(),
                &crypt_algo,
                plaintext.data(),
                plaintext.size(),
                CryptOperation::Encrypt
            );

            SCOPED_TRACE("pad_len=" + std::to_string(pad_len));

            auto assert_decrypt_fails = [&](std::vector<uint8_t> mutated) {
                // Reinitialize algo/IV so each mutation is evaluated from the same decrypt state.
                init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x68);
                azihsm_buffer input{ mutated.data(), static_cast<uint32_t>(mutated.size()) };
                azihsm_buffer output{ nullptr, 0 };

                // Accept either immediate failure or failure after buffer-size probing.
                auto err = crypt_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &input, &output);
                if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
                {
                    std::vector<uint8_t> candidate(output.len);
                    output.ptr = candidate.data();
                    err =
                        crypt_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &input, &output);
                }

                ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
            };

            // Case 1: invalid PKCS#7 terminal byte (0 is never a valid padding value).
            auto zero_pad = ciphertext;
            zero_pad.back() = 0x00;
            assert_decrypt_fails(std::move(zero_pad));

            if (pad_len > 1)
            {
                // Case 2: break pad-byte consistency while keeping ciphertext block aligned.
                auto inconsistent_pad = ciphertext;
                inconsistent_pad[inconsistent_pad.size() - 2] ^= 0x01;
                assert_decrypt_fails(std::move(inconsistent_pad));
            }
        }
    });
}

// Validates chunked CBC-PAD decrypt still rejects tampered padding regardless of chunk boundaries.
TEST_F(azihsm_aes_cbc, streaming_decrypt_invalid_padding_fails_for_varied_chunks)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x69);

        std::vector<uint8_t> plaintext(31, 0x5B);
        auto ciphertext = single_shot_crypt(
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            CryptOperation::Encrypt
        );

        // Corrupt terminal padding byte so rejection can happen during update or final.
        ciphertext.back() ^= 0xFF;

        std::vector<size_t> chunk_sizes = { 1, 7, 16, 31 };
        for (auto chunk_size : chunk_sizes)
        {
            SCOPED_TRACE("chunk_size=" + std::to_string(chunk_size));
            init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x69);

            azihsm_handle ctx = 0;
            auto err = crypt_init_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &ctx);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            bool saw_failure = false;
            size_t offset = 0;
            while (offset < ciphertext.size())
            {
                // Feed mutated ciphertext in variable chunk boundaries to exercise stream parser paths.
                size_t current_chunk = std::min(chunk_size, ciphertext.size() - offset);
                azihsm_buffer input{
                    ciphertext.data() + offset,
                    static_cast<uint32_t>(current_chunk),
                };
                azihsm_buffer output{ nullptr, 0 };

                err = crypt_update_call(CryptOperation::Decrypt, ctx, &input, &output);
                if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
                {
                    std::vector<uint8_t> out_buf(output.len);
                    output.ptr = out_buf.data();
                    err = crypt_update_call(CryptOperation::Decrypt, ctx, &input, &output);
                }

                if (err != AZIHSM_STATUS_SUCCESS)
                {
                    saw_failure = true;
                    break;
                }

                offset += current_chunk;
            }

            if (!saw_failure)
            {
                // If update accepted all chunks, final must still reject invalid PKCS#7 state.
                azihsm_buffer final_out{ nullptr, 0 };
                err = crypt_final_call(CryptOperation::Decrypt, ctx, &final_out);
                if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
                {
                    std::vector<uint8_t> out_buf(final_out.len);
                    final_out.ptr = out_buf.data();
                    err = crypt_final_call(CryptOperation::Decrypt, ctx, &final_out);
                }

                ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
            }
        }
    });
}

// Verifies zero-length update is a no-op for CBC-PAD and output is emitted only at final.
TEST_F(azihsm_aes_cbc, streaming_zero_length_update_with_padding_is_noop_until_final)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x6A);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t dummy = 0x00;
        azihsm_buffer empty_input{ &dummy, 0 };
        azihsm_buffer update_out{ nullptr, 0 };
        err = crypt_update_call(CryptOperation::Encrypt, ctx, &empty_input, &update_out);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(update_out.len, 0u);

        azihsm_buffer final_out{ nullptr, 0 };
        err = crypt_final_call(CryptOperation::Encrypt, ctx, &final_out);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(final_out.len, AES_BLOCK_SIZE);

        std::vector<uint8_t> final_buf(final_out.len);
        final_out.ptr = final_buf.data();
        err = crypt_final_call(CryptOperation::Encrypt, ctx, &final_out);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(final_out.len, AES_BLOCK_SIZE);
    });
}

// Ensures streaming APIs consistently reject obviously invalid context handles.
TEST_F(azihsm_aes_cbc, streaming_invalid_context_handles_are_rejected)
{
    uint8_t data[AES_BLOCK_SIZE] = { 0x11 };
    azihsm_buffer input{ data, sizeof(data) };
    azihsm_buffer output{ nullptr, 0 };

    auto err = crypt_update_call(CryptOperation::Encrypt, 0xDEADBEEF, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = crypt_update_call(CryptOperation::Decrypt, 0xDEADBEEF, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = crypt_final_call(CryptOperation::Encrypt, 0xDEADBEEF, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = crypt_final_call(CryptOperation::Decrypt, 0xDEADBEEF, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

// Verifies context state is terminal after final, so further update/final calls fail.
TEST_F(azihsm_aes_cbc, streaming_use_after_final_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x78);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer output{ nullptr, 0 };
        err = crypt_final_call(CryptOperation::Encrypt, ctx, &output);
        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            std::vector<uint8_t> out_buf(output.len);
            output.ptr = out_buf.data();
            err = crypt_final_call(CryptOperation::Encrypt, ctx, &output);
        }
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t data[AES_BLOCK_SIZE] = { 0x33 };
        azihsm_buffer input{ data, sizeof(data) };
        azihsm_buffer after_final_output{ nullptr, 0 };

        err = crypt_update_call(CryptOperation::Encrypt, ctx, &input, &after_final_output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);

        err = crypt_final_call(CryptOperation::Encrypt, ctx, &after_final_output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Verifies an encrypt-initialized context cannot be used through decrypt update/final APIs.
TEST_F(azihsm_aes_cbc, streaming_operation_mismatch_on_context_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x79);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t data[AES_BLOCK_SIZE] = { 0x41 };
        azihsm_buffer input{ data, sizeof(data) };
        azihsm_buffer output{ nullptr, 0 };

        err = crypt_update_call(CryptOperation::Decrypt, ctx, &input, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);

        err = crypt_final_call(CryptOperation::Decrypt, ctx, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);

        err = crypt_final_call(CryptOperation::Encrypt, ctx, &output);
        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            std::vector<uint8_t> out_buf(output.len);
            output.ptr = out_buf.data();
            err = crypt_final_call(CryptOperation::Encrypt, ctx, &output);
        }
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Checks PKCS#7 behavior in streaming mode: final without update emits one full padding block.
TEST_F(azihsm_aes_cbc, streaming_encrypt_final_without_update_with_padding_outputs_padding_block)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x7A);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer output{ nullptr, 0 };
        err = crypt_final_call(CryptOperation::Encrypt, ctx, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(output.len, AES_BLOCK_SIZE);

        std::vector<uint8_t> out_buf(output.len);
        output.ptr = out_buf.data();
        err = crypt_final_call(CryptOperation::Encrypt, ctx, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(output.len, AES_BLOCK_SIZE);
    });
}

// Validates update() output-buffer contract for no-padding mode (query/too-small/exact-size).
TEST_F(azihsm_aes_cbc, streaming_update_output_buffer_contract_no_padding)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC, 0x7B);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t data[AES_BLOCK_SIZE] = { 0x22 };
        azihsm_buffer input{ data, sizeof(data) };
        azihsm_buffer output{ nullptr, 0 };

        err = crypt_update_call(CryptOperation::Encrypt, ctx, &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(output.len, AES_BLOCK_SIZE);

        std::vector<uint8_t> too_small(AES_BLOCK_SIZE - 1);
        azihsm_buffer short_output{ too_small.data(), static_cast<uint32_t>(too_small.size()) };
        err = crypt_update_call(CryptOperation::Encrypt, ctx, &input, &short_output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(short_output.len, AES_BLOCK_SIZE);

        std::vector<uint8_t> exact(AES_BLOCK_SIZE);
        azihsm_buffer exact_output{ exact.data(), static_cast<uint32_t>(exact.size()) };
        err = crypt_update_call(CryptOperation::Encrypt, ctx, &input, &exact_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(exact_output.len, AES_BLOCK_SIZE);

        azihsm_buffer final_output{ nullptr, 0 };
        err = crypt_final_call(CryptOperation::Encrypt, ctx, &final_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(final_output.len, 0u);
    });
}

// Validates final() output-buffer contract for padding mode (query/too-small/exact-size).
TEST_F(azihsm_aes_cbc, streaming_final_output_buffer_contract_with_padding)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 128);

        azihsm_algo_aes_cbc_params cbc_params{};
        azihsm_algo crypt_algo{};
        init_cbc_algo(crypt_algo, cbc_params, AZIHSM_ALGO_ID_AES_CBC_PAD, 0x7C);

        azihsm_handle ctx = 0;
        auto err = crypt_init_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer final_out{ nullptr, 0 };
        err = crypt_final_call(CryptOperation::Encrypt, ctx, &final_out);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(final_out.len, AES_BLOCK_SIZE);

        std::vector<uint8_t> too_small(AES_BLOCK_SIZE - 1);
        azihsm_buffer short_out{ too_small.data(), static_cast<uint32_t>(too_small.size()) };
        err = crypt_final_call(CryptOperation::Encrypt, ctx, &short_out);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(short_out.len, AES_BLOCK_SIZE);

        std::vector<uint8_t> exact(AES_BLOCK_SIZE);
        azihsm_buffer exact_out{ exact.data(), static_cast<uint32_t>(exact.size()) };
        err = crypt_final_call(CryptOperation::Encrypt, ctx, &exact_out);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(exact_out.len, AES_BLOCK_SIZE);
    });
}

TEST_F(azihsm_aes_cbc, single_shot_padding_size_sweep)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        for (size_t plaintext_len = 0; plaintext_len <= 64; ++plaintext_len)
        {
            std::vector<uint8_t> plaintext(plaintext_len, 0x5A);

            uint8_t iv[AES_BLOCK_SIZE] = { 0x89 };
            azihsm_algo_aes_cbc_params cbc_params{};
            std::memcpy(cbc_params.iv, iv, sizeof(iv));

            azihsm_algo crypt_algo{};
            crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC_PAD;
            crypt_algo.params = &cbc_params;
            crypt_algo.len = sizeof(cbc_params);

            auto ciphertext = single_shot_crypt(
                key.get(),
                &crypt_algo,
                plaintext.data(),
                plaintext.size(),
                CryptOperation::Encrypt
            );
            ASSERT_EQ(ciphertext.size(), padded_ciphertext_len(plaintext_len));

            std::memcpy(cbc_params.iv, iv, sizeof(iv));
            auto decrypted = single_shot_crypt(
                key.get(),
                &crypt_algo,
                ciphertext.data(),
                ciphertext.size(),
                CryptOperation::Decrypt
            );
            ASSERT_EQ(decrypted.size(), plaintext.size());
            ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
        }
    });
}

TEST_F(azihsm_aes_cbc, streaming_padding_size_and_chunk_sweep)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_key(session, 256);

        std::vector<size_t> sizes;
        for (size_t value = 0; value <= 32; ++value)
        {
            sizes.push_back(value);
        }
        sizes.push_back(63);
        sizes.push_back(64);
        sizes.push_back(65);
        sizes.push_back(127);
        sizes.push_back(128);
        sizes.push_back(129);

        std::vector<size_t> chunk_sizes = { 1, 2, 3, 5, 7, 8, 15, 16, 17, 31, 32, 33, 64, 256 };

        for (auto plaintext_len : sizes)
        {
            std::vector<uint8_t> plaintext(plaintext_len);
            for (size_t i = 0; i < plaintext_len; ++i)
            {
                plaintext[i] = static_cast<uint8_t>(i & 0xFF);
            }

            for (auto chunk_size : chunk_sizes)
            {
                SCOPED_TRACE(
                    "plaintext_len=" + std::to_string(plaintext_len) +
                    " chunk_size=" + std::to_string(chunk_size)
                );

                test_streaming_roundtrip(
                    key.get(),
                    AZIHSM_ALGO_ID_AES_CBC_PAD,
                    plaintext.data(),
                    plaintext.size(),
                    chunk_size,
                    padded_ciphertext_len(plaintext_len)
                );
            }
        }
    });
}