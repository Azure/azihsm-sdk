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
#include <functional>

class azihsm_aes_cbc : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Helper function for single-shot encryption/decryption
    static std::vector<uint8_t> single_shot_crypt(
        azihsm_handle key_handle,
        azihsm_algo *algo,
        const uint8_t *input_data,
        size_t input_len,
        bool encrypt
    )
    {
        azihsm_buffer input{ const_cast<uint8_t *>(input_data), static_cast<uint32_t>(input_len) };
        azihsm_buffer output{ nullptr, 0 };
        azihsm_status err;

        // Query required buffer size
        if (encrypt)
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

        if (encrypt)
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
        bool encrypt
    )
    {
        azihsm_handle ctx = 0;
        azihsm_status err;

        // Initialize context
        if (encrypt)
        {
            err = azihsm_crypt_encrypt_init(algo, key_handle, &ctx);
        }
        else
        {
            err = azihsm_crypt_decrypt_init(algo, key_handle, &ctx);
        }
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_NE(ctx, 0);

        std::vector<uint8_t> output;
        size_t offset = 0;

        // Process in chunks
        while (offset < input_len)
        {
            size_t current_chunk = std::min(chunk_size, input_len - offset);
            azihsm_buffer input{ const_cast<uint8_t *>(input_data + offset),
                                 static_cast<uint32_t>(current_chunk) };
            azihsm_buffer out_buf{ nullptr, 0 };

            if (encrypt)
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

                if (encrypt)
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

        // Finalize
        azihsm_buffer final_out{ nullptr, 0 };
        if (encrypt)
        {
            err = azihsm_crypt_encrypt_final(ctx, &final_out);
        }
        else
        {
            err = azihsm_crypt_decrypt_final(ctx, &final_out);
        }

        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            EXPECT_GT(final_out.len, 0);
            size_t current_pos = output.size();
            output.resize(current_pos + final_out.len);
            final_out.ptr = output.data() + current_pos;

            if (encrypt)
            {
                err = azihsm_crypt_encrypt_final(ctx, &final_out);
            }
            else
            {
                err = azihsm_crypt_decrypt_final(ctx, &final_out);
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
        auto ciphertext =
            single_shot_crypt(key_handle, &crypt_algo, plaintext, plaintext_len, true);
        ASSERT_EQ(ciphertext.size(), expected_ciphertext_len);

        // Reset IV for decryption
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        // Decrypt
        auto decrypted =
            single_shot_crypt(key_handle, &crypt_algo, ciphertext.data(), ciphertext.size(), false);

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
        auto ciphertext =
            streaming_crypt(key_handle, &crypt_algo, plaintext, plaintext_len, chunk_size, true);
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
            false
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
        auto single_shot_ciphertext =
            single_shot_crypt(key.get(), &crypt_algo, plaintext.data(), plaintext.size(), true);

        // Reset IV for streaming
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        // Streaming encrypt
        auto streaming_ciphertext =
            streaming_crypt(key.get(), &crypt_algo, plaintext.data(), plaintext.size(), 17, true);

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
        auto ciphertext =
            streaming_crypt(key.get(), &crypt_algo, plaintext.data(), plaintext.size(), 256, true);

        // Reset IV for decryption
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        // Decrypt
        auto decrypted = streaming_crypt(
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            256,
            false
        );

        ASSERT_EQ(decrypted.size(), plaintext.size());
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
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

        auto ciphertext1 =
            single_shot_crypt(key.get(), &crypt_algo1, plaintext, sizeof(plaintext), true);

        // Encrypt with IV2
        uint8_t iv2[16] = { 0xBB };
        azihsm_algo_aes_cbc_params cbc_params2{};
        std::memcpy(cbc_params2.iv, iv2, sizeof(iv2));

        azihsm_algo crypt_algo2{};
        crypt_algo2.id = AZIHSM_ALGO_ID_AES_CBC;
        crypt_algo2.params = &cbc_params2;
        crypt_algo2.len = sizeof(cbc_params2);

        auto ciphertext2 =
            single_shot_crypt(key.get(), &crypt_algo2, plaintext, sizeof(plaintext), true);

        // Ciphertexts should be different
        ASSERT_EQ(ciphertext1.size(), ciphertext2.size());
        ASSERT_NE(std::memcmp(ciphertext1.data(), ciphertext2.data(), ciphertext1.size()), 0);
    });
}