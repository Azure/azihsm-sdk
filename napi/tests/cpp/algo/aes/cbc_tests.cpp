// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include <vector>

#include "handle/key_handle.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"

class azihsm_aes_cbc : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Helper function for single-shot encryption/decryption
    static std::vector<uint8_t> single_shot_crypt(azihsm_handle key_handle, azihsm_algo *algo,
                                                  const uint8_t *input_data, size_t input_len, bool encrypt)
    {
        azihsm_buffer input{const_cast<uint8_t *>(input_data), static_cast<uint32_t>(input_len)};
        azihsm_buffer output{nullptr, 0};
        azihsm_error err;

        // Query required buffer size
        if (encrypt)
        {
            err = azihsm_crypt_encrypt(algo, key_handle, &input, &output);
        }
        else
        {
            err = azihsm_crypt_decrypt(algo, key_handle, &input, &output);
        }
        EXPECT_EQ(err, AZIHSM_ERROR_BUFFER_TOO_SMALL);
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
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Resize to actual bytes written
        result.resize(output.len);
        return result;
    }

    // Helper function for streaming encryption/decryption
    static std::vector<uint8_t> streaming_crypt(azihsm_handle key_handle, azihsm_algo *algo, const uint8_t *input_data,
                                                size_t input_len, size_t chunk_size, bool encrypt)
    {
        azihsm_handle ctx = 0;
        azihsm_error err;

        // Initialize context
        if (encrypt)
        {
            err = azihsm_crypt_encrypt_init(algo, key_handle, &ctx);
        }
        else
        {
            err = azihsm_crypt_decrypt_init(algo, key_handle, &ctx);
        }
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
        EXPECT_NE(ctx, 0);

        std::vector<uint8_t> output;
        size_t offset = 0;

        // Process in chunks
        while (offset < input_len)
        {
            size_t current_chunk = std::min(chunk_size, input_len - offset);
            azihsm_buffer input{const_cast<uint8_t *>(input_data + offset), static_cast<uint32_t>(current_chunk)};
            azihsm_buffer out_buf{nullptr, 0};

            if (encrypt)
            {
                err = azihsm_crypt_encrypt_update(ctx, &input, &out_buf);
            }
            else
            {
                err = azihsm_crypt_decrypt_update(ctx, &input, &out_buf);
            }

            if (err == AZIHSM_ERROR_BUFFER_TOO_SMALL)
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
                EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
                // Adjust output size to actual bytes written
                output.resize(current_pos + out_buf.len);
            }
            else if (err == AZIHSM_ERROR_SUCCESS)
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
        azihsm_buffer final_out{nullptr, 0};
        if (encrypt)
        {
            err = azihsm_crypt_encrypt_final(ctx, &final_out);
        }
        else
        {
            err = azihsm_crypt_decrypt_final(ctx, &final_out);
        }

        if (err == AZIHSM_ERROR_BUFFER_TOO_SMALL)
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
            EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
            // Adjust output size to actual bytes written
            output.resize(current_pos + final_out.len);
        }

        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

        return output;
    }
};

TEST_F(azihsm_aes_cbc, encrypt_decrypt_128)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        // Open partition and create session
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate AES-128 key
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        KeyProps key_props;
        key_props.key_kind = 3;  // AZIHSM_KEY_KIND_AES
        key_props.key_class = 1; // AZIHSM_KEY_CLASS_SECRET
        key_props.bits = 128;
        key_props.is_session = true;
        key_props.can_encrypt = true;
        key_props.can_decrypt = true;

        auto key = KeyHandle(session.get(), &keygen_algo, key_props);

        // Setup encryption algorithm (AES-CBC with padding)
        uint8_t iv[16] = {0xCC};
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC;
        crypt_algo.params = &cbc_params;
        crypt_algo.len = sizeof(cbc_params);

        // Test data
        uint8_t plaintext[16] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67,
                                 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x20, 0x30, 0x40};

        // Encrypt using helper
        auto ciphertext = single_shot_crypt(key.get(), &crypt_algo, plaintext, sizeof(plaintext), true);
        ASSERT_EQ(ciphertext.size(), sizeof(plaintext));

        // Reset IV for decryption
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        // Decrypt using helper
        auto decrypted = single_shot_crypt(key.get(), &crypt_algo, ciphertext.data(), ciphertext.size(), false);

        ASSERT_EQ(decrypted.size(), sizeof(plaintext));
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, sizeof(plaintext)), 0);
    });
}

TEST_F(azihsm_aes_cbc, encrypt_decrypt_128_with_padding)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        // Open partition and create session
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate AES-128 key
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        KeyProps key_props;
        key_props.key_kind = 3;  // AZIHSM_KEY_KIND_AES
        key_props.key_class = 1; // AZIHSM_KEY_CLASS_SECRET
        key_props.bits = 128;
        key_props.is_session = true;
        key_props.can_encrypt = true;
        key_props.can_decrypt = true;

        auto key = KeyHandle(session.get(), &keygen_algo, key_props);

        // Setup encryption algorithm (AES-CBC with padding)
        uint8_t iv[16] = {0xCC};
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_CBC_PAD;
        crypt_algo.params = &cbc_params;
        crypt_algo.len = sizeof(cbc_params);

        // Test data - non-block-aligned size (13 bytes) to test padding
        uint8_t plaintext[13] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10};

        // Encrypt using helper
        auto ciphertext = single_shot_crypt(key.get(), &crypt_algo, plaintext, sizeof(plaintext), true);
        // With padding, output should be padded to block size (16 bytes)
        ASSERT_EQ(ciphertext.size(), 16);

        // Reset IV for decryption
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        // Decrypt using helper
        auto decrypted = single_shot_crypt(key.get(), &crypt_algo, ciphertext.data(), ciphertext.size(), false);

        // Verify decrypted matches original (padding should be removed)
        ASSERT_EQ(decrypted.size(), sizeof(plaintext));
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, sizeof(plaintext)), 0);
    });
}

TEST_F(azihsm_aes_cbc, streaming_encrypt_decrypt_no_padding)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        // Open partition and create session
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate AES-128 key
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        KeyProps key_props;
        key_props.key_kind = 3;  // AZIHSM_KEY_KIND_AES
        key_props.key_class = 1; // AZIHSM_KEY_CLASS_SECRET
        key_props.bits = 128;
        key_props.is_session = true;
        key_props.can_encrypt = true;
        key_props.can_decrypt = true;

        auto key = KeyHandle(session.get(), &keygen_algo, key_props);

        // Setup encryption algorithm (AES-CBC without padding)
        uint8_t iv[16] = {0xAA};
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        azihsm_algo encrypt_algo{};
        encrypt_algo.id = AZIHSM_ALGO_ID_AES_CBC;
        encrypt_algo.params = &cbc_params;
        encrypt_algo.len = sizeof(cbc_params);

        // Test data - block-aligned (32 bytes = 2 blocks)
        uint8_t plaintext[32] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
                                 0xEF, 0x10, 0x20, 0x30, 0x40, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
        size_t plaintext_len = sizeof(plaintext);

        // Encrypt using helper
        auto ciphertext = streaming_crypt(key.get(), &encrypt_algo, plaintext, plaintext_len, 16, true);
        ASSERT_EQ(ciphertext.size(), plaintext_len);

        // Reset IV for decryption
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        // Decrypt using helper
        auto decrypted = streaming_crypt(key.get(), &encrypt_algo, ciphertext.data(), ciphertext.size(), 16, false);

        // Verify decrypted matches original
        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, plaintext_len), 0);
    });
}

TEST_F(azihsm_aes_cbc, streaming_encrypt_decrypt_with_padding)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        // Open partition and create session
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate AES-128 key
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        KeyProps key_props;
        key_props.key_kind = 3;  // AZIHSM_KEY_KIND_AES
        key_props.key_class = 1; // AZIHSM_KEY_CLASS_SECRET
        key_props.bits = 128;
        key_props.is_session = true;
        key_props.can_encrypt = true;
        key_props.can_decrypt = true;

        auto key = KeyHandle(session.get(), &keygen_algo, key_props);

        // Setup encryption algorithm (AES-CBC with padding)
        uint8_t iv[16] = {0xBB};
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        azihsm_algo encrypt_algo{};
        encrypt_algo.id = AZIHSM_ALGO_ID_AES_CBC_PAD;
        encrypt_algo.params = &cbc_params;
        encrypt_algo.len = sizeof(cbc_params);

        // Test data - non-block-aligned size (27 bytes) to test padding
        uint8_t plaintext[27] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x20,
                                 0x30, 0x40, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
        size_t plaintext_len = sizeof(plaintext);

        // Encrypt using helper with 10-byte chunks
        auto ciphertext = streaming_crypt(key.get(), &encrypt_algo, plaintext, plaintext_len, 10, true);
        // With padding, ciphertext should be padded to block size (32 bytes)
        ASSERT_EQ(ciphertext.size(), 32);

        // Reset IV for decryption
        std::memcpy(cbc_params.iv, iv, sizeof(iv));

        // Decrypt using helper
        auto decrypted = streaming_crypt(key.get(), &encrypt_algo, ciphertext.data(), ciphertext.size(), 10, false);

        // Verify decrypted matches original (padding should be removed)
        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, plaintext_len), 0);
    });
}