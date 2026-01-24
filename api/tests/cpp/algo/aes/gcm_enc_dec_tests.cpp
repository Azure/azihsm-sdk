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
#include <functional>

class azihsm_aes_gcm : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Helper function for single-shot encryption
    static std::vector<uint8_t> single_shot_encrypt(
        azihsm_handle key_handle,
        azihsm_algo *algo,
        const uint8_t *input_data,
        size_t input_len,
        azihsm_algo_aes_gcm_params *params
    )
    {
        azihsm_buffer input{ const_cast<uint8_t *>(input_data), static_cast<uint32_t>(input_len) };
        azihsm_buffer output{ nullptr, 0 };

        // Query required buffer size
        auto err = azihsm_crypt_encrypt(algo, key_handle, &input, &output);
        EXPECT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        EXPECT_GT(output.len, 0);

        // Allocate buffer and perform operation
        std::vector<uint8_t> result(output.len);
        output.ptr = result.data();

        err = azihsm_crypt_encrypt(algo, key_handle, &input, &output);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Resize to actual bytes written
        result.resize(output.len);
        return result;
    }

    // Helper function for single-shot decryption
    static std::vector<uint8_t> single_shot_decrypt(
        azihsm_handle key_handle,
        azihsm_algo *algo,
        const uint8_t *input_data,
        size_t input_len
    )
    {
        azihsm_buffer input{ const_cast<uint8_t *>(input_data), static_cast<uint32_t>(input_len) };
        azihsm_buffer output{ nullptr, 0 };

        // Query required buffer size
        auto err = azihsm_crypt_decrypt(algo, key_handle, &input, &output);
        EXPECT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        EXPECT_GT(output.len, 0);

        // Allocate buffer and perform operation
        std::vector<uint8_t> result(output.len);
        output.ptr = result.data();

        err = azihsm_crypt_decrypt(algo, key_handle, &input, &output);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Resize to actual bytes written
        result.resize(output.len);
        return result;
    }

    // Helper function for streaming encryption
    static std::vector<uint8_t> streaming_encrypt(
        azihsm_handle key_handle,
        azihsm_algo *algo,
        const uint8_t *input_data,
        size_t input_len,
        size_t chunk_size
    )
    {
        azihsm_handle ctx = 0;
        azihsm_status err;

        // Initialize context
        err = azihsm_crypt_encrypt_init(algo, key_handle, &ctx);
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

            err = azihsm_crypt_encrypt_update(ctx, &input, &out_buf);

            if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
            {
                // Buffer too small, allocate and retry with same input
                EXPECT_GT(out_buf.len, 0);
                size_t current_pos = output.size();
                output.resize(current_pos + out_buf.len);
                out_buf.ptr = output.data() + current_pos;

                err = azihsm_crypt_encrypt_update(ctx, &input, &out_buf);
                EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
                // Adjust output size to actual bytes written
                output.resize(current_pos + out_buf.len);
            }
            else if (err == AZIHSM_STATUS_SUCCESS)
            {
                // Success - data may or may not have been produced
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
        err = azihsm_crypt_encrypt_final(ctx, &final_out);

        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            EXPECT_GT(final_out.len, 0);
            size_t current_pos = output.size();
            output.resize(current_pos + final_out.len);
            final_out.ptr = output.data() + current_pos;

            err = azihsm_crypt_encrypt_final(ctx, &final_out);
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

    // Helper function for streaming decryption
    static std::vector<uint8_t> streaming_decrypt(
        azihsm_handle key_handle,
        azihsm_algo *algo,
        const uint8_t *input_data,
        size_t input_len,
        size_t chunk_size
    )
    {
        azihsm_handle ctx = 0;
        azihsm_status err;

        // Initialize context
        err = azihsm_crypt_decrypt_init(algo, key_handle, &ctx);
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

            err = azihsm_crypt_decrypt_update(ctx, &input, &out_buf);

            if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
            {
                // Buffer too small, allocate and retry with same input
                EXPECT_GT(out_buf.len, 0);
                size_t current_pos = output.size();
                output.resize(current_pos + out_buf.len);
                out_buf.ptr = output.data() + current_pos;

                err = azihsm_crypt_decrypt_update(ctx, &input, &out_buf);
                EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
                // Adjust output size to actual bytes written
                output.resize(current_pos + out_buf.len);
            }
            else if (err == AZIHSM_STATUS_SUCCESS)
            {
                // Success - data may or may not have been produced
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
        err = azihsm_crypt_decrypt_final(ctx, &final_out);

        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            EXPECT_GT(final_out.len, 0);
            size_t current_pos = output.size();
            output.resize(current_pos + final_out.len);
            final_out.ptr = output.data() + current_pos;

            err = azihsm_crypt_decrypt_final(ctx, &final_out);
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

    // Helper to generate AES GCM key
    static KeyHandle generate_aes_gcm_key(azihsm_handle session, uint32_t bits)
    {
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        key_props key_props;
        key_props.key_kind = AZIHSM_KEY_KIND_AES_GCM;
        key_props.key_class = AZIHSM_KEY_CLASS_SECRET;
        key_props.bits = bits;
        key_props.is_session = true;
        key_props.can_encrypt = true;
        key_props.can_decrypt = true;

        return KeyHandle(session, &keygen_algo, key_props);
    }

    // Helper to test single-shot encrypt/decrypt roundtrip
    void test_single_shot_roundtrip(
        azihsm_handle key_handle,
        const uint8_t *plaintext,
        size_t plaintext_len,
        const uint8_t *aad,
        size_t aad_len
    )
    {
        uint8_t iv[12] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                           0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };

        azihsm_buffer aad_buf{};
        if (aad != nullptr && aad_len > 0)
        {
            aad_buf.ptr = const_cast<uint8_t *>(aad);
            aad_buf.len = static_cast<uint32_t>(aad_len);
        }

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = (aad != nullptr && aad_len > 0) ? &aad_buf : nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        // Encrypt
        auto ciphertext =
            single_shot_encrypt(key_handle, &crypt_algo, plaintext, plaintext_len, &gcm_params);

        // Ciphertext should be same length as plaintext for GCM (no padding)
        ASSERT_EQ(ciphertext.size(), plaintext_len);

        // Save the tag from encryption for decryption
        uint8_t saved_tag[16];
        std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));

        // Reset IV and set tag for decryption
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

        // Decrypt
        auto decrypted =
            single_shot_decrypt(key_handle, &crypt_algo, ciphertext.data(), ciphertext.size());

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, plaintext_len), 0);
    }

    // Helper to test streaming encrypt/decrypt roundtrip
    void test_streaming_roundtrip(
        azihsm_handle key_handle,
        const uint8_t *plaintext,
        size_t plaintext_len,
        size_t chunk_size,
        const uint8_t *aad,
        size_t aad_len
    )
    {
        uint8_t iv[12] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                           0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

        azihsm_buffer aad_buf{};
        if (aad != nullptr && aad_len > 0)
        {
            aad_buf.ptr = const_cast<uint8_t *>(aad);
            aad_buf.len = static_cast<uint32_t>(aad_len);
        }

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = (aad != nullptr && aad_len > 0) ? &aad_buf : nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        // Encrypt
        auto ciphertext =
            streaming_encrypt(key_handle, &crypt_algo, plaintext, plaintext_len, chunk_size);
        ASSERT_EQ(ciphertext.size(), plaintext_len);

        // Save the tag from encryption for decryption
        uint8_t saved_tag[16];
        std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));

        // Reset IV and set tag for decryption
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

        // Decrypt
        auto decrypted = streaming_decrypt(
            key_handle,
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            chunk_size
        );

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, plaintext_len), 0);
    }
};

// Test data structures
struct AesGcmKeyTestParams
{
    uint32_t bits;
    const char *test_name;
};

struct AesGcmDataSizeTestParams
{
    size_t data_size;
    const char *test_name;
};

// ==================== Single-Shot Tests ====================

TEST_F(azihsm_aes_gcm, single_shot_all_key_sizes_no_aad)
{
    // Note: AES-GCM only supports 256-bit keys in this implementation
    std::vector<AesGcmKeyTestParams> key_sizes = {
        { 256, "AES-256" },
    };

    std::vector<AesGcmDataSizeTestParams> data_sizes = {
        { 16, "16_bytes" },
        { 32, "32_bytes" },
        { 64, "64_bytes" },
        { 100, "100_bytes" },
    };

    for (const auto &key_param : key_sizes)
    {
        for (const auto &data_param : data_sizes)
        {
            SCOPED_TRACE(
                std::string(key_param.test_name) + " no_aad " + data_param.test_name
            );

            part_list_.for_each_session([&](azihsm_handle session) {
                auto key = generate_aes_gcm_key(session, key_param.bits);

                std::vector<uint8_t> plaintext(data_param.data_size, 0xAB);

                test_single_shot_roundtrip(
                    key.get(),
                    plaintext.data(),
                    plaintext.size(),
                    nullptr,
                    0
                );
            });
        }
    }
}

TEST_F(azihsm_aes_gcm, single_shot_all_key_sizes_with_aad)
{
    // Note: AES-GCM only supports 256-bit keys in this implementation
    std::vector<AesGcmKeyTestParams> key_sizes = {
        { 256, "AES-256" },
    };

    std::vector<AesGcmDataSizeTestParams> data_sizes = {
        { 16, "16_bytes" },
        { 32, "32_bytes" },
        { 64, "64_bytes" },
    };

    for (const auto &key_param : key_sizes)
    {
        for (const auto &data_param : data_sizes)
        {
            SCOPED_TRACE(
                std::string(key_param.test_name) + " with_aad " + data_param.test_name
            );

            part_list_.for_each_session([&](azihsm_handle session) {
                auto key = generate_aes_gcm_key(session, key_param.bits);

                std::vector<uint8_t> plaintext(data_param.data_size, 0xCD);
                std::vector<uint8_t> aad = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

                test_single_shot_roundtrip(
                    key.get(),
                    plaintext.data(),
                    plaintext.size(),
                    aad.data(),
                    aad.size()
                );
            });
        }
    }
}

// ==================== Streaming Tests ====================

TEST_F(azihsm_aes_gcm, streaming_all_key_sizes_no_aad)
{
    // Note: AES-GCM only supports 256-bit keys in this implementation
    std::vector<AesGcmKeyTestParams> key_sizes = {
        { 256, "AES-256" },
    };

    for (const auto &key_param : key_sizes)
    {
        SCOPED_TRACE("Testing " + std::string(key_param.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto key = generate_aes_gcm_key(session, key_param.bits);

            std::vector<uint8_t> plaintext(64, 0xEF);

            test_streaming_roundtrip(
                key.get(),
                plaintext.data(),
                plaintext.size(),
                16, // Process in 16-byte chunks
                nullptr,
                0
            );
        });
    }
}

TEST_F(azihsm_aes_gcm, streaming_all_key_sizes_with_aad)
{
    // Note: AES-GCM only supports 256-bit keys in this implementation
    std::vector<AesGcmKeyTestParams> key_sizes = {
        { 256, "AES-256" },
    };

    for (const auto &key_param : key_sizes)
    {
        SCOPED_TRACE("Testing " + std::string(key_param.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto key = generate_aes_gcm_key(session, key_param.bits);

            std::vector<uint8_t> plaintext(64, 0x12);
            std::vector<uint8_t> aad = { 0xAA, 0xBB, 0xCC, 0xDD };

            test_streaming_roundtrip(
                key.get(),
                plaintext.data(),
                plaintext.size(),
                16,
                aad.data(),
                aad.size()
            );
        });
    }
}

TEST_F(azihsm_aes_gcm, streaming_various_chunk_sizes)
{
    std::vector<size_t> chunk_sizes = { 1, 7, 16, 32, 64 };

    for (size_t chunk_size : chunk_sizes)
    {
        SCOPED_TRACE("Testing chunk size " + std::to_string(chunk_size));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto key = generate_aes_gcm_key(session, 256);

            std::vector<uint8_t> plaintext(100, 0x55);

            test_streaming_roundtrip(
                key.get(),
                plaintext.data(),
                plaintext.size(),
                chunk_size,
                nullptr,
                0
            );
        });
    }
}

// ==================== Edge Case Tests ====================

TEST_F(azihsm_aes_gcm, empty_plaintext)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0xFF };
        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        // Encrypt empty data - note: tag is stored separately in gcm_params.tag,
        // so ciphertext output is 0 bytes for empty plaintext
        azihsm_buffer input{ nullptr, 0 };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);

        // For empty input, the API may return success immediately or require buffer size query.
        // In either case, ciphertext length should be 0 (tag is stored in params.tag).
        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            // GCM ciphertext equals plaintext length (tag is separate)
            ASSERT_EQ(output.len, 0u);
            err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        }
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // The authentication tag should have been populated
        bool tag_has_data = false;
        for (size_t i = 0; i < sizeof(gcm_params.tag); ++i)
        {
            if (gcm_params.tag[i] != 0)
            {
                tag_has_data = true;
                break;
            }
        }
        ASSERT_TRUE(tag_has_data) << "Tag should be populated after encryption";

        // Save tag and decrypt
        uint8_t saved_tag[16];
        std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

        azihsm_buffer cipher_buf{ nullptr, 0 };
        azihsm_buffer plain_buf{ nullptr, 0 };

        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_buf, &plain_buf);

        // For empty ciphertext, the API may return success immediately or require buffer size query
        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            ASSERT_EQ(plain_buf.len, 0u);
            err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_buf, &plain_buf);
        }
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_aes_gcm, null_params)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = nullptr; // No parameters provided
        crypt_algo.len = 0;

        uint8_t plaintext[16] = { 0xAA };
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_gcm, invalid_key_handle)
{
    uint8_t iv[12] = { 0xDD };
    azihsm_algo_aes_gcm_params gcm_params{};
    std::memcpy(gcm_params.iv, iv, sizeof(iv));
    std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
    gcm_params.aad = nullptr;

    azihsm_algo crypt_algo{};
    crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
    crypt_algo.params = &gcm_params;
    crypt_algo.len = sizeof(gcm_params);

    uint8_t plaintext[16] = { 0xEE };
    azihsm_buffer input{ plaintext, sizeof(plaintext) };
    azihsm_buffer output{ nullptr, 0 };

    auto err = azihsm_crypt_encrypt(&crypt_algo, 0xDEADBEEF, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST_F(azihsm_aes_gcm, wrong_tag_fails_decryption)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                           0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        // Encrypt
        std::vector<uint8_t> plaintext = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

        std::vector<uint8_t> ciphertext(output.len);
        output.ptr = ciphertext.data();
        err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Corrupt the tag
        gcm_params.tag[0] ^= 0xFF;

        // Reset IV for decryption
        std::memcpy(gcm_params.iv, iv, sizeof(iv));

        // Decrypt with corrupted tag should fail
        azihsm_buffer cipher_buf{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        azihsm_buffer plain_buf{ nullptr, 0 };

        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_buf, &plain_buf);
        // Even the size query might fail or succeed depending on implementation
        // But actual decryption should fail authentication
        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            std::vector<uint8_t> decrypted(plain_buf.len);
            plain_buf.ptr = decrypted.data();
            err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_buf, &plain_buf);
        }
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_aes_gcm, different_ivs_produce_different_ciphertexts)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        std::vector<uint8_t> plaintext = { 0x42, 0x42, 0x42, 0x42 };

        // Encrypt with IV1
        uint8_t iv1[12] = { 0xAA };
        azihsm_algo_aes_gcm_params gcm_params1{};
        std::memcpy(gcm_params1.iv, iv1, sizeof(iv1));
        std::memset(gcm_params1.tag, 0, sizeof(gcm_params1.tag));
        gcm_params1.aad = nullptr;

        azihsm_algo crypt_algo1{};
        crypt_algo1.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo1.params = &gcm_params1;
        crypt_algo1.len = sizeof(gcm_params1);

        azihsm_buffer input1{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        azihsm_buffer output1{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo1, key.get(), &input1, &output1);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

        std::vector<uint8_t> ciphertext1(output1.len);
        output1.ptr = ciphertext1.data();
        err = azihsm_crypt_encrypt(&crypt_algo1, key.get(), &input1, &output1);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Encrypt with IV2
        uint8_t iv2[12] = { 0xBB };
        azihsm_algo_aes_gcm_params gcm_params2{};
        std::memcpy(gcm_params2.iv, iv2, sizeof(iv2));
        std::memset(gcm_params2.tag, 0, sizeof(gcm_params2.tag));
        gcm_params2.aad = nullptr;

        azihsm_algo crypt_algo2{};
        crypt_algo2.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo2.params = &gcm_params2;
        crypt_algo2.len = sizeof(gcm_params2);

        azihsm_buffer input2{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        azihsm_buffer output2{ nullptr, 0 };

        err = azihsm_crypt_encrypt(&crypt_algo2, key.get(), &input2, &output2);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

        std::vector<uint8_t> ciphertext2(output2.len);
        output2.ptr = ciphertext2.data();
        err = azihsm_crypt_encrypt(&crypt_algo2, key.get(), &input2, &output2);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Ciphertexts should be different
        ASSERT_EQ(ciphertext1.size(), ciphertext2.size());
        ASSERT_NE(std::memcmp(ciphertext1.data(), ciphertext2.data(), ciphertext1.size()), 0);
    });
}

TEST_F(azihsm_aes_gcm, large_data_streaming)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x11 };
        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        // Test with larger data (4KB)
        std::vector<uint8_t> plaintext(4096);
        for (size_t i = 0; i < plaintext.size(); ++i)
        {
            plaintext[i] = static_cast<uint8_t>(i & 0xFF);
        }

        // Encrypt
        auto ciphertext =
            streaming_encrypt(key.get(), &crypt_algo, plaintext.data(), plaintext.size(), 256);

        // Save tag for decryption
        uint8_t saved_tag[16];
        std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));

        // Reset IV and set tag for decryption
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

        // Decrypt
        auto decrypted = streaming_decrypt(
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            256
        );

        ASSERT_EQ(decrypted.size(), plaintext.size());
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
    });
}

TEST_F(azihsm_aes_gcm, streaming_consistency_with_single_shot)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0xFF };

        std::vector<uint8_t> plaintext(100, 0x55);

        // Single-shot encrypt
        azihsm_algo_aes_gcm_params gcm_params_single{};
        std::memcpy(gcm_params_single.iv, iv, sizeof(iv));
        std::memset(gcm_params_single.tag, 0, sizeof(gcm_params_single.tag));
        gcm_params_single.aad = nullptr;

        azihsm_algo crypt_algo_single{};
        crypt_algo_single.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo_single.params = &gcm_params_single;
        crypt_algo_single.len = sizeof(gcm_params_single);

        auto single_shot_ciphertext = single_shot_encrypt(
            key.get(),
            &crypt_algo_single,
            plaintext.data(),
            plaintext.size(),
            &gcm_params_single
        );

        // Save tag
        uint8_t single_shot_tag[16];
        std::memcpy(single_shot_tag, gcm_params_single.tag, sizeof(single_shot_tag));

        // Streaming encrypt with same IV
        azihsm_algo_aes_gcm_params gcm_params_streaming{};
        std::memcpy(gcm_params_streaming.iv, iv, sizeof(iv));
        std::memset(gcm_params_streaming.tag, 0, sizeof(gcm_params_streaming.tag));
        gcm_params_streaming.aad = nullptr;

        azihsm_algo crypt_algo_streaming{};
        crypt_algo_streaming.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo_streaming.params = &gcm_params_streaming;
        crypt_algo_streaming.len = sizeof(gcm_params_streaming);

        auto streaming_ciphertext =
            streaming_encrypt(key.get(), &crypt_algo_streaming, plaintext.data(), plaintext.size(), 17);

        // Ciphertexts should be identical
        ASSERT_EQ(single_shot_ciphertext.size(), streaming_ciphertext.size());
        ASSERT_EQ(
            std::memcmp(
                single_shot_ciphertext.data(),
                streaming_ciphertext.data(),
                single_shot_ciphertext.size()
            ),
            0
        );

        // Tags should be identical
        ASSERT_EQ(std::memcmp(single_shot_tag, gcm_params_streaming.tag, 16), 0);
    });
}
