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

class azihsm_aes_xts : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Helper function for single-shot AES XTS encryption/decryption
    static std::vector<uint8_t> single_shot_xts_crypt(
        azihsm_handle key_handle,
        azihsm_algo *algo,
        const uint8_t *input_data,
        size_t input_len,
        bool encrypt
    ){
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

    // Helper function for streaming AES XTS encryption/decryption
    static std::vector<uint8_t> streaming_xts_crypt(
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

    // Helper to test streaming encrypt/decrypt roundtrip
    void test_xts_streaming_roundtrip(
        azihsm_handle key_handle,
        azihsm_algo_id algo_id,
        const uint8_t *plaintext,
        size_t plaintext_len,
        size_t dul,
        size_t chunk_size,
        size_t expected_ciphertext_len
    )
    {
        uint8_t sector_num[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        xts_params.dul = static_cast<uint32_t>(dul);

        azihsm_algo crypt_algo{};
        crypt_algo.id = algo_id;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        // Encrypt with streaming
        auto ciphertext =
            streaming_xts_crypt(key_handle, &crypt_algo, plaintext, plaintext_len, chunk_size, true);
        ASSERT_EQ(ciphertext.size(), expected_ciphertext_len);

        // Reset sector number for decryption
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));

        // Decrypt with streaming
        auto decrypted =
            streaming_xts_crypt(key_handle, &crypt_algo, ciphertext.data(), ciphertext.size(), chunk_size, false);

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, plaintext_len), 0);
    }

    // Helper to test single-shot encrypt/decrypt roundtrip
    void test_xts_single_shot_roundtrip(
        azihsm_handle key_handle,
        azihsm_algo_id algo_id,
        const uint8_t *plaintext,
        size_t plaintext_len,
        size_t expected_ciphertext_len
    )
    {
        uint8_t sector_num[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        xts_params.dul = static_cast<uint32_t>(plaintext_len);

        azihsm_algo crypt_algo{};
        crypt_algo.id = algo_id;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        // Encrypt
        auto ciphertext =
            single_shot_xts_crypt(key_handle, &crypt_algo, plaintext, plaintext_len, true);
        ASSERT_EQ(ciphertext.size(), expected_ciphertext_len);

        // Reset IV for decryption
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));

        // Decrypt
        auto decrypted =
            single_shot_xts_crypt(key_handle, &crypt_algo, ciphertext.data(), ciphertext.size(), false);

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, plaintext_len), 0);
    }

    // Helper to generate AES-XTS key
    static KeyHandle generate_aes_xts_key(azihsm_handle session)
    {
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        key_props props;
        props.key_kind = AZIHSM_KEY_KIND_AES_XTS;
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.bits = 512;  // AES-256 XTS requires 512 bits
        props.is_session = true;
        props.can_encrypt = true;
        props.can_decrypt = true;

        return KeyHandle(session, &keygen_algo, props);
    }
};

// Test: verify we can generate an XTS key (manual API calls)
TEST_F(azihsm_aes_xts, GenerateXtsKey)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES_XTS;
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t bits = 512;
        uint8_t is_session = 1;
        uint8_t can_encrypt = 1;
        uint8_t can_decrypt = 1;

        std::vector<azihsm_key_prop> props_vec = {
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) },
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) },
            { .id = AZIHSM_KEY_PROP_ID_SESSION, .val = &is_session, .len = sizeof(is_session) },
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) },
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &can_decrypt, .len = sizeof(can_decrypt) }
        };

        azihsm_key_prop_list prop_list{
            .props = props_vec.data(),
            .count = static_cast<uint32_t>(props_vec.size())
        };

        azihsm_handle key_handle = 0;
        azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, &key_handle);
        
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS) << "Key generation failed with error: " << err;
        ASSERT_NE(key_handle, 0);

        auto cleanup = scope_guard::make_scope_exit([key_handle] {
            if (key_handle != 0) {
                azihsm_key_delete(key_handle);
            }
        });
    });
}

// Test: simple encrypt/decrypt roundtrip with AES-XTS
TEST_F(azihsm_aes_xts, EncryptDecryptRoundtrip)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        // Generate AES-XTS key
        KeyHandle key = generate_aes_xts_key(session);
        ASSERT_NE(key.get(), 0);

        // Test with 512 bytes of plaintext (must be >= 16 bytes for XTS)
        const size_t plaintext_len = 512;
        std::vector<uint8_t> plaintext(plaintext_len);
        for (size_t i = 0; i < plaintext_len; i++) {
            plaintext[i] = static_cast<uint8_t>(i & 0xFF);
        }

        // Perform encrypt/decrypt roundtrip
        test_xts_single_shot_roundtrip(
            key.get(),
            AZIHSM_ALGO_ID_AES_XTS,
            plaintext.data(),
            plaintext_len,
            plaintext_len  // XTS doesn't add padding
        );
    });
}

// Test: streaming encryption with exact 16-byte chunks
TEST_F(azihsm_aes_xts, streaming_exact_blocks)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session);

        // 512 bytes of plaintext (DUL = 512)
        std::vector<uint8_t> plaintext(512);
        for (size_t i = 0; i < plaintext.size(); i++) {
            plaintext[i] = static_cast<uint8_t>(i & 0xFF);
        }

        // XTS requires chunks to be multiples of DUL
        // Process the entire 512 bytes as one data unit
        test_xts_streaming_roundtrip(
            key.get(),
            AZIHSM_ALGO_ID_AES_XTS,
            plaintext.data(),
            plaintext.size(),
            512,  // DUL = 512 bytes
            512,  // Chunk size = 1 DUL
            plaintext.size()
        );
    });
}

// Test: streaming encryption with multiple data units
TEST_F(azihsm_aes_xts, streaming_multiple_data_units)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session);

        // 1024 bytes total, DUL = 256, so 4 data units
        std::vector<uint8_t> plaintext(1024);
        for (size_t i = 0; i < plaintext.size(); i++) {
            plaintext[i] = static_cast<uint8_t>((i * 3) & 0xFF);
        }

        // Process 2 data units at a time (256 * 2 = 512 bytes per chunk)
        test_xts_streaming_roundtrip(
            key.get(),
            AZIHSM_ALGO_ID_AES_XTS,
            plaintext.data(),
            plaintext.size(),
            256,  // DUL = 256 bytes
            512,  // Chunk size = 2 DULs (256 * 2)
            plaintext.size()
        );
    });
}

// Test: streaming encryption processing one data unit at a time
TEST_F(azihsm_aes_xts, streaming_single_data_unit_chunks)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session);

        // 512 bytes total, DUL = 128, so 4 data units
        std::vector<uint8_t> plaintext(512);
        for (size_t i = 0; i < plaintext.size(); i++) {
            plaintext[i] = static_cast<uint8_t>((i * 7) & 0xFF);
        }

        // Process one data unit at a time (128 bytes per chunk)
        test_xts_streaming_roundtrip(
            key.get(),
            AZIHSM_ALGO_ID_AES_XTS,
            plaintext.data(),
            plaintext.size(),
            128,  // DUL = 128 bytes
            128,  // Chunk size = 1 DUL
            plaintext.size()
        );
    });
}

// Test: single-shot encrypt, streaming decrypt
TEST_F(azihsm_aes_xts, single_shot_encrypt_streaming_decrypt)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session);

        const size_t plaintext_len = 512;
        const size_t dul = 128;  // Same DUL for both operations
        std::vector<uint8_t> plaintext(plaintext_len);
        for (size_t i = 0; i < plaintext_len; i++) {
            plaintext[i] = static_cast<uint8_t>(i & 0xFF);
        }

        // Encrypt with single-shot (DUL = 128)
        uint8_t sector_num[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        xts_params.dul = static_cast<uint32_t>(dul);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        auto ciphertext = single_shot_xts_crypt(key.get(), &crypt_algo, plaintext.data(), plaintext_len, true);
        ASSERT_EQ(ciphertext.size(), plaintext_len);

        // Decrypt with streaming (same DUL = 128)
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        xts_params.dul = static_cast<uint32_t>(dul);

        auto decrypted = streaming_xts_crypt(key.get(), &crypt_algo, ciphertext.data(), ciphertext.size(), dul, false);

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext_len), 0);
    });
}

// Test: streaming encrypt, single-shot decrypt
TEST_F(azihsm_aes_xts, streaming_encrypt_single_shot_decrypt)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session);

        const size_t plaintext_len = 512;
        const size_t dul = 128;  // Same DUL for both operations
        std::vector<uint8_t> plaintext(plaintext_len);
        for (size_t i = 0; i < plaintext_len; i++) {
            plaintext[i] = static_cast<uint8_t>((i * 5) & 0xFF);
        }

        // Encrypt with streaming (DUL = 128)
        uint8_t sector_num[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        xts_params.dul = static_cast<uint32_t>(dul);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        auto ciphertext = streaming_xts_crypt(key.get(), &crypt_algo, plaintext.data(), plaintext_len, dul, true);
        ASSERT_EQ(ciphertext.size(), plaintext_len);

        // Decrypt with single-shot (same DUL = 128)
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        xts_params.dul = static_cast<uint32_t>(dul);

        auto decrypted = single_shot_xts_crypt(key.get(), &crypt_algo, ciphertext.data(), ciphertext.size(), false);

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext_len), 0);
    });
}

// Test: different tweaks produce different ciphertexts
TEST_F(azihsm_aes_xts, different_tweaks_different_ciphertexts)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session);

        const size_t plaintext_len = 256;
        std::vector<uint8_t> plaintext(plaintext_len, 0xAB);

        // Encrypt with tweak = 0
        uint8_t sector_num1[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params1{};
        std::memcpy(xts_params1.sector_num, sector_num1, sizeof(sector_num1));
        xts_params1.dul = static_cast<uint32_t>(plaintext_len);

        azihsm_algo crypt_algo1{};
        crypt_algo1.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo1.params = &xts_params1;
        crypt_algo1.len = sizeof(xts_params1);

        auto ciphertext1 = single_shot_xts_crypt(key.get(), &crypt_algo1, plaintext.data(), plaintext_len, true);

        // Encrypt with tweak = 1
        uint8_t sector_num2[16] = { 0x01, 0x00 };
        azihsm_algo_aes_xts_params xts_params2{};
        std::memcpy(xts_params2.sector_num, sector_num2, sizeof(sector_num2));
        xts_params2.dul = static_cast<uint32_t>(plaintext_len);

        azihsm_algo crypt_algo2{};
        crypt_algo2.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo2.params = &xts_params2;
        crypt_algo2.len = sizeof(xts_params2);

        auto ciphertext2 = single_shot_xts_crypt(key.get(), &crypt_algo2, plaintext.data(), plaintext_len, true);

        // Ciphertexts should be different
        ASSERT_EQ(ciphertext1.size(), ciphertext2.size());
        ASSERT_NE(std::memcmp(ciphertext1.data(), ciphertext2.data(), ciphertext1.size()), 0);
    });
}

// Test: tweak is updated after encryption
TEST_F(azihsm_aes_xts, tweak_updated_after_encryption)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session);

        const size_t plaintext_len = 128;
        std::vector<uint8_t> plaintext(plaintext_len, 0xCC);

        // Initial tweak
        uint8_t sector_num[16] = { 0x05, 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        xts_params.dul = static_cast<uint32_t>(plaintext_len);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        auto ciphertext = single_shot_xts_crypt(key.get(), &crypt_algo, plaintext.data(), plaintext_len, true);

        // Verify tweak was incremented (should be 0x06 now)
        uint8_t expected_tweak[16] = { 0x06, 0x00 };
        ASSERT_EQ(std::memcmp(xts_params.sector_num, expected_tweak, sizeof(expected_tweak)), 0);
    });
}

// Test: minimum plaintext size (16 bytes)
TEST_F(azihsm_aes_xts, minimum_plaintext_size)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session);

        const size_t plaintext_len = 16;
        std::vector<uint8_t> plaintext(plaintext_len, 0xEE);

        uint8_t sector_num[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        xts_params.dul = static_cast<uint32_t>(plaintext_len);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        auto ciphertext = single_shot_xts_crypt(key.get(), &crypt_algo, plaintext.data(), plaintext_len, true);
        ASSERT_EQ(ciphertext.size(), plaintext_len);

        // Decrypt and verify
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        auto decrypted = single_shot_xts_crypt(key.get(), &crypt_algo, ciphertext.data(), ciphertext.size(), false);

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext_len), 0);
    });
}

// Test: plaintext too small (less than 16 bytes) should fail
TEST_F(azihsm_aes_xts, plaintext_too_small_fails)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session);

        const size_t plaintext_len = 8;  // Too small for XTS
        std::vector<uint8_t> plaintext(plaintext_len, 0xAA);

        uint8_t sector_num[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        xts_params.dul = static_cast<uint32_t>(plaintext_len);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext_len) };
        azihsm_buffer output{ nullptr, 0 };

        azihsm_status err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    });
}

// Test: DUL = 0 should fail
TEST_F(azihsm_aes_xts, zero_dul_fails)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session);

        const size_t plaintext_len = 128;
        std::vector<uint8_t> plaintext(plaintext_len, 0xBB);

        uint8_t sector_num[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        xts_params.dul = 0;  // Invalid DUL

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext_len) };
        azihsm_buffer output{ nullptr, 0 };

        azihsm_status err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Test: plaintext not multiple of DUL should fail in streaming
TEST_F(azihsm_aes_xts, streaming_non_dul_aligned_fails)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session);

        const size_t plaintext_len = 257;  // Not a multiple of DUL=128
        const size_t dul = 128;
        std::vector<uint8_t> plaintext(plaintext_len, 0xDD);

        uint8_t sector_num[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        xts_params.dul = static_cast<uint32_t>(dul);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        azihsm_handle ctx = 0;
        azihsm_status err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), &ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Try to update with non-DUL-aligned data
        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext_len) };
        azihsm_buffer output{ nullptr, 0 };

        err = azihsm_crypt_encrypt_update(ctx, &input, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    });
}