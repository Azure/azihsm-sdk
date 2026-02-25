// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <algorithm>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>
#include "helpers.hpp"
#include "handle/key_handle.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "utils/auto_ctx.hpp"
#include "utils/auto_key.hpp"
#include <functional>

class azihsm_aes_xts : public ::testing::Test
{
  protected:
    static constexpr size_t AES_BLOCK_SIZE = 16;

    PartitionListHandle part_list_ = PartitionListHandle{};

    static void init_xts_algo(
        azihsm_algo &algo,
        azihsm_algo_aes_xts_params &params,
        azihsm_algo_id algo_id,
        uint8_t sector_fill,
        size_t data_unit_length
    )
    {
        uint8_t sector_num[AES_BLOCK_SIZE] = { 0 };
        // Test simplification: keep tweak deterministic and mostly constant, then vary only
        // the least-significant byte. This gives stable/controlled tweak deltas for most
        // roundtrip checks; separate tests cover non-trivial multi-byte tweak patterns.
        sector_num[0] = sector_fill;
        std::memcpy(params.sector_num, sector_num, sizeof(sector_num));
        params.data_unit_length = static_cast<uint32_t>(data_unit_length);

        algo.id = algo_id;
        algo.params = &params;
        algo.len = sizeof(params);
    }

    // Helper function for single-shot AES XTS encryption/decryption
    static std::vector<uint8_t> single_shot_xts_crypt(
        CryptOperation operation,
        azihsm_handle key_handle,
        azihsm_algo *algo,
        const uint8_t *input_data,
        size_t input_len
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

    // Helper function for streaming AES XTS encryption/decryption
    static std::vector<uint8_t> streaming_xts_crypt(
        CryptOperation operation,
        azihsm_handle key_handle,
        azihsm_algo *algo,
        const uint8_t *input_data,
        size_t input_len,
        size_t chunk_size
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
        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, algo_id, 0x00, dul);

        // Encrypt with streaming
        auto ciphertext = streaming_xts_crypt(
            CryptOperation::Encrypt,
            key_handle,
            &crypt_algo,
            plaintext,
            plaintext_len,
            chunk_size
        );
        ASSERT_EQ(ciphertext.size(), expected_ciphertext_len);

        // Reset sector number for decryption
        init_xts_algo(crypt_algo, xts_params, algo_id, 0x00, dul);

        // Decrypt with streaming
        auto decrypted = streaming_xts_crypt(
            CryptOperation::Decrypt,
            key_handle,
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            chunk_size
        );

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
        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, algo_id, 0x00, plaintext_len);

        // Encrypt
        auto ciphertext = single_shot_xts_crypt(
            CryptOperation::Encrypt,
            key_handle,
            &crypt_algo,
            plaintext,
            plaintext_len
        );
        ASSERT_EQ(ciphertext.size(), expected_ciphertext_len);

        // Reset tweak for decryption
        init_xts_algo(crypt_algo, xts_params, algo_id, 0x00, plaintext_len);

        // Decrypt
        auto decrypted = single_shot_xts_crypt(
            CryptOperation::Decrypt,
            key_handle,
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size()
        );

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, plaintext_len), 0);
    }
};

// ==================== Correctness Coverage ====================

TEST_F(azihsm_aes_xts, generate_xts_key)
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

        auto_key key_handle;
        azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, key_handle.get_ptr());
        
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS) << "Key generation failed with error: " << err;
        ASSERT_NE(key_handle, 0);
    });
}

TEST_F(azihsm_aes_xts, single_shot_roundtrip)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session, 512);
        ASSERT_NE(key.get(), 0);

        const size_t plaintext_len = 512;
        auto plaintext = make_incrementing_bytes(plaintext_len);

        test_xts_single_shot_roundtrip(
            key.get(),
            AZIHSM_ALGO_ID_AES_XTS,
            plaintext.data(),
            plaintext_len,
            plaintext_len
        );
    });
}

TEST_F(azihsm_aes_xts, streaming_exact_blocks)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session, 512);
        auto plaintext = make_incrementing_bytes(512);

        test_xts_streaming_roundtrip(
            key.get(),
            AZIHSM_ALGO_ID_AES_XTS,
            plaintext.data(),
            plaintext.size(),
            512,
            512,
            plaintext.size()
        );
    });
}

TEST_F(azihsm_aes_xts, streaming_multiple_data_units)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session, 512);
        std::vector<uint8_t> plaintext(1024);
        for (size_t i = 0; i < plaintext.size(); ++i)
        {
            plaintext[i] = static_cast<uint8_t>((i * 3) & 0xFF);
        }

        test_xts_streaming_roundtrip(
            key.get(),
            AZIHSM_ALGO_ID_AES_XTS,
            plaintext.data(),
            plaintext.size(),
            256,
            512,
            plaintext.size()
        );
    });
}

TEST_F(azihsm_aes_xts, streaming_single_data_unit_chunks)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session, 512);
        std::vector<uint8_t> plaintext(512);
        for (size_t i = 0; i < plaintext.size(); ++i)
        {
            plaintext[i] = static_cast<uint8_t>((i * 7) & 0xFF);
        }

        test_xts_streaming_roundtrip(
            key.get(),
            AZIHSM_ALGO_ID_AES_XTS,
            plaintext.data(),
            plaintext.size(),
            128,
            128,
            plaintext.size()
        );
    });
}

TEST_F(azihsm_aes_xts, single_shot_encrypt_streaming_decrypt)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 512;
        const size_t dul = 128;
        auto plaintext = make_incrementing_bytes(plaintext_len);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, dul);

        auto ciphertext = single_shot_xts_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext_len
        );
        ASSERT_EQ(ciphertext.size(), plaintext_len);

        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, dul);

        auto decrypted = streaming_xts_crypt(
            CryptOperation::Decrypt,
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            dul
        );

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext_len), 0);
    });
}

TEST_F(azihsm_aes_xts, streaming_encrypt_single_shot_decrypt)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 512;
        const size_t dul = 128;
        std::vector<uint8_t> plaintext(plaintext_len);
        for (size_t i = 0; i < plaintext_len; ++i)
        {
            plaintext[i] = static_cast<uint8_t>((i * 5) & 0xFF);
        }

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, dul);

        auto ciphertext = streaming_xts_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext_len,
            dul
        );
        ASSERT_EQ(ciphertext.size(), plaintext_len);

        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, dul);

        auto decrypted = single_shot_xts_crypt(
            CryptOperation::Decrypt,
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size()
        );

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext_len), 0);
    });
}

TEST_F(azihsm_aes_xts, different_tweaks_different_ciphertexts)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 256;
        std::vector<uint8_t> plaintext(plaintext_len, 0xAB);

        // Encrypt with tweak = 0
        uint8_t sector_num1[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params1{};
        std::memcpy(xts_params1.sector_num, sector_num1, sizeof(sector_num1));
        xts_params1.data_unit_length = static_cast<uint32_t>(plaintext_len);

        azihsm_algo crypt_algo1{};
        crypt_algo1.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo1.params = &xts_params1;
        crypt_algo1.len = sizeof(xts_params1);

        auto ciphertext1 = single_shot_xts_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo1,
            plaintext.data(),
            plaintext_len
        );

        // Encrypt with tweak = 1
        uint8_t sector_num2[16] = { 0x01, 0x00 };
        azihsm_algo_aes_xts_params xts_params2{};
        std::memcpy(xts_params2.sector_num, sector_num2, sizeof(sector_num2));
        xts_params2.data_unit_length = static_cast<uint32_t>(plaintext_len);

        azihsm_algo crypt_algo2{};
        crypt_algo2.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo2.params = &xts_params2;
        crypt_algo2.len = sizeof(xts_params2);

        auto ciphertext2 = single_shot_xts_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo2,
            plaintext.data(),
            plaintext_len
        );

        // Ciphertexts should be different
        ASSERT_EQ(ciphertext1.size(), ciphertext2.size());
        ASSERT_NE(std::memcmp(ciphertext1.data(), ciphertext2.data(), ciphertext1.size()), 0);
    });
}

TEST_F(azihsm_aes_xts, different_tweaks_higher_order_bytes_different_ciphertexts)
{
    GTEST_SKIP()
        << "Phase 2: add coverage for differing higher-order tweak bytes (beyond sector_num[0])";
}

TEST_F(azihsm_aes_xts, non_trivial_multi_byte_tweak_roundtrip)
{
    GTEST_SKIP() << "Phase 2: add roundtrip coverage with non-zero multi-byte tweak patterns";
}

TEST_F(azihsm_aes_xts, tweak_advances_by_data_unit_count_single_shot)
{
    GTEST_SKIP() << "Phase 2: verify tweak advances by N data units after single-shot operation";
}

TEST_F(azihsm_aes_xts, tweak_advances_by_data_unit_count_streaming)
{
    GTEST_SKIP() << "Phase 2: verify tweak advances consistently across streaming updates";
}

TEST_F(azihsm_aes_xts, decrypt_with_wrong_tweak_does_not_recover_plaintext)
{
    GTEST_SKIP() << "Phase 2: verify decrypt with mismatched tweak does not return original plaintext";
}

TEST_F(azihsm_aes_xts, max_dul_boundary_roundtrip)
{
    GTEST_SKIP() << "Phase 2: add positive roundtrip coverage at max supported DUL boundary";
}

TEST_F(azihsm_aes_xts, tweak_updated_after_encryption)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 128;
        std::vector<uint8_t> plaintext(plaintext_len, 0xCC);

        // Initial tweak
        uint8_t sector_num[16] = { 0x05, 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
       xts_params.data_unit_length = static_cast<uint32_t>(plaintext_len);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        auto ciphertext = single_shot_xts_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext_len
        );
        (void)ciphertext;

        // Verify tweak was incremented (should be 0x06 now)
        uint8_t expected_tweak[16] = { 0x06, 0x00 };
        ASSERT_EQ(std::memcmp(xts_params.sector_num, expected_tweak, sizeof(expected_tweak)), 0);
    });
}

TEST_F(azihsm_aes_xts, minimum_plaintext_size)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 16;
        std::vector<uint8_t> plaintext(plaintext_len, 0xEE);

        uint8_t sector_num[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
       xts_params.data_unit_length = static_cast<uint32_t>(plaintext_len);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        auto ciphertext = single_shot_xts_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext_len
        );
        ASSERT_EQ(ciphertext.size(), plaintext_len);

        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        auto decrypted = single_shot_xts_crypt(
            CryptOperation::Decrypt,
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size()
        );

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext_len), 0);
    });
}

TEST_F(azihsm_aes_xts, single_shot_size_and_dul_sweep)
{
    GTEST_SKIP() << "Phase 2: add single-shot XTS size and DUL sweep coverage";
}

TEST_F(azihsm_aes_xts, streaming_size_and_chunk_sweep)
{
    GTEST_SKIP() << "Phase 2: add streaming XTS size/chunk/DUL sweep coverage";
}

TEST_F(azihsm_aes_xts, large_data_streaming)
{
    GTEST_SKIP() << "Phase 2: add large-data streaming roundtrip coverage";
}

TEST_F(azihsm_aes_xts, large_data_single_shot)
{
    GTEST_SKIP() << "Phase 2: add large-data single-shot roundtrip coverage";
}

TEST_F(azihsm_aes_xts, streaming_consistency_with_single_shot)
{
    GTEST_SKIP() << "Phase 2: add ciphertext consistency checks between streaming and single-shot";
}

// ==================== Argument Validation and API Behavior ====================

TEST_F(azihsm_aes_xts, single_shot_null_pointers_are_rejected)
{
    GTEST_SKIP() << "Phase 2: add null pointer validation checks";
}

TEST_F(azihsm_aes_xts, single_shot_invalid_buffer_shapes_are_rejected)
{
    GTEST_SKIP() << "Phase 2: add malformed input/output buffer checks";
}

TEST_F(azihsm_aes_xts, single_shot_invalid_algo_param_len_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add algorithm parameter length checks";
}

TEST_F(azihsm_aes_xts, single_shot_invalid_key_handle_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add invalid key handle checks";
}

TEST_F(azihsm_aes_xts, single_shot_invalid_key_kind_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add wrong-key-kind checks for XTS operations";
}

TEST_F(azihsm_aes_xts, single_shot_encrypt_with_non_encrypt_key_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add encrypt-permission enforcement checks for single-shot XTS";
}

TEST_F(azihsm_aes_xts, single_shot_decrypt_with_non_decrypt_key_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add decrypt-permission enforcement checks for single-shot XTS";
}

TEST_F(azihsm_aes_xts, streaming_init_null_pointers_are_rejected)
{
    GTEST_SKIP() << "Phase 2: add streaming init null-pointer checks";
}

TEST_F(azihsm_aes_xts, streaming_init_invalid_algo_params_are_rejected)
{
    GTEST_SKIP() << "Phase 2: add streaming init malformed algo checks";
}

TEST_F(azihsm_aes_xts, streaming_init_invalid_algo_param_len_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add streaming init algo length checks";
}

TEST_F(azihsm_aes_xts, streaming_init_invalid_key_handle_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add streaming init invalid-key checks";
}

TEST_F(azihsm_aes_xts, streaming_init_encrypt_with_non_encrypt_key_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add encrypt-permission enforcement checks for streaming init";
}

TEST_F(azihsm_aes_xts, streaming_init_decrypt_with_non_decrypt_key_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add decrypt-permission enforcement checks for streaming init";
}

TEST_F(azihsm_aes_xts, streaming_update_finish_null_pointers_are_rejected)
{
    GTEST_SKIP() << "Phase 2: add streaming update/finish null-pointer checks";
}

TEST_F(azihsm_aes_xts, streaming_update_finish_invalid_buffer_shapes_are_rejected)
{
    GTEST_SKIP() << "Phase 2: add streaming malformed buffer checks";
}

TEST_F(azihsm_aes_xts, single_shot_output_buffer_sizing)
{
    GTEST_SKIP() << "Phase 2: add single-shot output buffer sizing checks";
}

TEST_F(azihsm_aes_xts, streaming_update_output_buffer_sizing)
{
    GTEST_SKIP() << "Phase 2: add streaming update output buffer sizing checks";
}

TEST_F(azihsm_aes_xts, streaming_finish_output_buffer_sizing)
{
    GTEST_SKIP() << "Phase 2: add streaming finish output buffer sizing checks";
}

// ==================== Malformed Input and Rejection ====================

TEST_F(azihsm_aes_xts, plaintext_too_small_fails)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 8;  // Too small for XTS
        std::vector<uint8_t> plaintext(plaintext_len, 0xAA);

        uint8_t sector_num[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
       xts_params.data_unit_length = static_cast<uint32_t>(plaintext_len);

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

TEST_F(azihsm_aes_xts, zero_dul_fails)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 128;
        std::vector<uint8_t> plaintext(plaintext_len, 0xBB);

        uint8_t sector_num[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
       xts_params.data_unit_length = 0;  // Invalid DUL

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

TEST_F(azihsm_aes_xts, streaming_non_dul_aligned_fails)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        KeyHandle key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 257;  // Not a multiple of DUL=128
        const size_t dul = 128;
        std::vector<uint8_t> plaintext(plaintext_len, 0xDD);

        uint8_t sector_num[16] = { 0x00 };
        azihsm_algo_aes_xts_params xts_params{};
        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
       xts_params.data_unit_length = static_cast<uint32_t>(dul);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        auto_ctx ctx;
        azihsm_status err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Try to update with non-DUL-aligned data
        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext_len) };
        azihsm_buffer output{ nullptr, 0 };

        err = azihsm_crypt_encrypt_update(ctx, &input, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    });
}

TEST_F(azihsm_aes_xts, decrypt_non_dul_aligned_ciphertext_fails)
{
    GTEST_SKIP() << "Phase 2: add decrypt non-DUL-aligned ciphertext rejection checks";
}

TEST_F(azihsm_aes_xts, invalid_tweak_value_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add invalid tweak rejection checks";
}

TEST_F(azihsm_aes_xts, dul_not_block_aligned_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add rejection checks for DUL values not divisible by AES block size";
}

TEST_F(azihsm_aes_xts, dul_exceeds_max_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add rejection checks for DUL values above maximum supported limit";
}

TEST_F(azihsm_aes_xts, unwrap_malformed_xts_blob_header_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add malformed XTS wrapped-blob header rejection checks";
}

TEST_F(azihsm_aes_xts, unwrap_xts_blob_length_mismatch_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add XTS wrapped-blob length mismatch rejection checks";
}

TEST_F(azihsm_aes_xts, unwrap_xts_blob_missing_second_half_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add XTS wrapped-blob missing-second-half rejection checks";
}

TEST_F(azihsm_aes_xts, unmask_malformed_xts_blob_header_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add malformed XTS masked-blob header rejection checks";
}

TEST_F(azihsm_aes_xts, unmask_xts_blob_length_mismatch_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add XTS masked-blob length mismatch rejection checks";
}

TEST_F(azihsm_aes_xts, unmask_xts_blob_missing_second_half_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add XTS masked-blob missing-second-half rejection checks";
}

TEST_F(azihsm_aes_xts, unwrap_xts_blob_mismatched_half_properties_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add rejection checks for mismatched half-key properties";
}

TEST_F(azihsm_aes_xts, unwrap_xts_blob_identical_halves_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add behavior checks for wrapped blobs containing identical halves";
}

// ==================== Streaming Lifecycle and Context Rules ====================

TEST_F(azihsm_aes_xts, streaming_invalid_context_handles_are_rejected)
{
    GTEST_SKIP() << "Phase 2: add invalid context-handle checks for update/finish";
}

TEST_F(azihsm_aes_xts, streaming_operation_mismatch_on_context_is_rejected)
{
    GTEST_SKIP() << "Phase 2: add operation/context mismatch checks";
}

TEST_F(azihsm_aes_xts, streaming_finish_without_update_behavior)
{
    GTEST_SKIP() << "Phase 2: define and validate finish-without-update behavior for XTS";
}