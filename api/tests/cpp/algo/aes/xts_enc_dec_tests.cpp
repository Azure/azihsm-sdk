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
#include "utils/key_import.hpp"
#include "utils/auto_ctx.hpp"
#include "utils/auto_key.hpp"
#include "utils/rsa_keygen.hpp"
#include <functional>

class azihsm_aes_xts : public ::testing::Test
{
  protected:
    static constexpr size_t AES_BLOCK_SIZE = 16;
    static constexpr size_t XTS_BLOB_HEADER_LEN = 16;

    PartitionListHandle part_list_ = PartitionListHandle{};

    static std::vector<uint8_t> build_xts_blob_header(uint16_t key1_len, uint16_t key2_len)
    {
        // Header layout (16 bytes, little-endian):
        // [0..7]   magic   = "AZHSMXTS"
        // [8..9]   version = 1
        // [10..11] key1_len
        // [12..13] key2_len
        // [14..15] reserved = 0
        //
        // Note: the u64 literal is the little-endian encoding of the ASCII marker
        // "AZHSMXTS", matching the Rust parser in ddi/aes_xts_key.rs.
        const uint64_t wrap_blob_magic = 0x5354584D'53485A41ULL;
        const uint16_t wrap_blob_version = 1;

        std::vector<uint8_t> header(XTS_BLOB_HEADER_LEN, 0);
        for (int i = 0; i < 8; ++i)
        {
            header[i] = static_cast<uint8_t>((wrap_blob_magic >> (i * 8)) & 0xFF);
        }

        header[8] = static_cast<uint8_t>(wrap_blob_version & 0xFF);
        header[9] = static_cast<uint8_t>((wrap_blob_version >> 8) & 0xFF);

        header[10] = static_cast<uint8_t>(key1_len & 0xFF);
        header[11] = static_cast<uint8_t>((key1_len >> 8) & 0xFF);
        header[12] = static_cast<uint8_t>(key2_len & 0xFF);
        header[13] = static_cast<uint8_t>((key2_len >> 8) & 0xFF);

        return header;
    }

    static std::vector<uint8_t> build_xts_wrapped_blob(
        azihsm_handle wrapping_pub_key,
        const std::vector<uint8_t> &key1_plain,
        const std::vector<uint8_t> &key2_plain
    )
    {
        // Build a syntactically valid AES-XTS wrapped blob from two local key halves.
        const auto wrap_half = [&](const std::vector<uint8_t> &plain_half) -> std::vector<uint8_t> {
            std::vector<uint8_t> wrapped_data;
            auto wrap_status = rsa_aes_wrap_bytes(
                wrapping_pub_key,
                plain_half,
                static_cast<uint32_t>(plain_half.size() * 8),
                wrapped_data
            );
            if (wrap_status != AZIHSM_STATUS_SUCCESS)
            {
                return {};
            }

            return wrapped_data;
        };

        auto key1_wrapped_data = wrap_half(key1_plain);
        if (key1_wrapped_data.empty())
        {
            return {};
        }

        auto key2_wrapped_data = wrap_half(key2_plain);
        if (key2_wrapped_data.empty())
        {
            return {};
        }

        // Encode both wrapped halves into the XTS key-pair blob format.
        auto header = build_xts_blob_header(
            static_cast<uint16_t>(key1_wrapped_data.size()),
            static_cast<uint16_t>(key2_wrapped_data.size())
        );

        std::vector<uint8_t> blob;
        blob.reserve(header.size() + key1_wrapped_data.size() + key2_wrapped_data.size());
        blob.insert(blob.end(), header.begin(), header.end());
        blob.insert(blob.end(), key1_wrapped_data.begin(), key1_wrapped_data.end());
        blob.insert(blob.end(), key2_wrapped_data.begin(), key2_wrapped_data.end());
        return blob;
    }

    static std::vector<uint8_t> get_masked_blob_for_key(azihsm_handle key)
    {
        // Retrieve the device-exported masked representation of an existing XTS key.
        // This is an opaque serialized form (not plaintext key bytes) used by unmask APIs.
        //
        // Two-call size pattern:
        // 1) call with null output to get required length,
        // 2) allocate exact buffer and fetch bytes.
        azihsm_key_prop masked_prop{};
        masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
        masked_prop.val = nullptr;
        masked_prop.len = 0;

        auto err = azihsm_key_get_prop(key, &masked_prop);
        if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL || masked_prop.len == 0)
        {
            return {};
        }

        std::vector<uint8_t> masked_blob(masked_prop.len);
        masked_prop.val = masked_blob.data();
        err = azihsm_key_get_prop(key, &masked_prop);
        if (err != AZIHSM_STATUS_SUCCESS)
        {
            return {};
        }

        masked_blob.resize(masked_prop.len);
        return masked_blob;
    }

    static azihsm_status unwrap_xts_blob(
        azihsm_handle wrapping_priv_key,
        std::vector<uint8_t> &wrapped_blob,
        auto_key &unwrapped_key
    )
    {
        // Unwrap a previously constructed XTS wrapped blob into an HSM key handle.
        //
        // Conceptually:
        // - wrapped_blob contains two RSA-wrapped AES halves + XTS header metadata
        // - wrapping_priv_key is the RSA private key that can decrypt those halves
        // - unwrap properties describe the resulting logical key (kind, size, permissions)
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES_XTS;
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t bits = 512;
        bool is_session = true;
        bool can_encrypt = true;
        bool can_decrypt = true;

        azihsm_algo_rsa_pkcs_oaep_params oaep_params{};
        oaep_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
        oaep_params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256;
        oaep_params.label = nullptr;

        azihsm_algo_rsa_aes_key_wrap_params unwrap_params{};
        unwrap_params.aes_key_bits = 256;
        unwrap_params.oaep_params = &oaep_params;

        azihsm_algo unwrap_algo{};
        unwrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP;
        unwrap_algo.params = &unwrap_params;
        unwrap_algo.len = sizeof(unwrap_params);

        std::vector<azihsm_key_prop> unwrap_props_vec;
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) });
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) });
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_SESSION, &is_session, sizeof(is_session) });
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) });
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) });

        azihsm_key_prop_list unwrap_prop_list{
            unwrap_props_vec.data(),
            static_cast<uint32_t>(unwrap_props_vec.size())
        };

        azihsm_buffer wrapped_blob_buf{
            wrapped_blob.data(),
            static_cast<uint32_t>(wrapped_blob.size())
        };

        // Result: one logical AES-XTS key handle backed by two internal AES-256 halves.
        return azihsm_key_unwrap(
            &unwrap_algo,
            wrapping_priv_key,
            &wrapped_blob_buf,
            &unwrap_prop_list,
            unwrapped_key.get_ptr()
        );
    }

    static void init_xts_algo(
        azihsm_algo &algo,
        azihsm_algo_aes_xts_params &params,
        azihsm_algo_id algo_id,
        uint8_t sector_fill,
        size_t data_unit_length
    )
    {
        // In XTS, sector_num is the tweak/nonce-like value that separates data units.
        // Using deterministic values keeps tests reproducible while still exercising
        // tweak-dependent behavior.
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
        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key_handle,
            &crypt_algo,
            plaintext,
            plaintext_len,
            ciphertext
        ));
        ASSERT_EQ(ciphertext.size(), expected_ciphertext_len);

        // Reset tweak for decryption
        init_xts_algo(crypt_algo, xts_params, algo_id, 0x00, plaintext_len);

        // Decrypt
        std::vector<uint8_t> decrypted;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Decrypt,
            key_handle,
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            decrypted
        ));

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
            plaintext_len  // XTS doesn't add padding
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
            512,  // DUL = 512 bytes
            512,  // Chunk size = 1 DUL
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
            128,  // DUL = 128 bytes
            128,  // Chunk size = 1 DUL
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

        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext_len,
            ciphertext
        ));
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

        std::vector<uint8_t> decrypted;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Decrypt,
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            decrypted
        ));

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext_len), 0);
    });
}

// Sanity check: same plaintext under different tweaks must produce different ciphertext.
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

        std::vector<uint8_t> ciphertext1;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo1,
            plaintext.data(),
            plaintext_len,
            ciphertext1
        ));

        // Encrypt with tweak = 1
        uint8_t sector_num2[16] = { 0x01, 0x00 };
        azihsm_algo_aes_xts_params xts_params2{};
        std::memcpy(xts_params2.sector_num, sector_num2, sizeof(sector_num2));
        xts_params2.data_unit_length = static_cast<uint32_t>(plaintext_len);

        azihsm_algo crypt_algo2{};
        crypt_algo2.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo2.params = &xts_params2;
        crypt_algo2.len = sizeof(xts_params2);

        std::vector<uint8_t> ciphertext2;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo2,
            plaintext.data(),
            plaintext_len,
            ciphertext2
        ));

        // Ciphertexts should be different
        ASSERT_EQ(ciphertext1.size(), ciphertext2.size());
        ASSERT_NE(std::memcmp(ciphertext1.data(), ciphertext2.data(), ciphertext1.size()), 0);
    });
}

// Ensures tweak entropy in higher-order bytes (not just byte 0) affects ciphertext.
TEST_F(azihsm_aes_xts, different_tweaks_higher_order_bytes_different_ciphertexts)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 256;
        auto plaintext = make_incrementing_bytes(plaintext_len);

        azihsm_algo_aes_xts_params xts_params1{};
        std::memset(xts_params1.sector_num, 0, sizeof(xts_params1.sector_num));
        // Use a higher-order tweak byte to ensure the implementation is not
        // effectively treating the tweak as only a low-byte counter.
        xts_params1.sector_num[7] = 0x01;
        xts_params1.data_unit_length = static_cast<uint32_t>(plaintext_len);

        azihsm_algo crypt_algo1{};
        crypt_algo1.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo1.params = &xts_params1;
        crypt_algo1.len = sizeof(xts_params1);

        azihsm_algo_aes_xts_params xts_params2{};
        std::memset(xts_params2.sector_num, 0, sizeof(xts_params2.sector_num));
        xts_params2.sector_num[7] = 0x02;
        xts_params2.data_unit_length = static_cast<uint32_t>(plaintext_len);

        azihsm_algo crypt_algo2{};
        crypt_algo2.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo2.params = &xts_params2;
        crypt_algo2.len = sizeof(xts_params2);

        std::vector<uint8_t> ciphertext1;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo1,
            plaintext.data(),
            plaintext.size(),
            ciphertext1
        ));
        std::vector<uint8_t> ciphertext2;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo2,
            plaintext.data(),
            plaintext.size(),
            ciphertext2
        ));

        ASSERT_EQ(ciphertext1.size(), ciphertext2.size());
        ASSERT_NE(std::memcmp(ciphertext1.data(), ciphertext2.data(), ciphertext1.size()), 0);
    });
}

// Verifies roundtrip correctness with a realistic, non-trivial 128-bit tweak value.
TEST_F(azihsm_aes_xts, non_trivial_multi_byte_tweak_roundtrip)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 256;
        auto plaintext = make_incrementing_bytes(plaintext_len);

        azihsm_algo_aes_xts_params xts_params{};
        uint8_t tweak[16] = {
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
        };
        std::memcpy(xts_params.sector_num, tweak, sizeof(tweak));
        xts_params.data_unit_length = 128;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        std::memcpy(xts_params.sector_num, tweak, sizeof(tweak));
        std::vector<uint8_t> decrypted;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Decrypt,
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            decrypted
        ));

        ASSERT_EQ(decrypted.size(), plaintext.size());
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
    });
}

// XTS processes data units; after encrypting N units, tweak should advance by N.
TEST_F(azihsm_aes_xts, tweak_advances_by_data_unit_count_single_shot)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        const size_t dul = 128;
        // One "unit" == one full data unit (DUL bytes); use 3 to verify repeated
        // tweak increments (not just a single-step case) while keeping the test small.
        const size_t units = 3;
        auto plaintext = make_incrementing_bytes(dul * units);

        azihsm_algo_aes_xts_params xts_params{};
        uint8_t initial_tweak[16] = { 0xFC, 0x00 };
        std::memcpy(xts_params.sector_num, initial_tweak, sizeof(initial_tweak));
        xts_params.data_unit_length = static_cast<uint32_t>(dul);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));
        ASSERT_EQ(ciphertext.size(), plaintext.size());

        // Recompute expected tweak locally using little-endian +1 per processed data unit.
        uint8_t expected_tweak[16];
        std::memcpy(expected_tweak, initial_tweak, sizeof(expected_tweak));
        for (size_t step = 0; step < units; ++step)
        {
            // Carry propagation across all 16 tweak bytes.
            for (size_t idx = 0; idx < sizeof(expected_tweak); ++idx)
            {
                expected_tweak[idx] = static_cast<uint8_t>(expected_tweak[idx] + 1);
                if (expected_tweak[idx] != 0)
                {
                    break;
                }
            }
        }

        ASSERT_EQ(std::memcmp(xts_params.sector_num, expected_tweak, sizeof(expected_tweak)), 0);
    });
}

// Same tweak-advance contract as single-shot, validated across streaming updates.
TEST_F(azihsm_aes_xts, tweak_advances_by_data_unit_count_streaming)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        const size_t dul = 128;
        const size_t units = 4;
        auto plaintext = make_incrementing_bytes(dul * units);

        azihsm_algo_aes_xts_params xts_params{};
        uint8_t initial_tweak[16] = { 0xFE, 0x00 };
        std::memcpy(xts_params.sector_num, initial_tweak, sizeof(initial_tweak));
        xts_params.data_unit_length = static_cast<uint32_t>(dul);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        auto ciphertext = streaming_xts_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            2 * dul
        );
        ASSERT_EQ(ciphertext.size(), plaintext.size());

        // Same expected increment model as single-shot: one tweak step per full data unit.
        uint8_t expected_tweak[16];
        std::memcpy(expected_tweak, initial_tweak, sizeof(expected_tweak));
        for (size_t step = 0; step < units; ++step)
        {
            // Treat tweak as a 128-bit little-endian counter.
            for (size_t idx = 0; idx < sizeof(expected_tweak); ++idx)
            {
                expected_tweak[idx] = static_cast<uint8_t>(expected_tweak[idx] + 1);
                if (expected_tweak[idx] != 0)
                {
                    break;
                }
            }
        }

        ASSERT_EQ(std::memcmp(xts_params.sector_num, expected_tweak, sizeof(expected_tweak)), 0);
    });
}

// Decryption must use the same tweak context; wrong tweak should not recover plaintext.
TEST_F(azihsm_aes_xts, decrypt_with_wrong_tweak_does_not_recover_plaintext)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 256;
        auto plaintext = make_incrementing_bytes(plaintext_len);

        azihsm_algo_aes_xts_params enc_params{};
        azihsm_algo enc_algo{};
        init_xts_algo(enc_algo, enc_params, AZIHSM_ALGO_ID_AES_XTS, 0x10, plaintext_len);

        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &enc_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        // Intentionally use a different tweak than encryption.
        azihsm_algo_aes_xts_params dec_params{};
        azihsm_algo dec_algo{};
        init_xts_algo(dec_algo, dec_params, AZIHSM_ALGO_ID_AES_XTS, 0x11, plaintext_len);

        std::vector<uint8_t> decrypted;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Decrypt,
            key.get(),
            &dec_algo,
            ciphertext.data(),
            ciphertext.size(),
            decrypted
        ));

        ASSERT_EQ(decrypted.size(), plaintext.size());
        ASSERT_NE(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
    });
}

TEST_F(azihsm_aes_xts, max_dul_boundary_roundtrip)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        // XTS implementation caps DUL at 8192 bytes; verify the max accepted value works.
        constexpr size_t dul = 8192;
        auto plaintext = make_incrementing_bytes(dul);

        test_xts_single_shot_roundtrip(
            key.get(),
            AZIHSM_ALGO_ID_AES_XTS,
            plaintext.data(),
            plaintext.size(),
            plaintext.size()
        );
    });
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

        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext_len,
            ciphertext
        ));
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

        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext_len,
            ciphertext
        ));
        ASSERT_EQ(ciphertext.size(), plaintext_len);

        std::memcpy(xts_params.sector_num, sector_num, sizeof(sector_num));
        std::vector<uint8_t> decrypted;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Decrypt,
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            decrypted
        ));

        ASSERT_EQ(decrypted.size(), plaintext_len);
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext_len), 0);
    });
}

TEST_F(azihsm_aes_xts, single_shot_size_and_dul_sweep)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        // Sweep representative valid DUL values (all block-aligned, including max boundary).
        const std::vector<size_t> duls = { 16, 32, 64, 128, 256, 512, 1024, 4096, 8192 };

        for (size_t dul : duls)
        {
            for (size_t units : { 1u, 2u })
            {
                const size_t plaintext_len = dul * units;
                SCOPED_TRACE(
                    "single_shot DUL sweep: dul=" + std::to_string(dul) +
                    " units=" + std::to_string(units)
                );

                auto plaintext = make_incrementing_bytes(plaintext_len);
                azihsm_algo_aes_xts_params xts_params{};
                azihsm_algo crypt_algo{};
                init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x21, dul);

                // Encrypt/decrypt with identical tweak + DUL to validate roundtrip for each case.
                std::vector<uint8_t> ciphertext;
                ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
                    CryptOperation::Encrypt,
                    key.get(),
                    &crypt_algo,
                    plaintext.data(),
                    plaintext.size(),
                    ciphertext
                ));
                ASSERT_EQ(ciphertext.size(), plaintext.size());

                init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x21, dul);
                std::vector<uint8_t> decrypted;
                ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
                    CryptOperation::Decrypt,
                    key.get(),
                    &crypt_algo,
                    ciphertext.data(),
                    ciphertext.size(),
                    decrypted
                ));

                ASSERT_EQ(decrypted.size(), plaintext.size());
                ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
            }
        }
    });
}

TEST_F(azihsm_aes_xts, streaming_size_and_chunk_sweep)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        // Keep update chunk sizes DUL-aligned to exercise valid streaming segmentation.
        const std::vector<size_t> duls = { 16, 64, 128, 256, 512, 1024 };

        for (size_t dul : duls)
        {
            for (size_t units : { 2u, 4u })
            {
                const size_t plaintext_len = dul * units;
                auto plaintext = make_incrementing_bytes(plaintext_len);

                for (size_t chunk_units : { 1u, 2u })
                {
                    size_t chunk_size = dul * chunk_units;
                    // Skip invalid segmentation where one update would exceed total input.
                    if (chunk_size > plaintext_len)
                    {
                        continue;
                    }

                    SCOPED_TRACE(
                        "streaming sweep: dul=" + std::to_string(dul) +
                        " units=" + std::to_string(units) +
                        " chunk_size=" + std::to_string(chunk_size)
                    );

                    test_xts_streaming_roundtrip(
                        key.get(),
                        AZIHSM_ALGO_ID_AES_XTS,
                        plaintext.data(),
                        plaintext.size(),
                        dul,
                        chunk_size,
                        plaintext.size()
                    );
                }
            }
        }
    });
}

TEST_F(azihsm_aes_xts, large_data_streaming)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 64 * 1024;
        const size_t dul = 1024;
        const size_t chunk_size = 2 * dul;
        auto plaintext = make_incrementing_bytes(plaintext_len);

        test_xts_streaming_roundtrip(
            key.get(),
            AZIHSM_ALGO_ID_AES_XTS,
            plaintext.data(),
            plaintext.size(),
            dul,
            chunk_size,
            plaintext.size()
        );
    });
}

TEST_F(azihsm_aes_xts, large_data_single_shot)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 32 * 1024;
        const size_t dul = 1024;
        auto plaintext = make_incrementing_bytes(plaintext_len);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x21, dul);

        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));
        ASSERT_EQ(ciphertext.size(), plaintext.size());

        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x21, dul);
        std::vector<uint8_t> decrypted;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Decrypt,
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            decrypted
        ));

        ASSERT_EQ(decrypted.size(), plaintext.size());
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
    });
}

// Confirms API shape does not change semantics: streaming and single-shot ciphertext match.
TEST_F(azihsm_aes_xts, streaming_consistency_with_single_shot)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        const size_t plaintext_len = 4096;
        const size_t dul = 256;
        const size_t chunk_size = 512;
        auto plaintext = make_incrementing_bytes(plaintext_len);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x42, dul);

        std::vector<uint8_t> single_shot_ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            single_shot_ciphertext
        ));

        // Reinitialize to identical starting tweak so only API shape differs.
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x42, dul);
        auto streaming_ciphertext = streaming_xts_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            chunk_size
        );

        ASSERT_EQ(streaming_ciphertext.size(), single_shot_ciphertext.size());
        ASSERT_EQ(
            std::memcmp(
                streaming_ciphertext.data(),
                single_shot_ciphertext.data(),
                single_shot_ciphertext.size()
            ),
            0
        );
    });
}

// ==================== Argument Validation and API Behavior ====================

TEST_F(azihsm_aes_xts, single_shot_null_pointers_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        uint8_t input_data[128] = { 0xAA };
        azihsm_buffer input{ input_data, sizeof(input_data) };
        azihsm_buffer output{ nullptr, 0 };

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, sizeof(input_data));

        auto err = crypt_call(CryptOperation::Encrypt, nullptr, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), nullptr, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_call(CryptOperation::Decrypt, nullptr, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_call(CryptOperation::Decrypt, &crypt_algo, key.get(), nullptr, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = crypt_call(CryptOperation::Decrypt, &crypt_algo, key.get(), &input, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_xts, single_shot_invalid_buffer_shapes_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, 128);

        uint8_t data[128] = { 0xAB };
        azihsm_buffer bad_input{ nullptr, 1 };
        azihsm_buffer output{ nullptr, 0 };

        auto err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &bad_input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        azihsm_buffer input{ data, sizeof(data) };
        azihsm_buffer bad_output{ nullptr, 1 };
        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_xts, single_shot_invalid_algo_param_len_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        uint8_t data[128] = { 0xCD };
        azihsm_buffer input{ data, sizeof(data) };
        azihsm_buffer output{ nullptr, 0 };

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, sizeof(data));

        crypt_algo.len = sizeof(xts_params) - 1;
        auto err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        crypt_algo.len = sizeof(xts_params) + 1;
        err = crypt_call(CryptOperation::Encrypt, &crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_xts, single_shot_invalid_key_handle_is_rejected)
{
    azihsm_algo_aes_xts_params xts_params{};
    azihsm_algo crypt_algo{};
    init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, 128);

    uint8_t data[128] = { 0xEE };
    azihsm_buffer input{ data, sizeof(data) };
    azihsm_buffer output{ nullptr, 0 };

    auto err = crypt_call(CryptOperation::Encrypt, &crypt_algo, 0xDEADBEEF, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST_F(azihsm_aes_xts, single_shot_invalid_key_kind_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // CBC key kind intentionally does not match XTS operation requirements.
        auto non_xts_key = generate_aes_key(session, 256);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, 128);

        uint8_t data[128] = { 0x12 };
        azihsm_buffer input{ data, sizeof(data) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = crypt_call(CryptOperation::Encrypt, &crypt_algo, non_xts_key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

        err = crypt_call(CryptOperation::Decrypt, &crypt_algo, non_xts_key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_aes_xts, key_gen_with_encrypt_disabled_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // XTS key validation requires BOTH encrypt and decrypt permissions.
        // Verify key creation is rejected when encrypt is disabled.
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN;

        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES_XTS;
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t bits = 512;
        uint8_t is_session = 1;
        uint8_t can_encrypt = 0;
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
        auto err = azihsm_key_gen(session, &keygen_algo, &prop_list, key_handle.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(key_handle, 0);
    });
}

TEST_F(azihsm_aes_xts, key_gen_with_decrypt_disabled_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // XTS key validation requires BOTH encrypt and decrypt permissions.
        // Verify key creation is rejected when decrypt is disabled.
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN;

        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES_XTS;
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t bits = 512;
        uint8_t is_session = 1;
        uint8_t can_encrypt = 1;
        uint8_t can_decrypt = 0;

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
        auto err = azihsm_key_gen(session, &keygen_algo, &prop_list, key_handle.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(key_handle, 0);
    });
}

TEST_F(azihsm_aes_xts, streaming_init_null_pointers_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, 128);

        auto_ctx ctx;
        auto err = azihsm_crypt_encrypt_init(nullptr, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_init(nullptr, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_xts, streaming_init_invalid_algo_params_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, 128);

        auto_ctx ctx;
        crypt_algo.params = nullptr;
        crypt_algo.len = 0;

        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_xts, streaming_init_invalid_algo_param_len_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, 128);

        auto_ctx ctx;

        crypt_algo.len = sizeof(xts_params) - 1;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        crypt_algo.len = sizeof(xts_params) + 1;
        err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_xts, streaming_init_invalid_key_handle_is_rejected)
{
    azihsm_algo_aes_xts_params xts_params{};
    azihsm_algo crypt_algo{};
    init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, 128);

    auto_ctx ctx;
    auto err = azihsm_crypt_encrypt_init(&crypt_algo, 0xDEADBEEF, ctx.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = azihsm_crypt_decrypt_init(&crypt_algo, 0xDEADBEEF, ctx.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST_F(azihsm_aes_xts, streaming_update_finish_null_pointers_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, 128);

        auto_ctx enc_ctx;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), enc_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto_ctx dec_ctx;
        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), dec_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t data[128] = { 0xAB };
        azihsm_buffer input{ data, sizeof(data) };
        azihsm_buffer output{ nullptr, 0 };

        err = azihsm_crypt_encrypt_update(enc_ctx, nullptr, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_encrypt_update(enc_ctx, &input, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_encrypt_finish(enc_ctx, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_update(dec_ctx, nullptr, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_update(dec_ctx, &input, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_finish(dec_ctx, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_xts, streaming_update_finish_invalid_buffer_shapes_are_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, 128);

        auto_ctx enc_ctx;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), enc_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto_ctx dec_ctx;
        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), dec_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t byte = 0x01;
        uint8_t block[128] = { 0x01 };
        azihsm_buffer bad_input{ nullptr, 1 };
        azihsm_buffer bad_output{ nullptr, 1 };
        azihsm_buffer good_input{ block, sizeof(block) };
        azihsm_buffer good_output{ &byte, 1 };

        err = azihsm_crypt_encrypt_update(enc_ctx, &bad_input, &good_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_encrypt_update(enc_ctx, &good_input, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_encrypt_finish(enc_ctx, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_update(dec_ctx, &bad_input, &good_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_update(dec_ctx, &good_input, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_finish(dec_ctx, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Validates standard two-call sizing contract (query, exact, too-small) for XTS single-shot.
TEST_F(azihsm_aes_xts, single_shot_output_buffer_sizing)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        std::vector<uint8_t> plaintext(256, 0x5A);
        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x19, 128);

        azihsm_buffer output{ nullptr, 0 };
        // Query-only call: implementation reports required ciphertext size.
        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(output.len, plaintext.size());

        // Exact-size buffer must succeed and return full ciphertext length.
        std::vector<uint8_t> exact(output.len);
        output.ptr = exact.data();
        err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(output.len, plaintext.size());

        // One-byte-short buffer should fail while still returning required length.
        std::vector<uint8_t> small(plaintext.size() - 1);
        azihsm_buffer too_small{ small.data(), static_cast<uint32_t>(small.size()) };
        err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &too_small);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(too_small.len, plaintext.size());
    });
}

// Verifies update() sizing behavior and that XTS emits output immediately per full data unit.
TEST_F(azihsm_aes_xts, streaming_update_output_buffer_sizing)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x29, 128);

        auto_ctx ctx;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t block[128] = { 0x11 };
        azihsm_buffer input{ block, sizeof(block) };
        azihsm_buffer output{ nullptr, 0 };

        // Query update output size for one full data unit.
        err = azihsm_crypt_encrypt_update(ctx, &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(output.len, sizeof(block));

        // Verify too-small update buffer reports the same required length.
        std::vector<uint8_t> too_small_buf(sizeof(block) - 1);
        azihsm_buffer too_small{
            too_small_buf.data(),
            static_cast<uint32_t>(too_small_buf.size())
        };
        err = azihsm_crypt_encrypt_update(ctx, &input, &too_small);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(too_small.len, sizeof(block));

        std::vector<uint8_t> exact(sizeof(block));
        azihsm_buffer exact_output{ exact.data(), static_cast<uint32_t>(exact.size()) };
        // Exact-size update buffer should produce ciphertext immediately.
        err = azihsm_crypt_encrypt_update(ctx, &input, &exact_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(exact_output.len, sizeof(block));

        // XTS finish has no deferred output.
        azihsm_buffer finish_output{ nullptr, 0 };
        err = azihsm_crypt_encrypt_finish(ctx, &finish_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(finish_output.len, 0u);
    });
}

// XTS finish() has no buffered tail; expected output length is always zero.
TEST_F(azihsm_aes_xts, streaming_finish_output_buffer_sizing)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x2A, 128);

        auto_ctx enc_ctx;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), enc_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Encrypt finish without pending data should return success with zero output.
        azihsm_buffer query_output{ nullptr, 0 };
        err = azihsm_crypt_encrypt_finish(enc_ctx, &query_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(query_output.len, 0u);

        auto_ctx dec_ctx;
        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), dec_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t dummy = 0;
        azihsm_buffer non_empty_output{ &dummy, 1 };
        // Decrypt finish should ignore caller-provided capacity and still report zero bytes.
        err = azihsm_crypt_decrypt_finish(dec_ctx, &non_empty_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(non_empty_output.len, 0u);
    });
}

// ==================== Malformed Input and Rejection ====================

// XTS requires at least one AES block in a data unit; sub-block payload must be rejected.
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

// Data-unit length is required metadata; zero is nonsensical and must fail validation.
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

// Test: plaintext not multiple of DUL should fail in streaming
// Streaming XTS accepts only whole data units; partial/misaligned updates must fail.
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
        // Misaligned update should be rejected before any output-size negotiation.
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    });
}

// Ciphertext framing must preserve full data units; truncated input is invalid for decrypt.
TEST_F(azihsm_aes_xts, decrypt_non_dul_aligned_ciphertext_fails)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        const size_t dul = 128;
        auto plaintext = make_incrementing_bytes(dul * 2);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x33, dul);

        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        // Non-obvious XTS contract: ciphertext must also be DUL-aligned.
        ciphertext.pop_back();

        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x33, dul);
        azihsm_buffer cipher_buf{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        azihsm_buffer plain_buf{ nullptr, 0 };

        auto err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_buf, &plain_buf);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    });
}

// Starting at max tweak and processing one unit overflows the counter and should be rejected.
TEST_F(azihsm_aes_xts, invalid_tweak_value_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        const size_t dul = 128;
        auto plaintext = make_incrementing_bytes(dul);

        azihsm_algo_aes_xts_params xts_params{};
        std::memset(xts_params.sector_num, 0xFF, sizeof(xts_params.sector_num));
        xts_params.data_unit_length = static_cast<uint32_t>(dul);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        crypt_algo.params = &xts_params;
        crypt_algo.len = sizeof(xts_params);

        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        azihsm_buffer output{ nullptr, 0 };

        // First call is only for output sizing.
        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

        // Provide output buffer so operation executes and tweak-overflow validation is reached.
        std::vector<uint8_t> ciphertext(output.len);
        output.ptr = ciphertext.data();
        err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_TWEAK);
    });
}

// DUL must be AES-block aligned; non-aligned values are invalid by XTS contract.
TEST_F(azihsm_aes_xts, dul_not_block_aligned_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, 17);

        uint8_t data[34] = { 0x44 };
        azihsm_buffer input{ data, sizeof(data) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Implementation safety guard: reject DUL values above the supported upper bound.
TEST_F(azihsm_aes_xts, dul_exceeds_max_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x00, 8193);

        uint8_t data[16] = { 0x55 };
        azihsm_buffer input{ data, sizeof(data) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Header marker/version validation: corrupt magic should fail before any unwrap attempt.
TEST_F(azihsm_aes_xts, unwrap_malformed_xts_blob_header_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key wrapping_priv_key;
        auto_key wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto wrapped_blob = build_xts_wrapped_blob(
            wrapping_pub_key,
            std::vector<uint8_t>(32, 0x11),
            std::vector<uint8_t>(32, 0x22)
        );
        ASSERT_FALSE(wrapped_blob.empty());

        // Corrupt the magic byte so header validation fails.
        wrapped_blob[0] ^= 0xFF;

        auto_key unwrapped_key;
        err = unwrap_xts_blob(wrapping_priv_key, wrapped_blob, unwrapped_key);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Header length fields must match payload; mismatch should fail deterministic blob parsing.
TEST_F(azihsm_aes_xts, unwrap_xts_blob_length_mismatch_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key wrapping_priv_key;
        auto_key wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto wrapped_blob = build_xts_wrapped_blob(
            wrapping_pub_key,
            std::vector<uint8_t>(32, 0x31),
            std::vector<uint8_t>(32, 0x32)
        );
        ASSERT_FALSE(wrapped_blob.empty());

        // Inflate key1 length LSB (header[10]) to force payload-length mismatch.
        wrapped_blob[10] = static_cast<uint8_t>(wrapped_blob[10] + 1);

        auto_key unwrapped_key;
        err = unwrap_xts_blob(wrapping_priv_key, wrapped_blob, unwrapped_key);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// XTS key blob requires two halves; dropping one half must be rejected.
TEST_F(azihsm_aes_xts, unwrap_xts_blob_missing_second_half_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key wrapping_priv_key;
        auto_key wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto wrapped_blob = build_xts_wrapped_blob(
            wrapping_pub_key,
            std::vector<uint8_t>(32, 0x41),
            std::vector<uint8_t>(32, 0x42)
        );
        ASSERT_FALSE(wrapped_blob.empty());

        // Keep only header + first wrapped half to emulate truncated transport/storage.
        uint16_t key1_len = static_cast<uint16_t>(wrapped_blob[10] | (wrapped_blob[11] << 8));
        wrapped_blob.resize(XTS_BLOB_HEADER_LEN + key1_len);

        auto_key unwrapped_key;
        err = unwrap_xts_blob(wrapping_priv_key, wrapped_blob, unwrapped_key);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Same malformed-header rejection path for masked (device-exported) XTS blobs.
TEST_F(azihsm_aes_xts, unmask_malformed_xts_blob_header_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);
        auto masked_blob = get_masked_blob_for_key(key.get());
        ASSERT_FALSE(masked_blob.empty());

        masked_blob[0] ^= 0xFF;

        azihsm_buffer masked_key_buf{ masked_blob.data(), static_cast<uint32_t>(masked_blob.size()) };
        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_AES_XTS,
            &masked_key_buf,
            unmasked_key.get_ptr()
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Masked blob parser must also enforce internal length consistency.
TEST_F(azihsm_aes_xts, unmask_xts_blob_length_mismatch_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);
        auto masked_blob = get_masked_blob_for_key(key.get());
        ASSERT_FALSE(masked_blob.empty());

        // Bump key2 length LSB (header[12]) so header-declared sizes exceed payload.
        masked_blob[12] = static_cast<uint8_t>(masked_blob[12] + 1);

        azihsm_buffer masked_key_buf{ masked_blob.data(), static_cast<uint32_t>(masked_blob.size()) };
        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_AES_XTS,
            &masked_key_buf,
            unmasked_key.get_ptr()
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Unmask path requires both encoded halves; one-half blobs are invalid.
TEST_F(azihsm_aes_xts, unmask_xts_blob_missing_second_half_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);
        auto masked_blob = get_masked_blob_for_key(key.get());
        ASSERT_FALSE(masked_blob.empty());

        // Same truncation pattern as unwrap case, but through masked-key parser.
        uint16_t key1_len = static_cast<uint16_t>(masked_blob[10] | (masked_blob[11] << 8));
        masked_blob.resize(XTS_BLOB_HEADER_LEN + key1_len);

        azihsm_buffer masked_key_buf{ masked_blob.data(), static_cast<uint32_t>(masked_blob.size()) };
        auto_key unmasked_key;
        auto err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_AES_XTS,
            &masked_key_buf,
            unmasked_key.get_ptr()
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Both halves must describe compatible key properties (size/flags/etc.); mismatch is rejected.
TEST_F(azihsm_aes_xts, unwrap_xts_blob_mismatched_half_properties_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key wrapping_priv_key;
        auto_key wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Deliberately use mismatched half sizes (256-bit and 128-bit).
        auto wrapped_blob = build_xts_wrapped_blob(
            wrapping_pub_key,
            std::vector<uint8_t>(32, 0x51),
            std::vector<uint8_t>(16, 0x52)
        );
        ASSERT_FALSE(wrapped_blob.empty());

        auto_key unwrapped_key;
        err = unwrap_xts_blob(wrapping_priv_key, wrapped_blob, unwrapped_key);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// ==================== Streaming Lifecycle and Context Rules ====================

// Defensive API behavior: obvious invalid context handles should be rejected consistently.
TEST_F(azihsm_aes_xts, streaming_invalid_context_handles_are_rejected)
{
    uint8_t data[128] = { 0x11 };
    azihsm_buffer input{ data, sizeof(data) };
    azihsm_buffer output{ nullptr, 0 };

    auto err = azihsm_crypt_encrypt_update(0xDEADBEEF, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = azihsm_crypt_decrypt_update(0xDEADBEEF, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = azihsm_crypt_encrypt_finish(0xDEADBEEF, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = azihsm_crypt_decrypt_finish(0xDEADBEEF, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

// Prevent cross-wiring APIs: encrypt context must not be accepted by decrypt operations.
TEST_F(azihsm_aes_xts, streaming_operation_mismatch_on_context_is_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x6A, 128);

        auto_ctx enc_ctx;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), enc_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t block[128] = { 0x41 };
        azihsm_buffer input{ block, sizeof(block) };
        azihsm_buffer output{ nullptr, 0 };

        err = azihsm_crypt_decrypt_update(enc_ctx, &input, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);

        err = azihsm_crypt_decrypt_finish(enc_ctx, &output);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);

        // Original encrypt context remains valid for its matching finish call.
        err = azihsm_crypt_encrypt_finish(enc_ctx, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(output.len, 0u);
    });
}

// Clarifies edge behavior: XTS finish-without-update is valid and produces zero bytes.
TEST_F(azihsm_aes_xts, streaming_finish_without_update_behavior)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_xts_key(session, 512);

        azihsm_algo_aes_xts_params xts_params{};
        azihsm_algo crypt_algo{};
        init_xts_algo(crypt_algo, xts_params, AZIHSM_ALGO_ID_AES_XTS, 0x6B, 128);

        auto_ctx enc_ctx;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), enc_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer enc_finish{ nullptr, 0 };
        // No update calls: finish should still close context cleanly.
        err = azihsm_crypt_encrypt_finish(enc_ctx, &enc_finish);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(enc_finish.len, 0u);

        auto_ctx dec_ctx;
        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), dec_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer dec_finish{ nullptr, 0 };
        // Same expectation for decrypt path with an untouched context.
        err = azihsm_crypt_decrypt_finish(dec_ctx, &dec_finish);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(dec_finish.len, 0u);
    });
}
