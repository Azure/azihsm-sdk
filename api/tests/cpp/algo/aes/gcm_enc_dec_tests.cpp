// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <algorithm>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>
#include <string>
#include <functional>

#include "handle/key_handle.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_ctx.hpp"
#include "utils/auto_key.hpp"

class azihsm_aes_gcm : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    static void with_unwrapped_aes_gcm_key(
        azihsm_handle session,
        const std::function<void(azihsm_handle)> &fn
    )
    {
        azihsm_algo rsa_keygen_algo{};
        rsa_keygen_algo.id = AZIHSM_ALGO_ID_RSA_KEY_UNWRAPPING_KEY_PAIR_GEN;
        rsa_keygen_algo.params = nullptr;
        rsa_keygen_algo.len = 0;

        azihsm_key_kind rsa_kind = AZIHSM_KEY_KIND_RSA;
        azihsm_key_class priv_class = AZIHSM_KEY_CLASS_PRIVATE;
        azihsm_key_class pub_class = AZIHSM_KEY_CLASS_PUBLIC;
        uint32_t rsa_bits = 2048;
        bool is_session = false;
        bool can_wrap = true;
        bool can_unwrap = true;

        std::vector<azihsm_key_prop> priv_props_vec = {
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &rsa_bits, sizeof(rsa_bits) },
            { AZIHSM_KEY_PROP_ID_CLASS, &priv_class, sizeof(priv_class) },
            { AZIHSM_KEY_PROP_ID_KIND, &rsa_kind, sizeof(rsa_kind) },
            { AZIHSM_KEY_PROP_ID_SESSION, &is_session, sizeof(is_session) },
            { AZIHSM_KEY_PROP_ID_UNWRAP, &can_unwrap, sizeof(can_unwrap) }
        };

        std::vector<azihsm_key_prop> pub_props_vec = {
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &rsa_bits, sizeof(rsa_bits) },
            { AZIHSM_KEY_PROP_ID_CLASS, &pub_class, sizeof(pub_class) },
            { AZIHSM_KEY_PROP_ID_KIND, &rsa_kind, sizeof(rsa_kind) },
            { AZIHSM_KEY_PROP_ID_SESSION, &is_session, sizeof(is_session) },
            { AZIHSM_KEY_PROP_ID_WRAP, &can_wrap, sizeof(can_wrap) }
        };

        azihsm_key_prop_list priv_prop_list{
            priv_props_vec.data(),
            static_cast<uint32_t>(priv_props_vec.size())
        };

        azihsm_key_prop_list pub_prop_list{
            pub_props_vec.data(),
            static_cast<uint32_t>(pub_props_vec.size())
        };

        auto_key wrapping_priv_key;
        auto_key wrapping_pub_key;

        azihsm_status err = azihsm_key_gen_pair(
            session,
            &rsa_keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(wrapping_priv_key, 0);
        ASSERT_NE(wrapping_pub_key, 0);

        std::vector<uint8_t> local_aes_gcm_key = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };

        azihsm_algo_rsa_pkcs_oaep_params oaep_params{};
        oaep_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
        oaep_params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256;
        oaep_params.label = nullptr;

        azihsm_algo_rsa_aes_wrap_params wrap_params{};
        wrap_params.oaep_params = &oaep_params;
        wrap_params.aes_key_bits = 256;

        azihsm_algo wrap_algo{};
        wrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_WRAP;
        wrap_algo.params = &wrap_params;
        wrap_algo.len = sizeof(wrap_params);

        azihsm_buffer local_key_buf{};
        local_key_buf.ptr = local_aes_gcm_key.data();
        local_key_buf.len = static_cast<uint32_t>(local_aes_gcm_key.size());

        azihsm_buffer wrapped_buf{};
        wrapped_buf.ptr = nullptr;
        wrapped_buf.len = 0;

        err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &local_key_buf, &wrapped_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(wrapped_buf.len, 0);

        std::vector<uint8_t> wrapped_data(wrapped_buf.len);
        wrapped_buf.ptr = wrapped_data.data();

        err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &local_key_buf, &wrapped_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_algo_rsa_aes_key_wrap_params unwrap_params{};
        unwrap_params.aes_key_bits = 256;
        unwrap_params.oaep_params = &oaep_params;

        azihsm_algo unwrap_algo{};
        unwrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP;
        unwrap_algo.params = &unwrap_params;
        unwrap_algo.len = sizeof(unwrap_params);

        azihsm_key_kind aes_kind = AZIHSM_KEY_KIND_AES_GCM;
        azihsm_key_class aes_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t aes_bits = 256;
        bool aes_is_session = true;
        bool can_encrypt = true;
        bool can_decrypt = true;

        std::vector<azihsm_key_prop> unwrap_props_vec = {
            { AZIHSM_KEY_PROP_ID_KIND, &aes_kind, sizeof(aes_kind) },
            { AZIHSM_KEY_PROP_ID_CLASS, &aes_class, sizeof(aes_class) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &aes_bits, sizeof(aes_bits) },
            { AZIHSM_KEY_PROP_ID_SESSION, &aes_is_session, sizeof(aes_is_session) },
            { AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) },
            { AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) }
        };

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
            wrapping_priv_key,
            &wrapped_key_buf,
            &unwrap_prop_list,
            unwrapped_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unwrapped_key, 0);

        fn(unwrapped_key.get());
    }

    static void for_each_aes_gcm_key(
        azihsm_handle session,
        const std::function<void(azihsm_handle)> &fn
    )
    {
        auto key = generate_aes_gcm_key(session, 256);
        fn(key.get());
        with_unwrapped_aes_gcm_key(session, fn);
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
        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(CryptOperation::Encrypt, key_handle, &crypt_algo, plaintext, plaintext_len, ciphertext));

        // Ciphertext should be same length as plaintext for GCM (no padding)
        ASSERT_EQ(ciphertext.size(), plaintext_len);

        // Save the tag from encryption for decryption
        uint8_t saved_tag[16];
        std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));

        // Reset IV and set tag for decryption
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

        // Decrypt
        std::vector<uint8_t> decrypted;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(CryptOperation::Decrypt, key_handle, &crypt_algo, ciphertext.data(), ciphertext.size(), decrypted));

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
        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::streaming_crypt(CryptOperation::Encrypt, key_handle, &crypt_algo, plaintext, plaintext_len, chunk_size, ciphertext));
        ASSERT_EQ(ciphertext.size(), plaintext_len);

        // Save the tag from encryption for decryption
        uint8_t saved_tag[16];
        std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));

        // Reset IV and set tag for decryption
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

        // Decrypt
        std::vector<uint8_t> decrypted;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::streaming_crypt(CryptOperation::Decrypt, key_handle, &crypt_algo, ciphertext.data(), ciphertext.size(), chunk_size, decrypted));

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

// ==================== Correctness Coverage ====================

// Validate single-shot AES-GCM without AAD across key sizes and data sizes.
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

// Validate single-shot AES-GCM with AAD across key sizes and data sizes.
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

// Validate streaming AES-GCM without AAD across key sizes.
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

// Validate streaming AES-GCM with AAD across key sizes.
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

// Validate streaming AES-GCM across multiple chunk sizes.
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

// Validate AES-GCM handles empty plaintext and tag generation.
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

// Validate AES-GCM empty plaintext with various AAD sizes and AAD mismatch failure.
TEST_F(azihsm_aes_gcm, empty_plaintext_with_aad_sizes)
{
    std::vector<size_t> aad_sizes = { 1, 15, 16, 17, 31, 32, 33 };

    part_list_.for_each_session([&](azihsm_handle session) {
        for_each_aes_gcm_key(session, [&](azihsm_handle key_handle) {
            for (size_t aad_len : aad_sizes)
            {
                SCOPED_TRACE("aad_len=" + std::to_string(aad_len));

                std::vector<uint8_t> aad(aad_len);
                for (size_t i = 0; i < aad.size(); ++i)
                {
                    aad[i] = static_cast<uint8_t>(0xA0 + (i & 0x3F));
                }

                azihsm_buffer aad_buf{ aad.data(), static_cast<uint32_t>(aad.size()) };

                uint8_t iv[12] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
                                   0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0 };

                azihsm_algo_aes_gcm_params gcm_params{};
                std::memcpy(gcm_params.iv, iv, sizeof(iv));
                std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
                gcm_params.aad = &aad_buf;

                azihsm_algo crypt_algo{};
                crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
                crypt_algo.params = &gcm_params;
                crypt_algo.len = sizeof(gcm_params);

                azihsm_buffer input{ nullptr, 0 };
                azihsm_buffer output{ nullptr, 0 };

                auto err = azihsm_crypt_encrypt(&crypt_algo, key_handle, &input, &output);
                if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
                {
                    ASSERT_EQ(output.len, 0u);
                    err = azihsm_crypt_encrypt(&crypt_algo, key_handle, &input, &output);
                }
                ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

                uint8_t saved_tag[16];
                std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));

                std::memcpy(gcm_params.iv, iv, sizeof(iv));
                std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

                azihsm_buffer cipher_buf{ nullptr, 0 };
                azihsm_buffer plain_buf{ nullptr, 0 };

                err = azihsm_crypt_decrypt(&crypt_algo, key_handle, &cipher_buf, &plain_buf);
                if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
                {
                    ASSERT_EQ(plain_buf.len, 0u);
                    err = azihsm_crypt_decrypt(&crypt_algo, key_handle, &cipher_buf, &plain_buf);
                }
                ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

                std::vector<uint8_t> aad_bad = aad;
                aad_bad[0] ^= 0xFF;
                azihsm_buffer aad_bad_buf{ aad_bad.data(), static_cast<uint32_t>(aad_bad.size()) };
                gcm_params.aad = &aad_bad_buf;

                std::memcpy(gcm_params.iv, iv, sizeof(iv));
                std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

                err = azihsm_crypt_decrypt(&crypt_algo, key_handle, &cipher_buf, &plain_buf);
                if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
                {
                    ASSERT_EQ(plain_buf.len, 0u);
                    err = azihsm_crypt_decrypt(&crypt_algo, key_handle, &cipher_buf, &plain_buf);
                }
                ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
            }
        });
    });
}

// Validate AES-GCM empty plaintext with an empty AAD buffer (non-null, zero length).
TEST_F(azihsm_aes_gcm, empty_plaintext_with_empty_aad_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        for_each_aes_gcm_key(session, [&](azihsm_handle key_handle) {
            uint8_t iv[12] = { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                               0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C };

            std::vector<uint8_t> aad(1, 0x5A);
            azihsm_buffer aad_buf{ aad.data(), 0 };

            azihsm_algo_aes_gcm_params gcm_params{};
            std::memcpy(gcm_params.iv, iv, sizeof(iv));
            std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
            gcm_params.aad = &aad_buf;

            azihsm_algo crypt_algo{};
            crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
            crypt_algo.params = &gcm_params;
            crypt_algo.len = sizeof(gcm_params);

            azihsm_buffer input{ nullptr, 0 };
            azihsm_buffer output{ nullptr, 0 };

            auto err = azihsm_crypt_encrypt(&crypt_algo, key_handle, &input, &output);
            if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
            {
                ASSERT_EQ(output.len, 0u);
                err = azihsm_crypt_encrypt(&crypt_algo, key_handle, &input, &output);
            }
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            uint8_t saved_tag[16];
            std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));

            std::memcpy(gcm_params.iv, iv, sizeof(iv));
            std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

            azihsm_buffer cipher_buf{ nullptr, 0 };
            azihsm_buffer plain_buf{ nullptr, 0 };

            err = azihsm_crypt_decrypt(&crypt_algo, key_handle, &cipher_buf, &plain_buf);
            if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
            {
                ASSERT_EQ(plain_buf.len, 0u);
                err = azihsm_crypt_decrypt(&crypt_algo, key_handle, &cipher_buf, &plain_buf);
            }
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        });
    });
}

// Validate streaming AES-GCM empty plaintext with AAD and tag verification.
TEST_F(azihsm_aes_gcm, streaming_empty_plaintext_with_aad)
{
    part_list_.for_each_session([](azihsm_handle session) {
        for_each_aes_gcm_key(session, [&](azihsm_handle key_handle) {
            uint8_t iv[12] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                               0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C };

            std::vector<uint8_t> aad = { 0x01, 0x02, 0x03, 0x04, 0x05 };
            azihsm_buffer aad_buf{ aad.data(), static_cast<uint32_t>(aad.size()) };

            azihsm_algo_aes_gcm_params gcm_params{};
            std::memcpy(gcm_params.iv, iv, sizeof(iv));
            std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
            gcm_params.aad = &aad_buf;

            azihsm_algo crypt_algo{};
            crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
            crypt_algo.params = &gcm_params;
            crypt_algo.len = sizeof(gcm_params);

            std::vector<uint8_t> ciphertext;
            ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::streaming_crypt(
                CryptOperation::Encrypt,
                key_handle,
                &crypt_algo,
                nullptr,
                0,
                16,
                ciphertext
            ));
            ASSERT_EQ(ciphertext.size(), 0u);

            uint8_t saved_tag[16];
            std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));

            std::memcpy(gcm_params.iv, iv, sizeof(iv));
            std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

            std::vector<uint8_t> decrypted;
            ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::streaming_crypt(
                CryptOperation::Decrypt,
                key_handle,
                &crypt_algo,
                nullptr,
                0,
                16,
                decrypted
            ));
            ASSERT_EQ(decrypted.size(), 0u);
        });
    });
}

// Validate AES-GCM empty plaintext fails on wrong tag.
TEST_F(azihsm_aes_gcm, empty_plaintext_wrong_tag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        for_each_aes_gcm_key(session, [&](azihsm_handle key_handle) {
            uint8_t iv[12] = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
                               0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C };

            azihsm_algo_aes_gcm_params gcm_params{};
            std::memcpy(gcm_params.iv, iv, sizeof(iv));
            std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
            gcm_params.aad = nullptr;

            azihsm_algo crypt_algo{};
            crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
            crypt_algo.params = &gcm_params;
            crypt_algo.len = sizeof(gcm_params);

            azihsm_buffer input{ nullptr, 0 };
            azihsm_buffer output{ nullptr, 0 };

            auto err = azihsm_crypt_encrypt(&crypt_algo, key_handle, &input, &output);
            if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
            {
                ASSERT_EQ(output.len, 0u);
                err = azihsm_crypt_encrypt(&crypt_algo, key_handle, &input, &output);
            }
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            std::memcpy(gcm_params.iv, iv, sizeof(iv));
            gcm_params.tag[0] ^= 0xFF;

            azihsm_buffer cipher_buf{ nullptr, 0 };
            azihsm_buffer plain_buf{ nullptr, 0 };

            err = azihsm_crypt_decrypt(&crypt_algo, key_handle, &cipher_buf, &plain_buf);
            if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
            {
                ASSERT_EQ(plain_buf.len, 0u);
                err = azihsm_crypt_decrypt(&crypt_algo, key_handle, &cipher_buf, &plain_buf);
            }
            ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        });
    });
}

// Validate different IVs produce different ciphertexts.
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

// Validate streaming AES-GCM with 4KB payload.
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
        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::streaming_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            256,
            ciphertext
        ));

        // Save tag for decryption
        uint8_t saved_tag[16];
        std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));

        // Reset IV and set tag for decryption
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

        // Decrypt
        std::vector<uint8_t> decrypted;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::streaming_crypt(
            CryptOperation::Decrypt,
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            256,
            decrypted
        ));

        ASSERT_EQ(decrypted.size(), plaintext.size());
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
    });
}

// Validate streaming output matches single-shot for identical inputs.
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

        std::vector<uint8_t> single_shot_ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo_single,
            plaintext.data(),
            plaintext.size(),
            single_shot_ciphertext
        ));

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

        std::vector<uint8_t> streaming_ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::streaming_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo_streaming,
            plaintext.data(),
            plaintext.size(),
            17,
            streaming_ciphertext
        ));

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


// Validate streaming AES-GCM with 8KB payload.
TEST_F(azihsm_aes_gcm, large_data_streaming_8k)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x22 };
        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        // Test with larger data (8KB)
        std::vector<uint8_t> plaintext(8192);
        for (size_t i = 0; i < plaintext.size(); ++i)
        {
            plaintext[i] = static_cast<uint8_t>(i & 0xFF);
        }

        // Encrypt
        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::streaming_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            256,
            ciphertext
        ));

        // Save tag for decryption
        uint8_t saved_tag[16];
        std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));

        // Reset IV and set tag for decryption
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

        // Decrypt
        std::vector<uint8_t> decrypted;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::streaming_crypt(
            CryptOperation::Decrypt,
            key.get(),
            &crypt_algo,
            ciphertext.data(),
            ciphertext.size(),
            256,
            decrypted
        ));

        ASSERT_EQ(decrypted.size(), plaintext.size());
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);
    });
}

// Validate unwrapping an AES-GCM key using RSA-AES key wrap and using it for encryption/decryption.
// This ensures the unwrapped key material is correctly transported and functional for cryptographic operations.
TEST_F(azihsm_aes_gcm, unwrap_and_encrypt_decrypt_roundtrip)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        with_unwrapped_aes_gcm_key(session, [&](azihsm_handle key_handle) {
            std::vector<uint8_t> plaintext(128, 0x5A);

            test_single_shot_roundtrip(
                key_handle,
                plaintext.data(),
                plaintext.size(),
                nullptr,
                0
            );
        });
    });
}

// Validate single-shot AES-GCM with 4KB payload.
TEST_F(azihsm_aes_gcm, large_data_single_shot)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x31 };
        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        std::vector<uint8_t> plaintext = make_incrementing_bytes(4096);

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

        uint8_t saved_tag[16];
        std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));

        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

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

TEST_F(azihsm_aes_gcm, single_shot_size_sweep_and_aad_sweep)
{
    const std::vector<size_t> plaintext_sizes = { 0, 1, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128 };
    const std::vector<size_t> aad_sizes = { 0, 1, 15, 16, 17, 31, 32 };

    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        for (auto plaintext_size : plaintext_sizes)
        {
            for (auto aad_size : aad_sizes)
            {
                SCOPED_TRACE(
                    "single_shot plaintext_size=" +
                    std::to_string(plaintext_size) +
                    " aad_size=" +
                    std::to_string(aad_size)
                );

                auto plaintext = make_incrementing_bytes(plaintext_size);
                auto aad = make_incrementing_bytes(aad_size);

                test_single_shot_roundtrip(
                    key.get(),
                    plaintext_size > 0 ? plaintext.data() : nullptr,
                    plaintext_size,
                    aad_size > 0 ? aad.data() : nullptr,
                    aad_size
                );
            }
        }
    });
}

TEST_F(azihsm_aes_gcm, streaming_size_and_chunk_sweep)
{
    const std::vector<size_t> plaintext_sizes = { 0, 1, 15, 16, 17, 63, 64, 65, 127 };
    const std::vector<size_t> aad_sizes = { 0, 1, 15, 16, 17, 31 };
    const std::vector<size_t> chunk_sizes = { 1, 2, 3, 5, 7, 8, 15, 16, 17, 31, 32, 64 };

    part_list_.for_each_session([&](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        for (auto plaintext_size : plaintext_sizes)
        {
            for (auto aad_size : aad_sizes)
            {
                auto plaintext = make_incrementing_bytes(plaintext_size);
                auto aad = make_incrementing_bytes(aad_size);

                for (auto chunk_size : chunk_sizes)
                {
                    SCOPED_TRACE(
                        "streaming plaintext_size=" +
                        std::to_string(plaintext_size) +
                        " aad_size=" +
                        std::to_string(aad_size) +
                        " chunk_size=" +
                        std::to_string(chunk_size)
                    );

                    test_streaming_roundtrip(
                        key.get(),
                        plaintext_size > 0 ? plaintext.data() : nullptr,
                        plaintext_size,
                        chunk_size,
                        aad_size > 0 ? aad.data() : nullptr,
                        aad_size
                    );
                }
            }
        }
    });
}

// ==================== Argument Validation and API Behavior ====================

// Validate AES-GCM rejects null parameters.
TEST_F(azihsm_aes_gcm, single_shot_null_params_are_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = nullptr;
        crypt_algo.len = 0;

        uint8_t plaintext[16] = { 0xAA };
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Validate AES-GCM rejects invalid key handles.
TEST_F(azihsm_aes_gcm, single_shot_invalid_key_handle_is_rejected)
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

TEST_F(azihsm_aes_gcm, single_shot_null_pointers_are_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
                           0xCD, 0xEF, 0x10, 0x32, 0x54, 0x76 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        uint8_t plaintext[16] = { 0xAA };
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(nullptr, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_encrypt(&crypt_algo, key.get(), nullptr, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt(nullptr, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), nullptr, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &input, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_gcm, single_shot_invalid_buffer_shapes_are_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA,
                           0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        uint8_t plaintext[16] = { 0xAB };
        azihsm_buffer bad_input{ nullptr, 1 };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &bad_input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        azihsm_buffer good_input{ plaintext, sizeof(plaintext) };
        azihsm_buffer bad_output{ nullptr, 1 };
        err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &good_input, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_gcm, single_shot_invalid_aad_pointer_shapes_are_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23,
                           0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

        azihsm_buffer bad_aad{ nullptr, 1 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = &bad_aad;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        uint8_t plaintext[16] = { 0xBC };
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_gcm, single_shot_invalid_algo_param_len_is_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x22, 0x44, 0x66, 0x88, 0xAA, 0xCC,
                           0xEE, 0x00, 0x11, 0x33, 0x55, 0x77 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        uint8_t plaintext[16] = { 0xCD };
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        crypt_algo.len = sizeof(gcm_params) - 1;
        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        crypt_algo.len = sizeof(gcm_params) + 1;
        err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_gcm, single_shot_invalid_key_kind_is_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto non_gcm_key = generate_aes_key(session, 256);

        uint8_t iv[12] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
                           0xDE, 0xF0, 0x21, 0x43, 0x65, 0x87 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        uint8_t plaintext[16] = { 0xDE };
        azihsm_buffer input{ plaintext, sizeof(plaintext) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, non_gcm_key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

        err = azihsm_crypt_decrypt(&crypt_algo, non_gcm_key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_aes_gcm, streaming_init_null_pointers_are_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x31, 0x41, 0x59, 0x26, 0x53, 0x58,
                           0x97, 0x93, 0x23, 0x84, 0x62, 0x64 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

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

TEST_F(azihsm_aes_gcm, streaming_init_invalid_algo_params_are_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x27, 0x18, 0x28, 0x18, 0x28, 0x45,
                           0x90, 0x45, 0x23, 0x53, 0x60, 0x28 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto_ctx ctx;

        crypt_algo.params = nullptr;
        crypt_algo.len = 0;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_gcm, streaming_init_invalid_algo_param_len_is_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x16, 0x18, 0x03, 0x39, 0x88, 0x74,
                           0x98, 0x94, 0x84, 0x82, 0x04, 0x58 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto_ctx ctx;

        crypt_algo.len = sizeof(gcm_params) - 1;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        crypt_algo.len = sizeof(gcm_params) + 1;
        err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_gcm, streaming_init_invalid_key_handle_is_rejected)
{
    uint8_t iv[12] = { 0x14, 0x14, 0x21, 0x35, 0x62, 0x37,
                       0x30, 0x95, 0x04, 0x88, 0x16, 0x88 };

    azihsm_algo_aes_gcm_params gcm_params{};
    std::memcpy(gcm_params.iv, iv, sizeof(iv));
    std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
    gcm_params.aad = nullptr;

    azihsm_algo crypt_algo{};
    crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
    crypt_algo.params = &gcm_params;
    crypt_algo.len = sizeof(gcm_params);

    auto_ctx ctx;

    auto err = azihsm_crypt_encrypt_init(&crypt_algo, 0xDEADBEEF, ctx.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

    err = azihsm_crypt_decrypt_init(&crypt_algo, 0xDEADBEEF, ctx.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST_F(azihsm_aes_gcm, streaming_init_invalid_key_kind_is_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto non_gcm_key = generate_aes_key(session, 256);

        uint8_t iv[12] = { 0x17, 0x17, 0x19, 0x99, 0x37, 0x51,
                           0x05, 0x82, 0x09, 0x74, 0x94, 0x45 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto_ctx ctx;

        auto err = azihsm_crypt_encrypt_init(&crypt_algo, non_gcm_key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

        err = azihsm_crypt_decrypt_init(&crypt_algo, non_gcm_key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_aes_gcm, streaming_update_finish_null_pointers_are_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x24, 0x68, 0x13, 0x57, 0x90, 0x12,
                           0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto_ctx enc_ctx;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), enc_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto_ctx dec_ctx;
        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), dec_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t data[16] = { 0x44 };
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

TEST_F(azihsm_aes_gcm, streaming_update_finish_invalid_buffer_shapes_are_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x42, 0x42, 0x42, 0x42, 0x10, 0x20,
                           0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto_ctx enc_ctx;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), enc_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto_ctx dec_ctx;
        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), dec_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t byte = 0x01;
        azihsm_buffer bad_input{ nullptr, 1 };
        azihsm_buffer bad_output{ nullptr, 1 };
        azihsm_buffer good_input{ &byte, 1 };
        azihsm_buffer good_output{ &byte, 1 };

        err = azihsm_crypt_encrypt_update(enc_ctx, &bad_input, &good_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_encrypt_update(enc_ctx, &good_input, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_update(dec_ctx, &bad_input, &good_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_update(dec_ctx, &good_input, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_encrypt_finish(enc_ctx, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_finish(dec_ctx, &bad_output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_gcm, streaming_invalid_aad_pointer_shapes_are_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A,
                           0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4 };

        azihsm_buffer bad_aad{ nullptr, 1 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = &bad_aad;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto_ctx ctx;

        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_aes_gcm, single_shot_output_buffer_sizing_behavior)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0xAA, 0x55, 0xAA, 0x55, 0x00, 0x11,
                           0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto plaintext = make_incrementing_bytes(31);
        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(output.len, plaintext.size());

        std::vector<uint8_t> ciphertext(output.len);
        output.ptr = ciphertext.data();
        err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(output.len, plaintext.size());

        std::vector<uint8_t> too_small_buf(plaintext.size() - 1);
        azihsm_buffer too_small{ too_small_buf.data(), static_cast<uint32_t>(too_small_buf.size()) };
        err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &too_small);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(too_small.len, plaintext.size());

        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        azihsm_buffer cipher_input{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        azihsm_buffer plain_output{ nullptr, 0 };

        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_input, &plain_output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(plain_output.len, plaintext.size());

        std::vector<uint8_t> decrypted(plain_output.len);
        plain_output.ptr = decrypted.data();
        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_input, &plain_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(plain_output.len, plaintext.size());

        std::vector<uint8_t> dec_too_small_buf(plaintext.size() - 1);
        azihsm_buffer dec_too_small{ dec_too_small_buf.data(), static_cast<uint32_t>(dec_too_small_buf.size()) };
        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_input, &dec_too_small);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(dec_too_small.len, plaintext.size());
    });
}

TEST_F(azihsm_aes_gcm, streaming_update_output_buffer_sizing_behavior)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x7F, 0x6E, 0x5D, 0x4C, 0x3B, 0x2A,
                           0x19, 0x08, 0x17, 0x26, 0x35, 0x44 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);
        auto plaintext = make_incrementing_bytes(17);
        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };

        auto run_update_and_finish_check = [&](azihsm_buffer update_output) {
            auto_ctx enc_ctx;
            auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), enc_ctx.get_ptr());
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            err = azihsm_crypt_encrypt_update(enc_ctx, &input, &update_output);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(update_output.len, 0u);

            // For GCM streaming, update() emits no ciphertext and finish() emits all bytes.
            azihsm_buffer finish_query{ nullptr, 0 };
            err = azihsm_crypt_encrypt_finish(enc_ctx, &finish_query);
            ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            ASSERT_EQ(finish_query.len, plaintext.size());
        };

        // Query form: null pointer + zero length.
        azihsm_buffer query_output{ nullptr, 0 };
        run_update_and_finish_check(query_output);

        // Non-zero provided output buffer is still accepted; update() should write 0 bytes.
        uint8_t one_byte = 0x00;
        azihsm_buffer tiny_output{ &one_byte, 1 };
        run_update_and_finish_check(tiny_output);

        std::vector<uint8_t> larger_buf(64, 0x00);
        azihsm_buffer larger_output{ larger_buf.data(), static_cast<uint32_t>(larger_buf.size()) };
        run_update_and_finish_check(larger_output);
    });
}

// For GCM streaming, update() buffers only; finish() emits all ciphertext.
TEST_F(azihsm_aes_gcm, streaming_finish_output_buffer_sizing_behavior)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02,
                           0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto_ctx ctx;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto plaintext = make_incrementing_bytes(23);
        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        azihsm_buffer update_output{ nullptr, 0 };
        err = azihsm_crypt_encrypt_update(ctx, &input, &update_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(update_output.len, 0u);

        azihsm_buffer finish_query{ nullptr, 0 };
        err = azihsm_crypt_encrypt_finish(ctx, &finish_query);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(finish_query.len, plaintext.size());

        std::vector<uint8_t> small_output(plaintext.size() - 1);
        azihsm_buffer finish_small{ small_output.data(), static_cast<uint32_t>(small_output.size()) };
        err = azihsm_crypt_encrypt_finish(ctx, &finish_small);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_EQ(finish_small.len, plaintext.size());

        std::vector<uint8_t> exact_output(plaintext.size());
        azihsm_buffer finish_exact{ exact_output.data(), static_cast<uint32_t>(exact_output.size()) };
        err = azihsm_crypt_encrypt_finish(ctx, &finish_exact);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(finish_exact.len, plaintext.size());
    });
}

// ==================== Malformed Input and Authentication Rejection ====================

// Validate AES-GCM decryption fails on wrong tag.
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

        std::vector<uint8_t> plaintext = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        azihsm_buffer output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

        std::vector<uint8_t> ciphertext(output.len);
        output.ptr = ciphertext.data();
        err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        gcm_params.tag[0] ^= 0xFF;
        std::memcpy(gcm_params.iv, iv, sizeof(iv));

        azihsm_buffer cipher_buf{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        azihsm_buffer plain_buf{ nullptr, 0 };

        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_buf, &plain_buf);
        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            std::vector<uint8_t> decrypted(plain_buf.len);
            plain_buf.ptr = decrypted.data();
            err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &cipher_buf, &plain_buf);
        }
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_aes_gcm, decrypt_tampered_ciphertext_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                           0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto plaintext = make_incrementing_bytes(32);
        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        ciphertext[0] ^= 0x80;

        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        azihsm_buffer input{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };

        auto err = single_shot_status_with_sizing(
            CryptOperation::Decrypt,
            &crypt_algo,
            key.get(),
            &input
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_aes_gcm, decrypt_tampered_aad_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                           0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C };

        std::vector<uint8_t> aad = { 0xA1, 0xB2, 0xC3, 0xD4, 0xE5 };
        azihsm_buffer aad_buf{ aad.data(), static_cast<uint32_t>(aad.size()) };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = &aad_buf;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto plaintext = make_incrementing_bytes(24);
        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        auto tampered_aad = aad;
        tampered_aad[0] ^= 0x01;
        azihsm_buffer tampered_aad_buf{ tampered_aad.data(), static_cast<uint32_t>(tampered_aad.size()) };

        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        gcm_params.aad = &tampered_aad_buf;

        azihsm_buffer input{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        auto err = single_shot_status_with_sizing(
            CryptOperation::Decrypt,
            &crypt_algo,
            key.get(),
            &input
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_aes_gcm, decrypt_wrong_iv_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
                           0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto plaintext = make_incrementing_bytes(19);
        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        uint8_t wrong_iv[12];
        std::memcpy(wrong_iv, iv, sizeof(iv));
        wrong_iv[0] ^= 0xFF;
        std::memcpy(gcm_params.iv, wrong_iv, sizeof(wrong_iv));

        azihsm_buffer input{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        auto err = single_shot_status_with_sizing(
            CryptOperation::Decrypt,
            &crypt_algo,
            key.get(),
            &input
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_aes_gcm, decrypt_wrong_key_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto encrypt_key = generate_aes_gcm_key(session, 256);
        auto decrypt_key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
                           0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto plaintext = make_incrementing_bytes(27);
        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            encrypt_key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        azihsm_buffer input{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };

        auto err = single_shot_status_with_sizing(
            CryptOperation::Decrypt,
            &crypt_algo,
            decrypt_key.get(),
            &input
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_aes_gcm, decrypt_truncated_ciphertext_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
                           0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto plaintext = make_incrementing_bytes(33);
        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        ASSERT_GT(ciphertext.size(), 1u);
        ciphertext.resize(ciphertext.size() - 1);

        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        azihsm_buffer input{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        auto err = single_shot_status_with_sizing(
            CryptOperation::Decrypt,
            &crypt_algo,
            key.get(),
            &input
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_aes_gcm, decrypt_missing_tag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
                           0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto plaintext = make_incrementing_bytes(20);
        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &crypt_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        // Simulate a missing/omitted tag by clearing tag bytes before decrypt.
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));

        azihsm_buffer input{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        auto err = single_shot_status_with_sizing(
            CryptOperation::Decrypt,
            &crypt_algo,
            key.get(),
            &input
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// ==================== Streaming Lifecycle and Context Rules ====================

TEST_F(azihsm_aes_gcm, streaming_invalid_context_handles_are_rejected)
{
    uint8_t data[16] = { 0x11 };
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

TEST_F(azihsm_aes_gcm, streaming_operation_mismatch_on_context_is_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
                           0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto_ctx ctx;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t byte = 0x41;
        azihsm_buffer input{ &byte, 1 };
        azihsm_buffer output{ nullptr, 0 };

        err = azihsm_crypt_decrypt_update(ctx, &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

        err = azihsm_crypt_decrypt_finish(ctx, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);

        err = streaming_finish_status_with_sizing(CryptOperation::Encrypt, ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Zero-length update should not emit output, but finish must still compute/verify the tag.
TEST_F(azihsm_aes_gcm, streaming_zero_length_update_is_noop_until_finish)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
                           0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto_ctx enc_ctx;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), enc_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint8_t dummy = 0;
        azihsm_buffer empty_input{ &dummy, 0 };
        azihsm_buffer update_output{ nullptr, 0 };

        err = azihsm_crypt_encrypt_update(enc_ctx, &empty_input, &update_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(update_output.len, 0u);

        azihsm_buffer finish_output{ nullptr, 0 };
        err = azihsm_crypt_encrypt_finish(enc_ctx, &finish_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(finish_output.len, 0u);

        bool tag_has_data = false;
        for (auto byte : gcm_params.tag)
        {
            if (byte != 0)
            {
                tag_has_data = true;
                break;
            }
        }
        ASSERT_TRUE(tag_has_data);

        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        auto_ctx dec_ctx;
        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), dec_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer dec_update_output{ nullptr, 0 };
        err = azihsm_crypt_decrypt_update(dec_ctx, &empty_input, &dec_update_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(dec_update_output.len, 0u);

        azihsm_buffer dec_finish_output{ nullptr, 0 };
        err = azihsm_crypt_decrypt_finish(dec_ctx, &dec_finish_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(dec_finish_output.len, 0u);
    });
}

// AAD-only streaming flow (no plaintext/ciphertext) should still authenticate via tag.
TEST_F(azihsm_aes_gcm, streaming_finish_without_update_with_aad_only)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
                           0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC };

        std::vector<uint8_t> aad = { 0x10, 0x20, 0x30, 0x40, 0x50 };
        azihsm_buffer aad_buf{ aad.data(), static_cast<uint32_t>(aad.size()) };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = &aad_buf;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto_ctx enc_ctx;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), enc_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer enc_finish_output{ nullptr, 0 };
        err = azihsm_crypt_encrypt_finish(enc_ctx, &enc_finish_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(enc_finish_output.len, 0u);

        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        auto_ctx dec_ctx;
        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), dec_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer dec_finish_output{ nullptr, 0 };
        err = azihsm_crypt_decrypt_finish(dec_ctx, &dec_finish_output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(dec_finish_output.len, 0u);
    });
}

// ==================== GCM-Specific Integrity and AAD Semantics ====================

// Empty-plaintext single-shot flow with AAD should authenticate via tag and round-trip.
TEST_F(azihsm_aes_gcm, aad_only_message_authentication_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
                           0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC };
        std::vector<uint8_t> aad = { 0x01, 0x03, 0x05, 0x07, 0x09 };
        azihsm_buffer aad_buf{ aad.data(), static_cast<uint32_t>(aad.size()) };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = &aad_buf;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        uint8_t dummy = 0;
        azihsm_buffer empty_input{ &dummy, 0 };
        azihsm_buffer enc_output{ nullptr, 0 };

        auto err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &empty_input, &enc_output);
        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            ASSERT_EQ(enc_output.len, 0u);
            err = azihsm_crypt_encrypt(&crypt_algo, key.get(), &empty_input, &enc_output);
        }
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        bool tag_has_data = false;
        for (auto byte : gcm_params.tag)
        {
            if (byte != 0)
            {
                tag_has_data = true;
                break;
            }
        }
        ASSERT_TRUE(tag_has_data);

        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        azihsm_buffer dec_output{ nullptr, 0 };
        err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &empty_input, &dec_output);
        if (err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
        {
            ASSERT_EQ(dec_output.len, 0u);
            err = azihsm_crypt_decrypt(&crypt_algo, key.get(), &empty_input, &dec_output);
        }
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Empty-plaintext streaming flow with AAD should authenticate via tag at finish.
TEST_F(azihsm_aes_gcm, streaming_aad_only_message_authentication_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        uint8_t iv[12] = { 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6,
                           0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC };
        std::vector<uint8_t> aad = { 0x10, 0x20, 0x30, 0x40 };
        azihsm_buffer aad_buf{ aad.data(), static_cast<uint32_t>(aad.size()) };

        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = &aad_buf;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        auto_ctx enc_ctx;
        auto err = azihsm_crypt_encrypt_init(&crypt_algo, key.get(), enc_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer enc_finish{ nullptr, 0 };
        err = azihsm_crypt_encrypt_finish(enc_ctx, &enc_finish);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(enc_finish.len, 0u);

        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        auto_ctx dec_ctx;
        err = azihsm_crypt_decrypt_init(&crypt_algo, key.get(), dec_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer dec_finish{ nullptr, 0 };
        err = azihsm_crypt_decrypt_finish(dec_ctx, &dec_finish);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(dec_finish.len, 0u);
    });
}

// AAD influences authentication tag, even when IV/plaintext are unchanged.
TEST_F(azihsm_aes_gcm, same_plaintext_iv_different_aad_changes_tag)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        auto plaintext = make_incrementing_bytes(32);
        uint8_t iv[12] = { 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
                           0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC };

        std::vector<uint8_t> aad1 = { 0x01, 0x02, 0x03 };
        std::vector<uint8_t> aad2 = { 0x01, 0x02, 0x04 };
        azihsm_buffer aad_buf1{ aad1.data(), static_cast<uint32_t>(aad1.size()) };
        azihsm_buffer aad_buf2{ aad2.data(), static_cast<uint32_t>(aad2.size()) };

        azihsm_algo_aes_gcm_params params1{};
        std::memcpy(params1.iv, iv, sizeof(iv));
        std::memset(params1.tag, 0, sizeof(params1.tag));
        params1.aad = &aad_buf1;

        azihsm_algo algo1{};
        algo1.id = AZIHSM_ALGO_ID_AES_GCM;
        algo1.params = &params1;
        algo1.len = sizeof(params1);

        std::vector<uint8_t> ct1;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &algo1,
            plaintext.data(),
            plaintext.size(),
            ct1
        ));

        azihsm_algo_aes_gcm_params params2{};
        std::memcpy(params2.iv, iv, sizeof(iv));
        std::memset(params2.tag, 0, sizeof(params2.tag));
        params2.aad = &aad_buf2;

        azihsm_algo algo2{};
        algo2.id = AZIHSM_ALGO_ID_AES_GCM;
        algo2.params = &params2;
        algo2.len = sizeof(params2);

        std::vector<uint8_t> ct2;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &algo2,
            plaintext.data(),
            plaintext.size(),
            ct2
        ));

        ASSERT_EQ(ct1.size(), ct2.size());
        ASSERT_EQ(std::memcmp(ct1.data(), ct2.data(), ct1.size()), 0);
        ASSERT_NE(std::memcmp(params1.tag, params2.tag, sizeof(params1.tag)), 0);
    });
}

// With same key/IV/plaintext and no AAD, GCM output is deterministic (ciphertext + tag).
TEST_F(azihsm_aes_gcm, same_key_iv_plaintext_produces_same_ciphertext_and_tag)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);

        auto plaintext = make_incrementing_bytes(29);
        uint8_t iv[12] = { 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,
                           0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC };

        azihsm_algo_aes_gcm_params params1{};
        std::memcpy(params1.iv, iv, sizeof(iv));
        std::memset(params1.tag, 0, sizeof(params1.tag));
        params1.aad = nullptr;

        azihsm_algo algo1{};
        algo1.id = AZIHSM_ALGO_ID_AES_GCM;
        algo1.params = &params1;
        algo1.len = sizeof(params1);

        std::vector<uint8_t> ct1;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &algo1,
            plaintext.data(),
            plaintext.size(),
            ct1
        ));

        azihsm_algo_aes_gcm_params params2{};
        std::memcpy(params2.iv, iv, sizeof(iv));
        std::memset(params2.tag, 0, sizeof(params2.tag));
        params2.aad = nullptr;

        azihsm_algo algo2{};
        algo2.id = AZIHSM_ALGO_ID_AES_GCM;
        algo2.params = &params2;
        algo2.len = sizeof(params2);

        std::vector<uint8_t> ct2;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &algo2,
            plaintext.data(),
            plaintext.size(),
            ct2
        ));

        ASSERT_EQ(ct1.size(), ct2.size());
        ASSERT_EQ(std::memcmp(ct1.data(), ct2.data(), ct1.size()), 0);
        ASSERT_EQ(std::memcmp(params1.tag, params2.tag, sizeof(params1.tag)), 0);
    });
}

// Streaming and single-shot should produce identical ciphertext and tag for same inputs/AAD.
TEST_F(azihsm_aes_gcm, streaming_consistency_with_single_shot_with_aad)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);
        auto plaintext = make_incrementing_bytes(47);
        std::vector<uint8_t> aad = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
        azihsm_buffer aad_buf{ aad.data(), static_cast<uint32_t>(aad.size()) };

        uint8_t iv[12] = { 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6,
                           0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC };

        azihsm_algo_aes_gcm_params single_params{};
        std::memcpy(single_params.iv, iv, sizeof(iv));
        std::memset(single_params.tag, 0, sizeof(single_params.tag));
        single_params.aad = &aad_buf;

        azihsm_algo single_algo{};
        single_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        single_algo.params = &single_params;
        single_algo.len = sizeof(single_params);

        std::vector<uint8_t> single_ct;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &single_algo,
            plaintext.data(),
            plaintext.size(),
            single_ct
        ));

        azihsm_algo_aes_gcm_params stream_params{};
        std::memcpy(stream_params.iv, iv, sizeof(iv));
        std::memset(stream_params.tag, 0, sizeof(stream_params.tag));
        stream_params.aad = &aad_buf;

        azihsm_algo stream_algo{};
        stream_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        stream_algo.params = &stream_params;
        stream_algo.len = sizeof(stream_params);

        std::vector<uint8_t> stream_ct;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::streaming_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &stream_algo,
            plaintext.data(),
            plaintext.size(),
            7,
            stream_ct
        ));

        ASSERT_EQ(single_ct.size(), stream_ct.size());
        ASSERT_EQ(std::memcmp(single_ct.data(), stream_ct.data(), single_ct.size()), 0);
        ASSERT_EQ(std::memcmp(single_params.tag, stream_params.tag, sizeof(single_params.tag)), 0);
    });
}

// Repeating the same single-shot inputs (including AAD) should produce the same tag.
TEST_F(azihsm_aes_gcm, same_inputs_with_same_aad_produces_same_tag_single_shot)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);
        auto plaintext = make_incrementing_bytes(21);
        std::vector<uint8_t> aad = { 0x01, 0x02, 0x03, 0x04 };
        azihsm_buffer aad_buf{ aad.data(), static_cast<uint32_t>(aad.size()) };

        uint8_t iv[12] = { 0x11, 0x21, 0x31, 0x41, 0x51, 0x61,
                           0x71, 0x81, 0x91, 0xA1, 0xB1, 0xC1 };

        azihsm_algo_aes_gcm_params params1{};
        std::memcpy(params1.iv, iv, sizeof(iv));
        std::memset(params1.tag, 0, sizeof(params1.tag));
        params1.aad = &aad_buf;

        azihsm_algo algo1{};
        algo1.id = AZIHSM_ALGO_ID_AES_GCM;
        algo1.params = &params1;
        algo1.len = sizeof(params1);

        { std::vector<uint8_t> ignored_output; ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &algo1,
            plaintext.data(),
            plaintext.size(),
            ignored_output
        )); }

        azihsm_algo_aes_gcm_params params2{};
        std::memcpy(params2.iv, iv, sizeof(iv));
        std::memset(params2.tag, 0, sizeof(params2.tag));
        params2.aad = &aad_buf;

        azihsm_algo algo2{};
        algo2.id = AZIHSM_ALGO_ID_AES_GCM;
        algo2.params = &params2;
        algo2.len = sizeof(params2);

        { std::vector<uint8_t> ignored_output; ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &algo2,
            plaintext.data(),
            plaintext.size(),
            ignored_output
        )); }

        ASSERT_EQ(std::memcmp(params1.tag, params2.tag, sizeof(params1.tag)), 0);
    });
}

// Repeating the same streaming inputs (including AAD) should produce the same tag.
TEST_F(azihsm_aes_gcm, same_inputs_with_same_aad_produces_same_tag_streaming)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);
        auto plaintext = make_incrementing_bytes(35);
        std::vector<uint8_t> aad = { 0x0A, 0x0B, 0x0C };
        azihsm_buffer aad_buf{ aad.data(), static_cast<uint32_t>(aad.size()) };

        uint8_t iv[12] = { 0x12, 0x22, 0x32, 0x42, 0x52, 0x62,
                           0x72, 0x82, 0x92, 0xA2, 0xB2, 0xC2 };

        azihsm_algo_aes_gcm_params params1{};
        std::memcpy(params1.iv, iv, sizeof(iv));
        std::memset(params1.tag, 0, sizeof(params1.tag));
        params1.aad = &aad_buf;

        azihsm_algo algo1{};
        algo1.id = AZIHSM_ALGO_ID_AES_GCM;
        algo1.params = &params1;
        algo1.len = sizeof(params1);

        { std::vector<uint8_t> ignored_output; ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::streaming_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &algo1,
            plaintext.data(),
            plaintext.size(),
            5,
            ignored_output
        )); }

        azihsm_algo_aes_gcm_params params2{};
        std::memcpy(params2.iv, iv, sizeof(iv));
        std::memset(params2.tag, 0, sizeof(params2.tag));
        params2.aad = &aad_buf;

        azihsm_algo algo2{};
        algo2.id = AZIHSM_ALGO_ID_AES_GCM;
        algo2.params = &params2;
        algo2.len = sizeof(params2);

        { std::vector<uint8_t> ignored_output; ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::streaming_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &algo2,
            plaintext.data(),
            plaintext.size(),
            13,
            ignored_output
        )); }

        ASSERT_EQ(std::memcmp(params1.tag, params2.tag, sizeof(params1.tag)), 0);
    });
}

// Decrypt must fail when ciphertext was authenticated with AAD but caller omits AAD.
TEST_F(azihsm_aes_gcm, decrypt_with_missing_aad_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);
        auto plaintext = make_incrementing_bytes(30);
        uint8_t iv[12] = { 0x13, 0x23, 0x33, 0x43, 0x53, 0x63,
                           0x73, 0x83, 0x93, 0xA3, 0xB3, 0xC3 };

        std::vector<uint8_t> aad = { 0xAB, 0xCD, 0xEF };
        azihsm_buffer aad_buf{ aad.data(), static_cast<uint32_t>(aad.size()) };

        azihsm_algo_aes_gcm_params params{};
        std::memcpy(params.iv, iv, sizeof(iv));
        std::memset(params.tag, 0, sizeof(params.tag));
        params.aad = &aad_buf;

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_AES_GCM;
        algo.params = &params;
        algo.len = sizeof(params);

        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        std::memcpy(params.iv, iv, sizeof(iv));
        params.aad = nullptr;

        azihsm_buffer input{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        auto err = single_shot_status_with_sizing(CryptOperation::Decrypt, &algo, key.get(), &input);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Decrypt must fail when caller provides unexpected AAD for ciphertext encrypted without AAD.
TEST_F(azihsm_aes_gcm, decrypt_with_unexpected_aad_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);
        auto plaintext = make_incrementing_bytes(30);
        uint8_t iv[12] = { 0x14, 0x24, 0x34, 0x44, 0x54, 0x64,
                           0x74, 0x84, 0x94, 0xA4, 0xB4, 0xC4 };

        azihsm_algo_aes_gcm_params params{};
        std::memcpy(params.iv, iv, sizeof(iv));
        std::memset(params.tag, 0, sizeof(params.tag));
        params.aad = nullptr;

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_AES_GCM;
        algo.params = &params;
        algo.len = sizeof(params);

        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        std::vector<uint8_t> unexpected_aad = { 0x11, 0x22, 0x33 };
        azihsm_buffer unexpected_aad_buf{
            unexpected_aad.data(),
            static_cast<uint32_t>(unexpected_aad.size())
        };

        std::memcpy(params.iv, iv, sizeof(iv));
        params.aad = &unexpected_aad_buf;

        azihsm_buffer input{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        auto err = single_shot_status_with_sizing(CryptOperation::Decrypt, &algo, key.get(), &input);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    });
}

// Auth failure must be independent of chunk boundaries when AAD is tampered.
TEST_F(azihsm_aes_gcm, streaming_decrypt_tampered_aad_fails_across_chunk_sizes)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);
        auto plaintext = make_incrementing_bytes(40);
        uint8_t iv[12] = { 0x15, 0x25, 0x35, 0x45, 0x55, 0x65,
                           0x75, 0x85, 0x95, 0xA5, 0xB5, 0xC5 };

        std::vector<uint8_t> aad = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        azihsm_buffer aad_buf{ aad.data(), static_cast<uint32_t>(aad.size()) };

        azihsm_algo_aes_gcm_params enc_params{};
        std::memcpy(enc_params.iv, iv, sizeof(iv));
        std::memset(enc_params.tag, 0, sizeof(enc_params.tag));
        enc_params.aad = &aad_buf;

        azihsm_algo enc_algo{};
        enc_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        enc_algo.params = &enc_params;
        enc_algo.len = sizeof(enc_params);

        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &enc_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        auto tampered_aad = aad;
        tampered_aad[0] ^= 0x01;
        azihsm_buffer tampered_aad_buf{ tampered_aad.data(), static_cast<uint32_t>(tampered_aad.size()) };

        std::vector<size_t> chunk_sizes = { 1, 3, 7, 16, 31 };
        for (auto chunk_size : chunk_sizes)
        {
            SCOPED_TRACE("chunk_size=" + std::to_string(chunk_size));

            azihsm_algo_aes_gcm_params dec_params{};
            std::memcpy(dec_params.iv, iv, sizeof(iv));
            std::memcpy(dec_params.tag, enc_params.tag, sizeof(dec_params.tag));
            dec_params.aad = &tampered_aad_buf;

            azihsm_algo dec_algo{};
            dec_algo.id = AZIHSM_ALGO_ID_AES_GCM;
            dec_algo.params = &dec_params;
            dec_algo.len = sizeof(dec_params);

            auto_ctx ctx;
            auto err = azihsm_crypt_decrypt_init(&dec_algo, key.get(), ctx.get_ptr());
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            size_t offset = 0;
            while (offset < ciphertext.size())
            {
                size_t current_chunk = std::min(chunk_size, ciphertext.size() - offset);
                azihsm_buffer input{
                    ciphertext.data() + offset,
                    static_cast<uint32_t>(current_chunk),
                };

                err = streaming_update_status_with_sizing(CryptOperation::Decrypt, ctx, &input);
                ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
                offset += current_chunk;
            }

            err = streaming_finish_status_with_sizing(CryptOperation::Decrypt, ctx);
            ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        }
    });
}

// Auth failure must be independent of chunk boundaries when IV is wrong.
TEST_F(azihsm_aes_gcm, streaming_decrypt_wrong_iv_fails_across_chunk_sizes)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);
        auto plaintext = make_incrementing_bytes(36);
        uint8_t iv[12] = { 0x16, 0x26, 0x36, 0x46, 0x56, 0x66,
                           0x76, 0x86, 0x96, 0xA6, 0xB6, 0xC6 };

        azihsm_algo_aes_gcm_params enc_params{};
        std::memcpy(enc_params.iv, iv, sizeof(iv));
        std::memset(enc_params.tag, 0, sizeof(enc_params.tag));
        enc_params.aad = nullptr;

        azihsm_algo enc_algo{};
        enc_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        enc_algo.params = &enc_params;
        enc_algo.len = sizeof(enc_params);

        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &enc_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        uint8_t wrong_iv[12];
        std::memcpy(wrong_iv, iv, sizeof(iv));
        wrong_iv[0] ^= 0xFF;

        std::vector<size_t> chunk_sizes = { 1, 5, 9, 17 };
        for (auto chunk_size : chunk_sizes)
        {
            SCOPED_TRACE("chunk_size=" + std::to_string(chunk_size));

            azihsm_algo_aes_gcm_params dec_params{};
            std::memcpy(dec_params.iv, wrong_iv, sizeof(wrong_iv));
            std::memcpy(dec_params.tag, enc_params.tag, sizeof(dec_params.tag));
            dec_params.aad = nullptr;

            azihsm_algo dec_algo{};
            dec_algo.id = AZIHSM_ALGO_ID_AES_GCM;
            dec_algo.params = &dec_params;
            dec_algo.len = sizeof(dec_params);

            auto_ctx ctx;
            auto err = azihsm_crypt_decrypt_init(&dec_algo, key.get(), ctx.get_ptr());
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            size_t offset = 0;
            while (offset < ciphertext.size())
            {
                size_t current_chunk = std::min(chunk_size, ciphertext.size() - offset);
                azihsm_buffer input{
                    ciphertext.data() + offset,
                    static_cast<uint32_t>(current_chunk),
                };

                err = streaming_update_status_with_sizing(CryptOperation::Decrypt, ctx, &input);
                ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
                offset += current_chunk;
            }

            err = streaming_finish_status_with_sizing(CryptOperation::Decrypt, ctx);
            ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        }
    });
}

// Auth failure must be independent of chunk boundaries when tag is tampered.
TEST_F(azihsm_aes_gcm, tampered_tag_fails_across_chunk_sizes)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto key = generate_aes_gcm_key(session, 256);
        auto plaintext = make_incrementing_bytes(34);
        uint8_t iv[12] = { 0x17, 0x27, 0x37, 0x47, 0x57, 0x67,
                           0x77, 0x87, 0x97, 0xA7, 0xB7, 0xC7 };

        azihsm_algo_aes_gcm_params enc_params{};
        std::memcpy(enc_params.iv, iv, sizeof(iv));
        std::memset(enc_params.tag, 0, sizeof(enc_params.tag));
        enc_params.aad = nullptr;

        azihsm_algo enc_algo{};
        enc_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        enc_algo.params = &enc_params;
        enc_algo.len = sizeof(enc_params);

        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(AZIHSM_STATUS_SUCCESS, ::single_shot_crypt(
            CryptOperation::Encrypt,
            key.get(),
            &enc_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        ));

        uint8_t tampered_tag[16];
        std::memcpy(tampered_tag, enc_params.tag, sizeof(tampered_tag));
        tampered_tag[0] ^= 0x80;

        std::vector<size_t> chunk_sizes = { 1, 4, 8, 15 };
        for (auto chunk_size : chunk_sizes)
        {
            SCOPED_TRACE("chunk_size=" + std::to_string(chunk_size));

            azihsm_algo_aes_gcm_params dec_params{};
            std::memcpy(dec_params.iv, iv, sizeof(iv));
            std::memcpy(dec_params.tag, tampered_tag, sizeof(tampered_tag));
            dec_params.aad = nullptr;

            azihsm_algo dec_algo{};
            dec_algo.id = AZIHSM_ALGO_ID_AES_GCM;
            dec_algo.params = &dec_params;
            dec_algo.len = sizeof(dec_params);

            auto_ctx ctx;
            auto err = azihsm_crypt_decrypt_init(&dec_algo, key.get(), ctx.get_ptr());
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            size_t offset = 0;
            while (offset < ciphertext.size())
            {
                size_t current_chunk = std::min(chunk_size, ciphertext.size() - offset);
                azihsm_buffer input{
                    ciphertext.data() + offset,
                    static_cast<uint32_t>(current_chunk),
                };

                err = streaming_update_status_with_sizing(CryptOperation::Decrypt, ctx, &input);
                ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
                offset += current_chunk;
            }

            err = streaming_finish_status_with_sizing(CryptOperation::Decrypt, ctx);
            ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        }
    });
}



