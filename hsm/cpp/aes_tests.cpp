// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"
#include <cstring>

class AESTest : public ::testing::Test
{
protected:
    struct AesTestParam
    {
        uint32_t size;
        const uint8_t *key;
        const uint8_t *iv;
        size_t iv_len;
        const uint8_t *plain;
        size_t plain_len;
        const uint8_t *cipher;
        size_t cipher_len;
    };

    void SetUp() override
    {
        std::tie(partition_handle, session_handle) = open_session();
        ASSERT_NE(session_handle, 0);
    }

    void TearDown() override
    {
        if (session_handle != 0)
        {
            EXPECT_EQ(azihsm_sess_close(session_handle), AZIHSM_ERROR_SUCCESS);
        }
        if (partition_handle != 0)
        {
            EXPECT_EQ(azihsm_part_close(partition_handle), AZIHSM_ERROR_SUCCESS);
        }
    }

    // Helper method for running AES Encrypt-Decrypt tests w/ hardcoded keys
    // Executes a wrap-unwrap-encrypt-decrypt workflow as follows:
    // Uses hard-coded key, iv, plaintext, & ciphertext values from AesTestParam parameter
    // 1. Generate RSA key pair for wrapping
    // 2. Use helper function to wrap hard-coded key from params
    // 3: Unwrap wrapped hard-coded key to store on device & get handle for key
    // 4: Encrypt plaintext w/ key handle
    // 5: Decrypt ciphertext w/ key handle
    void AesHardcodedKeysHelper(AesTestParam params)
    {
        // Step 1: Generate RSA key pair for wrapping
        azihsm_algo key_gen_algo = {
            .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
            .params = nullptr,
            .len = 0};

        uint32_t rsa_key_size = 2048;
        uint8_t wrap_flag = 1;
        uint8_t unwrap_flag = 1;

        azihsm_key_prop pub_key_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &rsa_key_size, .len = sizeof(rsa_key_size)},
            {.id = AZIHSM_KEY_PROP_ID_WRAP, .val = &wrap_flag, .len = sizeof(wrap_flag)}};

        azihsm_key_prop priv_key_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &rsa_key_size, .len = sizeof(rsa_key_size)},
            {.id = AZIHSM_KEY_PROP_ID_UNWRAP, .val = &unwrap_flag, .len = sizeof(unwrap_flag)}};

        azihsm_key_prop_list pub_key_prop_list = {.props = pub_key_props, .count = 2};
        azihsm_key_prop_list priv_key_prop_list = {.props = priv_key_props, .count = 2};

        azihsm_handle pub_key_handle = 0, priv_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session_handle,
            &key_gen_algo,
            &pub_key_prop_list,
            &priv_key_prop_list,
            &pub_key_handle,
            &priv_key_handle);

        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate RSA wrapping key pair";
        EXPECT_NE(pub_key_handle, 0) << "Public key handle should be valid";
        EXPECT_NE(priv_key_handle, 0) << "Private key handle should be valid";
        EXPECT_NE(session_handle, 0) << "Session handle should remain valid";

        std::cout << "[OK] Step 1: Generated RSA 2048-bit key pair (pub: " << pub_key_handle
                  << ", priv: " << priv_key_handle << ")" << std::endl;

        // Step 2: Use helper function to wrap hard-coded key from params
        std::vector<uint8_t> wrapped_data(1024); // Allocate enough space for wrapped data
        uint32_t wrapped_data_len = static_cast<uint32_t>(wrapped_data.size());

        err = rsa_wrap_data_helper(
            session_handle,
            pub_key_handle,
            params.key,
            static_cast<uint32_t>(params.size / 8),
            256, // AES-256 (required by implementation)
            wrapped_data.data(),
            &wrapped_data_len);

        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "RSA key wrap operation should succeed";
        EXPECT_GT(wrapped_data_len, params.size / 8) << "Wrapped data should be larger than original";
        EXPECT_LT(wrapped_data_len, wrapped_data.size()) << "Wrapped data should fit in allocated buffer";

        std::cout << "[OK] Step 2: Successfully wrapped data using helper function" << std::endl;
        std::cout << "  Original data size: " << params.size / 8 << " bytes" << std::endl;
        std::cout << "  Wrapped data size: " << wrapped_data_len << " bytes" << std::endl;

        // Step 3: Unwrap wrapped hard-coded key to store on device & get key handle
        azihsm_handle key_handle = 0;

        azihsm_buffer wrapped_key_buffer = {
            .buf = wrapped_data.data(),
            .len = static_cast<uint32_t>(wrapped_data_len)};

        // Empty label
        struct azihsm_buffer label = {
            .buf = NULL,
            .len = 0,
        };

        // Note: hash_algo_id and mgf1_hash_algo_id must use the same hash algorithm
        struct azihsm_algo_rsa_pkcs_oaep_params oaep_params = {
            .hash_algo_id = AZIHSM_ALGO_ID_SHA256,
            .mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256,
            .label = &label,
        };

        struct azihsm_algo_rsa_aes_key_wrap_params unwrap_params = {
            .aes_key_bits = 256,
            .key_type = AZIHSM_KEY_TYPE_AES,
            .oaep_params = &oaep_params,
        };

        azihsm_algo key_unwrap_algo = {
            .id = AZIHSM_ALGO_ID_RSA_AES_KEYWRAP,
            .params = &unwrap_params,
            .len = sizeof(struct azihsm_algo_rsa_aes_key_wrap_params),
        };

        // Set up properties for the unwrapped AES key - match working test exactly
        uint32_t aes_bit_len = 256;
        uint8_t aes_encrypt_flag = 1; // Boolean properties must be uint8_t (1 byte)
        uint8_t aes_decrypt_flag = 1; // Boolean properties must be uint8_t (1 byte)

        azihsm_key_prop unwrapped_key_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &aes_bit_len, .len = sizeof(aes_bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &aes_encrypt_flag, .len = sizeof(aes_encrypt_flag)},
            {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &aes_decrypt_flag, .len = sizeof(aes_decrypt_flag)}};

        azihsm_key_prop_list unwrapped_key_prop_list = {
            .props = unwrapped_key_props,
            .count = 3};

        err = azihsm_key_unwrap(
            session_handle,
            &key_unwrap_algo,
            priv_key_handle,
            &wrapped_key_buffer,
            &unwrapped_key_prop_list,
            &key_handle);

        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "RSA key unwrap operation should succeed";
        EXPECT_NE(key_handle, 0) << "key handle should be valid";

        std::cout << "[OK] Step 3: Successfully unwrapped wrapped key" << std::endl;
        std::cout << "  key handle: " << key_handle << std::endl;

        auto key_guard = scope_guard::make_scope_exit([&]
                                                      {
            if (key_handle != 0) {
                EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS);
            } });

        // Step 4: Encrypt plaintext w/ key handle

        // Prepare arguments for encryption

        // create copy of iv because CBC mode modifies iv
        uint8_t iv_data[16];
        memcpy(iv_data, params.iv, params.iv_len);
        azihsm_algo_aes_cbc_params cbc_params = {0};
        memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
        azihsm_algo encrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC,
            .params = &cbc_params,
            .len = sizeof(cbc_params)};

        std::vector<uint8_t> plain_data;
        plain_data.insert(plain_data.begin(), params.plain, params.plain + params.plain_len);
        azihsm_buffer pt_buffer = {.buf = plain_data.data(), .len = static_cast<uint32_t>(plain_data.size())};
        std::vector<uint8_t> ciphertext_data(params.plain_len);
        azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = static_cast<uint32_t>(ciphertext_data.size())};

        // Perform encryption
        err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
        if (params.plain_len == 0)
        {
            EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT)
                << "AZIHSM_ERROR_INVALID_ARGUMENT should be returned during encryption with empty input for AES-" << params.size;

            std::cout << "[OK] Step 4: Successfully received AZIHSM_ERROR_INVALID_ARGUMENT" << std::endl;
        }
        else
        {
            EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed for AES-" << params.size;

            // Verify ciphertext is different from plaintext
            EXPECT_NE(memcmp(params.plain, ciphertext_data.data(), params.plain_len), 0)
                << "Ciphertext should be different from plaintext for AES-" << params.size;

            // Verify ciphertext is expected
            EXPECT_EQ(memcmp(params.cipher, ciphertext_data.data(), params.cipher_len), 0)
                << "Ciphertext should be expected data for AES-" << params.size;

            std::cout << "[OK] Step 4: Successfully encrypted plaintext" << std::endl;
        }

        // Step 5: Decrypt ciphertext w/ key handle

        // Prepare arguments for decryption

        // Reset IV for decryption (CBC mode modifies IV)
        memcpy(iv_data, params.iv, params.iv_len);
        memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

        azihsm_algo decrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC,
            .params = &cbc_params,
            .len = sizeof(cbc_params)};

        std::vector<uint8_t> decrypted_data(params.plain_len);
        azihsm_buffer decrypted_buffer = {.buf = decrypted_data.data(), .len = static_cast<uint32_t>(decrypted_data.size())};

        // Perform decryption
        err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
        if (params.plain_len == 0)
        {
            EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT)
                << "AZIHSM_ERROR_INVALID_ARGUMENT should be returned during decryption with empty input for AES-" << params.size;

            std::cout << "[OK] Step 5: Successfully received AZIHSM_ERROR_INVALID_ARGUMENT" << std::endl;
        }
        else
        {
            EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Decryption failed for AES-" << params.size;

            // Verify size of decrypted data matches original plaintext size
            EXPECT_EQ(decrypted_data.size(), params.plain_len)
                << "Decrypted data length should match original plaintext length for AES-" << params.size;
            // Verify decrypted data matches original plaintext
            EXPECT_EQ(memcmp(params.plain, decrypted_data.data(), params.plain_len), 0)
                << "Decrypted data should match original plaintext for AES-" << params.size;

            std::cout << "[OK] Step 5: Successfully decrypted ciphertext" << std::endl;
        }

        std::cout << "AES-" << params.size << " CBC decrypt test passed" << std::endl;
    }

    azihsm_handle partition_handle = 0;
    azihsm_handle session_handle = 0;
};

TEST_F(AESTest, AesKeySizeValidation)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    // Test valid AES key sizes
    std::vector<uint32_t> valid_sizes = {128, 192, 256};
    for (auto bit_len : valid_sizes)
    {
        azihsm_handle key_handle = 0;
        azihsm_key_prop props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}};
        azihsm_key_prop_list prop_list = {.props = props, .count = 1};

        auto err = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES-" << bit_len << " key";
        EXPECT_NE(key_handle, 0) << "Got null handle for AES-" << bit_len << " key";

        if (key_handle != 0)
        {
            EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS);
        }
    }

    // Test invalid AES key sizes
    std::vector<uint32_t> invalid_sizes = {64, 96, 160, 224, 384, 1024};
    for (auto bit_len : invalid_sizes)
    {
        azihsm_handle key_handle = 0;
        azihsm_key_prop props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}};
        azihsm_key_prop_list prop_list = {.props = props, .count = 1};

        auto err = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
        EXPECT_EQ(err, AZIHSM_UNSUPPORTED_KEY_SIZE) << "Should reject invalid AES key size: " << bit_len;
        EXPECT_EQ(key_handle, 0);
    }
}

// ================================================================================
// AES CBC (Unpadded) Tests
// ================================================================================

TEST_F(AESTest, AesCbcEncryptDecrypt)
{
    std::vector<uint32_t> bit_lengths = {128, 192, 256};

    for (auto bit_len : bit_lengths)
    {
        azihsm_handle key_handle = 0;
        azihsm_algo key_gen_algo = {
            .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
            .params = nullptr,
            .len = 0};

        bool encrypt_prop = true;
        bool decrypt_prop = true;
        azihsm_key_prop props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
            {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

        azihsm_key_prop_list prop_list = {.props = props, .count = 3};

        auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES-" << bit_len << " key";
        EXPECT_NE(key_handle, 0) << "Got null handle for AES-" << bit_len << " key";

        auto key_guard = scope_guard::make_scope_exit([&]
                                                      {
            if (key_handle != 0) {
                EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS);
            } });

        // Test data - 16 bytes (one AES block)
        uint8_t plaintext[] = "1234567890123456"; // 16 bytes
        size_t plaintext_len = 16;

        // IV for AES-CBC (16 bytes) - use different IV for each key size
        uint8_t iv_data[16] = {
            static_cast<uint8_t>(bit_len & 0xFF), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, static_cast<uint8_t>((bit_len >> 8) & 0xFF)};

        azihsm_algo_aes_cbc_params cbc_params = {0};
        memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
        azihsm_algo encrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC,
            .params = &cbc_params,
            .len = sizeof(cbc_params)};

        azihsm_buffer pt_buffer = {.buf = plaintext, .len = static_cast<uint32_t>(plaintext_len)};
        std::vector<uint8_t> ciphertext_data(plaintext_len);
        azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = static_cast<uint32_t>(ciphertext_data.size())};

        // Perform encryption
        err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed for AES-" << bit_len;

        // Verify ciphertext is different from plaintext
        EXPECT_NE(memcmp(plaintext, ciphertext_data.data(), plaintext_len), 0)
            << "Ciphertext should be different from plaintext for AES-" << bit_len;

        // Reset IV for decryption (CBC mode modifies IV)
        memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

        azihsm_algo decrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC,
            .params = &cbc_params,
            .len = sizeof(cbc_params)};

        std::vector<uint8_t> decrypted_data(plaintext_len);
        azihsm_buffer decrypted_buffer = {.buf = decrypted_data.data(), .len = static_cast<uint32_t>(decrypted_data.size())};

        // Perform decryption
        err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Decryption failed for AES-" << bit_len;

        // Verify decrypted data matches original plaintext
        EXPECT_EQ(memcmp(plaintext, decrypted_data.data(), plaintext_len), 0)
            << "Decrypted data should match original plaintext for AES-" << bit_len;

        std::cout << "AES-" << bit_len << " CBC encrypt/decrypt test passed" << std::endl;
    }
}

TEST_F(AESTest, AesCbcMultipleBlocks)
{
    std::vector<uint32_t> bit_lengths = {128, 192, 256};

    for (auto bit_len : bit_lengths)
    {
        azihsm_handle key_handle = 0;
        azihsm_algo key_gen_algo = {
            .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
            .params = nullptr,
            .len = 0};

        bool encrypt_prop = true;
        bool decrypt_prop = true;
        azihsm_key_prop props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
            {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

        azihsm_key_prop_list prop_list = {.props = props, .count = 3};

        auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

        auto key_guard = scope_guard::make_scope_exit([&]
                                                      { azihsm_key_delete(session_handle, key_handle); });

        // Test data - 32 bytes (two AES blocks)
        uint8_t plaintext[] = "12345678901234561234567890123456"; // 32 bytes
        size_t plaintext_len = 32;

        uint8_t iv_data[16] = {
            0x11, 0x22, 0x33, 0x44, static_cast<uint8_t>(bit_len & 0xFF), 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, static_cast<uint8_t>((bit_len >> 8) & 0xFF)};

        azihsm_algo_aes_cbc_params cbc_params = {0};
        memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
        azihsm_algo encrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC,
            .params = &cbc_params,
            .len = sizeof(cbc_params)};

        azihsm_buffer pt_buffer = {.buf = plaintext, .len = static_cast<uint32_t>(plaintext_len)};
        std::vector<uint8_t> ciphertext_data(plaintext_len);
        azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = static_cast<uint32_t>(ciphertext_data.size())};

        // Perform encryption
        err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Verify ciphertext is different from plaintext
        EXPECT_NE(memcmp(plaintext, ciphertext_data.data(), plaintext_len), 0);

        // Reset IV for decryption
        memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

        azihsm_algo decrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC,
            .params = &cbc_params,
            .len = sizeof(cbc_params)};

        std::vector<uint8_t> decrypted_data(plaintext_len);
        azihsm_buffer decrypted_buffer = {.buf = decrypted_data.data(), .len = static_cast<uint32_t>(decrypted_data.size())};

        err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

        EXPECT_EQ(memcmp(plaintext, decrypted_data.data(), plaintext_len), 0);

        std::cout << "AES-" << bit_len << " CBC multiple blocks test passed" << std::endl;
    }
}

TEST_F(AESTest, AesCbcInvalidParamSize)
{
    // Generate AES key first
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 128;
    bool encrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 2};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    uint8_t plaintext[] = "1234567890123456";
    uint8_t iv_data[16] = {0};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    // Test with incorrect parameter length (too small)
    azihsm_algo encrypt_algo_invalid = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params) - 1 // Make it smaller than required
    };

    azihsm_buffer pt_buffer = {.buf = plaintext, .len = 16};
    std::vector<uint8_t> ciphertext_data(16);
    azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = 16};

    // Should fail with invalid argument due to insufficient parameter size
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo_invalid, key_handle, &pt_buffer, &ct_buffer);
    // [TODO] Investigate why this fails when run via xtask but passes when run directly.
    // EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT) << "Should reject algorithm params with insufficient length";

    // Test with zero length
    azihsm_algo encrypt_algo_zero = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = 0};

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo_zero, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT) << "Should reject algorithm params with zero length";
}

// ================================================================================
// AES CBC PKCS7 Padded Tests
// ================================================================================

TEST_F(AESTest, AesCbcPaddingBasicEncryptDecrypt)
{
    std::vector<uint32_t> bit_lengths = {128, 192, 256};

    for (auto bit_len : bit_lengths)
    {
        azihsm_handle key_handle = 0;
        azihsm_algo key_gen_algo = {
            .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
            .params = nullptr,
            .len = 0};

        bool encrypt_prop = true;
        bool decrypt_prop = true;
        azihsm_key_prop props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
            {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

        azihsm_key_prop_list prop_list = {.props = props, .count = 3};

        auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES-" << bit_len << " key";

        auto key_guard = scope_guard::make_scope_exit([&]
                                                      {
            if (key_handle != 0) {
                EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS);
            } });

        // Test data - 13 bytes (not aligned to block boundary)
        uint8_t plaintext[] = "Hello, World!"; // 13 bytes
        size_t plaintext_len = 13;

        uint8_t iv_data[16] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

        azihsm_algo_aes_cbc_params cbc_params = {0};
        memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

        // Use the padded CBC algorithm
        azihsm_algo encrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
            .params = &cbc_params,
            .len = sizeof(cbc_params)};

        azihsm_buffer pt_buffer = {.buf = plaintext, .len = static_cast<uint32_t>(plaintext_len)};

        // Allocate space for padded output (should be aligned to next block boundary)
        size_t padded_size = ((plaintext_len / 16) + 1) * 16;
        std::vector<uint8_t> ciphertext_data(padded_size);
        azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = static_cast<uint32_t>(ciphertext_data.size())};

        // Perform encryption
        err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Padded encryption failed for AES-" << bit_len;

        // Verify ciphertext is larger than plaintext (due to padding)
        EXPECT_GT(ct_buffer.len, plaintext_len) << "Ciphertext should be larger than plaintext due to padding";
        EXPECT_EQ(ct_buffer.len % 16, 0u) << "Ciphertext should be block-aligned";

        // Reset IV for decryption
        memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

        azihsm_algo decrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
            .params = &cbc_params,
            .len = sizeof(cbc_params)};

        std::vector<uint8_t> decrypted_data(padded_size);
        azihsm_buffer decrypted_buffer = {.buf = decrypted_data.data(), .len = static_cast<uint32_t>(decrypted_data.size())};

        // Perform decryption
        err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Padded decryption failed for AES-" << bit_len;

        // Verify decrypted data matches original plaintext
        EXPECT_EQ(decrypted_buffer.len, plaintext_len) << "Decrypted data should have original length";
        EXPECT_EQ(memcmp(plaintext, decrypted_data.data(), plaintext_len), 0)
            << "Decrypted data should match original plaintext for AES-" << bit_len;

        std::cout << "AES-" << bit_len << " CBC with PKCS#7 padding test passed" << std::endl;
    }
}

TEST_F(AESTest, AesCbcPaddingDifferentInputSizes)
{
    // Test various input sizes to verify padding behavior
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 128;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (key_handle != 0) {
            EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS);
        } });

    uint8_t iv_data[16] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};

    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Test various input sizes
    std::vector<size_t> test_sizes = {1, 5, 15, 16, 17, 31, 32, 33, 63, 64, 100};

    for (auto input_size : test_sizes)
    {
        // Create test data
        std::vector<uint8_t> plaintext(input_size);
        for (size_t i = 0; i < input_size; ++i)
        {
            plaintext[i] = static_cast<uint8_t>(i & 0xFF);
        }

        azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(input_size)};

        // Calculate expected ciphertext size (padded to block boundary)
        size_t expected_ct_size = ((input_size / 16) + 1) * 16;
        std::vector<uint8_t> ciphertext_data(expected_ct_size);
        azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = static_cast<uint32_t>(ciphertext_data.size())};

        // Reset IV for each test
        memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

        // Encrypt
        err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed for input size: " << input_size;
        EXPECT_EQ(ct_buffer.len, expected_ct_size) << "Unexpected ciphertext size for input: " << input_size;

        // Reset IV for decryption
        memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

        azihsm_algo decrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
            .params = &cbc_params,
            .len = sizeof(cbc_params)};

        std::vector<uint8_t> decrypted_data(expected_ct_size);
        azihsm_buffer decrypted_buffer = {.buf = decrypted_data.data(), .len = static_cast<uint32_t>(decrypted_data.size())};

        // Decrypt
        err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Decryption failed for input size: " << input_size;
        EXPECT_EQ(decrypted_buffer.len, input_size) << "Decrypted length mismatch for input size: " << input_size;

        // Verify content
        EXPECT_EQ(memcmp(plaintext.data(), decrypted_data.data(), input_size), 0)
            << "Content mismatch for input size: " << input_size;

        std::cout << "Padding test passed for input size: " << input_size << std::endl;
    }
}

TEST_F(AESTest, AesCbcPaddingEmptyInput)
{
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 128;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (key_handle != 0) {
            EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS);
        } });

    uint8_t iv_data[16] = {0};
    azihsm_algo_aes_cbc_params cbc_params;
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    // Verify that zero-length input for encryption is rejected
    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    uint8_t dummy_data = 0;
    azihsm_buffer empty_pt_buffer = {.buf = &dummy_data, .len = 0}; // Zero length
    std::vector<uint8_t> ciphertext_data(16);
    azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = 16};

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &empty_pt_buffer, &ct_buffer);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Zero-length input encryption should be rejected";

    // Verify that zero-length input for decryption is rejected
    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    azihsm_buffer empty_ct_buffer = {.buf = &dummy_data, .len = 0}; // Zero length
    std::vector<uint8_t> plaintext_data(16);
    azihsm_buffer pt_buffer = {.buf = plaintext_data.data(), .len = 16};

    // Reset IV for decryption test
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &empty_ct_buffer, &pt_buffer);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Zero-length input decryption should be rejected";
}

TEST_F(AESTest, AesCbcPaddingLargeInput)
{
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 256;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (key_handle != 0) {
            EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS);
        } });

    // Large input - 1009 bytes (not block aligned, padded output will be 1024 bytes)
    constexpr size_t input_size = 1009;
    std::vector<uint8_t> plaintext(input_size);
    for (size_t i = 0; i < input_size; ++i)
    {
        plaintext[i] = static_cast<uint8_t>((i * 31) & 0xFF); // Some pattern
    }

    uint8_t iv_data[16] = {
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};

    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(input_size)};

    // Calculate padded size - 1009 bytes needs 7 bytes of padding to reach 1016,
    // then full block padding adds 16 more = 1024 bytes total
    size_t padded_size = ((input_size / 16) + 1) * 16; // This equals 1024
    std::vector<uint8_t> ciphertext_data(padded_size);
    azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = static_cast<uint32_t>(ciphertext_data.size())};

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Large input encryption should succeed";
    EXPECT_EQ(ct_buffer.len, padded_size) << "Unexpected ciphertext size for large input";
    EXPECT_LE(ct_buffer.len, 1024u) << "Padded output should not exceed hardware limit of 1024 bytes";

    // Reset IV for decryption
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    std::vector<uint8_t> decrypted_data(padded_size);
    azihsm_buffer decrypted_buffer = {.buf = decrypted_data.data(), .len = static_cast<uint32_t>(decrypted_data.size())};

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Large input decryption should succeed";
    EXPECT_EQ(decrypted_buffer.len, input_size) << "Decrypted size should match original";

    // Verify content
    EXPECT_EQ(memcmp(plaintext.data(), decrypted_data.data(), input_size), 0)
        << "Large input content should match after round-trip";

    std::cout << "Large input padding test passed (size: " << input_size << ")" << std::endl;
}

TEST_F(AESTest, AesCbcPaddingVsNoPadding)
{
    // Test that padded and non-padded algorithms produce different results
    // and that non-padded algorithm requires block-aligned input
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 128;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (key_handle != 0) {
            EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS);
        } });

    uint8_t iv_data[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    // Test 1: Non-padded algorithm should reject non-block-aligned input
    uint8_t non_aligned_data[] = "Hello!"; // 6 bytes, not block aligned
    azihsm_buffer non_aligned_buffer = {.buf = non_aligned_data, .len = 6};
    std::vector<uint8_t> output_data(16);
    azihsm_buffer output_buffer = {.buf = output_data.data(), .len = 16};

    azihsm_algo no_pad_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    err = azihsm_crypt_encrypt(session_handle, &no_pad_algo, key_handle, &non_aligned_buffer, &output_buffer);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Non-padded CBC should reject non-block-aligned input";

    // Test 2: Padded algorithm should accept the same input
    azihsm_algo pad_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    std::vector<uint8_t> padded_output(16);
    azihsm_buffer padded_output_buffer = {.buf = padded_output.data(), .len = 16};

    // Reset IV
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    err = azihsm_crypt_encrypt(session_handle, &pad_algo, key_handle, &non_aligned_buffer, &padded_output_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Padded CBC should accept non-block-aligned input";

    // Test 3: Both algorithms should work with block-aligned input, but produce different results
    uint8_t aligned_data[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    azihsm_buffer aligned_buffer = {.buf = aligned_data, .len = 16};

    std::vector<uint8_t> no_pad_output(16);
    azihsm_buffer no_pad_output_buffer = {.buf = no_pad_output.data(), .len = 16};

    std::vector<uint8_t> pad_output(32); // Padded version will be larger
    azihsm_buffer pad_output_buffer = {.buf = pad_output.data(), .len = 32};

    // Reset IV for no-padding test
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    err = azihsm_crypt_encrypt(session_handle, &no_pad_algo, key_handle, &aligned_buffer, &no_pad_output_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Non-padded CBC should work with block-aligned input";
    EXPECT_EQ(no_pad_output_buffer.len, 16u) << "Non-padded output should be same size as input";

    // Reset IV for padding test
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    err = azihsm_crypt_encrypt(session_handle, &pad_algo, key_handle, &aligned_buffer, &pad_output_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Padded CBC should work with block-aligned input";
    EXPECT_EQ(pad_output_buffer.len, 32u) << "Padded output should be larger due to full block of padding";

    // The first blocks should be identical (same input, key, IV)
    EXPECT_EQ(memcmp(no_pad_output.data(), pad_output.data(), 16), 0)
        << "First block should be identical for both algorithms";

    // The total outputs are different (different lengths)
    EXPECT_NE(no_pad_output_buffer.len, pad_output_buffer.len)
        << "Output lengths should be different due to padding";

    std::cout << "Padding vs non-padding comparison test passed" << std::endl;
}

TEST_F(AESTest, Aes128Cbc)
{
    // key: 2b7e151628aed2a6abf7158809cf4f3c
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    // iv: 000102030405060708090a0b0c0d0e0f
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // plain: 6bc1bee22e409f96e93d7e117393172a
    uint8_t plain[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

    // cipher: 7649abac8119b246cee98e9b12e9197d
    uint8_t cipher[16] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d};

    struct AesTestParam params = {
        .size = 128,
        .key = reinterpret_cast<const uint8_t *>(key),
        .iv = reinterpret_cast<const uint8_t *>(iv),
        .iv_len = 16,
        .plain = reinterpret_cast<const uint8_t *>(plain),
        .plain_len = 16,
        .cipher = reinterpret_cast<const uint8_t *>(cipher),
        .cipher_len = 16};

    AesHardcodedKeysHelper(params);
}

TEST_F(AESTest, Aes192Cbc)
{
    // key: 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
    uint8_t key[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};

    // iv: 000102030405060708090a0b0c0d0e0f
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // plain: 6bc1bee22e409f96e93d7e117393172a
    uint8_t plain[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

    // cipher: 4f021db243bc633d7178183a9fa071e8
    uint8_t cipher[16] = {
        0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d,
        0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8};

    struct AesTestParam params = {
        .size = 192,
        .key = reinterpret_cast<const uint8_t *>(key),
        .iv = reinterpret_cast<const uint8_t *>(iv),
        .iv_len = 16,
        .plain = reinterpret_cast<const uint8_t *>(plain),
        .plain_len = 16,
        .cipher = reinterpret_cast<const uint8_t *>(cipher),
        .cipher_len = 16};

    AesHardcodedKeysHelper(params);
}

TEST_F(AESTest, Aes256Cbc)
{
    // key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

    // iv: 000102030405060708090a0b0c0d0e0f
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // plain: 6bc1bee22e409f96e93d7e117393172a
    uint8_t plain[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

    // cipher: f58c4c04d6e5f1ba779eabfb5f7bfbd6
    uint8_t cipher[16] = {
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
        0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6};

    struct AesTestParam params = {
        .size = 256,
        .key = reinterpret_cast<const uint8_t *>(key),
        .iv = reinterpret_cast<const uint8_t *>(iv),
        .iv_len = 16,
        .plain = reinterpret_cast<const uint8_t *>(plain),
        .plain_len = 16,
        .cipher = reinterpret_cast<const uint8_t *>(cipher),
        .cipher_len = 16};

    AesHardcodedKeysHelper(params);
}

TEST_F(AESTest, AesCbcEmptyInput)
{
    // key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

    // iv: 000102030405060708090a0b0c0d0e0f
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    struct AesTestParam params = {
        .size = 256,
        .key = reinterpret_cast<const uint8_t *>(key),
        .iv = reinterpret_cast<const uint8_t *>(iv),
        .iv_len = 16,
        .plain = reinterpret_cast<const uint8_t *>(""),
        .plain_len = 0,
        .cipher = reinterpret_cast<const uint8_t *>(""),
        .cipher_len = 0};

    AesHardcodedKeysHelper(params);
}

TEST_F(AESTest, AesCbcOutputIv)
{
    uint32_t bit_len = 128;
    const uint8_t key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    constexpr size_t IV_LEN = 16;
    const uint8_t iv[IV_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    constexpr size_t PLAIN_SIZE = 1024;
    constexpr size_t PLAIN_SIZE_HALF = 512;
    uint8_t expected_plain[PLAIN_SIZE];
    std::fill_n(expected_plain, PLAIN_SIZE, 0x01);

    // generate AES key
    // TODO: replace key generation logic w/ import of hardcoded key once API is available
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES-" << bit_len << " key";
    EXPECT_NE(key_handle, 0) << "Got null handle for AES-" << bit_len << " key";

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (key_handle != 0) {
            EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS);
        } });

    // Test encryption #1: entire plain text buffer (1024 bytes)

    // Prepare arguments for encryption
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv, IV_LEN);
    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    std::vector<uint8_t> plain_data;
    plain_data.insert(plain_data.begin(), expected_plain, expected_plain + std::size(expected_plain));
    azihsm_buffer pt_buffer = {.buf = plain_data.data(), .len = static_cast<uint32_t>(plain_data.size())};
    std::vector<uint8_t> ciphertext_data(std::size(expected_plain));
    azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = static_cast<uint32_t>(ciphertext_data.size())};

    // Perform encryption
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed for AES-" << bit_len;

    uint8_t expected_cipher[PLAIN_SIZE];
    memcpy(expected_cipher, ct_buffer.buf, ct_buffer.len);

    // Save the output IV after encryption
    uint8_t expected_iv[IV_LEN];
    memcpy(expected_iv, cbc_params.iv, IV_LEN);

    // Test encryption #2: first half of plain text buffer (512 bytes)

    // Reset IV to original value
    memcpy(cbc_params.iv, iv, IV_LEN);

    plain_data.clear();
    plain_data.insert(plain_data.begin(), expected_plain, expected_plain + PLAIN_SIZE_HALF);
    pt_buffer.len = static_cast<uint32_t>(plain_data.size());
    ciphertext_data.resize(PLAIN_SIZE_HALF);
    ct_buffer.len = static_cast<uint32_t>(ciphertext_data.size());

    // Perform encryption
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed for AES-" << bit_len;

    uint8_t cipher_1[PLAIN_SIZE_HALF];
    memcpy(cipher_1, ct_buffer.buf, ct_buffer.len);

    // Save the output IV after first encryption
    uint8_t output_iv_1[IV_LEN];
    memcpy(output_iv_1, cbc_params.iv, IV_LEN);

    // Test encryption #3: last half of plain text buffer (512 bytes)

    plain_data.clear();
    plain_data.insert(plain_data.begin(), expected_plain + PLAIN_SIZE_HALF, expected_plain + sizeof(expected_plain));

    // Perform encryption
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed for AES-" << bit_len;

    uint8_t cipher_2[PLAIN_SIZE_HALF];
    memcpy(cipher_2, ct_buffer.buf, ct_buffer.len);

    // Save the output IV after second encryption
    uint8_t output_iv_2[IV_LEN];
    memcpy(output_iv_2, cbc_params.iv, IV_LEN);

    uint8_t cipher[PLAIN_SIZE];
    memcpy(cipher, cipher_1, sizeof(cipher_1));
    memcpy(cipher + PLAIN_SIZE_HALF, cipher_2, sizeof(cipher_2));

    EXPECT_EQ(memcmp(output_iv_2, expected_iv, IV_LEN), 0) << "Outputted IV is not expected value";
    EXPECT_EQ(memcmp(cipher, expected_cipher, PLAIN_SIZE), 0) << "Cipher is not expected value";

    // Test decryption #1: entire cipher (1024 bytes)

    // Reset IV for decryption
    memcpy(cbc_params.iv, iv, IV_LEN);

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    std::vector<uint8_t> decrypted_data(std::size(cipher));
    azihsm_buffer decrypted_buffer = {.buf = decrypted_data.data(), .len = static_cast<uint32_t>(decrypted_data.size())};

    // fill ct_buffer with cipher
    ciphertext_data.clear();
    ciphertext_data.insert(ciphertext_data.begin(), cipher, cipher + std::size(cipher));
    ct_buffer.len = static_cast<uint32_t>(ciphertext_data.size());

    // Perform decryption
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Decryption failed for AES-" << bit_len;

    // Verify decrypted data matches original plaintext
    EXPECT_EQ(memcmp(expected_plain, decrypted_data.data(), PLAIN_SIZE), 0)
        << "Decrypted data should match original plaintext for AES-" << bit_len;

    // Test decryption #2: first half of cipher (512 bytes)

    // Reset IV for decryption
    memcpy(cbc_params.iv, iv, IV_LEN);

    decrypted_data.resize(PLAIN_SIZE_HALF);
    decrypted_buffer.len = static_cast<uint32_t>(PLAIN_SIZE_HALF);

    // fill ct_buffer with cipher[..512]
    ciphertext_data.clear();
    ciphertext_data.insert(ciphertext_data.begin(), cipher, cipher + PLAIN_SIZE_HALF);
    ct_buffer.len = static_cast<uint32_t>(PLAIN_SIZE_HALF);

    // Perform decryption
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Decryption failed for AES-" << bit_len;

    uint8_t plain_1[PLAIN_SIZE_HALF];
    memcpy(plain_1, decrypted_buffer.buf, decrypted_buffer.len);

    // Test decryption #3: last half of cipher (512 bytes)

    // fill ct_buffer with cipher[512..]
    ciphertext_data.clear();
    ciphertext_data.insert(ciphertext_data.begin(), cipher + PLAIN_SIZE_HALF, cipher + std::size(cipher));

    // Perform decryption
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Decryption failed for AES-" << bit_len;

    uint8_t plain_2[PLAIN_SIZE_HALF];
    memcpy(plain_2, decrypted_buffer.buf, decrypted_buffer.len);

    // Save the final output IV
    memcpy(output_iv_2, cbc_params.iv, IV_LEN);

    uint8_t plain[PLAIN_SIZE];
    memcpy(plain, plain_1, sizeof(plain_1));
    memcpy(plain + PLAIN_SIZE_HALF, plain_2, sizeof(plain_2));

    EXPECT_EQ(memcmp(output_iv_2, expected_iv, IV_LEN), 0) << "Outputted IV is not expected value";
    EXPECT_EQ(memcmp(plain, expected_plain, PLAIN_SIZE), 0) << "Plain is not expected value";
}

TEST_F(AESTest, AesCbcBufferSizeValidation)
{
    azihsm_error err;

    // Generate AES 128-bit key for testing
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 128;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {
        .props = props,
        .count = 3};

    err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES key for buffer validation test";

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    // Setup IV for CBC mode
    uint8_t iv_data[16] = {0};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Test data for unpadded mode (must be block-aligned)
    uint8_t plaintext[] = "1234567890123456"; // 16 bytes - exactly one block
    azihsm_buffer pt_buffer = {.buf = plaintext, .len = 16};

    // === ENCRYPT BUFFER VALIDATION TESTS ===

    // Test 1: Insufficient ciphertext buffer for encrypt
    std::vector<uint8_t> small_ciphertext(8); // Too small for 16 byte plaintext
    azihsm_buffer small_ct_buffer = {.buf = small_ciphertext.data(), .len = 8};

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &small_ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << "Should reject insufficient ciphertext buffer for CBC encrypt";

    // Test 2: Exact size ciphertext buffer for encrypt
    std::vector<uint8_t> exact_ciphertext(16); // Exact match
    azihsm_buffer exact_ct_buffer = {.buf = exact_ciphertext.data(), .len = 16};

    // Reset IV for each test
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &exact_ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should succeed with exact size ciphertext buffer for CBC encrypt";

    // Verify the ciphertext is different from plaintext
    EXPECT_NE(memcmp(exact_ciphertext.data(), plaintext, 16), 0) << "Ciphertext should differ from plaintext";

    // Test 3: Larger ciphertext buffer for encrypt
    std::vector<uint8_t> large_ciphertext(32); // Larger than needed
    azihsm_buffer large_ct_buffer = {.buf = large_ciphertext.data(), .len = 32};

    // Reset IV and fill large buffer with known pattern to verify unused space
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
    std::fill(large_ciphertext.begin(), large_ciphertext.end(), 0xAA);

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &large_ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should succeed with larger ciphertext buffer for CBC encrypt";

    // Verify that only the first 16 bytes were modified
    EXPECT_NE(memcmp(large_ciphertext.data(), plaintext, 16), 0) << "First 16 bytes should contain encrypted data";

    // Verify unused buffer space remains unchanged
    bool unused_space_unchanged = true;
    for (size_t i = 16; i < large_ciphertext.size(); ++i)
    {
        if (large_ciphertext[i] != 0xAA)
        {
            unused_space_unchanged = false;
            break;
        }
    }
    EXPECT_TRUE(unused_space_unchanged) << "Unused buffer space should remain unchanged";

    // Test 4: Non-block-aligned input (unpadded mode)
    uint8_t unaligned_plaintext[] = "12345"; // 5 bytes - not block-aligned
    azihsm_buffer unaligned_pt_buffer = {.buf = unaligned_plaintext, .len = 5};
    std::vector<uint8_t> unaligned_ciphertext(16);
    azihsm_buffer unaligned_ct_buffer = {.buf = unaligned_ciphertext.data(), .len = 16};

    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &unaligned_pt_buffer, &unaligned_ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT) << "Should reject non-block-aligned input in unpadded CBC mode";

    // === DECRYPT BUFFER VALIDATION TESTS ===

    // First, create valid ciphertext by encrypting known plaintext
    std::vector<uint8_t> valid_ciphertext(16);
    azihsm_buffer valid_ct_buffer = {.buf = valid_ciphertext.data(), .len = 16};

    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &valid_ct_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to create test ciphertext for decrypt validation";

    // Test 5: Insufficient plaintext buffer for decrypt
    std::vector<uint8_t> small_plaintext(8); // Too small for 16 byte ciphertext
    azihsm_buffer small_pt_buffer_decrypt = {.buf = small_plaintext.data(), .len = 8};

    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &valid_ct_buffer, &small_pt_buffer_decrypt);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << "Should reject insufficient plaintext buffer for CBC decrypt";

    // Test 6: Exact size plaintext buffer for decrypt
    std::vector<uint8_t> exact_plaintext(16); // Exact match
    azihsm_buffer exact_pt_buffer = {.buf = exact_plaintext.data(), .len = 16};

    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &valid_ct_buffer, &exact_pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should succeed with exact size plaintext buffer for CBC decrypt";

    // Verify decrypted data matches original plaintext
    EXPECT_EQ(memcmp(exact_plaintext.data(), plaintext, 16), 0) << "Decrypted data should match original plaintext";

    // Test 7: Larger plaintext buffer for decrypt
    std::vector<uint8_t> large_plaintext(32); // Larger than needed
    azihsm_buffer large_pt_buffer = {.buf = large_plaintext.data(), .len = 32};

    // Reset IV and fill large buffer with known pattern
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
    std::fill(large_plaintext.begin(), large_plaintext.end(), 0xBB);

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &valid_ct_buffer, &large_pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should succeed with larger plaintext buffer for CBC decrypt";

    // Verify that only the first 16 bytes contain decrypted data
    EXPECT_EQ(memcmp(large_plaintext.data(), plaintext, 16), 0) << "First 16 bytes should contain decrypted data";

    // Verify unused buffer space remains unchanged
    unused_space_unchanged = true;
    for (size_t i = 16; i < large_plaintext.size(); ++i)
    {
        if (large_plaintext[i] != 0xBB)
        {
            unused_space_unchanged = false;
            break;
        }
    }
    EXPECT_TRUE(unused_space_unchanged) << "Unused buffer space should remain unchanged after decrypt";

    std::cout << "AES CBC buffer size validation test passed" << std::endl;
}

// ================================================================================
// AES XTS One-Shot Tests
// ================================================================================

TEST_F(AESTest, AesXtsKeySizeValidation)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    // Test valid AES XTS key size (512-bit = 256-bit per key)
    uint32_t valid_size = 512;
    azihsm_handle key_handle = 0;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &valid_size, .len = sizeof(valid_size)}};
    azihsm_key_prop_list prop_list = {.props = props, .count = 1};

    auto err = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES XTS 512-bit key";
    EXPECT_NE(key_handle, 0) << "Got null handle for AES XTS 512-bit key";

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    // Test invalid AES XTS key sizes
    std::vector<uint32_t> invalid_sizes = {128, 192, 256, 384, 1024};
    for (auto bit_len : invalid_sizes)
    {
        azihsm_handle invalid_key_handle = 0;
        azihsm_key_prop invalid_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}};
        azihsm_key_prop_list invalid_prop_list = {.props = invalid_props, .count = 1};

        auto invalid_err = azihsm_key_gen(session_handle, &algo, &invalid_prop_list, &invalid_key_handle);
        EXPECT_EQ(invalid_err, AZIHSM_UNSUPPORTED_KEY_SIZE) << "Should reject invalid AES XTS key size: " << bit_len;
        EXPECT_EQ(invalid_key_handle, 0);
    }
}

TEST_F(AESTest, AesXtsEncryptDecrypt)
{
    // Generate AES XTS key (512-bit)
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES XTS 256-bit key";
    EXPECT_NE(key_handle, 0) << "Got null handle for AES XTS 256-bit key";

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    // Test data - 16 bytes (minimum for XTS mode)
    uint8_t plaintext[] = "1234567890123456"; // 16 bytes
    size_t plaintext_len = 16;

    // Sector number for AES-XTS (16 bytes)

    azihsm_algo_aes_xts_params xts_params = {
        .sector_num = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
        .data_unit_len = 0};

    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    azihsm_buffer pt_buffer = {.buf = plaintext, .len = static_cast<uint32_t>(plaintext_len)};
    std::vector<uint8_t> ciphertext_data(plaintext_len);
    azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = static_cast<uint32_t>(ciphertext_data.size())};

    // Perform encryption
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed for AES XTS";

    // Verify ciphertext is different from plaintext
    EXPECT_NE(memcmp(plaintext, ciphertext_data.data(), plaintext_len), 0)
        << "Ciphertext should be different from plaintext for AES XTS";

    // For XTS, sector number doesn't get modified like CBC IV - no need to reset
    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    std::vector<uint8_t> decrypted_data(plaintext_len);
    azihsm_buffer decrypted_buffer = {.buf = decrypted_data.data(), .len = static_cast<uint32_t>(decrypted_data.size())};

    // Perform decryption
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Decryption failed for AES XTS";

    // Verify decrypted data matches original plaintext
    EXPECT_EQ(memcmp(plaintext, decrypted_data.data(), plaintext_len), 0)
        << "Decrypted data should match original plaintext for AES XTS";

    std::cout << "AES XTS encrypt/decrypt test passed" << std::endl;
}

TEST_F(AESTest, AesXtsEncryptDecryptLargeData)
{
    // Generate AES XTS key
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    // Test data - 512 bytes (32 AES blocks)
    std::vector<uint8_t> plaintext(512);
    for (size_t i = 0; i < plaintext.size(); ++i)
    {
        plaintext[i] = static_cast<uint8_t>(i % 256);
    }

    azihsm_algo_aes_xts_params xts_params = {
        .sector_num = {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00},
        .data_unit_len = 0};

    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};
    std::vector<uint8_t> ciphertext_data(plaintext.size());
    azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = static_cast<uint32_t>(ciphertext_data.size())};

    // Perform encryption
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify ciphertext is different from plaintext
    EXPECT_NE(memcmp(plaintext.data(), ciphertext_data.data(), plaintext.size()), 0);

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    std::vector<uint8_t> decrypted_data(plaintext.size());
    azihsm_buffer decrypted_buffer = {.buf = decrypted_data.data(), .len = static_cast<uint32_t>(decrypted_data.size())};

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    EXPECT_EQ(memcmp(plaintext.data(), decrypted_data.data(), plaintext.size()), 0);

    std::cout << "AES XTS large data encrypt/decrypt test passed" << std::endl;
}

TEST_F(AESTest, AesXtsDifferentSectorNumbers)
{
    // Generate AES XTS key
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    // Test data - 64 bytes
    uint8_t plaintext[] = "1234567890123456789012345678901234567890123456789012345678901234"; // 64 bytes
    size_t plaintext_len = 64;

    // Test with different sector numbers
    azihsm_algo_aes_xts_params xts_params1 = {
        .sector_num = {
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        .data_unit_len = 0};

    azihsm_algo_aes_xts_params xts_params2 = {
        .sector_num = {
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        .data_unit_len = 0};

    azihsm_algo encrypt_algo1 = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params1,
        .len = sizeof(xts_params1)};

    azihsm_algo encrypt_algo2 = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params2,
        .len = sizeof(xts_params2)};

    azihsm_buffer pt_buffer = {.buf = plaintext, .len = static_cast<uint32_t>(plaintext_len)};
    std::vector<uint8_t> ciphertext1(plaintext_len);
    std::vector<uint8_t> ciphertext2(plaintext_len);
    azihsm_buffer ct_buffer1 = {.buf = ciphertext1.data(), .len = static_cast<uint32_t>(ciphertext1.size())};
    azihsm_buffer ct_buffer2 = {.buf = ciphertext2.data(), .len = static_cast<uint32_t>(ciphertext2.size())};

    // Encrypt with sector number 1
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo1, key_handle, &pt_buffer, &ct_buffer1);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Encrypt with sector number 2
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo2, key_handle, &pt_buffer, &ct_buffer2);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Ciphertexts should be different due to different sector numbers (tweaks)
    EXPECT_NE(memcmp(ciphertext1.data(), ciphertext2.data(), plaintext_len), 0)
        << "Ciphertexts should be different with different sector numbers";

    // Both should be different from plaintext
    EXPECT_NE(memcmp(plaintext, ciphertext1.data(), plaintext_len), 0);
    EXPECT_NE(memcmp(plaintext, ciphertext2.data(), plaintext_len), 0);

    // Decrypt with correct sector numbers
    azihsm_algo decrypt_algo1 = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params1,
        .len = sizeof(xts_params1)};

    azihsm_algo decrypt_algo2 = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params2,
        .len = sizeof(xts_params2)};

    std::vector<uint8_t> decrypted1(plaintext_len);
    std::vector<uint8_t> decrypted2(plaintext_len);
    azihsm_buffer decrypted_buffer1 = {.buf = decrypted1.data(), .len = static_cast<uint32_t>(decrypted1.size())};
    azihsm_buffer decrypted_buffer2 = {.buf = decrypted2.data(), .len = static_cast<uint32_t>(decrypted2.size())};

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo1, key_handle, &ct_buffer1, &decrypted_buffer1);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo2, key_handle, &ct_buffer2, &decrypted_buffer2);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Both should decrypt to original plaintext
    EXPECT_EQ(memcmp(plaintext, decrypted1.data(), plaintext_len), 0);
    EXPECT_EQ(memcmp(plaintext, decrypted2.data(), plaintext_len), 0);

    std::cout << "AES XTS different sector numbers test passed" << std::endl;
}

TEST_F(AESTest, AesXtsVariousDataSizes)
{
    // Generate AES XTS key
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    // Test various data sizes that are valid for XTS (>= 16 bytes)
    std::vector<size_t> test_sizes = {16, 32, 48, 64, 128, 256, 1024};

    for (size_t size : test_sizes)
    {
        // Create test data of specified size
        std::vector<uint8_t> plaintext(size);
        for (size_t i = 0; i < size; ++i)
        {
            plaintext[i] = static_cast<uint8_t>(i % 256);
        }

        azihsm_algo_aes_xts_params xts_params = {
            .sector_num = {
                static_cast<uint8_t>(size & 0xFF), static_cast<uint8_t>((size >> 8) & 0xFF), 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0},
            .data_unit_len = 0};

        azihsm_algo encrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_XTS,
            .params = &xts_params,
            .len = sizeof(xts_params)};

        azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};
        std::vector<uint8_t> ciphertext(size);
        std::vector<uint8_t> decrypted(size);
        azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};
        azihsm_buffer decrypted_buffer = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

        // Test encrypt/decrypt round trip
        err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to encrypt data of size " << size;

        EXPECT_NE(memcmp(plaintext.data(), ciphertext.data(), size), 0)
            << "Ciphertext should differ from plaintext for size " << size;

        azihsm_algo decrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_XTS,
            .params = &xts_params,
            .len = sizeof(xts_params)};

        err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to decrypt data of size " << size;

        EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), size), 0)
            << "Round-trip should succeed for size " << size;
    }

    std::cout << "AES XTS various data sizes test passed" << std::endl;
}

TEST_F(AESTest, AesXtsEncryptDecryptLoop)
{
    // Generate AES XTS key
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES XTS key";

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS); });

    // Seed random number generator for reproducible tests
    std::srand(42);

    // Perform multiple encrypt/decrypt operations with different data and sector numbers
    constexpr int num_iterations = 10;
    constexpr size_t data_size = 64; // 64 bytes (4 AES blocks)

    for (int i = 0; i < num_iterations; ++i)
    {
        // Generate different test data for each iteration
        std::vector<uint8_t> plaintext(data_size);
        for (size_t j = 0; j < data_size; ++j)
        {
            plaintext[j] = static_cast<uint8_t>(std::rand() & 0xFF);
        }

        // Generate random sector number
        azihsm_algo_aes_xts_params xts_params = {};
        for (int k = 0; k < 16; ++k)
        {
            xts_params.sector_num[k] = static_cast<uint8_t>(std::rand() & 0xFF);
        }

        azihsm_algo encrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_XTS,
            .params = &xts_params,
            .len = sizeof(xts_params)};

        azihsm_algo decrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_XTS,
            .params = &xts_params,
            .len = sizeof(xts_params)};

        // Prepare buffers
        azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};
        std::vector<uint8_t> ciphertext(data_size);
        std::vector<uint8_t> decrypted(data_size);
        azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};
        azihsm_buffer decrypted_buffer = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

        // Encrypt
        err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed on iteration " << i;

        // Verify ciphertext is different from plaintext
        EXPECT_NE(memcmp(plaintext.data(), ciphertext.data(), data_size), 0)
            << "Ciphertext should differ from plaintext on iteration " << i;

        // Decrypt
        err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Decryption failed on iteration " << i;

        // Verify decrypted data matches original plaintext
        EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), data_size), 0)
            << "Decrypted data should match plaintext on iteration " << i;

        // Print progress for debugging
        std::cout << "AES XTS loop test iteration " << i << " passed" << std::endl;
    }

    std::cout << "AES XTS encrypt/decrypt loop test with " << num_iterations << " iterations passed" << std::endl;
}

TEST_F(AESTest, AesXtsInvalidParamSize)
{
    // Generate AES XTS key first
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 2};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    uint8_t plaintext[] = "1234567890123456";

    azihsm_algo_aes_xts_params xts_params = {.sector_num = {0}, .data_unit_len = 0};

    // Test with incorrect parameter length (too small)
    azihsm_algo encrypt_algo_invalid = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params) - 1 // Make it smaller than required
    };

    azihsm_buffer pt_buffer = {.buf = plaintext, .len = 16};
    std::vector<uint8_t> ciphertext_data(16);
    azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = 16};

    // Should fail with invalid argument due to insufficient parameter size
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo_invalid, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT) << "Should reject algorithm params with insufficient length";

    // Test with zero length
    azihsm_algo encrypt_algo_zero = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = 0};

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo_zero, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT) << "Should reject algorithm params with zero length";
}

TEST_F(AESTest, AesXtsSectorNumberValidation)
{
    // Generate AES XTS key
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 2};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    uint8_t plaintext[] = "1234567890123456";
    azihsm_buffer pt_buffer = {.buf = plaintext, .len = 16};
    std::vector<uint8_t> ciphertext_data(16);
    azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = 16};

    // Valid sector number (16 bytes) - this is now always valid since it's a fixed array

    azihsm_algo_aes_xts_params valid_sector_params = {
        .sector_num = {0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
                       0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78},
        .data_unit_len = 0};

    azihsm_algo valid_sector_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &valid_sector_params,
        .len = sizeof(valid_sector_params)};

    err = azihsm_crypt_encrypt(session_handle, &valid_sector_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should accept valid 16-byte sector number for AES XTS";
}

TEST_F(AESTest, AesXtsConsistentResults)
{
    // Generate AES XTS key
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS); });

    uint8_t plaintext[] = "This is a test message for XTS mode encryption and decryption testing. Done!!!!"; // 80 bytes
    size_t plaintext_len = sizeof(plaintext);

    // Test that same sector number produces consistent results
    azihsm_algo_aes_xts_params xts_params = {
        .sector_num = {
            0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
            0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78},
        .data_unit_len = 0};

    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    azihsm_buffer pt_buffer = {.buf = plaintext, .len = static_cast<uint32_t>(plaintext_len)};
    std::vector<uint8_t> ciphertext1(plaintext_len);
    std::vector<uint8_t> ciphertext2(plaintext_len);
    azihsm_buffer ct_buffer1 = {.buf = ciphertext1.data(), .len = static_cast<uint32_t>(ciphertext1.size())};
    azihsm_buffer ct_buffer2 = {.buf = ciphertext2.data(), .len = static_cast<uint32_t>(ciphertext2.size())};

    // First encryption
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer1);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Second encryption with same parameters
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer2);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Results should be identical
    EXPECT_EQ(memcmp(ciphertext1.data(), ciphertext2.data(), plaintext_len), 0)
        << "Same sector number should produce identical ciphertext";

    // Decrypt and verify
    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    std::vector<uint8_t> decrypted(plaintext_len);
    azihsm_buffer decrypted_buffer = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer1, &decrypted_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    EXPECT_EQ(memcmp(plaintext, decrypted.data(), plaintext_len), 0);

    std::cout << "AES XTS consistent results test passed" << std::endl;
}

TEST_F(AESTest, AesXtsBufferSizeValidation)
{
    // Generate AES XTS key
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    azihsm_algo_aes_xts_params xts_params = {
        .sector_num = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
        .data_unit_len = 0};

    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    uint8_t plaintext[] = "This is test data for XTS buffer validation testing success!!!!"; // 64 bytes
    azihsm_buffer pt_buffer = {.buf = plaintext, .len = sizeof(plaintext)};

    // Test 1: Insufficient ciphertext buffer for encrypt
    std::vector<uint8_t> small_ciphertext(sizeof(plaintext) - 1); // Smaller than plaintext
    azihsm_buffer small_ct_buffer = {.buf = small_ciphertext.data(), .len = static_cast<uint32_t>(small_ciphertext.size())};

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &small_ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << "Should reject insufficient ciphertext buffer for XTS encrypt";

    // Test 2: Valid encrypt with adequate buffer
    std::vector<uint8_t> adequate_ciphertext(sizeof(plaintext) + 1); // Slightly larger than plaintext
    azihsm_buffer adequate_ct_buffer = {.buf = adequate_ciphertext.data(), .len = static_cast<uint32_t>(adequate_ciphertext.size())};

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &adequate_ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should succeed with adequate ciphertext buffer for XTS encrypt";

    // Test 3: Insufficient plaintext buffer for decrypt
    std::vector<uint8_t> small_plaintext(sizeof(plaintext) - 1); // Smaller than ciphertext
    azihsm_buffer small_pt_buffer = {.buf = small_plaintext.data(), .len = static_cast<uint32_t>(small_plaintext.size())};

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &adequate_ct_buffer, &small_pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << "Should reject insufficient plaintext buffer for XTS decrypt";

    // Test 4: Valid decrypt with adequate buffer
    std::vector<uint8_t> adequate_plaintext(sizeof(plaintext));
    azihsm_buffer adequate_pt_buffer = {.buf = adequate_plaintext.data(), .len = static_cast<uint32_t>(adequate_plaintext.size())};

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &adequate_ct_buffer, &adequate_pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should succeed with adequate plaintext buffer for XTS decrypt";

    // Test 5: Larger buffer should work fine
    std::vector<uint8_t> large_ciphertext(sizeof(plaintext) + 1); // Larger than plaintext
    azihsm_buffer large_ct_buffer = {.buf = large_ciphertext.data(), .len = static_cast<uint32_t>(large_ciphertext.size())};

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &large_ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should succeed with larger ciphertext buffer for XTS encrypt";

    std::cout << "AES XTS buffer size validation test passed" << std::endl;
}

TEST_F(AESTest, AesXtsBufferSizeQuery)
{
    // Generate a 512-bit AES-XTS key
    uint32_t bit_len = 512;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    azihsm_algo_aes_xts_params xts_params = {
        .sector_num = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
        .data_unit_len = 0};

    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    uint8_t plaintext[] = "This is test data for XTS buffer validation testing success!!!!"; // 64 bytes
    azihsm_buffer pt_buffer = {.buf = plaintext, .len = sizeof(plaintext)};

    printf("Plaintext length: %u bytes\n", pt_buffer.len);

    // Test 1: Query required ciphertext buffer size for encrypt
    azihsm_buffer query_ct_buffer = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &query_ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << "Should return insufficient buffer when querying size";
    EXPECT_GT(query_ct_buffer.len, 0) << "Should return required ciphertext buffer size";
    EXPECT_GE(query_ct_buffer.len, sizeof(plaintext)) << "Required size should be at least as large as plaintext";

    // Test 2: Encrypt with the recommended buffer size
    std::vector<uint8_t> ciphertext_data(query_ct_buffer.len);
    azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = query_ct_buffer.len};

    printf("Recommended ciphertext buffer size: %u bytes\n", ct_buffer.len);

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should succeed with recommended ciphertext buffer size";

    // Test 3: Query required plaintext buffer size for decrypt
    azihsm_buffer query_pt_buffer = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &query_pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << "Should return insufficient buffer when querying size";
    EXPECT_GT(query_pt_buffer.len, 0) << "Should return required plaintext buffer size";
    EXPECT_GE(query_pt_buffer.len, ct_buffer.len) << "Required size should be at least as large as ciphertext";

    // Test 4: Decrypt with the recommended buffer size
    std::vector<uint8_t> decrypted_data(query_pt_buffer.len);
    azihsm_buffer decrypt_pt_buffer = {.buf = decrypted_data.data(), .len = query_pt_buffer.len};

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypt_pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should succeed with recommended plaintext buffer size";

    // Verify decrypted data matches original
    EXPECT_EQ(memcmp(plaintext, decrypted_data.data(), sizeof(plaintext)), 0) << "Decrypted data should match original plaintext";

    std::cout << "AES XTS buffer size query test passed (encrypt query size: " << query_ct_buffer.len
              << ", decrypt query size: " << query_pt_buffer.len << ")" << std::endl;
}

// ================================================================================
// AES CBC Streaming (No Padding) Tests
// ================================================================================

TEST_F(AESTest, CbcStreamingUnpadded_EncryptBasic)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Test data - 48 bytes (3 blocks)
    const char *plaintext = "123456789012345612345678901234561234567890123456";
    constexpr size_t plaintext_len = 48;

    uint8_t iv_data[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                           0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Initialize streaming encryption
    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_encrypt_init(session_handle, &algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    // Scope guard to clean up context if test fails before finalize
    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            // Try to finalize to clean up - ignore errors since we're in cleanup
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    std::vector<uint8_t> ciphertext(plaintext_len);
    size_t total_written = 0;

    // Process data in 16-byte chunks using update()
    for (size_t chunk_start = 0; chunk_start < plaintext_len; chunk_start += 16)
    {
        size_t chunk_size = std::min(size_t(16), plaintext_len - chunk_start);

        azihsm_buffer pt_chunk = {
            .buf = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(plaintext + chunk_start)),
            .len = static_cast<uint32_t>(chunk_size)};

        azihsm_buffer ct_chunk = {
            .buf = ciphertext.data() + total_written,
            .len = static_cast<uint32_t>(ciphertext.size() - total_written)};

        err = azihsm_crypt_encrypt_update(session_handle, ctx_handle, &pt_chunk, &ct_chunk);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        total_written += ct_chunk.len;

        // Each complete block should produce exactly 16 bytes of output
        if (chunk_size == 16)
        {
            EXPECT_EQ(ct_chunk.len, 16) << "Should write 16 bytes for complete block";
        }
    }

    // Finalize should return 0 bytes in unpadded mode when all data is block-aligned
    azihsm_buffer final_buf = {.buf = nullptr, .len = 0};

    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(final_buf.len, 0) << "Should write 0 bytes in finalize for unpadded mode";

    ctx_handle = 0; // Mark as cleaned up so scope guard doesn't try again

    EXPECT_EQ(total_written, plaintext_len) << "Should have written all 48 bytes";

    // Verify total output matches non-streaming encryption
    // Reset IV since streaming operation modified it
    uint8_t iv_data_compare[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    azihsm_algo_aes_cbc_params cbc_params_compare = {0};
    memcpy(cbc_params_compare.iv, iv_data_compare, sizeof(iv_data_compare));

    azihsm_algo algo_compare = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params_compare,
        .len = sizeof(cbc_params_compare)};

    azihsm_buffer pt_buffer = {
        .buf = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(plaintext)),
        .len = plaintext_len};

    std::vector<uint8_t> expected_ct(plaintext_len);
    azihsm_buffer expected_ct_buffer = {.buf = expected_ct.data(), .len = static_cast<uint32_t>(expected_ct.size())};

    err = azihsm_crypt_encrypt(session_handle, &algo_compare, key_handle, &pt_buffer, &expected_ct_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    EXPECT_EQ(ciphertext, expected_ct) << "Streaming and non-streaming should match";
}

TEST_F(AESTest, CbcStreamingUnpadded_DecryptBasic)
{
    // Generate a 256-bit AES-CBC key
    uint32_t bit_len = 256;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Create test data and encrypt it first
    const char *plaintext = "12345678901234561234567890123456"; // 32 bytes (2 blocks)
    constexpr size_t plaintext_len = 32;

    uint8_t iv_data[16] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                           0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    azihsm_buffer pt_buffer = {
        .buf = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(plaintext)),
        .len = plaintext_len};

    std::vector<uint8_t> ciphertext(plaintext_len);
    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Now test streaming decryption
    // Reset IV since encryption modified it
    uint8_t iv_data_decrypt[16] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                                   0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    azihsm_algo_aes_cbc_params decrypt_params = {0};
    memcpy(decrypt_params.iv, iv_data_decrypt, sizeof(iv_data_decrypt));

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &decrypt_params,
        .len = sizeof(decrypt_params)};

    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_decrypt_init(session_handle, &decrypt_algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    // Scope guard to clean up context if test fails before finalize
    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            // Try to finalize to clean up - ignore errors since we're in cleanup
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_decrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    std::vector<uint8_t> decrypted(plaintext_len);

    // Decrypt first block (16 bytes)
    azihsm_buffer ct_chunk1 = {.buf = ciphertext.data(), .len = 16};
    azihsm_buffer pt_chunk1 = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt_update(session_handle, ctx_handle, &ct_chunk1, &pt_chunk1);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(pt_chunk1.len, 16) << "Should write 16 bytes for first block";

    // Decrypt second block (16 bytes)
    azihsm_buffer ct_chunk2 = {.buf = ciphertext.data() + 16, .len = 16};
    azihsm_buffer pt_chunk2 = {.buf = decrypted.data() + pt_chunk1.len, .len = static_cast<uint32_t>(decrypted.size() - pt_chunk1.len)};

    err = azihsm_crypt_decrypt_update(session_handle, ctx_handle, &ct_chunk2, &pt_chunk2);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(pt_chunk2.len, 16) << "Should write 16 bytes for second block";

    // Finalize with no remaining data
    azihsm_buffer final_buf = {.buf = nullptr, .len = 0};

    err = azihsm_crypt_decrypt_final(session_handle, ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(final_buf.len, 0) << "Finalize should return 0 bytes when no data remains";

    ctx_handle = 0; // Mark as cleaned up so scope guard doesn't try again

    // Verify decrypted data matches original
    EXPECT_EQ(memcmp(decrypted.data(), plaintext, plaintext_len), 0) << "Decrypted data should match original";
}

TEST_F(AESTest, CbcStreamingUnpadded_EncryptPartialBlocks)
{
    // Generate a 256-bit AES-CBC key
    uint32_t bit_len = 256;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 2};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Test data - 48 bytes (block-aligned, should succeed)
    std::vector<uint8_t> plaintext(48, 0xAA);

    uint8_t iv_data[16] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                           0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Initialize streaming encryption without padding
    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_encrypt_init(session_handle, &algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    // Scope guard to clean up context if test fails before finalize
    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            // Try to finalize to clean up - ignore errors since we're in cleanup
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    std::vector<uint8_t> ciphertext(48);
    size_t total_written = 0;

    // Feed data in small chunks to test partial block handling
    const size_t chunks[] = {7, 5, 12, 8, 10, 6}; // Total: 48 bytes (block-aligned)
    size_t offset = 0;

    for (size_t chunk_size : chunks)
    {
        size_t end = std::min(offset + chunk_size, plaintext.size());

        azihsm_buffer pt_chunk = {
            .buf = plaintext.data() + offset,
            .len = static_cast<uint32_t>(end - offset)};

        azihsm_buffer ct_chunk = {
            .buf = ciphertext.data() + total_written,
            .len = static_cast<uint32_t>(ciphertext.size() - total_written)};

        err = azihsm_crypt_encrypt_update(session_handle, ctx_handle, &pt_chunk, &ct_chunk);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        total_written += ct_chunk.len;
        offset = end;

        // Only complete blocks should be output
        EXPECT_EQ(total_written % 16, 0) << "Should only output complete blocks";
    }

    // Should have processed 48 bytes (3 complete blocks)
    EXPECT_EQ(total_written, 48) << "Should have written 48 bytes for 3 complete blocks";

    // Finalize should succeed with block-aligned data (should return 0 bytes)
    azihsm_buffer final_buf = {.buf = nullptr, .len = 0};

    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(final_buf.len, 0) << "Finalize should return 0 bytes when data is block-aligned";

    ctx_handle = 0; // Mark as cleaned up so scope guard doesn't try again

    total_written += final_buf.len;

    EXPECT_EQ(total_written, 48) << "Should have encrypted all 48 bytes";

    // Verify by decrypting in single shot
    // Reset IV since encryption modified it
    uint8_t iv_data_decrypt[16] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                   0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
    azihsm_algo_aes_cbc_params decrypt_params = {0};
    memcpy(decrypt_params.iv, iv_data_decrypt, sizeof(iv_data_decrypt));

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &decrypt_params,
        .len = sizeof(decrypt_params)};

    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    std::vector<uint8_t> decrypted(48);
    azihsm_buffer pt_buffer = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &pt_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify decrypted data matches original
    EXPECT_EQ(decrypted, plaintext) << "Decrypted data should match original plaintext";
}

TEST_F(AESTest, CbcStreamingUnpadded_DecryptPartialBlocks)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Create plaintext (3 blocks = 48 bytes)
    std::vector<uint8_t> plaintext(48, 0xBB);

    uint8_t iv_data[16] = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                           0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};

    std::vector<uint8_t> ciphertext(48);
    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Now test streaming decryption with partial chunks
    // Reset IV since encryption modified it
    uint8_t iv_data_decrypt[16] = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                                   0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
    azihsm_algo_aes_cbc_params decrypt_params = {0};
    memcpy(decrypt_params.iv, iv_data_decrypt, sizeof(iv_data_decrypt));

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &decrypt_params,
        .len = sizeof(decrypt_params)};

    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_decrypt_init(session_handle, &decrypt_algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    // Scope guard to clean up context if test fails before finalize
    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            // Try to finalize to clean up - ignore errors since we're in cleanup
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_decrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    std::vector<uint8_t> decrypted(48);
    size_t total_written = 0;

    // Feed ciphertext in irregular chunks to test partial block handling
    const size_t chunks[] = {10, 6, 20, 12}; // Total: 48 bytes
    size_t offset = 0;

    for (size_t chunk_size : chunks)
    {
        size_t end = offset + chunk_size;

        azihsm_buffer ct_chunk = {
            .buf = ciphertext.data() + offset,
            .len = static_cast<uint32_t>(end - offset)};

        azihsm_buffer pt_chunk = {
            .buf = decrypted.data() + total_written,
            .len = static_cast<uint32_t>(decrypted.size() - total_written)};

        err = azihsm_crypt_decrypt_update(session_handle, ctx_handle, &ct_chunk, &pt_chunk);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        total_written += pt_chunk.len;
        offset = end;
    }

    // Finalize with no remaining data (should return 0 bytes in unpadded mode)
    azihsm_buffer final_buf = {.buf = nullptr, .len = 0};

    err = azihsm_crypt_decrypt_final(session_handle, ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(final_buf.len, 0) << "Finalize should return 0 bytes in unpadded mode";

    ctx_handle = 0; // Mark as cleaned up so scope guard doesn't try again

    total_written += final_buf.len;

    EXPECT_EQ(total_written, 48) << "Should have decrypted all 48 bytes";
    EXPECT_EQ(decrypted, plaintext) << "Decrypted data should match original";
}

TEST_F(AESTest, CbcStreamingUnpadded_SingleByteChunks)
{
    // Generate a 256-bit AES-CBC key
    uint32_t bit_len = 256;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Test data - exactly 2 blocks
    const char *plaintext = "12345678901234561234567890123456"; // 32 bytes
    constexpr size_t plaintext_len = 32;

    uint8_t iv_data[16] = {0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                           0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Test encryption with single-byte chunks
    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_encrypt_init(session_handle, &algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    // Scope guard to clean up context if test fails before finalize
    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            // Try to finalize to clean up - ignore errors since we're in cleanup
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    std::vector<uint8_t> ciphertext(32);
    size_t total_written = 0;

    // Feed data byte by byte
    for (size_t i = 0; i < plaintext_len; ++i)
    {
        azihsm_buffer pt_byte = {
            .buf = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(plaintext + i)),
            .len = 1};

        azihsm_buffer ct_chunk = {
            .buf = ciphertext.data() + total_written,
            .len = static_cast<uint32_t>(ciphertext.size() - total_written)};

        err = azihsm_crypt_encrypt_update(session_handle, ctx_handle, &pt_byte, &ct_chunk);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        total_written += ct_chunk.len;

        // Should only output complete blocks
        if ((i + 1) % 16 == 0)
        {
            EXPECT_EQ(ct_chunk.len, 16) << "Should output complete block";
        }
        else
        {
            EXPECT_EQ(ct_chunk.len, 0) << "Should not output partial blocks";
        }
    }

    EXPECT_EQ(total_written, 32) << "Should have written all 32 bytes";

    // Finalize with no remaining data
    azihsm_buffer final_buf = {.buf = nullptr, .len = 0};

    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(final_buf.len, 0) << "Finalize should return 0 bytes when data is block-aligned";

    ctx_handle = 0; // Mark as cleaned up so scope guard doesn't try again

    // Verify by decrypting in single shot
    // Reset IV since encryption modified it
    uint8_t iv_data_decrypt[16] = {0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                                   0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
    azihsm_algo_aes_cbc_params decrypt_params = {0};
    memcpy(decrypt_params.iv, iv_data_decrypt, sizeof(iv_data_decrypt));

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &decrypt_params,
        .len = sizeof(decrypt_params)};

    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    std::vector<uint8_t> decrypted(32);
    azihsm_buffer pt_buffer = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &pt_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify decrypted data matches original
    EXPECT_EQ(memcmp(decrypted.data(), plaintext, plaintext_len), 0) << "Decrypted data should match original plaintext";
}

TEST_F(AESTest, CbcStreamingUnpadded_LargeData)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Large test data - 1024 bytes (64 blocks)
    std::vector<uint8_t> plaintext(1024, 0xCC);

    uint8_t iv_data[16] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                           0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Test streaming encryption
    azihsm_handle enc_ctx_handle = 0;
    err = azihsm_crypt_encrypt_init(session_handle, &encrypt_algo, key_handle, &enc_ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(enc_ctx_handle, 0);

    // Scope guard to clean up encrypt context if test fails before finalize
    auto enc_ctx_guard = scope_guard::make_scope_exit([&]
                                                      {
        if (enc_ctx_handle != 0)
        {
            // Try to finalize to clean up - ignore errors since we're in cleanup
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, enc_ctx_handle, &final_buf);
        } });

    std::vector<uint8_t> ciphertext(1024);
    size_t total_written = 0;

    // Process in chunks of 100 bytes
    for (size_t chunk_start = 0; chunk_start < 1024; chunk_start += 100)
    {
        size_t chunk_end = std::min(chunk_start + 100, size_t(1024));

        azihsm_buffer pt_chunk = {
            .buf = plaintext.data() + chunk_start,
            .len = static_cast<uint32_t>(chunk_end - chunk_start)};

        azihsm_buffer ct_chunk = {
            .buf = ciphertext.data() + total_written,
            .len = static_cast<uint32_t>(ciphertext.size() - total_written)};

        err = azihsm_crypt_encrypt_update(session_handle, enc_ctx_handle, &pt_chunk, &ct_chunk);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        total_written += ct_chunk.len;
    }

    // Finalize should return 0 bytes in unpadded mode
    azihsm_buffer final_enc_buf = {.buf = nullptr, .len = 0};

    err = azihsm_crypt_encrypt_final(session_handle, enc_ctx_handle, &final_enc_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(final_enc_buf.len, 0) << "Finalize should return 0 bytes when data is block-aligned";

    enc_ctx_handle = 0; // Mark as cleaned up so scope guard doesn't try again

    total_written += final_enc_buf.len;

    EXPECT_EQ(total_written, 1024) << "Should process all 1024 bytes";

    // Verify by decrypting in single shot
    // Reset IV since encryption modified it
    uint8_t iv_data_decrypt[16] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                                   0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    azihsm_algo_aes_cbc_params decrypt_params = {0};
    memcpy(decrypt_params.iv, iv_data_decrypt, sizeof(iv_data_decrypt));

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &decrypt_params,
        .len = sizeof(decrypt_params)};

    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    std::vector<uint8_t> decrypted(1024);
    azihsm_buffer pt_buffer = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &pt_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify decrypted data matches original
    EXPECT_EQ(decrypted, plaintext) << "Decrypted data should match original plaintext";
}

TEST_F(AESTest, CbcStreamingUnpadded_ErrorConditions)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    uint8_t iv_data[16] = {0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
                           0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE};

    // Test 1: Finalize without padding when partial data remains
    {
        azihsm_algo_aes_cbc_params cbc_params = {0};
        memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

        azihsm_algo encrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC, // No padding
            .params = &cbc_params,
            .len = sizeof(cbc_params)};

        azihsm_handle enc_ctx_handle = 0;
        err = azihsm_crypt_encrypt_init(session_handle, &encrypt_algo, key_handle, &enc_ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(enc_ctx_handle, 0);

        auto enc_ctx_guard = scope_guard::make_scope_exit([&]
                                                          {
            if (enc_ctx_handle != 0)
            {
                azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
                azihsm_crypt_encrypt_final(session_handle, enc_ctx_handle, &final_buf);
            } });

        // Add partial block data
        const char *partial_data = "12345"; // 5 bytes - not a complete block
        azihsm_buffer pt_buf = {
            .buf = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(partial_data)),
            .len = 5};

        std::vector<uint8_t> ciphertext(16);
        azihsm_buffer ct_buf = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

        err = azihsm_crypt_encrypt_update(session_handle, enc_ctx_handle, &pt_buf, &ct_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS); // Update should succeed but no output
        EXPECT_EQ(ct_buf.len, 0) << "Should not output partial blocks";

        // Finalize should fail because we have partial data and no padding
        azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
        err = azihsm_crypt_encrypt_final(session_handle, enc_ctx_handle, &final_buf);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Finalize should fail with partial data and no padding";

        enc_ctx_handle = 0; // Mark as cleaned up
    }

    // Test 2: Insufficient output buffer should fail without corrupting state
    {
        std::fill(std::begin(iv_data), std::end(iv_data), 0xEE);

        azihsm_algo_aes_cbc_params cbc_params = {0};
        memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

        azihsm_algo encrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC,
            .params = &cbc_params,
            .len = sizeof(cbc_params)};

        azihsm_handle enc_ctx_handle = 0;
        err = azihsm_crypt_encrypt_init(session_handle, &encrypt_algo, key_handle, &enc_ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(enc_ctx_handle, 0);

        auto enc_ctx_guard = scope_guard::make_scope_exit([&]
                                                          {
            if (enc_ctx_handle != 0)
            {
                azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
                azihsm_crypt_encrypt_final(session_handle, enc_ctx_handle, &final_buf);
            } });

        // First update: 12 bytes (buffered, no output)
        std::vector<uint8_t> pt1(12, 0xAA);
        azihsm_buffer pt_buf1 = {.buf = pt1.data(), .len = 12};
        std::vector<uint8_t> ct_dummy(32);
        azihsm_buffer ct_buf1 = {.buf = ct_dummy.data(), .len = 32};

        err = azihsm_crypt_encrypt_update(session_handle, enc_ctx_handle, &pt_buf1, &ct_buf1);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(ct_buf1.len, 0) << "First 12 bytes should be buffered";

        // Second update: 20 bytes with insufficient output buffer
        // Total buffered: 12 + 20 = 32 bytes = 2 blocks
        // Required output: 32 bytes, but we provide only 8 bytes
        std::vector<uint8_t> pt2(20, 0xBB);
        azihsm_buffer pt_buf2 = {.buf = pt2.data(), .len = 20};
        std::vector<uint8_t> ct_small(8); // Too small!
        azihsm_buffer ct_buf2 = {.buf = ct_small.data(), .len = 8};

        err = azihsm_crypt_encrypt_update(session_handle, enc_ctx_handle, &pt_buf2, &ct_buf2);
        EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << "Should fail due to insufficient buffer";
        EXPECT_EQ(ct_buf2.len, 32) << "Should return required buffer size of 32 bytes";

        // Third update: same data with correct buffer size
        // If state was NOT corrupted, this should succeed
        std::vector<uint8_t> ct_correct(32);
        azihsm_buffer ct_buf3 = {.buf = ct_correct.data(), .len = 32};

        err = azihsm_crypt_encrypt_update(session_handle, enc_ctx_handle, &pt_buf2, &ct_buf3);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should succeed with correct buffer size after previous failure";
        EXPECT_EQ(ct_buf3.len, 32) << "Should output 32 bytes (2 complete blocks)";

        // Verify finalize succeeds (no partial data remaining)
        azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
        err = azihsm_crypt_encrypt_final(session_handle, enc_ctx_handle, &final_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(final_buf.len, 0);

        enc_ctx_handle = 0;
    }

    // Test 3: Decryption with wrong ciphertext length for unpadded mode
    {
        // Reset IV
        std::fill(std::begin(iv_data), std::end(iv_data), 0xEE);

        azihsm_algo_aes_cbc_params decrypt_params = {0};
        memcpy(decrypt_params.iv, iv_data, sizeof(iv_data));

        azihsm_algo decrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC, // No padding
            .params = &decrypt_params,
            .len = sizeof(decrypt_params)};

        azihsm_handle dec_ctx_handle = 0;
        err = azihsm_crypt_decrypt_init(session_handle, &decrypt_algo, key_handle, &dec_ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(dec_ctx_handle, 0);

        auto dec_ctx_guard = scope_guard::make_scope_exit([&]
                                                          {
            if (dec_ctx_handle != 0)
            {
                azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
                azihsm_crypt_decrypt_final(session_handle, dec_ctx_handle, &final_buf);
            } });

        // Provide non-block-aligned ciphertext (invalid for unpadded mode)
        std::vector<uint8_t> bad_ciphertext(10, 0); // 10 bytes - not block-aligned
        azihsm_buffer bad_ct_buf = {.buf = bad_ciphertext.data(), .len = static_cast<uint32_t>(bad_ciphertext.size())};

        std::vector<uint8_t> plaintext(16);
        azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};

        err = azihsm_crypt_decrypt_update(session_handle, dec_ctx_handle, &bad_ct_buf, &pt_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Update should buffer partial data";

        // Try to add more data to make 1.5 blocks (24 bytes) - should fail in finalize
        std::vector<uint8_t> more_bad_data(14, 0);
        azihsm_buffer more_bad_buf = {.buf = more_bad_data.data(), .len = static_cast<uint32_t>(more_bad_data.size())};

        pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};
        err = azihsm_crypt_decrypt_update(session_handle, dec_ctx_handle, &more_bad_buf, &pt_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Update should buffer data";

        azihsm_buffer final_dec_buf = {.buf = nullptr, .len = 0};
        err = azihsm_crypt_decrypt_final(session_handle, dec_ctx_handle, &final_dec_buf);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Finalize should fail with non-block-aligned data";

        dec_ctx_handle = 0; // Mark as cleaned up
    }
}

// Test that insufficient output buffer is detected BEFORE modifying internal state
TEST_F(AESTest, CbcStreamingUnpadded_InsufficientBufferBeforeStateModification)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    uint8_t iv_data[16] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};

    // Test encrypt: insufficient buffer should fail without corrupting state
    {
        azihsm_algo_aes_cbc_params cbc_params = {0};
        memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

        azihsm_algo encrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC,
            .params = &cbc_params,
            .len = sizeof(cbc_params)};

        azihsm_handle enc_ctx_handle = 0;
        err = azihsm_crypt_encrypt_init(session_handle, &encrypt_algo, key_handle, &enc_ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(enc_ctx_handle, 0);

        auto enc_ctx_guard = scope_guard::make_scope_exit([&]
                                                          {
            if (enc_ctx_handle != 0)
            {
                azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
                azihsm_crypt_encrypt_final(session_handle, enc_ctx_handle, &final_buf);
            } });

        // First update: 12 bytes (buffered, no output)
        std::vector<uint8_t> pt1(12, 0xAA);
        azihsm_buffer pt_buf1 = {.buf = pt1.data(), .len = 12};
        std::vector<uint8_t> ct_dummy(32);
        azihsm_buffer ct_buf1 = {.buf = ct_dummy.data(), .len = 32};

        err = azihsm_crypt_encrypt_update(session_handle, enc_ctx_handle, &pt_buf1, &ct_buf1);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(ct_buf1.len, 0) << "First 12 bytes should be buffered";

        // Second update: 20 bytes with insufficient output buffer
        // Total buffered: 12 + 20 = 32 bytes = 2 blocks
        // Required output: 32 bytes, but we provide only 8 bytes
        std::vector<uint8_t> pt2(20, 0xBB);
        azihsm_buffer pt_buf2 = {.buf = pt2.data(), .len = 20};
        std::vector<uint8_t> ct_small(8); // Too small!
        azihsm_buffer ct_buf2 = {.buf = ct_small.data(), .len = 8};

        err = azihsm_crypt_encrypt_update(session_handle, enc_ctx_handle, &pt_buf2, &ct_buf2);
        EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << "Should fail due to insufficient buffer";

        // Third update: same data with correct buffer size
        // If state was NOT corrupted, this should succeed
        std::vector<uint8_t> ct_correct(32);
        azihsm_buffer ct_buf3 = {.buf = ct_correct.data(), .len = 32};

        err = azihsm_crypt_encrypt_update(session_handle, enc_ctx_handle, &pt_buf2, &ct_buf3);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should succeed with correct buffer size";
        EXPECT_EQ(ct_buf3.len, 32) << "Should output 32 bytes (2 complete blocks)";

        // Verify finalize succeeds (no partial data remaining)
        azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
        err = azihsm_crypt_encrypt_final(session_handle, enc_ctx_handle, &final_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(final_buf.len, 0);

        enc_ctx_handle = 0;
    }

    // Test decrypt: insufficient buffer should fail without corrupting state
    {
        // First create valid ciphertext
        std::vector<uint8_t> plaintext(32, 0xCC);
        std::vector<uint8_t> ciphertext(32);

        azihsm_algo_aes_cbc_params enc_params = {0};
        memcpy(enc_params.iv, iv_data, sizeof(iv_data));
        azihsm_algo encrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC,
            .params = &enc_params,
            .len = sizeof(enc_params)};

        azihsm_buffer pt_buf = {.buf = plaintext.data(), .len = 32};
        azihsm_buffer ct_buf = {.buf = ciphertext.data(), .len = 32};

        err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buf, &ct_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Reset IV for decryption
        uint8_t reset_iv[16] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
        std::memcpy(iv_data, reset_iv, 16);

        azihsm_algo_aes_cbc_params dec_params = {0};
        memcpy(dec_params.iv, iv_data, sizeof(iv_data));
        azihsm_algo decrypt_algo = {
            .id = AZIHSM_ALGO_ID_AES_CBC,
            .params = &dec_params,
            .len = sizeof(dec_params)};

        azihsm_handle dec_ctx_handle = 0;
        err = azihsm_crypt_decrypt_init(session_handle, &decrypt_algo, key_handle, &dec_ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(dec_ctx_handle, 0);

        auto dec_ctx_guard = scope_guard::make_scope_exit([&]
                                                          {
            if (dec_ctx_handle != 0)
            {
                azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
                azihsm_crypt_decrypt_final(session_handle, dec_ctx_handle, &final_buf);
            } });

        // First update: 12 bytes (buffered, no output for unpadded)
        azihsm_buffer ct_buf1 = {.buf = ciphertext.data(), .len = 12};
        std::vector<uint8_t> pt_dummy(32);
        azihsm_buffer pt_buf1 = {.buf = pt_dummy.data(), .len = 32};

        err = azihsm_crypt_decrypt_update(session_handle, dec_ctx_handle, &ct_buf1, &pt_buf1);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(pt_buf1.len, 0) << "First 12 bytes should be buffered";

        // Second update: 20 bytes with insufficient output buffer
        // Total buffered: 12 + 20 = 32 bytes = 2 blocks
        // For unpadded mode, all blocks can be processed: required output = 32 bytes
        azihsm_buffer ct_buf2 = {.buf = ciphertext.data() + 12, .len = 20};
        std::vector<uint8_t> pt_small(8); // Too small!
        azihsm_buffer pt_buf2 = {.buf = pt_small.data(), .len = 8};

        err = azihsm_crypt_decrypt_update(session_handle, dec_ctx_handle, &ct_buf2, &pt_buf2);
        EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << "Should fail due to insufficient buffer";

        // Third update: same data with correct buffer size
        // If state was NOT corrupted, this should succeed
        std::vector<uint8_t> pt_correct(32);
        azihsm_buffer pt_buf3 = {.buf = pt_correct.data(), .len = 32};

        err = azihsm_crypt_decrypt_update(session_handle, dec_ctx_handle, &ct_buf2, &pt_buf3);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should succeed with correct buffer size";
        EXPECT_EQ(pt_buf3.len, 32) << "Should output 32 bytes (2 complete blocks)";

        // Verify decrypted data matches original
        EXPECT_EQ(std::memcmp(pt_correct.data(), plaintext.data(), 32), 0);

        // Verify finalize succeeds
        azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
        err = azihsm_crypt_decrypt_final(session_handle, dec_ctx_handle, &final_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(final_buf.len, 0);

        dec_ctx_handle = 0;
    }
}

// Test that required_output_len calculation is correct for various input sizes
TEST_F(AESTest, CbcStreamingUnpadded_RequiredOutputLenCalculation)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 2};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    uint8_t iv_data[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                           0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};

    // Store the original IV for resetting
    uint8_t original_iv[16];
    std::memcpy(original_iv, iv_data, 16);

    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    azihsm_handle enc_ctx_handle = 0;
    err = azihsm_crypt_encrypt_init(session_handle, &encrypt_algo, key_handle, &enc_ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(enc_ctx_handle, 0);

    auto enc_ctx_guard = scope_guard::make_scope_exit([&]
                                                      {
        if (enc_ctx_handle != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, enc_ctx_handle, &final_buf);
        } });

    // Test various buffer + input combinations
    struct TestCase
    {
        uint32_t buffered;        // Bytes already in internal buffer
        uint32_t new_input;       // New input bytes
        uint32_t expected_output; // Expected output bytes
        const char *description;
    };

    TestCase test_cases[] = {
        {0, 5, 0, "Empty buffer + 5 bytes = no complete blocks"},
        {0, 16, 16, "Empty buffer + 16 bytes = 1 complete block"},
        {0, 32, 32, "Empty buffer + 32 bytes = 2 complete blocks"},
        {5, 11, 16, "5 buffered + 11 new = 1 complete block"},
        {5, 27, 32, "5 buffered + 27 new = 2 complete blocks"},
        {12, 4, 16, "12 buffered + 4 new = 1 complete block"},
        {12, 20, 32, "12 buffered + 20 new = 2 complete blocks"},
        {15, 1, 16, "15 buffered + 1 new = 1 complete block"},
        {15, 17, 32, "15 buffered + 17 new = 2 complete blocks"},
    };

    for (const auto &tc : test_cases)
    {
        SCOPED_TRACE(tc.description);

        // Reset context for each test case
        if (enc_ctx_handle != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, enc_ctx_handle, &final_buf);
            enc_ctx_handle = 0;
        }

        // Reset IV
        std::memcpy(iv_data, original_iv, 16);

        err = azihsm_crypt_encrypt_init(session_handle, &encrypt_algo, key_handle, &enc_ctx_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Buffer initial data if needed
        if (tc.buffered > 0)
        {
            std::vector<uint8_t> buffer_data(tc.buffered, 0xAA);
            azihsm_buffer buf = {.buf = buffer_data.data(), .len = tc.buffered};
            std::vector<uint8_t> dummy_output(64);
            azihsm_buffer out_buf = {.buf = dummy_output.data(), .len = 64};

            err = azihsm_crypt_encrypt_update(session_handle, enc_ctx_handle, &buf, &out_buf);
            ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        }

        // Now provide new input with exact buffer size
        std::vector<uint8_t> new_data(tc.new_input, 0xBB);
        azihsm_buffer in_buf = {.buf = new_data.data(), .len = tc.new_input};
        std::vector<uint8_t> output(tc.expected_output);
        azihsm_buffer out_buf = {.buf = output.data(), .len = tc.expected_output};

        err = azihsm_crypt_encrypt_update(session_handle, enc_ctx_handle, &in_buf, &out_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(out_buf.len, tc.expected_output) << "Output length mismatch";

        // Verify with one less byte buffer should fail
        if (tc.expected_output > 0)
        {
            // Reset context
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, enc_ctx_handle, &final_buf);

            // Reset IV
            std::memcpy(iv_data, original_iv, 16);

            err = azihsm_crypt_encrypt_init(session_handle, &encrypt_algo, key_handle, &enc_ctx_handle);
            ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

            // Buffer initial data if needed
            if (tc.buffered > 0)
            {
                std::vector<uint8_t> buffer_data(tc.buffered, 0xAA);
                azihsm_buffer buf = {.buf = buffer_data.data(), .len = tc.buffered};
                std::vector<uint8_t> dummy_output(64);
                azihsm_buffer out_buf2 = {.buf = dummy_output.data(), .len = 64};

                err = azihsm_crypt_encrypt_update(session_handle, enc_ctx_handle, &buf, &out_buf2);
                ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
            }

            // Try with insufficient buffer
            std::vector<uint8_t> small_output(tc.expected_output - 1);
            azihsm_buffer small_buf = {.buf = small_output.data(), .len = tc.expected_output - 1};

            err = azihsm_crypt_encrypt_update(session_handle, enc_ctx_handle, &in_buf, &small_buf);
            EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << "Should fail with buffer size - 1";
        }
    }
}

TEST_F(AESTest, CbcStreamingUnpadded_EncryptFinalizeWithoutUpdate)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 2};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    uint8_t iv_data[16] = {0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43,
                           0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC, // Unpadded
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Initialize streaming encryption
    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_encrypt_init(session_handle, &algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    // Call finalize directly without any update calls
    // For unpadded mode with empty buffer, this should return 0 bytes
    azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(final_buf.len, 0) << "Should output 0 bytes for empty input in unpadded mode";

    ctx_handle = 0;
}

// ================================================================================
// ==================== AES CBC Streaming Padded Tests ============================
// ================================================================================

TEST_F(AESTest, CbcStreamingPadded_EncryptBasic)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Test data - 43 bytes (not block-aligned, requires 5 bytes of padding)
    const uint8_t plaintext[] = {
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6D,
        0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66,
        0x6F, 0x72, 0x20, 0x70, 0x61, 0x64, 0x64, 0x65,
        0x64, 0x20, 0x43, 0x42, 0x43, 0x20, 0x6D, 0x6F,
        0x64, 0x65, 0x10};
    const size_t plaintext_len = sizeof(plaintext);

    uint8_t iv_data[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                           0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

    // Store the original IV for resetting
    uint8_t original_iv[16];
    std::memcpy(original_iv, iv_data, 16);

    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Initialize streaming encryption with padding
    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_encrypt_init(session_handle, &algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    // Padded output will be 48 bytes (43 + 5 bytes padding)
    std::vector<uint8_t> ciphertext(48);
    size_t total_written = 0;

    // Process data in chunks using update()
    size_t chunk_sizes[] = {20, 23}; // Total: 43 bytes
    size_t offset = 0;

    for (size_t chunk_size : chunk_sizes)
    {
        azihsm_buffer pt_chunk = {
            .buf = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(plaintext + offset)),
            .len = static_cast<uint32_t>(chunk_size)};

        azihsm_buffer ct_chunk = {
            .buf = ciphertext.data() + total_written,
            .len = static_cast<uint32_t>(ciphertext.size() - total_written)};

        err = azihsm_crypt_encrypt_update(session_handle, ctx_handle, &pt_chunk, &ct_chunk);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        total_written += ct_chunk.len;
        offset += chunk_size;
    }

    // Finalize should add the padding (43 bytes needs 5 bytes padding to reach 48)
    azihsm_buffer final_buf = {.buf = nullptr, .len = 0};

    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << "Should fail with null buffer";
    EXPECT_GT(final_buf.len, 0) << "Finalize should return the needed buffer size";

    std::vector<uint8_t> final_data(final_buf.len);
    final_buf = {.buf = final_data.data(), .len = static_cast<uint32_t>(final_data.size())};
    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    ctx_handle = 0;

    total_written += final_buf.len;
    EXPECT_EQ(total_written, 48) << "Should have written 48 bytes (43 + 5 bytes padding)";

    // Verify total output matches non-streaming encryption
    uint8_t iv_data_compare[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                                   0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    azihsm_algo_aes_cbc_params cbc_params_compare = {0};
    memcpy(cbc_params_compare.iv, iv_data_compare, sizeof(iv_data_compare));

    azihsm_algo algo_compare = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params_compare,
        .len = sizeof(cbc_params_compare)};

    azihsm_buffer pt_buffer = {
        .buf = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(plaintext)),
        .len = plaintext_len};

    std::vector<uint8_t> expected_ct(48);
    azihsm_buffer expected_ct_buffer = {.buf = expected_ct.data(), .len = static_cast<uint32_t>(expected_ct.size())};

    err = azihsm_crypt_encrypt(session_handle, &algo_compare, key_handle, &pt_buffer, &expected_ct_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Copy final data into ciphertext
    memcpy(ciphertext.data() + total_written - final_buf.len, final_data.data(), final_buf.len);

    EXPECT_EQ(ciphertext, expected_ct) << "Streaming and non-streaming should match";
}

TEST_F(AESTest, CbcStreamingPadded_DecryptBasic)
{
    // Generate a 256-bit AES-CBC key
    uint32_t bit_len = 256;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Create test data - 27 bytes (not block-aligned)
    const uint8_t plaintext[] = {
        0x54, 0x65, 0x73, 0x74, 0x20, 0x64, 0x61, 0x74,
        0x61, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x43, 0x42,
        0x43, 0x20, 0x70, 0x61, 0x64, 0x64, 0x69, 0x6E,
        0x67, 0x21, 0x00};
    constexpr size_t plaintext_len = sizeof(plaintext);

    uint8_t iv_data[16] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                           0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    azihsm_buffer pt_buffer = {
        .buf = const_cast<uint8_t *>(plaintext),
        .len = plaintext_len};

    // Encrypted data will be 32 bytes (27 + 5 bytes padding)
    std::vector<uint8_t> ciphertext(32);
    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(ct_buffer.len, 32);

    // Now test streaming decryption
    uint8_t iv_data_decrypt[16] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
                                   0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    azihsm_algo_aes_cbc_params decrypt_params = {0};
    memcpy(decrypt_params.iv, iv_data_decrypt, sizeof(iv_data_decrypt));

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &decrypt_params,
        .len = sizeof(decrypt_params)};

    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_decrypt_init(session_handle, &decrypt_algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_decrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    std::vector<uint8_t> decrypted(32);
    size_t total_written = 0;

    // Decrypt in chunks - in padded mode, last block is held back in update
    azihsm_buffer ct_chunk1 = {.buf = ciphertext.data(), .len = 20};
    azihsm_buffer pt_chunk1 = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt_update(session_handle, ctx_handle, &ct_chunk1, &pt_chunk1);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    total_written += pt_chunk1.len;

    // Second chunk
    azihsm_buffer ct_chunk2 = {.buf = ciphertext.data() + 20, .len = 12};
    azihsm_buffer pt_chunk2 = {.buf = decrypted.data() + total_written, .len = static_cast<uint32_t>(decrypted.size() - total_written)};

    err = azihsm_crypt_decrypt_update(session_handle, ctx_handle, &ct_chunk2, &pt_chunk2);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    total_written += pt_chunk2.len;

    // Finalize should strip padding and return remaining plaintext
    // First try with null buffer to test retry capability
    azihsm_buffer null_final_buf = {.buf = nullptr, .len = 0};

    err = azihsm_crypt_decrypt_final(session_handle, ctx_handle, &null_final_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << "Should fail with null buffer";
    EXPECT_GT(null_final_buf.len, 0) << "Should report required buffer size";

    // Now retry with adequate buffer
    std::vector<uint8_t> final_data(null_final_buf.len);
    azihsm_buffer final_buf = {.buf = final_data.data(), .len = static_cast<uint32_t>(final_data.size())};

    err = azihsm_crypt_decrypt_final(session_handle, ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Copy final data if any
    if (final_buf.len > 0)
    {
        memcpy(decrypted.data() + total_written, final_data.data(), final_buf.len);
        total_written += final_buf.len;
    }

    ctx_handle = 0;

    EXPECT_EQ(total_written, plaintext_len) << "Should have decrypted to original length (padding removed)";
    EXPECT_EQ(memcmp(decrypted.data(), plaintext, plaintext_len), 0) << "Decrypted data should match original";
}

TEST_F(AESTest, CbcStreamingPadded_EncryptPartialBlocks)
{
    // Generate a 256-bit AES-CBC key
    uint32_t bit_len = 256;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 2};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Test data - 51 bytes (not block-aligned, needs 13 bytes padding to reach 64)
    std::vector<uint8_t> plaintext(51, 0xAA);

    uint8_t iv_data[16] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                           0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_encrypt_init(session_handle, &algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    std::vector<uint8_t> ciphertext(64);
    size_t total_written = 0;

    // Feed data in small chunks to test partial block handling
    const size_t chunks[] = {7, 5, 12, 8, 10, 9}; // Total: 51 bytes
    size_t offset = 0;

    for (size_t chunk_size : chunks)
    {
        azihsm_buffer pt_chunk = {
            .buf = plaintext.data() + offset,
            .len = static_cast<uint32_t>(chunk_size)};

        azihsm_buffer ct_chunk = {
            .buf = ciphertext.data() + total_written,
            .len = static_cast<uint32_t>(ciphertext.size() - total_written)};

        err = azihsm_crypt_encrypt_update(session_handle, ctx_handle, &pt_chunk, &ct_chunk);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        total_written += ct_chunk.len;
        offset += chunk_size;

        // Only complete blocks should be output
        EXPECT_EQ(total_written % 16, 0) << "Should only output complete blocks";
    }

    // First, try with null buffer to get required size
    azihsm_buffer final_buf_query = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf_query);
    ASSERT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_GT(final_buf_query.len, 0) << "Should return required buffer size";

    // Now call with proper buffer
    std::vector<uint8_t> final_data(final_buf_query.len);
    azihsm_buffer final_buf = {.buf = final_data.data(), .len = static_cast<uint32_t>(final_data.size())};

    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_GT(final_buf.len, 0) << "Finalize should output padding";

    ctx_handle = 0;

    total_written += final_buf.len;
    EXPECT_EQ(total_written, 64) << "Should have encrypted to 64 bytes with padding";

    // Verify by decrypting
    uint8_t iv_data_decrypt[16] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                                   0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
    azihsm_algo_aes_cbc_params decrypt_params = {0};
    memcpy(decrypt_params.iv, iv_data_decrypt, sizeof(iv_data_decrypt));

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &decrypt_params,
        .len = sizeof(decrypt_params)};

    // Copy final data into ciphertext
    memcpy(ciphertext.data() + total_written - final_buf.len, final_data.data(), final_buf.len);

    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(total_written)};

    std::vector<uint8_t> decrypted(64);
    azihsm_buffer pt_buffer = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &pt_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(pt_buffer.len, 51) << "Decrypted should be original length";

    EXPECT_EQ(memcmp(decrypted.data(), plaintext.data(), 51), 0) << "Decrypted data should match original plaintext";
}

TEST_F(AESTest, CbcStreamingPadded_DecryptPartialBlocks)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Create plaintext (38 bytes, needs 10 bytes padding to reach 48)
    std::vector<uint8_t> plaintext(38, 0xBB);

    uint8_t iv_data[16] = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                           0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};

    std::vector<uint8_t> ciphertext(48);
    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(ct_buffer.len, 48);

    // Now test streaming decryption with partial chunks
    uint8_t iv_data_decrypt[16] = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                                   0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
    azihsm_algo_aes_cbc_params decrypt_params = {0};
    memcpy(decrypt_params.iv, iv_data_decrypt, sizeof(iv_data_decrypt));

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &decrypt_params,
        .len = sizeof(decrypt_params)};

    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_decrypt_init(session_handle, &decrypt_algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_decrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    std::vector<uint8_t> decrypted(48);
    size_t total_written = 0;

    // Feed ciphertext in irregular chunks
    const size_t chunks[] = {10, 6, 20, 12}; // Total: 48 bytes
    size_t offset = 0;

    for (size_t chunk_size : chunks)
    {
        azihsm_buffer ct_chunk = {
            .buf = ciphertext.data() + offset,
            .len = static_cast<uint32_t>(chunk_size)};

        azihsm_buffer pt_chunk = {
            .buf = decrypted.data() + total_written,
            .len = static_cast<uint32_t>(decrypted.size() - total_written)};

        err = azihsm_crypt_decrypt_update(session_handle, ctx_handle, &ct_chunk, &pt_chunk);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        total_written += pt_chunk.len;
        offset += chunk_size;
    }

    // First, try with null buffer to get required size
    azihsm_buffer final_buf_query = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_decrypt_final(session_handle, ctx_handle, &final_buf_query);
    ASSERT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_GT(final_buf_query.len, 0) << "Should return required buffer size";

    // Now call with proper buffer - finalize should strip padding and return remaining data
    std::vector<uint8_t> final_data(final_buf_query.len);
    azihsm_buffer final_buf = {.buf = final_data.data(), .len = static_cast<uint32_t>(final_data.size())};

    err = azihsm_crypt_decrypt_final(session_handle, ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    if (final_buf.len > 0)
    {
        memcpy(decrypted.data() + total_written, final_data.data(), final_buf.len);
        total_written += final_buf.len;
    }

    ctx_handle = 0;

    EXPECT_EQ(total_written, 38) << "Should have decrypted to original 38 bytes";
    EXPECT_EQ(memcmp(decrypted.data(), plaintext.data(), 38), 0) << "Decrypted data should match original";
}

TEST_F(AESTest, CbcStreamingPadded_BlockAlignedInput)
{
    // Test when input is already block-aligned - should add full block of padding
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Test data - exactly 32 bytes (block-aligned)
    const uint8_t plaintext[] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
    constexpr size_t plaintext_len = sizeof(plaintext);

    uint8_t iv_data[16] = {0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                           0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_encrypt_init(session_handle, &algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    // Output should be 48 bytes (32 + 16 bytes full block padding)
    std::vector<uint8_t> ciphertext(48);
    size_t total_written = 0;

    azihsm_buffer pt_buffer_in = {
        .buf = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(plaintext)),
        .len = plaintext_len};

    azihsm_buffer ct_buffer = {
        .buf = ciphertext.data(),
        .len = static_cast<uint32_t>(ciphertext.size())};

    err = azihsm_crypt_encrypt_update(session_handle, ctx_handle, &pt_buffer_in, &ct_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    total_written += ct_buffer.len;

    // First, try with null buffer to get required size
    azihsm_buffer final_buf_query = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf_query);
    ASSERT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(final_buf_query.len, 16) << "Should require 16 bytes for full block padding";

    // Now call with proper buffer - finalize should add a full block of padding (16 bytes)
    std::vector<uint8_t> final_data(final_buf_query.len);
    azihsm_buffer final_buf = {.buf = final_data.data(), .len = static_cast<uint32_t>(final_data.size())};

    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(final_buf.len, 16) << "Should add full block of padding for block-aligned input";

    ctx_handle = 0;

    total_written += final_buf.len;
    EXPECT_EQ(total_written, 48) << "Should output 48 bytes (32 + 16 padding)";

    // Verify decryption recovers original
    uint8_t iv_data_decrypt[16] = {0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                                   0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33};
    azihsm_algo_aes_cbc_params decrypt_params = {0};
    memcpy(decrypt_params.iv, iv_data_decrypt, sizeof(iv_data_decrypt));

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &decrypt_params,
        .len = sizeof(decrypt_params)};

    memcpy(ciphertext.data() + 32, final_data.data(), final_buf.len);

    azihsm_buffer ct_buf_decrypt = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(total_written)};

    std::vector<uint8_t> decrypted(48);
    azihsm_buffer pt_buffer = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buf_decrypt, &pt_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(pt_buffer.len, plaintext_len) << "Should decrypt to original length";

    EXPECT_EQ(memcmp(decrypted.data(), plaintext, plaintext_len), 0) << "Decrypted should match original";
}

TEST_F(AESTest, CbcStreamingPadded_ErrorConditions)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    uint8_t iv_data[16] = {0};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Test 1: Invalid padding during decrypt finalize
    const uint8_t plaintext[] = {
        0x54, 0x65, 0x73, 0x74, 0x44, 0x61, 0x74, 0x61,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    constexpr size_t plaintext_len = sizeof(plaintext);

    // Encrypt to get valid ciphertext
    azihsm_buffer pt_buffer = {
        .buf = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(plaintext)),
        .len = plaintext_len};

    // First query required ciphertext size
    std::vector<uint8_t> ciphertext(0);
    azihsm_buffer ct_buffer = {.buf = nullptr, .len = 0};

    err = azihsm_crypt_encrypt(session_handle, &algo, key_handle, &pt_buffer, &ct_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    ASSERT_GT(ct_buffer.len, 0) << "Should return required ciphertext size";

    // Now encrypt with proper buffer size
    ciphertext.resize(ct_buffer.len);
    ct_buffer.buf = ciphertext.data();

    err = azihsm_crypt_encrypt(session_handle, &algo, key_handle, &pt_buffer, &ct_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Corrupt the ciphertext to create invalid padding
    ciphertext[ct_buffer.len - 1] ^= 0xFF;

    // Try to decrypt with corrupted padding
    uint8_t iv_data_decrypt[16] = {0};
    azihsm_algo_aes_cbc_params decrypt_params = {0};
    memcpy(decrypt_params.iv, iv_data_decrypt, sizeof(iv_data_decrypt));

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &decrypt_params,
        .len = sizeof(decrypt_params)};

    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_decrypt_init(session_handle, &decrypt_algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_decrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    azihsm_buffer corrupted_ct = {.buf = ciphertext.data(), .len = ct_buffer.len};
    std::vector<uint8_t> decrypted(32);
    azihsm_buffer pt_out = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt_update(session_handle, ctx_handle, &corrupted_ct, &pt_out);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Final should fail due to invalid padding
    azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_decrypt_final(session_handle, ctx_handle, &final_buf);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should fail with invalid padding";

    ctx_handle = 0;
}

TEST_F(AESTest, CbcStreamingPadded_EncryptFinalizeWithoutUpdate)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 2};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    uint8_t iv_data[16] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                           0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Initialize streaming encryption
    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_encrypt_init(session_handle, &algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    // Call finalize directly without any update calls
    // This should produce a full block of padding (16 bytes)

    // First, query required size with null buffer
    azihsm_buffer final_buf_query = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf_query);
    ASSERT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(final_buf_query.len, 16) << "Should require 16 bytes for empty input with padding";

    // Now finalize with proper buffer
    std::vector<uint8_t> encrypted_padding(final_buf_query.len);
    azihsm_buffer final_buf = {.buf = encrypted_padding.data(), .len = static_cast<uint32_t>(encrypted_padding.size())};

    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(final_buf.len, 16) << "Should output 16 bytes of padding for empty input";

    ctx_handle = 0;

    // Verify by decrypting - should get back empty plaintext
    uint8_t iv_data_decrypt[16] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                                   0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
    azihsm_algo_aes_cbc_params decrypt_params = {0};
    memcpy(decrypt_params.iv, iv_data_decrypt, sizeof(iv_data_decrypt));

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &decrypt_params,
        .len = sizeof(decrypt_params)};

    azihsm_buffer ct_input = {.buf = encrypted_padding.data(), .len = final_buf.len};
    std::vector<uint8_t> decrypted(16);
    azihsm_buffer pt_output = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_input, &pt_output);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(pt_output.len, 0) << "Decrypting encrypted padding should yield empty plaintext";
}

TEST_F(AESTest, CbcStreamingPadded_DecryptFinalizeBufferQuery)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Create test data and encrypt it first
    const uint8_t plaintext[] = {
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x74, 0x65, 0x73, 0x74, 0x20, 0x64, 0x61, 0x74,
        0x61, 0x21, 0x21}; // 19 bytes
    constexpr size_t plaintext_len = sizeof(plaintext);

    uint8_t iv_data[16] = {0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                           0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Encrypt to get valid ciphertext
    azihsm_buffer pt_buffer = {
        .buf = const_cast<uint8_t *>(plaintext),
        .len = plaintext_len};

    std::vector<uint8_t> ciphertext(32); // Should be 32 bytes (19 + 13 padding)
    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_EQ(ct_buffer.len, 32) << "Ciphertext should be 32 bytes";

    // Now test streaming decryption with two-step finalize
    uint8_t iv_data_decrypt[16] = {0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
                                   0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44};
    azihsm_algo_aes_cbc_params decrypt_params = {0};
    memcpy(decrypt_params.iv, iv_data_decrypt, sizeof(iv_data_decrypt));

    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &decrypt_params,
        .len = sizeof(decrypt_params)};

    azihsm_handle dec_ctx_handle = 0;
    err = azihsm_crypt_decrypt_init(session_handle, &decrypt_algo, key_handle, &dec_ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(dec_ctx_handle, 0);

    auto dec_ctx_guard = scope_guard::make_scope_exit([&]
                                                      {
        if (dec_ctx_handle != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_decrypt_final(session_handle, dec_ctx_handle, &final_buf);
        } });

    // Feed all ciphertext through update
    azihsm_buffer ct_input = {.buf = ciphertext.data(), .len = ct_buffer.len};
    std::vector<uint8_t> decrypted(32);
    azihsm_buffer pt_output = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt_update(session_handle, dec_ctx_handle, &ct_input, &pt_output);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    // Update should output first block(s) but keep last block buffered
    EXPECT_EQ(pt_output.len, 16) << "Update should output 16 bytes, keeping last block for finalize";

    // Step 1: Query finalize buffer size with null buffer
    azihsm_buffer final_buf_query = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_decrypt_final(session_handle, dec_ctx_handle, &final_buf_query);
    ASSERT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(final_buf_query.len, 16) << "Should return upper bound of 16 bytes for finalize";

    // Step 2: Call finalize with proper buffer
    std::vector<uint8_t> final_data(final_buf_query.len);
    azihsm_buffer final_buf = {.buf = final_data.data(), .len = static_cast<uint32_t>(final_data.size())};

    err = azihsm_crypt_decrypt_final(session_handle, dec_ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(final_buf.len, 3) << "Should output 3 bytes after padding removal";

    dec_ctx_handle = 0;

    // Verify decrypted data matches original
    std::vector<uint8_t> full_decrypted(pt_output.len + final_buf.len);
    std::memcpy(full_decrypted.data(), decrypted.data(), pt_output.len);
    std::memcpy(full_decrypted.data() + pt_output.len, final_data.data(), final_buf.len);

    EXPECT_EQ(full_decrypted.size(), plaintext_len);
    EXPECT_EQ(std::memcmp(full_decrypted.data(), plaintext, plaintext_len), 0)
        << "Decrypted data should match original";
}

TEST_F(AESTest, CbcStreaming_ContextReuseAfterFinalize)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 2};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    uint8_t iv_data[16] = {0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45,
                           0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Initialize streaming encryption
    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_encrypt_init(session_handle, &algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    auto enc_ctx_guard = scope_guard::make_scope_exit([&]
                                                      {
        if (ctx_handle != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    // Process one block of data
    const uint8_t plaintext[16] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36};

    azihsm_buffer pt_buffer = {
        .buf = const_cast<uint8_t *>(plaintext),
        .len = sizeof(plaintext)};

    std::vector<uint8_t> ciphertext(16);
    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    err = azihsm_crypt_encrypt_update(session_handle, ctx_handle, &pt_buffer, &ct_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_EQ(ct_buffer.len, 16);

    // Finalize the context
    azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Now try to use the context again - should fail
    std::vector<uint8_t> ciphertext2(16);
    azihsm_buffer ct_buffer2 = {.buf = ciphertext2.data(), .len = static_cast<uint32_t>(ciphertext2.size())};

    err = azihsm_crypt_encrypt_update(session_handle, ctx_handle, &pt_buffer, &ct_buffer2);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Update should fail after finalize";

    // Finalize again should also fail
    azihsm_buffer final_buf2 = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf2);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Second finalize should fail";

    ctx_handle = 0;
}

TEST_F(AESTest, CbcStreaming_MultipleEmptyUpdates)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 2};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    uint8_t iv_data[16] = {0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46,
                           0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46, 0x46};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Initialize streaming encryption
    azihsm_handle ctx_handle = 0;
    err = azihsm_crypt_encrypt_init(session_handle, &algo, key_handle, &ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(ctx_handle, 0);

    auto ctx_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (ctx_handle != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
        } });

    std::vector<uint8_t> dummy_output(32);

    // Multiple empty updates should all succeed and return 0 bytes
    for (int i = 0; i < 5; i++)
    {
        azihsm_buffer empty_input = {.buf = nullptr, .len = 0};
        azihsm_buffer output = {.buf = dummy_output.data(), .len = static_cast<uint32_t>(dummy_output.size())};

        err = azihsm_crypt_encrypt_update(session_handle, ctx_handle, &empty_input, &output);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Empty update " << i << " should succeed";
        EXPECT_EQ(output.len, 0) << "Empty update " << i << " should return 0 bytes";
    }

    // Now add real data and verify it still works
    const uint8_t plaintext[] = {0x54, 0x65, 0x73, 0x74};
    azihsm_buffer pt_buffer = {
        .buf = const_cast<uint8_t *>(plaintext),
        .len = sizeof(plaintext)};

    azihsm_buffer ct_buffer = {.buf = dummy_output.data(), .len = static_cast<uint32_t>(dummy_output.size())};

    err = azihsm_crypt_encrypt_update(session_handle, ctx_handle, &pt_buffer, &ct_buffer);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(ct_buffer.len, 0) << "4 bytes should be buffered, no output yet";

    // Finalize should work correctly
    azihsm_buffer final_buf_query = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf_query);
    ASSERT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(final_buf_query.len, 16) << "Should need 16 bytes for 4 bytes + padding";

    std::vector<uint8_t> final_data(final_buf_query.len);
    azihsm_buffer final_buf = {.buf = final_data.data(), .len = static_cast<uint32_t>(final_data.size())};

    err = azihsm_crypt_encrypt_final(session_handle, ctx_handle, &final_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(final_buf.len, 16);

    ctx_handle = 0;
}

TEST_F(AESTest, CbcStreaming_InterleavedContexts)
{
    // Generate a 128-bit AES-CBC key
    uint32_t bit_len = 128;
    azihsm_handle key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { 
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Create two different IVs
    uint8_t iv_data1[16] = {0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47,
                            0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47};
    uint8_t iv_data2[16] = {0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
                            0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48};

    azihsm_algo_aes_cbc_params cbc_params1 = {0};
    memcpy(cbc_params1.iv, iv_data1, sizeof(iv_data1));

    azihsm_algo_aes_cbc_params cbc_params2 = {0};
    memcpy(cbc_params2.iv, iv_data2, sizeof(iv_data2));

    azihsm_algo algo1 = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params1,
        .len = sizeof(cbc_params1)};

    azihsm_algo algo2 = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params2,
        .len = sizeof(cbc_params2)};

    // Initialize two encryption contexts
    azihsm_handle enc_ctx1 = 0;
    azihsm_handle enc_ctx2 = 0;

    err = azihsm_crypt_encrypt_init(session_handle, &algo1, key_handle, &enc_ctx1);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(enc_ctx1, 0);

    err = azihsm_crypt_encrypt_init(session_handle, &algo2, key_handle, &enc_ctx2);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(enc_ctx2, 0);

    auto ctx1_guard = scope_guard::make_scope_exit([&]
                                                   {
        if (enc_ctx1 != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, enc_ctx1, &final_buf);
        } });

    auto ctx2_guard = scope_guard::make_scope_exit([&]
                                                   {
        if (enc_ctx2 != 0)
        {
            azihsm_buffer final_buf = {.buf = nullptr, .len = 0};
            azihsm_crypt_encrypt_final(session_handle, enc_ctx2, &final_buf);
        } });

    // Interleave operations on both contexts
    const uint8_t plaintext1[16] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36};

    const uint8_t plaintext2[16] = {
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};

    std::vector<uint8_t> ciphertext1(16);
    std::vector<uint8_t> ciphertext2(16);

    // Update context 1
    azihsm_buffer pt_buf1 = {.buf = const_cast<uint8_t *>(plaintext1), .len = sizeof(plaintext1)};
    azihsm_buffer ct_buf1 = {.buf = ciphertext1.data(), .len = static_cast<uint32_t>(ciphertext1.size())};

    err = azihsm_crypt_encrypt_update(session_handle, enc_ctx1, &pt_buf1, &ct_buf1);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_EQ(ct_buf1.len, 16);

    // Update context 2
    azihsm_buffer pt_buf2 = {.buf = const_cast<uint8_t *>(plaintext2), .len = sizeof(plaintext2)};
    azihsm_buffer ct_buf2 = {.buf = ciphertext2.data(), .len = static_cast<uint32_t>(ciphertext2.size())};

    err = azihsm_crypt_encrypt_update(session_handle, enc_ctx2, &pt_buf2, &ct_buf2);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_EQ(ct_buf2.len, 16);

    // Finalize both contexts
    azihsm_buffer final_buf1 = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_encrypt_final(session_handle, enc_ctx1, &final_buf1);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(final_buf1.len, 0);

    azihsm_buffer final_buf2 = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_encrypt_final(session_handle, enc_ctx2, &final_buf2);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(final_buf2.len, 0);

    enc_ctx1 = 0;
    enc_ctx2 = 0;

    // Verify ciphertexts are different (different IVs)
    EXPECT_NE(std::memcmp(ciphertext1.data(), ciphertext2.data(), 16), 0)
        << "Ciphertexts should differ due to different IVs";
}

TEST_F(AESTest, AesXtsDataUnitLen512)
{
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES XTS 256-bit key";
    EXPECT_NE(key_handle, 0) << "Got null handle for AES XTS 256-bit key";

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    // Test data - 1024 bytes (two data units of 512 bytes each)
    std::vector<uint8_t> plaintext(1024, 0xCD);
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> decrypted(plaintext.size());

    azihsm_algo_aes_xts_params xts_params = {
        .sector_num = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                       0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02},
        .data_unit_len = 512};

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};
    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    // Perform encryption
    err = azihsm_crypt_encrypt(session_handle, &algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed for AES XTS with data_unit_len=512";

    // Perform decryption
    azihsm_buffer decrypted_buffer = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt(session_handle, &algo, key_handle, &ct_buffer, &decrypted_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Decryption failed for AES XTS with data_unit_len=512";

    // Verify decrypted data matches original plaintext
    EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0)
        << "Decrypted data should match original plaintext";

    std::cout << "AES XTS data_unit_len=512 test passed" << std::endl;
}

TEST_F(AESTest, AesXtsDataUnitLen4096)
{
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES XTS 256-bit key";
    EXPECT_NE(key_handle, 0) << "Got null handle for AES XTS 256-bit key";

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    // Test data - 16384 bytes (four data units of 4096 bytes each)
    std::vector<uint8_t> plaintext(16384, 0xEF);
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> decrypted(plaintext.size());

    azihsm_algo_aes_xts_params xts_params = {
        .sector_num = {0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                       0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03},
        .data_unit_len = 4096};

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};
    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    // Perform encryption
    err = azihsm_crypt_encrypt(session_handle, &algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed for AES XTS with data_unit_len=4096";

    // Perform decryption
    azihsm_buffer decrypted_buffer = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt(session_handle, &algo, key_handle, &ct_buffer, &decrypted_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Decryption failed for AES XTS with data_unit_len=4096";

    // Verify decrypted data matches original plaintext
    EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0)
        << "Decrypted data should match original plaintext";

    std::cout << "AES XTS data_unit_len=4096 test passed" << std::endl;
}

TEST_F(AESTest, AesXtsDataUnitLen8192)
{
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES XTS 256-bit key";
    EXPECT_NE(key_handle, 0) << "Got null handle for AES XTS 256-bit key";

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    // Test data - 24576 bytes (three data units of 8192 bytes each)
    std::vector<uint8_t> plaintext(24576, 0x12);
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> decrypted(plaintext.size());

    azihsm_algo_aes_xts_params xts_params = {
        .sector_num = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
                       0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04},
        .data_unit_len = 8192};

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};
    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    // Perform encryption
    err = azihsm_crypt_encrypt(session_handle, &algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed for AES XTS with data_unit_len=8192";

    // Perform decryption
    azihsm_buffer decrypted_buffer = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt(session_handle, &algo, key_handle, &ct_buffer, &decrypted_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Decryption failed for AES XTS with data_unit_len=8192";

    // Verify decrypted data matches original plaintext
    EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0)
        << "Decrypted data should match original plaintext";

    std::cout << "AES XTS data_unit_len=8192 test passed" << std::endl;
}

TEST_F(AESTest, AesXtsDataUnitLenInvalid)
{
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES XTS 256-bit key";
    EXPECT_NE(key_handle, 0) << "Got null handle for AES XTS 256-bit key";

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    // Test data - 1024 bytes
    std::vector<uint8_t> plaintext(1024, 0x34);
    std::vector<uint8_t> ciphertext(plaintext.size());

    // Test with invalid data_unit_len (2048 - not a standard size)
    azihsm_algo_aes_xts_params xts_params = {
        .sector_num = {0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
                       0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05},
        .data_unit_len = 2048};

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};
    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    // Encryption should fail with invalid data_unit_len
    err = azihsm_crypt_encrypt(session_handle, &algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_AES_UNSUPPORTED_DATA_UNIT_LENGTH) << "Should fail with invalid data_unit_len";

    std::cout << "AES XTS invalid data_unit_len test passed" << std::endl;
}

TEST_F(AESTest, AesXtsDataUnitLenNotMultipleOfPlaintext)
{
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES XTS 256-bit key";
    EXPECT_NE(key_handle, 0) << "Got null handle for AES XTS 256-bit key";

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    // Test 1: Plaintext 4097 bytes with data_unit_len=4096 (not a multiple)
    {
        std::vector<uint8_t> plaintext(4097, 0xAB);
        std::vector<uint8_t> ciphertext(plaintext.size());

        azihsm_algo_aes_xts_params xts_params = {
            .sector_num = {0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
                           0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06},
            .data_unit_len = 4096};

        azihsm_algo algo = {
            .id = AZIHSM_ALGO_ID_AES_XTS,
            .params = &xts_params,
            .len = sizeof(xts_params)};

        azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};
        azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

        // Encryption should fail at DDI layer (not validation)
        err = azihsm_crypt_encrypt(session_handle, &algo, key_handle, &pt_buffer, &ct_buffer);
        EXPECT_EQ(err, AZIHSM_AES_ENCRYPT_FAILED) << "Should fail during encryption (not validation)";
    }

    // Test 2: Plaintext 513 bytes with data_unit_len=512 (not a multiple)
    {
        std::vector<uint8_t> plaintext(513, 0xCD);
        std::vector<uint8_t> ciphertext(plaintext.size());

        azihsm_algo_aes_xts_params xts_params = {
            .sector_num = {0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
                           0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07},
            .data_unit_len = 512};

        azihsm_algo algo = {
            .id = AZIHSM_ALGO_ID_AES_XTS,
            .params = &xts_params,
            .len = sizeof(xts_params)};

        azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};
        azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

        // Encryption should fail at DDI layer (not validation)
        err = azihsm_crypt_encrypt(session_handle, &algo, key_handle, &pt_buffer, &ct_buffer);
        EXPECT_EQ(err, AZIHSM_AES_ENCRYPT_FAILED) << "Should fail during encryption (not validation)";
    }

    // Test 3: Plaintext 8193 bytes with data_unit_len=8192 (not a multiple)
    {
        std::vector<uint8_t> plaintext(8193, 0xEF);
        std::vector<uint8_t> ciphertext(plaintext.size());

        azihsm_algo_aes_xts_params xts_params = {
            .sector_num = {0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
                           0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08},
            .data_unit_len = 8192};

        azihsm_algo algo = {
            .id = AZIHSM_ALGO_ID_AES_XTS,
            .params = &xts_params,
            .len = sizeof(xts_params)};

        azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};
        azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

        // Encryption should fail at DDI layer (not validation)
        err = azihsm_crypt_encrypt(session_handle, &algo, key_handle, &pt_buffer, &ct_buffer);
        EXPECT_EQ(err, AZIHSM_AES_ENCRYPT_FAILED) << "Should fail during encryption (not validation)";
    }

    std::cout << "AES XTS data_unit_len not multiple of plaintext test passed" << std::endl;
}

TEST_F(AESTest, AesXtsDataUnitLenNone)
{
    // Test that when data_unit_len = 0, it defaults to plaintext length
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 512;
    bool encrypt_prop = true;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_prop, .len = sizeof(encrypt_prop)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 3};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES XTS 256-bit key";
    EXPECT_NE(key_handle, 0) << "Got null handle for AES XTS 256-bit key";

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  { azihsm_key_delete(session_handle, key_handle); });

    // Test data - arbitrary size
    std::vector<uint8_t> plaintext(2048, 0xAA);
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> decrypted(plaintext.size());

    // Use data_unit_len = 0 (should default to plaintext length)
    azihsm_algo_aes_xts_params xts_params = {
        .sector_num = {0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
                       0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09},
        .data_unit_len = 0};

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_AES_XTS,
        .params = &xts_params,
        .len = sizeof(xts_params)};

    azihsm_buffer pt_buffer = {.buf = plaintext.data(), .len = static_cast<uint32_t>(plaintext.size())};
    azihsm_buffer ct_buffer = {.buf = ciphertext.data(), .len = static_cast<uint32_t>(ciphertext.size())};

    // Perform encryption
    err = azihsm_crypt_encrypt(session_handle, &algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed with data_unit_len=0";

    // Perform decryption
    azihsm_buffer decrypted_buffer = {.buf = decrypted.data(), .len = static_cast<uint32_t>(decrypted.size())};

    err = azihsm_crypt_decrypt(session_handle, &algo, key_handle, &ct_buffer, &decrypted_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Decryption failed with data_unit_len=0";

    // Verify decrypted data matches original plaintext
    EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0)
        << "Decrypted data should match original plaintext";

    std::cout << "AES XTS data_unit_len=0 (default) test passed" << std::endl;
}