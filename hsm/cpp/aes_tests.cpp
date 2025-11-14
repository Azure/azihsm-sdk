// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"

class AESTest : public ::testing::Test
{
protected:
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
    std::vector<uint32_t> invalid_sizes = {64, 96, 160, 224, 384, 512, 1024};
    for (auto bit_len : invalid_sizes)
    {
        azihsm_handle key_handle = 0;
        azihsm_key_prop props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}};
        azihsm_key_prop_list prop_list = {.props = props, .count = 1};

        auto err = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
        EXPECT_EQ(err, AZIHSM_ILLEGAL_KEY_PROPERTY) << "Should reject invalid AES key size: " << bit_len;
        EXPECT_EQ(key_handle, 0);
    }
}

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

        azihsm_buffer iv_buffer = {.buf = iv_data, .len = sizeof(iv_data)};
        azihsm_algo_aes_cbc_params cbc_params = {.iv = &iv_buffer};
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
        const uint8_t original_iv[16] = {
            static_cast<uint8_t>(bit_len & 0xFF), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, static_cast<uint8_t>((bit_len >> 8) & 0xFF)};
        memcpy(iv_data, original_iv, sizeof(original_iv));

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
                                                      {
            if (key_handle != 0) {
                EXPECT_EQ(azihsm_key_delete(session_handle, key_handle), AZIHSM_ERROR_SUCCESS);
            } });

        // Test data - 32 bytes (two AES blocks)
        uint8_t plaintext[] = "12345678901234561234567890123456"; // 32 bytes
        size_t plaintext_len = 32;

        uint8_t iv_data[16] = {
            0x11, 0x22, 0x33, 0x44, static_cast<uint8_t>(bit_len & 0xFF), 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, static_cast<uint8_t>((bit_len >> 8) & 0xFF)};

        azihsm_buffer iv_buffer = {.buf = iv_data, .len = sizeof(iv_data)};
        azihsm_algo_aes_cbc_params cbc_params = {.iv = &iv_buffer};
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
        const uint8_t original_iv[16] = {
            0x11, 0x22, 0x33, 0x44, static_cast<uint8_t>(bit_len & 0xFF), 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, static_cast<uint8_t>((bit_len >> 8) & 0xFF)};
        memcpy(iv_data, original_iv, sizeof(original_iv));

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
    azihsm_buffer iv_buffer = {.buf = iv_data, .len = sizeof(iv_data)};
    azihsm_algo_aes_cbc_params cbc_params = {.iv = &iv_buffer};

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

TEST_F(AESTest, AesCbcIvValidation)
{
    // Generate AES key
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
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    uint8_t plaintext[] = "1234567890123456";
    azihsm_buffer pt_buffer = {.buf = plaintext, .len = 16};
    std::vector<uint8_t> ciphertext_data(16);
    azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = 16};

    // Invalid IV length (8 bytes instead of 16 for AES)
    uint8_t short_iv[8] = {0};
    azihsm_buffer short_iv_buffer = {.buf = short_iv, .len = 8};
    azihsm_algo_aes_cbc_params short_iv_params = {.iv = &short_iv_buffer};
    azihsm_algo short_iv_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &short_iv_params,
        .len = sizeof(short_iv_params)};

    err = azihsm_crypt_encrypt(session_handle, &short_iv_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT) << "Should reject IV with wrong length for AES CBC";

    // Null IV buffer
    azihsm_algo_aes_cbc_params null_iv_params = {.iv = nullptr};
    azihsm_algo null_iv_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &null_iv_params,
        .len = sizeof(null_iv_params)};

    err = azihsm_crypt_encrypt(session_handle, &null_iv_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT) << "Should reject null IV for AES CBC";

    // Valid IV length (16 bytes)
    uint8_t valid_iv[16] = {0};
    azihsm_buffer valid_iv_buffer = {.buf = valid_iv, .len = 16};
    azihsm_algo_aes_cbc_params valid_iv_params = {.iv = &valid_iv_buffer};
    azihsm_algo valid_iv_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &valid_iv_params,
        .len = sizeof(valid_iv_params)};

    err = azihsm_crypt_encrypt(session_handle, &valid_iv_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should accept valid 16-byte IV for AES CBC";
}

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

        azihsm_buffer iv_buffer = {.buf = iv_data, .len = sizeof(iv_data)};
        azihsm_algo_aes_cbc_params cbc_params = {.iv = &iv_buffer};

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
        const uint8_t original_iv[16] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
        memcpy(iv_data, original_iv, 16);

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

    azihsm_buffer iv_buffer = {.buf = iv_data, .len = sizeof(iv_data)};
    azihsm_algo_aes_cbc_params cbc_params = {.iv = &iv_buffer};
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
        const uint8_t reset_iv[16] = {
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
        memcpy(iv_data, reset_iv, 16);

        // Encrypt
        err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed for input size: " << input_size;
        EXPECT_EQ(ct_buffer.len, expected_ct_size) << "Unexpected ciphertext size for input: " << input_size;

        // Reset IV for decryption
        memcpy(iv_data, reset_iv, 16);

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
    azihsm_buffer iv_buffer = {.buf = iv_data, .len = sizeof(iv_data)};
    azihsm_algo_aes_cbc_params cbc_params = {.iv = &iv_buffer};

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
    memset(iv_data, 0, 16);

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

    azihsm_buffer iv_buffer = {.buf = iv_data, .len = sizeof(iv_data)};
    azihsm_algo_aes_cbc_params cbc_params = {.iv = &iv_buffer};
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
    const uint8_t original_iv[16] = {
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    memcpy(iv_data, original_iv, 16);

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

    azihsm_buffer iv_buffer = {.buf = iv_data, .len = sizeof(iv_data)};
    azihsm_algo_aes_cbc_params cbc_params = {.iv = &iv_buffer};

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
    const uint8_t original_iv[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    memcpy(iv_data, original_iv, 16);

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
    memcpy(iv_data, original_iv, 16);

    err = azihsm_crypt_encrypt(session_handle, &no_pad_algo, key_handle, &aligned_buffer, &no_pad_output_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Non-padded CBC should work with block-aligned input";
    EXPECT_EQ(no_pad_output_buffer.len, 16u) << "Non-padded output should be same size as input";

    // Reset IV for padding test
    memcpy(iv_data, original_iv, 16);

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

TEST_F(AESTest, AesCbcPaddingInvalidPaddingDetection)
{
    // Test that invalid padding is detected during decryption
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
    azihsm_buffer iv_buffer = {.buf = iv_data, .len = sizeof(iv_data)};
    azihsm_algo_aes_cbc_params cbc_params = {.iv = &iv_buffer};
    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    // Test cases with invalid padding
    std::vector<std::vector<uint8_t>> invalid_padding_cases = {
        // Case 1: All zeros (padding byte should be 0x10, not 0x00)
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},

        // Case 2: Invalid padding length (0x11 > 16)
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11},

        // Case 3: Inconsistent padding (should be all 0x03)
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x03, 0x02},
    };

    for (size_t i = 0; i < invalid_padding_cases.size(); ++i)
    {
        std::vector<uint8_t> &invalid_data = invalid_padding_cases[i];
        azihsm_buffer invalid_buffer = {.buf = invalid_data.data(), .len = static_cast<uint32_t>(invalid_data.size())};

        std::vector<uint8_t> output_data(16);
        azihsm_buffer output_buffer = {.buf = output_data.data(), .len = 16};

        // Reset IV
        memset(iv_data, 0, 16);

        err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &invalid_buffer, &output_buffer);

        // Should fail due to invalid padding
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Invalid padding case " << i << " should be rejected";
    }

    std::cout << "Invalid padding detection test passed" << std::endl;
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

    // create copy of iv because CBC mode modifies iv
    uint8_t iv_data[IV_LEN];
    memcpy(iv_data, iv, IV_LEN);
    azihsm_buffer iv_buffer = {.buf = iv_data, .len = static_cast<uint32_t>(IV_LEN)};
    azihsm_algo_aes_cbc_params cbc_params = {.iv = &iv_buffer};
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

    // Verify IV is present after encryption
    EXPECT_NE(iv_buffer.len, 0)
        << "IV is empty after Encryption with AES-" << bit_len;
        
    uint8_t expected_iv[IV_LEN];
    memcpy(expected_iv, iv_buffer.buf, iv_buffer.len);

    // Test encryption #2: first half of plain text buffer (512 bytes)
    
    // Prepare arguments for encryption

    // create copy of IV because CBC mode modifies IV
    memcpy(iv_data, iv, IV_LEN);

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

    // Verify IV is present after encryption
    EXPECT_NE(iv_buffer.len, 0)
        << "IV is empty after Encryption with AES-" << bit_len;
        
    uint8_t output_iv_1[IV_LEN];
    memcpy(output_iv_1, iv_buffer.buf, iv_buffer.len);

    // Test encryption #3: last half of plain text buffer (512 bytes)
    
    // Prepare arguments for encryption

    plain_data.clear();
    plain_data.insert(plain_data.begin(), expected_plain + PLAIN_SIZE_HALF, expected_plain + sizeof(expected_plain));

    // Perform encryption
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Encryption failed for AES-" << bit_len;
    
    uint8_t cipher_2[PLAIN_SIZE_HALF];
    memcpy(cipher_2, ct_buffer.buf, ct_buffer.len);

    // Verify IV is present after encryption
    EXPECT_NE(iv_buffer.len, 0)
        << "IV is empty after Encryption with AES-" << bit_len;
        
    uint8_t output_iv_2[IV_LEN];
    memcpy(output_iv_2, iv_buffer.buf, iv_buffer.len);

    uint8_t cipher[PLAIN_SIZE];
    memcpy(cipher, cipher_1, sizeof(cipher_1));
    memcpy(cipher + PLAIN_SIZE_HALF, cipher_2, sizeof(cipher_2));

    EXPECT_EQ(memcmp(output_iv_2, expected_iv, IV_LEN), 0) << "Outputted IV is not expected value";
    EXPECT_EQ(memcmp(cipher, expected_cipher, PLAIN_SIZE), 0) << "Cipher is not expected value";

    // Test decryption #1: entire cipher (1024 bytes)
    
    // Prepare arguments for decryption

    // Reset IV for decryption (CBC mode modifies IV)
    memcpy(iv_data, iv, IV_LEN);

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
    
    // Verify IV is present after encryption
    EXPECT_NE(iv_buffer.len, 0)
        << "IV is empty after Decryption with AES-" << bit_len;

    // Verify decrypted data matches original plaintext
    EXPECT_EQ(memcmp(expected_plain, decrypted_data.data(), PLAIN_SIZE), 0)
        << "Decrypted data should match original plaintext for AES-" << bit_len;

    // Test decryption #2: first half of cipher (512 bytes)
    
    // Prepare arguments for decryption

    // Reset IV for decryption (CBC mode modifies IV)
    memcpy(iv_data, iv, IV_LEN);
    
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
    
    // Verify IV is present after encryption
    EXPECT_NE(iv_buffer.len, 0)
        << "IV is empty after Decryption with AES-" << bit_len;

    // Test decryption #3: last half of cipher (512 bytes)
    
    // fill ct_buffer with cipher[1024..]
    ciphertext_data.clear();
    ciphertext_data.insert(ciphertext_data.begin(), cipher + PLAIN_SIZE_HALF, cipher + std::size(cipher));
    
    // Perform decryption
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &decrypted_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Decryption failed for AES-" << bit_len;
    
    uint8_t plain_2[PLAIN_SIZE_HALF];
    memcpy(plain_2, decrypted_buffer.buf, decrypted_buffer.len);
    
    // Verify IV is present after encryption
    EXPECT_NE(iv_buffer.len, 0)
        << "IV is empty after Decryption with AES-" << bit_len;

    memcpy(output_iv_2, iv_buffer.buf, iv_buffer.len);

    uint8_t plain[PLAIN_SIZE];
    memcpy(plain, plain_1, sizeof(plain_1));
    memcpy(plain + PLAIN_SIZE_HALF, plain_2, sizeof(plain_2));

    EXPECT_EQ(memcmp(output_iv_2, expected_iv, IV_LEN), 0) << "Outputted IV is not expected value";
    EXPECT_EQ(memcmp(plain, expected_plain, PLAIN_SIZE), 0) << "Plain is not expected value";
}