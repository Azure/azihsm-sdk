// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"

class EncryptDecryptTest : public ::testing::Test
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

TEST_F(EncryptDecryptTest, EncryptArgumentValidation)
{
    // Generate a test AES key for validation tests
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

    azihsm_key_prop_list prop_list = {
        .props = props,
        .count = 2};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Set up valid test data
    uint8_t plaintext[] = "1234567890123456";
    uint8_t iv_data[16] = {0};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    azihsm_buffer pt_buffer = {.buf = plaintext, .len = 16};
    std::vector<uint8_t> ciphertext_data(16);
    azihsm_buffer ct_buffer = {.buf = ciphertext_data.data(), .len = 16};

    // Null session handle
    err = azihsm_crypt_encrypt(0, &encrypt_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Null algorithm pointer
    err = azihsm_crypt_encrypt(session_handle, nullptr, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Invalid key handle
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, 0xDEADBEEF, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Null plaintext buffer
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, nullptr, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Null ciphertext buffer
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, nullptr);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Zero-length plaintext
    azihsm_buffer zero_pt_buffer = {.buf = plaintext, .len = 0};
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &zero_pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Zero-length ciphertext buffer
    azihsm_buffer zero_ct_buffer = {.buf = ciphertext_data.data(), .len = 0};
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &zero_ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);

    // Null plaintext buffer data
    azihsm_buffer null_pt_buffer = {.buf = nullptr, .len = 16};
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &null_pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Null ciphertext buffer data
    azihsm_buffer null_ct_buffer = {.buf = nullptr, .len = 16};
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &null_ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Unsupported algorithm
    azihsm_algo invalid_algo = {
        .id = static_cast<azihsm_algo_id>(0xFFFFFFFF),
        .params = nullptr,
        .len = 0};
    err = azihsm_crypt_encrypt(session_handle, &invalid_algo, key_handle, &pt_buffer, &ct_buffer);
    EXPECT_EQ(err, AZIHSM_ALGORITHM_NOT_SUPPORTED);
}

TEST_F(EncryptDecryptTest, DecryptArgumentValidation)
{
    // Generate a test AES key for validation tests
    azihsm_handle key_handle = 0;
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_AES_KEY_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t bit_len = 128;
    bool decrypt_prop = true;
    azihsm_key_prop props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_prop, .len = sizeof(decrypt_prop)}};

    azihsm_key_prop_list prop_list = {
        .props = props,
        .count = 2};

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    // Set up valid test data
    uint8_t ciphertext[] = "encrypted_data16"; // 16 bytes of dummy ciphertext
    uint8_t iv_data[16] = {0};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
    azihsm_algo decrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    azihsm_buffer ct_buffer = {.buf = ciphertext, .len = 16};
    std::vector<uint8_t> plaintext_data(16);
    azihsm_buffer pt_buffer = {.buf = plaintext_data.data(), .len = 16};

    // Null session handle
    err = azihsm_crypt_decrypt(0, &decrypt_algo, key_handle, &ct_buffer, &pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Null algorithm pointer
    err = azihsm_crypt_decrypt(session_handle, nullptr, key_handle, &ct_buffer, &pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Invalid key handle
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, 0xDEADBEEF, &ct_buffer, &pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Null ciphertext buffer
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, nullptr, &pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Null plaintext buffer
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, nullptr);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Zero-length ciphertext
    azihsm_buffer zero_ct_buffer = {.buf = ciphertext, .len = 0};
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &zero_ct_buffer, &pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Zero-length plaintext buffer
    azihsm_buffer zero_pt_buffer = {.buf = plaintext_data.data(), .len = 0};
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &zero_pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);

    // Null ciphertext buffer data
    azihsm_buffer null_ct_buffer = {.buf = nullptr, .len = 16};
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &null_ct_buffer, &pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Null plaintext buffer data
    azihsm_buffer null_pt_buffer = {.buf = nullptr, .len = 16};
    err = azihsm_crypt_decrypt(session_handle, &decrypt_algo, key_handle, &ct_buffer, &null_pt_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Unsupported algorithm
    azihsm_algo invalid_algo = {
        .id = static_cast<azihsm_algo_id>(0xFFFFFFFF),
        .params = nullptr,
        .len = 0};
    err = azihsm_crypt_decrypt(session_handle, &invalid_algo, key_handle, &ct_buffer, &pt_buffer);
    EXPECT_EQ(err, AZIHSM_ALGORITHM_NOT_SUPPORTED);
}

TEST_F(EncryptDecryptTest, BufferSizeValidation)
{
    // Generate a test AES key
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

    auto err = azihsm_key_gen(session_handle, &key_gen_algo, &prop_list, &key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (key_handle != 0) {
            azihsm_key_delete(session_handle, key_handle);
        } });

    uint8_t plaintext[] = "1234567890123456"; // 16 bytes
    uint8_t iv_data[16] = {0};
    azihsm_algo_aes_cbc_params cbc_params = {0};
    memcpy(cbc_params.iv, iv_data, sizeof(iv_data));
    azihsm_algo encrypt_algo = {
        .id = AZIHSM_ALGO_ID_AES_CBC,
        .params = &cbc_params,
        .len = sizeof(cbc_params)};

    azihsm_buffer pt_buffer = {.buf = plaintext, .len = 16};

    // Test insufficient ciphertext buffer
    std::vector<uint8_t> small_ciphertext(8); // Too small
    azihsm_buffer small_ct_buffer = {.buf = small_ciphertext.data(), .len = 8};
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &small_ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);

    // Test valid size
    std::vector<uint8_t> valid_ciphertext(16);
    azihsm_buffer valid_ct_buffer = {.buf = valid_ciphertext.data(), .len = 16};
    err = azihsm_crypt_encrypt(session_handle, &encrypt_algo, key_handle, &pt_buffer, &valid_ct_buffer);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
}