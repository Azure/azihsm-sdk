// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <gtest/gtest.h>

#include "algo/aes/helpers.hpp"
#include "algo/ecc/helpers.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "utils/auto_key.hpp"

class azihsm_handle_mgmt : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(azihsm_handle_mgmt, free_sha_context_on_error)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // Init SHA context
        azihsm_handle sha_ctx = 0;
        azihsm_algo algo = { AZIHSM_ALGO_ID_SHA256, nullptr, 0 };
        auto err = azihsm_crypt_digest_init(session, &algo, &sha_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(sha_ctx, 0);

        // Simulate error scenario - free the context without calling final
        err = azihsm_free_handle(sha_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Verify handle is now invalid
        uint8_t data[] = { 0x01, 0x02, 0x03 };
        azihsm_buffer buf = { data, sizeof(data) };
        err = azihsm_crypt_digest_update(sha_ctx, &buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_handle_mgmt, free_sign_context_on_error)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // Generate ECC key pair
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Init sign context
        azihsm_handle sign_ctx = 0;
        azihsm_algo sign_algo = { AZIHSM_ALGO_ID_ECDSA_SHA256, nullptr, 0 };
        err = azihsm_crypt_sign_init(&sign_algo, priv_key.get(), &sign_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(sign_ctx, 0);

        // Free the context without calling final
        err = azihsm_free_handle(sign_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Verify handle is now invalid
        uint8_t data[] = { 0x01, 0x02, 0x03 };
        azihsm_buffer buf = { data, sizeof(data) };
        err = azihsm_crypt_sign_update(sign_ctx, &buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_handle_mgmt, free_verify_context_on_error)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // Generate ECC key pair
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Init verify context
        azihsm_handle verify_ctx = 0;
        azihsm_algo verify_algo = { AZIHSM_ALGO_ID_ECDSA_SHA256, nullptr, 0 };
        err = azihsm_crypt_verify_init(&verify_algo, pub_key.get(), &verify_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(verify_ctx, 0);

        // Free the context without calling final
        err = azihsm_free_handle(verify_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Verify handle is now invalid
        uint8_t data[] = { 0x01, 0x02, 0x03 };
        azihsm_buffer buf = { data, sizeof(data) };
        err = azihsm_crypt_verify_update(verify_ctx, &buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_handle_mgmt, free_encrypt_context_on_error)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // Generate AES key
        auto key = generate_aes_key(session, 128);

        // Init encrypt context
        azihsm_handle encrypt_ctx = 0;
        uint8_t iv[16] = { 0 };
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));
        azihsm_algo encrypt_algo = { AZIHSM_ALGO_ID_AES_CBC, &cbc_params, sizeof(cbc_params) };
        auto err = azihsm_crypt_encrypt_init(&encrypt_algo, key.get(), &encrypt_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(encrypt_ctx, 0);

        // Free the context without calling final
        err = azihsm_free_handle(encrypt_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Verify handle is now invalid
        uint8_t plaintext[16] = { 0x01, 0x02, 0x03 };
        uint8_t ciphertext[16] = { 0 };
        azihsm_buffer in_buf = { plaintext, sizeof(plaintext) };
        azihsm_buffer out_buf = { ciphertext, sizeof(ciphertext) };
        err = azihsm_crypt_encrypt_update(encrypt_ctx, &in_buf, &out_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_handle_mgmt, free_decrypt_context_on_error)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // Generate AES key
        auto key = generate_aes_key(session, 128);

        // Init decrypt context
        azihsm_handle decrypt_ctx = 0;
        uint8_t iv[16] = { 0 };
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));
        azihsm_algo decrypt_algo = { AZIHSM_ALGO_ID_AES_CBC, &cbc_params, sizeof(cbc_params) };
        auto err = azihsm_crypt_decrypt_init(&decrypt_algo, key.get(), &decrypt_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(decrypt_ctx, 0);

        // Free the context without calling final
        err = azihsm_free_handle(decrypt_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Verify handle is now invalid
        uint8_t ciphertext[16] = { 0x01, 0x02, 0x03 };
        uint8_t plaintext[16] = { 0 };
        azihsm_buffer in_buf = { ciphertext, sizeof(ciphertext) };
        azihsm_buffer out_buf = { plaintext, sizeof(plaintext) };
        err = azihsm_crypt_decrypt_update(decrypt_ctx, &in_buf, &out_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_handle_mgmt, free_handle_invalid)
{
    azihsm_handle bad_handle = 0xDEADBEEF;
    auto err = azihsm_free_handle(bad_handle);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST_F(azihsm_handle_mgmt, free_handle_double_free)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_handle sha_ctx = 0;
        azihsm_algo algo = { AZIHSM_ALGO_ID_SHA256, nullptr, 0 };
        auto err = azihsm_crypt_digest_init(session, &algo, &sha_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // First free should succeed
        err = azihsm_free_handle(sha_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Second free should fail
        err = azihsm_free_handle(sha_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_handle_mgmt, free_handle_multiple_contexts)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // Create multiple contexts
        azihsm_algo algo256 = { AZIHSM_ALGO_ID_SHA256, nullptr, 0 };
        azihsm_handle sha256_ctx = 0;
        auto err = azihsm_crypt_digest_init(session, &algo256, &sha256_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_algo algo512 = { AZIHSM_ALGO_ID_SHA512, nullptr, 0 };
        azihsm_handle sha512_ctx = 0;
        err = azihsm_crypt_digest_init(session, &algo512, &sha512_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Free both contexts
        err = azihsm_free_handle(sha256_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        err = azihsm_free_handle(sha512_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    });
}