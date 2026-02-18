// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <gtest/gtest.h>

#include "algo/aes/helpers.hpp"
#include "algo/ecc/helpers.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "utils/auto_ctx.hpp"
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
        auto_ctx sha_ctx;
        azihsm_algo algo = { AZIHSM_ALGO_ID_SHA256, nullptr, 0 };
        auto err = azihsm_crypt_digest_init(session, &algo, sha_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(sha_ctx.get(), 0);

        // Simulate error scenario - free the context without calling final
        azihsm_handle raw_sha_ctx = sha_ctx.release();
        err = azihsm_free_ctx_handle(raw_sha_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Verify handle is now invalid
        uint8_t data[] = { 0x01, 0x02, 0x03 };
        azihsm_buffer buf = { data, sizeof(data) };
        err = azihsm_crypt_digest_update(raw_sha_ctx, &buf);
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
        auto_ctx sign_ctx;
        azihsm_algo sign_algo = { AZIHSM_ALGO_ID_ECDSA_SHA256, nullptr, 0 };
        err = azihsm_crypt_sign_init(&sign_algo, priv_key.get(), sign_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(sign_ctx.get(), 0);

        // Free the context without calling final
        azihsm_handle raw_sign_ctx = sign_ctx.release();
        err = azihsm_free_ctx_handle(raw_sign_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Verify handle is now invalid
        uint8_t data[] = { 0x01, 0x02, 0x03 };
        azihsm_buffer buf = { data, sizeof(data) };
        err = azihsm_crypt_sign_update(raw_sign_ctx, &buf);
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
        auto_ctx verify_ctx;
        azihsm_algo verify_algo = { AZIHSM_ALGO_ID_ECDSA_SHA256, nullptr, 0 };
        err = azihsm_crypt_verify_init(&verify_algo, pub_key.get(), verify_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(verify_ctx.get(), 0);

        // Free the context without calling final
        azihsm_handle raw_verify_ctx = verify_ctx.release();
        err = azihsm_free_ctx_handle(raw_verify_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Verify handle is now invalid
        uint8_t data[] = { 0x01, 0x02, 0x03 };
        azihsm_buffer buf = { data, sizeof(data) };
        err = azihsm_crypt_verify_update(raw_verify_ctx, &buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_handle_mgmt, free_encrypt_context_on_error)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // Generate AES key
        auto key = generate_aes_key(session, 128);

        // Init encrypt context
        auto_ctx encrypt_ctx;
        uint8_t iv[16] = { 0 };
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));
        azihsm_algo encrypt_algo = { AZIHSM_ALGO_ID_AES_CBC, &cbc_params, sizeof(cbc_params) };
        auto err = azihsm_crypt_encrypt_init(&encrypt_algo, key.get(), encrypt_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(encrypt_ctx.get(), 0);

        // Free the context without calling final
        azihsm_handle raw_encrypt_ctx = encrypt_ctx.release();
        err = azihsm_free_ctx_handle(raw_encrypt_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Verify handle is now invalid
        uint8_t plaintext[16] = { 0x01, 0x02, 0x03 };
        uint8_t ciphertext[16] = { 0 };
        azihsm_buffer in_buf = { plaintext, sizeof(plaintext) };
        azihsm_buffer out_buf = { ciphertext, sizeof(ciphertext) };
        err = azihsm_crypt_encrypt_update(raw_encrypt_ctx, &in_buf, &out_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_handle_mgmt, free_decrypt_context_on_error)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // Generate AES key
        auto key = generate_aes_key(session, 128);

        // Init decrypt context
        auto_ctx decrypt_ctx;
        uint8_t iv[16] = { 0 };
        azihsm_algo_aes_cbc_params cbc_params{};
        std::memcpy(cbc_params.iv, iv, sizeof(iv));
        azihsm_algo decrypt_algo = { AZIHSM_ALGO_ID_AES_CBC, &cbc_params, sizeof(cbc_params) };
        auto err = azihsm_crypt_decrypt_init(&decrypt_algo, key.get(), decrypt_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(decrypt_ctx.get(), 0);

        // Free the context without calling final
        azihsm_handle raw_decrypt_ctx = decrypt_ctx.release();
        err = azihsm_free_ctx_handle(raw_decrypt_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Verify handle is now invalid
        uint8_t ciphertext[16] = { 0x01, 0x02, 0x03 };
        uint8_t plaintext[16] = { 0 };
        azihsm_buffer in_buf = { ciphertext, sizeof(ciphertext) };
        azihsm_buffer out_buf = { plaintext, sizeof(plaintext) };
        err = azihsm_crypt_decrypt_update(raw_decrypt_ctx, &in_buf, &out_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_handle_mgmt, free_handle_invalid)
{
    azihsm_handle bad_handle = 0xDEADBEEF;
    auto err = azihsm_free_ctx_handle(bad_handle);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST_F(azihsm_handle_mgmt, free_handle_double_free)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_ctx sha_ctx;
        azihsm_algo algo = { AZIHSM_ALGO_ID_SHA256, nullptr, 0 };
        auto err = azihsm_crypt_digest_init(session, &algo, sha_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // First free should succeed
        azihsm_handle raw_sha_ctx = sha_ctx.release();
        err = azihsm_free_ctx_handle(raw_sha_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Second free should fail
        err = azihsm_free_ctx_handle(raw_sha_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    });
}

TEST_F(azihsm_handle_mgmt, free_handle_multiple_contexts)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // Create multiple contexts
        azihsm_algo algo256 = { AZIHSM_ALGO_ID_SHA256, nullptr, 0 };
        auto_ctx sha256_ctx;
        auto err = azihsm_crypt_digest_init(session, &algo256, sha256_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_algo algo512 = { AZIHSM_ALGO_ID_SHA512, nullptr, 0 };
        auto_ctx sha512_ctx;
        err = azihsm_crypt_digest_init(session, &algo512, sha512_ctx.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Free both contexts
        azihsm_handle raw_sha256_ctx = sha256_ctx.release();
        err = azihsm_free_ctx_handle(raw_sha256_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_handle raw_sha512_ctx = sha512_ctx.release();
        err = azihsm_free_ctx_handle(raw_sha512_ctx);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    });
}