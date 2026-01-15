// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils.hpp"

class azihsm_hmac_sign_verify : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(azihsm_hmac_sign_verify, sign_verify_hmac_sha256)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate EC key pairs and derive HMAC key
        EcdhKeyPairs key_pairs;
        AutoKey hmac_key;

        auto err = generate_ecdh_keys_and_derive_hmac(session.get(), AZIHSM_KEY_KIND_HMAC_SHA256, key_pairs,
                                                      hmac_key.handle, AZIHSM_ECC_CURVE_P256);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Prepare test data
        const char *message = "Hello, HMAC authentication with HSM!";
        std::vector<uint8_t> data(message, message + strlen(message));

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_HMAC_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Sign
        std::vector<uint8_t> signature(32);
        azihsm_buffer data_buf{data.data(), static_cast<uint32_t>(data.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        auto sign_err = azihsm_crypt_sign(&algo, hmac_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(sig_buf.len, 32);

        // Verify
        auto verify_err = azihsm_crypt_verify(&algo, hmac_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_hmac_sign_verify, sign_verify_hmac_sha384)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate EC key pairs and derive HMAC key
        EcdhKeyPairs key_pairs;
        AutoKey hmac_key;

        auto err = generate_ecdh_keys_and_derive_hmac(session.get(), AZIHSM_KEY_KIND_HMAC_SHA384, key_pairs,
                                                      hmac_key.handle, AZIHSM_ECC_CURVE_P384);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Prepare test data
        const char *message = "Hello, HMAC-SHA384 authentication with HSM!";
        std::vector<uint8_t> data(message, message + strlen(message));

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_HMAC_SHA384;
        algo.params = nullptr;
        algo.len = 0;

        // Sign
        std::vector<uint8_t> signature(48); // SHA384 produces 48-byte signature
        azihsm_buffer data_buf{data.data(), static_cast<uint32_t>(data.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        auto sign_err = azihsm_crypt_sign(&algo, hmac_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(sig_buf.len, 48);

        // Verify
        auto verify_err = azihsm_crypt_verify(&algo, hmac_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_hmac_sign_verify, sign_verify_hmac_sha512)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate EC key pairs and derive HMAC key
        EcdhKeyPairs key_pairs;
        AutoKey hmac_key;

        auto err = generate_ecdh_keys_and_derive_hmac(session.get(), AZIHSM_KEY_KIND_HMAC_SHA512, key_pairs,
                                                      hmac_key.handle, AZIHSM_ECC_CURVE_P521);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Prepare test data
        const char *message = "Hello, HMAC-SHA512 authentication with HSM!";
        std::vector<uint8_t> data(message, message + strlen(message));

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_HMAC_SHA512;
        algo.params = nullptr;
        algo.len = 0;

        // Sign
        std::vector<uint8_t> signature(66);
        azihsm_buffer data_buf{data.data(), static_cast<uint32_t>(data.size())};
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};

        auto sign_err = azihsm_crypt_sign(&algo, hmac_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(sig_buf.len, 64);

        // Verify
        auto verify_err = azihsm_crypt_verify(&algo, hmac_key.get(), &data_buf, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_hmac_sign_verify, sign_verify_hmac_sha256_streaming)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate EC key pairs and derive HMAC key
        EcdhKeyPairs key_pairs;
        AutoKey hmac_key;

        auto err = generate_ecdh_keys_and_derive_hmac(session.get(), AZIHSM_KEY_KIND_HMAC_SHA256, key_pairs,
                                                      hmac_key.handle, AZIHSM_ECC_CURVE_P256);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Prepare test data in chunks
        const char *chunk1 = "Hello, ";
        const char *chunk2 = "HMAC streaming ";
        const char *chunk3 = "authentication!";

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_HMAC_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize streaming sign operation
        azihsm_handle sign_op_handle = 0;
        auto init_err = azihsm_crypt_sign_init(&algo, hmac_key.get(), &sign_op_handle);
        ASSERT_EQ(init_err, AZIHSM_ERROR_SUCCESS);

        // Update with chunks
        azihsm_buffer chunk1_buf{(uint8_t *)chunk1, static_cast<uint32_t>(strlen(chunk1))};
        auto update1_err = azihsm_crypt_sign_update(sign_op_handle, &chunk1_buf);
        ASSERT_EQ(update1_err, AZIHSM_ERROR_SUCCESS);

        azihsm_buffer chunk2_buf{(uint8_t *)chunk2, static_cast<uint32_t>(strlen(chunk2))};
        auto update2_err = azihsm_crypt_sign_update(sign_op_handle, &chunk2_buf);
        ASSERT_EQ(update2_err, AZIHSM_ERROR_SUCCESS);

        azihsm_buffer chunk3_buf{(uint8_t *)chunk3, static_cast<uint32_t>(strlen(chunk3))};
        auto update3_err = azihsm_crypt_sign_update(sign_op_handle, &chunk3_buf);
        ASSERT_EQ(update3_err, AZIHSM_ERROR_SUCCESS);

        // Finalize to get signature
        std::vector<uint8_t> signature(32);
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};
        auto final_err = azihsm_crypt_sign_final(sign_op_handle, &sig_buf);
        ASSERT_EQ(final_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(sig_buf.len, 32);

        // Verify using streaming
        azihsm_handle verify_op_handle = 0;
        auto verify_init_err = azihsm_crypt_verify_init(&algo, hmac_key.get(), &verify_op_handle);
        ASSERT_EQ(verify_init_err, AZIHSM_ERROR_SUCCESS);

        auto verify_update1_err = azihsm_crypt_verify_update(verify_op_handle, &chunk1_buf);
        ASSERT_EQ(verify_update1_err, AZIHSM_ERROR_SUCCESS);

        auto verify_update2_err = azihsm_crypt_verify_update(verify_op_handle, &chunk2_buf);
        ASSERT_EQ(verify_update2_err, AZIHSM_ERROR_SUCCESS);

        auto verify_update3_err = azihsm_crypt_verify_update(verify_op_handle, &chunk3_buf);
        ASSERT_EQ(verify_update3_err, AZIHSM_ERROR_SUCCESS);

        auto verify_final_err = azihsm_crypt_verify_final(verify_op_handle, &sig_buf);
        ASSERT_EQ(verify_final_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_hmac_sign_verify, sign_verify_hmac_sha384_streaming)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate EC key pairs and derive HMAC key
        EcdhKeyPairs key_pairs;
        AutoKey hmac_key;

        auto err = generate_ecdh_keys_and_derive_hmac(session.get(), AZIHSM_KEY_KIND_HMAC_SHA384, key_pairs,
                                                      hmac_key.handle, AZIHSM_ECC_CURVE_P384);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Prepare test data in chunks
        const char *chunk1 = "Hello, ";
        const char *chunk2 = "HMAC-SHA384 streaming ";
        const char *chunk3 = "authentication!";

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_HMAC_SHA384;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize streaming sign operation
        azihsm_handle sign_op_handle = 0;
        auto init_err = azihsm_crypt_sign_init(&algo, hmac_key.get(), &sign_op_handle);
        ASSERT_EQ(init_err, AZIHSM_ERROR_SUCCESS);

        // Update with chunks
        azihsm_buffer chunk1_buf{(uint8_t *)chunk1, static_cast<uint32_t>(strlen(chunk1))};
        auto update1_err = azihsm_crypt_sign_update(sign_op_handle, &chunk1_buf);
        ASSERT_EQ(update1_err, AZIHSM_ERROR_SUCCESS);

        azihsm_buffer chunk2_buf{(uint8_t *)chunk2, static_cast<uint32_t>(strlen(chunk2))};
        auto update2_err = azihsm_crypt_sign_update(sign_op_handle, &chunk2_buf);
        ASSERT_EQ(update2_err, AZIHSM_ERROR_SUCCESS);

        azihsm_buffer chunk3_buf{(uint8_t *)chunk3, static_cast<uint32_t>(strlen(chunk3))};
        auto update3_err = azihsm_crypt_sign_update(sign_op_handle, &chunk3_buf);
        ASSERT_EQ(update3_err, AZIHSM_ERROR_SUCCESS);

        // Finalize to get signature
        std::vector<uint8_t> signature(48); // SHA384 produces 48-byte signature
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};
        auto final_err = azihsm_crypt_sign_final(sign_op_handle, &sig_buf);
        ASSERT_EQ(final_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(sig_buf.len, 48);

        // Verify using streaming
        azihsm_handle verify_op_handle = 0;
        auto verify_init_err = azihsm_crypt_verify_init(&algo, hmac_key.get(), &verify_op_handle);
        ASSERT_EQ(verify_init_err, AZIHSM_ERROR_SUCCESS);

        auto verify_update1_err = azihsm_crypt_verify_update(verify_op_handle, &chunk1_buf);
        ASSERT_EQ(verify_update1_err, AZIHSM_ERROR_SUCCESS);

        auto verify_update2_err = azihsm_crypt_verify_update(verify_op_handle, &chunk2_buf);
        ASSERT_EQ(verify_update2_err, AZIHSM_ERROR_SUCCESS);

        auto verify_update3_err = azihsm_crypt_verify_update(verify_op_handle, &chunk3_buf);
        ASSERT_EQ(verify_update3_err, AZIHSM_ERROR_SUCCESS);

        auto verify_final_err = azihsm_crypt_verify_final(verify_op_handle, &sig_buf);
        ASSERT_EQ(verify_final_err, AZIHSM_ERROR_SUCCESS);
    });
}

TEST_F(azihsm_hmac_sign_verify, sign_verify_hmac_sha512_streaming)
{
    part_list_.for_each_part([](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());

        // Generate EC key pairs and derive HMAC key
        EcdhKeyPairs key_pairs;
        AutoKey hmac_key;

        auto err = generate_ecdh_keys_and_derive_hmac(session.get(), AZIHSM_KEY_KIND_HMAC_SHA512, key_pairs,
                                                      hmac_key.handle, AZIHSM_ECC_CURVE_P521);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Prepare test data in chunks
        const char *chunk1 = "Hello, ";
        const char *chunk2 = "HMAC-SHA512 streaming ";
        const char *chunk3 = "authentication!";

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_HMAC_SHA512;
        algo.params = nullptr;
        algo.len = 0;

        // Initialize streaming sign operation
        azihsm_handle sign_op_handle = 0;
        auto init_err = azihsm_crypt_sign_init(&algo, hmac_key.get(), &sign_op_handle);
        ASSERT_EQ(init_err, AZIHSM_ERROR_SUCCESS);

        // Update with chunks
        azihsm_buffer chunk1_buf{(uint8_t *)chunk1, static_cast<uint32_t>(strlen(chunk1))};
        auto update1_err = azihsm_crypt_sign_update(sign_op_handle, &chunk1_buf);
        ASSERT_EQ(update1_err, AZIHSM_ERROR_SUCCESS);

        azihsm_buffer chunk2_buf{(uint8_t *)chunk2, static_cast<uint32_t>(strlen(chunk2))};
        auto update2_err = azihsm_crypt_sign_update(sign_op_handle, &chunk2_buf);
        ASSERT_EQ(update2_err, AZIHSM_ERROR_SUCCESS);

        azihsm_buffer chunk3_buf{(uint8_t *)chunk3, static_cast<uint32_t>(strlen(chunk3))};
        auto update3_err = azihsm_crypt_sign_update(sign_op_handle, &chunk3_buf);
        ASSERT_EQ(update3_err, AZIHSM_ERROR_SUCCESS);

        // Finalize to get signature
        std::vector<uint8_t> signature(66);
        azihsm_buffer sig_buf{signature.data(), static_cast<uint32_t>(signature.size())};
        auto final_err = azihsm_crypt_sign_final(sign_op_handle, &sig_buf);
        ASSERT_EQ(final_err, AZIHSM_ERROR_SUCCESS);
        ASSERT_EQ(sig_buf.len, 64);

        // Verify using streaming
        azihsm_handle verify_op_handle = 0;
        auto verify_init_err = azihsm_crypt_verify_init(&algo, hmac_key.get(), &verify_op_handle);
        ASSERT_EQ(verify_init_err, AZIHSM_ERROR_SUCCESS);

        auto verify_update1_err = azihsm_crypt_verify_update(verify_op_handle, &chunk1_buf);
        ASSERT_EQ(verify_update1_err, AZIHSM_ERROR_SUCCESS);

        auto verify_update2_err = azihsm_crypt_verify_update(verify_op_handle, &chunk2_buf);
        ASSERT_EQ(verify_update2_err, AZIHSM_ERROR_SUCCESS);

        auto verify_update3_err = azihsm_crypt_verify_update(verify_op_handle, &chunk3_buf);
        ASSERT_EQ(verify_update3_err, AZIHSM_ERROR_SUCCESS);

        auto verify_final_err = azihsm_crypt_verify_final(verify_op_handle, &sig_buf);
        ASSERT_EQ(verify_final_err, AZIHSM_ERROR_SUCCESS);
    });
}