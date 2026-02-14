// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_ctx.hpp"
#include "utils/auto_key.hpp"

class azihsm_hmac_sign_verify : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Helper function to perform single-shot HMAC sign/verify test
    void test_single_shot_hmac_sign_verify(
        azihsm_handle hmac_key,
        azihsm_algo &algo,
        const std::vector<uint8_t> &data
    )
    {
        azihsm_buffer data_buf = { .ptr = const_cast<uint8_t *>(data.data()),
                                   .len = static_cast<uint32_t>(data.size()) };

        // First call to get required signature size
        azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };
        auto size_err = azihsm_crypt_sign(&algo, hmac_key, &data_buf, &sig_buf);
        ASSERT_EQ(size_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(sig_buf.len, 0);

        // Allocate buffer and sign
        std::vector<uint8_t> signature(sig_buf.len);
        sig_buf.ptr = signature.data();
        auto sign_err = azihsm_crypt_sign(&algo, hmac_key, &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        // Verify
        auto verify_err = azihsm_crypt_verify(&algo, hmac_key, &data_buf, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_STATUS_SUCCESS);
    }

    // Helper function to perform streaming HMAC sign/verify test
    void test_streaming_hmac_sign_verify(
        azihsm_handle hmac_key,
        azihsm_algo &algo,
        const std::vector<const char *> &data_chunks
    )
    {
        // Initialize streaming sign operation
        auto_ctx sign_op_handle;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&algo, hmac_key, sign_op_handle.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        // Update with chunks
        for (const char *chunk : data_chunks)
        {
            azihsm_buffer chunk_buf = { .ptr = (uint8_t *)chunk,
                                        .len = static_cast<uint32_t>(strlen(chunk)) };

            // Print the chunk being processed
            for (size_t i = 0; i < chunk_buf.len; ++i)
            {
                std::cout << reinterpret_cast<char *>(chunk_buf.ptr)[i];
            }
            std::cout << std::endl;
            ASSERT_EQ(
                azihsm_crypt_sign_update(sign_op_handle, &chunk_buf),
                AZIHSM_STATUS_SUCCESS
            );
        }

        // First call to get required signature size
        azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };
        auto size_err = azihsm_crypt_sign_final(sign_op_handle, &sig_buf);
        ASSERT_EQ(size_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(sig_buf.len, 0);

        // Allocate buffer and finalize
        std::vector<uint8_t> signature(sig_buf.len);
        sig_buf.ptr = signature.data();
        auto final_err = azihsm_crypt_sign_final(sign_op_handle, &sig_buf);
        ASSERT_EQ(final_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        // Verify using streaming
        auto_ctx verify_op_handle;
        ASSERT_EQ(
            azihsm_crypt_verify_init(&algo, hmac_key, verify_op_handle.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        for (const char *chunk : data_chunks)
        {
            azihsm_buffer chunk_buf = { .ptr = (uint8_t *)chunk,
                                        .len = static_cast<uint32_t>(strlen(chunk)) };

            // Print the chunk being processed
            for (size_t i = 0; i < chunk_buf.len; ++i)
            {
                std::cout << reinterpret_cast<char *>(chunk_buf.ptr)[i];
            }
            std::cout << std::endl;
            ASSERT_EQ(
                azihsm_crypt_verify_update(verify_op_handle, &chunk_buf),
                AZIHSM_STATUS_SUCCESS
            );
        }

        ASSERT_EQ(
            azihsm_crypt_verify_final(verify_op_handle, &sig_buf),
            AZIHSM_STATUS_SUCCESS
        );
    }
};

// Unified test data structure for HMAC tests
struct HmacTestParams
{
    azihsm_key_kind key_kind;
    azihsm_algo_id algo_id;
    azihsm_ecc_curve curve;
    const char *test_name;
};

// HMAC Single-Shot Sign/Verify Tests
TEST_F(azihsm_hmac_sign_verify, sign_verify_hmac_all_algorithms)
{
    std::vector<HmacTestParams> test_cases = {
        { AZIHSM_KEY_KIND_HMAC_SHA256,
          AZIHSM_ALGO_ID_HMAC_SHA256,
          AZIHSM_ECC_CURVE_P256,
          "SHA256" },
        { AZIHSM_KEY_KIND_HMAC_SHA384,
          AZIHSM_ALGO_ID_HMAC_SHA384,
          AZIHSM_ECC_CURVE_P384,
          "SHA384" },
        { AZIHSM_KEY_KIND_HMAC_SHA512,
          AZIHSM_ALGO_ID_HMAC_SHA512,
          AZIHSM_ECC_CURVE_P521,
          "SHA512" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing HMAC with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            // Generate EC key pairs and derive HMAC key
            EcdhKeyPairSet key_pairs;
            auto_key hmac_key;

            auto err = generate_ecdh_keys_and_derive_hmac(
                session,
                test_case.key_kind,
                key_pairs,
                hmac_key.handle,
                test_case.curve
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            // Prepare test data
            std::string message =
                std::string("Hello, HMAC-") + test_case.test_name + " authentication with HSM!";
            std::vector<uint8_t> data(message.begin(), message.end());

            azihsm_algo algo = { .id = test_case.algo_id, .params = nullptr, .len = 0 };

            test_single_shot_hmac_sign_verify(hmac_key.get(), algo, data);
        });
    }
}

// HMAC Streaming Sign/Verify Tests
TEST_F(azihsm_hmac_sign_verify, sign_verify_hmac_streaming_all_algorithms)
{
    std::vector<HmacTestParams> test_cases = {
        { AZIHSM_KEY_KIND_HMAC_SHA256,
          AZIHSM_ALGO_ID_HMAC_SHA256,
          AZIHSM_ECC_CURVE_P256,
          "SHA256" },
        { AZIHSM_KEY_KIND_HMAC_SHA384,
          AZIHSM_ALGO_ID_HMAC_SHA384,
          AZIHSM_ECC_CURVE_P384,
          "SHA384" },
        { AZIHSM_KEY_KIND_HMAC_SHA512,
          AZIHSM_ALGO_ID_HMAC_SHA512,
          AZIHSM_ECC_CURVE_P521,
          "SHA512" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing HMAC streaming with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            // Generate EC key pairs and derive HMAC key
            EcdhKeyPairSet key_pairs;
            auto_key hmac_key;

            auto err = generate_ecdh_keys_and_derive_hmac(
                session,
                test_case.key_kind,
                key_pairs,
                hmac_key.handle,
                test_case.curve
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            // Prepare test data in chunks
            const std::vector<const char *> chunks = { "Hello, ",
                                                       "HMAC streaming ",
                                                       "authentication!" };

            azihsm_algo algo = { .id = test_case.algo_id, .params = nullptr, .len = 0 };

            test_streaming_hmac_sign_verify(hmac_key.get(), algo, chunks);
        });
    }
}