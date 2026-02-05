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
#include "utils/auto_key.hpp"
#include "utils/key_import.hpp"
#include "utils/key_props.hpp"
#include "utils/rsa_keygen.hpp"

class azihsm_rsa_sign_verify : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Helper function to setup wrapping and imported key pairs
    void setup_keys(
        azihsm_handle session,
        auto_key &wrapping_priv_key,
        auto_key &wrapping_pub_key,
        auto_key &imported_priv_key,
        auto_key &imported_pub_key
    )
    {
        // Generate wrapping key pair
        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        // Import test key pair
        key_props import_props = {
            .key_kind = AZIHSM_KEY_KIND_RSA,
            .key_size_bits = 2048,
            .session_key = true,
            .sign = true,
            .verify = true,
            .encrypt = false,
            .decrypt = false,
        };
        auto import_err = import_keypair(
            wrapping_pub_key.get(),
            wrapping_priv_key.get(),
            rsa_private_key_der,
            import_props,
            imported_priv_key.get_ptr(),
            imported_pub_key.get_ptr()
        );
        ASSERT_EQ(import_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(imported_priv_key.get(), 0);
        ASSERT_NE(imported_pub_key.get(), 0);
    }

    // Helper function to perform single-shot sign/verify test
    void test_single_shot_sign_verify(
        azihsm_handle priv_key,
        azihsm_handle pub_key,
        azihsm_algo &sign_algo,
        const std::vector<uint8_t> &data_to_sign
    )
    {
        azihsm_buffer data_buf = { .ptr = const_cast<uint8_t *>(data_to_sign.data()),
                                   .len = static_cast<uint32_t>(data_to_sign.size()) };

        std::vector<uint8_t> signature_data(256);
        azihsm_buffer sig_buf = { .ptr = signature_data.data(),
                                  .len = static_cast<uint32_t>(signature_data.size()) };

        // Sign
        auto sign_err = azihsm_crypt_sign(&sign_algo, priv_key, &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);
        ASSERT_LE(sig_buf.len, 256);

        // Verify
        azihsm_buffer verify_sig_buf = { .ptr = signature_data.data(), .len = sig_buf.len };
        auto verify_err = azihsm_crypt_verify(&sign_algo, pub_key, &data_buf, &verify_sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_STATUS_SUCCESS);

        // Verify fails with modified data
        std::vector<uint8_t> modified_data = data_to_sign;
        modified_data[0] ^= 0xFF;
        azihsm_buffer modified_buf = { .ptr = modified_data.data(),
                                       .len = static_cast<uint32_t>(modified_data.size()) };
        auto verify_fail_err =
            azihsm_crypt_verify(&sign_algo, pub_key, &modified_buf, &verify_sig_buf);
        ASSERT_NE(verify_fail_err, AZIHSM_STATUS_SUCCESS);
    }

    // Helper function to perform streaming sign/verify test
    void test_streaming_sign_verify(
        azihsm_handle priv_key,
        azihsm_handle pub_key,
        azihsm_algo &sign_algo,
        const std::vector<const char *> &data_chunks
    )
    {
        // Streaming sign
        azihsm_handle sign_ctx = 0;
        ASSERT_EQ(azihsm_crypt_sign_init(&sign_algo, priv_key, &sign_ctx), AZIHSM_STATUS_SUCCESS);

        for (const char *chunk : data_chunks)
        {
            azihsm_buffer buf = { .ptr = (uint8_t *)chunk, .len = (uint32_t)strlen(chunk) };
            ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &buf), AZIHSM_STATUS_SUCCESS);
        }

        std::vector<uint8_t> signature_data(256);
        azihsm_buffer sig_buf = { .ptr = signature_data.data(), .len = 256 };
        ASSERT_EQ(azihsm_crypt_sign_final(sign_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        // Streaming verify
        azihsm_handle verify_ctx = 0;
        ASSERT_EQ(azihsm_crypt_verify_init(&sign_algo, pub_key, &verify_ctx), AZIHSM_STATUS_SUCCESS);

        for (const char *chunk : data_chunks)
        {
            azihsm_buffer buf = { .ptr = (uint8_t *)chunk, .len = (uint32_t)strlen(chunk) };
            ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &buf), AZIHSM_STATUS_SUCCESS);
        }

        azihsm_buffer verify_sig_buf = { .ptr = signature_data.data(), .len = sig_buf.len };
        ASSERT_EQ(azihsm_crypt_verify_final(verify_ctx, &verify_sig_buf), AZIHSM_STATUS_SUCCESS);

        // Verify fails with modified data
        azihsm_handle verify_fail_ctx = 0;
        ASSERT_EQ(
            azihsm_crypt_verify_init(&sign_algo, pub_key, &verify_fail_ctx),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<const char *> modified_chunks = data_chunks;
        modified_chunks[0] = "Modified ";

        for (const char *chunk : modified_chunks)
        {
            azihsm_buffer buf = { .ptr = (uint8_t *)chunk, .len = (uint32_t)strlen(chunk) };
            ASSERT_EQ(azihsm_crypt_verify_update(verify_fail_ctx, &buf), AZIHSM_STATUS_SUCCESS);
        }

        ASSERT_NE(
            azihsm_crypt_verify_final(verify_fail_ctx, &verify_sig_buf),
            AZIHSM_STATUS_SUCCESS
        );
    }
};

// Unified test data structure for RSA tests (both single-shot and streaming)
struct RsaTestParams
{
    azihsm_algo_id algo_id;
    const char *test_name;
    azihsm_algo_rsa_pkcs_pss_params *pss_params; // nullptr for PKCS#1
};

// RSA PKCS#1 Single-Shot Sign/Verify Tests (Raw Message)
TEST_F(azihsm_rsa_sign_verify, sign_verify_pkcs_all_hash_algorithms)
{
    std::vector<RsaTestParams> test_cases = {
        { AZIHSM_ALGO_ID_RSA_PKCS_SHA1, "SHA1", nullptr },
        { AZIHSM_ALGO_ID_RSA_PKCS_SHA256, "SHA256", nullptr },
        { AZIHSM_ALGO_ID_RSA_PKCS_SHA384, "SHA384", nullptr },
        { AZIHSM_ALGO_ID_RSA_PKCS_SHA512, "SHA512", nullptr },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing PKCS#1 with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto_key wrapping_priv_key, wrapping_pub_key;
            auto_key imported_priv_key, imported_pub_key;
            setup_keys(
                session,
                wrapping_priv_key,
                wrapping_pub_key,
                imported_priv_key,
                imported_pub_key
            );

            std::string test_data =
                std::string("Test RSA PKCS#1 v1.5 ") + test_case.test_name + " signing";
            std::vector<uint8_t> data_to_sign(test_data.begin(), test_data.end());

            azihsm_algo sign_algo = {
                .id = test_case.algo_id,
                .params = test_case.pss_params,
                .len = test_case.pss_params
                           ? static_cast<uint32_t>(sizeof(azihsm_algo_rsa_pkcs_pss_params))
                           : 0
            };

            test_single_shot_sign_verify(
                imported_priv_key.get(),
                imported_pub_key.get(),
                sign_algo,
                data_to_sign
            );

            ASSERT_EQ(azihsm_key_delete(imported_priv_key.release()), AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(azihsm_key_delete(imported_pub_key.release()), AZIHSM_STATUS_SUCCESS);
        });
    }
}

// RSA PSS Single-Shot Sign/Verify Tests (Raw Message)
TEST_F(azihsm_rsa_sign_verify, sign_verify_pss_all_hash_algorithms)
{
    azihsm_algo_rsa_pkcs_pss_params pss_params_sha1 = { .hash_algo_id = AZIHSM_ALGO_ID_SHA1,
                                                        .mgf_id = AZIHSM_MGF1_ID_SHA1,
                                                        .salt_len = 20 };

    azihsm_algo_rsa_pkcs_pss_params pss_params_sha256 = { .hash_algo_id = AZIHSM_ALGO_ID_SHA256,
                                                          .mgf_id = AZIHSM_MGF1_ID_SHA256,
                                                          .salt_len = 32 };

    azihsm_algo_rsa_pkcs_pss_params pss_params_sha384 = { .hash_algo_id = AZIHSM_ALGO_ID_SHA384,
                                                          .mgf_id = AZIHSM_MGF1_ID_SHA384,
                                                          .salt_len = 48 };

    azihsm_algo_rsa_pkcs_pss_params pss_params_sha512 = { .hash_algo_id = AZIHSM_ALGO_ID_SHA512,
                                                          .mgf_id = AZIHSM_MGF1_ID_SHA512,
                                                          .salt_len = 64 };

    std::vector<RsaTestParams> test_cases = {
        { AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA1, "SHA1", &pss_params_sha1 },
        { AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA256, "SHA256", &pss_params_sha256 },
        { AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA384, "SHA384", &pss_params_sha384 },
        { AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA512, "SHA512", &pss_params_sha512 },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing PSS with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto_key wrapping_priv_key, wrapping_pub_key;
            auto_key imported_priv_key, imported_pub_key;
            setup_keys(
                session,
                wrapping_priv_key,
                wrapping_pub_key,
                imported_priv_key,
                imported_pub_key
            );

            std::string test_data = std::string("Test RSA PSS ") + test_case.test_name + " signing";
            std::vector<uint8_t> data_to_sign(test_data.begin(), test_data.end());

            azihsm_algo sign_algo = { .id = test_case.algo_id,
                                      .params = test_case.pss_params,
                                      .len = sizeof(azihsm_algo_rsa_pkcs_pss_params) };

            test_single_shot_sign_verify(
                imported_priv_key.get(),
                imported_pub_key.get(),
                sign_algo,
                data_to_sign
            );

            ASSERT_EQ(azihsm_key_delete(imported_priv_key.release()), AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(azihsm_key_delete(imported_pub_key.release()), AZIHSM_STATUS_SUCCESS);
        });
    }
}

// RSA PSS Pre-hashed Sign/Verify Tests (Pre-hashed Message)
TEST_F(azihsm_rsa_sign_verify, sign_verify_pss_prehashed_all_hash_algorithms)
{
    azihsm_algo_rsa_pkcs_pss_params pss_params_sha1 = { .hash_algo_id = AZIHSM_ALGO_ID_SHA1,
                                                        .mgf_id = AZIHSM_MGF1_ID_SHA1,
                                                        .salt_len = 20 };

    azihsm_algo_rsa_pkcs_pss_params pss_params_sha256 = { .hash_algo_id = AZIHSM_ALGO_ID_SHA256,
                                                          .mgf_id = AZIHSM_MGF1_ID_SHA256,
                                                          .salt_len = 32 };

    azihsm_algo_rsa_pkcs_pss_params pss_params_sha384 = { .hash_algo_id = AZIHSM_ALGO_ID_SHA384,
                                                          .mgf_id = AZIHSM_MGF1_ID_SHA384,
                                                          .salt_len = 48 };

    azihsm_algo_rsa_pkcs_pss_params pss_params_sha512 = { .hash_algo_id = AZIHSM_ALGO_ID_SHA512,
                                                          .mgf_id = AZIHSM_MGF1_ID_SHA512,
                                                          .salt_len = 64 };

    struct PrehashedTestParams
    {
        const char *test_name;
        azihsm_algo_rsa_pkcs_pss_params *pss_params;
        size_t hash_size;
        uint8_t fill_byte;
    };

    std::vector<PrehashedTestParams> test_cases = {
        { "SHA1", &pss_params_sha1, 20, 0x9A },
        { "SHA256", &pss_params_sha256, 32, 0xAB },
        { "SHA384", &pss_params_sha384, 48, 0xCD },
        { "SHA512", &pss_params_sha512, 64, 0xEF },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing PSS pre-hashed with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto_key wrapping_priv_key, wrapping_pub_key;
            auto_key imported_priv_key, imported_pub_key;
            setup_keys(
                session,
                wrapping_priv_key,
                wrapping_pub_key,
                imported_priv_key,
                imported_pub_key
            );

            std::vector<uint8_t> hashed_data(test_case.hash_size, test_case.fill_byte);

            azihsm_algo sign_algo = { .id = AZIHSM_ALGO_ID_RSA_PKCS_PSS,
                                      .params = test_case.pss_params,
                                      .len = sizeof(azihsm_algo_rsa_pkcs_pss_params) };

            test_single_shot_sign_verify(
                imported_priv_key.get(),
                imported_pub_key.get(),
                sign_algo,
                hashed_data
            );

            ASSERT_EQ(azihsm_key_delete(imported_priv_key.release()), AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(azihsm_key_delete(imported_pub_key.release()), AZIHSM_STATUS_SUCCESS);
        });
    }
}

// RSA PKCS#1 Streaming Sign/Verify Tests (Raw Message)
TEST_F(azihsm_rsa_sign_verify, streaming_sign_verify_pkcs_all_hash_algorithms)
{
    std::vector<RsaTestParams> test_cases = {
        { AZIHSM_ALGO_ID_RSA_PKCS_SHA1, "SHA1", nullptr },
        { AZIHSM_ALGO_ID_RSA_PKCS_SHA256, "SHA256", nullptr },
        { AZIHSM_ALGO_ID_RSA_PKCS_SHA384, "SHA384", nullptr },
        { AZIHSM_ALGO_ID_RSA_PKCS_SHA512, "SHA512", nullptr },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing PKCS#1 streaming with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto_key wrapping_priv_key, wrapping_pub_key;
            auto_key imported_priv_key, imported_pub_key;
            setup_keys(
                session,
                wrapping_priv_key,
                wrapping_pub_key,
                imported_priv_key,
                imported_pub_key
            );

            azihsm_algo sign_algo = {
                .id = test_case.algo_id,
                .params = test_case.pss_params,
                .len = test_case.pss_params
                           ? static_cast<uint32_t>(sizeof(azihsm_algo_rsa_pkcs_pss_params))
                           : 0
            };

            std::vector<const char *> chunks = { "Part1 ", "Part2 ", "Part3" };
            test_streaming_sign_verify(
                imported_priv_key.get(),
                imported_pub_key.get(),
                sign_algo,
                chunks
            );

            ASSERT_EQ(azihsm_key_delete(imported_priv_key.release()), AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(azihsm_key_delete(imported_pub_key.release()), AZIHSM_STATUS_SUCCESS);
        });
    }
}

// RSA PSS Streaming Sign/Verify Tests
TEST_F(azihsm_rsa_sign_verify, streaming_sign_verify_pss_all_hash_algorithms)
{
    azihsm_algo_rsa_pkcs_pss_params pss_params_sha1 = { .hash_algo_id = AZIHSM_ALGO_ID_SHA1,
                                                        .mgf_id = AZIHSM_MGF1_ID_SHA1,
                                                        .salt_len = 20 };

    azihsm_algo_rsa_pkcs_pss_params pss_params_sha256 = { .hash_algo_id = AZIHSM_ALGO_ID_SHA256,
                                                          .mgf_id = AZIHSM_MGF1_ID_SHA256,
                                                          .salt_len = 32 };

    azihsm_algo_rsa_pkcs_pss_params pss_params_sha384 = { .hash_algo_id = AZIHSM_ALGO_ID_SHA384,
                                                          .mgf_id = AZIHSM_MGF1_ID_SHA384,
                                                          .salt_len = 48 };

    azihsm_algo_rsa_pkcs_pss_params pss_params_sha512 = { .hash_algo_id = AZIHSM_ALGO_ID_SHA512,
                                                          .mgf_id = AZIHSM_MGF1_ID_SHA512,
                                                          .salt_len = 64 };

    std::vector<RsaTestParams> test_cases = {
        { AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA1, "SHA1", &pss_params_sha1 },
        { AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA256, "SHA256", &pss_params_sha256 },
        { AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA384, "SHA384", &pss_params_sha384 },
        { AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA512, "SHA512", &pss_params_sha512 },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing PSS streaming with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto_key wrapping_priv_key, wrapping_pub_key;
            auto_key imported_priv_key, imported_pub_key;
            setup_keys(
                session,
                wrapping_priv_key,
                wrapping_pub_key,
                imported_priv_key,
                imported_pub_key
            );

            azihsm_algo sign_algo = { .id = test_case.algo_id,
                                      .params = test_case.pss_params,
                                      .len = sizeof(azihsm_algo_rsa_pkcs_pss_params) };

            std::vector<const char *> chunks = { "Streaming ", "PSS ", test_case.test_name };
            test_streaming_sign_verify(
                imported_priv_key.get(),
                imported_pub_key.get(),
                sign_algo,
                chunks
            );

            ASSERT_EQ(azihsm_key_delete(imported_priv_key.release()), AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(azihsm_key_delete(imported_pub_key.release()), AZIHSM_STATUS_SUCCESS);
        });
    }
}