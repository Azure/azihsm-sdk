// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstring>
#include <fstream>
#include <gtest/gtest.h>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_ctx.hpp"
#include "utils/auto_key.hpp"
#include "utils/part_init_config.hpp"
#include "utils/rsa_keygen.hpp"
#include "utils/utils.hpp"
#include <filesystem>

class azihsm_ecc_sign_verify : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

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

        // First call to get required signature size
        azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };
        auto size_err = azihsm_crypt_sign(&sign_algo, priv_key, &data_buf, &sig_buf);
        ASSERT_EQ(size_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(sig_buf.len, 0);

        // Allocate buffer and sign
        std::vector<uint8_t> signature_data(sig_buf.len);
        sig_buf.ptr = signature_data.data();
        auto sign_err = azihsm_crypt_sign(&sign_algo, priv_key, &data_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

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
        auto_ctx sign_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&sign_algo, priv_key, sign_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        for (const char *chunk : data_chunks)
        {
            azihsm_buffer buf = { .ptr = (uint8_t *)chunk, .len = (uint32_t)strlen(chunk) };
            ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &buf), AZIHSM_STATUS_SUCCESS);
        }

        // First call to get required signature size
        azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };
        auto size_err = azihsm_crypt_sign_finish(sign_ctx, &sig_buf);
        ASSERT_EQ(size_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(sig_buf.len, 0);

        // Allocate buffer and finish
        std::vector<uint8_t> signature_data(sig_buf.len);
        sig_buf.ptr = signature_data.data();
        auto final_err = azihsm_crypt_sign_finish(sign_ctx, &sig_buf);
        ASSERT_EQ(final_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        // Streaming verify
        auto_ctx verify_ctx;
        ASSERT_EQ(
            azihsm_crypt_verify_init(&sign_algo, pub_key, verify_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        for (const char *chunk : data_chunks)
        {
            azihsm_buffer buf = { .ptr = (uint8_t *)chunk, .len = (uint32_t)strlen(chunk) };
            ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &buf), AZIHSM_STATUS_SUCCESS);
        }

        azihsm_buffer verify_sig_buf = { .ptr = signature_data.data(), .len = sig_buf.len };
        ASSERT_EQ(azihsm_crypt_verify_finish(verify_ctx, &verify_sig_buf), AZIHSM_STATUS_SUCCESS);

        // Verify fails with modified data
        auto_ctx verify_fail_ctx;
        ASSERT_EQ(
            azihsm_crypt_verify_init(&sign_algo, pub_key, verify_fail_ctx.get_ptr()),
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
            azihsm_crypt_verify_finish(verify_fail_ctx, &verify_sig_buf),
            AZIHSM_STATUS_SUCCESS
        );
    }
};

// Unified test data structure for ECC tests
struct EcdsaTestParams
{
    azihsm_ecc_curve curve;
    azihsm_algo_id algo_id;
    const char *test_name;
};

// ECDSA Pre-hashed Sign/Verify Tests (Pre-hashed Message)
TEST_F(azihsm_ecc_sign_verify, sign_verify_ecdsa_prehashed_all_curves)
{
    struct PrehashedTestParams
    {
        azihsm_ecc_curve curve;
        size_t hash_size;
        const char *test_name;
        uint8_t fill_byte;
    };

    std::vector<PrehashedTestParams> test_cases = {
        { AZIHSM_ECC_CURVE_P256, 32, "P256", 0x42 },
        { AZIHSM_ECC_CURVE_P384, 48, "P384", 0x55 },
        { AZIHSM_ECC_CURVE_P521, 64, "P521", 0x77 },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing ECDSA pre-hashed with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto_key priv_key;
            auto_key pub_key;
            auto err = generate_ecc_keypair(
                session,
                test_case.curve,
                true,
                priv_key.get_ptr(),
                pub_key.get_ptr()
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(priv_key.get(), 0);
            ASSERT_NE(pub_key.get(), 0);

            std::vector<uint8_t> hashed_data(test_case.hash_size, test_case.fill_byte);

            azihsm_algo sign_algo = { .id = AZIHSM_ALGO_ID_ECDSA, .params = nullptr, .len = 0 };

            test_single_shot_sign_verify(priv_key.get(), pub_key.get(), sign_algo, hashed_data);
        });
    }
}

// ECDSA Single-Shot Sign/Verify Tests (Raw Message)
TEST_F(azihsm_ecc_sign_verify, sign_verify_ecdsa_all_hash_algorithms)
{
    std::vector<EcdsaTestParams> test_cases = {
        { AZIHSM_ECC_CURVE_P256, AZIHSM_ALGO_ID_ECDSA_SHA256, "SHA256_P256" },
        { AZIHSM_ECC_CURVE_P384, AZIHSM_ALGO_ID_ECDSA_SHA384, "SHA384_P384" },
        { AZIHSM_ECC_CURVE_P521, AZIHSM_ALGO_ID_ECDSA_SHA512, "SHA512_P521" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing ECDSA with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto_key priv_key;
            auto_key pub_key;
            auto err = generate_ecc_keypair(
                session,
                test_case.curve,
                true,
                priv_key.get_ptr(),
                pub_key.get_ptr()
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(priv_key.get(), 0);
            ASSERT_NE(pub_key.get(), 0);

            std::string test_data = std::string("Test ECDSA ") + test_case.test_name + " signing";
            std::vector<uint8_t> data_to_sign(test_data.begin(), test_data.end());

            azihsm_algo sign_algo = { .id = test_case.algo_id, .params = nullptr, .len = 0 };

            test_single_shot_sign_verify(priv_key.get(), pub_key.get(), sign_algo, data_to_sign);
        });
    }
}

// ECDSA Streaming Sign/Verify Tests (Raw Message only)
TEST_F(azihsm_ecc_sign_verify, streaming_sign_verify_ecdsa_all_hash_algorithms)
{
    std::vector<EcdsaTestParams> test_cases = {
        { AZIHSM_ECC_CURVE_P256, AZIHSM_ALGO_ID_ECDSA_SHA256, "SHA256_P256" },
        { AZIHSM_ECC_CURVE_P384, AZIHSM_ALGO_ID_ECDSA_SHA384, "SHA384_P384" },
        { AZIHSM_ECC_CURVE_P521, AZIHSM_ALGO_ID_ECDSA_SHA512, "SHA512_P521" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing ECDSA streaming with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            auto_key priv_key;
            auto_key pub_key;
            auto err = generate_ecc_keypair(
                session,
                test_case.curve,
                true,
                priv_key.get_ptr(),
                pub_key.get_ptr()
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(priv_key.get(), 0);
            ASSERT_NE(pub_key.get(), 0);

            azihsm_algo sign_algo = { .id = test_case.algo_id, .params = nullptr, .len = 0 };

            const std::vector<const char *> chunks = { "Streaming ", "ECDSA ", "signing" };
            test_streaming_sign_verify(priv_key.get(), pub_key.get(), sign_algo, chunks);
        });
    }
}

TEST_F(azihsm_ecc_sign_verify, verify_fails_with_invalid_signature)
{
    part_list_.for_each_session([&](azihsm_handle session) {
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

        std::vector<uint8_t> hash(32, 0x42);
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(64);
        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };

        auto sign_err = azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_STATUS_SUCCESS);

        // Corrupt signature
        signature[0] ^= 0xFF;

        auto verify_err = azihsm_crypt_verify(&algo, pub_key, &hash_buf, &sig_buf);
        ASSERT_NE(verify_err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, verify_fails_with_wrong_data)
{
    part_list_.for_each_session([&](azihsm_handle session) {
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

        std::vector<uint8_t> hash(32, 0x42);
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(64);
        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };

        auto sign_err = azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_STATUS_SUCCESS);

        // Use different data
        std::vector<uint8_t> wrong_hash(32, 0x99);
        azihsm_buffer wrong_buf{ wrong_hash.data(), static_cast<uint32_t>(wrong_hash.size()) };

        auto verify_err = azihsm_crypt_verify(&algo, pub_key, &wrong_buf, &sig_buf);
        ASSERT_NE(verify_err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, sign_buffer_too_small)
{
    part_list_.for_each_session([&](azihsm_handle session) {
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

        std::vector<uint8_t> hash(32, 0x42);
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(32); // Too small for P-256 (needs 64)
        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };

        auto sign_err = azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    });
}

TEST_F(azihsm_ecc_sign_verify, sign_null_algorithm)
{
    part_list_.for_each_session([&](azihsm_handle session) {
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

        std::vector<uint8_t> hash(32, 0x42);
        std::vector<uint8_t> signature(64);
        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };

        auto sign_err = azihsm_crypt_sign(nullptr, priv_key, &hash_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_ecc_sign_verify, sign_invalid_key_handle)
{
    std::vector<uint8_t> hash(32, 0x42);

    azihsm_algo algo{};
    algo.id = AZIHSM_ALGO_ID_ECDSA;
    algo.params = nullptr;
    algo.len = 0;

    std::vector<uint8_t> signature(64);
    azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
    azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };

    auto err = azihsm_crypt_sign(&algo, 0xDEADBEEF, &hash_buf, &sig_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

TEST_F(azihsm_ecc_sign_verify, sign_unsupported_algorithm)
{
    part_list_.for_each_session([&](azihsm_handle session) {
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

        std::vector<uint8_t> hash(32, 0x42);
        azihsm_algo algo{};
        algo.id = static_cast<azihsm_algo_id>(0xFFFFFFFF); // Invalid algorithm
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(64);
        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };

        auto sign_err = azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf);
        ASSERT_NE(sign_err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, wrong_key_type_for_sign)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        // Generate RSA key instead of ECC
        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto rsa_err =
            generate_rsa_unwrapping_keypair(session, rsa_priv_key.get_ptr(), rsa_pub_key.get_ptr());
        ASSERT_EQ(rsa_err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> hash(32, 0x42);
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(64);
        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };

        auto sign_err = azihsm_crypt_sign(&algo, rsa_priv_key, &hash_buf, &sig_buf);
        ASSERT_NE(sign_err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, wrong_key_type_for_verify)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        std::vector<uint8_t> hash(32, 0x42);
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(64);
        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };

        auto sign_err = azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_STATUS_SUCCESS);

        // Generate RSA key for verification
        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto rsa_err =
            generate_rsa_unwrapping_keypair(session, rsa_priv_key.get_ptr(), rsa_pub_key.get_ptr());
        ASSERT_EQ(rsa_err, AZIHSM_STATUS_SUCCESS);

        auto verify_err = azihsm_crypt_verify(&algo, rsa_pub_key, &hash_buf, &sig_buf);
        ASSERT_NE(verify_err, AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, streaming_verify_fails_with_invalid_signature)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        const char *message = "Test message for streaming ECDSA";

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Streaming sign
        auto_ctx sign_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&algo, priv_key, sign_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer msg_buf{ const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message)),
                               static_cast<uint32_t>(strlen(message)) };
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> signature(64);
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
        ASSERT_EQ(azihsm_crypt_sign_finish(sign_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);

        // Corrupt signature
        signature[0] ^= 0xFF;

        // Streaming verify with corrupted signature
        auto_ctx verify_ctx;
        ASSERT_EQ(
            azihsm_crypt_verify_init(&algo, pub_key, verify_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(azihsm_crypt_verify_finish(verify_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, streaming_verify_fails_with_wrong_data)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        const char *message = "Test message for streaming ECDSA";

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Streaming sign
        auto_ctx sign_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&algo, priv_key, sign_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer msg_buf{ const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message)),
                               static_cast<uint32_t>(strlen(message)) };
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> signature(64);
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
        ASSERT_EQ(azihsm_crypt_sign_finish(sign_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);

        // Verify with different data
        const char *wrong_message = "Wrong message";
        azihsm_buffer wrong_buf{
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(wrong_message)),
            static_cast<uint32_t>(strlen(wrong_message))
        };

        auto_ctx verify_ctx;
        ASSERT_EQ(
            azihsm_crypt_verify_init(&algo, pub_key, verify_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &wrong_buf), AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(azihsm_crypt_verify_finish(verify_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, streaming_sign_finish_buffer_too_small)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        const char *message = "Test message";

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        auto_ctx sign_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&algo, priv_key, sign_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer msg_buf{ const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message)),
                               static_cast<uint32_t>(strlen(message)) };
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> signature(32); // Too small for P-256 (needs 64)
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
        ASSERT_EQ(azihsm_crypt_sign_finish(sign_ctx, &sig_buf), AZIHSM_STATUS_BUFFER_TOO_SMALL);
    });
}

TEST_F(azihsm_ecc_sign_verify, streaming_sign_consistency_with_single_shot)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        const char *message = "Test message for consistency check";
        std::vector<uint8_t> data(message, message + strlen(message));

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        // Single-shot sign
        std::vector<uint8_t> single_shot_sig(64);
        azihsm_buffer data_buf{ data.data(), static_cast<uint32_t>(data.size()) };
        azihsm_buffer single_sig_buf{ single_shot_sig.data(),
                                      static_cast<uint32_t>(single_shot_sig.size()) };
        ASSERT_EQ(
            azihsm_crypt_sign(&algo, priv_key, &data_buf, &single_sig_buf),
            AZIHSM_STATUS_SUCCESS
        );

        // Streaming sign
        auto_ctx sign_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&algo, priv_key, sign_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &data_buf), AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> streaming_sig(64);
        azihsm_buffer streaming_sig_buf{ streaming_sig.data(),
                                         static_cast<uint32_t>(streaming_sig.size()) };
        ASSERT_EQ(azihsm_crypt_sign_finish(sign_ctx, &streaming_sig_buf), AZIHSM_STATUS_SUCCESS);

        // Both signatures should verify successfully
        azihsm_buffer verify_single_buf{ single_shot_sig.data(), single_sig_buf.len };
        ASSERT_EQ(
            azihsm_crypt_verify(&algo, pub_key, &data_buf, &verify_single_buf),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer verify_streaming_buf{ streaming_sig.data(), streaming_sig_buf.len };
        ASSERT_EQ(
            azihsm_crypt_verify(&algo, pub_key, &data_buf, &verify_streaming_buf),
            AZIHSM_STATUS_SUCCESS
        );
    });
}

//! ECC key persistence tests for resiliency scenarios.
//!
//! These tests verify that ECC keys can be:
//! 1. Generated and their masked blobs persisted to disk
//! 2. Restored from disk and used to verify previously created signatures
//!
//! Test 1 (persist_key_and_signature) generates a key pair, signs data,
//! and saves everything to a binary file including BMK and MOBK.
//!
//! Test 2 (MANUAL_restore_key_and_verify) is DISABLED for manual execution.
//! It reads the persisted data, unmasks the key, and verifies the signature.

// Cross-platform temp file path under target/tmp/
static std::string get_persistence_file_path()
{
    return (get_test_tmp_dir() / "azihsm_ecc_persistence_test.bin").string();
}

// Simple binary file format:
// [4 bytes] bmk_len
// [bmk_len bytes] bmk (backup masking key)
// [4 bytes] mobk_len
// [mobk_len bytes] mobk (masked owner backup key)
// [4 bytes] masked_key_len
// [masked_key_len bytes] masked_key
// [4 bytes] signature_len
// [signature_len bytes] signature
// [4 bytes] message_len
// [message_len bytes] message

static bool write_persistence_file(
    const std::string &path,
    const std::vector<uint8_t> &bmk,
    const std::vector<uint8_t> &mobk,
    const std::vector<uint8_t> &masked_key,
    const std::vector<uint8_t> &signature,
    const std::string &message
)
{
    std::ofstream file(path, std::ios::binary);
    if (!file)
        return false;

    auto write_blob = [&file](const std::vector<uint8_t> &data) {
        uint32_t len = static_cast<uint32_t>(data.size());
        file.write(reinterpret_cast<const char *>(&len), sizeof(len));
        if (!data.empty())
        {
            file.write(reinterpret_cast<const char *>(data.data()), len);
        }
    };

    write_blob(bmk);
    write_blob(mobk);
    write_blob(masked_key);
    write_blob(signature);

    // Write message
    uint32_t msg_len = static_cast<uint32_t>(message.size());
    file.write(reinterpret_cast<const char *>(&msg_len), sizeof(msg_len));
    file.write(message.data(), msg_len);

    return file.good();
}

static bool read_persistence_file(
    const std::string &path,
    std::vector<uint8_t> &bmk,
    std::vector<uint8_t> &mobk,
    std::vector<uint8_t> &masked_key,
    std::vector<uint8_t> &signature,
    std::string &message
)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return false;

    auto read_blob = [&file](std::vector<uint8_t> &data) -> bool {
        uint32_t len = 0;
        file.read(reinterpret_cast<char *>(&len), sizeof(len));
        if (!file)
            return false;
        data.resize(len);
        if (len > 0)
        {
            file.read(reinterpret_cast<char *>(data.data()), len);
        }
        return file.good() || file.eof();
    };

    if (!read_blob(bmk))
        return false;
    if (!read_blob(mobk))
        return false;
    if (!read_blob(masked_key))
        return false;
    if (!read_blob(signature))
        return false;

    // Read message
    uint32_t msg_len = 0;
    file.read(reinterpret_cast<char *>(&msg_len), sizeof(msg_len));
    if (!file)
        return false;
    message.resize(msg_len);
    if (msg_len > 0)
    {
        file.read(&message[0], msg_len);
    }

    return true;
}

// Helper to get first partition path from list
static std::vector<azihsm_char> get_first_partition_path()
{
    azihsm_handle list_handle = 0;
    auto err = azihsm_part_get_list(&list_handle);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        throw std::runtime_error("Failed to get partition list. Error: " + std::to_string(err));
    }

    uint32_t count = 0;
    err = azihsm_part_get_count(list_handle, &count);
    if (err != AZIHSM_STATUS_SUCCESS || count == 0)
    {
        azihsm_part_free_list(list_handle);
        throw std::runtime_error("No partitions available");
    }

    // Get path size first
    azihsm_str path = { nullptr, 0 };
    err = azihsm_part_get_path(list_handle, 0, &path);
    if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        azihsm_part_free_list(list_handle);
        throw std::runtime_error("Failed to get path size. Error: " + std::to_string(err));
    }

    std::vector<azihsm_char> buffer(path.len);
    path.str = buffer.data();
    err = azihsm_part_get_path(list_handle, 0, &path);
    azihsm_part_free_list(list_handle);

    if (err != AZIHSM_STATUS_SUCCESS)
    {
        throw std::runtime_error("Failed to get partition path. Error: " + std::to_string(err));
    }

    return buffer;
}

// Helper to get partition property as bytes
static std::vector<uint8_t> get_part_prop_bytes(azihsm_handle part, azihsm_part_prop_id id)
{
    azihsm_part_prop prop = { id, nullptr, 0 };
    auto err = azihsm_part_get_prop(part, &prop);
    if (err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        throw std::runtime_error("Failed to get part prop size. Error: " + std::to_string(err));
    }
    std::vector<uint8_t> buffer(prop.len);
    prop.val = buffer.data();
    err = azihsm_part_get_prop(part, &prop);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        throw std::runtime_error("Failed to get part prop. Error: " + std::to_string(err));
    }
    return buffer;
}

// Test 1: Generate ECC key pair, sign data, and persist to disk.
// Uses ECDSA_SHA384 which hashes and signs in one operation.
// Explicitly calls azihsm_part_open, azihsm_part_init, and azihsm_sess_open.
// Persists BMK and MOBK for proper restoration.
TEST_F(azihsm_ecc_sign_verify, persist_key_and_signature){

    // Clean up any stale file from a previous run
    std::string file_path = get_persistence_file_path();
    std::error_code ec;
    std::filesystem::remove(file_path, ec);

    // Step 1: Open and initialize partition
    auto path = get_first_partition_path();
    PartitionHandle part_handle(path);

    // Step 2: Get BMK and MOBK for persistence (needed for restore)
    auto bmk = get_part_prop_bytes(part_handle.get(), AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY);
    auto mobk = get_part_prop_bytes(part_handle.get(), AZIHSM_PART_PROP_ID_MASKED_OWNER_BACKUP_KEY);

    // Step 3: Open session
    SessionHandle session(part_handle.get());

    // Step 4: Generate ECC P384 key pair (matches SHA384)
    auto_key priv_key;
    auto_key pub_key;
    auto err = generate_ecc_keypair(
        session.get(),
        AZIHSM_ECC_CURVE_P384,
        false, // Token key
        priv_key.get_ptr(),
        pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(priv_key.get(), 0);
    ASSERT_NE(pub_key.get(), 0);

    // Step 7: Sign the message using ECDSA_SHA384 (hashes and signs in one operation)
    azihsm_algo sign_algo{};
    sign_algo.id = AZIHSM_ALGO_ID_ECDSA_SHA384;
    sign_algo.params = nullptr;
    sign_algo.len = 0;

    const std::string message = "Test message for ECC key persistence and resiliency verification";
    azihsm_buffer msg_buf{};
    msg_buf.ptr = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message.data()));
    msg_buf.len = static_cast<uint32_t>(message.size());

    // Get signature size
    azihsm_buffer sig_buf{ nullptr, 0 };
    err = azihsm_crypt_sign(&sign_algo, priv_key.get(), &msg_buf, &sig_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

    std::vector<uint8_t> signature(sig_buf.len);
    sig_buf.ptr = signature.data();
    err = azihsm_crypt_sign(&sign_algo, priv_key.get(), &msg_buf, &sig_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    // Step 8: Get masked key from private key
    azihsm_key_prop masked_prop{};
    masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
    masked_prop.val = nullptr;
    masked_prop.len = 0;

    err = azihsm_key_get_prop(priv_key.get(), &masked_prop);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    ASSERT_GT(masked_prop.len, 0u);

    std::vector<uint8_t> masked_key(masked_prop.len);
    masked_prop.val = masked_key.data();
    err = azihsm_key_get_prop(priv_key.get(), &masked_prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS) << "azihsm_key_get_prop failed";

    // Step 10: Write to disk
    bool write_ok = write_persistence_file(file_path, bmk, mobk, masked_key, signature, message);
    ASSERT_TRUE(write_ok) << "Failed to write persistence file: " << file_path;

    std::cout << "Persisted key data to: " << file_path << std::endl;
    std::cout << std::endl;
    std::cout << "To verify, run the restore test:" << std::endl;
    std::cout << "  ctest -R MANUAL_restore_key_and_verify --verbose" << std::endl;
}

// Test 2: Restore ECC key from disk and verify signature.
// DISABLED by default - run manually after Test 1.
// Explicitly calls azihsm_part_open, azihsm_part_init (with BMK/MOBK), and azihsm_sess_open.
// To run: ctest -R MANUAL_restore_key_and_verify --verbose
TEST_F(azihsm_ecc_sign_verify, DISABLED_MANUAL_restore_key_and_verify)
{
    // Step 1: Read persistence file
    std::string file_path = get_persistence_file_path();
    std::vector<uint8_t> bmk;
    std::vector<uint8_t> mobk;
    std::vector<uint8_t> masked_key;
    std::vector<uint8_t> original_signature;
    std::string message;

    bool read_ok =
        read_persistence_file(file_path, bmk, mobk, masked_key, original_signature, message);
    ASSERT_TRUE(read_ok) << "Failed to read persistence file: " << file_path
                         << ". Run persist_key_and_signature test first.";

    // Step 2: Get partition path (discover it, not from file)
    auto path = get_first_partition_path();
    azihsm_str path_str = { path.data(), static_cast<uint32_t>(path.size()) };

    // Step 3: Open partition
    azihsm_handle raw_part = 0;
    auto err = azihsm_part_open(&path_str, &raw_part);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS) << "azihsm_part_open failed";
    ASSERT_NE(raw_part, 0u);
    PartitionHandle part_handle = PartitionHandle::from_raw(raw_part);

    // Step 4: Initialize partition with credentials AND BMK/MOBK
    azihsm_credentials creds{};
    std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
    std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

    azihsm_buffer bmk_buf = { bmk.data(), static_cast<uint32_t>(bmk.size()) };
    azihsm_buffer mobk_buf = { mobk.data(), static_cast<uint32_t>(mobk.size()) };

    PartInitConfig init_config{};
    make_part_init_config(part_handle.get(), init_config);

    err = azihsm_part_init(
        part_handle.get(),
        &creds,
        &bmk_buf,
        nullptr,
        &init_config.backup_config,
        &init_config.pota_endorsement
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS) << "azihsm_part_init with BMK/MOBK failed";

    // Step 5: Open session
    SessionHandle session(part_handle.get());

    // Step 6: Unmask the key pair (returns both private and public keys)
    azihsm_buffer masked_key_buf{};
    masked_key_buf.ptr = masked_key.data();
    masked_key_buf.len = static_cast<uint32_t>(masked_key.size());

    auto_key restored_priv_key;
    auto_key restored_pub_key;
    err = azihsm_key_unmask_pair(
        session.get(),
        AZIHSM_KEY_KIND_ECC,
        &masked_key_buf,
        restored_priv_key.get_ptr(),
        restored_pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS) << "azihsm_key_unmask_pair failed";
    ASSERT_NE(restored_priv_key.get(), 0);
    ASSERT_NE(restored_pub_key.get(), 0);

    // Step 7: Verify the original signature using the restored public key
    azihsm_algo sign_algo{};
    sign_algo.id = AZIHSM_ALGO_ID_ECDSA_SHA384;
    sign_algo.params = nullptr;
    sign_algo.len = 0;

    azihsm_buffer msg_buf{};
    msg_buf.ptr = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message.data()));
    msg_buf.len = static_cast<uint32_t>(message.size());

    azihsm_buffer sig_buf{};
    sig_buf.ptr = original_signature.data();
    sig_buf.len = static_cast<uint32_t>(original_signature.size());

    err = azihsm_crypt_verify(&sign_algo, restored_pub_key.get(), &msg_buf, &sig_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS) << "Original signature verification failed";

    // Step 8: Sign the same message again with restored private key
    azihsm_buffer new_sig_buf{ nullptr, 0 };
    err = azihsm_crypt_sign(&sign_algo, restored_priv_key.get(), &msg_buf, &new_sig_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);

    std::vector<uint8_t> new_signature(new_sig_buf.len);
    new_sig_buf.ptr = new_signature.data();
    err = azihsm_crypt_sign(&sign_algo, restored_priv_key.get(), &msg_buf, &new_sig_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS) << "azihsm_crypt_sign failed";

    // Step 9: Verify the new signature
    err = azihsm_crypt_verify(&sign_algo, restored_pub_key.get(), &msg_buf, &new_sig_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS) << "New signature verification failed";

    // Clean up the persistence file
    std::error_code ec;
    std::filesystem::remove(file_path, ec);

    std::cout << std::endl;
    std::cout << "=== All verifications passed! ===" << std::endl;
}