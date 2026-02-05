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
#include "utils/rsa_keygen.hpp"

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
        azihsm_handle sign_ctx = 0;
        ASSERT_EQ(azihsm_crypt_sign_init(&sign_algo, priv_key, &sign_ctx), AZIHSM_STATUS_SUCCESS);

        for (const char *chunk : data_chunks)
        {
            azihsm_buffer buf = { .ptr = (uint8_t *)chunk, .len = (uint32_t)strlen(chunk) };
            ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &buf), AZIHSM_STATUS_SUCCESS);
        }

        // First call to get required signature size
        azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };
        auto size_err = azihsm_crypt_sign_final(sign_ctx, &sig_buf);
        ASSERT_EQ(size_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(sig_buf.len, 0);

        // Allocate buffer and finalize
        std::vector<uint8_t> signature_data(sig_buf.len);
        sig_buf.ptr = signature_data.data();
        auto final_err = azihsm_crypt_sign_final(sign_ctx, &sig_buf);
        ASSERT_EQ(final_err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(sig_buf.len, 0);

        // Streaming verify
        azihsm_handle verify_ctx = 0;
        ASSERT_EQ(
            azihsm_crypt_verify_init(&sign_algo, pub_key, &verify_ctx),
            AZIHSM_STATUS_SUCCESS
        );

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
        azihsm_handle sign_ctx = 0;
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, &sign_ctx), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer msg_buf{ const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message)),
                               static_cast<uint32_t>(strlen(message)) };
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> signature(64);
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
        ASSERT_EQ(azihsm_crypt_sign_final(sign_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);

        // Corrupt signature
        signature[0] ^= 0xFF;

        // Streaming verify with corrupted signature
        azihsm_handle verify_ctx = 0;
        ASSERT_EQ(azihsm_crypt_verify_init(&algo, pub_key, &verify_ctx), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(azihsm_crypt_verify_final(verify_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);
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
        azihsm_handle sign_ctx = 0;
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, &sign_ctx), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer msg_buf{ const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message)),
                               static_cast<uint32_t>(strlen(message)) };
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> signature(64);
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
        ASSERT_EQ(azihsm_crypt_sign_final(sign_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);

        // Verify with different data
        const char *wrong_message = "Wrong message";
        azihsm_buffer wrong_buf{
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(wrong_message)),
            static_cast<uint32_t>(strlen(wrong_message))
        };

        azihsm_handle verify_ctx = 0;
        ASSERT_EQ(azihsm_crypt_verify_init(&algo, pub_key, &verify_ctx), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &wrong_buf), AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(azihsm_crypt_verify_final(verify_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);
    });
}

TEST_F(azihsm_ecc_sign_verify, streaming_sign_final_buffer_too_small)
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

        azihsm_handle sign_ctx = 0;
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, &sign_ctx), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer msg_buf{ const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message)),
                               static_cast<uint32_t>(strlen(message)) };
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> signature(32); // Too small for P-256 (needs 64)
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
        ASSERT_EQ(azihsm_crypt_sign_final(sign_ctx, &sig_buf), AZIHSM_STATUS_BUFFER_TOO_SMALL);
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
        azihsm_handle sign_ctx = 0;
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, &sign_ctx), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &data_buf), AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> streaming_sig(64);
        azihsm_buffer streaming_sig_buf{ streaming_sig.data(),
                                         static_cast<uint32_t>(streaming_sig.size()) };
        ASSERT_EQ(azihsm_crypt_sign_final(sign_ctx, &streaming_sig_buf), AZIHSM_STATUS_SUCCESS);

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