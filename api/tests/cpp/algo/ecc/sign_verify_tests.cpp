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

// This file focuses on ECC sign/verify behavior for single-shot and streaming

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

// ==================== Correctness and Curve Coverage ====================

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

// Ensures single-shot signing/verifying supports binary payloads (including embedded NUL bytes).
TEST_F(azihsm_ecc_sign_verify, single_shot_binary_payload)
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

        azihsm_algo algo{ .id = AZIHSM_ALGO_ID_ECDSA_SHA256, .params = nullptr, .len = 0 };
        const std::vector<uint8_t> payload = {
            0x00,
            0x01,
            0x7F,
            0x80,
            0xFF,
            0x10,
            0x00,
            0x20,
            0xAA,
            0x55,
        };

        test_single_shot_sign_verify(priv_key.get(), pub_key.get(), algo, payload);
    });
}

// Ensures streaming sign/verify handles binary chunks with explicit lengths.
TEST_F(azihsm_ecc_sign_verify, streaming_binary_payload)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        const std::vector<std::vector<uint8_t>> chunks = {
            { 0x00, 0x01, 0x7F },
            { 0x80, 0xFF, 0x10, 0x00 },
            { 0x20, 0xAA, 0x55, 0x00, 0x42 },
        };

        auto_ctx sign_ctx;
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, sign_ctx.get_ptr()), AZIHSM_STATUS_SUCCESS);
        for (const auto &chunk : chunks)
        {
            azihsm_buffer chunk_buf{ const_cast<uint8_t *>(chunk.data()), static_cast<uint32_t>(chunk.size()) };
            ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &chunk_buf), AZIHSM_STATUS_SUCCESS);
        }

        azihsm_buffer size_probe{ nullptr, 0 };
        ASSERT_EQ(azihsm_crypt_sign_finish(sign_ctx, &size_probe), AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(size_probe.len, 0u);

        std::vector<uint8_t> signature(size_probe.len, 0x00);
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
        ASSERT_EQ(azihsm_crypt_sign_finish(sign_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);

        auto_ctx verify_ctx;
        ASSERT_EQ(azihsm_crypt_verify_init(&algo, pub_key, verify_ctx.get_ptr()), AZIHSM_STATUS_SUCCESS);
        for (const auto &chunk : chunks)
        {
            azihsm_buffer chunk_buf{ const_cast<uint8_t *>(chunk.data()), static_cast<uint32_t>(chunk.size()) };
            ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &chunk_buf), AZIHSM_STATUS_SUCCESS);
        }
        ASSERT_EQ(azihsm_crypt_verify_finish(verify_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);

        auto_ctx verify_fail_ctx;
        ASSERT_EQ(azihsm_crypt_verify_init(&algo, pub_key, verify_fail_ctx.get_ptr()), AZIHSM_STATUS_SUCCESS);
        for (size_t idx = 0; idx < chunks.size(); ++idx)
        {
            auto modified = chunks[idx];
            if (idx == 1 && !modified.empty())
            {
                modified[1] ^= 0x01;
            }
            azihsm_buffer chunk_buf{ modified.data(), static_cast<uint32_t>(modified.size()) };
            ASSERT_EQ(azihsm_crypt_verify_update(verify_fail_ctx, &chunk_buf), AZIHSM_STATUS_SUCCESS);
        }
        ASSERT_EQ(azihsm_crypt_verify_finish(verify_fail_ctx, &sig_buf), AZIHSM_STATUS_INVALID_SIGNATURE);
    });
}

// ==================== Malformed Input and Boundary Coverage ====================

// Ensures verification fails when the signature bytes are tampered.
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

        signature[0] ^= 0xFF;

        auto verify_err = azihsm_crypt_verify(&algo, pub_key, &hash_buf, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_STATUS_INVALID_SIGNATURE);
    });
}

// Ensures verification fails when verifying the signature against different input data.
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
        ASSERT_EQ(verify_err, AZIHSM_STATUS_INVALID_SIGNATURE);
    });
}

// Ensures verification fails when signature is checked with a different ECC public key.
TEST_F(azihsm_ecc_sign_verify, verify_fails_with_wrong_public_key)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto_key priv_key_a;
        auto_key pub_key_a;
        auto err_a = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key_a.get_ptr(),
            pub_key_a.get_ptr()
        );
        ASSERT_EQ(err_a, AZIHSM_STATUS_SUCCESS);

        auto_key priv_key_b;
        auto_key pub_key_b;
        auto err_b = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key_b.get_ptr(),
            pub_key_b.get_ptr()
        );
        ASSERT_EQ(err_b, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> hash(32, 0x42);
        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> signature(64);
        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };

        auto sign_err = azihsm_crypt_sign(&algo, priv_key_a, &hash_buf, &sig_buf);
        ASSERT_EQ(sign_err, AZIHSM_STATUS_SUCCESS);

        auto verify_err = azihsm_crypt_verify(&algo, pub_key_b, &hash_buf, &sig_buf);
        ASSERT_EQ(verify_err, AZIHSM_STATUS_INVALID_SIGNATURE);
    });
}

// Ensures sign returns buffer-too-small when output signature buffer is undersized.
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

// Defines behavior for empty single-shot input across hash-and-sign variants.
TEST_F(azihsm_ecc_sign_verify, single_shot_empty_input)
{
    const std::vector<azihsm_algo_id> algos = {
        AZIHSM_ALGO_ID_ECDSA_SHA1,
        AZIHSM_ALGO_ID_ECDSA_SHA256,
        AZIHSM_ALGO_ID_ECDSA_SHA384,
        AZIHSM_ALGO_ID_ECDSA_SHA512,
    };

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

        azihsm_buffer empty_buf{ nullptr, 0 };

        for (auto algo_id : algos)
        {
            SCOPED_TRACE("algo=" + std::to_string(static_cast<uint32_t>(algo_id)));

            azihsm_algo algo{};
            algo.id = algo_id;
            algo.params = nullptr;
            algo.len = 0;

            azihsm_buffer size_probe{ nullptr, 0 };
            ASSERT_EQ(
                azihsm_crypt_sign(&algo, priv_key, &empty_buf, &size_probe),
                AZIHSM_STATUS_BUFFER_TOO_SMALL
            );
            ASSERT_GT(size_probe.len, 0u);

            std::vector<uint8_t> signature(size_probe.len, 0x00);
            azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
            ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &empty_buf, &sig_buf), AZIHSM_STATUS_SUCCESS);

            azihsm_buffer verify_sig_buf{ signature.data(), sig_buf.len };
            ASSERT_EQ(azihsm_crypt_verify(&algo, pub_key, &empty_buf, &verify_sig_buf), AZIHSM_STATUS_SUCCESS);
        }
    });
}

// Sweeps output signature sizes to check boundary transitions.
TEST_F(azihsm_ecc_sign_verify, sig_buf_size_sweep)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        auto run_case = [&](azihsm_ecc_curve curve, azihsm_algo_id algo_id, const std::vector<uint8_t> &input) {
            auto_key priv_key;
            auto_key pub_key;
            auto err = generate_ecc_keypair(session, curve, true, priv_key.get_ptr(), pub_key.get_ptr());
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            azihsm_algo algo{ .id = algo_id, .params = nullptr, .len = 0 };
            azihsm_buffer input_buf{ const_cast<uint8_t *>(input.data()), static_cast<uint32_t>(input.size()) };

            azihsm_buffer size_probe{ nullptr, 0 };
            ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &input_buf, &size_probe), AZIHSM_STATUS_BUFFER_TOO_SMALL);
            const uint32_t required = size_probe.len;
            ASSERT_GT(required, 0u);

            std::vector<uint32_t> sizes = { 0u, required > 0 ? required - 1 : 0u, required, required + 8 };
            for (uint32_t size : sizes)
            {
                std::vector<uint8_t> out(size > 0 ? size : 1, 0x00);
                azihsm_buffer sig_buf{ size > 0 ? out.data() : nullptr, size };
                auto sign_err = azihsm_crypt_sign(&algo, priv_key, &input_buf, &sig_buf);
                if (size < required)
                {
                    ASSERT_EQ(sign_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
                }
                else
                {
                    ASSERT_EQ(sign_err, AZIHSM_STATUS_SUCCESS);
                    ASSERT_GT(sig_buf.len, 0u);
                    ASSERT_LE(sig_buf.len, size);
                }
            }
        };

        run_case(AZIHSM_ECC_CURVE_P256, AZIHSM_ALGO_ID_ECDSA, std::vector<uint8_t>(32, 0xA1));
        run_case(AZIHSM_ECC_CURVE_P256, AZIHSM_ALGO_ID_ECDSA_SHA256, std::vector<uint8_t>{ 'a', 'b', 'c' });
        run_case(AZIHSM_ECC_CURVE_P384, AZIHSM_ALGO_ID_ECDSA_SHA384, std::vector<uint8_t>{ 'd', 'e', 'f' });
        run_case(AZIHSM_ECC_CURVE_P521, AZIHSM_ALGO_ID_ECDSA_SHA512, std::vector<uint8_t>{ 'g', 'h', 'i' });
    });
}

// Checks accepted pre-hash lengths and adjacent rejected lengths.
TEST_F(azihsm_ecc_sign_verify, prehash_input_len_boundaries)
{
    const std::vector<azihsm_ecc_curve> curves = {
        AZIHSM_ECC_CURVE_P256,
        AZIHSM_ECC_CURVE_P384,
        AZIHSM_ECC_CURVE_P521,
    };
    const std::vector<uint32_t> valid_lengths = { 20, 32, 48, 64 };
    const std::vector<uint32_t> invalid_lengths = { 19, 21, 31, 33, 47, 49, 63, 65 };

    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{ .id = AZIHSM_ALGO_ID_ECDSA, .params = nullptr, .len = 0 };

        for (auto curve : curves)
        {
            auto_key priv_key;
            auto_key pub_key;
            auto err = generate_ecc_keypair(
                session,
                curve,
                true,
                priv_key.get_ptr(),
                pub_key.get_ptr()
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            for (uint32_t len : valid_lengths)
            {
                SCOPED_TRACE(
                    "curve=" + std::to_string(static_cast<uint32_t>(curve))
                    + " valid_prehash_len=" + std::to_string(len)
                );

                std::vector<uint8_t> digest(len, 0x7A);
                azihsm_buffer digest_buf{ digest.data(), static_cast<uint32_t>(digest.size()) };

                azihsm_buffer size_probe{ nullptr, 0 };
                ASSERT_EQ(
                    azihsm_crypt_sign(&algo, priv_key, &digest_buf, &size_probe),
                    AZIHSM_STATUS_BUFFER_TOO_SMALL
                );
                ASSERT_GT(size_probe.len, 0u);

                std::vector<uint8_t> signature(size_probe.len, 0x00);
                azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
                ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &digest_buf, &sig_buf), AZIHSM_STATUS_SUCCESS);

                azihsm_buffer verify_sig_buf{ signature.data(), sig_buf.len };
                ASSERT_EQ(azihsm_crypt_verify(&algo, pub_key, &digest_buf, &verify_sig_buf), AZIHSM_STATUS_SUCCESS);
            }

            for (uint32_t len : invalid_lengths)
            {
                SCOPED_TRACE(
                    "curve=" + std::to_string(static_cast<uint32_t>(curve))
                    + " prehash_len=" + std::to_string(len)
                );

                std::vector<uint8_t> digest(len, 0x7A);
                azihsm_buffer digest_buf{ digest.data(), static_cast<uint32_t>(digest.size()) };

                azihsm_buffer size_probe{ nullptr, 0 };
                auto probe_err = azihsm_crypt_sign(&algo, priv_key, &digest_buf, &size_probe);
                if (probe_err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
                {
                    ASSERT_GT(size_probe.len, 0u);
                    std::vector<uint8_t> signature(size_probe.len, 0x00);
                    azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
                    ASSERT_EQ(
                        azihsm_crypt_sign(&algo, priv_key, &digest_buf, &sig_buf),
                        AZIHSM_STATUS_INVALID_ARGUMENT
                    );
                }
                else
                {
                    ASSERT_EQ(probe_err, AZIHSM_STATUS_INVALID_ARGUMENT);
                }
            }
        }
    });
}

// Runs a broader pre-hash length sweep across many sizes.
TEST_F(azihsm_ecc_sign_verify, prehash_input_len_sweep)
{
    const std::vector<azihsm_ecc_curve> curves = {
        AZIHSM_ECC_CURVE_P256,
        AZIHSM_ECC_CURVE_P384,
        AZIHSM_ECC_CURVE_P521,
    };

    // Mixes tiny, common digest, boundary-adjacent, and overlong sizes to catch
    // off-by-one and length-handling regressions in pre-hashed ECDSA paths.
    const std::vector<uint32_t> lengths = {
        1,
        2,
        7,
        16,
        20,
        28,
        31,
        32,
        33,
        47,
        48,
        49,
        64,
        66,
        80,
        96,
        1024,
        4096,
    };
    const auto is_valid_prehash_len = [](uint32_t len) {
        return len == 20 || len == 32 || len == 48 || len == 64;
    };

    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{ .id = AZIHSM_ALGO_ID_ECDSA, .params = nullptr, .len = 0 };

        for (auto curve : curves)
        {
            auto_key priv_key;
            auto_key pub_key;
            auto err = generate_ecc_keypair(session, curve, true, priv_key.get_ptr(), pub_key.get_ptr());
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            for (uint32_t len : lengths)
            {
                SCOPED_TRACE(
                    "curve=" + std::to_string(static_cast<uint32_t>(curve))
                    + " prehash_len=" + std::to_string(len)
                );

                std::vector<uint8_t> digest(len, static_cast<uint8_t>((len * 13) & 0xFF));
                azihsm_buffer digest_buf{ digest.data(), static_cast<uint32_t>(digest.size()) };

                azihsm_buffer size_probe{ nullptr, 0 };
                auto probe_err = azihsm_crypt_sign(&algo, priv_key, &digest_buf, &size_probe);

                if (is_valid_prehash_len(len))
                {
                    ASSERT_EQ(probe_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
                    ASSERT_GT(size_probe.len, 0u);

                    std::vector<uint8_t> signature(size_probe.len, 0x00);
                    azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
                    ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &digest_buf, &sig_buf), AZIHSM_STATUS_SUCCESS);

                    azihsm_buffer verify_sig_buf{ signature.data(), sig_buf.len };
                    ASSERT_EQ(azihsm_crypt_verify(&algo, pub_key, &digest_buf, &verify_sig_buf), AZIHSM_STATUS_SUCCESS);
                }
                else
                {
                    if (probe_err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
                    {
                        ASSERT_GT(size_probe.len, 0u);
                        std::vector<uint8_t> signature(size_probe.len, 0x00);
                        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
                        ASSERT_EQ(
                            azihsm_crypt_sign(&algo, priv_key, &digest_buf, &sig_buf),
                            AZIHSM_STATUS_INVALID_ARGUMENT
                        );
                    }
                    else
                    {
                        ASSERT_EQ(probe_err, AZIHSM_STATUS_INVALID_ARGUMENT);
                    }
                }
            }
        }
    });
}

// Defines rejection behavior for zero-length pre-hash input.
// Keep this separate from the generic length sweep: this case intentionally uses
// the explicit empty-buffer shape (ptr == nullptr, len == 0).
TEST_F(azihsm_ecc_sign_verify, prehash_input_len_zero)
{
    const std::vector<azihsm_ecc_curve> curves = {
        AZIHSM_ECC_CURVE_P256,
        AZIHSM_ECC_CURVE_P384,
        AZIHSM_ECC_CURVE_P521,
    };

    part_list_.for_each_session([&](azihsm_handle session) {
        azihsm_algo algo{ .id = AZIHSM_ALGO_ID_ECDSA, .params = nullptr, .len = 0 };
        azihsm_buffer empty_digest{ nullptr, 0 };

        for (auto curve : curves)
        {
            SCOPED_TRACE("curve=" + std::to_string(static_cast<uint32_t>(curve)));

            auto_key priv_key;
            auto_key pub_key;
            auto err = generate_ecc_keypair(session, curve, true, priv_key.get_ptr(), pub_key.get_ptr());
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            azihsm_buffer size_probe{ nullptr, 0 };
            auto probe_err = azihsm_crypt_sign(&algo, priv_key, &empty_digest, &size_probe);
            if (probe_err == AZIHSM_STATUS_BUFFER_TOO_SMALL)
            {
                ASSERT_GT(size_probe.len, 0u);
                std::vector<uint8_t> signature(size_probe.len, 0x00);
                azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
                ASSERT_EQ(
                    azihsm_crypt_sign(&algo, priv_key, &empty_digest, &sig_buf),
                    AZIHSM_STATUS_INVALID_ARGUMENT
                );
            }
            else
            {
                ASSERT_EQ(probe_err, AZIHSM_STATUS_INVALID_ARGUMENT);
            }
        }
    });
}

// Verifies behavior for truncated and oversized signatures.
TEST_F(azihsm_ecc_sign_verify, signature_len_boundaries)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> hash(32, 0x99);
        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };

        azihsm_buffer size_probe{ nullptr, 0 };
        ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &hash_buf, &size_probe), AZIHSM_STATUS_BUFFER_TOO_SMALL);

        std::vector<uint8_t> sig(size_probe.len, 0x00);
        azihsm_buffer sig_buf{ sig.data(), static_cast<uint32_t>(sig.size()) };
        ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer full_sig{ sig.data(), sig_buf.len };
        ASSERT_EQ(azihsm_crypt_verify(&algo, pub_key, &hash_buf, &full_sig), AZIHSM_STATUS_SUCCESS);

        if (sig_buf.len > 0)
        {
            azihsm_buffer truncated_sig{ sig.data(), sig_buf.len - 1 };
            ASSERT_NE(azihsm_crypt_verify(&algo, pub_key, &hash_buf, &truncated_sig), AZIHSM_STATUS_SUCCESS);
        }

        std::vector<uint8_t> extended = sig;
        extended.push_back(0x00);
        azihsm_buffer extended_sig{ extended.data(), static_cast<uint32_t>(extended.size()) };
        ASSERT_NE(azihsm_crypt_verify(&algo, pub_key, &hash_buf, &extended_sig), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer empty_sig{ nullptr, 0 };
        ASSERT_NE(azihsm_crypt_verify(&algo, pub_key, &hash_buf, &empty_sig), AZIHSM_STATUS_SUCCESS);
    });
}

// Runs full algorithm/curve compatibility matrix.
TEST_F(azihsm_ecc_sign_verify, algo_curve_matrix)
{
    const std::vector<azihsm_ecc_curve> curves = {
        AZIHSM_ECC_CURVE_P256,
        AZIHSM_ECC_CURVE_P384,
        AZIHSM_ECC_CURVE_P521,
    };
    const std::vector<azihsm_algo_id> algos = {
        AZIHSM_ALGO_ID_ECDSA_SHA1,
        AZIHSM_ALGO_ID_ECDSA_SHA256,
        AZIHSM_ALGO_ID_ECDSA_SHA384,
        AZIHSM_ALGO_ID_ECDSA_SHA512,
    };

    part_list_.for_each_session([&](azihsm_handle session) {
        for (auto curve : curves)
        {
            auto_key priv_key;
            auto_key pub_key;
            auto err = generate_ecc_keypair(session, curve, true, priv_key.get_ptr(), pub_key.get_ptr());
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            for (auto algo_id : algos)
            {
                azihsm_algo algo{ .id = algo_id, .params = nullptr, .len = 0 };
                const std::vector<uint8_t> data = { 'm', 'a', 't', 'r', 'i', 'x' };
                test_single_shot_sign_verify(priv_key.get(), pub_key.get(), algo, data);
            }
        }
    });
}

// Verifies many kinds of signature corruption are rejected.
TEST_F(azihsm_ecc_sign_verify, sig_mutation_sweep)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> hash(32, 0xC3);
        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };

        azihsm_buffer size_probe{ nullptr, 0 };
        ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &hash_buf, &size_probe), AZIHSM_STATUS_BUFFER_TOO_SMALL);

        std::vector<uint8_t> sig(size_probe.len, 0x00);
        azihsm_buffer sig_buf{ sig.data(), static_cast<uint32_t>(sig.size()) };
        ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf), AZIHSM_STATUS_SUCCESS);

        std::vector<size_t> mutate_indices = {
            0,
            sig_buf.len / 2,
            sig_buf.len > 0 ? sig_buf.len - 1 : 0
        };

        for (size_t idx : mutate_indices)
        {
            if (idx >= sig.size())
            {
                continue;
            }

            std::vector<uint8_t> mutated = sig;
            mutated[idx] ^= 0x5A;
            azihsm_buffer mutated_buf{ mutated.data(), static_cast<uint32_t>(sig_buf.len) };
            ASSERT_NE(azihsm_crypt_verify(&algo, pub_key, &hash_buf, &mutated_buf), AZIHSM_STATUS_SUCCESS);
        }
    });
}

// Expands hash-and-sign matrix for single-shot and streaming across all hash algorithms.
TEST_F(azihsm_ecc_sign_verify, hash_algo_curve_matrix)
{
    const std::vector<azihsm_ecc_curve> curves = {
        AZIHSM_ECC_CURVE_P256,
        AZIHSM_ECC_CURVE_P384,
        AZIHSM_ECC_CURVE_P521,
    };
    const std::vector<azihsm_algo_id> algos = {
        AZIHSM_ALGO_ID_ECDSA_SHA1,
        AZIHSM_ALGO_ID_ECDSA_SHA256,
        AZIHSM_ALGO_ID_ECDSA_SHA384,
        AZIHSM_ALGO_ID_ECDSA_SHA512,
    };

    part_list_.for_each_session([&](azihsm_handle session) {
        for (auto curve : curves)
        {
            auto_key priv_key;
            auto_key pub_key;
            auto err = generate_ecc_keypair(session, curve, true, priv_key.get_ptr(), pub_key.get_ptr());
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            for (auto algo_id : algos)
            {
                SCOPED_TRACE(
                    "curve=" + std::to_string(static_cast<uint32_t>(curve))
                    + " algo=" + std::to_string(static_cast<uint32_t>(algo_id))
                );

                azihsm_algo algo{};
                algo.id = algo_id;
                algo.params = nullptr;
                algo.len = 0;

                const std::vector<uint8_t> data = { 'h', 'a', 's', 'h', '-', 'm', 'a', 't', 'r', 'i', 'x' };
                test_single_shot_sign_verify(priv_key.get(), pub_key.get(), algo, data);

                const std::vector<const char *> chunks = { "hash", "-", "stream" };
                test_streaming_sign_verify(priv_key.get(), pub_key.get(), algo, chunks);
            }
        }
    });
}

// Confirms each hash-and-sign ECDSA variant works for both single-shot and streaming.
TEST_F(azihsm_ecc_sign_verify, hash_algo_happy_paths)
{
    const std::vector<azihsm_algo_id> algos = {
        AZIHSM_ALGO_ID_ECDSA_SHA1,
        AZIHSM_ALGO_ID_ECDSA_SHA256,
        AZIHSM_ALGO_ID_ECDSA_SHA384,
        AZIHSM_ALGO_ID_ECDSA_SHA512,
    };

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

        for (auto algo_id : algos)
        {
            SCOPED_TRACE("algo=" + std::to_string(static_cast<uint32_t>(algo_id)));

            azihsm_algo algo{};
            algo.id = algo_id;
            algo.params = nullptr;
            algo.len = 0;

            std::vector<uint8_t> message = {
                'E', 'C', 'D', 'S', 'A', '-', 'h', 'a', 's', 'h', '-', 't', 'e', 's', 't'
            };
            test_single_shot_sign_verify(priv_key.get(), pub_key.get(), algo, message);

            const std::vector<const char *> chunks = { "ECDSA ", "hash ", "stream" };
            test_streaming_sign_verify(priv_key.get(), pub_key.get(), algo, chunks);
        }
    });
}

// Confirms all hash-and-sign ECDSA variants return expected errors for bad pointers, handles, and buffers.
TEST_F(azihsm_ecc_sign_verify, hash_algo_expected_statuses)
{
    const std::vector<azihsm_algo_id> algos = {
        AZIHSM_ALGO_ID_ECDSA_SHA1,
        AZIHSM_ALGO_ID_ECDSA_SHA256,
        AZIHSM_ALGO_ID_ECDSA_SHA384,
        AZIHSM_ALGO_ID_ECDSA_SHA512,
    };

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

        std::vector<uint8_t> message = { 'S', 'H', 'A', '1' };
        std::vector<uint8_t> signature(64);
        azihsm_buffer msg_buf{ message.data(), static_cast<uint32_t>(message.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };

        azihsm_buffer bad_msg_buf{ nullptr, 1 };
        azihsm_buffer bad_sig_buf{ nullptr, 1 };

        for (auto algo_id : algos)
        {
            SCOPED_TRACE("algo=" + std::to_string(static_cast<uint32_t>(algo_id)));

            azihsm_algo algo{};
            algo.id = algo_id;
            algo.params = nullptr;
            algo.len = 0;

            ASSERT_EQ(
                azihsm_crypt_sign(nullptr, priv_key, &msg_buf, &sig_buf),
                AZIHSM_STATUS_INVALID_ARGUMENT
            );
            ASSERT_EQ(
                azihsm_crypt_verify(nullptr, pub_key, &msg_buf, &sig_buf),
                AZIHSM_STATUS_INVALID_ARGUMENT
            );

            ASSERT_EQ(
                azihsm_crypt_sign(&algo, 0xDEADBEEF, &msg_buf, &sig_buf),
                AZIHSM_STATUS_INVALID_HANDLE
            );
            ASSERT_EQ(
                azihsm_crypt_verify(&algo, 0xDEADBEEF, &msg_buf, &sig_buf),
                AZIHSM_STATUS_INVALID_HANDLE
            );

            // Invalid buffer shape: null pointer with non-zero length.
            ASSERT_EQ(
                azihsm_crypt_sign(&algo, priv_key, &bad_msg_buf, &sig_buf),
                AZIHSM_STATUS_INVALID_ARGUMENT
            );
            ASSERT_EQ(
                azihsm_crypt_verify(&algo, pub_key, &msg_buf, &bad_sig_buf),
                AZIHSM_STATUS_INVALID_ARGUMENT
            );
        }
    });
}

// ==================== Argument Validation and API Behavior ====================

// Ensures sign rejects a null algorithm pointer.
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

// Ensures sign rejects an invalid key handle.
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

// Ensures sign rejects an unsupported algorithm identifier.
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

// Ensures sign fails when a non-ECC key is used with ECDSA.
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

// Ensures verify fails when a non-ECC public key is used.
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

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto rsa_err =
            generate_rsa_unwrapping_keypair(session, rsa_priv_key.get_ptr(), rsa_pub_key.get_ptr());
        ASSERT_EQ(rsa_err, AZIHSM_STATUS_SUCCESS);

        auto verify_err = azihsm_crypt_verify(&algo, rsa_pub_key, &hash_buf, &sig_buf);
        ASSERT_NE(verify_err, AZIHSM_STATUS_SUCCESS);
    });
}

// Ensures single-shot APIs reject null required pointers.
TEST_F(azihsm_ecc_sign_verify, single_shot_null_ptrs)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };

        ASSERT_EQ(
            azihsm_crypt_sign(&algo, priv_key, nullptr, &sig_buf),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
        ASSERT_EQ(
            azihsm_crypt_sign(&algo, priv_key, &hash_buf, nullptr),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );

        // Produce a valid signature once so verify() pointer checks are isolated.
        ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf), AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(
            azihsm_crypt_verify(&algo, pub_key, nullptr, &sig_buf),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
        ASSERT_EQ(
            azihsm_crypt_verify(&algo, pub_key, &hash_buf, nullptr),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

// Ensures single-shot APIs reject invalid buffer shape (null ptr with non-zero length).
TEST_F(azihsm_ecc_sign_verify, single_shot_invalid_buffers)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };

        // Invalid shape means ptr == nullptr while len > 0.
        azihsm_buffer bad_input{ nullptr, 1 };
        azihsm_buffer bad_output{ nullptr, 64 };

        ASSERT_EQ(
            azihsm_crypt_sign(&algo, priv_key, &bad_input, &sig_buf),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
        ASSERT_EQ(
            azihsm_crypt_sign(&algo, priv_key, &hash_buf, &bad_output),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );

        ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf), AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(
            azihsm_crypt_verify(&algo, pub_key, &bad_input, &sig_buf),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
        ASSERT_EQ(
            azihsm_crypt_verify(&algo, pub_key, &hash_buf, &bad_output),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

// Ensures verify rejects a null algorithm pointer.
TEST_F(azihsm_ecc_sign_verify, verify_null_algo)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
        ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf), AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(
            azihsm_crypt_verify(nullptr, pub_key, &hash_buf, &sig_buf),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

// Ensures verify rejects an invalid key handle.
TEST_F(azihsm_ecc_sign_verify, verify_invalid_handle)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
        ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf), AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(
            azihsm_crypt_verify(&algo, 0xDEADBEEF, &hash_buf, &sig_buf),
            AZIHSM_STATUS_INVALID_HANDLE
        );
    });
}

// Ensures verify rejects unsupported algorithm identifiers.
TEST_F(azihsm_ecc_sign_verify, verify_unsupported_algo)
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

        azihsm_algo sign_algo{};
        sign_algo.id = AZIHSM_ALGO_ID_ECDSA;
        sign_algo.params = nullptr;
        sign_algo.len = 0;

        std::vector<uint8_t> signature(64);
        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
        ASSERT_EQ(
            azihsm_crypt_sign(&sign_algo, priv_key, &hash_buf, &sig_buf),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo invalid_algo{};
        invalid_algo.id = static_cast<azihsm_algo_id>(0xFFFFFFFF);
        invalid_algo.params = nullptr;
        invalid_algo.len = 0;

        ASSERT_EQ(
            azihsm_crypt_verify(&invalid_algo, pub_key, &hash_buf, &sig_buf),
            AZIHSM_STATUS_UNSUPPORTED_ALGORITHM
        );
    });
}

// Checks streaming init accepts only the correct ECC key class for sign vs verify.
TEST_F(azihsm_ecc_sign_verify, init_key_type_matrix)
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

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto rsa_err =
            generate_rsa_unwrapping_keypair(session, rsa_priv_key.get_ptr(), rsa_pub_key.get_ptr());
        ASSERT_EQ(rsa_err, AZIHSM_STATUS_SUCCESS);

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_handle ctx = 0;

        // Correct key classes for streaming operations.
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, &ctx), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(azihsm_free_ctx_handle(ctx), AZIHSM_STATUS_SUCCESS);
        ctx = 0;
        ASSERT_EQ(azihsm_crypt_verify_init(&algo, pub_key, &ctx), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(azihsm_free_ctx_handle(ctx), AZIHSM_STATUS_SUCCESS);

        // Wrong key classes should be rejected by key-type lookup.
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, pub_key, &ctx), AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(azihsm_crypt_verify_init(&algo, priv_key, &ctx), AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, rsa_priv_key, &ctx), AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(azihsm_crypt_verify_init(&algo, rsa_pub_key, &ctx), AZIHSM_STATUS_INVALID_HANDLE);
    });
}

// Checks that sign() returns the exact expected error code for bad inputs.
TEST_F(azihsm_ecc_sign_verify, sign_expected_statuses)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> hash(32, 0x5A);
        std::vector<uint8_t> sig(64, 0x00);
        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ sig.data(), static_cast<uint32_t>(sig.size()) };

        azihsm_buffer bad_hash{ nullptr, 1 };
        azihsm_buffer bad_sig{ nullptr, 1 };

        ASSERT_EQ(azihsm_crypt_sign(nullptr, priv_key, &hash_buf, &sig_buf), AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(azihsm_crypt_sign(&algo, 0xDEADBEEF, &hash_buf, &sig_buf), AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &bad_hash, &sig_buf), AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &hash_buf, &bad_sig), AZIHSM_STATUS_INVALID_ARGUMENT);

        std::vector<uint8_t> too_small_sig(8, 0x00);
        azihsm_buffer too_small_sig_buf{ too_small_sig.data(), static_cast<uint32_t>(too_small_sig.size()) };
        ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &hash_buf, &too_small_sig_buf), AZIHSM_STATUS_BUFFER_TOO_SMALL);
    });
}

// Checks that verify() returns the exact expected error code for bad inputs.
TEST_F(azihsm_ecc_sign_verify, verify_expected_statuses)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> hash(32, 0x21);
        std::vector<uint8_t> sig(64, 0x00);
        azihsm_buffer hash_buf{ hash.data(), static_cast<uint32_t>(hash.size()) };
        azihsm_buffer sig_buf{ sig.data(), static_cast<uint32_t>(sig.size()) };
        ASSERT_EQ(azihsm_crypt_sign(&algo, priv_key, &hash_buf, &sig_buf), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer bad_hash{ nullptr, 1 };
        azihsm_buffer bad_sig{ nullptr, 1 };

        ASSERT_EQ(azihsm_crypt_verify(nullptr, pub_key, &hash_buf, &sig_buf), AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(azihsm_crypt_verify(&algo, 0xDEADBEEF, &hash_buf, &sig_buf), AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(azihsm_crypt_verify(&algo, pub_key, &bad_hash, &sig_buf), AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(azihsm_crypt_verify(&algo, pub_key, &hash_buf, &bad_sig), AZIHSM_STATUS_INVALID_ARGUMENT);

        azihsm_algo bad_algo{};
        bad_algo.id = static_cast<azihsm_algo_id>(0xFFFFFFFF);
        bad_algo.params = nullptr;
        bad_algo.len = 0;
        ASSERT_EQ(azihsm_crypt_verify(&bad_algo, pub_key, &hash_buf, &sig_buf), AZIHSM_STATUS_UNSUPPORTED_ALGORITHM);
    });
}

// ==================== Streaming Lifecycle and Context Rules ====================

// Ensures streaming verify fails when the final signature is tampered.
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

        signature[0] ^= 0xFF;

        auto_ctx verify_ctx;
        ASSERT_EQ(
            azihsm_crypt_verify_init(&algo, pub_key, verify_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(
            azihsm_crypt_verify_finish(verify_ctx, &sig_buf),
            AZIHSM_STATUS_INVALID_SIGNATURE
        );
    });
}

// Ensures streaming verify fails when provided data differs from what was signed.
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
        ASSERT_EQ(
            azihsm_crypt_verify_finish(verify_ctx, &sig_buf),
            AZIHSM_STATUS_INVALID_SIGNATURE
        );
    });
}

// Ensures streaming verification fails when signature is checked with another public key.
TEST_F(azihsm_ecc_sign_verify, streaming_verify_fails_with_wrong_public_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key_a;
        auto_key pub_key_a;
        auto err_a = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key_a.get_ptr(),
            pub_key_a.get_ptr()
        );
        ASSERT_EQ(err_a, AZIHSM_STATUS_SUCCESS);

        auto_key priv_key_b;
        auto_key pub_key_b;
        auto err_b = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            priv_key_b.get_ptr(),
            pub_key_b.get_ptr()
        );
        ASSERT_EQ(err_b, AZIHSM_STATUS_SUCCESS);

        const char *message = "Test message for streaming ECDSA";

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        auto_ctx sign_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&algo, priv_key_a, sign_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer msg_buf{ const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(message)),
                               static_cast<uint32_t>(strlen(message)) };
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> signature(64);
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
        ASSERT_EQ(azihsm_crypt_sign_finish(sign_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);

        auto_ctx verify_ctx;
        ASSERT_EQ(
            azihsm_crypt_verify_init(&algo, pub_key_b, verify_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(
            azihsm_crypt_verify_finish(verify_ctx, &sig_buf),
            AZIHSM_STATUS_INVALID_SIGNATURE
        );
    });
}

// Ensures streaming sign finish reports buffer-too-small for undersized output.
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

// Confirms both single-shot and streaming signatures verify for the same message.
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

        std::vector<uint8_t> single_shot_sig(64);
        azihsm_buffer data_buf{ data.data(), static_cast<uint32_t>(data.size()) };
        azihsm_buffer single_sig_buf{ single_shot_sig.data(),
                                      static_cast<uint32_t>(single_shot_sig.size()) };
        ASSERT_EQ(
            azihsm_crypt_sign(&algo, priv_key, &data_buf, &single_sig_buf),
            AZIHSM_STATUS_SUCCESS
        );

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

// Ensures streaming init rejects null required pointers.
TEST_F(azihsm_ecc_sign_verify, stream_init_null_ptrs)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        azihsm_handle ctx = 0;
        ASSERT_EQ(
            azihsm_crypt_sign_init(nullptr, priv_key, &ctx),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
        ASSERT_EQ(
            azihsm_crypt_verify_init(nullptr, pub_key, &ctx),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );

        ASSERT_EQ(
            azihsm_crypt_sign_init(&algo, priv_key, nullptr),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
        ASSERT_EQ(
            azihsm_crypt_verify_init(&algo, pub_key, nullptr),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

// Ensures streaming update/finish rejects null input/output pointers.
TEST_F(azihsm_ecc_sign_verify, stream_update_finish_null_ptrs)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        auto_ctx sign_ctx;
        auto_ctx verify_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&algo, priv_key, sign_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(
            azihsm_crypt_verify_init(&algo, pub_key, verify_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, nullptr), AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, nullptr), AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(azihsm_crypt_sign_finish(sign_ctx, nullptr), AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(azihsm_crypt_verify_finish(verify_ctx, nullptr), AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Ensures streaming update/finish rejects invalid buffer shapes.
TEST_F(azihsm_ecc_sign_verify, stream_update_finish_invalid_buffers)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        auto_ctx sign_ctx;
        auto_ctx verify_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&algo, priv_key, sign_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(
            azihsm_crypt_verify_init(&algo, pub_key, verify_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer bad_input{ nullptr, 1 };
        azihsm_buffer bad_sig_out{ nullptr, 64 };
        azihsm_buffer bad_sig_in{ nullptr, 64 };

        ASSERT_EQ(
            azihsm_crypt_sign_update(sign_ctx, &bad_input),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
        ASSERT_EQ(
            azihsm_crypt_verify_update(verify_ctx, &bad_input),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
        ASSERT_EQ(
            azihsm_crypt_sign_finish(sign_ctx, &bad_sig_out),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
        ASSERT_EQ(
            azihsm_crypt_verify_finish(verify_ctx, &bad_sig_in),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

// Ensures streaming APIs reject context handles that do not exist.
TEST_F(azihsm_ecc_sign_verify, stream_invalid_ctx_handles)
{
    std::vector<uint8_t> input(8, 0x33);
    azihsm_buffer input_buf{ input.data(), static_cast<uint32_t>(input.size()) };
    std::vector<uint8_t> sig(64, 0x00);
    azihsm_buffer sig_buf{ sig.data(), static_cast<uint32_t>(sig.size()) };

    ASSERT_EQ(
        azihsm_crypt_sign_update(0xDEADBEEF, &input_buf),
        AZIHSM_STATUS_INVALID_HANDLE
    );
    ASSERT_EQ(
        azihsm_crypt_verify_update(0xDEADBEEF, &input_buf),
        AZIHSM_STATUS_INVALID_HANDLE
    );
    ASSERT_EQ(
        azihsm_crypt_sign_finish(0xDEADBEEF, &sig_buf),
        AZIHSM_STATUS_INVALID_HANDLE
    );
    ASSERT_EQ(
        azihsm_crypt_verify_finish(0xDEADBEEF, &sig_buf),
        AZIHSM_STATUS_INVALID_HANDLE
    );
}

// Ensures sign contexts cannot be used for verify calls (and vice versa).
TEST_F(azihsm_ecc_sign_verify, stream_op_mismatch)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        auto_ctx sign_ctx;
        auto_ctx verify_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&algo, priv_key, sign_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(
            azihsm_crypt_verify_init(&algo, pub_key, verify_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> input(8, 0x44);
        azihsm_buffer input_buf{ input.data(), static_cast<uint32_t>(input.size()) };
        std::vector<uint8_t> sig(64, 0x00);
        azihsm_buffer sig_buf{ sig.data(), static_cast<uint32_t>(sig.size()) };

        // Mismatched operation/context pair must not succeed.
        ASSERT_EQ(
            azihsm_crypt_sign_update(verify_ctx, &input_buf),
            AZIHSM_STATUS_INVALID_HANDLE
        );
        ASSERT_EQ(
            azihsm_crypt_verify_update(sign_ctx, &input_buf),
            AZIHSM_STATUS_INVALID_HANDLE
        );
        ASSERT_EQ(
            azihsm_crypt_sign_finish(verify_ctx, &sig_buf),
            AZIHSM_STATUS_INVALID_HANDLE
        );
        ASSERT_EQ(
            azihsm_crypt_verify_finish(sign_ctx, &sig_buf),
            AZIHSM_STATUS_INVALID_HANDLE
        );
    });
}

// Ensures streaming mode rejects pre-hashed ECDSA (AZIHSM_ALGO_ID_ECDSA) and only accepts hash-and-sign variants.
TEST_F(azihsm_ecc_sign_verify, stream_prehash_rejected)
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

        azihsm_algo prehash_algo{};
        prehash_algo.id = AZIHSM_ALGO_ID_ECDSA;
        prehash_algo.params = nullptr;
        prehash_algo.len = 0;

        azihsm_handle ctx = 0;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&prehash_algo, priv_key, &ctx),
            AZIHSM_STATUS_UNSUPPORTED_ALGORITHM
        );
        ASSERT_EQ(
            azihsm_crypt_verify_init(&prehash_algo, pub_key, &ctx),
            AZIHSM_STATUS_UNSUPPORTED_ALGORITHM
        );
    });
}

// Compares behavior across many streaming chunk-size splits.
TEST_F(azihsm_ecc_sign_verify, stream_chunk_sweep)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        const std::vector<std::vector<const char *>> chunk_patterns = {
            { "one chunk payload" },
            { "many ", "small ", "chunks" },
            { "", "prefix", "", "suffix" },
            { "a", "b", "c", "d", "e", "f" },
        };

        for (const auto &chunks : chunk_patterns)
        {
            test_streaming_sign_verify(priv_key.get(), pub_key.get(), algo, chunks);
        }
    });
}

// Sweeps streaming signature output buffer sizes.
TEST_F(azihsm_ecc_sign_verify, stream_sig_buf_sweep)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        std::vector<uint8_t> message = { 's', 't', 'r', 'e', 'a', 'm', '-', 's', 'i', 'z', 'e' };
        azihsm_buffer msg_buf{ message.data(), static_cast<uint32_t>(message.size()) };

        auto_ctx probe_ctx;
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, probe_ctx.get_ptr()), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(azihsm_crypt_sign_update(probe_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);
        azihsm_buffer size_probe{ nullptr, 0 };
        ASSERT_EQ(azihsm_crypt_sign_finish(probe_ctx, &size_probe), AZIHSM_STATUS_BUFFER_TOO_SMALL);
        const uint32_t required = size_probe.len;
        ASSERT_GT(required, 0u);

        std::vector<uint32_t> sizes = { 0u, required > 0 ? required - 1 : 0u, required, required + 8 };
        for (uint32_t size : sizes)
        {
            auto_ctx ctx;
            ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, ctx.get_ptr()), AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(azihsm_crypt_sign_update(ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);

            std::vector<uint8_t> out(size > 0 ? size : 1, 0x00);
            azihsm_buffer sig_buf{ size > 0 ? out.data() : nullptr, size };
            auto finish_err = azihsm_crypt_sign_finish(ctx, &sig_buf);

            if (size < required)
            {
                ASSERT_EQ(finish_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
            }
            else
            {
                ASSERT_EQ(finish_err, AZIHSM_STATUS_SUCCESS);
                ASSERT_GT(sig_buf.len, 0u);
                ASSERT_LE(sig_buf.len, size);
            }
        }
    });
}

// Zero-length update (ptr=null, len=0) is treated as a valid no-op, so signing
// and verifying an empty streamed message are both expected to succeed.
TEST_F(azihsm_ecc_sign_verify, stream_zero_len_update)
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

        azihsm_algo algo{};
        algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        algo.params = nullptr;
        algo.len = 0;

        auto_ctx sign_ctx;
        auto_ctx verify_ctx;
        ASSERT_EQ(azihsm_crypt_sign_init(&algo, priv_key, sign_ctx.get_ptr()), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(azihsm_crypt_verify_init(&algo, pub_key, verify_ctx.get_ptr()), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer empty_buf{ nullptr, 0 };
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &empty_buf), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &empty_buf), AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> signature(64, 0x00);
        azihsm_buffer sig_buf{ signature.data(), static_cast<uint32_t>(signature.size()) };
        ASSERT_EQ(azihsm_crypt_sign_finish(sign_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(azihsm_crypt_verify_finish(verify_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);
    });
}

// Verifies exact error codes for streaming misuse (wrong order / wrong context).
TEST_F(azihsm_ecc_sign_verify, stream_state_expected_statuses)
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

        azihsm_algo hash_algo{};
        hash_algo.id = AZIHSM_ALGO_ID_ECDSA_SHA256;
        hash_algo.params = nullptr;
        hash_algo.len = 0;

        azihsm_algo prehash_algo{};
        prehash_algo.id = AZIHSM_ALGO_ID_ECDSA;
        prehash_algo.params = nullptr;
        prehash_algo.len = 0;

        // Streaming APIs only support hash-while-signing variants, not pre-hashed ECDSA.
        auto_ctx rejected_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&prehash_algo, priv_key, rejected_ctx.get_ptr()),
            AZIHSM_STATUS_UNSUPPORTED_ALGORITHM
        );
        ASSERT_EQ(
            azihsm_crypt_verify_init(&prehash_algo, pub_key, rejected_ctx.get_ptr()),
            AZIHSM_STATUS_UNSUPPORTED_ALGORITHM
        );

        auto_ctx sign_ctx;
        auto_ctx verify_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&hash_algo, priv_key, sign_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(
            azihsm_crypt_verify_init(&hash_algo, pub_key, verify_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> input(8, 0xA5);
        azihsm_buffer input_buf{ input.data(), static_cast<uint32_t>(input.size()) };
        std::vector<uint8_t> sig_out(64, 0x00);
        azihsm_buffer sig_out_buf{ sig_out.data(), static_cast<uint32_t>(sig_out.size()) };
        std::vector<uint8_t> sig_in(64, 0x00);
        azihsm_buffer sig_in_buf{ sig_in.data(), static_cast<uint32_t>(sig_in.size()) };

        // Non-obvious but expected: wrong context type maps to INVALID_HANDLE.
        ASSERT_EQ(
            azihsm_crypt_sign_update(verify_ctx, &input_buf),
            AZIHSM_STATUS_INVALID_HANDLE
        );
        ASSERT_EQ(
            azihsm_crypt_verify_update(sign_ctx, &input_buf),
            AZIHSM_STATUS_INVALID_HANDLE
        );
        ASSERT_EQ(
            azihsm_crypt_sign_finish(verify_ctx, &sig_out_buf),
            AZIHSM_STATUS_INVALID_HANDLE
        );
        ASSERT_EQ(
            azihsm_crypt_verify_finish(sign_ctx, &sig_in_buf),
            AZIHSM_STATUS_INVALID_HANDLE
        );

        ASSERT_EQ(
            azihsm_crypt_sign_update(0xDEADBEEF, &input_buf),
            AZIHSM_STATUS_INVALID_HANDLE
        );
        ASSERT_EQ(
            azihsm_crypt_verify_update(0xDEADBEEF, &input_buf),
            AZIHSM_STATUS_INVALID_HANDLE
        );
    });
}

// ==================== Resiliency and Persistence ====================

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