// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
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

            ASSERT_EQ(azihsm_crypt_sign_update(sign_op_handle, &chunk_buf), AZIHSM_STATUS_SUCCESS);
        }

        // First call to get required signature size
        azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };
        auto size_err = azihsm_crypt_sign_finish(sign_op_handle, &sig_buf);
        ASSERT_EQ(size_err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(sig_buf.len, 0);

        // Allocate buffer and finish
        std::vector<uint8_t> signature(sig_buf.len);
        sig_buf.ptr = signature.data();
        auto final_err = azihsm_crypt_sign_finish(sign_op_handle, &sig_buf);
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
            ASSERT_EQ(
                azihsm_crypt_verify_update(verify_op_handle, &chunk_buf),
                AZIHSM_STATUS_SUCCESS
            );
        }

        ASSERT_EQ(azihsm_crypt_verify_finish(verify_op_handle, &sig_buf), AZIHSM_STATUS_SUCCESS);
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

static std::vector<HmacTestParams> hmac_test_cases()
{
    return {
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
}

static std::vector<uint8_t> test_message_bytes(uint8_t seed, size_t len)
{
    std::vector<uint8_t> msg(len);
    for (size_t i = 0; i < len; ++i)
    {
        msg[i] = static_cast<uint8_t>(seed + static_cast<uint8_t>(i));
    }
    return msg;
}

static uint32_t expected_hmac_tag_len(azihsm_key_kind key_kind)
{
    switch (key_kind)
    {
    case AZIHSM_KEY_KIND_HMAC_SHA256:
        return 32;
    case AZIHSM_KEY_KIND_HMAC_SHA384:
        return 48;
    case AZIHSM_KEY_KIND_HMAC_SHA512:
        return 64;
    default:
        return 0;
    }
}

static std::vector<uint8_t> hmac_sign_vec(
    azihsm_handle hmac_key,
    azihsm_algo &algo,
    const std::vector<uint8_t> &data
)
{
    azihsm_buffer data_buf = {
        .ptr = const_cast<uint8_t *>(data.data()),
        .len = static_cast<uint32_t>(data.size()),
    };

    azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };

    auto size_err = azihsm_crypt_sign(&algo, hmac_key, &data_buf, &sig_buf);
    if (size_err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        ADD_FAILURE() << "azihsm_crypt_sign size query failed: " << size_err;
        return {};
    }

    if (sig_buf.len == 0)
    {
        ADD_FAILURE() << "azihsm_crypt_sign size query returned zero length";
        return {};
    }

    std::vector<uint8_t> signature(sig_buf.len);
    sig_buf.ptr = signature.data();

    auto sign_err = azihsm_crypt_sign(&algo, hmac_key, &data_buf, &sig_buf);
    if (sign_err != AZIHSM_STATUS_SUCCESS)
    {
        ADD_FAILURE() << "azihsm_crypt_sign failed: " << sign_err;
        return {};
    }

    if (sig_buf.len == 0)
    {
        ADD_FAILURE() << "azihsm_crypt_sign returned zero length";
        return {};
    }

    signature.resize(sig_buf.len);
    return signature;
}

static std::vector<uint8_t> hmac_streaming_sign_vec(
    azihsm_handle hmac_key,
    azihsm_algo &algo,
    const std::vector<uint8_t> &msg,
    const std::vector<size_t> &chunk_sizes
)
{
    if (!msg.empty() && chunk_sizes.empty())
    {
        ADD_FAILURE() << "chunk_sizes must not be empty when msg is non-empty";
        return {};
    }

    auto_ctx sign_ctx;

    auto init_err = azihsm_crypt_sign_init(&algo, hmac_key, sign_ctx.get_ptr());
    if (init_err != AZIHSM_STATUS_SUCCESS)
    {
        ADD_FAILURE() << "azihsm_crypt_sign_init failed: " << init_err;
        return {};
    }

    size_t offset = 0;
    size_t chunk_index = 0;

    while (offset < msg.size())
    {
        const size_t requested_chunk_size = chunk_sizes[chunk_index++ % chunk_sizes.size()];
        if (requested_chunk_size == 0)
        {
            ADD_FAILURE() << "chunk_sizes must not contain zero-length chunks";
            return {};
        }
        const size_t end = std::min(offset + requested_chunk_size, msg.size());

        azihsm_buffer chunk_buf = {
            .ptr = const_cast<uint8_t *>(msg.data() + offset),
            .len = static_cast<uint32_t>(end - offset),
        };

        auto update_err = azihsm_crypt_sign_update(sign_ctx, &chunk_buf);
        if (update_err != AZIHSM_STATUS_SUCCESS)
        {
            ADD_FAILURE() << "azihsm_crypt_sign_update failed: " << update_err;
            return {};
        }

        offset = end;
    }

    azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };

    auto size_err = azihsm_crypt_sign_finish(sign_ctx, &sig_buf);
    if (size_err != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        ADD_FAILURE() << "azihsm_crypt_sign_finish size query failed: " << size_err;
        return {};
    }

    if (sig_buf.len == 0)
    {
        ADD_FAILURE() << "azihsm_crypt_sign_finish size query returned zero length";
        return {};
    }

    std::vector<uint8_t> signature(sig_buf.len);
    sig_buf.ptr = signature.data();

    auto finish_err = azihsm_crypt_sign_finish(sign_ctx, &sig_buf);
    if (finish_err != AZIHSM_STATUS_SUCCESS)
    {
        ADD_FAILURE() << "azihsm_crypt_sign_finish failed: " << finish_err;
        return {};
    }

    if (sig_buf.len == 0)
    {
        ADD_FAILURE() << "azihsm_crypt_sign_finish returned zero length";
        return {};
    }

    signature.resize(sig_buf.len);
    return signature;
}

static azihsm_status hmac_streaming_verify(
    azihsm_handle hmac_key,
    azihsm_algo &algo,
    const std::vector<uint8_t> &msg,
    const std::vector<size_t> &chunk_sizes,
    const std::vector<uint8_t> &tag
)
{
    if (!msg.empty() && chunk_sizes.empty())
    {
        ADD_FAILURE() << "chunk_sizes must not be empty when msg is non-empty";
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    auto_ctx verify_ctx;

    auto init_err = azihsm_crypt_verify_init(&algo, hmac_key, verify_ctx.get_ptr());
    if (init_err != AZIHSM_STATUS_SUCCESS)
    {
        ADD_FAILURE() << "azihsm_crypt_verify_init failed: " << init_err;
        return init_err;
    }

    size_t offset = 0;
    size_t chunk_index = 0;

    while (offset < msg.size())
    {
        const size_t requested_chunk_size = chunk_sizes[chunk_index++ % chunk_sizes.size()];
        if (requested_chunk_size == 0)
        {
            ADD_FAILURE() << "chunk_sizes must not contain zero-length chunks";
            return AZIHSM_STATUS_INVALID_ARGUMENT;
        }
        const size_t end = std::min(offset + requested_chunk_size, msg.size());

        azihsm_buffer chunk_buf = {
            .ptr = const_cast<uint8_t *>(msg.data() + offset),
            .len = static_cast<uint32_t>(end - offset),
        };

        auto update_err = azihsm_crypt_verify_update(verify_ctx, &chunk_buf);
        if (update_err != AZIHSM_STATUS_SUCCESS)
        {
            ADD_FAILURE() << "azihsm_crypt_verify_update failed: " << update_err;
            return update_err;
        }

        offset = end;
    }

    azihsm_buffer sig_buf = {
        .ptr = const_cast<uint8_t *>(tag.data()),
        .len = static_cast<uint32_t>(tag.size()),
    };

    return azihsm_crypt_verify_finish(verify_ctx, &sig_buf);
}

TEST_F(azihsm_hmac_sign_verify, sign_verify_hmac_all_algorithms)
{
    for (const auto &test_case : hmac_test_cases())
    {
        SCOPED_TRACE("Testing HMAC with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
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
    for (const auto &test_case : hmac_test_cases())
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
            const std::vector<const char *> chunks = {
                "Hello, ",
                "HMAC streaming ",
                "authentication!",
            };

            azihsm_algo algo = {
                .id = test_case.algo_id,
                .params = nullptr,
                .len = 0,
            };

            test_streaming_hmac_sign_verify(hmac_key.get(), algo, chunks);
        });
    }
}

// Verifies that HMAC verification rejects a modified signature.
TEST_F(azihsm_hmac_sign_verify, verify_rejects_tampered_hmac_signature)
{
    for (const auto &test_case : hmac_test_cases())
    {
        SCOPED_TRACE("Testing tampered HMAC signature with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            EcdhKeyPairSet key_pairs;
            auto_key hmac_key;

            ASSERT_EQ(
                generate_ecdh_keys_and_derive_hmac(
                    session,
                    test_case.key_kind,
                    key_pairs,
                    hmac_key.handle,
                    test_case.curve
                ),
                AZIHSM_STATUS_SUCCESS
            );

            std::string message =
                std::string("Message authenticated with HMAC-") + test_case.test_name;
            std::vector<uint8_t> data(message.begin(), message.end());

            azihsm_buffer data_buf = {
                .ptr = data.data(),
                .len = static_cast<uint32_t>(data.size()),
            };

            azihsm_algo algo = {
                .id = test_case.algo_id,
                .params = nullptr,
                .len = 0,
            };

            auto signature = hmac_sign_vec(hmac_key.get(), algo, data);
            ASSERT_FALSE(signature.empty());

            signature[0] ^= 0x01;

            azihsm_buffer sig_buf = {
                .ptr = signature.data(),
                .len = static_cast<uint32_t>(signature.size()),
            };

            ASSERT_NE(
                azihsm_crypt_verify(&algo, hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_SUCCESS
            );
        });
    }
}

// Verifies that HMAC verification fails when the original signed message is modified.
TEST_F(azihsm_hmac_sign_verify, verify_rejects_tampered_hmac_data)
{
    for (const auto &test_case : hmac_test_cases())
    {
        SCOPED_TRACE("Testing tampered HMAC data with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            EcdhKeyPairSet key_pairs;
            auto_key hmac_key;

            ASSERT_EQ(
                generate_ecdh_keys_and_derive_hmac(
                    session,
                    test_case.key_kind,
                    key_pairs,
                    hmac_key.handle,
                    test_case.curve
                ),
                AZIHSM_STATUS_SUCCESS
            );

            std::string message = std::string("Original HMAC message for ") + test_case.test_name;
            std::vector<uint8_t> data(message.begin(), message.end());

            azihsm_buffer data_buf = {
                .ptr = data.data(),
                .len = static_cast<uint32_t>(data.size()),
            };

            azihsm_algo algo = { .id = test_case.algo_id, .params = nullptr, .len = 0 };

            azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };
            ASSERT_EQ(
                azihsm_crypt_sign(&algo, hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_BUFFER_TOO_SMALL
            );
            ASSERT_GT(sig_buf.len, 0u);

            std::vector<uint8_t> signature(sig_buf.len);
            sig_buf.ptr = signature.data();
            ASSERT_EQ(
                azihsm_crypt_sign(&algo, hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_SUCCESS
            );

            data[0] ^= 0x01;

            azihsm_buffer tampered_data_buf = {
                .ptr = data.data(),
                .len = static_cast<uint32_t>(data.size()),
            };

            ASSERT_EQ(
                azihsm_crypt_verify(&algo, hmac_key.get(), &tampered_data_buf, &sig_buf),
                AZIHSM_STATUS_INVALID_SIGNATURE
            );
        });
    }
}

// Verifies that an HMAC tag generated with one derived key cannot be verified with another derived
// key.
TEST_F(azihsm_hmac_sign_verify, verify_rejects_signature_from_different_hmac_key)
{
    for (const auto &test_case : hmac_test_cases())
    {
        SCOPED_TRACE("Testing HMAC wrong-key rejection with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            EcdhKeyPairSet signing_key_pairs;
            EcdhKeyPairSet verifying_key_pairs;
            auto_key signing_hmac_key;
            auto_key verifying_hmac_key;

            ASSERT_EQ(
                generate_ecdh_keys_and_derive_hmac(
                    session,
                    test_case.key_kind,
                    signing_key_pairs,
                    signing_hmac_key.handle,
                    test_case.curve
                ),
                AZIHSM_STATUS_SUCCESS
            );

            ASSERT_EQ(
                generate_ecdh_keys_and_derive_hmac(
                    session,
                    test_case.key_kind,
                    verifying_key_pairs,
                    verifying_hmac_key.handle,
                    test_case.curve
                ),
                AZIHSM_STATUS_SUCCESS
            );

            std::string message =
                std::string("HMAC wrong-key verification test for ") + test_case.test_name;
            std::vector<uint8_t> data(message.begin(), message.end());

            azihsm_buffer data_buf = {
                .ptr = data.data(),
                .len = static_cast<uint32_t>(data.size()),
            };

            azihsm_algo algo = { .id = test_case.algo_id, .params = nullptr, .len = 0 };

            azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };
            ASSERT_EQ(
                azihsm_crypt_sign(&algo, signing_hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_BUFFER_TOO_SMALL
            );
            ASSERT_GT(sig_buf.len, 0u);

            std::vector<uint8_t> signature(sig_buf.len);
            sig_buf.ptr = signature.data();
            ASSERT_EQ(
                azihsm_crypt_sign(&algo, signing_hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_SUCCESS
            );

            ASSERT_EQ(
                azihsm_crypt_verify(&algo, verifying_hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_INVALID_SIGNATURE
            );
        });
    }
}

// Verifies that HMAC supports empty messages in single-shot mode.
TEST_F(azihsm_hmac_sign_verify, sign_verify_empty_hmac_message)
{
    for (const auto &test_case : hmac_test_cases())
    {
        SCOPED_TRACE("Testing empty HMAC message with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            EcdhKeyPairSet key_pairs;
            auto_key hmac_key;

            ASSERT_EQ(
                generate_ecdh_keys_and_derive_hmac(
                    session,
                    test_case.key_kind,
                    key_pairs,
                    hmac_key.handle,
                    test_case.curve
                ),
                AZIHSM_STATUS_SUCCESS
            );

            std::vector<uint8_t> empty_data;

            azihsm_algo algo = {
                .id = test_case.algo_id,
                .params = nullptr,
                .len = 0,
            };

            test_single_shot_hmac_sign_verify(hmac_key.get(), algo, empty_data);
        });
    }
}

// Verifies that streaming HMAC supports zero update calls before finish.
TEST_F(azihsm_hmac_sign_verify, streaming_sign_verify_empty_hmac_message)
{
    for (const auto &test_case : hmac_test_cases())
    {
        SCOPED_TRACE(
            "Testing empty streaming HMAC message with " + std::string(test_case.test_name)
        );

        part_list_.for_each_session([&](azihsm_handle session) {
            EcdhKeyPairSet key_pairs;
            auto_key hmac_key;

            ASSERT_EQ(
                generate_ecdh_keys_and_derive_hmac(
                    session,
                    test_case.key_kind,
                    key_pairs,
                    hmac_key.handle,
                    test_case.curve
                ),
                AZIHSM_STATUS_SUCCESS
            );

            azihsm_algo algo = {
                .id = test_case.algo_id,
                .params = nullptr,
                .len = 0,
            };

            const std::vector<const char *> empty_chunks = {};
            test_streaming_hmac_sign_verify(hmac_key.get(), algo, empty_chunks);
        });
    }
}

// Verifies that verify rejects a truncated HMAC signature.
TEST_F(azihsm_hmac_sign_verify, verify_rejects_truncated_hmac_signature)
{
    for (const auto &test_case : hmac_test_cases())
    {
        SCOPED_TRACE("Testing truncated HMAC signature with " + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            EcdhKeyPairSet key_pairs;
            auto_key hmac_key;

            ASSERT_EQ(
                generate_ecdh_keys_and_derive_hmac(
                    session,
                    test_case.key_kind,
                    key_pairs,
                    hmac_key.handle,
                    test_case.curve
                ),
                AZIHSM_STATUS_SUCCESS
            );

            std::string message =
                std::string("HMAC truncated signature test for ") + test_case.test_name;
            std::vector<uint8_t> data(message.begin(), message.end());

            azihsm_buffer data_buf = {
                .ptr = data.data(),
                .len = static_cast<uint32_t>(data.size()),
            };

            azihsm_algo algo = {
                .id = test_case.algo_id,
                .params = nullptr,
                .len = 0,
            };

            azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };
            ASSERT_EQ(
                azihsm_crypt_sign(&algo, hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_BUFFER_TOO_SMALL
            );
            ASSERT_GT(sig_buf.len, 0u);

            std::vector<uint8_t> signature(sig_buf.len);
            sig_buf.ptr = signature.data();
            ASSERT_EQ(
                azihsm_crypt_sign(&algo, hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_SUCCESS
            );

            ASSERT_GT(sig_buf.len, 1);
            sig_buf.len -= 1;

            ASSERT_EQ(
                azihsm_crypt_verify(&algo, hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_INVALID_SIGNATURE
            );
        });
    }
}

// Ensures streaming tag generation matches single-shot for the same key and message.
TEST_F(azihsm_hmac_sign_verify, streaming_matches_single_shot_all_algorithms)
{
    for (const auto &test_case : hmac_test_cases())
    {
        SCOPED_TRACE("Streaming matches single-shot with HMAC-" + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            EcdhKeyPairSet key_pairs;
            auto_key hmac_key;

            ASSERT_EQ(
                generate_ecdh_keys_and_derive_hmac(
                    session,
                    test_case.key_kind,
                    key_pairs,
                    hmac_key.handle,
                    test_case.curve
                ),
                AZIHSM_STATUS_SUCCESS
            );

            azihsm_algo algo = { .id = test_case.algo_id, .params = nullptr, .len = 0 };
            auto msg = test_message_bytes(0x5a, 1000);

            auto single_shot_tag = hmac_sign_vec(hmac_key.get(), algo, msg);
            auto streaming_tag =
                hmac_streaming_sign_vec(hmac_key.get(), algo, msg, { 1, 7, 64, 13, 128, 3 });

            ASSERT_EQ(single_shot_tag, streaming_tag);

            ASSERT_EQ(
                hmac_streaming_verify(hmac_key.get(), algo, msg, { 32, 5, 900 }, streaming_tag),
                AZIHSM_STATUS_SUCCESS
            );
        });
    }
}

// Ensures verification fails for truncated or extended tags.
TEST_F(azihsm_hmac_sign_verify, verify_fails_for_wrong_tag_length_all_algorithms)
{
    for (const auto &test_case : hmac_test_cases())
    {
        SCOPED_TRACE("Wrong tag length with HMAC-" + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            EcdhKeyPairSet key_pairs;
            auto_key hmac_key;

            ASSERT_EQ(
                generate_ecdh_keys_and_derive_hmac(
                    session,
                    test_case.key_kind,
                    key_pairs,
                    hmac_key.handle,
                    test_case.curve
                ),
                AZIHSM_STATUS_SUCCESS
            );

            azihsm_algo algo = { .id = test_case.algo_id, .params = nullptr, .len = 0 };
            auto data = test_message_bytes(0x77, 96);
            auto tag = hmac_sign_vec(hmac_key.get(), algo, data);

            ASSERT_GE(tag.size(), 2u);

            auto truncated = tag;
            truncated.pop_back();

            auto extended = tag;
            extended.push_back(0);

            azihsm_buffer data_buf = {
                .ptr = data.data(),
                .len = static_cast<uint32_t>(data.size()),
            };

            azihsm_buffer truncated_buf = {
                .ptr = truncated.data(),
                .len = static_cast<uint32_t>(truncated.size()),
            };

            azihsm_buffer extended_buf = {
                .ptr = extended.data(),
                .len = static_cast<uint32_t>(extended.size()),
            };

            ASSERT_EQ(
                azihsm_crypt_verify(&algo, hmac_key.get(), &data_buf, &truncated_buf),
                AZIHSM_STATUS_INVALID_SIGNATURE
            );

            ASSERT_EQ(
                azihsm_crypt_verify(&algo, hmac_key.get(), &data_buf, &extended_buf),
                AZIHSM_STATUS_INVALID_SIGNATURE
            );
        });
    }
}

// Ensures verification fails when the tag is empty.
TEST_F(azihsm_hmac_sign_verify, verify_fails_with_empty_tag)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> data = { 't', 'e', 's', 't' };
        std::vector<uint8_t> empty_tag;

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };

        azihsm_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        azihsm_buffer tag_buf = {
            .ptr = empty_tag.data(),
            .len = 0,
        };

        ASSERT_NE(
            azihsm_crypt_verify(&algo, hmac_key.get(), &data_buf, &tag_buf),
            AZIHSM_STATUS_SUCCESS
        );
    });
}

// Ensures HMAC output is deterministic for the same key and message.
TEST_F(azihsm_hmac_sign_verify, deterministic_output)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };
        auto data = test_message_bytes(0x42, 128);

        auto tag1 = hmac_sign_vec(hmac_key.get(), algo, data);
        auto tag2 = hmac_sign_vec(hmac_key.get(), algo, data);

        ASSERT_EQ(tag1, tag2);
    });
}

// Ensures HMAC tag length matches the selected hash algorithm.
TEST_F(azihsm_hmac_sign_verify, tag_length_matches_hash_algorithm)
{
    for (const auto &test_case : hmac_test_cases())
    {
        SCOPED_TRACE("Tag length with HMAC-" + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            EcdhKeyPairSet key_pairs;
            auto_key hmac_key;

            ASSERT_EQ(
                generate_ecdh_keys_and_derive_hmac(
                    session,
                    test_case.key_kind,
                    key_pairs,
                    hmac_key.handle,
                    test_case.curve
                ),
                AZIHSM_STATUS_SUCCESS
            );

            azihsm_algo algo = { .id = test_case.algo_id, .params = nullptr, .len = 0 };
            std::vector<uint8_t> data = { 'm', 's', 'g' };

            auto tag = hmac_sign_vec(hmac_key.get(), algo, data);

            ASSERT_EQ(tag.size(), expected_hmac_tag_len(test_case.key_kind));
        });
    }
}

// Ensures streaming works at the exact 1024-byte device limit.
TEST_F(azihsm_hmac_sign_verify, streaming_exact_limit_succeeds)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };
        auto msg = test_message_bytes(0x00, 1024);

        auto tag = hmac_streaming_sign_vec(hmac_key.get(), algo, msg, { 256, 256, 512 });

        ASSERT_EQ(
            hmac_streaming_verify(hmac_key.get(), algo, msg, { 128, 512, 384 }, tag),
            AZIHSM_STATUS_SUCCESS
        );
    });
}

// Ensures streaming update rejects input larger than the device limit.
TEST_F(azihsm_hmac_sign_verify, streaming_update_rejects_oversize_message)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };

        auto_ctx sign_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&algo, hmac_key.get(), sign_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        auto oversize = test_message_bytes(0x55, 1025);
        azihsm_buffer oversize_buf = {
            .ptr = oversize.data(),
            .len = static_cast<uint32_t>(oversize.size()),
        };

        ASSERT_EQ(
            azihsm_crypt_sign_update(sign_ctx, &oversize_buf),
            AZIHSM_STATUS_INDEX_OUT_OF_RANGE
        );
    });
}

// Ensures zero-length streaming update is treated as a no-op.
TEST_F(azihsm_hmac_sign_verify, streaming_zero_length_update_succeeds)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };

        auto_ctx sign_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&algo, hmac_key.get(), sign_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer empty_buf = { .ptr = nullptr, .len = 0 };
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &empty_buf), AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> msg = { 'z', 'e', 'r', 'o' };
        azihsm_buffer msg_buf = {
            .ptr = msg.data(),
            .len = static_cast<uint32_t>(msg.size()),
        };
        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };
        ASSERT_EQ(azihsm_crypt_sign_finish(sign_ctx, &sig_buf), AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(sig_buf.len, 0u);

        std::vector<uint8_t> tag(sig_buf.len);
        sig_buf.ptr = tag.data();
        ASSERT_EQ(azihsm_crypt_sign_finish(sign_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(
            azihsm_crypt_verify(&algo, hmac_key.get(), &msg_buf, &sig_buf),
            AZIHSM_STATUS_SUCCESS
        );
    });
}

// Ensures sign streaming context rejects update and finish after finish.
TEST_F(azihsm_hmac_sign_verify, streaming_sign_update_after_finish_fails)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };

        auto_ctx sign_ctx;
        ASSERT_EQ(
            azihsm_crypt_sign_init(&algo, hmac_key.get(), sign_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        std::vector<uint8_t> msg = { 't', 'e', 's', 't' };
        azihsm_buffer msg_buf = {
            .ptr = msg.data(),
            .len = static_cast<uint32_t>(msg.size()),
        };

        ASSERT_EQ(azihsm_crypt_sign_update(sign_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };
        ASSERT_EQ(azihsm_crypt_sign_finish(sign_ctx, &sig_buf), AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(sig_buf.len, 0u);

        std::vector<uint8_t> tag(sig_buf.len);
        sig_buf.ptr = tag.data();
        ASSERT_EQ(azihsm_crypt_sign_finish(sign_ctx, &sig_buf), AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(
            azihsm_crypt_sign_update(sign_ctx, &msg_buf),
            AZIHSM_STATUS_INVALID_CONTEXT_STATE
        );

        ASSERT_EQ(
            azihsm_crypt_sign_finish(sign_ctx, &sig_buf),
            AZIHSM_STATUS_INVALID_CONTEXT_STATE
        );
    });
}

// Ensures verify streaming context rejects update and finish after finish.
TEST_F(azihsm_hmac_sign_verify, streaming_verify_update_after_finish_fails)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };

        std::vector<uint8_t> msg = { 't', 'e', 's', 't' };
        auto tag = hmac_sign_vec(hmac_key.get(), algo, msg);

        auto_ctx verify_ctx;
        ASSERT_EQ(
            azihsm_crypt_verify_init(&algo, hmac_key.get(), verify_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer msg_buf = {
            .ptr = msg.data(),
            .len = static_cast<uint32_t>(msg.size()),
        };

        azihsm_buffer tag_buf = {
            .ptr = tag.data(),
            .len = static_cast<uint32_t>(tag.size()),
        };

        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(azihsm_crypt_verify_finish(verify_ctx, &tag_buf), AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(
            azihsm_crypt_verify_update(verify_ctx, &msg_buf),
            AZIHSM_STATUS_INVALID_CONTEXT_STATE
        );

        ASSERT_EQ(
            azihsm_crypt_verify_finish(verify_ctx, &tag_buf),
            AZIHSM_STATUS_INVALID_CONTEXT_STATE
        );
    });
}

// Ensures chunking does not affect streaming output.
TEST_F(azihsm_hmac_sign_verify, streaming_chunking_independence)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };
        auto msg = test_message_bytes(0x33, 512);

        auto tag1 = hmac_streaming_sign_vec(hmac_key.get(), algo, msg, { 512 });
        auto tag2 = hmac_streaming_sign_vec(hmac_key.get(), algo, msg, { 1 });
        auto tag3 = hmac_streaming_sign_vec(hmac_key.get(), algo, msg, { 13, 7, 64, 3, 99 });

        ASSERT_EQ(tag1, tag2);
        ASSERT_EQ(tag1, tag3);

        ASSERT_EQ(
            hmac_streaming_verify(hmac_key.get(), algo, msg, { 128, 128, 256 }, tag1),
            AZIHSM_STATUS_SUCCESS
        );
    });
}

// Ensures streaming verification rejects extra data appended after the valid message.
TEST_F(azihsm_hmac_sign_verify, streaming_verify_rejects_extra_data_after_valid_update)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };

        std::vector<uint8_t> msg = { 'm', 'e', 's', 's', 'a', 'g', 'e' };
        auto tag = hmac_streaming_sign_vec(hmac_key.get(), algo, msg, { msg.size() });

        auto_ctx verify_ctx;
        ASSERT_EQ(
            azihsm_crypt_verify_init(&algo, hmac_key.get(), verify_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer msg_buf = {
            .ptr = msg.data(),
            .len = static_cast<uint32_t>(msg.size()),
        };

        std::vector<uint8_t> extra = { 'e', 'x', 't', 'r', 'a' };
        azihsm_buffer extra_buf = {
            .ptr = extra.data(),
            .len = static_cast<uint32_t>(extra.size()),
        };

        azihsm_buffer tag_buf = {
            .ptr = tag.data(),
            .len = static_cast<uint32_t>(tag.size()),
        };

        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &extra_buf), AZIHSM_STATUS_SUCCESS);

        ASSERT_NE(azihsm_crypt_verify_finish(verify_ctx, &tag_buf), AZIHSM_STATUS_SUCCESS);
    });
}

// Ensures single-shot HMAC rejects input larger than the device limit.
TEST_F(azihsm_hmac_sign_verify, single_shot_large_input_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };
        auto data = test_message_bytes(0x55, 1025);

        azihsm_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        std::vector<uint8_t> signature(expected_hmac_tag_len(AZIHSM_KEY_KIND_HMAC_SHA256));
        azihsm_buffer sig_buf = {
            .ptr = signature.data(),
            .len = static_cast<uint32_t>(signature.size()),
        };

        ASSERT_EQ(
            azihsm_crypt_sign(&algo, hmac_key.get(), &data_buf, &sig_buf),
            AZIHSM_STATUS_INDEX_OUT_OF_RANGE
        );
    });
}

// Ensures single-shot verify rejects input larger than the device limit.
TEST_F(azihsm_hmac_sign_verify, single_shot_verify_large_input_rejected)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };

        auto valid_data = test_message_bytes(0x22, 128);
        auto tag = hmac_sign_vec(hmac_key.get(), algo, valid_data);

        auto oversized_data = test_message_bytes(0x33, 1025);

        azihsm_buffer data_buf = {
            .ptr = oversized_data.data(),
            .len = static_cast<uint32_t>(oversized_data.size()),
        };

        azihsm_buffer tag_buf = {
            .ptr = tag.data(),
            .len = static_cast<uint32_t>(tag.size()),
        };

        ASSERT_EQ(
            azihsm_crypt_verify(&algo, hmac_key.get(), &data_buf, &tag_buf),
            AZIHSM_STATUS_INDEX_OUT_OF_RANGE
        );
    });
}

// Ensures streaming verify update rejects input larger than the device limit.
TEST_F(azihsm_hmac_sign_verify, streaming_verify_update_rejects_oversize_message)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };

        auto_ctx verify_ctx;
        ASSERT_EQ(
            azihsm_crypt_verify_init(&algo, hmac_key.get(), verify_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        auto oversized = test_message_bytes(0x44, 1025);
        azihsm_buffer oversized_buf = {
            .ptr = oversized.data(),
            .len = static_cast<uint32_t>(oversized.size()),
        };

        ASSERT_EQ(
            azihsm_crypt_verify_update(verify_ctx, &oversized_buf),
            AZIHSM_STATUS_INDEX_OUT_OF_RANGE
        );
    });
}

// Ensures zero-length streaming verify update is treated as a no-op.
TEST_F(azihsm_hmac_sign_verify, streaming_verify_zero_length_update_succeeds)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };

        std::vector<uint8_t> msg = { 'z', 'e', 'r', 'o' };
        auto tag = hmac_sign_vec(hmac_key.get(), algo, msg);

        auto_ctx verify_ctx;
        ASSERT_EQ(
            azihsm_crypt_verify_init(&algo, hmac_key.get(), verify_ctx.get_ptr()),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_buffer empty_buf = { .ptr = nullptr, .len = 0 };
        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &empty_buf), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer msg_buf = {
            .ptr = msg.data(),
            .len = static_cast<uint32_t>(msg.size()),
        };

        ASSERT_EQ(azihsm_crypt_verify_update(verify_ctx, &msg_buf), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer tag_buf = {
            .ptr = tag.data(),
            .len = static_cast<uint32_t>(tag.size()),
        };

        ASSERT_EQ(azihsm_crypt_verify_finish(verify_ctx, &tag_buf), AZIHSM_STATUS_SUCCESS);
    });
}

// Ensures single-shot sign fails when caller-provided signature buffer is too small.
TEST_F(azihsm_hmac_sign_verify, single_shot_sign_rejects_too_small_output_buffer)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };
        auto data = test_message_bytes(0x11, 64);

        azihsm_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        std::vector<uint8_t> too_small(expected_hmac_tag_len(AZIHSM_KEY_KIND_HMAC_SHA256) - 1);

        azihsm_buffer sig_buf = {
            .ptr = too_small.data(),
            .len = static_cast<uint32_t>(too_small.size()),
        };

        ASSERT_EQ(
            azihsm_crypt_sign(&algo, hmac_key.get(), &data_buf, &sig_buf),
            AZIHSM_STATUS_BUFFER_TOO_SMALL
        );

        ASSERT_EQ(sig_buf.len, expected_hmac_tag_len(AZIHSM_KEY_KIND_HMAC_SHA256));
    });
}

// Ensures single-shot sign succeeds when caller provides an exact-size output buffer.
TEST_F(azihsm_hmac_sign_verify, single_shot_sign_exact_output_buffer_succeeds)
{
    for (const auto &test_case : hmac_test_cases())
    {
        SCOPED_TRACE("Exact output buffer with HMAC-" + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
            EcdhKeyPairSet key_pairs;
            auto_key hmac_key;

            ASSERT_EQ(
                generate_ecdh_keys_and_derive_hmac(
                    session,
                    test_case.key_kind,
                    key_pairs,
                    hmac_key.handle,
                    test_case.curve
                ),
                AZIHSM_STATUS_SUCCESS
            );

            azihsm_algo algo = { .id = test_case.algo_id, .params = nullptr, .len = 0 };
            auto data = test_message_bytes(0x99, 64);

            azihsm_buffer data_buf = {
                .ptr = data.data(),
                .len = static_cast<uint32_t>(data.size()),
            };

            std::vector<uint8_t> tag(expected_hmac_tag_len(test_case.key_kind));

            azihsm_buffer sig_buf = {
                .ptr = tag.data(),
                .len = static_cast<uint32_t>(tag.size()),
            };

            ASSERT_EQ(
                azihsm_crypt_sign(&algo, hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_SUCCESS
            );

            ASSERT_EQ(sig_buf.len, expected_hmac_tag_len(test_case.key_kind));

            ASSERT_EQ(
                azihsm_crypt_verify(&algo, hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_SUCCESS
            );
        });
    }
}

// HMAC key kind controls output length,
// even when the requested HMAC algorithm does not match the key kind.
TEST_F(azihsm_hmac_sign_verify, sign_with_sha256_hmac_key_and_sha512_algo_produces_sha256_tag)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_sha256_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_sha256_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo sha512_algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA512, .params = nullptr, .len = 0 };

        auto data = test_message_bytes(0x12, 64);

        azihsm_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        azihsm_buffer sig_buf = { .ptr = nullptr, .len = 0 };

        ASSERT_EQ(
            azihsm_crypt_sign(&sha512_algo, hmac_sha256_key.get(), &data_buf, &sig_buf),
            AZIHSM_STATUS_BUFFER_TOO_SMALL
        );

        ASSERT_EQ(sig_buf.len, expected_hmac_tag_len(AZIHSM_KEY_KIND_HMAC_SHA256));

        std::vector<uint8_t> signature(sig_buf.len);
        sig_buf.ptr = signature.data();

        ASSERT_EQ(
            azihsm_crypt_sign(&sha512_algo, hmac_sha256_key.get(), &data_buf, &sig_buf),
            AZIHSM_STATUS_SUCCESS
        );

        ASSERT_EQ(sig_buf.len, expected_hmac_tag_len(AZIHSM_KEY_KIND_HMAC_SHA256));

        ASSERT_EQ(
            azihsm_crypt_verify(&sha512_algo, hmac_sha256_key.get(), &data_buf, &sig_buf),
            AZIHSM_STATUS_SUCCESS
        );
    });
}

// verify succeeds with a mismatched HMAC algo when the tag was produced with the same key and
// message.
TEST_F(azihsm_hmac_sign_verify, verify_with_sha256_hmac_key_and_sha512_algo_accepts_sha256_tag)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_sha256_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_sha256_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo sha256_algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };

        azihsm_algo sha512_algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA512, .params = nullptr, .len = 0 };

        auto data = test_message_bytes(0x23, 64);
        auto sha256_tag = hmac_sign_vec(hmac_sha256_key.get(), sha256_algo, data);

        ASSERT_EQ(sha256_tag.size(), expected_hmac_tag_len(AZIHSM_KEY_KIND_HMAC_SHA256));

        azihsm_buffer data_buf = {
            .ptr = data.data(),
            .len = static_cast<uint32_t>(data.size()),
        };

        azihsm_buffer tag_buf = {
            .ptr = sha256_tag.data(),
            .len = static_cast<uint32_t>(sha256_tag.size()),
        };

        ASSERT_EQ(
            azihsm_crypt_verify(&sha512_algo, hmac_sha256_key.get(), &data_buf, &tag_buf),
            AZIHSM_STATUS_SUCCESS
        );
    });
}

// Ensures streaming verify rejects a tampered tag.
TEST_F(azihsm_hmac_sign_verify, streaming_verify_rejects_tampered_tag)
{
    part_list_.for_each_session([&](azihsm_handle session) {
        EcdhKeyPairSet key_pairs;
        auto_key hmac_key;

        ASSERT_EQ(
            generate_ecdh_keys_and_derive_hmac(
                session,
                AZIHSM_KEY_KIND_HMAC_SHA256,
                key_pairs,
                hmac_key.handle,
                AZIHSM_ECC_CURVE_P256
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo algo = { .id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0 };

        auto msg = test_message_bytes(0x66, 256);
        auto tag = hmac_streaming_sign_vec(hmac_key.get(), algo, msg, { 64, 64, 64, 64 });

        ASSERT_FALSE(tag.empty());
        tag[0] ^= 0x01;

        ASSERT_NE(
            hmac_streaming_verify(hmac_key.get(), algo, msg, { 32, 17, 99 }, tag),
            AZIHSM_STATUS_SUCCESS
        );
    });
}

// Verifies that single-shot HMAC supports a null message pointer when message length is zero.
TEST_F(azihsm_hmac_sign_verify, sign_verify_null_ptr_empty_hmac_message)
{
    for (const auto &test_case : hmac_test_cases())
    {
        SCOPED_TRACE(
            "Testing null pointer empty HMAC message with " + std::string(test_case.test_name)
        );

        part_list_.for_each_session([&](azihsm_handle session) {
            EcdhKeyPairSet key_pairs;
            auto_key hmac_key;

            ASSERT_EQ(
                generate_ecdh_keys_and_derive_hmac(
                    session,
                    test_case.key_kind,
                    key_pairs,
                    hmac_key.handle,
                    test_case.curve
                ),
                AZIHSM_STATUS_SUCCESS
            );

            azihsm_algo algo = {
                .id = test_case.algo_id,
                .params = nullptr,
                .len = 0,
            };

            azihsm_buffer data_buf = {
                .ptr = nullptr,
                .len = 0,
            };

            azihsm_buffer sig_buf = {
                .ptr = nullptr,
                .len = 0,
            };

            ASSERT_EQ(
                azihsm_crypt_sign(&algo, hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_BUFFER_TOO_SMALL
            );
            ASSERT_EQ(sig_buf.len, expected_hmac_tag_len(test_case.key_kind));

            std::vector<uint8_t> signature(sig_buf.len);
            sig_buf.ptr = signature.data();

            ASSERT_EQ(
                azihsm_crypt_sign(&algo, hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_SUCCESS
            );
            ASSERT_EQ(sig_buf.len, expected_hmac_tag_len(test_case.key_kind));

            ASSERT_EQ(
                azihsm_crypt_verify(&algo, hmac_key.get(), &data_buf, &sig_buf),
                AZIHSM_STATUS_SUCCESS
            );
        });
    }
}