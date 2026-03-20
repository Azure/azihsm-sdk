// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <algorithm>
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_key.hpp"
#include "utils/rsa_keygen.hpp"

class azihsm_ecc_keygen : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};
// ==================== lifecycle ====================

// Verifies masked-key restore lifecycle (generate->mask->unmask) preserves ECDSA sign/verify usability.
TEST_F(azihsm_ecc_keygen, masked_restore_sign_verify)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key original_private_key;
        auto_key original_public_key;
        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            original_private_key.get_ptr(),
            original_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> masked_key_data;
        err = get_masked_key_blob(original_private_key.get(), masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(masked_key_data.empty());

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_private_key;
        auto_key unmasked_public_key;
        err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_ECC,
            &masked_key_buf,
            unmasked_private_key.get_ptr(),
            unmasked_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unmasked_private_key.get(), 0);
        ASSERT_NE(unmasked_public_key.get(), 0);

        const std::vector<uint8_t> message = { 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6 };
        const auto roundtrip = run_ecdsa_sign_verify_roundtrip(
            unmasked_private_key.get(),
            unmasked_public_key.get(),
            message
        );
        ASSERT_EQ(roundtrip.status, AZIHSM_STATUS_SUCCESS)
            << "step=" << roundtrip.step << ", detail=" << roundtrip.detail
            << ", status=" << roundtrip.status;
    });
}

// Verifies wrapped-import lifecycle (RSA unwrap + ECC pair import) yields immediately usable ECDSA keys.
TEST_F(azihsm_ecc_keygen, wrapped_import_sign_verify)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> wrapped_blob;
        err = make_wrapped_ecc_pkcs8_blob(
            rsa_pub_key.get(),
            AZIHSM_ECC_CURVE_P256,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = wrapped_blob.data();
        wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        RsaAesUnwrapAlgo unwrap_algo{};

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            rsa_priv_key.get(),
            &wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key unwrapped_private_key;
        auto_key unwrapped_public_key;
        unwrapped_private_key.handle = result.private_key;
        unwrapped_public_key.handle = result.public_key;

        const std::vector<uint8_t> message = { 0x11, 0x22, 0x33, 0x44, 0x55 };
        const auto roundtrip = run_ecdsa_sign_verify_roundtrip(
            unwrapped_private_key.get(),
            unwrapped_public_key.get(),
            message
        );
        ASSERT_EQ(roundtrip.status, AZIHSM_STATUS_SUCCESS)
            << "step=" << roundtrip.step << ", detail=" << roundtrip.detail
            << ", status=" << roundtrip.status;
    });
}

// Verifies unmasked keys can be re-masked and restored again while preserving sign/verify usability.
TEST_F(azihsm_ecc_keygen, lifecycle_masked_restore_chain_sign_verify)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Step 1: Generate a baseline ECC key pair.
        auto_key original_private_key;
        auto_key original_public_key;
        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            original_private_key.get_ptr(),
            original_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Step 2: Mask and restore once.
        std::vector<uint8_t> first_masked_key_data;
        err = get_masked_key_blob(original_private_key.get(), first_masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(first_masked_key_data.empty());

        azihsm_buffer first_masked_key_buf{};
        first_masked_key_buf.ptr = first_masked_key_data.data();
        first_masked_key_buf.len = static_cast<uint32_t>(first_masked_key_data.size());

        auto_key first_unmasked_private_key;
        auto_key first_unmasked_public_key;
        err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_ECC,
            &first_masked_key_buf,
            first_unmasked_private_key.get_ptr(),
            first_unmasked_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(first_unmasked_private_key.get(), 0);
        ASSERT_NE(first_unmasked_public_key.get(), 0);

        // Step 3: Re-mask the restored private key and restore again.
        std::vector<uint8_t> second_masked_key_data;
        err = get_masked_key_blob(first_unmasked_private_key.get(), second_masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(second_masked_key_data.empty());

        azihsm_buffer second_masked_key_buf{};
        second_masked_key_buf.ptr = second_masked_key_data.data();
        second_masked_key_buf.len = static_cast<uint32_t>(second_masked_key_data.size());

        auto_key second_unmasked_private_key;
        auto_key second_unmasked_public_key;
        err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_ECC,
            &second_masked_key_buf,
            second_unmasked_private_key.get_ptr(),
            second_unmasked_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(second_unmasked_private_key.get(), 0);
        ASSERT_NE(second_unmasked_public_key.get(), 0);

        // Step 4: Confirm end-to-end sign/verify usability after the full chain.
        const std::vector<uint8_t> message = { 0x3A, 0x7C, 0x19, 0xE0, 0x55, 0x81 };
        const auto roundtrip = run_ecdsa_sign_verify_roundtrip(
            second_unmasked_private_key.get(),
            second_unmasked_public_key.get(),
            message
        );
        ASSERT_EQ(roundtrip.status, AZIHSM_STATUS_SUCCESS)
            << "step=" << roundtrip.step << ", detail=" << roundtrip.detail
            << ", status=" << roundtrip.status;
    });
}

// Verifies lifecycle verify rejects representative mismatch cases.
TEST_F(azihsm_ecc_keygen, lifecycle_verify_rejects_mismatch_cases)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Step 1: Prepare one signing pair and two mismatching verifier pairs.
        auto_key primary_private_key;
        auto_key primary_public_key;
        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            primary_private_key.get_ptr(),
            primary_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto_key wrong_curve_private_key;
        auto_key wrong_curve_public_key;
        err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P384,
            true,
            wrong_curve_private_key.get_ptr(),
            wrong_curve_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto_key wrong_pair_private_key;
        auto_key wrong_pair_public_key;
        err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            wrong_pair_private_key.get_ptr(),
            wrong_pair_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Step 2: Sign once and validate expected success path.
        const std::vector<uint8_t> message = { 0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB };
        std::vector<uint8_t> signature;
        err = ecdsa_sign_sha256(primary_private_key.get(), message, signature);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(signature.empty());

        ASSERT_EQ(ecdsa_verify_sha256(primary_public_key.get(), message, signature), AZIHSM_STATUS_SUCCESS);

        // Step 3: Validate representative mismatch rejections.
        ASSERT_NE(ecdsa_verify_sha256(wrong_pair_public_key.get(), message, signature), AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(ecdsa_verify_sha256(wrong_curve_public_key.get(), message, signature), AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> mutated_signature = signature;
        mutated_signature[0] ^= 0x01;
        ASSERT_NE(ecdsa_verify_sha256(primary_public_key.get(), message, mutated_signature), AZIHSM_STATUS_SUCCESS);
    });
}

// Verifies deleted lifecycle keys become unusable for subsequent sign/verify operations.
TEST_F(azihsm_ecc_keygen, lifecycle_rejects_use_after_delete)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Step 1: Generate a usable pair and confirm baseline sign/verify.
        auto_key private_key;
        auto_key public_key;
        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            private_key.get_ptr(),
            public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        const std::vector<uint8_t> message = { 0x10, 0x32, 0x54, 0x76, 0x98 };
        const auto baseline_roundtrip = run_ecdsa_sign_verify_roundtrip(
            private_key.get(),
            public_key.get(),
            message
        );
        ASSERT_EQ(baseline_roundtrip.status, AZIHSM_STATUS_SUCCESS)
            << "step=" << baseline_roundtrip.step << ", detail=" << baseline_roundtrip.detail
            << ", status=" << baseline_roundtrip.status;

        // Step 2: Delete private key and verify stale private handle is rejected.
        const auto deleted_private_handle = private_key.release();
        ASSERT_EQ(azihsm_key_delete(deleted_private_handle), AZIHSM_STATUS_SUCCESS);
        const auto private_deleted_roundtrip = run_ecdsa_sign_verify_roundtrip(
            deleted_private_handle,
            public_key.get(),
            message
        );
        ASSERT_EQ(private_deleted_roundtrip.status, AZIHSM_STATUS_INVALID_HANDLE)
            << "step=" << private_deleted_roundtrip.step << ", detail=" << private_deleted_roundtrip.detail
            << ", status=" << private_deleted_roundtrip.status;

        // Step 3: Delete public key and verify stale public handle is rejected.
        const auto deleted_public_handle = public_key.release();
        ASSERT_EQ(azihsm_key_delete(deleted_public_handle), AZIHSM_STATUS_SUCCESS);

        auto_key fresh_private_key;
        auto_key fresh_public_key;
        err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            fresh_private_key.get_ptr(),
            fresh_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        const auto public_deleted_roundtrip = run_ecdsa_sign_verify_roundtrip(
            fresh_private_key.get(),
            deleted_public_handle,
            message
        );
        ASSERT_EQ(public_deleted_roundtrip.status, AZIHSM_STATUS_INVALID_HANDLE)
            << "step=" << public_deleted_roundtrip.step << ", detail=" << public_deleted_roundtrip.detail
            << ", status=" << public_deleted_roundtrip.status;
    });
}

// Verifies session-reopen behavior for lifecycle keys (session keys fail, token keys survive).
TEST_F(azihsm_ecc_keygen, lifecycle_session_reopen_behavior)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        const std::vector<uint8_t> message = { 0x91, 0x73, 0x55, 0x37, 0x19 };

        azihsm_handle session_private_key = 0;
        azihsm_handle session_public_key = 0;
        auto_key token_private_key;
        auto_key token_public_key;

        // Step 1: Create session and token lifecycle keys and validate baseline usability.
        {
            SessionHandle first_session(partition.get());

            auto err = generate_ecc_keypair(
                first_session.get(),
                AZIHSM_ECC_CURVE_P256,
                true,
                &session_private_key,
                &session_public_key
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            err = generate_ecc_keypair(
                first_session.get(),
                AZIHSM_ECC_CURVE_P256,
                false,
                token_private_key.get_ptr(),
                token_public_key.get_ptr()
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            const auto session_roundtrip = run_ecdsa_sign_verify_roundtrip(
                session_private_key,
                session_public_key,
                message
            );
            ASSERT_EQ(session_roundtrip.status, AZIHSM_STATUS_SUCCESS)
                << "step=" << session_roundtrip.step << ", detail=" << session_roundtrip.detail
                << ", status=" << session_roundtrip.status;

            const auto token_roundtrip = run_ecdsa_sign_verify_roundtrip(
                token_private_key.get(),
                token_public_key.get(),
                message
            );
            ASSERT_EQ(token_roundtrip.status, AZIHSM_STATUS_SUCCESS)
                << "step=" << token_roundtrip.step << ", detail=" << token_roundtrip.detail
                << ", status=" << token_roundtrip.status;
        }

        // Step 2: Reopen session and verify session keys are stale while token keys remain usable.
        {
            SessionHandle reopened_session(partition.get());

            const auto stale_session_roundtrip = run_ecdsa_sign_verify_roundtrip(
                session_private_key,
                session_public_key,
                message
            );
            ASSERT_EQ(stale_session_roundtrip.status, AZIHSM_STATUS_INVALID_HANDLE)
                << "step=" << stale_session_roundtrip.step << ", detail=" << stale_session_roundtrip.detail
                << ", status=" << stale_session_roundtrip.status;

            const auto surviving_token_roundtrip = run_ecdsa_sign_verify_roundtrip(
                token_private_key.get(),
                token_public_key.get(),
                message
            );
            ASSERT_EQ(surviving_token_roundtrip.status, AZIHSM_STATUS_SUCCESS)
                << "step=" << surviving_token_roundtrip.step << ", detail=" << surviving_token_roundtrip.detail
                << ", status=" << surviving_token_roundtrip.status;
        }
    });
}

// Verifies lifecycle-produced key handles are rejected when used from a different session context.
TEST_F(azihsm_ecc_keygen, lifecycle_rejects_cross_session_usage)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        const std::vector<uint8_t> message = { 0x4D, 0x2E, 0x1F, 0xA0, 0xB1 };

        azihsm_handle session_private_key = 0;
        azihsm_handle session_public_key = 0;

        // Step 1: Create session-scoped lifecycle keys in one session.
        {
            SessionHandle owner_session(partition.get());
            auto err = generate_ecc_keypair(
                owner_session.get(),
                AZIHSM_ECC_CURVE_P256,
                true,
                &session_private_key,
                &session_public_key
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            const auto baseline_roundtrip = run_ecdsa_sign_verify_roundtrip(
                session_private_key,
                session_public_key,
                message
            );
            ASSERT_EQ(baseline_roundtrip.status, AZIHSM_STATUS_SUCCESS)
                << "step=" << baseline_roundtrip.step << ", detail=" << baseline_roundtrip.detail
                << ", status=" << baseline_roundtrip.status;
        }

        // Step 2: Use handles from a different session context and verify rejection.
        {
            SessionHandle other_session(partition.get());

            const auto cross_session_roundtrip = run_ecdsa_sign_verify_roundtrip(
                session_private_key,
                session_public_key,
                message
            );
            ASSERT_EQ(cross_session_roundtrip.status, AZIHSM_STATUS_INVALID_HANDLE)
                << "step=" << cross_session_roundtrip.step << ", detail=" << cross_session_roundtrip.detail
                << ", status=" << cross_session_roundtrip.status;
        }
    });
}

// Verifies lifecycle-produced key handles are rejected when used across partition boundaries.
TEST_F(azihsm_ecc_keygen, lifecycle_rejects_cross_partition_usage)
{
    if (part_list_.count() < 2u)
    {
        GTEST_SKIP() << "requires at least two partitions for cross-partition lifecycle semantics";
    }

    auto source_path = part_list_.get_path(0);
    auto other_path = part_list_.get_path(1);

    auto source_partition = PartitionHandle(source_path);
    auto other_partition = PartitionHandle(other_path);

    const std::vector<uint8_t> message = { 0xC0, 0xDE, 0x12, 0x34, 0x56 };

    auto_key token_private_key;
    auto_key token_public_key;

    // Step 1: Create token lifecycle keys in one partition and validate baseline usability.
    {
        SessionHandle source_session(source_partition.get());
        auto err = generate_ecc_keypair(
            source_session.get(),
            AZIHSM_ECC_CURVE_P256,
            false,
            token_private_key.get_ptr(),
            token_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        const auto baseline_roundtrip = run_ecdsa_sign_verify_roundtrip(
            token_private_key.get(),
            token_public_key.get(),
            message
        );
        ASSERT_EQ(baseline_roundtrip.status, AZIHSM_STATUS_SUCCESS)
            << "step=" << baseline_roundtrip.step << ", detail=" << baseline_roundtrip.detail
            << ", status=" << baseline_roundtrip.status;
    }

    // Step 2: Use handles with another partition context and verify rejection.
    {
        SessionHandle other_session(other_partition.get());

        const auto cross_partition_roundtrip = run_ecdsa_sign_verify_roundtrip(
            token_private_key.get(),
            token_public_key.get(),
            message
        );
        ASSERT_EQ(cross_partition_roundtrip.status, AZIHSM_STATUS_INVALID_HANDLE)
            << "step=" << cross_partition_roundtrip.step << ", detail=" << cross_partition_roundtrip.detail
            << ", status=" << cross_partition_roundtrip.status;
    }
}

