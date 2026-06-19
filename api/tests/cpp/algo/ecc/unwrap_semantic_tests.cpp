// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <azihsm_api.h>
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

class azihsm_ecc_keyunwrap_semantic : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// ==================== key_unwrap_pair: Cross-Argument Wrapped Payload Semantics
// ====================

// ----- Cross-Argument Wrapped Payload Semantics -----

// Verifies unwrap rejects a wrapped-key buffer with null pointer and non-zero length.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_wrapped_key_null_ptr_nonzero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = nullptr;
        wrapped_key_buf.len = 1;

        auto result = ctx.try_unwrap_with(&unwrap_inputs.unwrap_algo, &wrapped_key_buf);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects a wrapped-key buffer with non-null pointer and zero length.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_wrapped_key_nonnull_ptr_zero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        uint8_t byte = 0;
        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = &byte;
        wrapped_key_buf.len = 0;

        auto result = ctx.try_unwrap_with(&unwrap_inputs.unwrap_algo, &wrapped_key_buf);
        ASSERT_EQ(result.status, AZIHSM_STATUS_DDI_CMD_FAILURE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects a minimal one-byte wrapped blob.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_minimal_one_byte_blob)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        uint8_t byte = 0x01;
        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = &byte;
        wrapped_key_buf.len = 1;

        auto result = ctx.try_unwrap_with(&unwrap_inputs.unwrap_algo, &wrapped_key_buf);
        ASSERT_EQ(result.status, AZIHSM_STATUS_DDI_CMD_FAILURE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects wrapped payloads that encode a single key instead of a key pair.
TEST_F(
    azihsm_ecc_keyunwrap_semantic,
    unwrap_pair_rejects_wrapped_single_key_payload_for_pair_unwrap
)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key rsa_unwrap_priv_key;
        auto_key rsa_wrap_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_unwrap_priv_key.get_ptr(),
            rsa_wrap_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Step 1: Build transport-valid wrapped bytes whose plaintext is a single symmetric key,
        // not an ECC key-pair serialization.
        const auto single_key_payload = make_deterministic_payload(0x10, 0x22, 16);

        std::vector<uint8_t> wrapped_blob;
        err = wrap_plaintext_with_rsa_aes(
            rsa_wrap_pub_key.get(),
            single_key_payload,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());

        // Step 2: Sanity check that these bytes are valid for key_unwrap (single-key API).
        RsaAesUnwrapAlgo unwrap_algo{};

        azihsm_key_kind aes_kind = AZIHSM_KEY_KIND_AES;
        azihsm_key_class aes_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t aes_bits = 128;
        uint8_t aes_is_session = 1;
        uint8_t can_encrypt = 1;
        uint8_t can_decrypt = 1;
        std::vector<azihsm_key_prop> aes_props = {
            { AZIHSM_KEY_PROP_ID_KIND, &aes_kind, sizeof(aes_kind) },
            { AZIHSM_KEY_PROP_ID_CLASS, &aes_class, sizeof(aes_class) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &aes_bits, sizeof(aes_bits) },
            { AZIHSM_KEY_PROP_ID_SESSION, &aes_is_session, sizeof(aes_is_session) },
            { AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) },
            { AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) }
        };
        azihsm_key_prop_list aes_prop_list{ aes_props.data(),
                                            static_cast<uint32_t>(aes_props.size()) };

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = wrapped_blob.data();
        wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        auto_key single_key;
        err = azihsm_key_unwrap(
            &unwrap_algo.algo,
            rsa_unwrap_priv_key.get(),
            &wrapped_key_buf,
            &aes_prop_list,
            single_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(single_key.get(), 0);

        // Step 3: key_unwrap_pair should reject the same bytes because pair-shaped content is
        // required.
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto pair_result = try_unwrap_pair(
            &unwrap_algo.algo,
            rsa_unwrap_priv_key.get(),
            &wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(pair_result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(pair_result.private_key, 0);
        ASSERT_EQ(pair_result.public_key, 0);
    });
}

// Verifies unwrap rejects blobs wrapped by a different RSA wrapping key.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_blob_wrapped_by_different_wrapping_key)
{
    if (part_list_.count() < 2u)
    {
        GTEST_SKIP(
        ) << "requires at least two partitions to guarantee distinct wrapping-key contexts";
    }

    auto source_path = part_list_.get_path(0);
    auto other_path = part_list_.get_path(1);

    auto source_partition = PartitionHandle(source_path);
    auto other_partition = PartitionHandle(other_path);

    std::vector<uint8_t> wrapped_blob;
    auto_key wrapping_priv_key_b;

    {
        SessionHandle source_session(source_partition.get());
        auto_key wrapping_priv_key_a;
        auto_key wrapping_pub_key_a;
        auto err = generate_rsa_unwrapping_keypair(
            source_session.get(),
            wrapping_priv_key_a.get_ptr(),
            wrapping_pub_key_a.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        err = make_wrapped_ecc_pkcs8_blob(
            wrapping_pub_key_a.get(),
            AZIHSM_ECC_CURVE_P256,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());
    }

    {
        SessionHandle other_session(other_partition.get());
        auto_key wrapping_pub_key_b;
        auto err = generate_rsa_unwrapping_keypair(
            other_session.get(),
            wrapping_priv_key_b.get_ptr(),
            wrapping_pub_key_b.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    }

    azihsm_buffer wrapped_key_buf{};
    wrapped_key_buf.ptr = wrapped_blob.data();
    wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

    RsaAesUnwrapAlgo unwrap_algo{};
    DefaultEccPrivKeyProps priv_props;
    DefaultEccPubKeyProps pub_props;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();

    auto result = try_unwrap_pair(
        &unwrap_algo.algo,
        wrapping_priv_key_b.get(),
        &wrapped_key_buf,
        &priv_prop_list,
        &pub_prop_list
    );
    ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_KEY_PROPS);
    ASSERT_EQ(result.private_key, 0);
    ASSERT_EQ(result.public_key, 0);
}

// Verifies unwrap does not mutate caller-provided wrapped blob on failure.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_preserves_input_wrapped_blob_on_failure)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        // Deliberately malformed/truncated test payload used only to verify failure-path
        // immutability.
        std::vector<uint8_t> wrapped_data = make_deterministic_payload(0x01, 0x01, 5);
        const auto before = wrapped_data;

        ctx.wrapped_key_buf.ptr = wrapped_data.data();
        ctx.wrapped_key_buf.len = static_cast<uint32_t>(wrapped_data.size());

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_DDI_CMD_FAILURE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
        ASSERT_EQ(wrapped_data, before);
    });
}

// Verifies unwrap rejects when requested curve mismatches wrapped ECC key curve.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_requested_curve_mismatch)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        ctx.priv_props.ecc_curve = AZIHSM_ECC_CURVE_P384;
        ctx.pub_props.ecc_curve = AZIHSM_ECC_CURVE_P384;

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects when requested capability combination is invalid.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_requested_capability_mismatch)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        ctx.priv_props.can_sign = 0;

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects wrapped content whose kind conflicts with requested ECC properties.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_wrapped_content_kind_mismatch)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        // Wrap arbitrary non-ECC payload; pair unwrap should reject because content is not ECC-pair
        // shaped.
        const auto non_ecc_payload = make_deterministic_payload(0x01, 0x02, 16);

        std::vector<uint8_t> wrapped_blob;
        auto err = wrap_plaintext_with_rsa_aes(
            ctx.rsa_pub_key.get(),
            non_ecc_payload,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());

        ctx.wrapped_key_buf.ptr = wrapped_blob.data();
        ctx.wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_DDI_CMD_FAILURE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects wrapped content whose encoded curve conflicts with requested curve.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_wrapped_content_curve_mismatch)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P384, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        ctx.priv_props.ecc_curve = AZIHSM_ECC_CURVE_P521;
        ctx.pub_props.ecc_curve = AZIHSM_ECC_CURVE_P521;

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects a valid wrapped ECC blob after the first byte is corrupted.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_valid_blob_with_first_byte_corrupted)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_NE(ctx.wrapped_key_buf.ptr, nullptr);
        ASSERT_GT(ctx.wrapped_key_buf.len, 0u);

        const auto *wrapped_ptr = static_cast<const uint8_t *>(ctx.wrapped_key_buf.ptr);
        std::vector<uint8_t> corrupted_blob(wrapped_ptr, wrapped_ptr + ctx.wrapped_key_buf.len);

        corrupted_blob.front() ^= 0x01;

        ctx.wrapped_key_buf.ptr = corrupted_blob.data();
        ctx.wrapped_key_buf.len = static_cast<uint32_t>(corrupted_blob.size());

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_DDI_CMD_FAILURE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects a valid wrapped ECC blob after a middle byte is corrupted.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_valid_blob_with_middle_byte_corrupted)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_NE(ctx.wrapped_key_buf.ptr, nullptr);
        ASSERT_GT(ctx.wrapped_key_buf.len, 0u);

        const auto *wrapped_ptr = static_cast<const uint8_t *>(ctx.wrapped_key_buf.ptr);
        std::vector<uint8_t> corrupted_blob(wrapped_ptr, wrapped_ptr + ctx.wrapped_key_buf.len);

        corrupted_blob[corrupted_blob.size() / 2] ^= 0x5A;

        ctx.wrapped_key_buf.ptr = corrupted_blob.data();
        ctx.wrapped_key_buf.len = static_cast<uint32_t>(corrupted_blob.size());

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_DDI_CMD_FAILURE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects a valid wrapped ECC blob after the final byte is corrupted.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_valid_blob_with_last_byte_corrupted)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_NE(ctx.wrapped_key_buf.ptr, nullptr);
        ASSERT_GT(ctx.wrapped_key_buf.len, 0u);

        const auto *wrapped_ptr = static_cast<const uint8_t *>(ctx.wrapped_key_buf.ptr);
        std::vector<uint8_t> corrupted_blob(wrapped_ptr, wrapped_ptr + ctx.wrapped_key_buf.len);

        corrupted_blob.back() ^= 0x80;

        ctx.wrapped_key_buf.ptr = corrupted_blob.data();
        ctx.wrapped_key_buf.len = static_cast<uint32_t>(corrupted_blob.size());

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_DDI_CMD_FAILURE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects a valid wrapped ECC blob when the caller truncates the wrapped payload.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_truncated_valid_wrapped_blob)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_NE(ctx.wrapped_key_buf.ptr, nullptr);
        ASSERT_GT(ctx.wrapped_key_buf.len, 1u);

        const auto *wrapped_ptr = static_cast<const uint8_t *>(ctx.wrapped_key_buf.ptr);
        std::vector<uint8_t> truncated_blob(wrapped_ptr, wrapped_ptr + ctx.wrapped_key_buf.len - 1);

        ctx.wrapped_key_buf.ptr = truncated_blob.data();
        ctx.wrapped_key_buf.len = static_cast<uint32_t>(truncated_blob.size());

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_DDI_CMD_FAILURE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects when private and public requested curves disagree.
TEST_F(
    azihsm_ecc_keyunwrap_semantic,
    unwrap_pair_rejects_private_public_requested_curve_disagreement
)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        ctx.priv_props.ecc_curve = AZIHSM_ECC_CURVE_P256;
        ctx.pub_props.ecc_curve = AZIHSM_ECC_CURVE_P384;

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects when private requested curve mismatches even if public curve matches.
TEST_F(
    azihsm_ecc_keyunwrap_semantic,
    unwrap_pair_rejects_private_curve_mismatch_public_curve_matches
)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        ctx.priv_props.ecc_curve = AZIHSM_ECC_CURVE_P384;
        ctx.pub_props.ecc_curve = AZIHSM_ECC_CURVE_P256;

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects when public requested curve mismatches even if private curve matches.
TEST_F(
    azihsm_ecc_keyunwrap_semantic,
    unwrap_pair_rejects_public_curve_mismatch_private_curve_matches
)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        ctx.priv_props.ecc_curve = AZIHSM_ECC_CURVE_P256;
        ctx.pub_props.ecc_curve = AZIHSM_ECC_CURVE_P384;

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects when the requested public-key verify capability is missing.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_public_verify_capability_missing)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        ctx.pub_props.can_verify = 0;

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects when both private sign and public verify capabilities are missing.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_sign_and_verify_capabilities_missing)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        ctx.priv_props.can_sign = 0;
        ctx.pub_props.can_verify = 0;

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap does not mutate a transport-valid wrapped blob when unwrap fails after
// corruption.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_preserves_corrupted_valid_blob_on_failure)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_NE(ctx.wrapped_key_buf.ptr, nullptr);
        ASSERT_GT(ctx.wrapped_key_buf.len, 0u);

        const auto *wrapped_ptr = static_cast<const uint8_t *>(ctx.wrapped_key_buf.ptr);
        std::vector<uint8_t> corrupted_blob(wrapped_ptr, wrapped_ptr + ctx.wrapped_key_buf.len);

        corrupted_blob[corrupted_blob.size() / 2] ^= 0xA5;
        const auto before = corrupted_blob;

        ctx.wrapped_key_buf.ptr = corrupted_blob.data();
        ctx.wrapped_key_buf.len = static_cast<uint32_t>(corrupted_blob.size());

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_DDI_CMD_FAILURE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
        ASSERT_EQ(corrupted_blob, before);
    });
}

// Verifies unwrap rejects an empty wrapped-key buffer with null pointer and zero length.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_wrapped_key_null_ptr_zero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapAlgo unwrap_algo{};
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = nullptr;
        wrapped_key_buf.len = 0;

        auto priv_prop_list = ctx.priv_props.get_prop_list();
        auto pub_prop_list = ctx.pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );

        ASSERT_EQ(result.status, AZIHSM_STATUS_DDI_CMD_FAILURE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects a valid wrapped ECC blob with one extra trailing byte.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_valid_blob_with_extra_trailing_byte)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_NE(ctx.wrapped_key_buf.ptr, nullptr);
        ASSERT_GT(ctx.wrapped_key_buf.len, 0u);

        const auto *wrapped_ptr = static_cast<const uint8_t *>(ctx.wrapped_key_buf.ptr);
        std::vector<uint8_t> extended_blob(wrapped_ptr, wrapped_ptr + ctx.wrapped_key_buf.len);

        extended_blob.push_back(0xA5);

        ctx.wrapped_key_buf.ptr = extended_blob.data();
        ctx.wrapped_key_buf.len = static_cast<uint32_t>(extended_blob.size());

        auto result = ctx.try_unwrap();

        ASSERT_EQ(result.status, AZIHSM_STATUS_DDI_CMD_FAILURE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects a valid wrapped ECC blob with many extra trailing bytes.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_valid_blob_with_many_extra_trailing_bytes)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_NE(ctx.wrapped_key_buf.ptr, nullptr);
        ASSERT_GT(ctx.wrapped_key_buf.len, 0u);

        const auto *wrapped_ptr = static_cast<const uint8_t *>(ctx.wrapped_key_buf.ptr);
        std::vector<uint8_t> extended_blob(wrapped_ptr, wrapped_ptr + ctx.wrapped_key_buf.len);

        const auto trailing_bytes = make_deterministic_payload(0x10, 0x03, 32);
        extended_blob.insert(extended_blob.end(), trailing_bytes.begin(), trailing_bytes.end());

        ctx.wrapped_key_buf.ptr = extended_blob.data();
        ctx.wrapped_key_buf.len = static_cast<uint32_t>(extended_blob.size());

        auto result = ctx.try_unwrap();

        ASSERT_EQ(result.status, AZIHSM_STATUS_DDI_CMD_FAILURE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects when the unwrap algorithm pointer is null.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_null_unwrap_algorithm)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        auto priv_prop_list = ctx.priv_props.get_prop_list();
        auto pub_prop_list = ctx.pub_props.get_prop_list();

        azihsm_handle private_key = 0;
        azihsm_handle public_key = 0;

        auto err = azihsm_key_unwrap_pair(
            nullptr,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list,
            &private_key,
            &public_key
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(private_key, 0);
        ASSERT_EQ(public_key, 0);
    });
}

// Verifies unwrap rejects when the RSA unwrap key handle is zero.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_zero_unwrap_key_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapAlgo unwrap_algo{};
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        auto priv_prop_list = ctx.priv_props.get_prop_list();
        auto pub_prop_list = ctx.pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            0,
            &ctx.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );

        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects when the RSA public key is passed as the unwrap key.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_public_rsa_key_as_unwrap_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapAlgo unwrap_algo{};
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        auto priv_prop_list = ctx.priv_props.get_prop_list();
        auto pub_prop_list = ctx.pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            ctx.rsa_pub_key.get(),
            &ctx.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );

        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects when the private-key output handle pointer is null.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_null_private_output_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapAlgo unwrap_algo{};
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        auto priv_prop_list = ctx.priv_props.get_prop_list();
        auto pub_prop_list = ctx.pub_props.get_prop_list();

        azihsm_handle public_key = 0;

        auto err = azihsm_key_unwrap_pair(
            &unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list,
            nullptr,
            &public_key
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(public_key, 0);
    });
}

// Verifies unwrap rejects when the public-key output handle pointer is null.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_null_public_output_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapAlgo unwrap_algo{};
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        auto priv_prop_list = ctx.priv_props.get_prop_list();
        auto pub_prop_list = ctx.pub_props.get_prop_list();

        azihsm_handle private_key = 0;

        auto err = azihsm_key_unwrap_pair(
            &unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list,
            &private_key,
            nullptr
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(private_key, 0);
    });
}

// Verifies unwrap rejects when both output handle pointers are null.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_null_output_handles)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapAlgo unwrap_algo{};
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        auto priv_prop_list = ctx.priv_props.get_prop_list();
        auto pub_prop_list = ctx.pub_props.get_prop_list();

        auto err = azihsm_key_unwrap_pair(
            &unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list,
            nullptr,
            nullptr
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies unwrap rejects when the private-key property list pointer is null.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_null_private_prop_list)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapAlgo unwrap_algo{};
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        auto pub_prop_list = ctx.pub_props.get_prop_list();

        azihsm_handle private_key = 0;
        azihsm_handle public_key = 0;

        auto err = azihsm_key_unwrap_pair(
            &unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            nullptr,
            &pub_prop_list,
            &private_key,
            &public_key
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(private_key, 0);
        ASSERT_EQ(public_key, 0);
    });
}

// Verifies unwrap rejects when the public-key property list pointer is null.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_null_public_prop_list)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapAlgo unwrap_algo{};
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        auto priv_prop_list = ctx.priv_props.get_prop_list();

        azihsm_handle private_key = 0;
        azihsm_handle public_key = 0;

        auto err = azihsm_key_unwrap_pair(
            &unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            &priv_prop_list,
            nullptr,
            &private_key,
            &public_key
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(private_key, 0);
        ASSERT_EQ(public_key, 0);
    });
}

// Verifies unwrap rejects when both property list pointers are null.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_null_prop_lists)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapAlgo unwrap_algo{};
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_handle private_key = 0;
        azihsm_handle public_key = 0;

        auto err = azihsm_key_unwrap_pair(
            &unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            nullptr,
            nullptr,
            &private_key,
            &public_key
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(private_key, 0);
        ASSERT_EQ(public_key, 0);
    });
}

// Verifies unwrap rejects when private property-list data is null but count is non-zero.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_private_prop_list_null_data_nonzero_count)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapAlgo unwrap_algo{};
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_key_prop_list bad_priv_prop_list{ nullptr, 1 };
        auto pub_prop_list = ctx.pub_props.get_prop_list();

        azihsm_handle private_key = 0;
        azihsm_handle public_key = 0;

        auto err = azihsm_key_unwrap_pair(
            &unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            &bad_priv_prop_list,
            &pub_prop_list,
            &private_key,
            &public_key
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(private_key, 0);
        ASSERT_EQ(public_key, 0);
    });
}

// Verifies unwrap rejects when public property-list data is null but count is non-zero.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_public_prop_list_null_data_nonzero_count)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapAlgo unwrap_algo{};
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        auto priv_prop_list = ctx.priv_props.get_prop_list();
        azihsm_key_prop_list bad_pub_prop_list{ nullptr, 1 };

        azihsm_handle private_key = 0;
        azihsm_handle public_key = 0;

        auto err = azihsm_key_unwrap_pair(
            &unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            &priv_prop_list,
            &bad_pub_prop_list,
            &private_key,
            &public_key
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(private_key, 0);
        ASSERT_EQ(public_key, 0);
    });
}

// Verifies unwrap rejects when private property-list count is zero.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_private_prop_list_zero_count)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapAlgo unwrap_algo{};
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        auto valid_priv_prop_list = ctx.priv_props.get_prop_list();
        azihsm_key_prop_list empty_priv_prop_list{ valid_priv_prop_list.props, 0 };
        auto pub_prop_list = ctx.pub_props.get_prop_list();

        azihsm_handle private_key = 0;
        azihsm_handle public_key = 0;

        auto err = azihsm_key_unwrap_pair(
            &unwrap_algo.algo,
            ctx.rsa_priv_key.get(),
            &ctx.wrapped_key_buf,
            &empty_priv_prop_list,
            &pub_prop_list,
            &private_key,
            &public_key
        );

        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(private_key, 0);
        ASSERT_EQ(public_key, 0);
    });
}

// Verifies unwrap rejects when the OAEP hash used for wrapping does not match
// the OAEP hash requested for unwrapping.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_wrap_oaep_sha256_unwrap_oaep_sha384)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesWrapConfig wrap_config{};
        wrap_config.hash_algo = AZIHSM_ALGO_ID_SHA256;
        wrap_config.mgf1_hash_algo = AZIHSM_MGF1_ID_SHA256;

        RsaAesWrapConfig unwrap_config{};
        unwrap_config.hash_algo = AZIHSM_ALGO_ID_SHA384;
        unwrap_config.mgf1_hash_algo = AZIHSM_MGF1_ID_SHA384;

        UnwrapPairResult result{};
        auto err = unwrap_wrapped_ecc_pair_with_configs(
            session,
            AZIHSM_ECC_CURVE_P256,
            wrap_config,
            unwrap_config,
            result
        );

        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.status, AZIHSM_STATUS_DDI_CMD_FAILURE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}
