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

class azihsm_ecc_keyunwrap : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};
// ==================== key_unwrap_pair ====================

// ----- Positive Paths -----

// Helper: unwraps a wrapped ECC key pair for the given curve and verifies the
// imported keys report the expected curve.
static void verify_unwrap_pair_returns_valid_keys(
    PartitionListHandle &part_list,
    azihsm_ecc_curve curve
)
{
    part_list.for_each_session([&](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, curve, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key imported_private_key;
        auto_key imported_public_key;
        imported_private_key.handle = result.private_key;
        imported_public_key.handle = result.public_key;

        EccKeySummary private_summary{};
        EccKeySummary public_summary{};
        ASSERT_EQ(
            read_ecc_key_summary(imported_private_key.get(), private_summary),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(
            read_ecc_key_summary(imported_public_key.get(), public_summary),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_TRUE(is_expected_ecc_curve(private_summary, curve));
        ASSERT_TRUE(is_expected_ecc_curve(public_summary, curve));
    });
}

// Helper: unwraps a wrapped ECC key pair and verifies the imported keys are
// cryptographically functional by performing an ECDSA sign-then-verify roundtrip.
static void verify_unwrap_pair_keys_sign_verify_roundtrip(
    PartitionListHandle &part_list,
    azihsm_ecc_curve curve
)
{
    part_list.for_each_session([&](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, curve, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        auto result = ctx.try_unwrap();
        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key imported_private_key;
        auto_key imported_public_key;
        imported_private_key.handle = result.private_key;
        imported_public_key.handle = result.public_key;

        const std::vector<uint8_t> message = {
            0x48, 0x53, 0x4D, 0x20, 0x72, 0x6F, 0x75, 0x6E,
            0x64, 0x74, 0x72, 0x69, 0x70
        };
        auto roundtrip = run_ecdsa_sign_verify_roundtrip(
            imported_private_key.get(),
            imported_public_key.get(),
            message
        );
        ASSERT_EQ(roundtrip.status, AZIHSM_STATUS_SUCCESS)
            << "roundtrip failed at step: " << roundtrip.step
            << " detail: " << roundtrip.detail;
    });
}

TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_returns_valid_keys_p256)
{
    verify_unwrap_pair_returns_valid_keys(part_list_, AZIHSM_ECC_CURVE_P256);
}

// P-384: unwrapped keys report correct curve metadata.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_returns_valid_keys_p384)
{
    verify_unwrap_pair_returns_valid_keys(part_list_, AZIHSM_ECC_CURVE_P384);
}

// P-521: unwrapped keys report correct curve metadata.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_returns_valid_keys_p521)
{
    verify_unwrap_pair_returns_valid_keys(part_list_, AZIHSM_ECC_CURVE_P521);
}

// P-256: unwrapped keys can sign and verify an ECDSA roundtrip.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_keys_sign_verify_roundtrip_p256)
{
    verify_unwrap_pair_keys_sign_verify_roundtrip(part_list_, AZIHSM_ECC_CURVE_P256);
}

// P-384: unwrapped keys can sign and verify an ECDSA roundtrip.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_keys_sign_verify_roundtrip_p384)
{
    verify_unwrap_pair_keys_sign_verify_roundtrip(part_list_, AZIHSM_ECC_CURVE_P384);
}

// P-521: unwrapped keys can sign and verify an ECDSA roundtrip.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_keys_sign_verify_roundtrip_p521)
{
    verify_unwrap_pair_keys_sign_verify_roundtrip(part_list_, AZIHSM_ECC_CURVE_P521);
}

// Verifies repeated unwrap of the same wrapped blob yields distinct valid handles.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_same_blob_multiple_imports_unique_handles)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        auto first = ctx.try_unwrap();
        ASSERT_EQ(first.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(first.private_key, 0);
        ASSERT_NE(first.public_key, 0);

        auto_key first_private_key;
        auto_key first_public_key;
        first_private_key.handle = first.private_key;
        first_public_key.handle = first.public_key;

        auto second = ctx.try_unwrap();
        ASSERT_EQ(second.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(second.private_key, 0);
        ASSERT_NE(second.public_key, 0);

        auto_key second_private_key;
        auto_key second_public_key;
        second_private_key.handle = second.private_key;
        second_public_key.handle = second.public_key;

        ASSERT_NE(first_private_key.get(), second_private_key.get());
        ASSERT_NE(first_public_key.get(), second_public_key.get());
    });
}

// ----- Mandatory Pointers and Output Handles -----

// ----- Null Mandatory Pointer Rejection -----

// Verifies unwrap rejects a null algo pointer.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_null_algo_pointer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_with(nullptr, &unwrap_inputs.wrapped_key_buf);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects a null wrapped-key buffer pointer.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_null_wrapped_key_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_with(&unwrap_inputs.unwrap_algo, nullptr);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects a null private property-list pointer.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_null_private_prop_list)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto pub_prop_list = ctx.pub_props.get_prop_list();
        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            ctx.rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            nullptr,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects a null public property-list pointer.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_null_public_prop_list)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto priv_prop_list = ctx.priv_props.get_prop_list();
        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            ctx.rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            nullptr
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// ----- Null/Aliasing Output Handle Rejection -----

// Verifies unwrap rejects both output-handle pointers being null.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_both_null_output_handles)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto err = ctx.raw_unwrap(unwrap_inputs, nullptr, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies unwrap rejects a null private output-handle pointer.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_null_private_output_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        azihsm_handle pub_key_handle = 0;
        auto err = ctx.raw_unwrap(unwrap_inputs, nullptr, &pub_key_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(pub_key_handle, 0);
    });
}

// Verifies unwrap rejects a null public output-handle pointer.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_null_public_output_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        azihsm_handle priv_key_handle = 0;
        auto err = ctx.raw_unwrap(unwrap_inputs, &priv_key_handle, nullptr);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(priv_key_handle, 0);
    });
}

// Verifies unwrap rejects aliasing private/public output-handle pointers.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_aliased_output_handles)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        azihsm_handle key_handle = 0;
        auto err = ctx.raw_unwrap(unwrap_inputs, &key_handle, &key_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(key_handle, 0);
    });
}

// Verifies unwrap failure paths do not leak partial outputs into caller-provided handles.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_preserves_zero_output_handles_on_failure)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0x77);
        unwrap_inputs.unwrap_algo.id = static_cast<azihsm_algo_id>(0xFFFFFFFF);

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// ----- OAEP/RSA-AES Transport Parameter Validation -----

// OAEP/MGF1 note:
// - OAEP is RSA encryption padding used by key wrap/unwrap transports.
// - MGF1 is OAEP's mask-generation function (hash-based expansion).
// - OAEP label is optional associated input that must match between wrap and unwrap.
//   A mismatch should fail unwrap, while matched null/empty/non-empty labels should succeed.
// - These tests are in the ECC file because they validate transport parameters used
//   while importing wrapped ECC key pairs, not because ECC itself uses OAEP.

// Verifies unwrap accepts a non-empty OAEP label when wrap/unwrap labels match.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_accepts_non_empty_oaep_label_when_matched)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> label_bytes = { 0x4C, 0x42, 0x4C };
        azihsm_buffer label{};
        label.ptr = label_bytes.data();
        label.len = static_cast<uint32_t>(label_bytes.size());

        RsaAesWrapConfig wrap_config{};
        wrap_config.label = &label;
        RsaAesWrapConfig unwrap_config = wrap_config;

        UnwrapPairResult result{};
        auto err = unwrap_wrapped_ecc_pair_with_configs(
            session,
            AZIHSM_ECC_CURVE_P256,
            wrap_config,
            unwrap_config,
            result
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);
    });
}

// Verifies unwrap accepts a null OAEP label when both wrap and unwrap use null label.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_accepts_null_oaep_label_when_matched)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesWrapConfig wrap_config{};
        wrap_config.label = nullptr;
        RsaAesWrapConfig unwrap_config{};
        unwrap_config.label = nullptr;

        UnwrapPairResult result{};
        auto err = unwrap_wrapped_ecc_pair_with_configs(
            session,
            AZIHSM_ECC_CURVE_P256,
            wrap_config,
            unwrap_config,
            result
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);
    });
}

// Verifies unwrap accepts all supported RSA-AES key-wrap AES key sizes.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_accepts_supported_aes_key_bits)
{
    part_list_.for_each_session([](azihsm_handle session) {
        const std::vector<uint32_t> aes_key_sizes = { 128, 192, 256 };

        for (const auto aes_key_bits : aes_key_sizes)
        {
            SCOPED_TRACE("aes_key_bits=" + std::to_string(aes_key_bits));

            RsaAesWrapConfig config{};
            config.aes_key_bits = aes_key_bits;

            UnwrapPairResult result{};
            auto err = unwrap_wrapped_ecc_pair_with_configs(
                session,
                AZIHSM_ECC_CURVE_P256,
                config,
                config,
                result
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(result.private_key, 0);
            ASSERT_NE(result.public_key, 0);
        }
    });
}

// Verifies unwrap accepts OAEP SHA-256 with MGF1-SHA-256 when supported.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_accepts_oaep_sha256_mgf1_sha256)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesWrapConfig config{};
        config.hash_algo = AZIHSM_ALGO_ID_SHA256;
        config.mgf1_hash_algo = AZIHSM_MGF1_ID_SHA256;

        UnwrapPairResult result{};
        auto err = unwrap_wrapped_ecc_pair_with_configs(
            session,
            AZIHSM_ECC_CURVE_P256,
            config,
            config,
            result
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);
    });
}

// Verifies unwrap accepts OAEP SHA-384 with MGF1-SHA-384 when supported.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_accepts_oaep_sha384_mgf1_sha384)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesWrapConfig config{};
        config.hash_algo = AZIHSM_ALGO_ID_SHA384;
        config.mgf1_hash_algo = AZIHSM_MGF1_ID_SHA384;

        UnwrapPairResult result{};
        auto err = unwrap_wrapped_ecc_pair_with_configs(
            session,
            AZIHSM_ECC_CURVE_P256,
            config,
            config,
            result
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);
    });
}

// Verifies unwrap accepts OAEP SHA-512 with MGF1-SHA-512 when supported.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_accepts_oaep_sha512_mgf1_sha512)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesWrapConfig config{};
        config.hash_algo = AZIHSM_ALGO_ID_SHA512;
        config.mgf1_hash_algo = AZIHSM_MGF1_ID_SHA512;

        UnwrapPairResult result{};
        auto err = unwrap_wrapped_ecc_pair_with_configs(
            session,
            AZIHSM_ECC_CURVE_P256,
            config,
            config,
            result
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);
    });
}

// Verifies unwrap rejects null OAEP parameter pointer in unwrap params.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_null_oaep_params_pointer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        unwrap_inputs.unwrap_params.oaep_params = nullptr;

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects unsupported OAEP hash identifiers.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_unsupported_oaep_hash)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        unwrap_inputs.oaep_params.hash_algo_id = static_cast<azihsm_algo_id>(0xFFFFFFFF);

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects unsupported OAEP MGF1 identifiers.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_unsupported_oaep_mgf1)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        unwrap_inputs.oaep_params.mgf1_hash_algo_id = static_cast<azihsm_mgf1_id>(0xFFFFFFFF);

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects unsupported RSA-AES key-wrap AES key sizes.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_unsupported_aes_key_bits)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        unwrap_inputs.unwrap_params.aes_key_bits = 129;

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects OAEP hash/MGF1 mixed-strength combinations when unsupported.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_oaep_mixed_hash_mgf1_combo)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        unwrap_inputs.oaep_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
        unwrap_inputs.oaep_params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA512;

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects malformed OAEP label pointer/length shapes.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_invalid_oaep_label_shape)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        azihsm_buffer invalid_label{};
        invalid_label.ptr = nullptr;
        invalid_label.len = 1;
        unwrap_inputs.oaep_params.label = &invalid_label;

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// DISABLED TEST:
// Expected contract: non-empty OAEP label mismatch between wrap and unwrap must fail unwrap.
// Current backend behavior does not enforce OAEP label binding in RSA-AES unwrap path,
// so this test is intentionally skipped until DDI/HSM support is implemented.
TEST_F(
    azihsm_ecc_keyunwrap,
    DISABLED_unwrap_pair_rejects_oaep_label_mismatch_when_non_empty
)
{
    GTEST_SKIP() << "backend gap: RSA-AES unwrap path does not enforce OAEP label matching yet";

    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> wrap_label_bytes = { 0x41, 0x42, 0x43 };
        azihsm_buffer wrap_label{};
        wrap_label.ptr = wrap_label_bytes.data();
        wrap_label.len = static_cast<uint32_t>(wrap_label_bytes.size());

        std::vector<uint8_t> unwrap_label_bytes = { 0x58, 0x59, 0x5A };
        azihsm_buffer unwrap_label{};
        unwrap_label.ptr = unwrap_label_bytes.data();
        unwrap_label.len = static_cast<uint32_t>(unwrap_label_bytes.size());

        RsaAesWrapConfig wrap_config{};
        wrap_config.label = &wrap_label;

        RsaAesWrapConfig unwrap_config{};
        unwrap_config.label = &unwrap_label;

        UnwrapPairResult result{};
        auto err = unwrap_wrapped_ecc_pair_with_configs(
            session,
            AZIHSM_ECC_CURVE_P256,
            wrap_config,
            unwrap_config,
            result
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        // Expectation: OAEP label must match between wrap/unwrap.
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap accepts empty OAEP labels when wrap/unwrap labels are both empty and matched.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_accepts_empty_oaep_label_when_matched)
{
    part_list_.for_each_session([](azihsm_handle session) {
        uint8_t dummy = 0;
        azihsm_buffer empty_label{};
        empty_label.ptr = &dummy;
        empty_label.len = 0;

        RsaAesWrapConfig config{};
        config.label = &empty_label;

        UnwrapPairResult result{};
        auto err = unwrap_wrapped_ecc_pair_with_configs(
            session,
            AZIHSM_ECC_CURVE_P256,
            config,
            config,
            result
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);
    });
}

// ----- Algorithm Argument Validation -----

// Verifies unwrap rejects algorithm parameter layout/length mismatches.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_algorithm_param_layout_mismatch)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        unwrap_inputs.unwrap_algo.params = &unwrap_inputs.oaep_params;
        unwrap_inputs.unwrap_algo.len = sizeof(unwrap_inputs.oaep_params);

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects null algo.params pointer when algo.len is non-zero.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_null_algo_params_with_nonzero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        unwrap_inputs.unwrap_algo.params = nullptr;
        unwrap_inputs.unwrap_algo.len = sizeof(unwrap_inputs.unwrap_params);

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies unwrap rejects non-null algo.params pointer when algo.len is zero.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_non_null_algo_params_with_zero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        unwrap_inputs.unwrap_algo.len = 0;

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies unwrap rejects algo.len smaller than expected unwrap-parameter structure size.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_algo_len_too_small_for_unwrap_params)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        unwrap_inputs.unwrap_algo.len = sizeof(unwrap_inputs.unwrap_params) - 1;

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies unwrap rejects algo.len larger than expected when trailing parameter bytes are present.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_algo_len_with_trailing_parameter_bytes)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        unwrap_inputs.unwrap_algo.len = sizeof(unwrap_inputs.unwrap_params) + 1;

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies unwrap rejects null algo.params pointer with zero algo.len for unwrap API.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_null_algo_params_with_zero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        unwrap_inputs.unwrap_algo.params = nullptr;
        unwrap_inputs.unwrap_algo.len = 0;

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies unwrap rejects unsupported unwrap algorithm IDs.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_unsupported_algorithm_id)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        unwrap_inputs.unwrap_algo.id = static_cast<azihsm_algo_id>(0xFFFFFFFF);

        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_EQ(result.status, AZIHSM_STATUS_UNSUPPORTED_ALGORITHM);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// ----- Unwrapping Key Argument Validation -----

// Verifies unwrap rejects invalid or wrong-type unwrapping key handles.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_invalid_unwrap_key_handles)
{
    auto result = try_unwrap_with_invalid_handle(0xDEADBEEF);
    ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
    ASSERT_EQ(result.private_key, 0);
    ASSERT_EQ(result.public_key, 0);
}

// Verifies unwrap rejects zero-valued unwrapping key handle.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_zero_unwrap_key_handle)
{
    auto result = try_unwrap_with_invalid_handle(0);
    ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
    ASSERT_EQ(result.private_key, 0);
    ASSERT_EQ(result.public_key, 0);
}

// Verifies unwrap rejects random non-existent unwrapping key handle values.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_random_nonexistent_unwrap_key_handle)
{
    auto result = try_unwrap_with_invalid_handle(0xABCDEF01);
    ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
    ASSERT_EQ(result.private_key, 0);
    ASSERT_EQ(result.public_key, 0);
}

// Verifies unwrap rejects unwrapping key handles of the wrong handle type.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_unwrap_key_wrong_handle_type)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto result = try_unwrap_with_invalid_handle(session);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects RSA public-key handles as unwrapping keys.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_unwrap_key_public_rsa_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        // Use RSA public key instead of private key for unwrap.
        ctx.wrapped_key_buf = unwrap_inputs.wrapped_key_buf;
        auto result = ctx.try_unwrap_with_key(ctx.rsa_pub_key.get());
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects non-RSA private-key handles used as unwrapping keys.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_unwrapping_key_private_non_rsa_kind)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key ecc_priv_key;
        auto_key ecc_pub_key;
        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true,
            ecc_priv_key.get_ptr(),
            ecc_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        UnwrapPairContext ctx;
        ctx.wrapped_key_buf = unwrap_inputs.wrapped_key_buf;
        auto result = ctx.try_unwrap_with_key(ecc_priv_key.get());
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects a stale/deleted unwrapping key handle.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_stale_unwrap_key_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        const auto stale_unwrap_key = ctx.rsa_priv_key.release();
        ASSERT_EQ(azihsm_key_delete(stale_unwrap_key), AZIHSM_STATUS_SUCCESS);

        ctx.wrapped_key_buf = unwrap_inputs.wrapped_key_buf;
        auto result = ctx.try_unwrap_with_key(stale_unwrap_key);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// ----- Wrapped Key Argument Validation -----

// Verifies unwrap rejects an empty wrapped blob represented as null pointer + zero length.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_null_wrapped_key_with_zero_length)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = nullptr;
        wrapped_key_buf.len = 0;

        auto result = ctx.try_unwrap_with(&unwrap_inputs.unwrap_algo, &wrapped_key_buf);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects wrapped blob truncated by a single byte.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_truncated_blob_by_single_byte)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_GT(ctx.wrapped_blob.size(), 1u);

        ctx.wrapped_blob.pop_back();
        ctx.wrapped_key_buf.len = static_cast<uint32_t>(ctx.wrapped_blob.size());

        auto result = ctx.try_unwrap();
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects wrapped blob truncated by a larger chunk.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_truncated_blob_by_chunk)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P384, ctx),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_GT(ctx.wrapped_blob.size(), 16u);

        ctx.wrapped_blob.resize(ctx.wrapped_blob.size() - 16);
        ctx.wrapped_key_buf.ptr = ctx.wrapped_blob.data();
        ctx.wrapped_key_buf.len = static_cast<uint32_t>(ctx.wrapped_blob.size());

        auto result = ctx.try_unwrap();
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Security contract: wrapped blobs must be fully consumed; trailing bytes are rejected.
// Verifies unwrap rejects wrapped blobs when trailing garbage bytes are appended.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_wrapped_key_with_trailing_bytes)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_FALSE(ctx.wrapped_blob.empty());

        std::vector<uint8_t> mutated = ctx.wrapped_blob;
        mutated.push_back(0xAA);
        mutated.push_back(0x55);
        const auto before = mutated;

        ctx.wrapped_key_buf.ptr = mutated.data();
        ctx.wrapped_key_buf.len = static_cast<uint32_t>(mutated.size());

        auto result = ctx.try_unwrap();
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
        ASSERT_EQ(mutated, before);
    });
}

// Verifies unwrap rejects corrupted wrapped blob metadata/integrity.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_corrupted_wrapped_blob_integrity)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_GT(ctx.wrapped_blob.size(), 2u);

        std::vector<uint8_t> mutated = ctx.wrapped_blob;
        mutated[mutated.size() / 2] ^= 0x01;

        ctx.wrapped_key_buf.ptr = mutated.data();
        ctx.wrapped_key_buf.len = static_cast<uint32_t>(mutated.size());

        auto result = ctx.try_unwrap();
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects multi-byte corruption patterns across blob regions.
TEST_F(azihsm_ecc_keyunwrap, unwrap_pair_rejects_multi_byte_blob_corruption_patterns)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_GT(ctx.wrapped_blob.size(), 3u);

        const std::vector<size_t> offsets = {
            0, ctx.wrapped_blob.size() / 2, ctx.wrapped_blob.size() - 1
        };
        for (size_t offset : offsets)
        {
            SCOPED_TRACE("offset=" + std::to_string(offset));
            std::vector<uint8_t> mutated = ctx.wrapped_blob;
            mutated[offset] ^= 0xA5;
            mutated[(offset + 1) % mutated.size()] ^= 0x5A;

            ctx.wrapped_key_buf.ptr = mutated.data();
            ctx.wrapped_key_buf.len = static_cast<uint32_t>(mutated.size());

            auto result = ctx.try_unwrap();
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

