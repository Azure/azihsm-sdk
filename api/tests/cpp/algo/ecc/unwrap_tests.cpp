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
struct KeygenTestParams
{
    azihsm_ecc_curve curve;
    const char *test_name;
};
// ==================== key_unwrap_pair ====================

// ----- Positive Paths -----

// Verifies unwrap happy path across all supported curves with property parity checks.
TEST_F(azihsm_ecc_keygen, unwrap_pair_all_curves_happy_path)
{
    const std::vector<KeygenTestParams> test_cases = {
        { AZIHSM_ECC_CURVE_P256, "P256" },
        { AZIHSM_ECC_CURVE_P384, "P384" },
        { AZIHSM_ECC_CURVE_P521, "P521" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("curve=" + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
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
                test_case.curve,
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
            priv_props.ecc_curve = test_case.curve;
            pub_props.ecc_curve = test_case.curve;
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
            ASSERT_TRUE(is_expected_ecc_curve(private_summary, test_case.curve));
            ASSERT_TRUE(is_expected_ecc_curve(public_summary, test_case.curve));
        });
    }
}

// Verifies unwrap preserves requested private/public properties across P256/P384/P521.
// Specifically checks imported key CLASS, KIND, EC_CURVE, SESSION, and SIGN/VERIFY flags
// against the property lists supplied to key_unwrap_pair for each curve.
TEST_F(azihsm_ecc_keygen, unwrap_pair_preserves_property_parity_all_curves)
{
    const std::vector<KeygenTestParams> test_cases = {
        { AZIHSM_ECC_CURVE_P256, "P256" },
        { AZIHSM_ECC_CURVE_P384, "P384" },
        { AZIHSM_ECC_CURVE_P521, "P521" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("curve=" + std::string(test_case.test_name));

        part_list_.for_each_session([&](azihsm_handle session) {
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
                test_case.curve,
                RsaAesWrapConfig{},
                wrapped_blob
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            azihsm_buffer wrapped_key_buf{};
            wrapped_key_buf.ptr = wrapped_blob.data();
            wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

            RsaAesUnwrapAlgo unwrap_algo{};

            DummyEccPrivKeyProps priv_props;
            DummyEccPubKeyProps pub_props;
            priv_props.ecc_curve = test_case.curve;
            pub_props.ecc_curve = test_case.curve;
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

            auto_key imported_private_key;
            auto_key imported_public_key;
            imported_private_key.handle = result.private_key;
            imported_public_key.handle = result.public_key;

            azihsm_key_class private_class = AZIHSM_KEY_CLASS_PUBLIC;
            azihsm_key_kind private_kind = AZIHSM_KEY_KIND_AES;
            azihsm_ecc_curve private_curve = AZIHSM_ECC_CURVE_P256;
            uint8_t private_session = 0;
            uint8_t private_sign = 0;

            ASSERT_EQ(
                get_key_prop(imported_private_key.get(), AZIHSM_KEY_PROP_ID_CLASS, private_class),
                AZIHSM_STATUS_SUCCESS
            );
            ASSERT_EQ(
                get_key_prop(imported_private_key.get(), AZIHSM_KEY_PROP_ID_KIND, private_kind),
                AZIHSM_STATUS_SUCCESS
            );
            ASSERT_EQ(
                get_key_prop(imported_private_key.get(), AZIHSM_KEY_PROP_ID_EC_CURVE, private_curve),
                AZIHSM_STATUS_SUCCESS
            );
            ASSERT_EQ(
                get_key_prop(imported_private_key.get(), AZIHSM_KEY_PROP_ID_SESSION, private_session),
                AZIHSM_STATUS_SUCCESS
            );
            ASSERT_EQ(
                get_key_prop(imported_private_key.get(), AZIHSM_KEY_PROP_ID_SIGN, private_sign),
                AZIHSM_STATUS_SUCCESS
            );

            azihsm_key_class public_class = AZIHSM_KEY_CLASS_PRIVATE;
            azihsm_key_kind public_kind = AZIHSM_KEY_KIND_AES;
            azihsm_ecc_curve public_curve = AZIHSM_ECC_CURVE_P256;
            uint8_t public_session = 0;
            uint8_t public_verify = 0;

            ASSERT_EQ(
                get_key_prop(imported_public_key.get(), AZIHSM_KEY_PROP_ID_CLASS, public_class),
                AZIHSM_STATUS_SUCCESS
            );
            ASSERT_EQ(
                get_key_prop(imported_public_key.get(), AZIHSM_KEY_PROP_ID_KIND, public_kind),
                AZIHSM_STATUS_SUCCESS
            );
            ASSERT_EQ(
                get_key_prop(imported_public_key.get(), AZIHSM_KEY_PROP_ID_EC_CURVE, public_curve),
                AZIHSM_STATUS_SUCCESS
            );
            ASSERT_EQ(
                get_key_prop(imported_public_key.get(), AZIHSM_KEY_PROP_ID_SESSION, public_session),
                AZIHSM_STATUS_SUCCESS
            );
            ASSERT_EQ(
                get_key_prop(imported_public_key.get(), AZIHSM_KEY_PROP_ID_VERIFY, public_verify),
                AZIHSM_STATUS_SUCCESS
            );

            ASSERT_EQ(private_class, AZIHSM_KEY_CLASS_PRIVATE);
            ASSERT_EQ(private_kind, AZIHSM_KEY_KIND_ECC);
            ASSERT_EQ(private_curve, test_case.curve);
            ASSERT_EQ(private_session, priv_props.is_session);
            ASSERT_EQ(private_sign, priv_props.can_sign);

            ASSERT_EQ(public_class, AZIHSM_KEY_CLASS_PUBLIC);
            ASSERT_EQ(public_kind, AZIHSM_KEY_KIND_ECC);
            ASSERT_EQ(public_curve, test_case.curve);
            ASSERT_EQ(public_session, pub_props.is_session);
            ASSERT_EQ(public_verify, pub_props.can_verify);
        });
    }
}

// Verifies repeated unwrap of the same wrapped blob yields distinct valid handles.
TEST_F(azihsm_ecc_keygen, unwrap_pair_same_blob_multiple_imports_unique_handles)
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

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = wrapped_blob.data();
        wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        RsaAesUnwrapAlgo unwrap_algo{};

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto first = try_unwrap_pair(
            &unwrap_algo.algo,
            rsa_priv_key.get(),
            &wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(first.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(first.private_key, 0);
        ASSERT_NE(first.public_key, 0);

        auto second = try_unwrap_pair(
            &unwrap_algo.algo,
            rsa_priv_key.get(),
            &wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(second.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(second.private_key, 0);
        ASSERT_NE(second.public_key, 0);

        ASSERT_NE(first.private_key, second.private_key);
        ASSERT_NE(first.public_key, second.public_key);

        auto_key first_private_key;
        auto_key first_public_key;
        auto_key second_private_key;
        auto_key second_public_key;
        first_private_key.handle = first.private_key;
        first_public_key.handle = first.public_key;
        second_private_key.handle = second.private_key;
        second_public_key.handle = second.public_key;
    });
}

// ----- Mandatory Pointers and Output Handles -----

// Verifies unwrap rejects null mandatory pointers (algo, wrapped buffer, prop lists).
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_null_mandatory_pointers)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        {
            SCOPED_TRACE("null algo pointer");
            auto result = try_unwrap_pair(
                nullptr,
                rsa_priv_key.get(),
                &unwrap_inputs.wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("null wrapped-key buffer pointer");
            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                nullptr,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("null private property-list pointer");
            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &unwrap_inputs.wrapped_key_buf,
                nullptr,
                &pub_prop_list
            );
            ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("null public property-list pointer");
            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &unwrap_inputs.wrapped_key_buf,
                &priv_prop_list,
                nullptr
            );
            ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

// Verifies unwrap rejects null/aliasing output-handle configurations.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_invalid_output_handle_configurations)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        {
            SCOPED_TRACE("both output-handle pointers are null");
            err = azihsm_key_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &unwrap_inputs.wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list,
                nullptr,
                nullptr
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        }

        {
            SCOPED_TRACE("null private output-handle pointer");
            azihsm_handle pub_key_handle = 0;
            err = azihsm_key_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &unwrap_inputs.wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list,
                nullptr,
                &pub_key_handle
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(pub_key_handle, 0);
        }

        {
            SCOPED_TRACE("null public output-handle pointer");
            azihsm_handle priv_key_handle = 0;
            err = azihsm_key_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &unwrap_inputs.wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list,
                &priv_key_handle,
                nullptr
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(priv_key_handle, 0);
        }

        {
            SCOPED_TRACE("aliasing private/public output-handle pointers");
            azihsm_handle key_handle = 0;
            err = azihsm_key_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &unwrap_inputs.wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list,
                &key_handle,
                &key_handle
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(key_handle, 0);
        }
    });
}

// Verifies unwrap failure paths do not leak partial outputs into caller-provided handles.
TEST_F(azihsm_ecc_keygen, unwrap_pair_preserves_zero_output_handles_on_failure)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0x77);
        unwrap_inputs.unwrap_algo.id = static_cast<azihsm_algo_id>(0xFFFFFFFF);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
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
TEST_F(azihsm_ecc_keygen, unwrap_pair_accepts_non_empty_oaep_label_when_matched)
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
TEST_F(azihsm_ecc_keygen, unwrap_pair_accepts_null_oaep_label_when_matched)
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
TEST_F(azihsm_ecc_keygen, unwrap_pair_accepts_supported_aes_key_bits)
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
TEST_F(azihsm_ecc_keygen, unwrap_pair_accepts_oaep_sha256_mgf1_sha256)
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
TEST_F(azihsm_ecc_keygen, unwrap_pair_accepts_oaep_sha384_mgf1_sha384)
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
TEST_F(azihsm_ecc_keygen, unwrap_pair_accepts_oaep_sha512_mgf1_sha512)
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
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_null_oaep_params_pointer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        unwrap_inputs.unwrap_params.oaep_params = nullptr;

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects unsupported OAEP hash identifiers.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_unsupported_oaep_hash)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        unwrap_inputs.oaep_params.hash_algo_id = static_cast<azihsm_algo_id>(0xFFFFFFFF);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects unsupported OAEP MGF1 identifiers.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_unsupported_oaep_mgf1)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        unwrap_inputs.oaep_params.mgf1_hash_algo_id = static_cast<azihsm_mgf1_id>(0xFFFFFFFF);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects unsupported RSA-AES key-wrap AES key sizes.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_unsupported_aes_key_bits)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        unwrap_inputs.unwrap_params.aes_key_bits = 129;

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects OAEP hash/MGF1 mixed-strength combinations when unsupported.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_oaep_mixed_hash_mgf1_combo)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        unwrap_inputs.oaep_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
        unwrap_inputs.oaep_params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA512;

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects malformed OAEP label pointer/length shapes.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_invalid_oaep_label_shape)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        azihsm_buffer invalid_label{};
        invalid_label.ptr = nullptr;
        invalid_label.len = 1;
        unwrap_inputs.oaep_params.label = &invalid_label;

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
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
    azihsm_ecc_keygen,
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
TEST_F(azihsm_ecc_keygen, unwrap_pair_accepts_empty_oaep_label_when_matched)
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
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_algorithm_param_layout_mismatch)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        // Intentional mismatch: keep algo.id=RSA_AES_KEY_WRAP, but point params/len to the
        // nested OAEP params struct instead of azihsm_algo_rsa_aes_key_wrap_params.
        unwrap_inputs.unwrap_algo.params = &unwrap_inputs.oaep_params;
        unwrap_inputs.unwrap_algo.len = sizeof(unwrap_inputs.oaep_params);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects null algo.params pointer when algo.len is non-zero.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_null_algo_params_with_nonzero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        unwrap_inputs.unwrap_algo.params = nullptr;
        unwrap_inputs.unwrap_algo.len = sizeof(unwrap_inputs.unwrap_params);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies unwrap rejects non-null algo.params pointer when algo.len is zero.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_non_null_algo_params_with_zero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        unwrap_inputs.unwrap_algo.len = 0;

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies unwrap rejects algo.len smaller than expected unwrap-parameter structure size.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_algo_len_too_small_for_unwrap_params)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        unwrap_inputs.unwrap_algo.len = sizeof(unwrap_inputs.unwrap_params) - 1;

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies unwrap rejects algo.len larger than expected when trailing parameter bytes are present.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_algo_len_with_trailing_parameter_bytes)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        unwrap_inputs.unwrap_algo.len = sizeof(unwrap_inputs.unwrap_params) + 1;

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies unwrap rejects null algo.params pointer with zero algo.len for unwrap API.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_null_algo_params_with_zero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        unwrap_inputs.unwrap_algo.params = nullptr;
        unwrap_inputs.unwrap_algo.len = 0;

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies unwrap rejects unsupported unwrap algorithm IDs.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_unsupported_algorithm_id)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xAB);
        unwrap_inputs.unwrap_algo.id = static_cast<azihsm_algo_id>(0xFFFFFFFF);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_UNSUPPORTED_ALGORITHM);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// ----- Unwrapping Key Argument Validation -----

// Verifies unwrap rejects invalid or wrong-type unwrapping key handles.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_invalid_unwrap_key_handles)
{
    RsaAesUnwrapPairInputs unwrap_inputs(0xAB);

    DummyEccPrivKeyProps priv_props;
    DummyEccPubKeyProps pub_props;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();

    auto result = try_unwrap_pair(
        &unwrap_inputs.unwrap_algo,
        0xDEADBEEF,
        &unwrap_inputs.wrapped_key_buf,
        &priv_prop_list,
        &pub_prop_list
    );
    ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
    ASSERT_EQ(result.private_key, 0);
    ASSERT_EQ(result.public_key, 0);
}

// Verifies unwrap rejects zero-valued unwrapping key handle.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_zero_unwrap_key_handle)
{
    RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

    DummyEccPrivKeyProps priv_props;
    DummyEccPubKeyProps pub_props;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();

    auto result = try_unwrap_pair(
        &unwrap_inputs.unwrap_algo,
        0,
        &unwrap_inputs.wrapped_key_buf,
        &priv_prop_list,
        &pub_prop_list
    );
    ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
    ASSERT_EQ(result.private_key, 0);
    ASSERT_EQ(result.public_key, 0);
}

// Verifies unwrap rejects random non-existent unwrapping key handle values.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_random_nonexistent_unwrap_key_handle)
{
    RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

    DummyEccPrivKeyProps priv_props;
    DummyEccPubKeyProps pub_props;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();

    auto result = try_unwrap_pair(
        &unwrap_inputs.unwrap_algo,
        0xABCDEF01,
        &unwrap_inputs.wrapped_key_buf,
        &priv_prop_list,
        &pub_prop_list
    );
    ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
    ASSERT_EQ(result.private_key, 0);
    ASSERT_EQ(result.public_key, 0);
}

// Verifies unwrap rejects unwrapping key handles of the wrong handle type.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_unwrap_key_wrong_handle_type)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            session,
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects RSA public-key handles as unwrapping keys.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_unwrap_key_public_rsa_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_pub_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects non-RSA private-key handles used as unwrapping keys.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_unwrapping_key_private_non_rsa_kind)
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

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            ecc_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects a stale/deleted unwrapping key handle.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_stale_unwrap_key_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        const auto stale_unwrap_key = rsa_priv_key.release();
        ASSERT_EQ(azihsm_key_delete(stale_unwrap_key), AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            stale_unwrap_key,
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects an unwrapping key handle from the wrong partition/session context.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_cross_partition_unwrap_key_handle)
{
    if (part_list_.count() < 2u)
    {
        GTEST_SKIP() << "requires at least two partitions for cross-partition unwrap-key semantics";
    }

    auto source_path = part_list_.get_path(0);
    auto other_path = part_list_.get_path(1);

    auto source_partition = PartitionHandle(source_path);
    auto other_partition = PartitionHandle(other_path);

    auto_key source_unwrap_priv_key;
    std::vector<uint8_t> wrapped_blob;

    // Step 1: Build unwrap key and wrapped payload in source partition.
    {
        SessionHandle source_session(source_partition.get());
        auto_key source_wrap_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            source_session.get(),
            source_unwrap_priv_key.get_ptr(),
            source_wrap_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        err = make_wrapped_ecc_pkcs8_blob(
            source_wrap_pub_key.get(),
            AZIHSM_ECC_CURVE_P256,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());
    }

    // Step 2: Attempt unwrap using source key handle in a different partition context.
    {
        SessionHandle other_session(other_partition.get());
        (void)other_session;

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
            source_unwrap_priv_key.get(),
            &wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    }
}

// Verifies unwrap rejects an unwrapping key handle from the wrong session in the same partition.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_cross_session_unwrap_key_handle)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        auto_key owner_unwrap_priv_key;
        std::vector<uint8_t> wrapped_blob;

        // Step 1: Build unwrap key and wrapped payload in owner session.
        {
            SessionHandle owner_session(partition.get());
            auto_key owner_wrap_pub_key;
            auto err = generate_rsa_unwrapping_keypair(
                owner_session.get(),
                owner_unwrap_priv_key.get_ptr(),
                owner_wrap_pub_key.get_ptr()
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            err = make_wrapped_ecc_pkcs8_blob(
                owner_wrap_pub_key.get(),
                AZIHSM_ECC_CURVE_P256,
                RsaAesWrapConfig{},
                wrapped_blob
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_FALSE(wrapped_blob.empty());
        }

        // Step 2: Attempt unwrap from a different session context.
        {
            SessionHandle other_session(partition.get());

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
                owner_unwrap_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

// ----- Wrapped Key Argument Validation -----

// Verifies unwrap rejects invalid wrapped-key buffer pointer/length shapes.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_invalid_wrapped_key_buffer_shape)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        {
            SCOPED_TRACE("null pointer with non-zero len");
            azihsm_buffer wrapped_key_buf{};
            wrapped_key_buf.ptr = nullptr;
            wrapped_key_buf.len = 1;

            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("non-null pointer with zero len");
            uint8_t byte = 0;
            azihsm_buffer wrapped_key_buf{};
            wrapped_key_buf.ptr = &byte;
            wrapped_key_buf.len = 0;

            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

// Verifies unwrap rejects a null wrapped_key pointer.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_null_wrapped_key_pointer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            nullptr,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects an empty wrapped blob represented as null pointer + zero length.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_null_wrapped_key_with_zero_length)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = nullptr;
        wrapped_key_buf.len = 0;

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects wrapped blob truncated by a single byte.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_truncated_blob_by_single_byte)
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
        ASSERT_GT(wrapped_blob.size(), 1u);

        wrapped_blob.pop_back();

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
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects wrapped blob truncated by a larger chunk.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_truncated_blob_by_chunk)
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
            AZIHSM_ECC_CURVE_P384,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(wrapped_blob.size(), 16u);

        wrapped_blob.resize(wrapped_blob.size() - 16);

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = wrapped_blob.data();
        wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        RsaAesUnwrapAlgo unwrap_algo{};

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.ecc_curve = AZIHSM_ECC_CURVE_P384;
        pub_props.ecc_curve = AZIHSM_ECC_CURVE_P384;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            rsa_priv_key.get(),
            &wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Security contract: wrapped blobs must be fully consumed; trailing bytes are rejected.
// Verifies unwrap rejects wrapped blobs when trailing garbage bytes are appended.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_wrapped_key_with_trailing_bytes)
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

        std::vector<uint8_t> mutated = wrapped_blob;
        mutated.push_back(0xAA);
        mutated.push_back(0x55);
        const auto before = mutated;

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = mutated.data();
        wrapped_key_buf.len = static_cast<uint32_t>(mutated.size());

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
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
        ASSERT_EQ(mutated, before);
    });
}

// Verifies unwrap rejects corrupted wrapped blob metadata/integrity.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_corrupted_wrapped_blob_integrity)
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
        ASSERT_GT(wrapped_blob.size(), 2u);

        std::vector<uint8_t> mutated = wrapped_blob;
        mutated[mutated.size() / 2] ^= 0x01;

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = mutated.data();
        wrapped_key_buf.len = static_cast<uint32_t>(mutated.size());

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
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects multi-byte corruption patterns across blob regions.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_multi_byte_blob_corruption_patterns)
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
        ASSERT_GT(wrapped_blob.size(), 3u);

        RsaAesUnwrapAlgo unwrap_algo{};

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        const std::vector<size_t> offsets = { 0, wrapped_blob.size() / 2, wrapped_blob.size() - 1 };
        for (size_t offset : offsets)
        {
            SCOPED_TRACE("offset=" + std::to_string(offset));
            std::vector<uint8_t> mutated = wrapped_blob;
            mutated[offset] ^= 0xA5;
            mutated[(offset + 1) % mutated.size()] ^= 0x5A;

            azihsm_buffer wrapped_key_buf{};
            wrapped_key_buf.ptr = mutated.data();
            wrapped_key_buf.len = static_cast<uint32_t>(mutated.size());

            auto result = try_unwrap_pair(
                &unwrap_algo.algo,
                rsa_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

// ----- Private/Public Property Argument Validation -----

// Verifies unwrap preserves requested SESSION flag for session-key imports.
TEST_F(azihsm_ecc_keygen, unwrap_pair_preserves_session_flag_set)
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

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = wrapped_blob.data();
        wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        RsaAesUnwrapAlgo unwrap_algo{};

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.is_session = 1;
        pub_props.is_session = 1;
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

        auto_key imported_private_key;
        auto_key imported_public_key;
        imported_private_key.handle = result.private_key;
        imported_public_key.handle = result.public_key;

        uint8_t private_session = 0;
        uint8_t public_session = 0;
        ASSERT_EQ(get_key_prop(imported_private_key.get(), AZIHSM_KEY_PROP_ID_SESSION, private_session), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(get_key_prop(imported_public_key.get(), AZIHSM_KEY_PROP_ID_SESSION, public_session), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(private_session, 1);
        ASSERT_EQ(public_session, 1);
    });
}

// Verifies unwrap preserves requested SESSION flag for persistent/token-key imports.
TEST_F(azihsm_ecc_keygen, unwrap_pair_preserves_session_flag_cleared)
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

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = wrapped_blob.data();
        wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        RsaAesUnwrapAlgo unwrap_algo{};

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.is_session = 0;
        pub_props.is_session = 0;
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

        auto_key imported_private_key;
        auto_key imported_public_key;
        imported_private_key.handle = result.private_key;
        imported_public_key.handle = result.public_key;

        uint8_t private_session = 1;
        uint8_t public_session = 1;
        ASSERT_EQ(get_key_prop(imported_private_key.get(), AZIHSM_KEY_PROP_ID_SESSION, private_session), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(get_key_prop(imported_public_key.get(), AZIHSM_KEY_PROP_ID_SESSION, public_session), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(private_session, 0);
        ASSERT_EQ(public_session, 0);
    });
}

// Verifies unwrap rejects malformed or invalid private-key property lists.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_invalid_private_property_list)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPubKeyProps pub_props;
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_key_prop_list malformed_priv_list{};
        malformed_priv_list.props = nullptr;
        malformed_priv_list.count = 1;

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &malformed_priv_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects private CLASS set to PUBLIC.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_private_class_set_to_public)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.key_class = AZIHSM_KEY_CLASS_PUBLIC;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects private KIND set to non-ECC.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_private_kind_not_ecc)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.key_kind = AZIHSM_KEY_KIND_RSA;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects malformed or invalid public-key property lists.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_invalid_public_property_list)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        auto priv_prop_list = priv_props.get_prop_list();

        azihsm_key_prop_list malformed_pub_list{};
        malformed_pub_list.props = nullptr;
        malformed_pub_list.count = 1;

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &malformed_pub_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects public CLASS set to PRIVATE.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_public_class_set_to_private)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        pub_props.key_class = AZIHSM_KEY_CLASS_PRIVATE;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects public KIND set to non-ECC.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_public_kind_not_ecc)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        pub_props.key_kind = AZIHSM_KEY_KIND_RSA;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects private VERIFY-only capability without SIGN.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_private_verify_without_sign)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        remove_prop_by_id(priv_props.props, AZIHSM_KEY_PROP_ID_SIGN);
        priv_props.props.push_back(
            { AZIHSM_KEY_PROP_ID_VERIFY, &priv_props.can_sign, sizeof(priv_props.can_sign) }
        );

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects public SIGN-only capability without VERIFY.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_public_sign_without_verify)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        remove_prop_by_id(pub_props.props, AZIHSM_KEY_PROP_ID_VERIFY);
        pub_props.props.push_back(
            { AZIHSM_KEY_PROP_ID_SIGN, &pub_props.can_verify, sizeof(pub_props.can_verify) }
        );

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects duplicate/conflicting property IDs in unwrap property lists.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_duplicate_or_conflicting_property_ids)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        {
            SCOPED_TRACE("duplicate private property id");
            DummyEccPrivKeyProps priv_props;
            DummyEccPubKeyProps pub_props;
            priv_props.props.push_back(
                { AZIHSM_KEY_PROP_ID_EC_CURVE, &priv_props.ecc_curve, sizeof(priv_props.ecc_curve) }
            );

            auto priv_prop_list = priv_props.get_prop_list();
            auto pub_prop_list = pub_props.get_prop_list();

            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &unwrap_inputs.wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("conflicting public property value");
            DummyEccPrivKeyProps priv_props;
            DummyEccPubKeyProps pub_props;
            uint8_t conflicting_verify = 0;
            pub_props.props.push_back(
                { AZIHSM_KEY_PROP_ID_VERIFY, &conflicting_verify, sizeof(conflicting_verify) }
            );

            auto priv_prop_list = priv_props.get_prop_list();
            auto pub_prop_list = pub_props.get_prop_list();

            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &unwrap_inputs.wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

// Verifies unwrap rejects malformed property value shapes in unwrap lists.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_property_null_value_nonzero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        {
            SCOPED_TRACE("private property null value non-zero len");
            DummyEccPrivKeyProps priv_props;
            DummyEccPubKeyProps pub_props;
            priv_props.props[0].val = nullptr;
            priv_props.props[0].len = 1;

            auto priv_prop_list = priv_props.get_prop_list();
            auto pub_prop_list = pub_props.get_prop_list();

            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &unwrap_inputs.wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("public property null value non-zero len");
            DummyEccPrivKeyProps priv_props;
            DummyEccPubKeyProps pub_props;
            pub_props.props[0].val = nullptr;
            pub_props.props[0].len = 1;

            auto priv_prop_list = priv_props.get_prop_list();
            auto pub_prop_list = pub_props.get_prop_list();

            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &unwrap_inputs.wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

// Verifies unwrap rejects property length mismatches in unwrap lists.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_property_length_mismatch)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.props[0].len = 1;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects private required-property omissions (table-driven, non-exhaustive).
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_private_missing_required_properties_table)
{
    RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

    const std::vector<azihsm_key_prop_id> required_private_props = {
        AZIHSM_KEY_PROP_ID_CLASS,
        AZIHSM_KEY_PROP_ID_KIND,
        AZIHSM_KEY_PROP_ID_EC_CURVE,
        AZIHSM_KEY_PROP_ID_SESSION,
        AZIHSM_KEY_PROP_ID_SIGN,
    };

    for (const auto missing_prop_id : required_private_props)
    {
        SCOPED_TRACE("Missing private unwrap property id=" + std::to_string(missing_prop_id));

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;

        remove_prop_by_id(priv_props.props, missing_prop_id);

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            0,
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(priv_key_handle, 0);
        ASSERT_EQ(pub_key_handle, 0);
    }
}

// Verifies unwrap rejects public required-property omissions (table-driven, non-exhaustive).
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_public_missing_required_properties_table)
{
    RsaAesUnwrapPairInputs unwrap_inputs(0x5A);

    const std::vector<azihsm_key_prop_id> required_public_props = {
        AZIHSM_KEY_PROP_ID_CLASS,
        AZIHSM_KEY_PROP_ID_KIND,
        AZIHSM_KEY_PROP_ID_EC_CURVE,
        AZIHSM_KEY_PROP_ID_SESSION,
        AZIHSM_KEY_PROP_ID_VERIFY,
    };

    for (const auto missing_prop_id : required_public_props)
    {
        SCOPED_TRACE("Missing public unwrap property id=" + std::to_string(missing_prop_id));

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;

        remove_prop_by_id(pub_props.props, missing_prop_id);

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            0,
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(priv_key_handle, 0);
        ASSERT_EQ(pub_key_handle, 0);
    }
}

// Verifies representative private/public property combinations are rejected for unwrap.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_invalid_property_combinations_table)
{
    RsaAesUnwrapPairInputs unwrap_inputs(0xCC);

    {
        SCOPED_TRACE("Unwrap rejects curve mismatch between private/public properties");
        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        pub_props.ecc_curve = AZIHSM_ECC_CURVE_P384;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            0,
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(priv_key_handle, 0);
        ASSERT_EQ(pub_key_handle, 0);
    }

    {
        SCOPED_TRACE("Unwrap rejects session mismatch between private/public properties");
        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        pub_props.is_session = 0;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            0,
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(priv_key_handle, 0);
        ASSERT_EQ(pub_key_handle, 0);
    }

    {
        SCOPED_TRACE("Unwrap rejects private/public kind mismatch");
        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        pub_props.key_kind = AZIHSM_KEY_KIND_RSA;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            0,
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(priv_key_handle, 0);
        ASSERT_EQ(pub_key_handle, 0);
    }
}

// ----- Cross-Argument Wrapped Payload Semantics -----

// Verifies unwrap rejects malformed wrapped key-pair blob content.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_invalid_wrapped_blob_shapes)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        {
            SCOPED_TRACE("empty buffer (non-null ptr, zero len)");
            uint8_t b = 0;
            azihsm_buffer wrapped_key_buf{};
            wrapped_key_buf.ptr = &b;
            wrapped_key_buf.len = 0;

            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("minimal one-byte blob");
            uint8_t b = 0x01;
            azihsm_buffer wrapped_key_buf{};
            wrapped_key_buf.ptr = &b;
            wrapped_key_buf.len = 1;

            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("null ptr, non-zero len");
            azihsm_buffer wrapped_key_buf{};
            wrapped_key_buf.ptr = nullptr;
            wrapped_key_buf.len = 4;

            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

// Verifies unwrap rejects wrapped payloads that encode a single key instead of a key pair.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_wrapped_single_key_payload_for_pair_unwrap)
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
        azihsm_key_prop_list aes_prop_list{ aes_props.data(), static_cast<uint32_t>(aes_props.size()) };

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

        // Step 3: key_unwrap_pair should reject the same bytes because pair-shaped content is required.
        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
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
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_blob_wrapped_by_different_wrapping_key)
{
    if (part_list_.count() < 2u)
    {
        GTEST_SKIP() << "requires at least two partitions to guarantee distinct wrapping-key contexts";
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
    DummyEccPrivKeyProps priv_props;
    DummyEccPubKeyProps pub_props;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();

    auto result = try_unwrap_pair(
        &unwrap_algo.algo,
        wrapping_priv_key_b.get(),
        &wrapped_key_buf,
        &priv_prop_list,
        &pub_prop_list
    );
    ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(result.private_key, 0);
    ASSERT_EQ(result.public_key, 0);
}

// Verifies unwrap does not mutate caller-provided wrapped blob on failure.
TEST_F(azihsm_ecc_keygen, unwrap_pair_preserves_input_wrapped_blob_on_failure)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Deliberately malformed/truncated test payload used only to verify failure-path immutability.
        std::vector<uint8_t> wrapped_data = make_deterministic_payload(0x01, 0x01, 5);
        const auto before = wrapped_data;

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        unwrap_inputs.wrapped_key_buf.ptr = wrapped_data.data();
        unwrap_inputs.wrapped_key_buf.len = static_cast<uint32_t>(wrapped_data.size());

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
        ASSERT_EQ(wrapped_data, before);
    });
}

// Verifies unwrap rejects requested curve/capability props that mismatch wrapped content.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_requested_curve_or_capability_mismatch)
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

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = wrapped_blob.data();
        wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        RsaAesUnwrapAlgo unwrap_algo{};

        {
            SCOPED_TRACE("requested curve mismatches wrapped ECC key curve");
            DummyEccPrivKeyProps priv_props;
            DummyEccPubKeyProps pub_props;
            priv_props.ecc_curve = AZIHSM_ECC_CURVE_P384;
            pub_props.ecc_curve = AZIHSM_ECC_CURVE_P384;

            auto priv_prop_list = priv_props.get_prop_list();
            auto pub_prop_list = pub_props.get_prop_list();

            auto result = try_unwrap_pair(
                &unwrap_algo.algo,
                rsa_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("requested capability mismatch/invalid capability combination");
            DummyEccPrivKeyProps priv_props;
            DummyEccPubKeyProps pub_props;
            priv_props.can_sign = 0;

            auto priv_prop_list = priv_props.get_prop_list();
            auto pub_prop_list = pub_props.get_prop_list();

            auto result = try_unwrap_pair(
                &unwrap_algo.algo,
                rsa_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

// Verifies unwrap rejects wrapped content whose kind conflicts with requested ECC properties.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_wrapped_content_kind_mismatch)
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

        // Step 1: Build transport-valid wrapped bytes where plaintext is arbitrary non-ECC key material.
        // This is the kind-mismatch mechanism: unwrap props request ECC pair, but payload encodes no ECC pair.
        const auto non_ecc_payload = make_deterministic_payload(0x01, 0x02, 16);

        std::vector<uint8_t> wrapped_blob;
        err = wrap_plaintext_with_rsa_aes(
            rsa_wrap_pub_key.get(),
            non_ecc_payload,
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

        // Step 2: pair unwrap rejects because payload content kind does not match requested ECC-pair semantics.
        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            rsa_unwrap_priv_key.get(),
            &wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects wrapped content whose encoded curve conflicts with requested curve.
TEST_F(azihsm_ecc_keygen, unwrap_pair_rejects_wrapped_content_curve_mismatch)
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
            AZIHSM_ECC_CURVE_P384,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = wrapped_blob.data();
        wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        RsaAesUnwrapAlgo unwrap_algo{};

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.ecc_curve = AZIHSM_ECC_CURVE_P521;
        pub_props.ecc_curve = AZIHSM_ECC_CURVE_P521;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            rsa_priv_key.get(),
            &wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}


