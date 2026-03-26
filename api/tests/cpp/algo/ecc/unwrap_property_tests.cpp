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

class azihsm_ecc_keyunwrap_property : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};
// Helper: unwraps a wrapped ECC key pair for the given curve and verifies the
// imported keys preserve the requested properties (CLASS, KIND, EC_CURVE,
// SESSION, SIGN/VERIFY).
static void verify_unwrap_pair_preserves_properties(
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

        ctx.priv_props.ecc_curve = curve;
        ctx.pub_props.ecc_curve = curve;

        auto result = ctx.try_unwrap();
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
        ASSERT_EQ(private_curve, curve);
        ASSERT_EQ(private_session, ctx.priv_props.is_session);
        ASSERT_EQ(private_sign, ctx.priv_props.can_sign);

        ASSERT_EQ(public_class, AZIHSM_KEY_CLASS_PUBLIC);
        ASSERT_EQ(public_kind, AZIHSM_KEY_KIND_ECC);
        ASSERT_EQ(public_curve, curve);
        ASSERT_EQ(public_session, ctx.pub_props.is_session);
        ASSERT_EQ(public_verify, ctx.pub_props.can_verify);
    });
}

// P-256: unwrapped keys preserve all requested properties.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_preserves_properties_p256)
{
    verify_unwrap_pair_preserves_properties(part_list_, AZIHSM_ECC_CURVE_P256);
}

// P-384: unwrapped keys preserve all requested properties.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_preserves_properties_p384)
{
    verify_unwrap_pair_preserves_properties(part_list_, AZIHSM_ECC_CURVE_P384);
}

// P-521: unwrapped keys preserve all requested properties.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_preserves_properties_p521)
{
    verify_unwrap_pair_preserves_properties(part_list_, AZIHSM_ECC_CURVE_P521);
}

// ==================== key_unwrap_pair: Property Argument Validation ====================

// ----- Private/Public Property Argument Validation -----

// Verifies unwrap preserves requested SESSION flag for session-key imports.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_preserves_session_flag_set)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        ctx.priv_props.is_session = 1;
        ctx.pub_props.is_session = 1;

        auto result = ctx.try_unwrap();
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
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_preserves_session_flag_cleared)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(
            UnwrapPairContext::create_with_wrapped_blob(session, AZIHSM_ECC_CURVE_P256, ctx),
            AZIHSM_STATUS_SUCCESS
        );

        ctx.priv_props.is_session = 0;
        ctx.pub_props.is_session = 0;

        auto result = ctx.try_unwrap();
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
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_invalid_private_property_list)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        auto pub_prop_list = ctx.pub_props.get_prop_list();

        azihsm_key_prop_list malformed_priv_list{};
        malformed_priv_list.props = nullptr;
        malformed_priv_list.count = 1;

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            ctx.rsa_priv_key.get(),
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
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_private_class_set_to_public)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        ctx.priv_props.key_class = AZIHSM_KEY_CLASS_PUBLIC;

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects private KIND set to non-ECC.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_private_kind_not_ecc)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        ctx.priv_props.key_kind = AZIHSM_KEY_KIND_RSA;

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects malformed or invalid public-key property lists.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_invalid_public_property_list)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        auto priv_prop_list = ctx.priv_props.get_prop_list();

        azihsm_key_prop_list malformed_pub_list{};
        malformed_pub_list.props = nullptr;
        malformed_pub_list.count = 1;

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            ctx.rsa_priv_key.get(),
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
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_public_class_set_to_private)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        ctx.pub_props.key_class = AZIHSM_KEY_CLASS_PRIVATE;

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects public KIND set to non-ECC.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_public_kind_not_ecc)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        ctx.pub_props.key_kind = AZIHSM_KEY_KIND_RSA;

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects private VERIFY-only capability without SIGN.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_private_verify_without_sign)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        remove_prop_by_id(ctx.priv_props.props, AZIHSM_KEY_PROP_ID_SIGN);
        ctx.priv_props.props.push_back(
            { AZIHSM_KEY_PROP_ID_VERIFY, &ctx.priv_props.can_sign, sizeof(ctx.priv_props.can_sign) }
        );

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects public SIGN-only capability without VERIFY.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_public_sign_without_verify)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        remove_prop_by_id(ctx.pub_props.props, AZIHSM_KEY_PROP_ID_VERIFY);
        ctx.pub_props.props.push_back(
            { AZIHSM_KEY_PROP_ID_SIGN, &ctx.pub_props.can_verify, sizeof(ctx.pub_props.can_verify) }
        );

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects duplicate property IDs in private property list.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_duplicate_private_property_id)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        ctx.priv_props.props.push_back(
            { AZIHSM_KEY_PROP_ID_EC_CURVE, &ctx.priv_props.ecc_curve, sizeof(ctx.priv_props.ecc_curve) }
        );

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects conflicting property values in public property list.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_conflicting_public_property_value)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        uint8_t conflicting_verify = 0;
        ctx.pub_props.props.push_back(
            { AZIHSM_KEY_PROP_ID_VERIFY, &conflicting_verify, sizeof(conflicting_verify) }
        );

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects private property with null value and non-zero length.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_private_property_null_value_nonzero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        ctx.priv_props.props[0].val = nullptr;
        ctx.priv_props.props[0].len = 1;

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects public property with null value and non-zero length.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_public_property_null_value_nonzero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        ctx.pub_props.props[0].val = nullptr;
        ctx.pub_props.props[0].len = 1;

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects property length mismatches in unwrap lists.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_property_length_mismatch)
{
    part_list_.for_each_session([](azihsm_handle session) {
        UnwrapPairContext ctx;
        ASSERT_EQ(UnwrapPairContext::create(session, ctx), AZIHSM_STATUS_SUCCESS);

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        ctx.priv_props.props[0].len = 1;

        auto result = ctx.try_unwrap_inputs(unwrap_inputs);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects private required-property omissions (table-driven, non-exhaustive).
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_private_missing_required_properties_table)
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
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;

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
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS)
            << "expected failure for missing private prop id=" << missing_prop_id;
        ASSERT_EQ(priv_key_handle, 0);
        ASSERT_EQ(pub_key_handle, 0);
    }
}

// Verifies unwrap rejects public required-property omissions (table-driven, non-exhaustive).
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_public_missing_required_properties_table)
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
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;

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
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS)
            << "expected failure for missing public prop id=" << missing_prop_id;
        ASSERT_EQ(priv_key_handle, 0);
        ASSERT_EQ(pub_key_handle, 0);
    }
}

// Verifies unwrap rejects curve mismatch between private/public properties.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_curve_mismatch_between_priv_pub)
{
    RsaAesUnwrapPairInputs unwrap_inputs(0xCC);
    DefaultEccPrivKeyProps priv_props;
    DefaultEccPubKeyProps pub_props;
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

// Verifies unwrap rejects session mismatch between private/public properties.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_session_mismatch_between_priv_pub)
{
    RsaAesUnwrapPairInputs unwrap_inputs(0xCC);
    DefaultEccPrivKeyProps priv_props;
    DefaultEccPubKeyProps pub_props;
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

// Verifies unwrap rejects kind mismatch between private/public properties.
TEST_F(azihsm_ecc_keyunwrap_property, unwrap_pair_rejects_kind_mismatch_between_priv_pub)
{
    RsaAesUnwrapPairInputs unwrap_inputs(0xCC);
    DefaultEccPrivKeyProps priv_props;
    DefaultEccPubKeyProps pub_props;
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
