// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <algorithm>
#include <cstring>
#include <exception>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_key.hpp"
#include "utils/rsa_keygen.hpp"

// This file covers ECC key_gen_pair API behavior:
// - key generation argument validation,
// - private/public property validation,
// - and cross-argument semantics for generation-only flows.

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

namespace
{
// Builds the EC key-pair generation algorithm descriptor used by azihsm_key_gen_pair.
azihsm_algo make_ec_keygen_algo()
{
    azihsm_algo keygen_algo{};
    keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;
    return keygen_algo;
}

} // namespace

// ==================== key_gen_pair ====================

// ----- Positive Paths -----

// Verifies ECC key-pair generation succeeds for each supported curve.
TEST_F(azihsm_ecc_keygen, key_gen_pair_all_curves)
{
    std::vector<KeygenTestParams> test_cases = {
        { AZIHSM_ECC_CURVE_P256, "P256" },
        { AZIHSM_ECC_CURVE_P384, "P384" },
        { AZIHSM_ECC_CURVE_P521, "P521" },
    };

    for (const auto &test_case : test_cases)
    {
        SCOPED_TRACE("Testing key generation with " + std::string(test_case.test_name));

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

            auto delete_priv_err = azihsm_key_delete(priv_key.get());
            ASSERT_EQ(delete_priv_err, AZIHSM_STATUS_SUCCESS);
            priv_key.release();

            auto delete_pub_err = azihsm_key_delete(pub_key.get());
            ASSERT_EQ(delete_pub_err, AZIHSM_STATUS_SUCCESS);
            pub_key.release();
        });
    }
}

// ----- Mandatory Pointers and Output Handles -----

// Verifies null algorithm pointer is rejected for key-pair generation.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_null_algorithm)
{
    part_list_.for_each_session([](azihsm_handle session) {
        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto err = azihsm_key_gen_pair(
            session,
            nullptr,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies null private-key property list is rejected.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_null_private_props)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPubKeyProps pub_props;
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            nullptr,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies null public-key property list is rejected.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_null_public_props)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        auto priv_prop_list = priv_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            nullptr,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies key generation rejects null/aliasing output-handle configurations.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_invalid_output_handle_configurations)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        {
            SCOPED_TRACE("null private output handle pointer");
            azihsm_handle pub_key_handle = 0;
            auto err = azihsm_key_gen_pair(
                session,
                &keygen_algo,
                &priv_prop_list,
                &pub_prop_list,
                nullptr,
                &pub_key_handle
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(pub_key_handle, 0);
        }

        {
            SCOPED_TRACE("null public output handle pointer");
            azihsm_handle priv_key_handle = 0;
            auto err = azihsm_key_gen_pair(
                session,
                &keygen_algo,
                &priv_prop_list,
                &pub_prop_list,
                &priv_key_handle,
                nullptr
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(priv_key_handle, 0);
        }

        {
            SCOPED_TRACE("aliasing private/public output handle pointers");
            azihsm_handle key_handle = 0;
            auto err = azihsm_key_gen_pair(
                session,
                &keygen_algo,
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

// Verifies key generation failure paths preserve zeroed caller output handles.
TEST_F(azihsm_ecc_keygen, key_gen_pair_preserves_zero_output_handles_on_failure)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.ecc_curve = static_cast<uint32_t>(0xFFFFFFFF);

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(priv_key_handle, 0);
        ASSERT_EQ(pub_key_handle, 0);
    });
}

// ----- Session Argument Validation -----

// Verifies an invalid session handle is rejected.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_invalid_session_handle)
{
    auto keygen_algo = make_ec_keygen_algo();

    DummyEccPrivKeyProps priv_props;
    DummyEccPubKeyProps pub_props;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();

    azihsm_handle priv_key_handle = 0;
    azihsm_handle pub_key_handle = 0;

    auto err = azihsm_key_gen_pair(
        0xDEADBEEF,
        &keygen_algo,
        &priv_prop_list,
        &pub_prop_list,
        &priv_key_handle,
        &pub_key_handle
    );
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
}

// Verifies key generation rejects a zero-valued session handle.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_zero_session_handle)
{
    auto keygen_algo = make_ec_keygen_algo();

    DummyEccPrivKeyProps priv_props;
    DummyEccPubKeyProps pub_props;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();

    azihsm_handle priv_key_handle = 0;
    azihsm_handle pub_key_handle = 0;

    auto err = azihsm_key_gen_pair(
        0,
        &keygen_algo,
        &priv_prop_list,
        &pub_prop_list,
        &priv_key_handle,
        &pub_key_handle
    );
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    ASSERT_EQ(priv_key_handle, 0);
    ASSERT_EQ(pub_key_handle, 0);
}

// Verifies key generation rejects random non-existent session handle values.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_random_nonexistent_session_handle)
{
    auto keygen_algo = make_ec_keygen_algo();

    DummyEccPrivKeyProps priv_props;
    DummyEccPubKeyProps pub_props;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();

    azihsm_handle priv_key_handle = 0;
    azihsm_handle pub_key_handle = 0;

    auto err = azihsm_key_gen_pair(
        0xABCDEF01,
        &keygen_algo,
        &priv_prop_list,
        &pub_prop_list,
        &priv_key_handle,
        &pub_key_handle
    );
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
    ASSERT_EQ(priv_key_handle, 0);
    ASSERT_EQ(pub_key_handle, 0);
}

// ----- Algorithm Argument Validation -----

// Verifies unsupported algorithm IDs are rejected by key-pair generation.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_unsupported_algorithm)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();
        keygen_algo.id = static_cast<azihsm_algo_id>(0xFFFFFFFF);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        // Invalid EC curve enum value is rejected at FFI/property parsing boundary as InvalidArgument.
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies key generation rejects null algo.params pointer with non-zero algo.len.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_null_algo_params_with_nonzero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();
        keygen_algo.params = nullptr;
        keygen_algo.len = 1;

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies key generation rejects non-null algo.params pointer with zero algo.len.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_non_null_algo_params_with_zero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();
        uint8_t unexpected_param = 0xA5;
        keygen_algo.params = &unexpected_param;
        keygen_algo.len = 0;

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies key generation rejects non-null algorithm parameters for EC key-pair generation.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_non_null_algo_params_for_ec_key_pair_gen)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();
        uint32_t unexpected_param = 0x12345678;
        keygen_algo.params = &unexpected_param;
        keygen_algo.len = sizeof(unexpected_param);

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// ----- Private/Public Property Argument Validation -----

// Key properties checklist for key_gen_pair coverage:
// - Required IDs on both sides: CLASS, KIND, EC_CURVE, SESSION.
// - Required private/public capabilities: SIGN (private), VERIFY (public).
// - Value integrity: valid enum values and matching private/public curve.
// - Shape integrity: correct val pointer/len and no malformed list entries.
// - Policy integrity: reject duplicates, missing required IDs, and conflicting values.
//
// Strategy note (intentionally non-exhaustive):
// - We use table-driven tests for property omissions and combinations testing.
// - We avoid exhaustive coverage of all possible combinations of properties due to combinatorial explosion, 
//   but we do verify representative combinations of omissions and invalid values.

// Verifies private required property omissions are rejected (table-driven, non-exhaustive).
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_private_missing_required_properties_table)
{
    part_list_.for_each_session([](azihsm_handle session) {
        const std::vector<azihsm_key_prop_id> required_private_props = {
            AZIHSM_KEY_PROP_ID_CLASS,
            AZIHSM_KEY_PROP_ID_KIND,
            AZIHSM_KEY_PROP_ID_EC_CURVE,
            AZIHSM_KEY_PROP_ID_SESSION,
            AZIHSM_KEY_PROP_ID_SIGN,
        };

        for (const auto missing_prop_id : required_private_props)
        {
            SCOPED_TRACE("Missing private property id=" + std::to_string(missing_prop_id));

            auto keygen_algo = make_ec_keygen_algo();

            DummyEccPrivKeyProps priv_props;
            DummyEccPubKeyProps pub_props;

            remove_prop_by_id(priv_props.props, missing_prop_id);

            auto priv_prop_list = priv_props.get_prop_list();
            auto pub_prop_list = pub_props.get_prop_list();

            azihsm_handle priv_key_handle = 0;
            azihsm_handle pub_key_handle = 0;

            auto err = azihsm_key_gen_pair(
                session,
                &keygen_algo,
                &priv_prop_list,
                &pub_prop_list,
                &priv_key_handle,
                &pub_key_handle
            );
            azihsm_status expected = AZIHSM_STATUS_INVALID_KEY_PROPS;
            switch (missing_prop_id)
            {
                case AZIHSM_KEY_PROP_ID_CLASS:
                    expected = AZIHSM_STATUS_KEY_CLASS_NOT_SPECIFIED;
                    break;
                case AZIHSM_KEY_PROP_ID_KIND:
                    expected = AZIHSM_STATUS_KEY_KIND_NOT_SPECIFIED;
                    break;
                case AZIHSM_KEY_PROP_ID_EC_CURVE:
                    expected = AZIHSM_STATUS_PROPERTY_NOT_PRESENT;
                    break;
                default:
                    expected = AZIHSM_STATUS_INVALID_KEY_PROPS;
                    break;
            }
            ASSERT_EQ(err, expected);
        }
    });
}

// Verifies public required property omissions are rejected (table-driven, non-exhaustive).
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_public_missing_required_properties_table)
{
    part_list_.for_each_session([](azihsm_handle session) {
        const std::vector<azihsm_key_prop_id> required_public_props = {
            AZIHSM_KEY_PROP_ID_CLASS,
            AZIHSM_KEY_PROP_ID_KIND,
            AZIHSM_KEY_PROP_ID_EC_CURVE,
            AZIHSM_KEY_PROP_ID_SESSION,
            AZIHSM_KEY_PROP_ID_VERIFY,
        };

        for (const auto missing_prop_id : required_public_props)
        {
            SCOPED_TRACE("Missing public property id=" + std::to_string(missing_prop_id));

            auto keygen_algo = make_ec_keygen_algo();

            DummyEccPrivKeyProps priv_props;
            DummyEccPubKeyProps pub_props;

            remove_prop_by_id(pub_props.props, missing_prop_id);

            auto priv_prop_list = priv_props.get_prop_list();
            auto pub_prop_list = pub_props.get_prop_list();

            azihsm_handle priv_key_handle = 0;
            azihsm_handle pub_key_handle = 0;

            auto err = azihsm_key_gen_pair(
                session,
                &keygen_algo,
                &priv_prop_list,
                &pub_prop_list,
                &priv_key_handle,
                &pub_key_handle
            );
            azihsm_status expected = AZIHSM_STATUS_INVALID_KEY_PROPS;
            switch (missing_prop_id)
            {
                case AZIHSM_KEY_PROP_ID_CLASS:
                    expected = AZIHSM_STATUS_KEY_CLASS_NOT_SPECIFIED;
                    break;
                case AZIHSM_KEY_PROP_ID_KIND:
                    expected = AZIHSM_STATUS_KEY_KIND_NOT_SPECIFIED;
                    break;
                case AZIHSM_KEY_PROP_ID_EC_CURVE:
                    expected = AZIHSM_STATUS_PROPERTY_NOT_PRESENT;
                    break;
                default:
                    expected = AZIHSM_STATUS_INVALID_KEY_PROPS;
                    break;
            }
            ASSERT_EQ(err, expected);
        }
    });
}

// Verifies representative private/public property combinations are rejected,
// including cross-list mismatches for EC_CURVE, SESSION, and KIND.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_invalid_property_combinations_table)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        {
            SCOPED_TRACE("Curve mismatch between private/public properties");
            DummyEccPrivKeyProps priv_props;
            DummyEccPubKeyProps pub_props;
            pub_props.ecc_curve = AZIHSM_ECC_CURVE_P384;

            auto priv_prop_list = priv_props.get_prop_list();
            auto pub_prop_list = pub_props.get_prop_list();

            azihsm_handle priv_key_handle = 0;
            azihsm_handle pub_key_handle = 0;

            auto err = azihsm_key_gen_pair(
                session,
                &keygen_algo,
                &priv_prop_list,
                &pub_prop_list,
                &priv_key_handle,
                &pub_key_handle
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        }

        {
            SCOPED_TRACE("Session mismatch between private/public properties");
            DummyEccPrivKeyProps priv_props;
            DummyEccPubKeyProps pub_props;
            pub_props.is_session = 0;

            auto priv_prop_list = priv_props.get_prop_list();
            auto pub_prop_list = pub_props.get_prop_list();

            azihsm_handle priv_key_handle = 0;
            azihsm_handle pub_key_handle = 0;

            auto err = azihsm_key_gen_pair(
                session,
                &keygen_algo,
                &priv_prop_list,
                &pub_prop_list,
                &priv_key_handle,
                &pub_key_handle
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        }

        {
            SCOPED_TRACE("Kind mismatch between private/public properties");
            DummyEccPrivKeyProps priv_props;
            DummyEccPubKeyProps pub_props;
            pub_props.key_kind = AZIHSM_KEY_KIND_RSA;

            auto priv_prop_list = priv_props.get_prop_list();
            auto pub_prop_list = pub_props.get_prop_list();

            azihsm_handle priv_key_handle = 0;
            azihsm_handle pub_key_handle = 0;

            auto err = azihsm_key_gen_pair(
                session,
                &keygen_algo,
                &priv_prop_list,
                &pub_prop_list,
                &priv_key_handle,
                &pub_key_handle
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        }
    });
}

// Verifies malformed private-key property list layouts are rejected.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_malformed_private_property_list_shape)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPubKeyProps pub_props;
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_key_prop_list malformed_priv_list{};
        malformed_priv_list.props = nullptr;
        malformed_priv_list.count = 1;

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &malformed_priv_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies malformed public-key property list layouts are rejected.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_malformed_public_property_list_shape)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        auto priv_prop_list = priv_props.get_prop_list();

        azihsm_key_prop_list malformed_pub_list{};
        malformed_pub_list.props = nullptr;
        malformed_pub_list.count = 1;

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &malformed_pub_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies invalid ECC curve property values are rejected.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_invalid_curve_property_value)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.ecc_curve = 0xFFFFFFFF;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies private key CLASS must be PRIVATE, not PUBLIC.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_private_class_set_to_public)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.key_class = AZIHSM_KEY_CLASS_PUBLIC;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
    });
}

// Verifies public key CLASS must be PUBLIC, not PRIVATE.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_public_class_set_to_private)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        pub_props.key_class = AZIHSM_KEY_CLASS_PRIVATE;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
    });
}

// Verifies private key KIND must be ECC.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_private_kind_not_ecc)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.key_kind = AZIHSM_KEY_KIND_RSA;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
    });
}

// Verifies public key KIND must be ECC.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_public_kind_not_ecc)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        pub_props.key_kind = AZIHSM_KEY_KIND_RSA;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
    });
}

// Verifies generation succeeds when SESSION property is set to session key mode.
TEST_F(azihsm_ecc_keygen, key_gen_pair_accepts_session_flag_set)
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
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        uint8_t priv_session = 0;
        uint8_t pub_session = 0;
        ASSERT_EQ(get_key_prop(priv_key.get(), AZIHSM_KEY_PROP_ID_SESSION, priv_session), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(get_key_prop(pub_key.get(), AZIHSM_KEY_PROP_ID_SESSION, pub_session), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(priv_session, 1);
        ASSERT_EQ(pub_session, 1);
    });
}

// Verifies generation succeeds when SESSION property is set to persistent/token key mode.
TEST_F(azihsm_ecc_keygen, key_gen_pair_accepts_session_flag_cleared)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;

        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            false,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        uint8_t priv_session = 1;
        uint8_t pub_session = 1;
        ASSERT_EQ(get_key_prop(priv_key.get(), AZIHSM_KEY_PROP_ID_SESSION, priv_session), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(get_key_prop(pub_key.get(), AZIHSM_KEY_PROP_ID_SESSION, pub_session), AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(priv_session, 0);
        ASSERT_EQ(pub_session, 0);
    });
}


// Verifies generation rejects private list when VERIFY is set but SIGN is absent.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_private_verify_without_sign)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        remove_prop_by_id(priv_props.props, AZIHSM_KEY_PROP_ID_SIGN);
        priv_props.props.push_back({ AZIHSM_KEY_PROP_ID_VERIFY, &priv_props.can_sign, sizeof(priv_props.can_sign) });

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
    });
}

// Verifies generation rejects public list when SIGN is set but VERIFY is absent.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_public_sign_without_verify)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        remove_prop_by_id(pub_props.props, AZIHSM_KEY_PROP_ID_VERIFY);
        pub_props.props.push_back({ AZIHSM_KEY_PROP_ID_SIGN, &pub_props.can_verify, sizeof(pub_props.can_verify) });

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
    });
}

// Verifies duplicate property IDs with identical values in the private list
// are accepted (last-value-wins semantics).
TEST_F(azihsm_ecc_keygen, key_gen_pair_accepts_duplicate_private_property_ids_same_value)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.props.push_back({ AZIHSM_KEY_PROP_ID_EC_CURVE, &priv_props.ecc_curve, sizeof(priv_props.ecc_curve) });

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto_key priv_key;
        auto_key pub_key;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);
    });
}

// Verifies conflicting duplicate private property values cause the last value
// to win, resulting in a curve mismatch with the public properties.
TEST_F(azihsm_ecc_keygen, key_gen_pair_last_value_wins_conflicting_duplicate_private_property)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        uint32_t conflicting_curve = AZIHSM_ECC_CURVE_P384;
        priv_props.props.push_back({ AZIHSM_KEY_PROP_ID_EC_CURVE, &conflicting_curve, sizeof(conflicting_curve) });

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        // Last value (P384) wins for private, but public still has P256 → curve mismatch
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
    });
}

// Verifies duplicate property IDs with identical values in the public list
// are accepted (last-value-wins semantics).
TEST_F(azihsm_ecc_keygen, key_gen_pair_accepts_duplicate_public_property_ids_same_value)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        pub_props.props.push_back({ AZIHSM_KEY_PROP_ID_VERIFY, &pub_props.can_verify, sizeof(pub_props.can_verify) });

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto_key priv_key;
        auto_key pub_key;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            priv_key.get_ptr(),
            pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);
    });
}

// Verifies conflicting duplicate public property values cause the last value
// to win, resulting in a failed key generation due to missing required verify capability.
TEST_F(azihsm_ecc_keygen, key_gen_pair_last_value_wins_conflicting_duplicate_public_property)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        uint8_t conflicting_verify = 0;
        pub_props.props.push_back({ AZIHSM_KEY_PROP_ID_VERIFY, &conflicting_verify, sizeof(conflicting_verify) });

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        // Last value (verify=0) wins → missing required verify capability
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
    });
}

// Verifies malformed property value shape (null val with non-zero len) is rejected in private list.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_private_property_null_value_nonzero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.props[0].val = nullptr;
        priv_props.props[0].len = 1;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies malformed property value shape (null val with non-zero len) is rejected in public list.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_public_property_null_value_nonzero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        pub_props.props[0].val = nullptr;
        pub_props.props[0].len = 1;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies private/public property value lengths must match the expected type size.
TEST_F(azihsm_ecc_keygen, key_gen_pair_rejects_property_length_mismatch)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.props[0].len = 1;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

// Verifies key generation preserves input property-list bytes on failure.
TEST_F(azihsm_ecc_keygen, key_gen_pair_preserves_input_property_lists_on_failure)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto keygen_algo = make_ec_keygen_algo();

        DummyEccPrivKeyProps priv_props;
        DummyEccPubKeyProps pub_props;
        priv_props.ecc_curve = static_cast<uint32_t>(0xFFFFFFFF);

        const auto before_priv = priv_props.props;
        const auto before_pub = pub_props.props;

        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        auto err = azihsm_key_gen_pair(
            session,
            &keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);

        ASSERT_EQ(priv_props.props.size(), before_priv.size());
        ASSERT_EQ(pub_props.props.size(), before_pub.size());
        for (size_t i = 0; i < before_priv.size(); ++i)
        {
            ASSERT_EQ(priv_props.props[i].id, before_priv[i].id);
            ASSERT_EQ(priv_props.props[i].val, before_priv[i].val);
            ASSERT_EQ(priv_props.props[i].len, before_priv[i].len);
        }
        for (size_t i = 0; i < before_pub.size(); ++i)
        {
            ASSERT_EQ(pub_props.props[i].id, before_pub[i].id);
            ASSERT_EQ(pub_props.props[i].val, before_pub[i].val);
            ASSERT_EQ(pub_props.props[i].len, before_pub[i].len);
        }
    });
}


