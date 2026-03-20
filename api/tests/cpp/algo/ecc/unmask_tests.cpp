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
// ==================== key_unmask_pair ====================

// ----- Positive Paths -----

// Verifies unmasking an ECC P256 pair preserves key kind and curve properties.
TEST_F(azihsm_ecc_keygen, unmask_pair_p256_property_parity)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Step 1: Generate ECC P256 key pair with sign/verify capabilities
        auto_key original_priv_key;
        auto_key original_pub_key;
        auto err = generate_ecc_keypair(
            session,
            AZIHSM_ECC_CURVE_P256,
            true, // session key
            original_priv_key.get_ptr(),
            original_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(original_priv_key.get(), 0);
        ASSERT_NE(original_pub_key.get(), 0);

        // Step 2: Get masked key from private key
        std::vector<uint8_t> masked_key_data;
        err = get_masked_key_blob(original_priv_key.get(), masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(masked_key_data.size(), 0u);

        // Step 3: Unmask the key pair
        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_priv_key;
        auto_key unmasked_pub_key;
        err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_ECC,
            &masked_key_buf,
            unmasked_priv_key.get_ptr(),
            unmasked_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unmasked_priv_key.get(), 0);
        ASSERT_NE(unmasked_pub_key.get(), 0);

        // Step 4: Compare key properties - private keys
        EccKeySummary original_priv_summary{};
        ASSERT_EQ(
            read_ecc_key_summary(original_priv_key.get(), original_priv_summary),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_TRUE(is_expected_ecc_curve(original_priv_summary, AZIHSM_ECC_CURVE_P256));

        EccKeySummary unmasked_priv_summary{};
        ASSERT_EQ(
            read_ecc_key_summary(unmasked_priv_key.get(), unmasked_priv_summary),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_TRUE(is_expected_ecc_curve(unmasked_priv_summary, AZIHSM_ECC_CURVE_P256));

        // Step 5: Compare key properties - public keys
        EccKeySummary original_pub_summary{};
        ASSERT_EQ(
            read_ecc_key_summary(original_pub_key.get(), original_pub_summary),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_TRUE(is_expected_ecc_curve(original_pub_summary, AZIHSM_ECC_CURVE_P256));

        EccKeySummary unmasked_pub_summary{};
        ASSERT_EQ(
            read_ecc_key_summary(unmasked_pub_key.get(), unmasked_pub_summary),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_TRUE(is_expected_ecc_curve(unmasked_pub_summary, AZIHSM_ECC_CURVE_P256));
    });
}

// Verifies unmask property parity across all supported curves.
TEST_F(azihsm_ecc_keygen, unmask_pair_all_curves_property_parity)
{
    const std::vector<azihsm_ecc_curve> curves = {
        AZIHSM_ECC_CURVE_P256,
        AZIHSM_ECC_CURVE_P384,
        AZIHSM_ECC_CURVE_P521,
    };

    part_list_.for_each_session([&](azihsm_handle session) {
        for (auto curve : curves)
        {
            SCOPED_TRACE("curve=" + std::to_string(curve));

            std::vector<uint8_t> masked_key_data;
            auto err = make_valid_masked_ecc_blob(session, curve, masked_key_data);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_GT(masked_key_data.size(), 0u);

            azihsm_buffer masked_key_buf{};
            masked_key_buf.ptr = masked_key_data.data();
            masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

            auto_key unmasked_priv_key;
            auto_key unmasked_pub_key;
            err = azihsm_key_unmask_pair(
                session,
                AZIHSM_KEY_KIND_ECC,
                &masked_key_buf,
                unmasked_priv_key.get_ptr(),
                unmasked_pub_key.get_ptr()
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_NE(unmasked_priv_key.get(), 0);
            ASSERT_NE(unmasked_pub_key.get(), 0);

            EccKeySummary priv_summary{};
            ASSERT_EQ(read_ecc_key_summary(unmasked_priv_key.get(), priv_summary), AZIHSM_STATUS_SUCCESS);
            ASSERT_TRUE(is_expected_ecc_curve(priv_summary, curve));

            EccKeySummary pub_summary{};
            ASSERT_EQ(read_ecc_key_summary(unmasked_pub_key.get(), pub_summary), AZIHSM_STATUS_SUCCESS);
            ASSERT_TRUE(is_expected_ecc_curve(pub_summary, curve));
        }
    });
}

// Verifies unmask preserves derive capability where applicable.
TEST_F(azihsm_ecc_keygen, unmask_pair_derive_capability_parity)
{
    const std::vector<azihsm_ecc_curve> curves = {
        AZIHSM_ECC_CURVE_P256,
        AZIHSM_ECC_CURVE_P384,
        AZIHSM_ECC_CURVE_P521,
    };

    part_list_.for_each_session([&](azihsm_handle session) {
        for (auto curve : curves)
        {
            SCOPED_TRACE("curve=" + std::to_string(curve));

            auto_key original_priv_key;
            auto_key original_pub_key;
            auto err = generate_ecc_keypair(
                session,
                curve,
                true,
                original_priv_key.get_ptr(),
                original_pub_key.get_ptr()
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            std::vector<uint8_t> masked_key_data;
            err = get_masked_key_blob(original_priv_key.get(), masked_key_data);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            uint8_t original_priv_derive = 0;
            uint8_t original_pub_derive = 0;
            const auto original_priv_status =
                get_key_prop(original_priv_key.get(), AZIHSM_KEY_PROP_ID_DERIVE, original_priv_derive);
            const auto original_pub_status =
                get_key_prop(original_pub_key.get(), AZIHSM_KEY_PROP_ID_DERIVE, original_pub_derive);

            azihsm_buffer masked_key_buf{};
            masked_key_buf.ptr = masked_key_data.data();
            masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

            auto_key unmasked_priv_key;
            auto_key unmasked_pub_key;
            err = azihsm_key_unmask_pair(
                session,
                AZIHSM_KEY_KIND_ECC,
                &masked_key_buf,
                unmasked_priv_key.get_ptr(),
                unmasked_pub_key.get_ptr()
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            uint8_t unmasked_priv_derive = 0;
            uint8_t unmasked_pub_derive = 0;
            const auto unmasked_priv_status =
                get_key_prop(unmasked_priv_key.get(), AZIHSM_KEY_PROP_ID_DERIVE, unmasked_priv_derive);
            const auto unmasked_pub_status =
                get_key_prop(unmasked_pub_key.get(), AZIHSM_KEY_PROP_ID_DERIVE, unmasked_pub_derive);

            ASSERT_EQ(unmasked_priv_status, original_priv_status);
            ASSERT_EQ(unmasked_pub_status, original_pub_status);
            if (original_priv_status == AZIHSM_STATUS_SUCCESS)
            {
                ASSERT_EQ(unmasked_priv_derive, original_priv_derive);
            }
            if (original_pub_status == AZIHSM_STATUS_SUCCESS)
            {
                ASSERT_EQ(unmasked_pub_derive, original_pub_derive);
            }
        }
    });
}

// Verifies re-unmasking the same blob yields distinct valid handles.
TEST_F(azihsm_ecc_keygen, unmask_pair_same_blob_multiple_imports_unique_handles)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key first_priv;
        auto_key first_pub;
        err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_ECC,
            &masked_key_buf,
            first_priv.get_ptr(),
            first_pub.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        auto_key second_priv;
        auto_key second_pub;
        err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_ECC,
            &masked_key_buf,
            second_priv.get_ptr(),
            second_pub.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        ASSERT_NE(first_priv.get(), 0);
        ASSERT_NE(first_pub.get(), 0);
        ASSERT_NE(second_priv.get(), 0);
        ASSERT_NE(second_pub.get(), 0);
        ASSERT_NE(first_priv.get(), second_priv.get());
        ASSERT_NE(first_pub.get(), second_pub.get());
    });
}

// Verifies private/public capability invariants are preserved after unmask.
TEST_F(azihsm_ecc_keygen, unmask_pair_preserves_private_public_capability_invariants_all_curves)
{
    const std::vector<azihsm_ecc_curve> curves = {
        AZIHSM_ECC_CURVE_P256,
        AZIHSM_ECC_CURVE_P384,
        AZIHSM_ECC_CURVE_P521,
    };

    part_list_.for_each_session([&](azihsm_handle session) {
        for (auto curve : curves)
        {
            SCOPED_TRACE("curve=" + std::to_string(curve));

            std::vector<uint8_t> masked_key_data;
            auto err = make_valid_masked_ecc_blob(session, curve, masked_key_data);
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            azihsm_buffer masked_key_buf{};
            masked_key_buf.ptr = masked_key_data.data();
            masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

            auto_key priv_key;
            auto_key pub_key;
            err = azihsm_key_unmask_pair(
                session,
                AZIHSM_KEY_KIND_ECC,
                &masked_key_buf,
                priv_key.get_ptr(),
                pub_key.get_ptr()
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

            uint32_t priv_class = 0;
            uint32_t pub_class = 0;
            uint32_t priv_kind = 0;
            uint32_t pub_kind = 0;
            uint8_t priv_sign = 0;
            uint8_t pub_verify = 0;

            ASSERT_EQ(get_key_prop(priv_key.get(), AZIHSM_KEY_PROP_ID_CLASS, priv_class), AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(get_key_prop(pub_key.get(), AZIHSM_KEY_PROP_ID_CLASS, pub_class), AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(get_key_prop(priv_key.get(), AZIHSM_KEY_PROP_ID_KIND, priv_kind), AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(get_key_prop(pub_key.get(), AZIHSM_KEY_PROP_ID_KIND, pub_kind), AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(get_key_prop(priv_key.get(), AZIHSM_KEY_PROP_ID_SIGN, priv_sign), AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(get_key_prop(pub_key.get(), AZIHSM_KEY_PROP_ID_VERIFY, pub_verify), AZIHSM_STATUS_SUCCESS);

            ASSERT_EQ(priv_class, AZIHSM_KEY_CLASS_PRIVATE);
            ASSERT_EQ(pub_class, AZIHSM_KEY_CLASS_PUBLIC);
            ASSERT_EQ(priv_kind, AZIHSM_KEY_KIND_ECC);
            ASSERT_EQ(pub_kind, AZIHSM_KEY_KIND_ECC);
            ASSERT_EQ(priv_sign, 1);
            ASSERT_EQ(pub_verify, 1);
        }
    });
}

// ----- Mandatory Pointers and Output Handles -----

// Verifies unmask rejects null/aliasing output-handle configurations.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_invalid_output_handle_configurations)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        {
            SCOPED_TRACE("both output-handle pointers are null");
            err = azihsm_key_unmask_pair(
                session,
                AZIHSM_KEY_KIND_ECC,
                &masked_key_buf,
                nullptr,
                nullptr
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        }

        {
            SCOPED_TRACE("null private output-handle pointer");
            azihsm_handle pub_key_handle = 0;
            err = azihsm_key_unmask_pair(
                session,
                AZIHSM_KEY_KIND_ECC,
                &masked_key_buf,
                nullptr,
                &pub_key_handle
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(pub_key_handle, 0);
        }

        {
            SCOPED_TRACE("null public output-handle pointer");
            azihsm_handle priv_key_handle = 0;
            err = azihsm_key_unmask_pair(
                session,
                AZIHSM_KEY_KIND_ECC,
                &masked_key_buf,
                &priv_key_handle,
                nullptr
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(priv_key_handle, 0);
        }

        {
            SCOPED_TRACE("aliasing private/public output-handle pointers");
            azihsm_handle key_handle = 0;
            err = azihsm_key_unmask_pair(
                session,
                AZIHSM_KEY_KIND_ECC,
                &masked_key_buf,
                &key_handle,
                &key_handle
            );
            ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(key_handle, 0);
        }
    });
}

// Verifies unmask failure paths do not leak partial outputs into caller-provided handles.
TEST_F(azihsm_ecc_keygen, unmask_pair_preserves_zero_output_handles_on_failure)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_RSA,
            &masked_key_buf,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(priv_key_handle, 0);
        ASSERT_EQ(pub_key_handle, 0);
    });
}

// ----- Session Argument Validation -----

// Verifies unmask rejects invalid session handles.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_invalid_session_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        err = azihsm_key_unmask_pair(
            0xDEADBEEF,
            AZIHSM_KEY_KIND_ECC,
            &masked_key_buf,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(priv_key_handle, 0);
        ASSERT_EQ(pub_key_handle, 0);
    });
}

// Verifies unmask rejects zero-valued session handles.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_zero_session_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto result = try_unmask_pair(0, AZIHSM_KEY_KIND_ECC, &masked_key_buf);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unmask rejects random non-existent session handle values.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_random_nonexistent_session_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto result = try_unmask_pair(0xABCDEF01, AZIHSM_KEY_KIND_ECC, &masked_key_buf);
        ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_HANDLE);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// ----- Key Kind Argument Validation -----

// Verifies unmask accepts key kind ECC on otherwise valid inputs.
TEST_F(azihsm_ecc_keygen, unmask_pair_accepts_key_kind_ecc)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P384, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &masked_key_buf);
        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);
    });
}

// Verifies unmask rejects a key-kind value that does not match ECC.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_key_kind_not_ecc)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;
        err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_RSA,
            &masked_key_buf,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(priv_key_handle, 0);
        ASSERT_EQ(pub_key_handle, 0);
    });
}

// Verifies unmask rejects unsupported key-kind identifiers.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_unsupported_key_kind)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto result = try_unmask_pair(
            session,
            static_cast<azihsm_key_kind>(0xFFFFFFFF),
            &masked_key_buf
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// ----- Masked Key Argument Validation -----

// Verifies unmask rejects a null masked-key buffer pointer.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_null_masked_key_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_ECC,
            nullptr,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(priv_key_handle, 0);
        ASSERT_EQ(pub_key_handle, 0);
    });
}

// Verifies unmask rejects invalid buffer shapes (such as null pointer with non-zero length).
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_invalid_buffer_shape)
{
    part_list_.for_each_session([](azihsm_handle session) {
        {
            SCOPED_TRACE("null pointer with non-zero length");
            azihsm_buffer masked_key_buf{};
            masked_key_buf.ptr = nullptr;
            masked_key_buf.len = 1;

            auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &masked_key_buf);
            ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("non-null pointer with zero length");
            uint8_t blob_byte = 0x00;
            azihsm_buffer masked_key_buf{};
            masked_key_buf.ptr = &blob_byte;
            masked_key_buf.len = 0;

            auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &masked_key_buf);
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

// Verifies unmask rejects an empty masked blob represented as null pointer + zero length.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_null_blob_with_zero_length)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = nullptr;
        masked_key_buf.len = 0;

        azihsm_handle priv_key_handle = 0;
        azihsm_handle pub_key_handle = 0;

        auto err = azihsm_key_unmask_pair(
            session,
            AZIHSM_KEY_KIND_ECC,
            &masked_key_buf,
            &priv_key_handle,
            &pub_key_handle
        );
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(priv_key_handle, 0);
        ASSERT_EQ(pub_key_handle, 0);
    });
}

// Verifies unmask rejects empty or truncated masked blobs.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_empty_or_truncated_blob)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(masked_key_data.size(), 2u);

        {
            SCOPED_TRACE("empty non-null buffer");
            uint8_t empty_byte = 0;
            azihsm_buffer empty_buf{};
            empty_buf.ptr = &empty_byte;
            empty_buf.len = 0;

            auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &empty_buf);
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("truncated blob");
            std::vector<uint8_t> truncated(masked_key_data.begin(), masked_key_data.end() - 1);
            azihsm_buffer truncated_buf{};
            truncated_buf.ptr = truncated.data();
            truncated_buf.len = static_cast<uint32_t>(truncated.size());

            auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &truncated_buf);
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

// Verifies unmask rejects blob truncation by a single trailing byte.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_truncated_blob_by_single_byte)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(masked_key_data.size(), 1u);

        std::vector<uint8_t> truncated(masked_key_data.begin(), masked_key_data.end() - 1);
        azihsm_buffer truncated_buf{};
        truncated_buf.ptr = truncated.data();
        truncated_buf.len = static_cast<uint32_t>(truncated.size());

        auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &truncated_buf);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unmask rejects blob truncation by a larger chunk.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_truncated_blob_by_chunk)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(masked_key_data.size(), 8u);

        const size_t drop = std::min<size_t>(8, masked_key_data.size() - 1);
        std::vector<uint8_t> truncated(masked_key_data.begin(), masked_key_data.end() - drop);
        azihsm_buffer truncated_buf{};
        truncated_buf.ptr = truncated.data();
        truncated_buf.len = static_cast<uint32_t>(truncated.size());

        auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &truncated_buf);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unmask rejects minimal/header-only blob content.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_header_only_blob)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(masked_key_data.size(), 1u);

        std::vector<uint8_t> header_only(masked_key_data.begin(), masked_key_data.begin() + 1);
        azihsm_buffer header_only_buf{};
        header_only_buf.ptr = header_only.data();
        header_only_buf.len = static_cast<uint32_t>(header_only.size());

        auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &header_only_buf);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unmask rejects masked blobs when trailing garbage bytes are appended.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_masked_blob_with_trailing_bytes)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> mutated = masked_key_data;
        mutated.push_back(0xAA);
        mutated.push_back(0x55);

        azihsm_buffer mutated_buf{};
        mutated_buf.ptr = mutated.data();
        mutated_buf.len = static_cast<uint32_t>(mutated.size());

        auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &mutated_buf);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// ----- Cross-Argument Masked Payload Semantics -----

// Verifies ECC public keys do not expose masked-key blobs.
TEST_F(azihsm_ecc_keygen, unmask_pair_public_key_has_no_masked_blob_property)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        std::vector<uint8_t> masked_key_data;
        err = get_masked_key_blob(ecc_pub_key.get(), masked_key_data);
        // Public keys are not expected to carry AZIHSM_KEY_PROP_ID_MASKED_KEY in current API.
        ASSERT_EQ(err, AZIHSM_STATUS_PROPERTY_NOT_PRESENT);
        ASSERT_TRUE(masked_key_data.empty());
    });
}

// Verifies key_unmask_pair rejects syntactically valid ECC public-key bytes
// when those bytes are not a masked private-key payload.
//
// Subtlety:
// - This is intentionally an unmask-path negative test (operation semantics),
//   not a property-availability test.
// - We first validate property contract separately in
//   unmask_pair_public_key_has_no_masked_blob_property.
// - Here we intentionally feed AZIHSM_KEY_PROP_ID_PUB_KEY_INFO bytes to
//   key_unmask_pair to prove the parser/import path rejects "wrong blob kind"
//   even when input comes from a real, device-produced key property.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_public_key_info_blob)
{
    part_list_.for_each_session([](azihsm_handle session) {
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

        // Use real exported public-key info as adversarial input:
        // valid bytes, valid source, but invalid semantic type for unmask_pair.
        std::vector<uint8_t> pub_key_info;
        azihsm_key_prop pub_info_prop{};
        pub_info_prop.id = AZIHSM_KEY_PROP_ID_PUB_KEY_INFO;
        pub_info_prop.val = nullptr;
        pub_info_prop.len = 0;

        err = azihsm_key_get_prop(ecc_pub_key.get(), &pub_info_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(pub_info_prop.len, 0u);

        pub_key_info.resize(pub_info_prop.len);
        pub_info_prop.val = pub_key_info.data();
        err = azihsm_key_get_prop(ecc_pub_key.get(), &pub_info_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer fake_masked_blob{};
        fake_masked_blob.ptr = pub_key_info.data();
        fake_masked_blob.len = static_cast<uint32_t>(pub_key_info.size());

        // Expected outcome: unmask rejects this payload and returns no output handles,
        // preventing partial/ambiguous object creation from mismatched blob formats.
        auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &fake_masked_blob);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unmask rejects masked content produced from non-ECC key kinds.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_blob_from_non_ecc_key_kind)
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

        std::vector<uint8_t> masked_key_data;
        err = get_masked_key_blob(rsa_priv_key.get(), masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(masked_key_data.size(), 0u);

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &masked_key_buf);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unmask rejects masked blobs with corrupted integrity or metadata.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_corrupted_blob_integrity)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(masked_key_data.size(), 2u);

        std::vector<uint8_t> mutated = masked_key_data;
        mutated[mutated.size() / 2] ^= 0x01;

        azihsm_buffer mutated_buf{};
        mutated_buf.ptr = mutated.data();
        mutated_buf.len = static_cast<uint32_t>(mutated.size());

        auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &mutated_buf);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unmask rejects multi-byte corruption patterns across blob regions.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_multi_byte_blob_corruption_patterns)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(masked_key_data.size(), 4u);

        const std::vector<size_t> offsets = { 0, masked_key_data.size() / 2, masked_key_data.size() - 1 };
        for (size_t offset : offsets)
        {
            SCOPED_TRACE("offset=" + std::to_string(offset));
            std::vector<uint8_t> mutated = masked_key_data;
            mutated[offset] ^= 0xA5;
            mutated[(offset + 1) % mutated.size()] ^= 0x5A;

            azihsm_buffer mutated_buf{};
            mutated_buf.ptr = mutated.data();
            mutated_buf.len = static_cast<uint32_t>(mutated.size());

            auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &mutated_buf);
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

// Verifies unmask rejects restoring a blob across invalid session/partition boundaries.
TEST_F(azihsm_ecc_keygen, unmask_pair_rejects_cross_session_or_partition_restore)
{
    part_list_.for_each_part([&](std::vector<azihsm_char> &path) {
        auto partition = PartitionHandle(path);

        std::vector<uint8_t> masked_key_data;

        // Step 1: Produce a valid masked blob in one session.
        {
            SessionHandle owner_session(partition.get());
            auto err = make_valid_masked_ecc_blob(
                owner_session.get(),
                AZIHSM_ECC_CURVE_P256,
                masked_key_data
            );
            ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
            ASSERT_FALSE(masked_key_data.empty());
        }

        // Step 2: Attempt restore in another session context from same partition.
        SessionHandle other_session(partition.get());

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto result = try_unmask_pair(other_session->get(), AZIHSM_KEY_KIND_ECC, &masked_key_buf);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });

    if (part_list_.count() < 2u)
    {
        GTEST_SKIP() << "requires at least two partitions for cross-partition restore semantics";
    }

    auto source_path = part_list_.get_path(0);
    auto other_path = part_list_.get_path(1);

    auto source_partition = PartitionHandle(source_path);
    auto other_partition = PartitionHandle(other_path);

    std::vector<uint8_t> masked_key_data;

    // Step 3: Produce a valid masked blob in source partition.
    {
        SessionHandle source_session(source_partition.get());
        auto_key source_private_key;
        auto_key source_public_key;

        auto err = generate_ecc_keypair(
            source_session.get(),
            AZIHSM_ECC_CURVE_P256,
            false,
            source_private_key.get_ptr(),
            source_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        err = get_masked_key_blob(source_private_key.get(), masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(masked_key_data.empty());
    }

    // Step 4: Attempt restore with another partition context and verify rejection.
    {
        SessionHandle other_session(other_partition.get());

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto result = try_unmask_pair(other_session.get(), AZIHSM_KEY_KIND_ECC, &masked_key_buf);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    }
}

// Verifies unmask does not mutate caller-provided masked blob on failure.
TEST_F(azihsm_ecc_keygen, unmask_pair_preserves_input_masked_blob_on_failure)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P256, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        const auto before = masked_key_data;

        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_RSA, &masked_key_buf);
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(masked_key_data, before);
    });
}

// Sweeps masked-blob mutations to validate deterministic parser rejection behavior.
TEST_F(azihsm_ecc_keygen, unmask_pair_masked_blob_mutation_sweep)
{
    part_list_.for_each_session([](azihsm_handle session) {
        std::vector<uint8_t> masked_key_data;
        auto err = make_valid_masked_ecc_blob(session, AZIHSM_ECC_CURVE_P521, masked_key_data);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(masked_key_data.size(), 3u);

        for (size_t offset = 0; offset < masked_key_data.size(); offset += std::max<size_t>(1, masked_key_data.size() / 7))
        {
            SCOPED_TRACE("offset=" + std::to_string(offset));
            std::vector<uint8_t> mutated = masked_key_data;
            mutated[offset] ^= 0xFF;

            azihsm_buffer mutated_buf{};
            mutated_buf.ptr = mutated.data();
            mutated_buf.len = static_cast<uint32_t>(mutated.size());

            auto result = try_unmask_pair(session, AZIHSM_KEY_KIND_ECC, &mutated_buf);
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

