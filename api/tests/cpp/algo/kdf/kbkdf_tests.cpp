// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "handle/part_list_handle.hpp"
#include "utils/auto_key.hpp"
#include "utils/kdf_derive.hpp"
#include "utils/key_props.hpp"
#include "utils/shared_secret.hpp"

// ============================================================
// Test fixture
// ============================================================

class azihsm_kbkdf : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// ============================================================
// Test cases
// ============================================================

/// Test KBKDF (SP 800-108 Counter Mode) derive with various HMAC hash algorithms for P-256 curve
TEST_F(azihsm_kbkdf, kbkdf_matrix_p256)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_kbkdf_counter_matrix_for_curve(session, AZIHSM_ECC_CURVE_P256);
    });
}

/// Test KBKDF (SP 800-108 Counter Mode) derive with various HMAC hash algorithms for P-384 curve
TEST_F(azihsm_kbkdf, kbkdf_matrix_p384)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_kbkdf_counter_matrix_for_curve(session, AZIHSM_ECC_CURVE_P384);
    });
}

/// Test KBKDF (SP 800-108 Counter Mode) derive with various HMAC hash algorithms for P-521 curve
TEST_F(azihsm_kbkdf, kbkdf_matrix_p521)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_kbkdf_counter_matrix_for_curve(session, AZIHSM_ECC_CURVE_P521);
    });
}

/// Test that deriving an AES-GCM key with KBKDF fails with InvalidKeyProps
TEST_F(azihsm_kbkdf, kbkdf_derive_aes_gcm_key_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES_GCM;
        props.key_size_bits = 256;
        props.encrypt = 1;
        props.decrypt = 1;

        kbkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            AZIHSM_STATUS_INVALID_KEY_PROPS
        );
    });
}

/// Test that deriving a key with SharedSecret kind fails with InvalidArgument
TEST_F(azihsm_kbkdf, kbkdf_derive_unsupported_key_kind_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_SHARED_SECRET;
        props.key_size_bits = 256;
        props.derive = 1;

        kbkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that deriving a key with an invalid HMAC algorithm fails with InvalidArgument
TEST_F(azihsm_kbkdf, kbkdf_derive_invalid_hmac_algo_id_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 256;
        props.encrypt = 1;
        props.decrypt = 1;

        kbkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_SHA256,
            props,
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that deriving a key with zero bit length fails with InvalidKeyProps
TEST_F(azihsm_kbkdf, kbkdf_derive_zero_bit_len_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 0;
        props.encrypt = 1;
        props.decrypt = 1;

        kbkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            AZIHSM_STATUS_INVALID_KEY_PROPS
        );
    });
}

/// Test that deriving with only a label (no context) succeeds and produces correct output.
/// SP 800-108 requires at least one of label/context, so a label alone is a valid configuration.
TEST_F(azihsm_kbkdf, kbkdf_label_only_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        const char *label_str = "label-only";
        azihsm_buffer label_buf = { .ptr =
                                        reinterpret_cast<uint8_t *>(const_cast<char *>(label_str)),
                                    .len = static_cast<uint32_t>(std::strlen(label_str)) };

        azihsm_algo_kbkdf_counter_params kbkdf_params{};
        azihsm_algo kbkdf_algo{};
        build_kbkdf_counter_algo(
            kbkdf_params,
            kbkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &label_buf,
            nullptr
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "label only";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}
