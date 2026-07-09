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

static azihsm_status kbkdf_derive_with_custom_params(
    azihsm_handle session,
    azihsm_algo_id hmac_algo_id,
    key_props props,
    azihsm_buffer *label,
    azihsm_buffer *context
)
{
    auto_key secret_a;
    auto_key secret_b;
    derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

    azihsm_algo_kbkdf_counter_params kbkdf_params{};
    azihsm_algo kbkdf_algo{};
    build_kbkdf_counter_algo(kbkdf_params, kbkdf_algo, hmac_algo_id, label, context);

    std::vector<azihsm_key_prop> derived_key_props;
    azihsm_key_prop_list derived_key_prop_list = build_key_prop_list(props, derived_key_props);

    auto_key derived_key;

    return azihsm_key_derive(
        session,
        &kbkdf_algo,
        secret_a.get(),
        &derived_key_prop_list,
        derived_key.get_ptr()
    );
}

static azihsm_status kbkdf_derive_from_secret(
    azihsm_handle session,
    azihsm_handle secret,
    azihsm_algo_id hmac_algo_id,
    key_props props,
    azihsm_buffer *label,
    azihsm_buffer *context,
    auto_key &derived_key
)
{
    azihsm_algo_kbkdf_counter_params kbkdf_params{};
    azihsm_algo kbkdf_algo{};
    build_kbkdf_counter_algo(kbkdf_params, kbkdf_algo, hmac_algo_id, label, context);

    std::vector<azihsm_key_prop> derived_key_props;
    azihsm_key_prop_list derived_key_prop_list = build_key_prop_list(props, derived_key_props);

    return azihsm_key_derive(
        session,
        &kbkdf_algo,
        secret,
        &derived_key_prop_list,
        derived_key.get_ptr()
    );
}

static azihsm_status kbkdf_derive_with_algo(
    azihsm_handle session,
    azihsm_algo *algo,
    key_props props
)
{
    auto_key secret_a;
    auto_key secret_b;
    derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

    std::vector<azihsm_key_prop> derived_key_props;
    azihsm_key_prop_list derived_key_prop_list = build_key_prop_list(props, derived_key_props);

    auto_key derived_key;

    return azihsm_key_derive(
        session,
        algo,
        secret_a.get(),
        &derived_key_prop_list,
        derived_key.get_ptr()
    );
}

static key_props valid_kbkdf_aes_props()
{
    key_props props = {};
    props.key_class = AZIHSM_KEY_CLASS_SECRET;
    props.key_kind = AZIHSM_KEY_KIND_AES;
    props.key_size_bits = 256;
    props.encrypt = 1;
    props.decrypt = 1;
    return props;
}

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

/// Test that deriving an AES-GCM key with KBKDF fails with InvalidKeyProps.
TEST_F(azihsm_kbkdf, kbkdf_derive_aes_gcm_key_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES_GCM;
        props.key_size_bits = 256;
        props.encrypt = 1;
        props.decrypt = 1;

        const char *label_str = "aes-gcm-invalid-label";
        const char *context_str = "aes-gcm-invalid-context";

        azihsm_buffer label_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(label_str)),
            .len = static_cast<uint32_t>(std::strlen(label_str)),
        };

        azihsm_buffer context_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(context_str)),
            .len = static_cast<uint32_t>(std::strlen(context_str)),
        };

        EXPECT_EQ(
            kbkdf_derive_with_custom_params(
                session,
                AZIHSM_ALGO_ID_HMAC_SHA256,
                props,
                &label_buf,
                &context_buf
            ),
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

/// Test that deriving with only a context (no label) succeeds and produces correct output.
/// SP 800-108 requires at least one of label/context, so a context alone is valid.
TEST_F(azihsm_kbkdf, kbkdf_context_only_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        const char *context_str = "context-only";
        azihsm_buffer context_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(context_str)),
            .len = static_cast<uint32_t>(std::strlen(context_str)),
        };

        azihsm_algo_kbkdf_counter_params kbkdf_params{};
        azihsm_algo kbkdf_algo{};
        build_kbkdf_counter_algo(
            kbkdf_params,
            kbkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            nullptr,
            &context_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "context only";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test KBKDF roundtrip using HMAC-SHA512 with both label and context.
TEST_F(azihsm_kbkdf, kbkdf_hmac_sha512_label_context_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        const char *label_str = "kbkdf-sha512-label";
        const char *context_str = "kbkdf-sha512-context";

        azihsm_buffer label_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(label_str)),
            .len = static_cast<uint32_t>(std::strlen(label_str)),
        };

        azihsm_buffer context_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(context_str)),
            .len = static_cast<uint32_t>(std::strlen(context_str)),
        };

        azihsm_algo_kbkdf_counter_params kbkdf_params{};
        azihsm_algo kbkdf_algo{};
        build_kbkdf_counter_algo(
            kbkdf_params,
            kbkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA512,
            &label_buf,
            &context_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "kbkdf hmac sha512";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that KBKDF can derive a 128-bit AES key and use it for encryption/decryption.
TEST_F(azihsm_kbkdf, kbkdf_derive_aes_128_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        const char *label_str = "aes-128-label";
        const char *context_str = "aes-128-context";

        azihsm_buffer label_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(label_str)),
            .len = static_cast<uint32_t>(std::strlen(label_str)),
        };

        azihsm_buffer context_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(context_str)),
            .len = static_cast<uint32_t>(std::strlen(context_str)),
        };

        azihsm_algo_kbkdf_counter_params kbkdf_params{};
        azihsm_algo kbkdf_algo{};
        build_kbkdf_counter_algo(
            kbkdf_params,
            kbkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &label_buf,
            &context_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_a.get(), 128, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_b.get(), 128, key_b);

        const char *msg = "kbkdf aes 128";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that KBKDF can derive a 192-bit AES key and use it for encryption/decryption.
TEST_F(azihsm_kbkdf, kbkdf_derive_aes_192_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        const char *label_str = "aes-192-label";
        const char *context_str = "aes-192-context";

        azihsm_buffer label_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(label_str)),
            .len = static_cast<uint32_t>(std::strlen(label_str)),
        };

        azihsm_buffer context_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(context_str)),
            .len = static_cast<uint32_t>(std::strlen(context_str)),
        };

        azihsm_algo_kbkdf_counter_params kbkdf_params{};
        azihsm_algo kbkdf_algo{};
        build_kbkdf_counter_algo(
            kbkdf_params,
            kbkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &label_buf,
            &context_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_a.get(), 192, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_b.get(), 192, key_b);

        const char *msg = "kbkdf aes 192";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that deriving an AES key without encrypt/decrypt usage flags fails with InvalidKeyProps.
TEST_F(azihsm_kbkdf, kbkdf_derive_aes_without_usage_flags_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 256;

        kbkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            AZIHSM_STATUS_INVALID_KEY_PROPS
        );
    });
}

/// Test that deriving an AES key with an unsupported AES key size fails with InvalidArgument.
TEST_F(azihsm_kbkdf, kbkdf_derive_invalid_aes_key_size_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 129;
        props.encrypt = 1;
        props.decrypt = 1;

        kbkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that deriving a key with a non-secret key class fails with InvalidKeyProps.
TEST_F(azihsm_kbkdf, kbkdf_derive_non_secret_key_class_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_PUBLIC;
        props.key_kind = AZIHSM_KEY_KIND_AES;
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

/// Test that KBKDF derives compatible keys when the same shared secret and parameters are reused.
TEST_F(azihsm_kbkdf, kbkdf_same_secret_same_params_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        const char *label_str = "same-secret-label";
        const char *context_str = "same-secret-context";

        azihsm_buffer label_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(label_str)),
            .len = static_cast<uint32_t>(std::strlen(label_str)),
        };

        azihsm_buffer context_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(context_str)),
            .len = static_cast<uint32_t>(std::strlen(context_str)),
        };

        azihsm_algo_kbkdf_counter_params kbkdf_params{};
        azihsm_algo kbkdf_algo{};
        build_kbkdf_counter_algo(
            kbkdf_params,
            kbkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &label_buf,
            &context_buf
        );

        auto_key key_a;
        auto_key key_b;

        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_a.get(), 256, key_a);
        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_a.get(), 256, key_b);

        const char *msg = "same secret same params";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that KBKDF derive succeeds with HMAC-SHA384 using label and context.
TEST_F(azihsm_kbkdf, kbkdf_hmac_sha384_label_context_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        const char *label_str = "kbkdf-sha384-label";
        const char *context_str = "kbkdf-sha384-context";

        azihsm_buffer label_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(label_str)),
            .len = static_cast<uint32_t>(std::strlen(label_str)),
        };

        azihsm_buffer context_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(context_str)),
            .len = static_cast<uint32_t>(std::strlen(context_str)),
        };

        azihsm_algo_kbkdf_counter_params kbkdf_params{};
        azihsm_algo kbkdf_algo{};
        build_kbkdf_counter_algo(
            kbkdf_params,
            kbkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA384,
            &label_buf,
            &context_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &kbkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "kbkdf hmac sha384";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that KBKDF derive rejects a label buffer with null pointer and non-zero length.
TEST_F(azihsm_kbkdf, kbkdf_null_label_with_nonzero_len_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 256;
        props.encrypt = 1;
        props.decrypt = 1;

        const char *context_str = "valid-context";

        azihsm_buffer invalid_label_buf = {
            .ptr = nullptr,
            .len = 1,
        };

        azihsm_buffer context_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(context_str)),
            .len = static_cast<uint32_t>(std::strlen(context_str)),
        };

        EXPECT_EQ(
            kbkdf_derive_with_custom_params(
                session,
                AZIHSM_ALGO_ID_HMAC_SHA256,
                props,
                &invalid_label_buf,
                &context_buf
            ),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that KBKDF derive rejects a context buffer with null pointer and non-zero length.
TEST_F(azihsm_kbkdf, kbkdf_null_context_with_nonzero_len_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 256;
        props.encrypt = 1;
        props.decrypt = 1;

        const char *label_str = "valid-label";

        azihsm_buffer label_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(label_str)),
            .len = static_cast<uint32_t>(std::strlen(label_str)),
        };

        azihsm_buffer invalid_context_buf = {
            .ptr = nullptr,
            .len = 1,
        };

        EXPECT_EQ(
            kbkdf_derive_with_custom_params(
                session,
                AZIHSM_ALGO_ID_HMAC_SHA256,
                props,
                &label_buf,
                &invalid_context_buf
            ),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that KBKDF derive succeeds when both label and context are omitted.
TEST_F(azihsm_kbkdf, kbkdf_missing_label_and_context_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 256;
        props.encrypt = 1;
        props.decrypt = 1;

        EXPECT_EQ(
            kbkdf_derive_with_custom_params(
                session,
                AZIHSM_ALGO_ID_HMAC_SHA256,
                props,
                nullptr,
                nullptr
            ),
            AZIHSM_STATUS_SUCCESS
        );
    });
}

/// Test that changing the KBKDF label changes the derived key material.
TEST_F(azihsm_kbkdf, kbkdf_different_label_produces_different_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 256;
        props.encrypt = 1;
        props.decrypt = 1;

        const char *label1_str = "label-one";
        const char *label2_str = "label-two";
        const char *context_str = "same-context";

        azihsm_buffer label1_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(label1_str)),
            .len = static_cast<uint32_t>(std::strlen(label1_str)),
        };

        azihsm_buffer label2_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(label2_str)),
            .len = static_cast<uint32_t>(std::strlen(label2_str)),
        };

        azihsm_buffer context_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(context_str)),
            .len = static_cast<uint32_t>(std::strlen(context_str)),
        };

        auto_key derived_key_1;
        auto_key derived_key_2;

        ASSERT_EQ(
            kbkdf_derive_from_secret(
                session,
                secret_a.get(),
                AZIHSM_ALGO_ID_HMAC_SHA256,
                props,
                &label1_buf,
                &context_buf,
                derived_key_1
            ),
            AZIHSM_STATUS_SUCCESS
        );

        ASSERT_EQ(
            kbkdf_derive_from_secret(
                session,
                secret_a.get(),
                AZIHSM_ALGO_ID_HMAC_SHA256,
                props,
                &label2_buf,
                &context_buf,
                derived_key_2
            ),
            AZIHSM_STATUS_SUCCESS
        );

        EXPECT_NE(derived_key_1.get(), derived_key_2.get());
    });
}

/// Test that KBKDF rejects an AES key with only encrypt usage enabled.
TEST_F(azihsm_kbkdf, kbkdf_derive_aes_encrypt_only_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 256;
        props.encrypt = 1;

        const char *label_str = "encrypt-only-label";
        const char *context_str = "encrypt-only-context";

        azihsm_buffer label_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(label_str)),
            .len = static_cast<uint32_t>(std::strlen(label_str)),
        };

        azihsm_buffer context_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(context_str)),
            .len = static_cast<uint32_t>(std::strlen(context_str)),
        };

        EXPECT_EQ(
            kbkdf_derive_with_custom_params(
                session,
                AZIHSM_ALGO_ID_HMAC_SHA256,
                props,
                &label_buf,
                &context_buf
            ),
            AZIHSM_STATUS_INVALID_KEY_PROPS
        );
    });
}

/// Test that KBKDF derive rejects a null algorithm pointer.
TEST_F(azihsm_kbkdf, kbkdf_null_algo_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        EXPECT_EQ(
            kbkdf_derive_with_algo(session, nullptr, valid_kbkdf_aes_props()),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that KBKDF derive rejects null KBKDF params.
TEST_F(azihsm_kbkdf, kbkdf_null_algo_params_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        azihsm_algo kbkdf_algo = {};
        kbkdf_algo.id = AZIHSM_ALGO_ID_KBKDF_COUNTER_DERIVE;
        kbkdf_algo.params = nullptr;
        kbkdf_algo.len = sizeof(azihsm_algo_kbkdf_counter_params);

        EXPECT_EQ(
            kbkdf_derive_with_algo(session, &kbkdf_algo, valid_kbkdf_aes_props()),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that KBKDF derive rejects zero KBKDF params length.
TEST_F(azihsm_kbkdf, kbkdf_zero_algo_params_len_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        const char *label_str = "valid-label";
        const char *context_str = "valid-context";

        azihsm_buffer label_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(label_str)),
            .len = static_cast<uint32_t>(std::strlen(label_str)),
        };

        azihsm_buffer context_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(context_str)),
            .len = static_cast<uint32_t>(std::strlen(context_str)),
        };

        azihsm_algo_kbkdf_counter_params kbkdf_params = {};
        azihsm_algo kbkdf_algo = {};
        build_kbkdf_counter_algo(
            kbkdf_params,
            kbkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &label_buf,
            &context_buf
        );

        kbkdf_algo.len = 0;

        EXPECT_EQ(
            kbkdf_derive_with_algo(session, &kbkdf_algo, valid_kbkdf_aes_props()),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that KBKDF derive rejects a mismatched KBKDF params length.
TEST_F(azihsm_kbkdf, kbkdf_algo_params_len_mismatch_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        const char *label_str = "valid-label";
        const char *context_str = "valid-context";

        azihsm_buffer label_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(label_str)),
            .len = static_cast<uint32_t>(std::strlen(label_str)),
        };

        azihsm_buffer context_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(context_str)),
            .len = static_cast<uint32_t>(std::strlen(context_str)),
        };

        azihsm_algo_kbkdf_counter_params kbkdf_params = {};
        azihsm_algo kbkdf_algo = {};
        build_kbkdf_counter_algo(
            kbkdf_params,
            kbkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &label_buf,
            &context_buf
        );

        kbkdf_algo.len = sizeof(azihsm_algo_kbkdf_counter_params) - 1;

        EXPECT_EQ(
            kbkdf_derive_with_algo(session, &kbkdf_algo, valid_kbkdf_aes_props()),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that KBKDF derive rejects a null derived-key output pointer.
TEST_F(azihsm_kbkdf, kbkdf_null_derived_key_output_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        const char *label_str = "valid-label";
        const char *context_str = "valid-context";

        azihsm_buffer label_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(label_str)),
            .len = static_cast<uint32_t>(std::strlen(label_str)),
        };

        azihsm_buffer context_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(context_str)),
            .len = static_cast<uint32_t>(std::strlen(context_str)),
        };

        azihsm_algo_kbkdf_counter_params kbkdf_params = {};
        azihsm_algo kbkdf_algo = {};
        build_kbkdf_counter_algo(
            kbkdf_params,
            kbkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &label_buf,
            &context_buf
        );

        key_props props = valid_kbkdf_aes_props();

        std::vector<azihsm_key_prop> derived_key_props;
        azihsm_key_prop_list derived_key_prop_list = build_key_prop_list(props, derived_key_props);

        EXPECT_EQ(
            azihsm_key_derive(
                session,
                &kbkdf_algo,
                secret_a.get(),
                &derived_key_prop_list,
                nullptr
            ),
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}
