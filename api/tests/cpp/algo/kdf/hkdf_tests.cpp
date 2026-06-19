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

class azihsm_hkdf : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// ============================================================
// Test cases
// ============================================================

/// Test HKDF derive with various HMAC hash algorithms for P-256 curve
TEST_F(azihsm_hkdf, hkdf_matrix_p256)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_hkdf_matrix_for_curve(session, AZIHSM_ECC_CURVE_P256);
    });
}

/// Test HKDF derive with various HMAC hash algorithms for P-384 curve
TEST_F(azihsm_hkdf, hkdf_matrix_p384)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_hkdf_matrix_for_curve(session, AZIHSM_ECC_CURVE_P384);
    });
}

/// Test HKDF derive with various HMAC hash algorithms for P-521 curve
TEST_F(azihsm_hkdf, hkdf_matrix_p521)
{
    part_list_.for_each_session([](azihsm_handle session) {
        run_hkdf_matrix_for_curve(session, AZIHSM_ECC_CURVE_P521);
    });
}

/// Test that deriving an AES-GCM key with HKDF fails with InvalidKeyProps
TEST_F(azihsm_hkdf, hkdf_derive_aes_gcm_key_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES_GCM;
        props.key_size_bits = 256;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            AZIHSM_STATUS_INVALID_KEY_PROPS
        );
    });
}

/// Test that deriving a key with SharedSecret kind fails with InvalidArgument
TEST_F(azihsm_hkdf, hkdf_derive_unsupported_key_kind_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_SHARED_SECRET;
        props.key_size_bits = 256;
        props.derive = 1;

        hkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that deriving a key with an invalid HMAC algorithm fails with InvalidArgument
TEST_F(azihsm_hkdf, hkdf_derive_invalid_hmac_algo_id_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 256;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_SHA256,
            props,
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that deriving a key with zero bit length fails with InvalidKeyProps
TEST_F(azihsm_hkdf, hkdf_derive_zero_bit_len_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 0;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            AZIHSM_STATUS_INVALID_KEY_PROPS
        );
    });
}

/// Test that deriving a key with empty salt and info buffers succeeds (since salt and info are
/// optional in HKDF) and produces correct output
TEST_F(azihsm_hkdf, hkdf_empty_salt_info_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        // Empty (zero-length) salt and info buffers.
        azihsm_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        azihsm_buffer info_buf = { .ptr = nullptr, .len = 0 };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, AZIHSM_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "empty salt info";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF accepts non-null salt/info pointers with zero lengths
TEST_F(azihsm_hkdf, hkdf_allows_non_null_salt_info_with_zero_len)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        uint8_t salt[] = { 0xAA, 0xBB, 0xCC };
        uint8_t info[] = { 0x01, 0x02, 0x03 };

        azihsm_buffer salt_buf = { .ptr = salt, .len = 0 };
        azihsm_buffer info_buf = { .ptr = info, .len = 0 };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(
            hkdf_params,
            hkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "zero length salt info";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF supports AES-128 output key size
TEST_F(azihsm_hkdf, hkdf_supports_aes_128)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        const uint8_t salt[] = { 0x10, 0x20, 0x30 };
        const uint8_t info[] = { 0x40, 0x50, 0x60 };

        azihsm_buffer salt_buf = {
            .ptr = const_cast<uint8_t *>(salt),
            .len = sizeof(salt)
        };

        azihsm_buffer info_buf = {
            .ptr = const_cast<uint8_t *>(info),
            .len = sizeof(info)
        };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(
            hkdf_params,
            hkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 128, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 128, key_b);

        const char *msg = "hkdf aes 128";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF supports AES-192 output key size
TEST_F(azihsm_hkdf, hkdf_supports_aes_192)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        const uint8_t salt[] = { 0x10, 0x20, 0x30 };
        const uint8_t info[] = { 0x40, 0x50, 0x60 };

        azihsm_buffer salt_buf = {
            .ptr = const_cast<uint8_t *>(salt),
            .len = sizeof(salt)
        };

        azihsm_buffer info_buf = {
            .ptr = const_cast<uint8_t *>(info),
            .len = sizeof(info)
        };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(
            hkdf_params,
            hkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 192, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 192, key_b);

        const char *msg = "hkdf aes 192";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF rejects invalid AES output key size
TEST_F(azihsm_hkdf, hkdf_rejects_invalid_aes_key_size)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 129;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that identical HKDF inputs produce compatible derived keys
TEST_F(azihsm_hkdf, hkdf_same_inputs_are_deterministic)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        const uint8_t salt[] = { 0x11, 0x22, 0x33, 0x44 };
        const uint8_t info[] = { 0x55, 0x66, 0x77, 0x88 };

        azihsm_buffer salt_buf = {
            .ptr = const_cast<uint8_t *>(salt),
            .len = sizeof(salt)
        };

        azihsm_buffer info_buf = {
            .ptr = const_cast<uint8_t *>(info),
            .len = sizeof(info)
        };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(
            hkdf_params,
            hkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "same inputs deterministic";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF rejects very small invalid AES output key size
TEST_F(azihsm_hkdf, hkdf_rejects_too_small_aes_key_size)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 1;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test empty salt/info roundtrip for P-384
TEST_F(azihsm_hkdf, hkdf_empty_salt_info_roundtrip_p384)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P384, secret_a, secret_b);

        azihsm_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        azihsm_buffer info_buf = { .ptr = nullptr, .len = 0 };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(
            hkdf_params,
            hkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "empty salt info p384";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test empty salt/info roundtrip for P-521
TEST_F(azihsm_hkdf, hkdf_empty_salt_info_roundtrip_p521)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P521, secret_a, secret_b);

        azihsm_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        azihsm_buffer info_buf = { .ptr = nullptr, .len = 0 };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(
            hkdf_params,
            hkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "empty salt info p521";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF accepts large salt/info buffers
TEST_F(azihsm_hkdf, hkdf_salt_info_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        std::vector<uint8_t> salt(64, 0xA5);
        std::vector<uint8_t> info(64, 0x5A);

        azihsm_buffer salt_buf = {
            .ptr = salt.data(),
            .len = salt.size()
        };

        azihsm_buffer info_buf = {
            .ptr = info.data(),
            .len = info.size()
        };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(
            hkdf_params,
            hkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "large salt info";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF rejects public output key class
TEST_F(azihsm_hkdf, hkdf_rejects_public_output_key_class)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_PUBLIC;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 256;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            AZIHSM_STATUS_INVALID_KEY_PROPS
        );
    });
}

/// Test that HKDF supports AES-256 output key size
TEST_F(azihsm_hkdf, hkdf_supports_aes_256)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        const uint8_t salt[] = { 0x10, 0x20, 0x30 };
        const uint8_t info[] = { 0x40, 0x50, 0x60 };

        azihsm_buffer salt_buf = {
            .ptr = const_cast<uint8_t *>(salt),
            .len = sizeof(salt)
        };

        azihsm_buffer info_buf = {
            .ptr = const_cast<uint8_t *>(info),
            .len = sizeof(info)
        };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(
            hkdf_params,
            hkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "hkdf aes 256";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}

/// Test that HKDF rejects oversized AES output key size
TEST_F(azihsm_hkdf, hkdf_rejects_oversized_aes_key_size)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 1024;
        props.encrypt = 1;
        props.decrypt = 1;

        hkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            AZIHSM_STATUS_INVALID_ARGUMENT
        );
    });
}

/// Test that HKDF rejects AES output key with no usage flags
TEST_F(azihsm_hkdf, hkdf_rejects_aes_key_without_usage_flags)
{
    part_list_.for_each_session([](azihsm_handle session) {
        key_props props = {};
        props.key_class = AZIHSM_KEY_CLASS_SECRET;
        props.key_kind = AZIHSM_KEY_KIND_AES;
        props.key_size_bits = 256;
        props.encrypt = 0;
        props.decrypt = 0;

        hkdf_derive_fails_common(
            session,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            props,
            AZIHSM_STATUS_DDI_CMD_FAILURE
        );
    });
}

/// Test HKDF derive when only salt is provided
TEST_F(azihsm_hkdf, hkdf_with_only_salt)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        const uint8_t salt[] = { 'h', 'k', 'd', 'f', '-', 's', 'a', 'l', 't' };
        azihsm_buffer salt_buf = {
            .ptr = const_cast<uint8_t *>(salt),
            .len = sizeof(salt)
        };

        azihsm_buffer info_buf = { .ptr = nullptr, .len = 0 };

        for (uint32_t bits : { 128u, 192u, 256u }) {
            azihsm_algo_hkdf_params hkdf_params{};
            azihsm_algo hkdf_algo{};
            build_hkdf_algo(
                hkdf_params,
                hkdf_algo,
                AZIHSM_ALGO_ID_HMAC_SHA256,
                &salt_buf,
                &info_buf
            );

            auto_key key_a;
            derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), bits, key_a);

            auto_key key_b;
            derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), bits, key_b);

            std::string msg = "hkdf only salt aes " + std::to_string(bits);
            assert_aes_cbc_roundtrip(
                key_a.get(),
                key_b.get(),
                reinterpret_cast<const uint8_t *>(msg.data()),
                msg.size()
            );
        }
    });
}

/// Test HKDF derive when only info is provided
TEST_F(azihsm_hkdf, hkdf_with_only_info)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        azihsm_buffer salt_buf = { .ptr = nullptr, .len = 0 };

        const uint8_t info[] = { 'h', 'k', 'd', 'f', '-', 'i', 'n', 'f', 'o' };
        azihsm_buffer info_buf = {
            .ptr = const_cast<uint8_t *>(info),
            .len = sizeof(info)
        };

        for (uint32_t bits : { 128u, 192u, 256u }) {
            azihsm_algo_hkdf_params hkdf_params{};
            azihsm_algo hkdf_algo{};
            build_hkdf_algo(
                hkdf_params,
                hkdf_algo,
                AZIHSM_ALGO_ID_HMAC_SHA256,
                &salt_buf,
                &info_buf
            );

            auto_key key_a;
            derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), bits, key_a);

            auto_key key_b;
            derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), bits, key_b);

            std::string msg = "hkdf only info aes " + std::to_string(bits);
            assert_aes_cbc_roundtrip(
                key_a.get(),
                key_b.get(),
                reinterpret_cast<const uint8_t *>(msg.data()),
                msg.size()
            );
        }
    });
}

/// Test HKDF-derived AES keys with large plaintext
TEST_F(azihsm_hkdf, hkdf_large_plaintext_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        azihsm_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        azihsm_buffer info_buf = { .ptr = nullptr, .len = 0 };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(
            hkdf_params,
            hkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        std::vector<uint8_t> plaintext(32 * 1024, 0x55);

        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            plaintext.data(),
            plaintext.size()
        );
    });
}

/// Test HKDF-derived AES keys with empty plaintext
TEST_F(azihsm_hkdf, hkdf_empty_plaintext_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        azihsm_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        azihsm_buffer info_buf = { .ptr = nullptr, .len = 0 };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(
            hkdf_params,
            hkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const uint8_t *plaintext = reinterpret_cast<const uint8_t *>("");

        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            plaintext,
            0
        );
    });
}

/// Test HKDF-derived AES keys with single-byte plaintext
TEST_F(azihsm_hkdf, hkdf_single_byte_plaintext_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        azihsm_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        azihsm_buffer info_buf = { .ptr = nullptr, .len = 0 };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(
            hkdf_params,
            hkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const uint8_t plaintext[] = { 'A' };

        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            plaintext,
            sizeof(plaintext)
        );
    });
}

/// Test deriving multiple AES key sizes using the same HKDF parameters
TEST_F(azihsm_hkdf, hkdf_multi_key_size_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        azihsm_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        azihsm_buffer info_buf = { .ptr = nullptr, .len = 0 };

        for (uint32_t bits : { 128u, 192u, 256u }) {
            azihsm_algo_hkdf_params hkdf_params{};
            azihsm_algo hkdf_algo{};
            build_hkdf_algo(
                hkdf_params,
                hkdf_algo,
                AZIHSM_ALGO_ID_HMAC_SHA256,
                &salt_buf,
                &info_buf
            );

            auto_key key_a;
            derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), bits, key_a);

            auto_key key_b;
            derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), bits, key_b);

            const char *msg = "multi key size";
            assert_aes_cbc_roundtrip(
                key_a.get(),
                key_b.get(),
                reinterpret_cast<const uint8_t *>(msg),
                std::strlen(msg)
            );
        }
    });
}

/// Test HKDF with 128-byte salt/info buffers
TEST_F(azihsm_hkdf, hkdf_long_salt_info_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        std::vector<uint8_t> salt(128, 0x11);
        std::vector<uint8_t> info(128, 0x22);

        azihsm_buffer salt_buf = {
            .ptr = salt.data(),
            .len = salt.size()
        };

        azihsm_buffer info_buf = {
            .ptr = info.data(),
            .len = info.size()
        };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(
            hkdf_params,
            hkdf_algo,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_buf
        );

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "long salt info";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}