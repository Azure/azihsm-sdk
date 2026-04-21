// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "handle/part_list_handle.hpp"
#include "utils/auto_key.hpp"
#include "utils/shared_secret.hpp"
#include "utils/kdf_derive.hpp"

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

TEST_F(azihsm_hkdf, hkdf_matrix_p256)
{
    part_list_.for_each_session(
        [](azihsm_handle session) { run_hkdf_matrix_for_curve(session, AZIHSM_ECC_CURVE_P256); }
    );
}

TEST_F(azihsm_hkdf, hkdf_matrix_p384)
{
    part_list_.for_each_session(
        [](azihsm_handle session) { run_hkdf_matrix_for_curve(session, AZIHSM_ECC_CURVE_P384); }
    );
}

TEST_F(azihsm_hkdf, hkdf_matrix_p521)
{
    part_list_.for_each_session(
        [](azihsm_handle session) { run_hkdf_matrix_for_curve(session, AZIHSM_ECC_CURVE_P521); }
    );
}

TEST_F(azihsm_hkdf, hkdf_derive_aes_gcm_key_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, AZIHSM_ALGO_ID_HMAC_SHA256, nullptr, nullptr);

        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES_GCM;
        uint32_t bits = 256;
        uint8_t can_encrypt = 1;
        uint8_t can_decrypt = 1;

        std::vector<azihsm_key_prop> props;
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &can_decrypt, .len = sizeof(can_decrypt) }
        );

        azihsm_key_prop_list prop_list = { .props = props.data(),
                                           .count = static_cast<uint32_t>(props.size()) };

        // AesGcm is not in GenericSecretKey::check_key_kind, so validate_props
        // (called inside HsmKeyManager::derive_key) rejects it with InvalidKeyProps.
        azihsm_handle derived_handle = 0;
        auto err =
            azihsm_key_derive(session, &hkdf_algo, secret_a.get(), &prop_list, &derived_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(derived_handle, 0u);
    });
}

TEST_F(azihsm_hkdf, hkdf_derive_unsupported_key_kind_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, AZIHSM_ALGO_ID_HMAC_SHA256, nullptr, nullptr);

        // SharedSecret passes GenericSecretKey::validate_props but is not a valid
        // HKDF output key type in the DDI TryFrom<&HsmKeyProps> for DdiKeyType
        // (api/lib/src/ddi/hkdf.rs:101-117), which returns InvalidArgument.
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_SHARED_SECRET;
        uint32_t bits = 256;
        uint8_t can_derive = 1;

        std::vector<azihsm_key_prop> props;
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_DERIVE, .val = &can_derive, .len = sizeof(can_derive) }
        );

        azihsm_key_prop_list prop_list = { .props = props.data(),
                                           .count = static_cast<uint32_t>(props.size()) };

        azihsm_handle derived_handle = 0;
        auto err =
            azihsm_key_derive(session, &hkdf_algo, secret_a.get(), &prop_list, &derived_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(derived_handle, 0u);
    });
}

TEST_F(azihsm_hkdf, hkdf_derive_invalid_hmac_algo_id_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        // Use an algo ID that is not a valid HMAC algorithm to trigger the default branch
        // of the match on hmac_algo_id at kdf.rs:121
        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, AZIHSM_ALGO_ID_SHA256, nullptr, nullptr);

        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES;
        uint32_t bits = 256;
        uint8_t can_encrypt = 1;
        uint8_t can_decrypt = 1;

        std::vector<azihsm_key_prop> props;
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &can_decrypt, .len = sizeof(can_decrypt) }
        );

        azihsm_key_prop_list prop_list = { .props = props.data(),
                                           .count = static_cast<uint32_t>(props.size()) };

        azihsm_handle derived_handle = 0;
        auto err =
            azihsm_key_derive(session, &hkdf_algo, secret_a.get(), &prop_list, &derived_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(derived_handle, 0u);
    });
}

TEST_F(azihsm_hkdf, hkdf_derive_zero_bit_len_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, AZIHSM_ALGO_ID_HMAC_SHA256, nullptr, nullptr);

        // Use bits=0 to cause HsmGenericSecretKey::validate_props (called inside
        // HsmKeyManager::derive_key at kdf.rs:154) to fail.
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES;
        uint32_t bits = 0;
        uint8_t can_encrypt = 1;
        uint8_t can_decrypt = 1;

        std::vector<azihsm_key_prop> props;
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &can_decrypt, .len = sizeof(can_decrypt) }
        );

        azihsm_key_prop_list prop_list = { .props = props.data(),
                                           .count = static_cast<uint32_t>(props.size()) };

        azihsm_handle derived_handle = 0;
        auto err =
            azihsm_key_derive(session, &hkdf_algo, secret_a.get(), &prop_list, &derived_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(derived_handle, 0u);
    });
}

TEST_F(azihsm_hkdf, hkdf_empty_salt_info_fails)
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
