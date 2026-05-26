// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/auto_key.hpp"
#include "utils/rsa_keygen.hpp"

class azihsm_rsa_keygen : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

TEST_F(azihsm_rsa_keygen, generate_rsa_2048_keypair)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(priv_key.get(), 0);
        ASSERT_NE(pub_key.get(), 0);

        // Explicitly test deletion (auto_key will also delete on scope exit as backup)
        auto delete_priv_err = azihsm_key_delete(priv_key.get());
        ASSERT_EQ(delete_priv_err, AZIHSM_STATUS_SUCCESS);
        priv_key.release();

        auto delete_pub_err = azihsm_key_delete(pub_key.get());
        ASSERT_EQ(delete_pub_err, AZIHSM_STATUS_SUCCESS);
        pub_key.release();
    });
}

TEST_F(azihsm_rsa_keygen, get_key_properties)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_key_kind kind{};
        azihsm_key_prop prop{ .id = AZIHSM_KEY_PROP_ID_KIND, .val = &kind, .len = sizeof(kind) };

        err = azihsm_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(kind, AZIHSM_KEY_KIND_RSA);

        azihsm_key_class key_class{};
        prop.id = AZIHSM_KEY_PROP_ID_CLASS;
        prop.val = &key_class;
        prop.len = sizeof(key_class);

        err = azihsm_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(key_class, AZIHSM_KEY_CLASS_PRIVATE);
    });
}

TEST_F(azihsm_rsa_keygen, get_key_prop_rejects_invalid_output_buffer)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_key_kind kind{};
        azihsm_key_prop prop{ .id = AZIHSM_KEY_PROP_ID_KIND, .val = nullptr, .len = sizeof(kind) };

        err = azihsm_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
    });
}

TEST_F(azihsm_rsa_keygen, get_key_prop_ec_curve_not_present)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_ecc_curve curve{};
        azihsm_key_prop prop{ .id = AZIHSM_KEY_PROP_ID_EC_CURVE,
                              .val = &curve,
                              .len = sizeof(curve) };

        err = azihsm_key_get_prop(priv_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_PROPERTY_NOT_PRESENT);
    });
}

TEST_F(azihsm_rsa_keygen, get_key_prop_unknown_property_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key priv_key;
        auto_key pub_key;
        auto err = generate_rsa_unwrapping_keypair(session, priv_key.get_ptr(), pub_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        uint32_t value{};
        azihsm_key_prop prop{ .id = static_cast<azihsm_key_prop_id>(0xFFFFFFFF),
                              .val = &value,
                              .len = sizeof(value) };

        err = azihsm_key_get_prop(pub_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_UNSUPPORTED_PROPERTY);
    });
}
