// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "../ecc/helpers.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "rsa_static_der.hpp"
#include "utils/auto_key.hpp"
#include "utils/rsa_keygen.hpp"

class azihsm_rsa_unwrap : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// Wraps a pre-generated external RSA PKCS#8 private key blob for key_unwrap_pair tests.
static azihsm_status make_wrapped_rsa_pkcs8_blob(
    azihsm_handle wrapping_pub_key,
    uint32_t bit_len,
    const RsaAesWrapConfig &wrap_config,
    std::vector<uint8_t> &wrapped_blob
)
{
    const uint8_t *pkcs8_der = nullptr;
    size_t pkcs8_der_len = 0;

    auto err = get_static_rsa_pkcs8_der(bit_len, pkcs8_der, pkcs8_der_len);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        wrapped_blob.clear();
        return err;
    }

    std::vector<uint8_t> pkcs8_bytes(pkcs8_der, pkcs8_der + pkcs8_der_len);

    return wrap_plaintext_with_rsa_aes(wrapping_pub_key, pkcs8_bytes, wrap_config, wrapped_blob);
}

// Unwraps the external RSA-2048 PKCS#8 key using caller-selected KIND and CLASS properties.
static UnwrapPairResult unwrap_external_rsa_pair_with_identity_properties(
    azihsm_handle session,
    azihsm_key_kind private_kind,
    azihsm_key_class private_class,
    azihsm_key_kind public_kind,
    azihsm_key_class public_class
)
{
    UnwrapPairResult result{};

    auto_key wrapping_private_key;
    auto_key wrapping_public_key;

    auto err = generate_rsa_unwrapping_keypair(
        session,
        wrapping_private_key.get_ptr(),
        wrapping_public_key.get_ptr()
    );
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        result.status = err;
        return result;
    }

    std::vector<uint8_t> wrapped_blob;
    err = make_wrapped_rsa_pkcs8_blob(
        wrapping_public_key.get(),
        2048,
        RsaAesWrapConfig{},
        wrapped_blob
    );
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        result.status = err;
        return result;
    }

    azihsm_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                   .len = static_cast<uint32_t>(wrapped_blob.size()) };

    RsaAesUnwrapAlgo unwrap_algo{};

    uint32_t private_bit_len = 2048;
    uint8_t private_session = 1;
    uint8_t private_decrypt = 1;

    std::vector<azihsm_key_prop> private_props = {
        { AZIHSM_KEY_PROP_ID_CLASS, &private_class, sizeof(private_class) },
        { AZIHSM_KEY_PROP_ID_KIND, &private_kind, sizeof(private_kind) },
        { AZIHSM_KEY_PROP_ID_BIT_LEN, &private_bit_len, sizeof(private_bit_len) },
        { AZIHSM_KEY_PROP_ID_SESSION, &private_session, sizeof(private_session) },
        { AZIHSM_KEY_PROP_ID_DECRYPT, &private_decrypt, sizeof(private_decrypt) }
    };

    uint32_t public_bit_len = 2048;
    uint8_t public_session = 1;
    uint8_t public_encrypt = 1;

    std::vector<azihsm_key_prop> public_props = {
        { AZIHSM_KEY_PROP_ID_CLASS, &public_class, sizeof(public_class) },
        { AZIHSM_KEY_PROP_ID_KIND, &public_kind, sizeof(public_kind) },
        { AZIHSM_KEY_PROP_ID_BIT_LEN, &public_bit_len, sizeof(public_bit_len) },
        { AZIHSM_KEY_PROP_ID_SESSION, &public_session, sizeof(public_session) },
        { AZIHSM_KEY_PROP_ID_ENCRYPT, &public_encrypt, sizeof(public_encrypt) }
    };

    azihsm_key_prop_list private_prop_list{ .props = private_props.data(),
                                            .count = static_cast<uint32_t>(private_props.size()) };

    azihsm_key_prop_list public_prop_list{ .props = public_props.data(),
                                           .count = static_cast<uint32_t>(public_props.size()) };

    return try_unwrap_pair(
        &unwrap_algo.algo,
        wrapping_private_key.get(),
        &wrapped_key_buf,
        &private_prop_list,
        &public_prop_list
    );
}

// Verifies an externally generated 2048-bit RSA key pair can be unwrapped successfully.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_2048_keypair_succeeds)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key wrapping_private_key;
        auto_key wrapping_public_key;

        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_private_key.get_ptr(),
            wrapping_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> wrapped_blob;
        err = make_wrapped_rsa_pkcs8_blob(
            wrapping_public_key.get(),
            2048,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());

        azihsm_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                       .len = static_cast<uint32_t>(wrapped_blob.size()) };

        RsaAesUnwrapAlgo unwrap_algo{};

        azihsm_key_class private_class = AZIHSM_KEY_CLASS_PRIVATE;
        azihsm_key_kind private_kind = AZIHSM_KEY_KIND_RSA;
        uint32_t private_bit_len = 2048;
        uint8_t private_session = 1;
        uint8_t private_decrypt = 1;

        std::vector<azihsm_key_prop> private_props = {
            { AZIHSM_KEY_PROP_ID_CLASS, &private_class, sizeof(private_class) },
            { AZIHSM_KEY_PROP_ID_KIND, &private_kind, sizeof(private_kind) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &private_bit_len, sizeof(private_bit_len) },
            { AZIHSM_KEY_PROP_ID_SESSION, &private_session, sizeof(private_session) },
            { AZIHSM_KEY_PROP_ID_DECRYPT, &private_decrypt, sizeof(private_decrypt) }
        };

        azihsm_key_class public_class = AZIHSM_KEY_CLASS_PUBLIC;
        azihsm_key_kind public_kind = AZIHSM_KEY_KIND_RSA;
        uint32_t public_bit_len = 2048;
        uint8_t public_session = 1;
        uint8_t public_encrypt = 1;

        std::vector<azihsm_key_prop> public_props = {
            { AZIHSM_KEY_PROP_ID_CLASS, &public_class, sizeof(public_class) },
            { AZIHSM_KEY_PROP_ID_KIND, &public_kind, sizeof(public_kind) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &public_bit_len, sizeof(public_bit_len) },
            { AZIHSM_KEY_PROP_ID_SESSION, &public_session, sizeof(public_session) },
            { AZIHSM_KEY_PROP_ID_ENCRYPT, &public_encrypt, sizeof(public_encrypt) }
        };

        azihsm_key_prop_list private_prop_list{ .props = private_props.data(),
                                                .count =
                                                    static_cast<uint32_t>(private_props.size()) };

        azihsm_key_prop_list public_prop_list{ .props = public_props.data(),
                                               .count =
                                                   static_cast<uint32_t>(public_props.size()) };

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            wrapping_private_key.get(),
            &wrapped_key_buf,
            &private_prop_list,
            &public_prop_list
        );

        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);
        ASSERT_NE(result.private_key, result.public_key);

        auto_key imported_private_key;
        auto_key imported_public_key;
        imported_private_key.handle = result.private_key;
        imported_public_key.handle = result.public_key;
    });
}

// Verifies an unwrapped external RSA key pair reports the expected properties.
TEST_F(azihsm_rsa_unwrap, unwrapped_external_rsa_keypair_reports_expected_properties)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key wrapping_private_key;
        auto_key wrapping_public_key;

        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_private_key.get_ptr(),
            wrapping_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> wrapped_blob;
        err = make_wrapped_rsa_pkcs8_blob(
            wrapping_public_key.get(),
            2048,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                       .len = static_cast<uint32_t>(wrapped_blob.size()) };

        RsaAesUnwrapAlgo unwrap_algo{};

        azihsm_key_class private_class = AZIHSM_KEY_CLASS_PRIVATE;
        azihsm_key_kind private_kind = AZIHSM_KEY_KIND_RSA;
        uint32_t private_bit_len = 2048;
        uint8_t private_session = 1;
        uint8_t private_decrypt = 1;

        std::vector<azihsm_key_prop> private_props = {
            { AZIHSM_KEY_PROP_ID_CLASS, &private_class, sizeof(private_class) },
            { AZIHSM_KEY_PROP_ID_KIND, &private_kind, sizeof(private_kind) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &private_bit_len, sizeof(private_bit_len) },
            { AZIHSM_KEY_PROP_ID_SESSION, &private_session, sizeof(private_session) },
            { AZIHSM_KEY_PROP_ID_DECRYPT, &private_decrypt, sizeof(private_decrypt) }
        };

        azihsm_key_class public_class = AZIHSM_KEY_CLASS_PUBLIC;
        azihsm_key_kind public_kind = AZIHSM_KEY_KIND_RSA;
        uint32_t public_bit_len = 2048;
        uint8_t public_session = 1;
        uint8_t public_encrypt = 1;

        std::vector<azihsm_key_prop> public_props = {
            { AZIHSM_KEY_PROP_ID_CLASS, &public_class, sizeof(public_class) },
            { AZIHSM_KEY_PROP_ID_KIND, &public_kind, sizeof(public_kind) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &public_bit_len, sizeof(public_bit_len) },
            { AZIHSM_KEY_PROP_ID_SESSION, &public_session, sizeof(public_session) },
            { AZIHSM_KEY_PROP_ID_ENCRYPT, &public_encrypt, sizeof(public_encrypt) }
        };

        azihsm_key_prop_list private_prop_list{ .props = private_props.data(),
                                                .count =
                                                    static_cast<uint32_t>(private_props.size()) };

        azihsm_key_prop_list public_prop_list{ .props = public_props.data(),
                                               .count =
                                                   static_cast<uint32_t>(public_props.size()) };

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            wrapping_private_key.get(),
            &wrapped_key_buf,
            &private_prop_list,
            &public_prop_list
        );
        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);

        auto_key imported_private_key;
        auto_key imported_public_key;
        imported_private_key.handle = result.private_key;
        imported_public_key.handle = result.public_key;

        azihsm_key_kind actual_private_kind{};
        azihsm_key_prop prop{ .id = AZIHSM_KEY_PROP_ID_KIND,
                              .val = &actual_private_kind,
                              .len = sizeof(actual_private_kind) };

        err = azihsm_key_get_prop(imported_private_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(actual_private_kind, AZIHSM_KEY_KIND_RSA);

        azihsm_key_class actual_private_class{};
        prop.id = AZIHSM_KEY_PROP_ID_CLASS;
        prop.val = &actual_private_class;
        prop.len = sizeof(actual_private_class);

        err = azihsm_key_get_prop(imported_private_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(actual_private_class, AZIHSM_KEY_CLASS_PRIVATE);

        uint32_t actual_private_bits{};
        prop.id = AZIHSM_KEY_PROP_ID_BIT_LEN;
        prop.val = &actual_private_bits;
        prop.len = sizeof(actual_private_bits);

        err = azihsm_key_get_prop(imported_private_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(actual_private_bits, 2048u);

        azihsm_key_kind actual_public_kind{};
        prop.id = AZIHSM_KEY_PROP_ID_KIND;
        prop.val = &actual_public_kind;
        prop.len = sizeof(actual_public_kind);

        err = azihsm_key_get_prop(imported_public_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(actual_public_kind, AZIHSM_KEY_KIND_RSA);

        azihsm_key_class actual_public_class{};
        prop.id = AZIHSM_KEY_PROP_ID_CLASS;
        prop.val = &actual_public_class;
        prop.len = sizeof(actual_public_class);

        err = azihsm_key_get_prop(imported_public_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(actual_public_class, AZIHSM_KEY_CLASS_PUBLIC);

        uint32_t actual_public_bits{};
        prop.id = AZIHSM_KEY_PROP_ID_BIT_LEN;
        prop.val = &actual_public_bits;
        prop.len = sizeof(actual_public_bits);

        err = azihsm_key_get_prop(imported_public_key.get(), &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(actual_public_bits, 2048u);
    });
}

// Verifies RSA unwrap rejects corrupted externally generated key material.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_keypair_rejects_corrupted_blob)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key wrapping_private_key;
        auto_key wrapping_public_key;

        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_private_key.get_ptr(),
            wrapping_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> wrapped_blob;
        err = make_wrapped_rsa_pkcs8_blob(
            wrapping_public_key.get(),
            2048,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());

        wrapped_blob[wrapped_blob.size() / 2] ^= 0xA5;

        azihsm_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                       .len = static_cast<uint32_t>(wrapped_blob.size()) };

        RsaAesUnwrapAlgo unwrap_algo{};

        azihsm_key_class private_class = AZIHSM_KEY_CLASS_PRIVATE;
        azihsm_key_kind private_kind = AZIHSM_KEY_KIND_RSA;
        uint32_t private_bit_len = 2048;
        uint8_t private_session = 1;
        uint8_t private_decrypt = 1;

        std::vector<azihsm_key_prop> private_props = {
            { AZIHSM_KEY_PROP_ID_CLASS, &private_class, sizeof(private_class) },
            { AZIHSM_KEY_PROP_ID_KIND, &private_kind, sizeof(private_kind) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &private_bit_len, sizeof(private_bit_len) },
            { AZIHSM_KEY_PROP_ID_SESSION, &private_session, sizeof(private_session) },
            { AZIHSM_KEY_PROP_ID_DECRYPT, &private_decrypt, sizeof(private_decrypt) }
        };

        azihsm_key_class public_class = AZIHSM_KEY_CLASS_PUBLIC;
        azihsm_key_kind public_kind = AZIHSM_KEY_KIND_RSA;
        uint32_t public_bit_len = 2048;
        uint8_t public_session = 1;
        uint8_t public_encrypt = 1;

        std::vector<azihsm_key_prop> public_props = {
            { AZIHSM_KEY_PROP_ID_CLASS, &public_class, sizeof(public_class) },
            { AZIHSM_KEY_PROP_ID_KIND, &public_kind, sizeof(public_kind) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &public_bit_len, sizeof(public_bit_len) },
            { AZIHSM_KEY_PROP_ID_SESSION, &public_session, sizeof(public_session) },
            { AZIHSM_KEY_PROP_ID_ENCRYPT, &public_encrypt, sizeof(public_encrypt) }
        };

        azihsm_key_prop_list private_prop_list{ .props = private_props.data(),
                                                .count =
                                                    static_cast<uint32_t>(private_props.size()) };

        azihsm_key_prop_list public_prop_list{ .props = public_props.data(),
                                               .count =
                                                   static_cast<uint32_t>(public_props.size()) };

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            wrapping_private_key.get(),
            &wrapped_key_buf,
            &private_prop_list,
            &public_prop_list
        );

        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies RSA unwrap rejects a blob wrapped by a key from a different partition.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_rejects_wrong_unwrapping_key)
{
    if (part_list_.count() < 2u)
    {
        GTEST_SKIP(
        ) << "requires at least two partitions to guarantee distinct wrapping-key contexts";
    }

    auto source_path = part_list_.get_path(0);
    auto other_path = part_list_.get_path(1);

    auto source_partition = PartitionHandle(source_path);
    auto other_partition = PartitionHandle(other_path);

    std::vector<uint8_t> wrapped_blob;
    auto_key wrong_unwrapping_private_key;

    // Wrap the external RSA key using a public key from the first partition.
    {
        SessionHandle source_session(source_partition.get());

        auto_key source_wrapping_private_key;
        auto_key source_wrapping_public_key;

        auto err = generate_rsa_unwrapping_keypair(
            source_session.get(),
            source_wrapping_private_key.get_ptr(),
            source_wrapping_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        err = make_wrapped_rsa_pkcs8_blob(
            source_wrapping_public_key.get(),
            2048,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());
    }

    // Generate the wrong unwrapping private key in a different partition.
    {
        SessionHandle other_session(other_partition.get());

        auto_key wrong_wrapping_public_key;

        auto err = generate_rsa_unwrapping_keypair(
            other_session.get(),
            wrong_unwrapping_private_key.get_ptr(),
            wrong_wrapping_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    }

    azihsm_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                   .len = static_cast<uint32_t>(wrapped_blob.size()) };

    RsaAesUnwrapAlgo unwrap_algo{};

    azihsm_key_class private_class = AZIHSM_KEY_CLASS_PRIVATE;
    azihsm_key_kind private_kind = AZIHSM_KEY_KIND_RSA;
    uint32_t private_bit_len = 2048;
    uint8_t private_session = 1;
    uint8_t private_decrypt = 1;

    std::vector<azihsm_key_prop> private_props = {
        { AZIHSM_KEY_PROP_ID_CLASS, &private_class, sizeof(private_class) },
        { AZIHSM_KEY_PROP_ID_KIND, &private_kind, sizeof(private_kind) },
        { AZIHSM_KEY_PROP_ID_BIT_LEN, &private_bit_len, sizeof(private_bit_len) },
        { AZIHSM_KEY_PROP_ID_SESSION, &private_session, sizeof(private_session) },
        { AZIHSM_KEY_PROP_ID_DECRYPT, &private_decrypt, sizeof(private_decrypt) }
    };

    azihsm_key_class public_class = AZIHSM_KEY_CLASS_PUBLIC;
    azihsm_key_kind public_kind = AZIHSM_KEY_KIND_RSA;
    uint32_t public_bit_len = 2048;
    uint8_t public_session = 1;
    uint8_t public_encrypt = 1;

    std::vector<azihsm_key_prop> public_props = {
        { AZIHSM_KEY_PROP_ID_CLASS, &public_class, sizeof(public_class) },
        { AZIHSM_KEY_PROP_ID_KIND, &public_kind, sizeof(public_kind) },
        { AZIHSM_KEY_PROP_ID_BIT_LEN, &public_bit_len, sizeof(public_bit_len) },
        { AZIHSM_KEY_PROP_ID_SESSION, &public_session, sizeof(public_session) },
        { AZIHSM_KEY_PROP_ID_ENCRYPT, &public_encrypt, sizeof(public_encrypt) }
    };

    azihsm_key_prop_list private_prop_list{ .props = private_props.data(),
                                            .count = static_cast<uint32_t>(private_props.size()) };

    azihsm_key_prop_list public_prop_list{ .props = public_props.data(),
                                           .count = static_cast<uint32_t>(public_props.size()) };

    auto result = try_unwrap_pair(
        &unwrap_algo.algo,
        wrong_unwrapping_private_key.get(),
        &wrapped_key_buf,
        &private_prop_list,
        &public_prop_list
    );

    ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(result.private_key, 0);
    ASSERT_EQ(result.public_key, 0);
}

// Verifies RSA unwrap rejects a truncated wrapped blob.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_rejects_truncated_blob)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key wrapping_private_key;
        auto_key wrapping_public_key;

        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_private_key.get_ptr(),
            wrapping_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> wrapped_blob;
        err = make_wrapped_rsa_pkcs8_blob(
            wrapping_public_key.get(),
            2048,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(wrapped_blob.size(), 1u);

        wrapped_blob.pop_back();

        azihsm_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                       .len = static_cast<uint32_t>(wrapped_blob.size()) };

        RsaAesUnwrapAlgo unwrap_algo{};

        azihsm_key_class private_class = AZIHSM_KEY_CLASS_PRIVATE;
        azihsm_key_kind private_kind = AZIHSM_KEY_KIND_RSA;
        uint32_t private_bit_len = 2048;
        uint8_t private_session = 1;
        uint8_t private_decrypt = 1;

        std::vector<azihsm_key_prop> private_props = {
            { AZIHSM_KEY_PROP_ID_CLASS, &private_class, sizeof(private_class) },
            { AZIHSM_KEY_PROP_ID_KIND, &private_kind, sizeof(private_kind) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &private_bit_len, sizeof(private_bit_len) },
            { AZIHSM_KEY_PROP_ID_SESSION, &private_session, sizeof(private_session) },
            { AZIHSM_KEY_PROP_ID_DECRYPT, &private_decrypt, sizeof(private_decrypt) }
        };

        azihsm_key_class public_class = AZIHSM_KEY_CLASS_PUBLIC;
        azihsm_key_kind public_kind = AZIHSM_KEY_KIND_RSA;
        uint32_t public_bit_len = 2048;
        uint8_t public_session = 1;
        uint8_t public_encrypt = 1;

        std::vector<azihsm_key_prop> public_props = {
            { AZIHSM_KEY_PROP_ID_CLASS, &public_class, sizeof(public_class) },
            { AZIHSM_KEY_PROP_ID_KIND, &public_kind, sizeof(public_kind) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &public_bit_len, sizeof(public_bit_len) },
            { AZIHSM_KEY_PROP_ID_SESSION, &public_session, sizeof(public_session) },
            { AZIHSM_KEY_PROP_ID_ENCRYPT, &public_encrypt, sizeof(public_encrypt) }
        };

        azihsm_key_prop_list private_prop_list{ .props = private_props.data(),
                                                .count =
                                                    static_cast<uint32_t>(private_props.size()) };

        azihsm_key_prop_list public_prop_list{ .props = public_props.data(),
                                               .count =
                                                   static_cast<uint32_t>(public_props.size()) };

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            wrapping_private_key.get(),
            &wrapped_key_buf,
            &private_prop_list,
            &public_prop_list
        );

        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies RSA unwrap rejects a requested bit length that does not match the wrapped key.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_rejects_requested_bit_length_mismatch)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key wrapping_private_key;
        auto_key wrapping_public_key;

        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_private_key.get_ptr(),
            wrapping_public_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> wrapped_blob;
        err = make_wrapped_rsa_pkcs8_blob(
            wrapping_public_key.get(),
            2048,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                       .len = static_cast<uint32_t>(wrapped_blob.size()) };

        RsaAesUnwrapAlgo unwrap_algo{};

        azihsm_key_class private_class = AZIHSM_KEY_CLASS_PRIVATE;
        azihsm_key_kind private_kind = AZIHSM_KEY_KIND_RSA;
        uint32_t private_bit_len = 3072;
        uint8_t private_session = 1;
        uint8_t private_decrypt = 1;

        std::vector<azihsm_key_prop> private_props = {
            { AZIHSM_KEY_PROP_ID_CLASS, &private_class, sizeof(private_class) },
            { AZIHSM_KEY_PROP_ID_KIND, &private_kind, sizeof(private_kind) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &private_bit_len, sizeof(private_bit_len) },
            { AZIHSM_KEY_PROP_ID_SESSION, &private_session, sizeof(private_session) },
            { AZIHSM_KEY_PROP_ID_DECRYPT, &private_decrypt, sizeof(private_decrypt) }
        };

        azihsm_key_class public_class = AZIHSM_KEY_CLASS_PUBLIC;
        azihsm_key_kind public_kind = AZIHSM_KEY_KIND_RSA;
        uint32_t public_bit_len = 3072;
        uint8_t public_session = 1;
        uint8_t public_encrypt = 1;

        std::vector<azihsm_key_prop> public_props = {
            { AZIHSM_KEY_PROP_ID_CLASS, &public_class, sizeof(public_class) },
            { AZIHSM_KEY_PROP_ID_KIND, &public_kind, sizeof(public_kind) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &public_bit_len, sizeof(public_bit_len) },
            { AZIHSM_KEY_PROP_ID_SESSION, &public_session, sizeof(public_session) },
            { AZIHSM_KEY_PROP_ID_ENCRYPT, &public_encrypt, sizeof(public_encrypt) }
        };

        azihsm_key_prop_list private_prop_list{ .props = private_props.data(),
                                                .count =
                                                    static_cast<uint32_t>(private_props.size()) };

        azihsm_key_prop_list public_prop_list{ .props = public_props.data(),
                                               .count =
                                                   static_cast<uint32_t>(public_props.size()) };

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            wrapping_private_key.get(),
            &wrapped_key_buf,
            &private_prop_list,
            &public_prop_list
        );

        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies RSA unwrap rejects private KIND set to ECC.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_rejects_private_kind_not_rsa)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto result = unwrap_external_rsa_pair_with_identity_properties(
            session,
            AZIHSM_KEY_KIND_ECC,
            AZIHSM_KEY_CLASS_PRIVATE,
            AZIHSM_KEY_KIND_RSA,
            AZIHSM_KEY_CLASS_PUBLIC
        );

        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies RSA unwrap rejects public KIND set to ECC.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_rejects_public_kind_not_rsa)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto result = unwrap_external_rsa_pair_with_identity_properties(
            session,
            AZIHSM_KEY_KIND_RSA,
            AZIHSM_KEY_CLASS_PRIVATE,
            AZIHSM_KEY_KIND_ECC,
            AZIHSM_KEY_CLASS_PUBLIC
        );

        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies RSA unwrap rejects private CLASS set to PUBLIC.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_rejects_private_class_set_to_public)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto result = unwrap_external_rsa_pair_with_identity_properties(
            session,
            AZIHSM_KEY_KIND_RSA,
            AZIHSM_KEY_CLASS_PUBLIC,
            AZIHSM_KEY_KIND_RSA,
            AZIHSM_KEY_CLASS_PUBLIC
        );

        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies RSA unwrap rejects public CLASS set to PRIVATE.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_rejects_public_class_set_to_private)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto result = unwrap_external_rsa_pair_with_identity_properties(
            session,
            AZIHSM_KEY_KIND_RSA,
            AZIHSM_KEY_CLASS_PRIVATE,
            AZIHSM_KEY_KIND_RSA,
            AZIHSM_KEY_CLASS_PRIVATE
        );

        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies an externally generated RSA key pair remains usable after unwrapping.
TEST_F(azihsm_rsa_unwrap, unwrapped_external_rsa_keypair_encrypt_decrypt_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto result = unwrap_external_rsa_pair_with_identity_properties(
            session,
            AZIHSM_KEY_KIND_RSA,
            AZIHSM_KEY_CLASS_PRIVATE,
            AZIHSM_KEY_KIND_RSA,
            AZIHSM_KEY_CLASS_PUBLIC
        );

        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key imported_private_key;
        auto_key imported_public_key;
        imported_private_key.handle = result.private_key;
        imported_public_key.handle = result.public_key;

        const char *plaintext = "RSA unwrap functional roundtrip";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + std::strlen(plaintext));

        azihsm_algo rsa_algo{};
        rsa_algo.id = AZIHSM_ALGO_ID_RSA_PKCS;
        rsa_algo.params = nullptr;
        rsa_algo.len = 0;

        azihsm_buffer plaintext_buf{ .ptr = plaintext_data.data(),
                                     .len = static_cast<uint32_t>(plaintext_data.size()) };

        // RSA-2048 produces a 256-byte ciphertext.
        std::vector<uint8_t> ciphertext_data(256);
        azihsm_buffer ciphertext_buf{ .ptr = ciphertext_data.data(),
                                      .len = static_cast<uint32_t>(ciphertext_data.size()) };

        auto err = azihsm_crypt_encrypt(
            &rsa_algo,
            imported_public_key.get(),
            &plaintext_buf,
            &ciphertext_buf
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(ciphertext_buf.len, 256u);

        std::vector<uint8_t> decrypted_data(256);
        azihsm_buffer decrypted_buf{ .ptr = decrypted_data.data(),
                                     .len = static_cast<uint32_t>(decrypted_data.size()) };

        err = azihsm_crypt_decrypt(
            &rsa_algo,
            imported_private_key.get(),
            &ciphertext_buf,
            &decrypted_buf
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        ASSERT_EQ(decrypted_buf.len, plaintext_buf.len);
        ASSERT_EQ(0, std::memcmp(decrypted_buf.ptr, plaintext_buf.ptr, decrypted_buf.len));
    });
}