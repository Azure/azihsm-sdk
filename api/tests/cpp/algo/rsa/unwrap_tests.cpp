// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "algo/ecc/helpers.hpp"
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

// Wraps a pre-generated external RSA PKCS#8 private-key blob.
static azihsm_status make_wrapped_rsa_pkcs8_blob(
    azihsm_handle wrapping_public_key,
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

    return wrap_plaintext_with_rsa_aes(wrapping_public_key, pkcs8_bytes, wrap_config, wrapped_blob);
}

struct RsaUnwrapProperties
{
    azihsm_key_class private_class;
    azihsm_key_kind private_kind;
    uint32_t private_bit_len;
    uint8_t private_session = 1;
    uint8_t private_decrypt = 1;

    azihsm_key_class public_class;
    azihsm_key_kind public_kind;
    uint32_t public_bit_len;
    uint8_t public_session = 1;
    uint8_t public_encrypt = 1;

    std::vector<azihsm_key_prop> private_props;
    std::vector<azihsm_key_prop> public_props;

    RsaUnwrapProperties(
        uint32_t bit_len,
        azihsm_key_kind requested_private_kind = AZIHSM_KEY_KIND_RSA,
        azihsm_key_class requested_private_class = AZIHSM_KEY_CLASS_PRIVATE,
        azihsm_key_kind requested_public_kind = AZIHSM_KEY_KIND_RSA,
        azihsm_key_class requested_public_class = AZIHSM_KEY_CLASS_PUBLIC
    )
        : private_class(requested_private_class), private_kind(requested_private_kind),
          private_bit_len(bit_len), public_class(requested_public_class),
          public_kind(requested_public_kind), public_bit_len(bit_len)
    {
        private_props = {
            { AZIHSM_KEY_PROP_ID_CLASS, &private_class, sizeof(private_class) },
            { AZIHSM_KEY_PROP_ID_KIND, &private_kind, sizeof(private_kind) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &private_bit_len, sizeof(private_bit_len) },
            { AZIHSM_KEY_PROP_ID_SESSION, &private_session, sizeof(private_session) },
            { AZIHSM_KEY_PROP_ID_DECRYPT, &private_decrypt, sizeof(private_decrypt) }
        };

        public_props = { { AZIHSM_KEY_PROP_ID_CLASS, &public_class, sizeof(public_class) },
                         { AZIHSM_KEY_PROP_ID_KIND, &public_kind, sizeof(public_kind) },
                         { AZIHSM_KEY_PROP_ID_BIT_LEN, &public_bit_len, sizeof(public_bit_len) },
                         { AZIHSM_KEY_PROP_ID_SESSION, &public_session, sizeof(public_session) },
                         { AZIHSM_KEY_PROP_ID_ENCRYPT, &public_encrypt, sizeof(public_encrypt) } };
    }

    azihsm_key_prop_list private_prop_list()
    {
        return { private_props.data(), static_cast<uint32_t>(private_props.size()) };
    }

    azihsm_key_prop_list public_prop_list()
    {
        return { public_props.data(), static_cast<uint32_t>(public_props.size()) };
    }
};

// Unwraps an external RSA PKCS#8 key using caller-selected identity properties.
static UnwrapPairResult unwrap_external_rsa_pair_with_identity_properties(
    azihsm_handle session,
    uint32_t bit_len,
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
        bit_len,
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
    RsaUnwrapProperties properties(bit_len, private_kind, private_class, public_kind, public_class);

    auto private_prop_list = properties.private_prop_list();
    auto public_prop_list = properties.public_prop_list();

    return try_unwrap_pair(
        &unwrap_algo.algo,
        wrapping_private_key.get(),
        &wrapped_key_buf,
        &private_prop_list,
        &public_prop_list
    );
}

static UnwrapPairResult unwrap_external_rsa_pair(azihsm_handle session, uint32_t bit_len)
{
    return unwrap_external_rsa_pair_with_identity_properties(
        session,
        bit_len,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PRIVATE,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PUBLIC
    );
}

static void verify_external_rsa_keypair_unwrap_succeeds(
    PartitionListHandle &part_list,
    uint32_t bit_len
)
{
    part_list.for_each_session([bit_len](azihsm_handle session) {
        auto result = unwrap_external_rsa_pair(session, bit_len);

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

static void verify_unwrapped_external_rsa_properties(
    PartitionListHandle &part_list,
    uint32_t bit_len
)
{
    part_list.for_each_session([bit_len](azihsm_handle session) {
        auto result = unwrap_external_rsa_pair(session, bit_len);

        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key private_key;
        auto_key public_key;
        private_key.handle = result.private_key;
        public_key.handle = result.public_key;

        azihsm_key_kind private_kind{};
        ASSERT_EQ(
            get_key_prop(private_key.get(), AZIHSM_KEY_PROP_ID_KIND, private_kind),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(private_kind, AZIHSM_KEY_KIND_RSA);

        azihsm_key_class private_class{};
        ASSERT_EQ(
            get_key_prop(private_key.get(), AZIHSM_KEY_PROP_ID_CLASS, private_class),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(private_class, AZIHSM_KEY_CLASS_PRIVATE);

        uint32_t private_bits{};
        ASSERT_EQ(
            get_key_prop(private_key.get(), AZIHSM_KEY_PROP_ID_BIT_LEN, private_bits),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(private_bits, bit_len);

        azihsm_key_kind public_kind{};
        ASSERT_EQ(
            get_key_prop(public_key.get(), AZIHSM_KEY_PROP_ID_KIND, public_kind),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(public_kind, AZIHSM_KEY_KIND_RSA);

        azihsm_key_class public_class{};
        ASSERT_EQ(
            get_key_prop(public_key.get(), AZIHSM_KEY_PROP_ID_CLASS, public_class),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(public_class, AZIHSM_KEY_CLASS_PUBLIC);

        uint32_t public_bits{};
        ASSERT_EQ(
            get_key_prop(public_key.get(), AZIHSM_KEY_PROP_ID_BIT_LEN, public_bits),
            AZIHSM_STATUS_SUCCESS
        );
        ASSERT_EQ(public_bits, bit_len);
    });
}

static void verify_corrupted_blob_rejected(PartitionListHandle &part_list, uint32_t bit_len)
{
    part_list.for_each_session([bit_len](azihsm_handle session) {
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
            bit_len,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());

        wrapped_blob[wrapped_blob.size() / 2] ^= 0xA5;

        azihsm_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                       .len = static_cast<uint32_t>(wrapped_blob.size()) };

        RsaAesUnwrapAlgo unwrap_algo{};
        RsaUnwrapProperties properties(bit_len);
        auto private_prop_list = properties.private_prop_list();
        auto public_prop_list = properties.public_prop_list();

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

static void verify_truncated_blob_rejected(PartitionListHandle &part_list, uint32_t bit_len)
{
    part_list.for_each_session([bit_len](azihsm_handle session) {
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
            bit_len,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_GT(wrapped_blob.size(), 1u);

        wrapped_blob.pop_back();

        azihsm_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                       .len = static_cast<uint32_t>(wrapped_blob.size()) };

        RsaAesUnwrapAlgo unwrap_algo{};
        RsaUnwrapProperties properties(bit_len);
        auto private_prop_list = properties.private_prop_list();
        auto public_prop_list = properties.public_prop_list();

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

static void verify_requested_bit_length_mismatch_rejected(
    PartitionListHandle &part_list,
    uint32_t wrapped_bit_len,
    uint32_t requested_bit_len
)
{
    part_list.for_each_session([wrapped_bit_len, requested_bit_len](azihsm_handle session) {
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
            wrapped_bit_len,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer wrapped_key_buf{ .ptr = wrapped_blob.data(),
                                       .len = static_cast<uint32_t>(wrapped_blob.size()) };

        RsaAesUnwrapAlgo unwrap_algo{};
        RsaUnwrapProperties properties(requested_bit_len);
        auto private_prop_list = properties.private_prop_list();
        auto public_prop_list = properties.public_prop_list();

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

static void verify_identity_properties_rejected(
    PartitionListHandle &part_list,
    uint32_t bit_len,
    azihsm_key_kind private_kind,
    azihsm_key_class private_class,
    azihsm_key_kind public_kind,
    azihsm_key_class public_class
)
{
    part_list.for_each_session([=](azihsm_handle session) {
        auto result = unwrap_external_rsa_pair_with_identity_properties(
            session,
            bit_len,
            private_kind,
            private_class,
            public_kind,
            public_class
        );

        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

static void verify_unwrapped_external_rsa_roundtrip(
    PartitionListHandle &part_list,
    uint32_t bit_len
)
{
    part_list.for_each_session([bit_len](azihsm_handle session) {
        auto result = unwrap_external_rsa_pair(session, bit_len);

        ASSERT_EQ(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(result.private_key, 0);
        ASSERT_NE(result.public_key, 0);

        auto_key private_key;
        auto_key public_key;
        private_key.handle = result.private_key;
        public_key.handle = result.public_key;

        const char *plaintext = "RSA unwrap functional roundtrip";
        std::vector<uint8_t> plaintext_data(plaintext, plaintext + std::strlen(plaintext));

        azihsm_algo rsa_algo{ .id = AZIHSM_ALGO_ID_RSA_PKCS, .params = nullptr, .len = 0 };

        azihsm_buffer plaintext_buf{ .ptr = plaintext_data.data(),
                                     .len = static_cast<uint32_t>(plaintext_data.size()) };

        const uint32_t rsa_output_size = bit_len / 8u;

        std::vector<uint8_t> ciphertext_data(rsa_output_size);
        azihsm_buffer ciphertext_buf{ .ptr = ciphertext_data.data(),
                                      .len = static_cast<uint32_t>(ciphertext_data.size()) };

        auto err =
            azihsm_crypt_encrypt(&rsa_algo, public_key.get(), &plaintext_buf, &ciphertext_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(ciphertext_buf.len, rsa_output_size);

        std::vector<uint8_t> decrypted_data(rsa_output_size);
        azihsm_buffer decrypted_buf{ .ptr = decrypted_data.data(),
                                     .len = static_cast<uint32_t>(decrypted_data.size()) };

        err = azihsm_crypt_decrypt(&rsa_algo, private_key.get(), &ciphertext_buf, &decrypted_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(decrypted_buf.len, plaintext_buf.len);
        ASSERT_EQ(0, std::memcmp(decrypted_buf.ptr, plaintext_buf.ptr, decrypted_buf.len));
    });
}

static void verify_wrong_unwrapping_key_rejected(PartitionListHandle &part_list, uint32_t bit_len)
{
    if (part_list.count() < 2u)
    {
        GTEST_SKIP(
        ) << "requires at least two partitions to guarantee distinct wrapping-key contexts";
    }

    auto source_path = part_list.get_path(0);
    auto other_path = part_list.get_path(1);

    auto source_partition = PartitionHandle(source_path);
    auto other_partition = PartitionHandle(other_path);

    std::vector<uint8_t> wrapped_blob;
    auto_key wrong_unwrapping_private_key;

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
            bit_len,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());
    }

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
    RsaUnwrapProperties properties(bit_len);
    auto private_prop_list = properties.private_prop_list();
    auto public_prop_list = properties.public_prop_list();

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

// Verifies an externally generated 2048-bit RSA key pair can be unwrapped.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_2048_keypair_succeeds)
{
    verify_external_rsa_keypair_unwrap_succeeds(part_list_, 2048u);
}

// Verifies an externally generated 3072-bit RSA key pair can be unwrapped.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_3072_keypair_succeeds)
{
    verify_external_rsa_keypair_unwrap_succeeds(part_list_, 3072u);
}

// Verifies an unwrapped 2048-bit RSA key pair reports expected properties.
TEST_F(azihsm_rsa_unwrap, unwrapped_external_rsa_2048_reports_expected_properties)
{
    verify_unwrapped_external_rsa_properties(part_list_, 2048u);
}

// Verifies an unwrapped 3072-bit RSA key pair reports expected properties.
TEST_F(azihsm_rsa_unwrap, unwrapped_external_rsa_3072_reports_expected_properties)
{
    verify_unwrapped_external_rsa_properties(part_list_, 3072u);
}

// Verifies 2048-bit RSA unwrap rejects corrupted wrapped key material.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_2048_rejects_corrupted_blob)
{
    verify_corrupted_blob_rejected(part_list_, 2048u);
}

// Verifies 3072-bit RSA unwrap rejects corrupted wrapped key material.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_3072_rejects_corrupted_blob)
{
    verify_corrupted_blob_rejected(part_list_, 3072u);
}

// Verifies 2048-bit RSA unwrap rejects a wrong unwrapping key.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_2048_rejects_wrong_unwrapping_key)
{
    verify_wrong_unwrapping_key_rejected(part_list_, 2048u);
}

// Verifies 3072-bit RSA unwrap rejects a wrong unwrapping key.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_3072_rejects_wrong_unwrapping_key)
{
    verify_wrong_unwrapping_key_rejected(part_list_, 3072u);
}

// Verifies 2048-bit RSA unwrap rejects a truncated wrapped blob.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_2048_rejects_truncated_blob)
{
    verify_truncated_blob_rejected(part_list_, 2048u);
}

// Verifies 3072-bit RSA unwrap rejects a truncated wrapped blob.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_3072_rejects_truncated_blob)
{
    verify_truncated_blob_rejected(part_list_, 3072u);
}

// Verifies a wrapped 2048-bit RSA key rejects requested 3072-bit properties.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_2048_rejects_requested_3072_bit_length)
{
    verify_requested_bit_length_mismatch_rejected(part_list_, 2048u, 3072u);
}

// Verifies a wrapped 3072-bit RSA key rejects requested 2048-bit properties.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_3072_rejects_requested_2048_bit_length)
{
    verify_requested_bit_length_mismatch_rejected(part_list_, 3072u, 2048u);
}

// Verifies 2048-bit RSA unwrap rejects private KIND set to ECC.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_2048_rejects_private_kind_not_rsa)
{
    verify_identity_properties_rejected(
        part_list_,
        2048u,
        AZIHSM_KEY_KIND_ECC,
        AZIHSM_KEY_CLASS_PRIVATE,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PUBLIC
    );
}

// Verifies 3072-bit RSA unwrap rejects private KIND set to ECC.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_3072_rejects_private_kind_not_rsa)
{
    verify_identity_properties_rejected(
        part_list_,
        3072u,
        AZIHSM_KEY_KIND_ECC,
        AZIHSM_KEY_CLASS_PRIVATE,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PUBLIC
    );
}

// Verifies 2048-bit RSA unwrap rejects public KIND set to ECC.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_2048_rejects_public_kind_not_rsa)
{
    verify_identity_properties_rejected(
        part_list_,
        2048u,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PRIVATE,
        AZIHSM_KEY_KIND_ECC,
        AZIHSM_KEY_CLASS_PUBLIC
    );
}

// Verifies 3072-bit RSA unwrap rejects public KIND set to ECC.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_3072_rejects_public_kind_not_rsa)
{
    verify_identity_properties_rejected(
        part_list_,
        3072u,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PRIVATE,
        AZIHSM_KEY_KIND_ECC,
        AZIHSM_KEY_CLASS_PUBLIC
    );
}

// Verifies 2048-bit RSA unwrap rejects private CLASS set to PUBLIC.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_2048_rejects_private_class_set_to_public)
{
    verify_identity_properties_rejected(
        part_list_,
        2048u,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PUBLIC,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PUBLIC
    );
}

// Verifies 3072-bit RSA unwrap rejects private CLASS set to PUBLIC.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_3072_rejects_private_class_set_to_public)
{
    verify_identity_properties_rejected(
        part_list_,
        3072u,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PUBLIC,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PUBLIC
    );
}

// Verifies 2048-bit RSA unwrap rejects public CLASS set to PRIVATE.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_2048_rejects_public_class_set_to_private)
{
    verify_identity_properties_rejected(
        part_list_,
        2048u,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PRIVATE,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PRIVATE
    );
}

// Verifies 3072-bit RSA unwrap rejects public CLASS set to PRIVATE.
TEST_F(azihsm_rsa_unwrap, unwrap_external_rsa_3072_rejects_public_class_set_to_private)
{
    verify_identity_properties_rejected(
        part_list_,
        3072u,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PRIVATE,
        AZIHSM_KEY_KIND_RSA,
        AZIHSM_KEY_CLASS_PRIVATE
    );
}

// Verifies an unwrapped 2048-bit RSA key pair supports encrypt/decrypt.
TEST_F(azihsm_rsa_unwrap, unwrapped_external_rsa_2048_encrypt_decrypt_roundtrip)
{
    verify_unwrapped_external_rsa_roundtrip(part_list_, 2048u);
}

// Verifies an unwrapped 3072-bit RSA key pair supports encrypt/decrypt.
TEST_F(azihsm_rsa_unwrap, unwrapped_external_rsa_3072_encrypt_decrypt_roundtrip)
{
    verify_unwrapped_external_rsa_roundtrip(part_list_, 3072u);
}
