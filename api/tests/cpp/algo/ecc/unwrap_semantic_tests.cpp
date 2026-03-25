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

class azihsm_ecc_keyunwrap_semantic : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// ==================== key_unwrap_pair: Cross-Argument Wrapped Payload Semantics ====================

// ----- Cross-Argument Wrapped Payload Semantics -----

// Verifies unwrap rejects malformed wrapped key-pair blob content.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_invalid_wrapped_blob_shapes)
{
    part_list_.for_each_session([](azihsm_handle session) {
        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        {
            SCOPED_TRACE("empty buffer (non-null ptr, zero len)");
            uint8_t b = 0;
            azihsm_buffer wrapped_key_buf{};
            wrapped_key_buf.ptr = &b;
            wrapped_key_buf.len = 0;

            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("minimal one-byte blob");
            uint8_t b = 0x01;
            azihsm_buffer wrapped_key_buf{};
            wrapped_key_buf.ptr = &b;
            wrapped_key_buf.len = 1;

            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("null ptr, non-zero len");
            azihsm_buffer wrapped_key_buf{};
            wrapped_key_buf.ptr = nullptr;
            wrapped_key_buf.len = 4;

            auto result = try_unwrap_pair(
                &unwrap_inputs.unwrap_algo,
                rsa_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_EQ(result.status, AZIHSM_STATUS_INVALID_ARGUMENT);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

// Verifies unwrap rejects wrapped payloads that encode a single key instead of a key pair.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_wrapped_single_key_payload_for_pair_unwrap)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key rsa_unwrap_priv_key;
        auto_key rsa_wrap_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_unwrap_priv_key.get_ptr(),
            rsa_wrap_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Step 1: Build transport-valid wrapped bytes whose plaintext is a single symmetric key,
        // not an ECC key-pair serialization.
        const auto single_key_payload = make_deterministic_payload(0x10, 0x22, 16);

        std::vector<uint8_t> wrapped_blob;
        err = wrap_plaintext_with_rsa_aes(
            rsa_wrap_pub_key.get(),
            single_key_payload,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());

        // Step 2: Sanity check that these bytes are valid for key_unwrap (single-key API).
        RsaAesUnwrapAlgo unwrap_algo{};

        azihsm_key_kind aes_kind = AZIHSM_KEY_KIND_AES;
        azihsm_key_class aes_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t aes_bits = 128;
        uint8_t aes_is_session = 1;
        uint8_t can_encrypt = 1;
        uint8_t can_decrypt = 1;
        std::vector<azihsm_key_prop> aes_props = {
            { AZIHSM_KEY_PROP_ID_KIND, &aes_kind, sizeof(aes_kind) },
            { AZIHSM_KEY_PROP_ID_CLASS, &aes_class, sizeof(aes_class) },
            { AZIHSM_KEY_PROP_ID_BIT_LEN, &aes_bits, sizeof(aes_bits) },
            { AZIHSM_KEY_PROP_ID_SESSION, &aes_is_session, sizeof(aes_is_session) },
            { AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) },
            { AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) }
        };
        azihsm_key_prop_list aes_prop_list{ aes_props.data(), static_cast<uint32_t>(aes_props.size()) };

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = wrapped_blob.data();
        wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        auto_key single_key;
        err = azihsm_key_unwrap(
            &unwrap_algo.algo,
            rsa_unwrap_priv_key.get(),
            &wrapped_key_buf,
            &aes_prop_list,
            single_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(single_key.get(), 0);

        // Step 3: key_unwrap_pair should reject the same bytes because pair-shaped content is required.
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto pair_result = try_unwrap_pair(
            &unwrap_algo.algo,
            rsa_unwrap_priv_key.get(),
            &wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(pair_result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(pair_result.private_key, 0);
        ASSERT_EQ(pair_result.public_key, 0);
    });
}

// Verifies unwrap rejects blobs wrapped by a different RSA wrapping key.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_blob_wrapped_by_different_wrapping_key)
{
    if (part_list_.count() < 2u)
    {
        GTEST_SKIP() << "requires at least two partitions to guarantee distinct wrapping-key contexts";
    }

    auto source_path = part_list_.get_path(0);
    auto other_path = part_list_.get_path(1);

    auto source_partition = PartitionHandle(source_path);
    auto other_partition = PartitionHandle(other_path);

    std::vector<uint8_t> wrapped_blob;
    auto_key wrapping_priv_key_b;

    {
        SessionHandle source_session(source_partition.get());
        auto_key wrapping_priv_key_a;
        auto_key wrapping_pub_key_a;
        auto err = generate_rsa_unwrapping_keypair(
            source_session.get(),
            wrapping_priv_key_a.get_ptr(),
            wrapping_pub_key_a.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        err = make_wrapped_ecc_pkcs8_blob(
            wrapping_pub_key_a.get(),
            AZIHSM_ECC_CURVE_P256,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());
    }

    {
        SessionHandle other_session(other_partition.get());
        auto_key wrapping_pub_key_b;
        auto err = generate_rsa_unwrapping_keypair(
            other_session.get(),
            wrapping_priv_key_b.get_ptr(),
            wrapping_pub_key_b.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    }

    azihsm_buffer wrapped_key_buf{};
    wrapped_key_buf.ptr = wrapped_blob.data();
    wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

    RsaAesUnwrapAlgo unwrap_algo{};
    DefaultEccPrivKeyProps priv_props;
    DefaultEccPubKeyProps pub_props;
    auto priv_prop_list = priv_props.get_prop_list();
    auto pub_prop_list = pub_props.get_prop_list();

    auto result = try_unwrap_pair(
        &unwrap_algo.algo,
        wrapping_priv_key_b.get(),
        &wrapped_key_buf,
        &priv_prop_list,
        &pub_prop_list
    );
    ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(result.private_key, 0);
    ASSERT_EQ(result.public_key, 0);
}

// Verifies unwrap does not mutate caller-provided wrapped blob on failure.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_preserves_input_wrapped_blob_on_failure)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Deliberately malformed/truncated test payload used only to verify failure-path immutability.
        std::vector<uint8_t> wrapped_data = make_deterministic_payload(0x01, 0x01, 5);
        const auto before = wrapped_data;

        RsaAesUnwrapPairInputs unwrap_inputs(0xA5);
        unwrap_inputs.wrapped_key_buf.ptr = wrapped_data.data();
        unwrap_inputs.wrapped_key_buf.len = static_cast<uint32_t>(wrapped_data.size());

        auto_key rsa_priv_key;
        auto_key rsa_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_priv_key.get_ptr(),
            rsa_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_inputs.unwrap_algo,
            rsa_priv_key.get(),
            &unwrap_inputs.wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
        ASSERT_EQ(wrapped_data, before);
    });
}

// Verifies unwrap rejects requested curve/capability props that mismatch wrapped content.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_requested_curve_or_capability_mismatch)
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

        std::vector<uint8_t> wrapped_blob;
        err = make_wrapped_ecc_pkcs8_blob(
            rsa_pub_key.get(),
            AZIHSM_ECC_CURVE_P256,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = wrapped_blob.data();
        wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        RsaAesUnwrapAlgo unwrap_algo{};

        {
            SCOPED_TRACE("requested curve mismatches wrapped ECC key curve");
            DefaultEccPrivKeyProps priv_props;
            DefaultEccPubKeyProps pub_props;
            priv_props.ecc_curve = AZIHSM_ECC_CURVE_P384;
            pub_props.ecc_curve = AZIHSM_ECC_CURVE_P384;

            auto priv_prop_list = priv_props.get_prop_list();
            auto pub_prop_list = pub_props.get_prop_list();

            auto result = try_unwrap_pair(
                &unwrap_algo.algo,
                rsa_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }

        {
            SCOPED_TRACE("requested capability mismatch/invalid capability combination");
            DefaultEccPrivKeyProps priv_props;
            DefaultEccPubKeyProps pub_props;
            priv_props.can_sign = 0;

            auto priv_prop_list = priv_props.get_prop_list();
            auto pub_prop_list = pub_props.get_prop_list();

            auto result = try_unwrap_pair(
                &unwrap_algo.algo,
                rsa_priv_key.get(),
                &wrapped_key_buf,
                &priv_prop_list,
                &pub_prop_list
            );
            ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
            ASSERT_EQ(result.private_key, 0);
            ASSERT_EQ(result.public_key, 0);
        }
    });
}

// Verifies unwrap rejects wrapped content whose kind conflicts with requested ECC properties.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_wrapped_content_kind_mismatch)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key rsa_unwrap_priv_key;
        auto_key rsa_wrap_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            rsa_unwrap_priv_key.get_ptr(),
            rsa_wrap_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Step 1: Build transport-valid wrapped bytes where plaintext is arbitrary non-ECC key material.
        // This is the kind-mismatch mechanism: unwrap props request ECC pair, but payload encodes no ECC pair.
        const auto non_ecc_payload = make_deterministic_payload(0x01, 0x02, 16);

        std::vector<uint8_t> wrapped_blob;
        err = wrap_plaintext_with_rsa_aes(
            rsa_wrap_pub_key.get(),
            non_ecc_payload,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_FALSE(wrapped_blob.empty());

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = wrapped_blob.data();
        wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        RsaAesUnwrapAlgo unwrap_algo{};
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        // Step 2: pair unwrap rejects because payload content kind does not match requested ECC-pair semantics.
        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            rsa_unwrap_priv_key.get(),
            &wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}

// Verifies unwrap rejects wrapped content whose encoded curve conflicts with requested curve.
TEST_F(azihsm_ecc_keyunwrap_semantic, unwrap_pair_rejects_wrapped_content_curve_mismatch)
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

        std::vector<uint8_t> wrapped_blob;
        err = make_wrapped_ecc_pkcs8_blob(
            rsa_pub_key.get(),
            AZIHSM_ECC_CURVE_P384,
            RsaAesWrapConfig{},
            wrapped_blob
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        azihsm_buffer wrapped_key_buf{};
        wrapped_key_buf.ptr = wrapped_blob.data();
        wrapped_key_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        RsaAesUnwrapAlgo unwrap_algo{};

        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        priv_props.ecc_curve = AZIHSM_ECC_CURVE_P521;
        pub_props.ecc_curve = AZIHSM_ECC_CURVE_P521;
        auto priv_prop_list = priv_props.get_prop_list();
        auto pub_prop_list = pub_props.get_prop_list();

        auto result = try_unwrap_pair(
            &unwrap_algo.algo,
            rsa_priv_key.get(),
            &wrapped_key_buf,
            &priv_prop_list,
            &pub_prop_list
        );
        ASSERT_NE(result.status, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(result.private_key, 0);
        ASSERT_EQ(result.public_key, 0);
    });
}
