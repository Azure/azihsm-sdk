// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"

class ECDSATest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        std::tie(partition_handle, session_handle) = open_session();
        ASSERT_NE(session_handle, 0);
    }

    void TearDown() override
    {
        if (session_handle != 0)
        {
            EXPECT_EQ(azihsm_sess_close(session_handle), AZIHSM_ERROR_SUCCESS);
        }
        if (partition_handle != 0)
        {
            EXPECT_EQ(azihsm_part_close(partition_handle), AZIHSM_ERROR_SUCCESS);
        }
    }

    azihsm_handle partition_handle = 0;
    azihsm_handle session_handle = 0;
};

TEST_F(ECDSATest, EccCurveValidation)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    // Test valid ECC curves
    std::vector<std::pair<uint32_t, std::string>> valid_curves = {
        {1, "P-256"}, // EcCurve::P256 = 1
        {2, "P-384"}, // EcCurve::P384 = 2
        {3, "P-521"}  // EcCurve::P521 = 3
    };

    for (auto [curve_id, curve_name] : valid_curves)
    {
        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;

        bool sign_prop = true;
        bool verify_prop = true;
        azihsm_key_prop pub_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
            {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

        azihsm_key_prop priv_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
            {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

        azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
        azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

        auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate " << curve_name << " ECDSA key pair";
        EXPECT_NE(pub_key_handle, 0) << "Got null public key handle for " << curve_name;
        EXPECT_NE(priv_key_handle, 0) << "Got null private key handle for " << curve_name;

        // Clean up keys
        if (pub_key_handle != 0)
        {
            EXPECT_EQ(azihsm_key_delete(session_handle, pub_key_handle), AZIHSM_ERROR_SUCCESS);
        }
        if (priv_key_handle != 0)
        {
            EXPECT_EQ(azihsm_key_delete(session_handle, priv_key_handle), AZIHSM_ERROR_SUCCESS);
        }
    }

    // Test invalid ECC curves
    std::vector<uint32_t> invalid_curves = {0, 4, 5, 10, 255, 1000};
    for (auto curve_id : invalid_curves)
    {
        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;

        bool sign_prop = true;
        bool verify_prop = true;
        azihsm_key_prop pub_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
            {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

        azihsm_key_prop priv_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
            {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

        azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
        azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

        auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should reject invalid ECC curve: " << curve_id;
        EXPECT_EQ(pub_key_handle, 0);
        EXPECT_EQ(priv_key_handle, 0);
    }
}

TEST_F(ECDSATest, EcdsaKeyPairGeneration)
{
    std::vector<std::pair<uint32_t, std::string>> curves = {
        {1, "P-256"}, // EcCurve::P256 = 1
        {2, "P-384"}, // EcCurve::P384 = 2
        {3, "P-521"}  // EcCurve::P521 = 3
    };

    for (auto [curve_id, curve_name] : curves)
    {
        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;
        azihsm_algo algo = {
            .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
            .params = nullptr,
            .len = 0};

        bool sign_prop = true;
        bool verify_prop = true;
        azihsm_key_prop pub_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
            {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

        azihsm_key_prop priv_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
            {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

        azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
        azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

        auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate " << curve_name << " ECDSA key pair";
        EXPECT_NE(pub_key_handle, 0) << "Got null public key handle for " << curve_name;
        EXPECT_NE(priv_key_handle, 0) << "Got null private key handle for " << curve_name;

        auto key_guard = scope_guard::make_scope_exit([&]
                                                      {
            if (pub_key_handle != 0) {
                EXPECT_EQ(azihsm_key_delete(session_handle, pub_key_handle), AZIHSM_ERROR_SUCCESS);
            }
            if (priv_key_handle != 0) {
                EXPECT_EQ(azihsm_key_delete(session_handle, priv_key_handle), AZIHSM_ERROR_SUCCESS);
            } });

        std::cout << "ECDSA " << curve_name << " key pair generation test passed" << std::endl;
    }
}

TEST_F(ECDSATest, EcdsaKeyPairGenerationArgumentValidation)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P256;
    bool sign_prop = true;
    bool verify_prop = true;

    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Null session handle
    auto err = azihsm_key_gen_pair(0, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Null algorithm pointer
    err = azihsm_key_gen_pair(session_handle, nullptr, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Null public key handle pointer
    err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, nullptr, &priv_key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Null private key handle pointer
    err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, nullptr);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Unsupported algorithm
    azihsm_algo invalid_algo = {
        .id = static_cast<azihsm_algo_id>(0xFFFFFFFF),
        .params = nullptr,
        .len = 0};
    err = azihsm_key_gen_pair(session_handle, &invalid_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    EXPECT_EQ(err, AZIHSM_ALGORITHM_NOT_SUPPORTED);

    // Test with null property lists (should be allowed)
    err = azihsm_key_gen_pair(session_handle, &algo, nullptr, nullptr, &pub_key_handle, &priv_key_handle);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS); // Should fail due to missing required curve property

    // Clean up any handles that might have been allocated
    if (pub_key_handle != 0)
    {
        azihsm_key_delete(session_handle, pub_key_handle);
    }
    if (priv_key_handle != 0)
    {
        azihsm_key_delete(session_handle, priv_key_handle);
    }
}

TEST_F(ECDSATest, EcdsaIndividualKeyDeletion)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P256;
    bool sign_prop = true;
    bool verify_prop = true;

    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    // Test 1: Delete public key first
    {
        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;

        auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(pub_key_handle, 0);
        ASSERT_NE(priv_key_handle, 0);

        // Delete public key first
        err = azihsm_key_delete(session_handle, pub_key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to delete public key";

        // Delete private key second
        err = azihsm_key_delete(session_handle, priv_key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to delete private key after public key deletion";
    }

    // Test 2: Delete private key first
    {
        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;

        auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
        ASSERT_NE(pub_key_handle, 0);
        ASSERT_NE(priv_key_handle, 0);

        // Delete private key first
        err = azihsm_key_delete(session_handle, priv_key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to delete private key";

        // Delete public key second
        err = azihsm_key_delete(session_handle, pub_key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to delete public key after private key deletion";
    }

    std::cout << "ECDSA individual key deletion test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaKeyPropertyValidation)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P256;

    // Test missing curve property
    {
        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;

        bool sign_prop = true;
        azihsm_key_prop priv_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

        azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 1};

        auto err = azihsm_key_gen_pair(session_handle, &algo, nullptr, &priv_prop_list, &pub_key_handle, &priv_key_handle);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should fail without ECC curve property";
    }

    // Test invalid curve property length
    {
        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;

        uint16_t short_curve = 1; // Wrong size
        azihsm_key_prop priv_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &short_curve, .len = sizeof(short_curve)}};

        azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 1};

        auto err = azihsm_key_gen_pair(session_handle, &algo, nullptr, &priv_prop_list, &pub_key_handle, &priv_key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT) << "Should reject curve property with wrong length";
    }

    // Test different properties for public and private keys
    {
        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;

        bool verify_prop = true;
        bool sign_prop = true;

        azihsm_key_prop pub_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
            {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

        azihsm_key_prop priv_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
            {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

        azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
        azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

        auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Should allow different properties for public and private keys";

        // Clean up
        if (pub_key_handle != 0)
        {
            EXPECT_EQ(azihsm_key_delete(session_handle, pub_key_handle), AZIHSM_ERROR_SUCCESS);
        }
        if (priv_key_handle != 0)
        {
            EXPECT_EQ(azihsm_key_delete(session_handle, priv_key_handle), AZIHSM_ERROR_SUCCESS);
        }
    }

    std::cout << "ECDSA key property validation test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaSignVerifyBasic)
{
    // Test each curve with its recommended hash algorithm
    std::vector<std::tuple<uint32_t, std::string, azihsm_algo_id, std::string>> test_cases = {
        {1, "P-256", AZIHSM_ALGO_ID_ECDSA_SHA256, "ECDSA-SHA256"},
        {2, "P-384", AZIHSM_ALGO_ID_ECDSA_SHA384, "ECDSA-SHA384"},
        {3, "P-521", AZIHSM_ALGO_ID_ECDSA_SHA512, "ECDSA-SHA512"}};

    for (auto [curve_id, curve_name, hash_algo, algo_name] : test_cases)
    {
        std::cout << "Testing ECDSA sign/verify with " << curve_name << " curve using " << algo_name << std::endl;

        // Generate ECDSA key pair
        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;
        azihsm_algo key_gen_algo = {
            .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
            .params = nullptr,
            .len = 0};

        bool sign_prop = true;
        bool verify_prop = true;
        azihsm_key_prop pub_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
            {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

        azihsm_key_prop priv_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
            {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

        azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
        azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

        auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate " << curve_name << " ECDSA key pair";
        ASSERT_NE(pub_key_handle, 0);
        ASSERT_NE(priv_key_handle, 0);

        auto key_guard = scope_guard::make_scope_exit([&]
                                                      {
            if (pub_key_handle != 0) {
                EXPECT_EQ(azihsm_key_delete(session_handle, pub_key_handle), AZIHSM_ERROR_SUCCESS);
            }
            if (priv_key_handle != 0) {
                EXPECT_EQ(azihsm_key_delete(session_handle, priv_key_handle), AZIHSM_ERROR_SUCCESS);
            } });

        // Test message
        const char *test_message = "Hello, ECDSA signing and verification with HSM!";
        uint32_t message_len = static_cast<uint32_t>(strlen(test_message));

        azihsm_algo sign_algo = {
            .id = hash_algo,
            .params = nullptr,
            .len = 0};

        azihsm_buffer message_buf = {
            .buf = (uint8_t *)test_message,
            .len = message_len};

        // First, get required signature length
        azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
        err = azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &message_buf, &sig_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << "Should return insufficient buffer error for " << algo_name;
        EXPECT_GT(sig_buf.len, 0) << "Should return required signature length for " << algo_name;

        // Allocate signature buffer
        std::vector<uint8_t> signature_data(sig_buf.len);
        sig_buf.buf = signature_data.data();

        // Sign the message
        err = azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &message_buf, &sig_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to sign message with " << algo_name << " on " << curve_name;

        // Verify with public key
        azihsm_algo verify_algo = {
            .id = hash_algo,
            .params = nullptr,
            .len = 0};

        azihsm_buffer sig_verify_buf = {
            .buf = signature_data.data(),
            .len = sig_buf.len};

        err = azihsm_crypt_verify(session_handle, &verify_algo, pub_key_handle, &message_buf, &sig_verify_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to verify signature with " << algo_name << " on " << curve_name;

        std::cout << "  ✓ " << algo_name << " sign/verify test passed on " << curve_name << std::endl;
    }
}

TEST_F(ECDSATest, EcdsaSignVerifyRawDigest)
{
    // Test ECDSA with raw digest (no hashing)
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P256;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Generate key pair
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    // Use raw ECDSA algorithm (no hashing)
    azihsm_algo sign_algo = {
        .id = AZIHSM_ALGO_ID_ECDSA,
        .params = nullptr,
        .len = 0};

    // Pre-computed SHA-256 digest of "Hello World"
    uint8_t digest[] = {
        0xa5, 0x91, 0xa6, 0xd4, 0x0b, 0xf4, 0x20, 0x40,
        0x4a, 0x01, 0x17, 0x33, 0xcf, 0xb7, 0xb1, 0x90,
        0xd6, 0x2c, 0x65, 0xbf, 0x08, 0x58, 0xdd, 0x5a,
        0x8d, 0x1d, 0x3b, 0x53, 0xc3, 0x2e, 0xec, 0xb6};

    azihsm_buffer digest_buf = {
        .buf = digest,
        .len = sizeof(digest)};

    // Get signature length
    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &digest_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(sig_buf.len, 64);

    // Sign the digest
    std::vector<uint8_t> signature_data(sig_buf.len);
    sig_buf.buf = signature_data.data();
    err = azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &digest_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify the signature
    azihsm_buffer sig_verify_buf = {
        .buf = signature_data.data(),
        .len = sig_buf.len};

    err = azihsm_crypt_verify(session_handle, &sign_algo, pub_key_handle, &digest_buf, &sig_verify_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    std::cout << "ECDSA raw digest sign/verify test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaSignVerifyArgumentValidation)
{
    // Generate key pair for validation tests
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P256;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    azihsm_algo sign_algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA256,
        .params = nullptr,
        .len = 0};

    const char *test_message = "Test message";
    azihsm_buffer message_buf = {
        .buf = (uint8_t *)test_message,
        .len = (uint32_t)strlen(test_message)};

    std::vector<uint8_t> signature_data(64);
    azihsm_buffer sig_buf = {
        .buf = signature_data.data(),
        .len = 64};

    // === Sign Function Validation ===

    // Null session handle
    err = azihsm_crypt_sign(0, &sign_algo, priv_key_handle, &message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Null algorithm pointer
    err = azihsm_crypt_sign(session_handle, nullptr, priv_key_handle, &message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Invalid key handle
    err = azihsm_crypt_sign(session_handle, &sign_algo, 0xDEADBEEF, &message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Null data buffer
    err = azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, nullptr, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Null signature buffer
    err = azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &message_buf, nullptr);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Zero-length data
    azihsm_buffer zero_data_buf = {.buf = (uint8_t *)test_message, .len = 0};
    err = azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &zero_data_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Null data buffer pointer
    azihsm_buffer null_data_buf = {.buf = nullptr, .len = 10};
    err = azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &null_data_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Unsupported algorithm
    azihsm_algo invalid_algo = {
        .id = static_cast<azihsm_algo_id>(0xFFFFFFFF),
        .params = nullptr,
        .len = 0};
    err = azihsm_crypt_sign(session_handle, &invalid_algo, priv_key_handle, &message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Wrong key type (try to sign with public key)
    err = azihsm_crypt_sign(session_handle, &sign_algo, pub_key_handle, &message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // === Verify Function Validation ===
    // First create a valid signature
    azihsm_buffer temp_sig_buf = {.buf = nullptr, .len = 0};
    azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &message_buf, &temp_sig_buf);
    std::vector<uint8_t> valid_signature(temp_sig_buf.len);
    temp_sig_buf.buf = valid_signature.data();
    azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &message_buf, &temp_sig_buf);

    azihsm_buffer valid_sig_buf = {
        .buf = valid_signature.data(),
        .len = temp_sig_buf.len};

    // Null session handle
    err = azihsm_crypt_verify(0, &sign_algo, pub_key_handle, &message_buf, &valid_sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Null algorithm pointer
    err = azihsm_crypt_verify(session_handle, nullptr, pub_key_handle, &message_buf, &valid_sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Invalid key handle
    err = azihsm_crypt_verify(session_handle, &sign_algo, 0xDEADBEEF, &message_buf, &valid_sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Null data buffer
    err = azihsm_crypt_verify(session_handle, &sign_algo, pub_key_handle, nullptr, &valid_sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Null signature buffer
    err = azihsm_crypt_verify(session_handle, &sign_algo, pub_key_handle, &message_buf, nullptr);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Zero-length signature
    azihsm_buffer zero_sig_buf = {.buf = valid_signature.data(), .len = 0};
    err = azihsm_crypt_verify(session_handle, &sign_algo, pub_key_handle, &message_buf, &zero_sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Null signature buffer pointer
    azihsm_buffer null_sig_buf = {.buf = nullptr, .len = 64};
    err = azihsm_crypt_verify(session_handle, &sign_algo, pub_key_handle, &message_buf, &null_sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    std::cout << "ECDSA sign/verify argument validation test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaSignVerifyInvalidSignature)
{
    // Generate key pair
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P256;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    azihsm_algo sign_algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA256,
        .params = nullptr,
        .len = 0};

    const char *test_message = "Original message";
    const char *wrong_message = "Wrong message";

    azihsm_buffer message_buf = {
        .buf = (uint8_t *)test_message,
        .len = (uint32_t)strlen(test_message)};

    azihsm_buffer wrong_message_buf = {
        .buf = (uint8_t *)wrong_message,
        .len = (uint32_t)strlen(wrong_message)};

    // Create a valid signature
    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
    azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &message_buf, &sig_buf);
    std::vector<uint8_t> signature_data(sig_buf.len);
    sig_buf.buf = signature_data.data();
    err = azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &message_buf, &sig_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify with wrong message
    err = azihsm_crypt_verify(session_handle, &sign_algo, pub_key_handle, &wrong_message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ECC_VERIFY_FAILED) << "Should fail verification";

    // Verify with corrupted signature
    std::vector<uint8_t> corrupted_signature = signature_data;
    corrupted_signature[0] ^= 0xFF; // Flip all bits in first byte

    azihsm_buffer corrupted_sig_buf = {
        .buf = corrupted_signature.data(),
        .len = sig_buf.len};

    err = azihsm_crypt_verify(session_handle, &sign_algo, pub_key_handle, &message_buf, &corrupted_sig_buf);
    EXPECT_EQ(err, AZIHSM_ECC_VERIFY_FAILED) << "Should fail verification";

    // Wrong signature length
    azihsm_buffer short_sig_buf = {
        .buf = signature_data.data(),
        .len = sig_buf.len - 1};

    err = azihsm_crypt_verify(session_handle, &sign_algo, pub_key_handle, &message_buf, &short_sig_buf);
    EXPECT_EQ(err, AZIHSM_ECC_VERIFY_FAILED) << "Should fail verification";

    std::cout << "ECDSA invalid signature verification test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaSignVerifyLargeMessage)
{
    // Generate key pair
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P384;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    azihsm_algo sign_algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA384,
        .params = nullptr,
        .len = 0};

    // Create a large message (64KB)
    std::vector<uint8_t> large_message(65536);
    for (size_t i = 0; i < large_message.size(); ++i)
    {
        large_message[i] = static_cast<uint8_t>(i % 256);
    }

    azihsm_buffer message_buf = {
        .buf = large_message.data(),
        .len = static_cast<uint32_t>(large_message.size())};

    // Sign the large message
    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
    azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &message_buf, &sig_buf);
    EXPECT_EQ(sig_buf.len, 96); // P-384 signature length

    std::vector<uint8_t> signature_data(sig_buf.len);
    sig_buf.buf = signature_data.data();
    err = azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify the signature
    err = azihsm_crypt_verify(session_handle, &sign_algo, pub_key_handle, &message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    std::cout << "ECDSA large message sign/verify test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaSignVerifyEmptyMessage)
{
    // Generate key pair
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P256;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    azihsm_algo sign_algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA256,
        .params = nullptr,
        .len = 0};

    // Empty message buffer (should fail)
    uint8_t dummy_byte = 0;
    azihsm_buffer empty_message_buf = {
        .buf = &dummy_byte,
        .len = 0};

    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_sign(session_handle, &sign_algo, priv_key_handle, &empty_message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT) << "Should reject empty message";

    std::cout << "ECDSA empty message validation test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaStreamingSignVerifyP256SHA256)
{
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P256;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Generate key pair
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    // Initialize streaming sign
    azihsm_algo sign_algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA256,
        .params = nullptr,
        .len = 0};

    azihsm_handle sign_ctx_handle = 0;
    err = azihsm_crypt_sign_init(session_handle, &sign_algo, priv_key_handle, &sign_ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(sign_ctx_handle, 0);

    auto sign_ctx_guard = scope_guard::make_scope_exit([&]
                                                       {
                                                           // Context is consumed by finalize, so only clean up if test fails before finalize
                                                       });

    // Update with data in chunks
    const char *chunk1 = "Hello, ";
    const char *chunk2 = "ECDSA ";
    const char *chunk3 = "streaming!";

    azihsm_buffer buf1 = {.buf = (uint8_t *)chunk1, .len = (uint32_t)strlen(chunk1)};
    err = azihsm_crypt_sign_update(session_handle, sign_ctx_handle, &buf1);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer buf2 = {.buf = (uint8_t *)chunk2, .len = (uint32_t)strlen(chunk2)};
    err = azihsm_crypt_sign_update(session_handle, sign_ctx_handle, &buf2);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer buf3 = {.buf = (uint8_t *)chunk3, .len = (uint32_t)strlen(chunk3)};
    err = azihsm_crypt_sign_update(session_handle, sign_ctx_handle, &buf3);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Finalize sign - first query required size
    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_sign_final(session_handle, sign_ctx_handle, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_GT(sig_buf.len, 0);

    // Allocate and finalize
    std::vector<uint8_t> signature_data(sig_buf.len);
    sig_buf.buf = signature_data.data();
    err = azihsm_crypt_sign_final(session_handle, sign_ctx_handle, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Initialize streaming verify
    azihsm_handle verify_ctx_handle = 0;
    azihsm_algo verify_algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA256,
        .params = nullptr,
        .len = 0};

    err = azihsm_crypt_verify_init(session_handle, &verify_algo, pub_key_handle, &verify_ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(verify_ctx_handle, 0);

    // Update verify with same chunks
    err = azihsm_crypt_verify_update(session_handle, verify_ctx_handle, &buf1);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    err = azihsm_crypt_verify_update(session_handle, verify_ctx_handle, &buf2);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    err = azihsm_crypt_verify_update(session_handle, verify_ctx_handle, &buf3);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Finalize verify
    azihsm_buffer sig_verify_buf = {.buf = signature_data.data(), .len = sig_buf.len};
    err = azihsm_crypt_verify_final(session_handle, verify_ctx_handle, &sig_verify_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    std::cout << "P-256 SHA-256 streaming sign/verify test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaStreamingSignVerifyP384SHA384)
{
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P384;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Generate key pair
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    // Test with multiple small chunks
    const char *test_data = "Testing P-384 curve with streaming operations";
    std::vector<azihsm_buffer> chunks;

    // Split into 10-byte chunks
    size_t data_len = strlen(test_data);
    for (size_t i = 0; i < data_len; i += 10)
    {
        size_t chunk_len = std::min(size_t(10), data_len - i);
        chunks.push_back({.buf = (uint8_t *)(test_data + i), .len = (uint32_t)chunk_len});
    }

    // Initialize and update streaming sign
    azihsm_algo sign_algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA384,
        .params = nullptr,
        .len = 0};

    azihsm_handle sign_ctx_handle = 0;
    err = azihsm_crypt_sign_init(session_handle, &sign_algo, priv_key_handle, &sign_ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    for (const auto &chunk : chunks)
    {
        err = azihsm_crypt_sign_update(session_handle, sign_ctx_handle, &chunk);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    }

    // Get signature size and re-sign
    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_sign_final(session_handle, sign_ctx_handle, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);

    std::vector<uint8_t> signature_data(sig_buf.len);
    sig_buf.buf = signature_data.data();
    err = azihsm_crypt_sign_final(session_handle, sign_ctx_handle, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify with streaming
    azihsm_handle verify_ctx_handle = 0;
    err = azihsm_crypt_verify_init(session_handle, &sign_algo, pub_key_handle, &verify_ctx_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    for (const auto &chunk : chunks)
    {
        err = azihsm_crypt_verify_update(session_handle, verify_ctx_handle, &chunk);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    }

    azihsm_buffer sig_verify_buf = {.buf = signature_data.data(), .len = sig_buf.len};
    err = azihsm_crypt_verify_final(session_handle, verify_ctx_handle, &sig_verify_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    std::cout << "P-384 SHA-384 streaming sign/verify test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaStreamingSignVerifyP521SHA512)
{
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P521;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Generate key pair
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    // Single update call
    const char *message = "Testing the strongest curve P-521 with streaming SHA-512";
    azihsm_buffer message_buf = {
        .buf = (uint8_t *)message,
        .len = (uint32_t)strlen(message)};

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA512,
        .params = nullptr,
        .len = 0};

    // Sign
    azihsm_handle sign_ctx = 0;
    err = azihsm_crypt_sign_init(session_handle, &algo, priv_key_handle, &sign_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    err = azihsm_crypt_sign_update(session_handle, sign_ctx, &message_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_sign_final(session_handle, sign_ctx, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);

    std::vector<uint8_t> signature(sig_buf.len);
    sig_buf.buf = signature.data();
    err = azihsm_crypt_sign_final(session_handle, sign_ctx, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify
    azihsm_handle verify_ctx = 0;
    err = azihsm_crypt_verify_init(session_handle, &algo, pub_key_handle, &verify_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    err = azihsm_crypt_verify_update(session_handle, verify_ctx, &message_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer sig_verify = {.buf = signature.data(), .len = sig_buf.len};
    err = azihsm_crypt_verify_final(session_handle, verify_ctx, &sig_verify);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    std::cout << "P-521 SHA-512 streaming sign/verify test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaStreamingSignEmptyMessage)
{
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P256;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Generate key pair
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA256,
        .params = nullptr,
        .len = 0};

    // Sign empty message (no update calls)
    azihsm_handle sign_ctx = 0;
    err = azihsm_crypt_sign_init(session_handle, &algo, priv_key_handle, &sign_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Don't call update - go straight to finalize
    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_sign_final(session_handle, sign_ctx, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);

    std::vector<uint8_t> signature(sig_buf.len);
    sig_buf.buf = signature.data();
    err = azihsm_crypt_sign_final(session_handle, sign_ctx, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify empty message
    azihsm_handle verify_ctx = 0;
    err = azihsm_crypt_verify_init(session_handle, &algo, pub_key_handle, &verify_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer sig_verify = {.buf = signature.data(), .len = sig_buf.len};
    err = azihsm_crypt_verify_final(session_handle, verify_ctx, &sig_verify);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    std::cout << "Empty message streaming sign/verify test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaStreamingSignLargeMessage)
{
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P384;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Generate key pair
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA384,
        .params = nullptr,
        .len = 0};

    // Create large message (1MB)
    const size_t chunk_size = 1024;
    const size_t num_chunks = 1024;
    std::vector<uint8_t> chunk_data(chunk_size);

    // Sign
    azihsm_handle sign_ctx = 0;
    err = azihsm_crypt_sign_init(session_handle, &algo, priv_key_handle, &sign_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    for (size_t i = 0; i < num_chunks; ++i)
    {
        // Fill with pattern
        for (size_t j = 0; j < chunk_size; ++j)
        {
            chunk_data[j] = static_cast<uint8_t>((i + j) % 256);
        }

        azihsm_buffer chunk_buf = {.buf = chunk_data.data(), .len = (uint32_t)chunk_size};
        err = azihsm_crypt_sign_update(session_handle, sign_ctx, &chunk_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    }

    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_sign_final(session_handle, sign_ctx, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);

    std::vector<uint8_t> signature(sig_buf.len);
    sig_buf.buf = signature.data();
    err = azihsm_crypt_sign_final(session_handle, sign_ctx, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify
    azihsm_handle verify_ctx = 0;
    err = azihsm_crypt_verify_init(session_handle, &algo, pub_key_handle, &verify_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    for (size_t i = 0; i < num_chunks; ++i)
    {
        for (size_t j = 0; j < chunk_size; ++j)
        {
            chunk_data[j] = static_cast<uint8_t>((i + j) % 256);
        }

        azihsm_buffer chunk_buf = {.buf = chunk_data.data(), .len = (uint32_t)chunk_size};
        err = azihsm_crypt_verify_update(session_handle, verify_ctx, &chunk_buf);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    }

    azihsm_buffer sig_verify = {.buf = signature.data(), .len = sig_buf.len};
    err = azihsm_crypt_verify_final(session_handle, verify_ctx, &sig_verify);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    std::cout << "Large message (1MB) streaming sign/verify test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaStreamingVerifyTamperedMessage)
{
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P256;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Generate key pair
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA256,
        .params = nullptr,
        .len = 0};

    // Sign original message
    const char *chunk1 = "Original ";
    const char *chunk2 = "message";

    azihsm_handle sign_ctx = 0;
    err = azihsm_crypt_sign_init(session_handle, &algo, priv_key_handle, &sign_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer buf1 = {.buf = (uint8_t *)chunk1, .len = (uint32_t)strlen(chunk1)};
    azihsm_buffer buf2 = {.buf = (uint8_t *)chunk2, .len = (uint32_t)strlen(chunk2)};

    err = azihsm_crypt_sign_update(session_handle, sign_ctx, &buf1);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    err = azihsm_crypt_sign_update(session_handle, sign_ctx, &buf2);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_sign_final(session_handle, sign_ctx, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);

    std::vector<uint8_t> signature(sig_buf.len);
    sig_buf.buf = signature.data();
    err = azihsm_crypt_sign_final(session_handle, sign_ctx, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify with tampered message
    const char *tampered_chunk1 = "Tampered ";

    azihsm_handle verify_ctx = 0;
    err = azihsm_crypt_verify_init(session_handle, &algo, pub_key_handle, &verify_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer tampered_buf = {.buf = (uint8_t *)tampered_chunk1, .len = (uint32_t)strlen(tampered_chunk1)};
    err = azihsm_crypt_verify_update(session_handle, verify_ctx, &tampered_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    err = azihsm_crypt_verify_update(session_handle, verify_ctx, &buf2);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer sig_verify = {.buf = signature.data(), .len = sig_buf.len};
    err = azihsm_crypt_verify_final(session_handle, verify_ctx, &sig_verify);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Verification should fail with tampered message";

    std::cout << "Tampered message detection test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaStreamingVerifyTamperedSignature)
{
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P256;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Generate key pair
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA256,
        .params = nullptr,
        .len = 0};

    const char *message = "Test message for signature tampering";
    azihsm_buffer message_buf = {.buf = (uint8_t *)message, .len = (uint32_t)strlen(message)};

    // Sign
    azihsm_handle sign_ctx = 0;
    err = azihsm_crypt_sign_init(session_handle, &algo, priv_key_handle, &sign_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    err = azihsm_crypt_sign_update(session_handle, sign_ctx, &message_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_sign_final(session_handle, sign_ctx, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);

    std::vector<uint8_t> signature(sig_buf.len);
    sig_buf.buf = signature.data();
    err = azihsm_crypt_sign_final(session_handle, sign_ctx, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Tamper with signature
    signature[0] ^= 0xFF;

    // Verify with tampered signature
    azihsm_handle verify_ctx = 0;
    err = azihsm_crypt_verify_init(session_handle, &algo, pub_key_handle, &verify_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    err = azihsm_crypt_verify_update(session_handle, verify_ctx, &message_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer tampered_sig = {.buf = signature.data(), .len = sig_buf.len};
    err = azihsm_crypt_verify_final(session_handle, verify_ctx, &tampered_sig);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Verification should fail with tampered signature";

    std::cout << "Tampered signature detection test passed" << std::endl;
}

TEST_F(ECDSATest, EcdsaStreamingSignInvalidArguments)
{
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P256;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Generate key pair
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA256,
        .params = nullptr,
        .len = 0};

    azihsm_handle ctx_handle = 0;

    // Invalid session handle
    err = azihsm_crypt_sign_init(0, &algo, priv_key_handle, &ctx_handle);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS);

    // Null algo
    err = azihsm_crypt_sign_init(session_handle, nullptr, priv_key_handle, &ctx_handle);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS);

    // Invalid key handle
    err = azihsm_crypt_sign_init(session_handle, &algo, 0xDEADBEEF, &ctx_handle);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS);

    // Null ctx handle output
    err = azihsm_crypt_sign_init(session_handle, &algo, priv_key_handle, nullptr);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS);

    // Using public key for sign should fail
    err = azihsm_crypt_sign_init(session_handle, &algo, pub_key_handle, &ctx_handle);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS);

    std::cout << "Invalid arguments test passed for sign_init" << std::endl;
}

TEST_F(ECDSATest, EcdsaStreamingVsNonStreamingConsistency)
{
    uint32_t curve_id = AZIHSM_EC_CURVE_ID_P521;
    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Generate key pair
    azihsm_algo key_gen_algo = {
        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0};

    bool sign_prop = true;
    bool verify_prop = true;
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_prop, .len = sizeof(verify_prop)}};

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve_id, .len = sizeof(curve_id)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_prop, .len = sizeof(sign_prop)}};

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    auto err = azihsm_key_gen_pair(session_handle, &key_gen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto key_guard = scope_guard::make_scope_exit([&]
                                                  {
        if (pub_key_handle != 0) {
            azihsm_key_delete(session_handle, pub_key_handle);
        }
        if (priv_key_handle != 0) {
            azihsm_key_delete(session_handle, priv_key_handle);
        } });

    const char *message = "Test message for comparing streaming vs non-streaming operations";
    azihsm_buffer message_buf = {.buf = (uint8_t *)message, .len = (uint32_t)strlen(message)};

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_ECDSA_SHA512,
        .params = nullptr,
        .len = 0};

    // Non-streaming sign
    azihsm_buffer non_streaming_sig = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_sign(session_handle, &algo, priv_key_handle, &message_buf, &non_streaming_sig);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);

    std::vector<uint8_t> non_streaming_sig_data(non_streaming_sig.len);
    non_streaming_sig.buf = non_streaming_sig_data.data();
    err = azihsm_crypt_sign(session_handle, &algo, priv_key_handle, &message_buf, &non_streaming_sig);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Streaming sign
    azihsm_handle sign_ctx = 0;
    err = azihsm_crypt_sign_init(session_handle, &algo, priv_key_handle, &sign_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    err = azihsm_crypt_sign_update(session_handle, sign_ctx, &message_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer streaming_sig = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_sign_final(session_handle, sign_ctx, &streaming_sig);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);

    std::vector<uint8_t> streaming_sig_data(streaming_sig.len);
    streaming_sig.buf = streaming_sig_data.data();
    err = azihsm_crypt_sign_final(session_handle, sign_ctx, &streaming_sig);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify non-streaming signature with streaming verify
    azihsm_handle verify_ctx = 0;
    err = azihsm_crypt_verify_init(session_handle, &algo, pub_key_handle, &verify_ctx);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    err = azihsm_crypt_verify_update(session_handle, verify_ctx, &message_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    err = azihsm_crypt_verify_final(session_handle, verify_ctx, &non_streaming_sig);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Verify streaming signature with non-streaming verify
    err = azihsm_crypt_verify(session_handle, &algo, pub_key_handle, &message_buf, &streaming_sig);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    std::cout << "Streaming vs non-streaming consistency test passed" << std::endl;
}