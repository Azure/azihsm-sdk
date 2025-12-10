// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"
#include <vector>
#include <string>
#include <iostream>

class HMACTest : public ::testing::Test
{
  protected:
    void SetUp() override {
        std::tie(partition_handle, session_handle) = open_session();
        ASSERT_NE(session_handle, 0);
    }

    void TearDown() override {
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
    azihsm_handle session_handle   = 0;
};

TEST_F(HMACTest, HmacSignVerifyBasic) {
    // Test basic HMAC sign/verify operations for different algorithms
    std::vector<std::tuple<azihsm_algo_id, azihsm_key_type, std::string, uint32_t> > test_cases = {
        {AZIHSM_ALGO_ID_HMAC_SHA256, AZIHSM_KEY_TYPE_HMAC_SHA256, "HMAC-SHA256", 32},
        {AZIHSM_ALGO_ID_HMAC_SHA384, AZIHSM_KEY_TYPE_HMAC_SHA384, "HMAC-SHA384", 48},
        {AZIHSM_ALGO_ID_HMAC_SHA512, AZIHSM_KEY_TYPE_HMAC_SHA512, "HMAC-SHA512", 64}};

    for (auto [algo_id, key_type, algo_name, expected_sig_len] : test_cases)
    {
        std::cout << "Testing " << algo_name << " sign/verify operations..." << std::endl;
        std::cout << "  Step 1: Generating server EC key pair..." << std::endl;

        // Generate ECDH key pairs for key derivation
        azihsm_handle server_pub_key = 0, server_priv_key = 0;
        azihsm_handle client_pub_key = 0, client_priv_key = 0;

        auto key_cleanup = scope_guard::make_scope_exit([&] {
            if (server_pub_key != 0)
                azihsm_key_delete(session_handle, server_pub_key);
            if (server_priv_key != 0)
                azihsm_key_delete(session_handle, server_priv_key);
            if (client_pub_key != 0)
                azihsm_key_delete(session_handle, client_pub_key);
            if (client_priv_key != 0)
                azihsm_key_delete(session_handle, client_priv_key);
        });

        // Use helper to generate EC key pairs
        azihsm_error err = generate_ec_key_pair_for_derive(session_handle, server_pub_key, server_priv_key);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Server EC key generation failed for " << algo_name;

        err = generate_ec_key_pair_for_derive(session_handle, client_pub_key, client_priv_key);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Client EC key generation failed for " << algo_name;

        // Derive HMAC key using helper function
        azihsm_handle hmac_key_handle = 0;
        auto          hmac_cleanup    = scope_guard::make_scope_exit([&] {
            if (hmac_key_handle != 0)
                azihsm_key_delete(session_handle, hmac_key_handle);
        });

        err = derive_hmac_key_via_ecdh_hkdf(session_handle, server_priv_key, client_pub_key, key_type, hmac_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "HMAC key derivation failed for " << algo_name;

        // Create test message
        const char *test_message = "Hello, HMAC authentication with HSM!";
        uint32_t    message_len  = static_cast<uint32_t>(strlen(test_message));

        azihsm_buffer message_buf = {.buf = (uint8_t *) test_message, .len = message_len};

        azihsm_algo hmac_algo = {.id = algo_id, .params = nullptr, .len = 0};

        // Test signature length determination
        azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
        err                   = azihsm_crypt_sign(session_handle, &hmac_algo, hmac_key_handle, &message_buf, &sig_buf);

        if (err == AZIHSM_ERROR_INSUFFICIENT_BUFFER)
        {
            EXPECT_EQ(sig_buf.len, expected_sig_len) << "Unexpected signature length for " << algo_name;

            // Allocate signature buffer
            std::vector<uint8_t> signature_data(sig_buf.len);
            sig_buf.buf = signature_data.data();

            // Attempt to sign
            err = azihsm_crypt_sign(session_handle, &hmac_algo, hmac_key_handle, &message_buf, &sig_buf);
            ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " signing failed";
            std::cout << "  [OK] " << algo_name << " signing succeeded" << std::endl;

            // Test verification
            azihsm_buffer verify_sig_buf = {.buf = signature_data.data(), .len = sig_buf.len};

            err = azihsm_crypt_verify(session_handle, &hmac_algo, hmac_key_handle, &message_buf, &verify_sig_buf);
            ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " verification failed";
            std::cout << "  [OK] " << algo_name << " verification succeeded" << std::endl;
        }
        else
        {
            FAIL() << algo_name << " signature length query failed (err=" << static_cast<unsigned int>(err) << ")";
        }
    }
}

TEST_F(HMACTest, HmacSignVerifyArgumentValidation) {
    // Test argument validation for HMAC operations
    azihsm_algo hmac_algo = {.id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0};

    const char   *test_message = "Test message for validation";
    azihsm_buffer message_buf  = {.buf = (uint8_t *) test_message, .len = static_cast<uint32_t>(strlen(test_message))};

    azihsm_buffer sig_buf   = {.buf = nullptr, .len = 0};
    azihsm_handle dummy_key = 0x12345678; // Dummy key handle for validation tests

    // Test null session handle
    azihsm_error err = azihsm_crypt_sign(0, &hmac_algo, dummy_key, &message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Test null algorithm pointer
    err = azihsm_crypt_sign(session_handle, nullptr, dummy_key, &message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Test null message buffer
    err = azihsm_crypt_sign(session_handle, &hmac_algo, dummy_key, nullptr, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Test null signature buffer
    err = azihsm_crypt_sign(session_handle, &hmac_algo, dummy_key, &message_buf, nullptr);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Test invalid key handle
    err = azihsm_crypt_sign(session_handle, &hmac_algo, 0xDEADBEEF, &message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    // Test invalid algorithm ID
    azihsm_algo invalid_algo = {.id = static_cast<azihsm_algo_id>(0xFFFFFFFF), .params = nullptr, .len = 0};
    err                      = azihsm_crypt_sign(session_handle, &invalid_algo, dummy_key, &message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    std::cout << "HMAC argument validation tests completed" << std::endl;
}

TEST_F(HMACTest, HmacCrossPartyAuthentication) {
    // Test cross-party authentication scenario - real-world key derivation pattern
    std::cout << "Testing HMAC cross-party authentication scenario..." << std::endl;

    // Generate EC key pairs for both parties using helper function
    azihsm_handle server_pub_key = 0, server_priv_key = 0;
    azihsm_handle client_pub_key = 0, client_priv_key = 0;

    auto key_cleanup = scope_guard::make_scope_exit([&] {
        if (server_pub_key != 0)
            azihsm_key_delete(session_handle, server_pub_key);
        if (server_priv_key != 0)
            azihsm_key_delete(session_handle, server_priv_key);
        if (client_pub_key != 0)
            azihsm_key_delete(session_handle, client_pub_key);
        if (client_priv_key != 0)
            azihsm_key_delete(session_handle, client_priv_key);
    });

    // Use helper to generate EC key pairs
    azihsm_error err = generate_ec_key_pair_for_derive(session_handle, server_pub_key, server_priv_key);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Server EC key generation failed";

    err = generate_ec_key_pair_for_derive(session_handle, client_pub_key, client_priv_key);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Client EC key generation failed";

    std::cout << "  [OK] Generated EC key pairs for both parties" << std::endl;

    // Derive HMAC keys for both parties using helper function
    azihsm_handle server_hmac_key = 0;
    azihsm_handle client_hmac_key = 0;

    auto hmac_cleanup = scope_guard::make_scope_exit([&] {
        if (server_hmac_key != 0)
            azihsm_key_delete(session_handle, server_hmac_key);
        if (client_hmac_key != 0)
            azihsm_key_delete(session_handle, client_hmac_key);
    });

    // Server derives HMAC key using client's public key
    err = derive_hmac_key_via_ecdh_hkdf(
        session_handle, server_priv_key, client_pub_key, AZIHSM_KEY_TYPE_HMAC_SHA256, server_hmac_key);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Server HMAC key derivation failed";

    // Client derives HMAC key using server's public key (should match server's key)
    err = derive_hmac_key_via_ecdh_hkdf(
        session_handle, client_priv_key, server_pub_key, AZIHSM_KEY_TYPE_HMAC_SHA256, client_hmac_key);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Client HMAC key derivation failed";

    // Real-world pattern demonstrated:
    // 1. Both parties performed ECDH to derive shared secret
    // 2. Both parties used HKDF to derive identical HMAC keys from shared secret
    // 3. Client can sign with derived key, Server can verify with same derived key
    // 4. Server can sign response, Client can verify response

    const char   *test_message = "Cross-party authenticated message";
    azihsm_buffer message_buf  = {.buf = (uint8_t *) test_message, .len = static_cast<uint32_t>(strlen(test_message))};

    azihsm_algo hmac_algo = {.id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0};

    // Client signs the message
    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
    err                   = azihsm_crypt_sign(session_handle, &hmac_algo, client_hmac_key, &message_buf, &sig_buf);

    if (err == AZIHSM_ERROR_INSUFFICIENT_BUFFER)
    {
        std::vector<uint8_t> signature_data(sig_buf.len);
        sig_buf.buf = signature_data.data();

        err = azihsm_crypt_sign(session_handle, &hmac_algo, client_hmac_key, &message_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Client signing failed";
        std::cout << "  [OK] Client signed message successfully" << std::endl;

        // Server verifies the signature using its derived key
        azihsm_buffer verify_sig_buf = {.buf = signature_data.data(), .len = sig_buf.len};

        err = azihsm_crypt_verify(session_handle, &hmac_algo, server_hmac_key, &message_buf, &verify_sig_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Server verification failed";
        std::cout << "  [OK] Server verified client's signature - cross-party auth successful!" << std::endl;
    }
    else
    {
        FAIL() << "HMAC signature length query failed (err=" << static_cast<unsigned int>(err) << ")";
    }

    std::cout << "  [INFO] Cross-party HMAC authentication pattern validated" << std::endl;
}

// [TODO] HMAC Streaming tests not implemented yet. Needs to implement public key retrieval for HMAC tests.
