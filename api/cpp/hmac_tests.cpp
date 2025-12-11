// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"
#include <vector>
#include <string>
#include <iostream>

// Helper struct to manage ECDH key pairs with automatic cleanup
struct EcdhKeyPairs
{
    azihsm_handle server_pub_key = 0;
    azihsm_handle server_priv_key = 0;
    azihsm_handle client_pub_key = 0;
    azihsm_handle client_priv_key = 0;
    azihsm_handle session_handle = 0;

    ~EcdhKeyPairs()
    {
        if (server_pub_key != 0)
            azihsm_key_delete(session_handle, server_pub_key);
        if (server_priv_key != 0)
            azihsm_key_delete(session_handle, server_priv_key);
        if (client_pub_key != 0)
            azihsm_key_delete(session_handle, client_pub_key);
        if (client_priv_key != 0)
            azihsm_key_delete(session_handle, client_priv_key);
    }
};

// Helper function to generate EC key pairs and derive HMAC key
inline azihsm_error generate_ecdh_keys_and_derive_hmac(
    azihsm_handle session_handle,
    azihsm_key_type hmac_key_type,
    EcdhKeyPairs &key_pairs,
    azihsm_handle &hmac_key_handle)
{
    key_pairs.session_handle = session_handle;

    // Generate server EC key pair
    azihsm_error err = generate_ec_key_pair_for_derive(
        session_handle,
        key_pairs.server_pub_key,
        key_pairs.server_priv_key);
    if (err != AZIHSM_ERROR_SUCCESS)
        return err;

    // Generate client EC key pair
    err = generate_ec_key_pair_for_derive(
        session_handle,
        key_pairs.client_pub_key,
        key_pairs.client_priv_key);
    if (err != AZIHSM_ERROR_SUCCESS)
        return err;

    // Derive HMAC key
    err = derive_hmac_key_via_ecdh_hkdf(
        session_handle,
        key_pairs.server_priv_key,
        key_pairs.client_pub_key,
        hmac_key_type,
        hmac_key_handle);

    return err;
}

class HMACTest : public ::testing::Test
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

TEST_F(HMACTest, HmacSignVerifyBasic)
{
    // Test basic HMAC sign/verify operations for different algorithms
    std::vector<std::tuple<azihsm_algo_id, azihsm_key_type, std::string, uint32_t>> test_cases = {
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

        auto key_cleanup = scope_guard::make_scope_exit([&]
                                                        {
            if (server_pub_key != 0)
                azihsm_key_delete(session_handle, server_pub_key);
            if (server_priv_key != 0)
                azihsm_key_delete(session_handle, server_priv_key);
            if (client_pub_key != 0)
                azihsm_key_delete(session_handle, client_pub_key);
            if (client_priv_key != 0)
                azihsm_key_delete(session_handle, client_priv_key); });

        // Use helper to generate EC key pairs
        azihsm_error err = generate_ec_key_pair_for_derive(session_handle, server_pub_key, server_priv_key);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Server EC key generation failed for " << algo_name;

        err = generate_ec_key_pair_for_derive(session_handle, client_pub_key, client_priv_key);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Client EC key generation failed for " << algo_name;

        // Derive HMAC key using helper function
        azihsm_handle hmac_key_handle = 0;
        auto hmac_cleanup = scope_guard::make_scope_exit([&]
                                                         {
            if (hmac_key_handle != 0)
                azihsm_key_delete(session_handle, hmac_key_handle); });

        err = derive_hmac_key_via_ecdh_hkdf(session_handle, server_priv_key, client_pub_key, key_type, hmac_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "HMAC key derivation failed for " << algo_name;

        // Create test message
        const char *test_message = "Hello, HMAC authentication with HSM!";
        uint32_t message_len = static_cast<uint32_t>(strlen(test_message));

        azihsm_buffer message_buf = {.buf = (uint8_t *)test_message, .len = message_len};

        azihsm_algo hmac_algo = {.id = algo_id, .params = nullptr, .len = 0};

        // Test signature length determination
        azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
        err = azihsm_crypt_sign(session_handle, &hmac_algo, hmac_key_handle, &message_buf, &sig_buf);

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

TEST_F(HMACTest, HmacSignVerifyArgumentValidation)
{
    // Test argument validation for HMAC operations
    azihsm_algo hmac_algo = {.id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0};

    const char *test_message = "Test message for validation";
    azihsm_buffer message_buf = {.buf = (uint8_t *)test_message, .len = static_cast<uint32_t>(strlen(test_message))};

    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
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
    err = azihsm_crypt_sign(session_handle, &invalid_algo, dummy_key, &message_buf, &sig_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);

    std::cout << "HMAC argument validation tests completed" << std::endl;
}

TEST_F(HMACTest, HmacCrossPartyAuthentication)
{
    // Test cross-party authentication scenario - real-world key derivation pattern
    std::cout << "Testing HMAC cross-party authentication scenario..." << std::endl;

    // Generate EC key pairs for both parties using helper function
    azihsm_handle server_pub_key = 0, server_priv_key = 0;
    azihsm_handle client_pub_key = 0, client_priv_key = 0;

    auto key_cleanup = scope_guard::make_scope_exit([&]
                                                    {
        if (server_pub_key != 0)
            azihsm_key_delete(session_handle, server_pub_key);
        if (server_priv_key != 0)
            azihsm_key_delete(session_handle, server_priv_key);
        if (client_pub_key != 0)
            azihsm_key_delete(session_handle, client_pub_key);
        if (client_priv_key != 0)
            azihsm_key_delete(session_handle, client_priv_key); });

    // Use helper to generate EC key pairs
    azihsm_error err = generate_ec_key_pair_for_derive(session_handle, server_pub_key, server_priv_key);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Server EC key generation failed";

    err = generate_ec_key_pair_for_derive(session_handle, client_pub_key, client_priv_key);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Client EC key generation failed";

    std::cout << "  [OK] Generated EC key pairs for both parties" << std::endl;

    // Derive HMAC keys for both parties using helper function
    azihsm_handle server_hmac_key = 0;
    azihsm_handle client_hmac_key = 0;

    auto hmac_cleanup = scope_guard::make_scope_exit([&]
                                                     {
        if (server_hmac_key != 0)
            azihsm_key_delete(session_handle, server_hmac_key);
        if (client_hmac_key != 0)
            azihsm_key_delete(session_handle, client_hmac_key); });

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

    const char *test_message = "Cross-party authenticated message";
    azihsm_buffer message_buf = {.buf = (uint8_t *)test_message, .len = static_cast<uint32_t>(strlen(test_message))};

    azihsm_algo hmac_algo = {.id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0};

    // Client signs the message
    azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
    err = azihsm_crypt_sign(session_handle, &hmac_algo, client_hmac_key, &message_buf, &sig_buf);

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

TEST_F(HMACTest, HmacStreamingSignBasic)
{
    std::vector<std::tuple<azihsm_algo_id, azihsm_key_type, std::string, uint32_t>> test_cases = {
        {AZIHSM_ALGO_ID_HMAC_SHA256, AZIHSM_KEY_TYPE_HMAC_SHA256, "HMAC-SHA256", 32},
        {AZIHSM_ALGO_ID_HMAC_SHA384, AZIHSM_KEY_TYPE_HMAC_SHA384, "HMAC-SHA384", 48},
        {AZIHSM_ALGO_ID_HMAC_SHA512, AZIHSM_KEY_TYPE_HMAC_SHA512, "HMAC-SHA512", 64}};

    for (auto [algo_id, key_type, algo_name, expected_sig_len] : test_cases)
    {
        std::cout << "Testing " << algo_name << " streaming sign operations..." << std::endl;

        EcdhKeyPairs key_pairs;
        azihsm_handle hmac_key_handle = 0;
        auto hmac_cleanup = scope_guard::make_scope_exit([&]
                                                         {
        if (hmac_key_handle != 0)
            azihsm_key_delete(session_handle, hmac_key_handle); });

        azihsm_error err = generate_ecdh_keys_and_derive_hmac(
            session_handle,
            AZIHSM_KEY_TYPE_HMAC_SHA256,
            key_pairs,
            hmac_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Initialize streaming sign operation
        azihsm_algo hmac_algo = {.id = algo_id, .params = nullptr, .len = 0};
        azihsm_handle stream_handle = 0;

        err = azihsm_crypt_sign_init(session_handle, &hmac_algo, hmac_key_handle, &stream_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " sign init failed";
        ASSERT_NE(stream_handle, 0) << "Stream handle should be non-zero";

        auto stream_cleanup = scope_guard::make_scope_exit([&]
                                                           {
            if (stream_handle != 0)
                azihsm_crypt_sign_final(session_handle, stream_handle, nullptr); });

        // Test message in chunks
        const char *chunk1 = "Hello, ";
        const char *chunk2 = "HMAC streaming ";
        const char *chunk3 = "authentication!";

        // Update with first chunk
        azihsm_buffer chunk1_buf = {.buf = (uint8_t *)chunk1, .len = static_cast<uint32_t>(strlen(chunk1))};
        err = azihsm_crypt_sign_update(session_handle, stream_handle, &chunk1_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " sign update (chunk 1) failed";

        // Update with second chunk
        azihsm_buffer chunk2_buf = {.buf = (uint8_t *)chunk2, .len = static_cast<uint32_t>(strlen(chunk2))};
        err = azihsm_crypt_sign_update(session_handle, stream_handle, &chunk2_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " sign update (chunk 2) failed";

        // Update with third chunk
        azihsm_buffer chunk3_buf = {.buf = (uint8_t *)chunk3, .len = static_cast<uint32_t>(strlen(chunk3))};
        err = azihsm_crypt_sign_update(session_handle, stream_handle, &chunk3_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " sign update (chunk 3) failed";

        // Finalize and get signature
        azihsm_buffer sig_buf = {.buf = nullptr, .len = 0};
        err = azihsm_crypt_sign_final(session_handle, stream_handle, &sig_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER) << algo_name << " should return INSUFFICIENT_BUFFER for signature length query";

        EXPECT_EQ(sig_buf.len, expected_sig_len) << "Unexpected signature length for " << algo_name;

        std::vector<uint8_t> signature_data(sig_buf.len);
        sig_buf.buf = signature_data.data();

        err = azihsm_crypt_sign_final(session_handle, stream_handle, &sig_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " streaming sign finalize failed";
        std::cout << "  [OK] " << algo_name << " streaming signing succeeded" << std::endl;

        // Verify the streaming signature matches one-shot signature
        std::string complete_message = std::string(chunk1) + std::string(chunk2) + std::string(chunk3);
        azihsm_buffer message_buf = {.buf = (uint8_t *)complete_message.c_str(),
                                     .len = static_cast<uint32_t>(complete_message.length())};

        std::vector<uint8_t> oneshot_sig_data(expected_sig_len);
        azihsm_buffer oneshot_sig_buf = {.buf = oneshot_sig_data.data(), .len = expected_sig_len};

        err = azihsm_crypt_sign(session_handle, &hmac_algo, hmac_key_handle, &message_buf, &oneshot_sig_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " one-shot signing failed";

        // Compare signatures
        EXPECT_EQ(signature_data, oneshot_sig_data)
            << algo_name << " streaming signature doesn't match one-shot signature";
        std::cout << "  [OK] " << algo_name << " streaming signature matches one-shot" << std::endl;

        stream_handle = 0; // Prevent double cleanup
    }
}

TEST_F(HMACTest, HmacStreamingVerifyBasic)
{
    std::vector<std::tuple<azihsm_algo_id, azihsm_key_type, std::string, uint32_t>> test_cases = {
        {AZIHSM_ALGO_ID_HMAC_SHA256, AZIHSM_KEY_TYPE_HMAC_SHA256, "HMAC-SHA256", 32},
        {AZIHSM_ALGO_ID_HMAC_SHA384, AZIHSM_KEY_TYPE_HMAC_SHA384, "HMAC-SHA384", 48},
        {AZIHSM_ALGO_ID_HMAC_SHA512, AZIHSM_KEY_TYPE_HMAC_SHA512, "HMAC-SHA512", 64}};

    for (auto [algo_id, key_type, algo_name, expected_sig_len] : test_cases)
    {
        std::cout << "Testing " << algo_name << " streaming verify operations..." << std::endl;

        EcdhKeyPairs key_pairs;
        azihsm_handle hmac_key_handle = 0;
        auto hmac_cleanup = scope_guard::make_scope_exit([&]
                                                         {
        if (hmac_key_handle != 0)
            azihsm_key_delete(session_handle, hmac_key_handle); });

        azihsm_error err = generate_ecdh_keys_and_derive_hmac(
            session_handle,
            AZIHSM_KEY_TYPE_HMAC_SHA256,
            key_pairs,
            hmac_key_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

        // Create test message and generate signature using one-shot operation
        const char *chunk1 = "Hello, ";
        const char *chunk2 = "HMAC streaming ";
        const char *chunk3 = "verification!";
        std::string complete_message = std::string(chunk1) + std::string(chunk2) + std::string(chunk3);

        azihsm_algo hmac_algo = {.id = algo_id, .params = nullptr, .len = 0};
        azihsm_buffer message_buf = {.buf = (uint8_t *)complete_message.c_str(),
                                     .len = static_cast<uint32_t>(complete_message.length())};

        std::vector<uint8_t> signature_data(expected_sig_len);
        azihsm_buffer sig_buf = {.buf = signature_data.data(), .len = expected_sig_len};

        err = azihsm_crypt_sign(session_handle, &hmac_algo, hmac_key_handle, &message_buf, &sig_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " one-shot signing failed";

        // Initialize streaming verify operation
        azihsm_handle stream_handle = 0;
        err = azihsm_crypt_verify_init(session_handle, &hmac_algo, hmac_key_handle, &stream_handle);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " verify init failed";
        ASSERT_NE(stream_handle, 0) << "Stream handle should be non-zero";

        auto stream_cleanup = scope_guard::make_scope_exit([&]
                                                           {
            if (stream_handle != 0)
                azihsm_crypt_verify_final(session_handle, stream_handle, nullptr); });

        // Update with message chunks
        azihsm_buffer chunk1_buf = {.buf = (uint8_t *)chunk1, .len = static_cast<uint32_t>(strlen(chunk1))};
        err = azihsm_crypt_verify_update(session_handle, stream_handle, &chunk1_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " verify update (chunk 1) failed";

        azihsm_buffer chunk2_buf = {.buf = (uint8_t *)chunk2, .len = static_cast<uint32_t>(strlen(chunk2))};
        err = azihsm_crypt_verify_update(session_handle, stream_handle, &chunk2_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " verify update (chunk 2) failed";

        azihsm_buffer chunk3_buf = {.buf = (uint8_t *)chunk3, .len = static_cast<uint32_t>(strlen(chunk3))};
        err = azihsm_crypt_verify_update(session_handle, stream_handle, &chunk3_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " verify update (chunk 3) failed";

        // Finalize verification with signature
        azihsm_buffer verify_sig_buf = {.buf = signature_data.data(), .len = sig_buf.len};
        err = azihsm_crypt_verify_final(session_handle, stream_handle, &verify_sig_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << algo_name << " streaming verify finalize failed";
        std::cout << "  [OK] " << algo_name << " streaming verification succeeded" << std::endl;

        stream_handle = 0; // Prevent double cleanup
    }
}

TEST_F(HMACTest, HmacStreamingSignVerifyLargeData)
{
    std::cout << "Testing HMAC streaming sign/verify with large data..." << std::endl;

    EcdhKeyPairs key_pairs;
    azihsm_handle hmac_key_handle = 0;
    auto hmac_cleanup = scope_guard::make_scope_exit([&]
                                                     {
        if (hmac_key_handle != 0)
            azihsm_key_delete(session_handle, hmac_key_handle); });

    azihsm_error err = generate_ecdh_keys_and_derive_hmac(
        session_handle,
        AZIHSM_KEY_TYPE_HMAC_SHA256,
        key_pairs,
        hmac_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    // Create large test data (1024 bytes - at max size)
    const size_t data_size = 1024;
    std::vector<uint8_t> large_data(data_size);
    for (size_t i = 0; i < data_size; i++)
    {
        large_data[i] = static_cast<uint8_t>(i & 0xFF);
    }

    azihsm_algo hmac_algo = {.id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0};

    // Streaming sign
    azihsm_handle sign_stream_handle = 0;
    err = azihsm_crypt_sign_init(session_handle, &hmac_algo, hmac_key_handle, &sign_stream_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto sign_stream_cleanup = scope_guard::make_scope_exit([&]
                                                            {
        if (sign_stream_handle != 0)
            azihsm_crypt_sign_final(session_handle, sign_stream_handle, nullptr); });

    // Update in 256-byte chunks (4 chunks total)
    const size_t chunk_size = 256;
    for (size_t offset = 0; offset < data_size; offset += chunk_size)
    {
        size_t current_chunk_size = std::min(chunk_size, data_size - offset);
        azihsm_buffer chunk_buf = {
            .buf = large_data.data() + offset,
            .len = static_cast<uint32_t>(current_chunk_size)};
        err = azihsm_crypt_sign_update(session_handle, sign_stream_handle, &chunk_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Sign update failed at offset " << offset;
    }

    // Finalize sign
    std::vector<uint8_t> signature_data(32); // HMAC-SHA256 signature length
    azihsm_buffer sig_buf = {.buf = signature_data.data(), .len = 32};
    err = azihsm_crypt_sign_final(session_handle, sign_stream_handle, &sig_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    std::cout << "  [OK] Large data streaming signing succeeded" << std::endl;

    sign_stream_handle = 0;

    // Streaming verify
    azihsm_handle verify_stream_handle = 0;
    err = azihsm_crypt_verify_init(session_handle, &hmac_algo, hmac_key_handle, &verify_stream_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto verify_stream_cleanup = scope_guard::make_scope_exit([&]
                                                              {
        if (verify_stream_handle != 0)
            azihsm_crypt_verify_final(session_handle, verify_stream_handle, nullptr); });

    // Update in 256-byte chunks
    for (size_t offset = 0; offset < data_size; offset += chunk_size)
    {
        size_t current_chunk_size = std::min(chunk_size, data_size - offset);
        azihsm_buffer chunk_buf = {
            .buf = large_data.data() + offset,
            .len = static_cast<uint32_t>(current_chunk_size)};
        err = azihsm_crypt_verify_update(session_handle, verify_stream_handle, &chunk_buf);
        ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Verify update failed at offset " << offset;
    }

    // Finalize verify
    azihsm_buffer verify_sig_buf = {.buf = signature_data.data(), .len = sig_buf.len};
    err = azihsm_crypt_verify_final(session_handle, verify_stream_handle, &verify_sig_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    std::cout << "  [OK] Large data streaming verification succeeded" << std::endl;

    verify_stream_handle = 0;
}

TEST_F(HMACTest, HmacStreamingExceedMaxMessageSize)
{
    std::cout << "Testing HMAC streaming with message size limit enforcement..." << std::endl;

    EcdhKeyPairs key_pairs;
    azihsm_handle hmac_key_handle = 0;
    auto hmac_cleanup = scope_guard::make_scope_exit([&]
                                                     {
        if (hmac_key_handle != 0)
            azihsm_key_delete(session_handle, hmac_key_handle); });

    azihsm_error err = generate_ecdh_keys_and_derive_hmac(
        session_handle,
        AZIHSM_KEY_TYPE_HMAC_SHA256,
        key_pairs,
        hmac_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_algo hmac_algo = {.id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0};

    // Test exceeding max size in single update
    azihsm_handle sign_stream_handle = 0;
    err = azihsm_crypt_sign_init(session_handle, &hmac_algo, hmac_key_handle, &sign_stream_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto sign_stream_cleanup = scope_guard::make_scope_exit([&]
                                                            {
        if (sign_stream_handle != 0)
            azihsm_crypt_sign_final(session_handle, sign_stream_handle, nullptr); });

    std::vector<uint8_t> too_large_message(1025); // 1 byte over limit
    azihsm_buffer too_large_buf = {.buf = too_large_message.data(), .len = 1025};
    err = azihsm_crypt_sign_update(session_handle, sign_stream_handle, &too_large_buf);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should fail when message exceeds max size in single update";
    std::cout << "  [OK] Single oversized update rejected" << std::endl;

    // Clean up first stream
    if (sign_stream_handle != 0)
    {
        azihsm_crypt_sign_final(session_handle, sign_stream_handle, nullptr);
        sign_stream_handle = 0;
    }

    // Test exceeding max size across multiple updates
    err = azihsm_crypt_sign_init(session_handle, &hmac_algo, hmac_key_handle, &sign_stream_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    std::vector<uint8_t> chunk1(512, 0x42);
    azihsm_buffer chunk1_buf = {.buf = chunk1.data(), .len = 512};
    err = azihsm_crypt_sign_update(session_handle, sign_stream_handle, &chunk1_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "First 512-byte update should succeed";

    std::vector<uint8_t> chunk2(512, 0x42);
    azihsm_buffer chunk2_buf = {.buf = chunk2.data(), .len = 512};
    err = azihsm_crypt_sign_update(session_handle, sign_stream_handle, &chunk2_buf);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Second 512-byte update should succeed (total 1024)";

    std::vector<uint8_t> chunk3(1, 0x42); // This pushes over the limit
    azihsm_buffer chunk3_buf = {.buf = chunk3.data(), .len = 1};
    err = azihsm_crypt_sign_update(session_handle, sign_stream_handle, &chunk3_buf);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should fail when accumulated message exceeds max size";
    std::cout << "  [OK] Accumulated oversized updates rejected" << std::endl;

    // Clean up sign stream
    if (sign_stream_handle != 0)
    {
        azihsm_crypt_sign_final(session_handle, sign_stream_handle, nullptr);
        sign_stream_handle = 0;
    }

    // Test same for verify stream
    azihsm_handle verify_stream_handle = 0;
    err = azihsm_crypt_verify_init(session_handle, &hmac_algo, hmac_key_handle, &verify_stream_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto verify_stream_cleanup = scope_guard::make_scope_exit([&]
                                                              {
        if (verify_stream_handle != 0)
            azihsm_crypt_verify_final(session_handle, verify_stream_handle, nullptr); });

    err = azihsm_crypt_verify_update(session_handle, verify_stream_handle, &too_large_buf);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Verify should fail when message exceeds max size";
    std::cout << "  [OK] Verify stream oversized update rejected" << std::endl;
}

TEST_F(HMACTest, HmacStreamingVerifyTamperedMessage)
{
    std::cout << "Testing HMAC streaming verification with tampered message..." << std::endl;

    EcdhKeyPairs key_pairs;
    azihsm_handle hmac_key_handle = 0;
    auto hmac_cleanup = scope_guard::make_scope_exit([&]
                                                     {
        if (hmac_key_handle != 0)
            azihsm_key_delete(session_handle, hmac_key_handle); });

    azihsm_error err = generate_ecdh_keys_and_derive_hmac(
        session_handle,
        AZIHSM_KEY_TYPE_HMAC_SHA256,
        key_pairs,
        hmac_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_algo hmac_algo = {.id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0};

    // Sign original message using streaming
    const char *original_message = "Original message";
    azihsm_handle sign_stream_handle = 0;
    err = azihsm_crypt_sign_init(session_handle, &hmac_algo, hmac_key_handle, &sign_stream_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto sign_stream_cleanup = scope_guard::make_scope_exit([&]
                                                            {
        if (sign_stream_handle != 0)
            azihsm_crypt_sign_final(session_handle, sign_stream_handle, nullptr); });

    azihsm_buffer orig_msg_buf = {
        .buf = (uint8_t *)original_message,
        .len = static_cast<uint32_t>(strlen(original_message))};
    err = azihsm_crypt_sign_update(session_handle, sign_stream_handle, &orig_msg_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    std::vector<uint8_t> signature_data(32);
    azihsm_buffer sig_buf = {.buf = signature_data.data(), .len = 32};
    err = azihsm_crypt_sign_final(session_handle, sign_stream_handle, &sig_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    std::cout << "  [OK] Signed original message" << std::endl;

    sign_stream_handle = 0;

    // Try to verify with tampered message
    const char *tampered_message = "Tampered message";
    azihsm_handle verify_stream_handle = 0;
    err = azihsm_crypt_verify_init(session_handle, &hmac_algo, hmac_key_handle, &verify_stream_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto verify_stream_cleanup = scope_guard::make_scope_exit([&]
                                                              {
        if (verify_stream_handle != 0)
            azihsm_crypt_verify_final(session_handle, verify_stream_handle, nullptr); });

    azihsm_buffer tampered_msg_buf = {
        .buf = (uint8_t *)tampered_message,
        .len = static_cast<uint32_t>(strlen(tampered_message))};
    err = azihsm_crypt_verify_update(session_handle, verify_stream_handle, &tampered_msg_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer verify_sig_buf = {.buf = signature_data.data(), .len = sig_buf.len};
    err = azihsm_crypt_verify_final(session_handle, verify_stream_handle, &verify_sig_buf);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Verification should fail for tampered message";
    std::cout << "  [OK] Tampered message verification correctly rejected" << std::endl;

    verify_stream_handle = 0;
}

TEST_F(HMACTest, HmacStreamingVerifyTamperedSignature)
{
    std::cout << "Testing HMAC streaming verification with tampered signature..." << std::endl;

    EcdhKeyPairs key_pairs;
    azihsm_handle hmac_key_handle = 0;
    auto hmac_cleanup = scope_guard::make_scope_exit([&]
                                                     {
        if (hmac_key_handle != 0)
            azihsm_key_delete(session_handle, hmac_key_handle); });

    azihsm_error err = generate_ecdh_keys_and_derive_hmac(
        session_handle,
        AZIHSM_KEY_TYPE_HMAC_SHA256,
        key_pairs,
        hmac_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    azihsm_algo hmac_algo = {.id = AZIHSM_ALGO_ID_HMAC_SHA256, .params = nullptr, .len = 0};

    // Sign message using streaming
    const char *message = "Test message";
    azihsm_handle sign_stream_handle = 0;
    err = azihsm_crypt_sign_init(session_handle, &hmac_algo, hmac_key_handle, &sign_stream_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto sign_stream_cleanup = scope_guard::make_scope_exit([&]
                                                            {
        if (sign_stream_handle != 0)
            azihsm_crypt_sign_final(session_handle, sign_stream_handle, nullptr); });

    azihsm_buffer msg_buf = {
        .buf = (uint8_t *)message,
        .len = static_cast<uint32_t>(strlen(message))};
    err = azihsm_crypt_sign_update(session_handle, sign_stream_handle, &msg_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    std::vector<uint8_t> signature_data(32);
    azihsm_buffer sig_buf = {.buf = signature_data.data(), .len = 32};
    err = azihsm_crypt_sign_final(session_handle, sign_stream_handle, &sig_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    std::cout << "  [OK] Signed message" << std::endl;

    sign_stream_handle = 0;

    // Tamper with signature
    signature_data[0] ^= 0xFF;
    std::cout << "  [INFO] Tampered with signature byte" << std::endl;

    // Try to verify with tampered signature
    azihsm_handle verify_stream_handle = 0;
    err = azihsm_crypt_verify_init(session_handle, &hmac_algo, hmac_key_handle, &verify_stream_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    auto verify_stream_cleanup = scope_guard::make_scope_exit([&]
                                                              {
        if (verify_stream_handle != 0)
            azihsm_crypt_verify_final(session_handle, verify_stream_handle, nullptr); });

    err = azihsm_crypt_verify_update(session_handle, verify_stream_handle, &msg_buf);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);

    azihsm_buffer verify_sig_buf = {.buf = signature_data.data(), .len = sig_buf.len};
    err = azihsm_crypt_verify_final(session_handle, verify_stream_handle, &verify_sig_buf);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Verification should fail for tampered signature";
    std::cout << "  [OK] Tampered signature verification correctly rejected" << std::endl;

    verify_stream_handle = 0;
}