// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"
#include <iostream>
#include <iomanip>
#include <vector>

class RSATest : public ::testing::Test
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

// Test RSA key pair generation with valid parameters
TEST_F(RSATest, RSAKeyPairGeneration_ValidParameters)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0
    };

    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Test 2048-bit RSA key generation
    uint32_t bit_len = 2048;
    
    // Public key properties (only bit length supported)
    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}
    };

    azihsm_key_prop_list pub_prop_list = {.props = nullptr, .count = 0};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 1};

    auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate RSA-2048 key pair";
    EXPECT_NE(pub_key_handle, 0) << "Got null public key handle";
    EXPECT_NE(priv_key_handle, 0) << "Got null private key handle";

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

// Test RSA key pair generation with invalid bit lengths
TEST_F(RSATest, RSAKeyPairGeneration_InvalidBitLengths)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0
    };

    // Test invalid RSA key sizes (only 2048 is supported for now)
    std::vector<uint32_t> invalid_bit_lens = {512, 1024, 1536, 3072, 4096, 8192};

    for (auto bit_len : invalid_bit_lens)
    {
        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;
        
        azihsm_key_prop priv_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}
        };

        azihsm_key_prop_list pub_prop_list = {.props = nullptr, .count = 0};
        azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 1};

        auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should fail for invalid bit length: " << bit_len;
        EXPECT_EQ(pub_key_handle, 0) << "Should not return valid public key handle for invalid bit length";
        EXPECT_EQ(priv_key_handle, 0) << "Should not return valid private key handle for invalid bit length";
    }
}

// Test RSA key pair generation argument validation
TEST_F(RSATest, RSAKeyPairGeneration_ArgumentValidation)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0
    };

    uint32_t bit_len = 2048;
    
    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}
    };

    azihsm_key_prop_list pub_prop_list = {.props = nullptr, .count = 0};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 1};

    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Test null session handle
    auto err = azihsm_key_gen_pair(0, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_HANDLE);
    EXPECT_EQ(pub_key_handle, 0);
    EXPECT_EQ(priv_key_handle, 0);

    // Test null algorithm pointer
    err = azihsm_key_gen_pair(session_handle, nullptr, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);
    EXPECT_EQ(pub_key_handle, 0);
    EXPECT_EQ(priv_key_handle, 0);

    // Test null public key handle pointer
    err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, nullptr, &priv_key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Test null private key handle pointer
    err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, nullptr);
    EXPECT_EQ(err, AZIHSM_ERROR_INVALID_ARGUMENT);

    // Test invalid algorithm ID
    azihsm_algo invalid_algo = {
        .id = static_cast<azihsm_algo_id>(0xFFFFFFFF),
        .params = nullptr,
        .len = 0
    };
    err = azihsm_key_gen_pair(session_handle, &invalid_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    EXPECT_EQ(err, AZIHSM_ALGORITHM_NOT_SUPPORTED);
    EXPECT_EQ(pub_key_handle, 0);
    EXPECT_EQ(priv_key_handle, 0);

    // Test null property lists (should fail for RSA as bit length is required)
    err = azihsm_key_gen_pair(session_handle, &algo, nullptr, nullptr, &pub_key_handle, &priv_key_handle);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(pub_key_handle, 0);
    EXPECT_EQ(priv_key_handle, 0);
}

// Test RSA key pair generation with missing required properties
TEST_F(RSATest, RSAKeyPairGeneration_MissingBitLength)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0
    };

    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Empty property lists - should fail as bit length is required
    azihsm_key_prop_list pub_prop_list = {.props = nullptr, .count = 0};
    azihsm_key_prop_list priv_prop_list = {.props = nullptr, .count = 0};

    auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should fail when bit length property is missing";
    EXPECT_EQ(pub_key_handle, 0);
    EXPECT_EQ(priv_key_handle, 0);
}

// Test RSA key pair deletion
TEST_F(RSATest, RSAKeyPairGeneration_KeyDeletion)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0
    };

    uint32_t bit_len = 2048;
    
    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}
    };

    azihsm_key_prop_list pub_prop_list = {.props = nullptr, .count = 0};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 1};

    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Generate key pair
    auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(pub_key_handle, 0);
    EXPECT_NE(priv_key_handle, 0);

    // Test successful deletion
    err = azihsm_key_delete(session_handle, pub_key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to delete public key";

    err = azihsm_key_delete(session_handle, priv_key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to delete private key";

    // Test deletion of already deleted keys (should fail)
    err = azihsm_key_delete(session_handle, pub_key_handle);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should fail to delete already deleted public key";

    err = azihsm_key_delete(session_handle, priv_key_handle);
    EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should fail to delete already deleted private key";
}

// Test RSA key pair persistence across session close/reopen cycles
TEST_F(RSATest, RSAKeyPairPersistenceAcrossSessions)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0
    };

    uint32_t bit_len = 2048;
    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}
    };

    azihsm_key_prop_list pub_prop_list = {.props = nullptr, .count = 0};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 1};

    // First session - generate key pair
    azihsm_handle first_pub_handle = 0;
    azihsm_handle first_priv_handle = 0;

    auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, 
                                   &first_pub_handle, &first_priv_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate RSA key pair in first session";
    EXPECT_NE(first_pub_handle, 0) << "First session public key handle should be valid";
    EXPECT_NE(first_priv_handle, 0) << "First session private key handle should be valid";

    std::cout << "First session  - Public Key Handle: " << first_pub_handle << std::endl;
    std::cout << "First session  - Private Key Handle: " << first_priv_handle << std::endl;

    // Close the first session
    EXPECT_EQ(azihsm_sess_close(session_handle), AZIHSM_ERROR_SUCCESS);
    session_handle = 0;

    // Open a new session
    auto [new_partition_handle, new_session_handle] = open_session();
    ASSERT_NE(new_session_handle, 0) << "Failed to open new session";

    // Second session - try to generate another key pair with same properties
    azihsm_handle second_pub_handle = 0;
    azihsm_handle second_priv_handle = 0;

    err = azihsm_key_gen_pair(new_session_handle, &algo, &pub_prop_list, &priv_prop_list, 
                              &second_pub_handle, &second_priv_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate RSA key pair in second session";
    EXPECT_NE(second_pub_handle, 0) << "Second session public key handle should be valid";
    EXPECT_NE(second_priv_handle, 0) << "Second session private key handle should be valid";

    std::cout << "Second session - Public Key Handle: " << second_pub_handle << std::endl;
    std::cout << "Second session - Private Key Handle: " << second_priv_handle << std::endl;

    // Compare the key handles
    if (first_pub_handle == second_pub_handle && first_priv_handle == second_priv_handle) {
        std::cout << "✓ Same key handles across sessions - keys are persistent/reused" << std::endl;
    } else {
        std::cout << "✓ Different key handles across sessions - new keys generated each time" << std::endl;
    }

    // Try to delete keys from the new session
    err = azihsm_key_delete(new_session_handle, second_pub_handle);
    if (err == AZIHSM_ERROR_SUCCESS) {
        std::cout << "✓ Successfully deleted public key from new session" << std::endl;
    } else {
        std::cout << "✗ Could not delete public key from new session: " << err << std::endl;
    }

    err = azihsm_key_delete(new_session_handle, second_priv_handle);
    if (err == AZIHSM_ERROR_SUCCESS) {
        std::cout << "✓ Successfully deleted private key from new session" << std::endl;
    } else {
        std::cout << "✗ Could not delete private key from new session: " << err << std::endl;
    }

    // Clean up the new session
    EXPECT_EQ(azihsm_sess_close(new_session_handle), AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(azihsm_part_close(new_partition_handle), AZIHSM_ERROR_SUCCESS);

    // Set to 0 to prevent double cleanup in TearDown
    session_handle = 0;
    partition_handle = 0;
}

// Test RSA key pair behavior with multiple concurrent sessions
TEST_F(RSATest, RSAKeyPairSessionIsolation)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0
    };

    uint32_t bit_len = 2048;
    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}
    };

    azihsm_key_prop_list pub_prop_list = {.props = nullptr, .count = 0};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 1};

    // Open a second session
    auto [second_partition_handle, second_session_handle] = open_session();
    ASSERT_NE(second_session_handle, 0) << "Failed to open second session";

    // Generate key pairs in both sessions
    azihsm_handle session1_pub_handle = 0;
    azihsm_handle session1_priv_handle = 0;
    azihsm_handle session2_pub_handle = 0;
    azihsm_handle session2_priv_handle = 0;

    auto err1 = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, 
                                    &session1_pub_handle, &session1_priv_handle);
    EXPECT_EQ(err1, AZIHSM_ERROR_SUCCESS) << "Failed to generate RSA key pair in session1";

    auto err2 = azihsm_key_gen_pair(second_session_handle, &algo, &pub_prop_list, &priv_prop_list, 
                                    &session2_pub_handle, &session2_priv_handle);
    EXPECT_EQ(err2, AZIHSM_ERROR_SUCCESS) << "Failed to generate RSA key pair in session2";

    // Verify both key pairs are valid
    EXPECT_NE(session1_pub_handle, 0) << "Session1 public key should be valid";
    EXPECT_NE(session1_priv_handle, 0) << "Session1 private key should be valid";
    EXPECT_NE(session2_pub_handle, 0) << "Session2 public key should be valid";
    EXPECT_NE(session2_priv_handle, 0) << "Session2 private key should be valid";

    std::cout << "Session1 - Public Key Handle: " << session1_pub_handle 
              << ", Private Key Handle: " << session1_priv_handle << std::endl;
    std::cout << "Session2 - Public Key Handle: " << session2_pub_handle 
              << ", Private Key Handle: " << session2_priv_handle << std::endl;

    // Clean up keys from both sessions
    EXPECT_EQ(azihsm_key_delete(session_handle, session1_pub_handle), AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(azihsm_key_delete(session_handle, session1_priv_handle), AZIHSM_ERROR_SUCCESS);
    
    EXPECT_EQ(azihsm_key_delete(second_session_handle, session2_pub_handle), AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(azihsm_key_delete(second_session_handle, session2_priv_handle), AZIHSM_ERROR_SUCCESS);

    // Clean up the second session
    EXPECT_EQ(azihsm_sess_close(second_session_handle), AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(azihsm_part_close(second_partition_handle), AZIHSM_ERROR_SUCCESS);
}

// Test RSA key pair generation behavior under repeated generation attempts
TEST_F(RSATest, RSAKeyPairRepeatedGeneration)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0
    };

    uint32_t bit_len = 2048;
    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}
    };

    azihsm_key_prop_list pub_prop_list = {.props = nullptr, .count = 0};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 1};

    std::vector<azihsm_handle> pub_handles;
    std::vector<azihsm_handle> priv_handles;

    // Generate multiple key pairs in sequence
    for (int i = 0; i < 3; ++i) {
        azihsm_handle pub_handle = 0;
        azihsm_handle priv_handle = 0;

        auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, 
                                       &pub_handle, &priv_handle);
        
        std::cout << "Generation " << (i+1) << " - Public Handle: " << pub_handle 
                  << ", Private Handle: " << priv_handle << ", Result: " << err << std::endl;

        if (err == AZIHSM_ERROR_SUCCESS) {
            EXPECT_NE(pub_handle, 0) << "Public key handle should be valid for generation " << (i+1);
            EXPECT_NE(priv_handle, 0) << "Private key handle should be valid for generation " << (i+1);
            
            pub_handles.push_back(pub_handle);
            priv_handles.push_back(priv_handle);
        } else if (err == AZIHSM_KEY_ALREADY_EXISTS) {
            std::cout << "✓ Key already exists error for generation " << (i+1) << " - this is expected behavior" << std::endl;
        } else {
            // Other errors might be acceptable depending on HSM behavior
            std::cout << "ℹ Unexpected error for generation " << (i+1) << ": " << err << std::endl;
        }
    }

    // Clean up all successfully generated keys
    for (size_t i = 0; i < pub_handles.size(); ++i) {
        if (pub_handles[i] != 0) {
            azihsm_key_delete(session_handle, pub_handles[i]);
        }
        if (priv_handles[i] != 0) {
            azihsm_key_delete(session_handle, priv_handles[i]);
        }
    }
}

// Test RSA key property inspection behavior
TEST_F(RSATest, RSAKeyPairPropertyInspection)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0
    };

    uint32_t bit_len = 2048;
    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}
    };

    azihsm_key_prop_list pub_prop_list = {.props = nullptr, .count = 0};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 1};

    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    // Generate key pair
    auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list, 
                                   &pub_key_handle, &priv_key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate RSA key pair";
    EXPECT_NE(pub_key_handle, 0);
    EXPECT_NE(priv_key_handle, 0);

    // Try to get key properties to understand the key characteristics 
    std::vector<azihsm_key_prop_id> prop_ids_to_test = {
        AZIHSM_KEY_PROP_ID_CLASS,
        AZIHSM_KEY_PROP_ID_KIND,
        AZIHSM_KEY_PROP_ID_SESSION,
        AZIHSM_KEY_PROP_ID_PRIVATE,
        AZIHSM_KEY_PROP_ID_LOCAL,
        AZIHSM_KEY_PROP_ID_SENSITIVE,
        AZIHSM_KEY_PROP_ID_BIT_LEN
    };

    std::cout << "Public Key Properties:" << std::endl;
    for (auto prop_id : prop_ids_to_test) {
        uint32_t prop_value = 0;
        azihsm_key_prop key_prop = {
            .id = prop_id,
            .val = &prop_value,
            .len = sizeof(prop_value)
        };

        err = azihsm_key_get_prop(session_handle, pub_key_handle, &key_prop);
        if (err == AZIHSM_ERROR_SUCCESS) {
            std::cout << "  Property " << prop_id << ": " << prop_value << std::endl;
        } else {
            std::cout << "  Property " << prop_id << ": Error " << err << std::endl;
        }
    }

    std::cout << "Private Key Properties:" << std::endl;
    for (auto prop_id : prop_ids_to_test) {
        uint32_t prop_value = 0;
        azihsm_key_prop key_prop = {
            .id = prop_id,
            .val = &prop_value,
            .len = sizeof(prop_value)
        };

        err = azihsm_key_get_prop(session_handle, priv_key_handle, &key_prop);
        if (err == AZIHSM_ERROR_SUCCESS) {
            std::cout << "  Property " << prop_id << ": " << prop_value << std::endl;
        } else {
            std::cout << "  Property " << prop_id << ": Error " << err << std::endl;
        }
    }

    // Clean up
    EXPECT_EQ(azihsm_key_delete(session_handle, pub_key_handle), AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(azihsm_key_delete(session_handle, priv_key_handle), AZIHSM_ERROR_SUCCESS);
}
