// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>

class RSAKeyPropTest : public ::testing::Test
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

    // Helper function to generate a basic RSA key pair
    std::pair<azihsm_handle, azihsm_handle> generate_rsa_keypair(bool sign_usage = false, bool encrypt_usage = false)
    {
        azihsm_algo algo = {
            .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
            .params = nullptr,
            .len = 0
        };

        uint32_t bit_len = 2048;
        uint8_t sign_flag = sign_usage ? 1 : 0;
        uint8_t verify_flag = sign_usage ? 1 : 0;
        uint8_t decrypt_flag = encrypt_usage ? 1 : 0;
        uint8_t encrypt_flag = encrypt_usage ? 1 : 0;

        azihsm_key_prop pub_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_flag, .len = sizeof(encrypt_flag)},
            {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_flag, .len = sizeof(verify_flag)}
        };

        azihsm_key_prop priv_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_flag, .len = sizeof(decrypt_flag)},
            {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_flag, .len = sizeof(sign_flag)}
        };

        azihsm_key_prop_list pub_prop_list = {
            .props = pub_props, 
            .count = (encrypt_usage || sign_usage) ? 2u : 0u
        };
        azihsm_key_prop_list priv_prop_list = {
            .props = priv_props, 
            .count = (encrypt_usage || sign_usage) ? 3u : 1u
        };

        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;

        auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list,
                                       &pub_key_handle, &priv_key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate RSA key pair";
        
        return {pub_key_handle, priv_key_handle};
    }
};

// Test getting read-only properties that are set by the HSM
TEST_F(RSAKeyPropTest, GetReadOnlyProperties)
{
    auto [pub_key_handle, priv_key_handle] = generate_rsa_keypair();
    ASSERT_NE(pub_key_handle, 0);
    ASSERT_NE(priv_key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() {
        azihsm_key_delete(session_handle, pub_key_handle);
        azihsm_key_delete(session_handle, priv_key_handle);
    });

    // Test CLASS property (read-only, set by HSM)
    {
        uint32_t pub_class = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_CLASS,
            .val = &pub_class,
            .len = sizeof(pub_class)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(pub_class, 2u) // AZIHSM_KEY_CLASS_PUBLIC = 2
            << "Public key should have PUBLIC class";

        uint32_t priv_class = 0;
        prop.val = &priv_class;
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(priv_class, 1u) // AZIHSM_KEY_CLASS_PRIVATE = 1
            << "Private key should have PRIVATE class";
    }

    // Test KIND/TYPE property (read-only, set by algorithm)
    {
        uint32_t pub_kind = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_KIND,
            .val = &pub_kind,
            .len = sizeof(pub_kind)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(pub_kind, 1u) // AZIHSM_KEY_KIND_RSA = 1
            << "RSA public key should have RSA kind";

        uint32_t priv_kind = 0;
        prop.val = &priv_kind;
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(priv_kind, 1u) // AZIHSM_KEY_KIND_RSA = 1
            << "RSA private key should have RSA kind";
    }

    // Test PRIVATE property (read-only, always TRUE for session keys per spec)
    {
        uint8_t is_private = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_PRIVATE,
            .val = &is_private,
            .len = sizeof(is_private)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(is_private, 1) << "All session keys should be private per spec";
    }

    // Test LOCAL property (read-only, TRUE for generated keys)
    {
        uint8_t is_local = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_LOCAL,
            .val = &is_local,
            .len = sizeof(is_local)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(is_local, 1) << "Generated keys should have LOCAL=TRUE";
    }

    // Test SENSITIVE property (read-only, TRUE for private keys, FALSE for public keys)
    {
        uint8_t pub_sensitive = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_SENSITIVE,
            .val = &pub_sensitive,
            .len = sizeof(pub_sensitive)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(pub_sensitive, 0) << "Public keys should have SENSITIVE=FALSE";

        uint8_t priv_sensitive = 0;
        prop.val = &priv_sensitive;
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(priv_sensitive, 1) << "Private keys should have SENSITIVE=TRUE";
    }

    // Test ALWAYS_SENSITIVE property (read-only)
    {
        uint8_t always_sensitive = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_ALWAYS_SENSITIVE,
            .val = &always_sensitive,
            .len = sizeof(always_sensitive)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(always_sensitive, 1) << "Private keys should have ALWAYS_SENSITIVE=TRUE";
    }

    // Test COPYABLE property (read-only, always FALSE per spec)
    {
        uint8_t copyable = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_COPYABLE,
            .val = &copyable,
            .len = sizeof(copyable)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(copyable, 0) << "All keys should have COPYABLE=FALSE";
    }

    // Test DESTROYABLE property (read-only, TRUE for session keys)
    {
        uint8_t destroyable = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_DESTROYABLE,
            .val = &destroyable,
            .len = sizeof(destroyable)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(destroyable, 1) << "Session keys should have DESTROYABLE=TRUE";
    }

    // Test EXTRACTABLE property (read-only, TRUE for session keys)
    {
        uint8_t extractable = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_EXTRACTABLE,
            .val = &extractable,
            .len = sizeof(extractable)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(extractable, 1) << "Session keys should have EXTRACTABLE=TRUE";
    }

    // Test NEVER_EXTRACTABLE property (read-only, FALSE for session keys)
    {
        uint8_t never_extractable = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_NEVER_EXTRACTABLE,
            .val = &never_extractable,
            .len = sizeof(never_extractable)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(never_extractable, 0) << "Session keys should have NEVER_EXTRACTABLE=FALSE";
    }
}

// Test getting user-specifiable properties
TEST_F(RSAKeyPropTest, GetUserSpecifiableProperties)
{
    auto [pub_key_handle, priv_key_handle] = generate_rsa_keypair(true, false); // sign usage
    ASSERT_NE(pub_key_handle, 0);
    ASSERT_NE(priv_key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() {
        azihsm_key_delete(session_handle, pub_key_handle);
        azihsm_key_delete(session_handle, priv_key_handle);
    });

    // Test BIT_LEN property (user-specifiable during creation)
    {
        uint32_t bit_len = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
            .val = &bit_len,
            .len = sizeof(bit_len)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(bit_len, 2048u) << "Should return the specified bit length";

        bit_len = 0;
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(bit_len, 2048u) << "Private key should also have the same bit length";
    }

    // Test SESSION property (user-specifiable, defaults to TRUE)
    {
        uint8_t is_session = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_SESSION,
            .val = &is_session,
            .len = sizeof(is_session)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(is_session, 1) << "Default SESSION property should be TRUE";
    }

    // Test MODIFIABLE property (user-specifiable, defaults to FALSE)
    {
        uint8_t modifiable = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_MODIFIABLE,
            .val = &modifiable,
            .len = sizeof(modifiable)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(modifiable, 0) << "Default MODIFIABLE property should be FALSE";
    }

    // Test operation flags set during creation
    {
        uint8_t sign_flag = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_SIGN,
            .val = &sign_flag,
            .len = sizeof(sign_flag)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(sign_flag, 1) << "Private key should have SIGN=TRUE as specified during creation";

        uint8_t verify_flag = 0;
        prop.id = AZIHSM_KEY_PROP_ID_VERIFY;
        prop.val = &verify_flag;
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(verify_flag, 1) << "Public key should have VERIFY=TRUE as specified during creation";

        uint8_t encrypt_flag = 0;
        prop.id = AZIHSM_KEY_PROP_ID_ENCRYPT;
        prop.val = &encrypt_flag;
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(encrypt_flag, 0) << "Public key should have ENCRYPT=FALSE (not set during creation)";
    }
}

// Test that operation exclusivity is enforced per spec
TEST_F(RSAKeyPropTest, OperationExclusivityValidation)
{
    // Per spec and DDI layer:
    // Only ONE operation category is allowed per key:
    // - EncryptDecrypt: encrypt and/or decrypt
    // - SignVerify: sign and/or verify
    // - Unwrap: wrap and/or unwrap
    // - Derive: key derivation

    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0
    };

    uint32_t bit_len = 2048;

    // Test: Cannot have both sign and encrypt on the SAME key (different categories)
    {
        uint8_t sign_flag = 1;
        uint8_t encrypt_flag = 1;

        azihsm_key_prop pub_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_flag, .len = sizeof(encrypt_flag)},
            {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &sign_flag, .len = sizeof(sign_flag)}  // VERIFY is in SignVerify category
        };

        azihsm_key_prop priv_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_flag, .len = sizeof(sign_flag)},
            {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &encrypt_flag, .len = sizeof(encrypt_flag)}  // DECRYPT is in EncryptDecrypt category
        };

        azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 2};
        azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 3};

        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;

        auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list,
                                       &pub_key_handle, &priv_key_handle);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) 
            << "Should fail: public key has both ENCRYPT (EncryptDecrypt) and VERIFY (SignVerify), private key has both SIGN (SignVerify) and DECRYPT (EncryptDecrypt)";
    }

    // Test: Can have both encrypt and decrypt (same category)
    {
        uint8_t encrypt_flag = 1;
        uint8_t decrypt_flag = 1;

        azihsm_key_prop pub_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_flag, .len = sizeof(encrypt_flag)}
        };

        azihsm_key_prop priv_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_flag, .len = sizeof(decrypt_flag)}
        };

        azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 1};
        azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;

        auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list,
                                       &pub_key_handle, &priv_key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) 
            << "Should succeed: ENCRYPT and DECRYPT are in the same category (EncryptDecrypt)";

        if (err == AZIHSM_ERROR_SUCCESS) {
            azihsm_key_delete(session_handle, pub_key_handle);
            azihsm_key_delete(session_handle, priv_key_handle);
        }
    }

    // Test: Can have both sign and verify (same category)
    {
        uint8_t sign_flag = 1;
        uint8_t verify_flag = 1;

        azihsm_key_prop pub_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &verify_flag, .len = sizeof(verify_flag)}
        };

        azihsm_key_prop priv_props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &sign_flag, .len = sizeof(sign_flag)}
        };

        azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 1};
        azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

        azihsm_handle pub_key_handle = 0;
        azihsm_handle priv_key_handle = 0;

        auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list,
                                       &pub_key_handle, &priv_key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS)
            << "Should succeed: SIGN and VERIFY are in the same category (SignVerify)";

        if (err == AZIHSM_ERROR_SUCCESS) {
            azihsm_key_delete(session_handle, pub_key_handle);
            azihsm_key_delete(session_handle, priv_key_handle);
        }
    }
}

// Test setting properties after key creation (for modifiable keys)
TEST_F(RSAKeyPropTest, SetPropertyOnModifiableKey)
{
    // Note: Most properties are read-only or can only be set during creation
    // This test validates that attempting to set read-only properties fails

    auto [pub_key_handle, priv_key_handle] = generate_rsa_keypair();
    ASSERT_NE(pub_key_handle, 0);
    ASSERT_NE(priv_key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() {
        azihsm_key_delete(session_handle, pub_key_handle);
        azihsm_key_delete(session_handle, priv_key_handle);
    });

    // Test: Cannot set CLASS property (read-only)
    {
        uint32_t new_class = 3; // AZIHSM_KEY_CLASS_SECRET = 3
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_CLASS,
            .val = &new_class,
            .len = sizeof(new_class)
        };
        auto err = azihsm_key_set_prop(session_handle, pub_key_handle, &prop);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) 
            << "Should fail: CLASS is read-only";
    }

    // Test: Cannot set KIND property (read-only)
    {
        uint32_t new_kind = 3; // AZIHSM_KEY_KIND_AES = 3
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_KIND,
            .val = &new_kind,
            .len = sizeof(new_kind)
        };
        auto err = azihsm_key_set_prop(session_handle, pub_key_handle, &prop);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS)
            << "Should fail: KIND is read-only";
    }

    // Test: Cannot set BIT_LEN property after creation (immutable after first set)
    {
        uint32_t new_bit_len = 4096;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
            .val = &new_bit_len,
            .len = sizeof(new_bit_len)
        };
        auto err = azihsm_key_set_prop(session_handle, priv_key_handle, &prop);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS)
            << "Should fail: BIT_LEN is immutable after first set";
    }

    // Test: Cannot set PRIVATE property (read-only)
    {
        uint8_t new_private = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_PRIVATE,
            .val = &new_private,
            .len = sizeof(new_private)
        };
        auto err = azihsm_key_set_prop(session_handle, pub_key_handle, &prop);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS)
            << "Should fail: PRIVATE is read-only";
    }

    // Test: Cannot set LOCAL property (read-only)
    {
        uint8_t new_local = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_LOCAL,
            .val = &new_local,
            .len = sizeof(new_local)
        };
        auto err = azihsm_key_set_prop(session_handle, priv_key_handle, &prop);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS)
            << "Should fail: LOCAL is read-only";
    }
}

// Test property synchronization between public and private keys
TEST_F(RSAKeyPropTest, PublicPrivatePropertySynchronization)
{
    auto [pub_key_handle, priv_key_handle] = generate_rsa_keypair();
    ASSERT_NE(pub_key_handle, 0);
    ASSERT_NE(priv_key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() {
        azihsm_key_delete(session_handle, pub_key_handle);
        azihsm_key_delete(session_handle, priv_key_handle);
    });

    // Test: BIT_LEN should be synchronized between public and private keys
    {
        uint32_t pub_bit_len = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
            .val = &pub_bit_len,
            .len = sizeof(pub_bit_len)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);

        uint32_t priv_bit_len = 0;
        prop.val = &priv_bit_len;
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);

        EXPECT_EQ(pub_bit_len, priv_bit_len)
            << "BIT_LEN should be synchronized between public and private keys";
        EXPECT_EQ(pub_bit_len, 2048u) << "Both should be 2048 bits";
    }

    // Test: KIND should be the same for both keys
    {
        uint32_t pub_kind = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_KIND,
            .val = &pub_kind,
            .len = sizeof(pub_kind)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);

        uint32_t priv_kind = 0;
        prop.val = &priv_kind;
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);

        EXPECT_EQ(pub_kind, priv_kind) << "KIND should be synchronized";
        EXPECT_EQ(pub_kind, 1u); // AZIHSM_KEY_KIND_RSA = 1
    }

    // Test: CLASS should differ (public vs private)
    {
        uint32_t pub_class = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_CLASS,
            .val = &pub_class,
            .len = sizeof(pub_class)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);

        uint32_t priv_class = 0;
        prop.val = &priv_class;
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);

        EXPECT_NE(pub_class, priv_class) << "CLASS should differ between public and private";
        EXPECT_EQ(pub_class, 2u); // AZIHSM_KEY_CLASS_PUBLIC = 2
        EXPECT_EQ(priv_class, 1u); // AZIHSM_KEY_CLASS_PRIVATE = 1
    }

    // Test: SENSITIVE should differ (FALSE for public, TRUE for private)
    {
        uint8_t pub_sensitive = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_SENSITIVE,
            .val = &pub_sensitive,
            .len = sizeof(pub_sensitive)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);

        uint8_t priv_sensitive = 0;
        prop.val = &priv_sensitive;
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);

        EXPECT_EQ(pub_sensitive, 0) << "Public key SENSITIVE should be FALSE";
        EXPECT_EQ(priv_sensitive, 1) << "Private key SENSITIVE should be TRUE";
    }
}

// Test getting LABEL property
TEST_F(RSAKeyPropTest, LabelProperty)
{
    azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
        .params = nullptr,
        .len = 0
    };

    uint32_t bit_len = 2048;
    const char* test_label = "Test RSA Key";
    
    azihsm_key_prop pub_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_LABEL, .val = const_cast<char*>(test_label), .len = static_cast<uint32_t>(strlen(test_label))}
    };

    azihsm_key_prop priv_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
        {.id = AZIHSM_KEY_PROP_ID_LABEL, .val = const_cast<char*>(test_label), .len = static_cast<uint32_t>(strlen(test_label))}
    };

    azihsm_key_prop_list pub_prop_list = {.props = pub_props, .count = 1};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    azihsm_handle pub_key_handle = 0;
    azihsm_handle priv_key_handle = 0;

    auto err = azihsm_key_gen_pair(session_handle, &algo, &pub_prop_list, &priv_prop_list,
                                   &pub_key_handle, &priv_key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    if (err == AZIHSM_ERROR_SUCCESS) {
        auto cleanup = scope_guard::make_scope_exit([&]() {
            azihsm_key_delete(session_handle, pub_key_handle);
            azihsm_key_delete(session_handle, priv_key_handle);
        });

        // Get LABEL from public key
        {
            char label_buffer[128] = {0};
            azihsm_key_prop prop = {
                .id = AZIHSM_KEY_PROP_ID_LABEL,
                .val = label_buffer,
                .len = sizeof(label_buffer)
            };
            EXPECT_EQ(azihsm_key_get_prop(session_handle, pub_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
            EXPECT_STREQ(label_buffer, test_label) << "Public key label should match";
        }

        // Get LABEL from private key
        {
            char label_buffer[128] = {0};
            azihsm_key_prop prop = {
                .id = AZIHSM_KEY_PROP_ID_LABEL,
                .val = label_buffer,
                .len = sizeof(label_buffer)
            };
            EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
            EXPECT_STREQ(label_buffer, test_label) << "Private key label should match";
        }
    }
}

// Test WRAP_WITH_TRUSTED property (applicable to private keys)
TEST_F(RSAKeyPropTest, WrapWithTrustedProperty)
{
    auto [pub_key_handle, priv_key_handle] = generate_rsa_keypair();
    ASSERT_NE(pub_key_handle, 0);
    ASSERT_NE(priv_key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() {
        azihsm_key_delete(session_handle, pub_key_handle);
        azihsm_key_delete(session_handle, priv_key_handle);
    });

    // Test: WRAP_WITH_TRUSTED should be TRUE for private keys by default
    {
        uint8_t wrap_with_trusted = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_WRAP_WITH_TRUSTED,
            .val = &wrap_with_trusted,
            .len = sizeof(wrap_with_trusted)
        };
        EXPECT_EQ(azihsm_key_get_prop(session_handle, priv_key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(wrap_with_trusted, 1) 
            << "Private keys should have WRAP_WITH_TRUSTED=TRUE by default per spec";
    }
}

// Test invalid property access scenarios
TEST_F(RSAKeyPropTest, InvalidPropertyAccess)
{
    auto [pub_key_handle, priv_key_handle] = generate_rsa_keypair();
    ASSERT_NE(pub_key_handle, 0);
    ASSERT_NE(priv_key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() {
        azihsm_key_delete(session_handle, pub_key_handle);
        azihsm_key_delete(session_handle, priv_key_handle);
    });

    // Test: Invalid session handle
    {
        uint32_t value = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_CLASS,
            .val = &value,
            .len = sizeof(value)
        };
        auto err = azihsm_key_get_prop(999999, pub_key_handle, &prop);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should fail with invalid session handle";
    }

    // Test: Invalid key handle
    {
        uint32_t value = 0;
        azihsm_key_prop prop = {
            .id = AZIHSM_KEY_PROP_ID_CLASS,
            .val = &value,
            .len = sizeof(value)
        };
        auto err = azihsm_key_get_prop(session_handle, 999999, &prop);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should fail with invalid key handle";
    }

    // Test: Null property pointer
    {
        auto err = azihsm_key_get_prop(session_handle, pub_key_handle, nullptr);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should fail with null property pointer";
    }
}
