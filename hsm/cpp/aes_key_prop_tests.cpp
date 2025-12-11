// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"
#include <iostream>
#include <vector>
#include <cstring>

class AESKeyPropTest : public ::testing::Test
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

    // Helper function to generate an AES CBC key
    azihsm_handle generate_aes_cbc_key(uint32_t bit_len = 128, bool encrypt = true, bool decrypt = true) {
        azihsm_algo algo = {.id = AZIHSM_ALGO_ID_AES_KEY_GEN, .params = nullptr, .len = 0};

        uint8_t encrypt_flag = encrypt ? 1 : 0;
        uint8_t decrypt_flag = decrypt ? 1 : 0;

        azihsm_key_prop props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_flag, .len = sizeof(encrypt_flag)},
            {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_flag, .len = sizeof(decrypt_flag)}};

        azihsm_key_prop_list prop_list = {.props = props, .count = 3};

        azihsm_handle key_handle = 0;
        auto          err        = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES CBC key";

        return key_handle;
    }

    // Helper function to generate an AES XTS key
    azihsm_handle generate_aes_xts_key(bool encrypt = true, bool decrypt = true) {
        azihsm_algo algo = {.id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN, .params = nullptr, .len = 0};

        uint32_t bit_len      = 512; // AES-XTS requires 512 bits
        uint8_t  encrypt_flag = encrypt ? 1 : 0;
        uint8_t  decrypt_flag = decrypt ? 1 : 0;

        azihsm_key_prop props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_flag, .len = sizeof(encrypt_flag)},
            {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_flag, .len = sizeof(decrypt_flag)}};

        azihsm_key_prop_list prop_list = {.props = props, .count = 3};

        azihsm_handle key_handle = 0;
        auto          err        = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS) << "Failed to generate AES XTS key";

        return key_handle;
    }
};

// ================================================================================
// AES CBC Key Property Tests
// ================================================================================

// Test getting BitLen property for AES CBC keys
TEST_F(AESKeyPropTest, AesCbcGetBitLenProperty) {
    std::vector<uint32_t> bit_lengths = {128, 192, 256};

    for (auto expected_len : bit_lengths)
    {
        azihsm_handle key_handle = generate_aes_cbc_key(expected_len);
        ASSERT_NE(key_handle, 0);

        auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

        uint32_t        bit_len = 0;
        azihsm_key_prop prop    = {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)};

        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(bit_len, expected_len) << "BitLen should be " << expected_len;
    }
}

// Test getting boolean properties (Encrypt/Decrypt) for AES CBC keys
TEST_F(AESKeyPropTest, AesCbcGetBooleanProperties) {
    azihsm_handle key_handle = generate_aes_cbc_key(128, true, true);
    ASSERT_NE(key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

    // Test Encrypt property
    {
        uint8_t         encrypt_flag = 0;
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_flag, .len = sizeof(encrypt_flag)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(encrypt_flag, 1) << "Encrypt flag should be set to true";
    }

    // Test Decrypt property
    {
        uint8_t         decrypt_flag = 0;
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_flag, .len = sizeof(decrypt_flag)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(decrypt_flag, 1) << "Decrypt flag should be set to true";
    }
}

// Test getting Label property for AES CBC keys
TEST_F(AESKeyPropTest, AesCbcGetLabelProperty) {
    azihsm_algo algo = {.id = AZIHSM_ALGO_ID_AES_KEY_GEN, .params = nullptr, .len = 0};

    uint32_t    bit_len    = 256;
    const char *test_label = "Test AES CBC Key";

    azihsm_key_prop props[] = {{.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
                               {.id  = AZIHSM_KEY_PROP_ID_LABEL,
                                .val = const_cast<char *>(test_label),
                                .len = static_cast<uint32_t>(strlen(test_label))}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 2};

    azihsm_handle key_handle = 0;
    auto          err        = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

    // Get label property
    char            label_buffer[256] = {0};
    azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_LABEL, .val = label_buffer, .len = sizeof(label_buffer)};

    EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
    EXPECT_STREQ(label_buffer, test_label) << "Label should match the set value";
}

// Test getting Class and Kind properties for AES CBC keys
TEST_F(AESKeyPropTest, AesCbcGetClassAndKindProperties) {
    azihsm_handle key_handle = generate_aes_cbc_key(128);
    ASSERT_NE(key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

    // Test Class property (should be Secret for symmetric keys)
    {
        uint32_t        key_class = 0;
        azihsm_key_prop prop      = {.id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(key_class, 3u) // AZIHSM_KEY_CLASS_SECRET = 3
            << "AES CBC key should have SECRET class";
    }

    // Test Kind property (should be Aes)
    {
        uint32_t        key_kind = 0;
        azihsm_key_prop prop     = {.id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(key_kind, 3u) // AZIHSM_KEY_KIND_AES = 3
            << "AES CBC key should have AES kind";
    }
}

// Test that defaults are applied when operations are not specified
TEST_F(AESKeyPropTest, AesCbcDefaultsApplied) {
    azihsm_algo algo = {.id = AZIHSM_ALGO_ID_AES_KEY_GEN, .params = nullptr, .len = 0};

    // Generate key WITHOUT specifying encrypt/decrypt
    uint32_t        bit_len = 256;
    azihsm_key_prop props[] = {{.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 1};

    azihsm_handle key_handle = 0;
    auto          err        = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

    // Verify Encrypt is defaulted to true
    {
        uint8_t         encrypt_flag = 0;
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_flag, .len = sizeof(encrypt_flag)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(encrypt_flag, 1) << "Encrypt should default to true for AES keys";
    }

    // Verify Decrypt is defaulted to true
    {
        uint8_t         decrypt_flag = 0;
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_flag, .len = sizeof(decrypt_flag)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(decrypt_flag, 1) << "Decrypt should default to true for AES keys";
    }
}

// Test getting multiple properties in sequence
TEST_F(AESKeyPropTest, AesCbcGetMultipleProperties) {
    azihsm_algo algo = {.id = AZIHSM_ALGO_ID_AES_KEY_GEN, .params = nullptr, .len = 0};

    uint32_t    bit_len      = 192;
    uint8_t     encrypt_flag = 1;
    uint8_t     decrypt_flag = 1;
    const char *test_label   = "Multi-Prop AES Key";

    azihsm_key_prop props[] = {{.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
                               {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_flag, .len = sizeof(encrypt_flag)},
                               {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_flag, .len = sizeof(decrypt_flag)},
                               {.id  = AZIHSM_KEY_PROP_ID_LABEL,
                                .val = const_cast<char *>(test_label),
                                .len = static_cast<uint32_t>(strlen(test_label))}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 4};

    azihsm_handle key_handle = 0;
    auto          err        = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

    // Verify all properties are retrievable
    {
        uint32_t        retrieved_len = 0;
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &retrieved_len, .len = sizeof(retrieved_len)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(retrieved_len, 192u);
    }

    {
        uint8_t         retrieved_encrypt = 0;
        azihsm_key_prop prop              = {.id  = AZIHSM_KEY_PROP_ID_ENCRYPT,
                                             .val = &retrieved_encrypt,
                                             .len = sizeof(retrieved_encrypt)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(retrieved_encrypt, 1);
    }

    {
        uint8_t         retrieved_decrypt = 0;
        azihsm_key_prop prop              = {.id  = AZIHSM_KEY_PROP_ID_DECRYPT,
                                             .val = &retrieved_decrypt,
                                             .len = sizeof(retrieved_decrypt)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(retrieved_decrypt, 1);
    }

    {
        char            label_buf[256] = {0};
        azihsm_key_prop prop           = {.id = AZIHSM_KEY_PROP_ID_LABEL, .val = label_buf, .len = sizeof(label_buf)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_STREQ(label_buf, test_label);
    }

    {
        uint32_t        key_class = 0;
        azihsm_key_prop prop      = {.id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(key_class, 3u); // AZIHSM_KEY_CLASS_SECRET = 3
    }
}

// Test rejecting wrong KeyKind for AES CBC keys
TEST_F(AESKeyPropTest, AesCbcRejectWrongKind) {
    azihsm_handle key_handle = generate_aes_cbc_key(128);
    ASSERT_NE(key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

    // Try to set RSA KeyKind - should fail
    {
        uint32_t        rsa_kind = 1; // AZIHSM_KEY_KIND_RSA = 1
        azihsm_key_prop prop     = {.id = AZIHSM_KEY_PROP_ID_KIND, .val = &rsa_kind, .len = sizeof(rsa_kind)};
        auto            err      = azihsm_key_set_prop(session_handle, key_handle, &prop);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should reject RSA KeyKind for AES CBC key";
    }

    // Try to set AesXts KeyKind - should fail
    {
        uint32_t        aes_xts_kind = 4; // AZIHSM_KEY_KIND_AES_XTS = 4
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_KIND, .val = &aes_xts_kind, .len = sizeof(aes_xts_kind)};
        auto            err  = azihsm_key_set_prop(session_handle, key_handle, &prop);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should reject AesXts KeyKind for AES CBC key";
    }

    // Try to set correct KeyKind (Aes) - should also fail because KIND is immutable
    {
        uint32_t        aes_kind = 3; // AZIHSM_KEY_KIND_AES = 3
        azihsm_key_prop prop     = {.id = AZIHSM_KEY_PROP_ID_KIND, .val = &aes_kind, .len = sizeof(aes_kind)};
        auto            err      = azihsm_key_set_prop(session_handle, key_handle, &prop);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should fail: KIND is immutable after generation";
    }
}

// ================================================================================
// AES XTS Key Property Tests
// ================================================================================

// Test getting BitLen property for AES XTS keys
TEST_F(AESKeyPropTest, AesXtsGetBitLenProperty) {
    azihsm_handle key_handle = generate_aes_xts_key();
    ASSERT_NE(key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

    uint32_t        bit_len = 0;
    azihsm_key_prop prop    = {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)};

    EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
    EXPECT_EQ(bit_len, 512u) << "AES XTS key should have 512-bit length";
}

// Test getting boolean properties (Encrypt/Decrypt) for AES XTS keys
TEST_F(AESKeyPropTest, AesXtsGetBooleanProperties) {
    azihsm_handle key_handle = generate_aes_xts_key(true, true);
    ASSERT_NE(key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

    // Test Encrypt property
    {
        uint8_t         encrypt_flag = 0;
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_flag, .len = sizeof(encrypt_flag)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(encrypt_flag, 1) << "Encrypt flag should be set to true";
    }

    // Test Decrypt property
    {
        uint8_t         decrypt_flag = 0;
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_flag, .len = sizeof(decrypt_flag)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(decrypt_flag, 1) << "Decrypt flag should be set to true";
    }
}

// Test getting Class and Kind properties for AES XTS keys
TEST_F(AESKeyPropTest, AesXtsGetClassAndKindProperties) {
    azihsm_handle key_handle = generate_aes_xts_key();
    ASSERT_NE(key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

    // Test Class property (should be Secret for symmetric keys)
    {
        uint32_t        key_class = 0;
        azihsm_key_prop prop      = {.id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(key_class, 3u) // AZIHSM_KEY_CLASS_SECRET = 3
            << "AES XTS key should have SECRET class";
    }

    // Test Kind property (should be AesXts)
    {
        uint32_t        key_kind = 0;
        azihsm_key_prop prop     = {.id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(key_kind, 4u) // AZIHSM_KEY_KIND_AES_XTS = 4
            << "AES XTS key should have AES_XTS kind";
    }
}

// Test that defaults are applied when operations are not specified
TEST_F(AESKeyPropTest, AesXtsDefaultsApplied) {
    azihsm_algo algo = {.id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN, .params = nullptr, .len = 0};

    // Generate key WITHOUT specifying encrypt/decrypt
    uint32_t        bit_len = 512;
    azihsm_key_prop props[] = {{.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 1};

    azihsm_handle key_handle = 0;
    auto          err        = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

    // Verify Encrypt is defaulted to true
    {
        uint8_t         encrypt_flag = 0;
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_flag, .len = sizeof(encrypt_flag)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(encrypt_flag, 1) << "Encrypt should default to true for AES XTS keys";
    }

    // Verify Decrypt is defaulted to true
    {
        uint8_t         decrypt_flag = 0;
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_flag, .len = sizeof(decrypt_flag)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(decrypt_flag, 1) << "Decrypt should default to true for AES XTS keys";
    }
}

// Test getting multiple properties in sequence
TEST_F(AESKeyPropTest, AesXtsGetMultipleProperties) {
    azihsm_algo algo = {.id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN, .params = nullptr, .len = 0};

    uint32_t    bit_len      = 512;
    uint8_t     encrypt_flag = 1;
    uint8_t     decrypt_flag = 1;
    const char *test_label   = "Multi-Prop AES XTS Key";

    azihsm_key_prop props[] = {{.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
                               {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_flag, .len = sizeof(encrypt_flag)},
                               {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_flag, .len = sizeof(decrypt_flag)},
                               {.id  = AZIHSM_KEY_PROP_ID_LABEL,
                                .val = const_cast<char *>(test_label),
                                .len = static_cast<uint32_t>(strlen(test_label))}};

    azihsm_key_prop_list prop_list = {.props = props, .count = 4};

    azihsm_handle key_handle = 0;
    auto          err        = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

    // Verify all properties are retrievable
    {
        uint32_t        retrieved_len = 0;
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &retrieved_len, .len = sizeof(retrieved_len)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(retrieved_len, 512u);
    }

    {
        uint8_t         retrieved_encrypt = 0;
        azihsm_key_prop prop              = {.id  = AZIHSM_KEY_PROP_ID_ENCRYPT,
                                             .val = &retrieved_encrypt,
                                             .len = sizeof(retrieved_encrypt)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(retrieved_encrypt, 1);
    }

    {
        uint8_t         retrieved_decrypt = 0;
        azihsm_key_prop prop              = {.id  = AZIHSM_KEY_PROP_ID_DECRYPT,
                                             .val = &retrieved_decrypt,
                                             .len = sizeof(retrieved_decrypt)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(retrieved_decrypt, 1);
    }

    {
        char            label_buf[256] = {0};
        azihsm_key_prop prop           = {.id = AZIHSM_KEY_PROP_ID_LABEL, .val = label_buf, .len = sizeof(label_buf)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_STREQ(label_buf, test_label);
    }

    {
        uint32_t        key_class = 0;
        azihsm_key_prop prop      = {.id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(key_class, 3u); // AZIHSM_KEY_CLASS_SECRET = 3
    }
}

// Test rejecting wrong KeyKind for AES XTS keys
TEST_F(AESKeyPropTest, AesXtsRejectWrongKind) {
    azihsm_handle key_handle = generate_aes_xts_key();
    ASSERT_NE(key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

    // Try to set RSA KeyKind - should fail
    {
        uint32_t        rsa_kind = 1; // AZIHSM_KEY_KIND_RSA = 1
        azihsm_key_prop prop     = {.id = AZIHSM_KEY_PROP_ID_KIND, .val = &rsa_kind, .len = sizeof(rsa_kind)};
        auto            err      = azihsm_key_set_prop(session_handle, key_handle, &prop);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should reject RSA KeyKind for AES XTS key";
    }

    // Try to set Aes (CBC) KeyKind - should fail
    {
        uint32_t        aes_kind = 3; // AZIHSM_KEY_KIND_AES = 3
        azihsm_key_prop prop     = {.id = AZIHSM_KEY_PROP_ID_KIND, .val = &aes_kind, .len = sizeof(aes_kind)};
        auto            err      = azihsm_key_set_prop(session_handle, key_handle, &prop);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should reject Aes KeyKind for AES XTS key";
    }

    // Try to set correct KeyKind (AesXts) - should also fail because KIND is immutable
    {
        uint32_t        aes_xts_kind = 4; // AZIHSM_KEY_KIND_AES_XTS = 4
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_KIND, .val = &aes_xts_kind, .len = sizeof(aes_xts_kind)};
        auto            err  = azihsm_key_set_prop(session_handle, key_handle, &prop);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS) << "Should fail: KIND is immutable after generation";
    }
}

// Test read-only properties for AES keys
TEST_F(AESKeyPropTest, AesGetReadOnlyProperties) {
    azihsm_handle key_handle = generate_aes_cbc_key(256);
    ASSERT_NE(key_handle, 0);

    auto cleanup = scope_guard::make_scope_exit([&]() { azihsm_key_delete(session_handle, key_handle); });

    // Test PRIVATE property (read-only, always TRUE for session keys per spec)
    {
        uint8_t         is_private = 0;
        azihsm_key_prop prop       = {.id = AZIHSM_KEY_PROP_ID_PRIVATE, .val = &is_private, .len = sizeof(is_private)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(is_private, 1) << "All session keys should be private per spec";
    }

    // Test LOCAL property (read-only, TRUE for generated keys)
    {
        uint8_t         is_local = 0;
        azihsm_key_prop prop     = {.id = AZIHSM_KEY_PROP_ID_LOCAL, .val = &is_local, .len = sizeof(is_local)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(is_local, 1) << "Generated keys should have LOCAL=TRUE";
    }

    // Test SENSITIVE property (read-only, TRUE for secret keys)
    {
        uint8_t         is_sensitive = 0;
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_SENSITIVE, .val = &is_sensitive, .len = sizeof(is_sensitive)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(is_sensitive, 1) << "Secret keys should have SENSITIVE=TRUE";
    }

    // Test ALWAYS_SENSITIVE property (read-only)
    {
        uint8_t         always_sensitive = 0;
        azihsm_key_prop prop             = {.id  = AZIHSM_KEY_PROP_ID_ALWAYS_SENSITIVE,
                                            .val = &always_sensitive,
                                            .len = sizeof(always_sensitive)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(always_sensitive, 1) << "Secret keys should have ALWAYS_SENSITIVE=TRUE";
    }

    // Test SESSION property (defaults to TRUE)
    {
        uint8_t         is_session = 0;
        azihsm_key_prop prop       = {.id = AZIHSM_KEY_PROP_ID_SESSION, .val = &is_session, .len = sizeof(is_session)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(is_session, 1) << "Default SESSION property should be TRUE";
    }

    // Test MODIFIABLE property (defaults to FALSE)
    {
        uint8_t         modifiable = 0;
        azihsm_key_prop prop = {.id = AZIHSM_KEY_PROP_ID_MODIFIABLE, .val = &modifiable, .len = sizeof(modifiable)};
        EXPECT_EQ(azihsm_key_get_prop(session_handle, key_handle, &prop), AZIHSM_ERROR_SUCCESS);
        EXPECT_EQ(modifiable, 0) << "Default MODIFIABLE property should be FALSE";
    }
}

// Test that operation exclusivity is enforced for AES keys
TEST_F(AESKeyPropTest, AesOperationExclusivityValidation) {
    azihsm_algo algo = {.id = AZIHSM_ALGO_ID_AES_KEY_GEN, .params = nullptr, .len = 0};

    uint32_t bit_len = 256;

    // Test: Can have both encrypt and decrypt (same category - EncryptDecrypt)
    {
        uint8_t encrypt_flag = 1;
        uint8_t decrypt_flag = 1;

        azihsm_key_prop props[] = {
            {.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
            {.id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &encrypt_flag, .len = sizeof(encrypt_flag)},
            {.id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &decrypt_flag, .len = sizeof(decrypt_flag)}};

        azihsm_key_prop_list prop_list = {.props = props, .count = 3};

        azihsm_handle key_handle = 0;
        auto          err        = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS)
            << "Should succeed: ENCRYPT and DECRYPT are in the same category (EncryptDecrypt)";

        if (err == AZIHSM_ERROR_SUCCESS)
        {
            azihsm_key_delete(session_handle, key_handle);
        }
    }

    // Test: Cannot have both encrypt and wrap (different categories)
    {
        uint8_t encrypt_flag = 1;
        uint8_t wrap_flag    = 1;

        azihsm_key_prop props[] = {{.id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bit_len, .len = sizeof(bit_len)},
                                   {.id  = AZIHSM_KEY_PROP_ID_ENCRYPT,
                                    .val = &encrypt_flag,
                                    .len = sizeof(encrypt_flag)},
                                   {.id = AZIHSM_KEY_PROP_ID_WRAP, .val = &wrap_flag, .len = sizeof(wrap_flag)}};

        azihsm_key_prop_list prop_list = {.props = props, .count = 3};

        azihsm_handle key_handle = 0;
        auto          err        = azihsm_key_gen(session_handle, &algo, &prop_list, &key_handle);
        EXPECT_NE(err, AZIHSM_ERROR_SUCCESS)
            << "Should fail: ENCRYPT (EncryptDecrypt) and WRAP (Unwrap) are in different categories";
    }
}
