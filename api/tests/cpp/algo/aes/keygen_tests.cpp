// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include <vector>

#include "handle/key_handle.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"

// Helper to build XTS wrapped blob header
// Format: magic (u64 LE) + version (u16 LE) + key1_len (u16 LE) + key2_len (u16 LE) + reserved (u16 LE)
static std::vector<uint8_t> build_xts_wrapped_blob_header(uint16_t key1_len, uint16_t key2_len)
{
    const uint64_t WRAP_BLOB_MAGIC = 0x5354584D'53485A41ULL; // "AZHSMXTS" in little-endian
    const uint16_t WRAP_BLOB_VERSION = 1;

    std::vector<uint8_t> header(16, 0);
    
    // Magic (8 bytes, little-endian)
    for (int i = 0; i < 8; i++) {
        header[i] = static_cast<uint8_t>((WRAP_BLOB_MAGIC >> (i * 8)) & 0xFF);
    }
    
    // Version (2 bytes, little-endian)
    header[8] = static_cast<uint8_t>(WRAP_BLOB_VERSION & 0xFF);
    header[9] = static_cast<uint8_t>((WRAP_BLOB_VERSION >> 8) & 0xFF);
    
    // Key1 length (2 bytes, little-endian)
    header[10] = static_cast<uint8_t>(key1_len & 0xFF);
    header[11] = static_cast<uint8_t>((key1_len >> 8) & 0xFF);
    
    // Key2 length (2 bytes, little-endian)
    header[12] = static_cast<uint8_t>(key2_len & 0xFF);
    header[13] = static_cast<uint8_t>((key2_len >> 8) & 0xFF);
    
    // Reserved (2 bytes) - already zero
    
    return header;
}

// Helper to build complete XTS wrapped blob (header + wrapped_key1 + wrapped_key2)
static std::vector<uint8_t> build_xts_wrapped_blob(
    azihsm_handle wrapping_pub_key,
    const std::vector<uint8_t>& key1_plain,
    const std::vector<uint8_t>& key2_plain
)
{
    azihsm_status err;
    
    // Wrap key1
    azihsm_algo_rsa_pkcs_oaep_params oaep_params = {};
    oaep_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
    oaep_params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256;
    oaep_params.label = nullptr;

    azihsm_algo_rsa_aes_wrap_params wrap_params = {};
    wrap_params.oaep_params = &oaep_params;
    wrap_params.aes_key_bits = static_cast<uint32_t>(key1_plain.size() * 8);

    azihsm_algo wrap_algo = {};
    wrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_WRAP;
    wrap_algo.params = &wrap_params;
    wrap_algo.len = sizeof(wrap_params);

    azihsm_buffer key1_buf = {};
    key1_buf.ptr = const_cast<uint8_t*>(key1_plain.data());
    key1_buf.len = static_cast<uint32_t>(key1_plain.size());

    std::vector<uint8_t> key1_wrapped(4096);
    azihsm_buffer key1_wrapped_buf = {};
    key1_wrapped_buf.ptr = key1_wrapped.data();
    key1_wrapped_buf.len = static_cast<uint32_t>(key1_wrapped.size());

    err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &key1_buf, &key1_wrapped_buf);
    if (err != AZIHSM_STATUS_SUCCESS) {
        return {};
    }
    key1_wrapped.resize(key1_wrapped_buf.len);

    // Wrap key2
    wrap_params.aes_key_bits = static_cast<uint32_t>(key2_plain.size() * 8);
    
    azihsm_buffer key2_buf = {};
    key2_buf.ptr = const_cast<uint8_t*>(key2_plain.data());
    key2_buf.len = static_cast<uint32_t>(key2_plain.size());

    std::vector<uint8_t> key2_wrapped(4096);
    azihsm_buffer key2_wrapped_buf = {};
    key2_wrapped_buf.ptr = key2_wrapped.data();
    key2_wrapped_buf.len = static_cast<uint32_t>(key2_wrapped.size());

    err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &key2_buf, &key2_wrapped_buf);
    if (err != AZIHSM_STATUS_SUCCESS) {
        return {};
    }
    key2_wrapped.resize(key2_wrapped_buf.len);

    // Build header
    auto header = build_xts_wrapped_blob_header(
        static_cast<uint16_t>(key1_wrapped.size()),
        static_cast<uint16_t>(key2_wrapped.size())
    );

    // Combine header + key1_wrapped + key2_wrapped
    std::vector<uint8_t> blob;
    blob.reserve(header.size() + key1_wrapped.size() + key2_wrapped.size());
    blob.insert(blob.end(), header.begin(), header.end());
    blob.insert(blob.end(), key1_wrapped.begin(), key1_wrapped.end());
    blob.insert(blob.end(), key2_wrapped.begin(), key2_wrapped.end());

    return blob;
}

class azihsm_aes_keygen : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Helper function to compare key properties
    static void compare_key_properties(
        azihsm_handle original_key,
        azihsm_handle unmasked_key,
        uint32_t expected_bits
    )
    {
        // Compare key class
        azihsm_key_class original_class, unmasked_class;
        uint32_t len = sizeof(azihsm_key_class);
        azihsm_key_prop prop{};
        
        prop.id = AZIHSM_KEY_PROP_ID_CLASS;
        prop.val = &original_class;
        prop.len = len;
        azihsm_status err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_class;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_class, unmasked_class);

        // Compare key kind
        azihsm_key_kind original_kind, unmasked_kind;
        prop.id = AZIHSM_KEY_PROP_ID_KIND;
        prop.len = sizeof(azihsm_key_kind);
        
        prop.val = &original_kind;
        err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_kind;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_kind, unmasked_kind);
        EXPECT_EQ(original_kind, AZIHSM_KEY_KIND_AES);

        // Compare key bit length
        uint32_t original_bits, unmasked_bits;
        prop.id = AZIHSM_KEY_PROP_ID_BIT_LEN;
        prop.len = sizeof(uint32_t);
        
        prop.val = &original_bits;
        err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_bits;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_bits, unmasked_bits);
        EXPECT_EQ(original_bits, expected_bits);

        // Compare encrypt capability
        bool original_can_encrypt, unmasked_can_encrypt;
        prop.id = AZIHSM_KEY_PROP_ID_ENCRYPT;
        prop.len = sizeof(bool);
        
        prop.val = &original_can_encrypt;
        err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_can_encrypt;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_can_encrypt, unmasked_can_encrypt);

        // Compare decrypt capability
        bool original_can_decrypt, unmasked_can_decrypt;
        prop.id = AZIHSM_KEY_PROP_ID_DECRYPT;
        prop.len = sizeof(bool);
        
        prop.val = &original_can_decrypt;
        err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_can_decrypt;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_can_decrypt, unmasked_can_decrypt);
    }

    // Helper function to compare AES XTS key properties
    static void compare_aes_xts_key_properties(
        azihsm_handle original_key,
        azihsm_handle unmasked_key,
        uint32_t expected_bits
    )
    {
        // Compare key class
        azihsm_key_class original_class, unmasked_class;
        uint32_t len = sizeof(azihsm_key_class);
        azihsm_key_prop prop{};
        
        prop.id = AZIHSM_KEY_PROP_ID_CLASS;
        prop.val = &original_class;
        prop.len = len;
        azihsm_status err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_class;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_class, unmasked_class);

        // Compare key kind
        azihsm_key_kind original_kind, unmasked_kind;
        prop.id = AZIHSM_KEY_PROP_ID_KIND;
        prop.len = sizeof(azihsm_key_kind);
        
        prop.val = &original_kind;
        err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_kind;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_kind, unmasked_kind);
        EXPECT_EQ(original_kind, AZIHSM_KEY_KIND_AES_XTS);

        // Compare key bit length
        uint32_t original_bits, unmasked_bits;
        prop.id = AZIHSM_KEY_PROP_ID_BIT_LEN;
        prop.len = sizeof(uint32_t);
        
        prop.val = &original_bits;
        err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_bits;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_bits, unmasked_bits);
        EXPECT_EQ(original_bits, expected_bits);

        // Compare encrypt capability
        bool original_can_encrypt, unmasked_can_encrypt;
        prop.id = AZIHSM_KEY_PROP_ID_ENCRYPT;
        prop.len = sizeof(bool);
        
        prop.val = &original_can_encrypt;
        err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_can_encrypt;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_can_encrypt, unmasked_can_encrypt);

        // Compare decrypt capability
        bool original_can_decrypt, unmasked_can_decrypt;
        prop.id = AZIHSM_KEY_PROP_ID_DECRYPT;
        prop.len = sizeof(bool);
        
        prop.val = &original_can_decrypt;
        err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        
        prop.val = &unmasked_can_decrypt;
        err = azihsm_key_get_prop(unmasked_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_can_decrypt, unmasked_can_decrypt);
    }
};

TEST_F(azihsm_aes_keygen, unmask_aes_128_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Step 1: Generate AES-128 key
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES;
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t bits = 128;
        bool is_session = true;
        bool can_encrypt = true;
        bool can_decrypt = true;

        std::vector<azihsm_key_prop> props_vec = {
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) },
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) },
            { .id = AZIHSM_KEY_PROP_ID_SESSION, .val = &is_session, .len = sizeof(is_session) },
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) },
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &can_decrypt, .len = sizeof(can_decrypt) }
        };

        azihsm_key_prop_list prop_list{
            .props = props_vec.data(),
            .count = static_cast<uint32_t>(props_vec.size())
        };

        azihsm_handle original_key = 0;
        azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, &original_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(original_key, 0);

        auto cleanup_original = scope_guard::make_scope_exit([original_key] {
            azihsm_key_delete(original_key);
        });

        // Step 2: Get masked key via property
        uint8_t *masked_key_ptr = nullptr;
        uint32_t masked_key_len = 0;
        
        azihsm_key_prop masked_prop{};
        masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
        masked_prop.val = masked_key_ptr;
        masked_prop.len = masked_key_len;
        
        err = azihsm_key_get_prop(original_key, &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(masked_prop.len, 0);

        std::vector<uint8_t> masked_key_data(masked_prop.len);
        masked_prop.val = masked_key_data.data();
        
        err = azihsm_key_get_prop(original_key, &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Step 3: Unmask the masked key
        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        azihsm_handle unmasked_key = 0;
        err = azihsm_key_unmask(session, AZIHSM_KEY_KIND_AES, &masked_key_buf, &unmasked_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unmasked_key, 0);

        auto cleanup_unmasked = scope_guard::make_scope_exit([unmasked_key] {
            azihsm_key_delete(unmasked_key);
        });

        // Step 4: Compare key properties
        compare_key_properties(original_key, unmasked_key, 128);
    });
}

TEST_F(azihsm_aes_keygen, unmask_aes_xts_512_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Step 1: Generate AES-XTS-512 key
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES_XTS;
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t bits = 512;
        bool is_session = true;
        bool can_encrypt = true;
        bool can_decrypt = true;

        std::vector<azihsm_key_prop> props_vec;
        props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
        props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) });
        props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) });
        props_vec.push_back({ AZIHSM_KEY_PROP_ID_SESSION, &is_session, sizeof(is_session) });
        props_vec.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) });
        props_vec.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) });

        azihsm_key_prop_list prop_list{
            props_vec.data(),
            static_cast<uint32_t>(props_vec.size())
        };

        azihsm_handle original_key = 0;
        azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, &original_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(original_key, 0);

        auto cleanup_original = scope_guard::make_scope_exit([original_key] {
            azihsm_key_delete(original_key);
        });

        // Step 2: Get masked key via property
        uint8_t *masked_key_ptr = nullptr;
        uint32_t masked_key_len = 0;
        
        azihsm_key_prop masked_prop{};
        masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
        masked_prop.val = masked_key_ptr;
        masked_prop.len = masked_key_len;
        
        err = azihsm_key_get_prop(original_key, &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(masked_prop.len, 0);

        std::vector<uint8_t> masked_key_data(masked_prop.len);
        masked_prop.val = masked_key_data.data();
        
        err = azihsm_key_get_prop(original_key, &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Step 3: Unmask the masked key
        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        azihsm_handle unmasked_key = 0;
        err = azihsm_key_unmask(session, AZIHSM_KEY_KIND_AES_XTS, &masked_key_buf, &unmasked_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unmasked_key, 0);

        auto cleanup_unmasked = scope_guard::make_scope_exit([unmasked_key] {
            azihsm_key_delete(unmasked_key);
        });

        // Step 4: Compare key properties
        compare_aes_xts_key_properties(original_key, unmasked_key, 512);
    });
}

TEST_F(azihsm_aes_keygen, unwrap_aes_xts_512_key)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Step 1: Generate an RSA key pair for wrapping/unwrapping
        azihsm_algo rsa_keygen_algo{};
        rsa_keygen_algo.id = AZIHSM_ALGO_ID_RSA_KEY_UNWRAPPING_KEY_PAIR_GEN;
        rsa_keygen_algo.params = nullptr;
        rsa_keygen_algo.len = 0;

        azihsm_key_kind rsa_key_kind = AZIHSM_KEY_KIND_RSA;
        azihsm_key_class priv_key_class = AZIHSM_KEY_CLASS_PRIVATE;
        azihsm_key_class pub_key_class = AZIHSM_KEY_CLASS_PUBLIC;
        uint32_t rsa_bits = 2048;
        bool rsa_session = false;
        bool can_wrap = true;
        bool can_unwrap = true;

        std::vector<azihsm_key_prop> priv_props_vec;
        priv_props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &rsa_bits, sizeof(rsa_bits) });
        priv_props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &priv_key_class, sizeof(priv_key_class) });
        priv_props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &rsa_key_kind, sizeof(rsa_key_kind) });
        priv_props_vec.push_back({ AZIHSM_KEY_PROP_ID_SESSION, &rsa_session, sizeof(rsa_session) });
        priv_props_vec.push_back({ AZIHSM_KEY_PROP_ID_UNWRAP, &can_unwrap, sizeof(can_unwrap) });

        azihsm_key_prop_list priv_prop_list{
            priv_props_vec.data(),
            static_cast<uint32_t>(priv_props_vec.size())
        };

        std::vector<azihsm_key_prop> pub_props_vec;
        pub_props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &rsa_bits, sizeof(rsa_bits) });
        pub_props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &pub_key_class, sizeof(pub_key_class) });
        pub_props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &rsa_key_kind, sizeof(rsa_key_kind) });
        pub_props_vec.push_back({ AZIHSM_KEY_PROP_ID_SESSION, &rsa_session, sizeof(rsa_session) });
        pub_props_vec.push_back({ AZIHSM_KEY_PROP_ID_WRAP, &can_wrap, sizeof(can_wrap) });

        azihsm_key_prop_list pub_prop_list{
            pub_props_vec.data(),
            static_cast<uint32_t>(pub_props_vec.size())
        };

        azihsm_handle wrapping_priv_key = 0;
        azihsm_handle wrapping_pub_key = 0;
        azihsm_status err = azihsm_key_gen_pair(
            session,
            &rsa_keygen_algo,
            &priv_prop_list,
            &pub_prop_list,
            &wrapping_priv_key,
            &wrapping_pub_key
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(wrapping_priv_key, 0);
        ASSERT_NE(wrapping_pub_key, 0);

        auto cleanup_wrapping_keys = scope_guard::make_scope_exit([wrapping_priv_key, wrapping_pub_key] {
            azihsm_key_delete(wrapping_priv_key);
            azihsm_key_delete(wrapping_pub_key);
        });

        // Step 2: Create two AES-256 keys for XTS (32 bytes each = 256 bits)
        std::vector<uint8_t> key1_plain(32, 0x11); // First half of XTS key
        std::vector<uint8_t> key2_plain(32, 0x22); // Second half of XTS key

        // Step 3: Build the wrapped XTS blob with proper header
        auto wrapped_blob = build_xts_wrapped_blob(wrapping_pub_key, key1_plain, key2_plain);
        ASSERT_FALSE(wrapped_blob.empty());

        // Step 4: Unwrap the XTS key
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES_XTS;
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t bits = 512;
        bool is_session = true;
        bool can_encrypt = true;
        bool can_decrypt = true;

        azihsm_algo_rsa_pkcs_oaep_params oaep_params = {};
        oaep_params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
        oaep_params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256;
        oaep_params.label = nullptr;

        azihsm_algo_rsa_aes_key_wrap_params unwrap_params = {};
        unwrap_params.oaep_params = &oaep_params;

        azihsm_algo unwrap_algo = {};
        unwrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP;
        unwrap_algo.params = &unwrap_params;
        unwrap_algo.len = sizeof(unwrap_params);

        std::vector<azihsm_key_prop> unwrap_props_vec;
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) });
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) });
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_SESSION, &is_session, sizeof(is_session) });
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) });
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) });

        azihsm_key_prop_list unwrap_prop_list{
            unwrap_props_vec.data(),
            static_cast<uint32_t>(unwrap_props_vec.size())
        };

        azihsm_buffer wrapped_blob_buf = {};
        wrapped_blob_buf.ptr = wrapped_blob.data();
        wrapped_blob_buf.len = static_cast<uint32_t>(wrapped_blob.size());

        azihsm_handle unwrapped_key = 0;
        err = azihsm_key_unwrap(
            &unwrap_algo,
            wrapping_priv_key,
            &wrapped_blob_buf,
            &unwrap_prop_list,
            &unwrapped_key
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unwrapped_key, 0);

        auto cleanup_unwrapped = scope_guard::make_scope_exit([unwrapped_key] {
            azihsm_key_delete(unwrapped_key);
        });

        // Step 5: Verify the unwrapped key has correct properties
        azihsm_key_kind unwrapped_kind;
        azihsm_key_prop prop{};
        prop.id = AZIHSM_KEY_PROP_ID_KIND;
        prop.val = &unwrapped_kind;
        prop.len = sizeof(unwrapped_kind);
        err = azihsm_key_get_prop(unwrapped_key, &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(unwrapped_kind, AZIHSM_KEY_KIND_AES_XTS);

        uint32_t unwrapped_bits;
        prop.id = AZIHSM_KEY_PROP_ID_BIT_LEN;
        prop.val = &unwrapped_bits;
        prop.len = sizeof(unwrapped_bits);
        err = azihsm_key_get_prop(unwrapped_key, &prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(unwrapped_bits, 512);
    });
}
