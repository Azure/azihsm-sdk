// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "aes_keygen.hpp"
#include "rsa_keygen.hpp"
#include "utils/auto_key.hpp"

// Helper to build XTS wrapped blob header
// Format: magic (u64 LE) + version (u16 LE) + key1_len (u16 LE) + key2_len (u16 LE) + reserved (u16
// LE)
std::vector<uint8_t> build_xts_wrapped_blob_header(uint16_t key1_len, uint16_t key2_len)
{
    const uint64_t WRAP_BLOB_MAGIC = 0x5354584D'53485A41ULL; // "AZHSMXTS" in little-endian
    const uint16_t WRAP_BLOB_VERSION = 1;

    std::vector<uint8_t> header(16, 0);

    // Magic (8 bytes, little-endian)
    for (int i = 0; i < 8; i++)
    {
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
std::vector<uint8_t> build_xts_wrapped_blob(
    azihsm_handle wrapping_pub_key,
    const std::vector<uint8_t> &key1_plain,
    const std::vector<uint8_t> &key2_plain
)
{
    azihsm_status err;

    // Wrap key1
    azihsm_algo_rsa_pkcs_oaep_params oaep_params = build_oaep_sha256_params();

    azihsm_algo_rsa_aes_wrap_params wrap_params = {};
    wrap_params.oaep_params = &oaep_params;
    wrap_params.aes_key_bits = static_cast<uint32_t>(key1_plain.size() * 8);

    azihsm_algo wrap_algo = {};
    wrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_WRAP;
    wrap_algo.params = &wrap_params;
    wrap_algo.len = sizeof(wrap_params);

    azihsm_buffer key1_buf = {};
    key1_buf.ptr = const_cast<uint8_t *>(key1_plain.data());
    key1_buf.len = static_cast<uint32_t>(key1_plain.size());

    std::vector<uint8_t> key1_wrapped(4096);
    azihsm_buffer key1_wrapped_buf = {};
    key1_wrapped_buf.ptr = key1_wrapped.data();
    key1_wrapped_buf.len = static_cast<uint32_t>(key1_wrapped.size());

    err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &key1_buf, &key1_wrapped_buf);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
        return {};
    }
    key1_wrapped.resize(key1_wrapped_buf.len);

    // Wrap key2
    wrap_params.aes_key_bits = static_cast<uint32_t>(key2_plain.size() * 8);

    azihsm_buffer key2_buf = {};
    key2_buf.ptr = const_cast<uint8_t *>(key2_plain.data());
    key2_buf.len = static_cast<uint32_t>(key2_plain.size());

    std::vector<uint8_t> key2_wrapped(4096);
    azihsm_buffer key2_wrapped_buf = {};
    key2_wrapped_buf.ptr = key2_wrapped.data();
    key2_wrapped_buf.len = static_cast<uint32_t>(key2_wrapped.size());

    err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &key2_buf, &key2_wrapped_buf);
    if (err != AZIHSM_STATUS_SUCCESS)
    {
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

// Helper to build OAEP params with SHA-256 for RSA AES key unwrap
azihsm_algo_rsa_pkcs_oaep_params build_oaep_sha256_params()
{
    azihsm_algo_rsa_pkcs_oaep_params params{};
    params.hash_algo_id = AZIHSM_ALGO_ID_SHA256;
    params.mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256;
    params.label = nullptr;
    return params;
}

// Helper to build RSA AES key unwrap params for given key kind and bits
azihsm_algo_rsa_aes_key_wrap_params build_rsa_aes_key_unwrap_params(
    azihsm_algo_rsa_pkcs_oaep_params &oaep_params,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    azihsm_algo_rsa_aes_key_wrap_params unwrap_params{};
    unwrap_params.oaep_params = &oaep_params;

    if (key_kind == AZIHSM_KEY_KIND_AES_XTS)
    {
        // For AES_XTS, the unwrap params must specify 256 bits
        unwrap_params.aes_key_bits = 256;
    }
    else
    {
        unwrap_params.aes_key_bits = bits;
    }

    return unwrap_params;
}

// Helper to build RSA AES key unwrap algo struct
azihsm_algo build_rsa_aes_key_unwrap_algo(azihsm_algo_rsa_aes_key_wrap_params &unwrap_params)
{
    azihsm_algo algo{};
    algo.id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP;
    algo.params = &unwrap_params;
    algo.len = sizeof(unwrap_params);
    return algo;
}

// Helper function to wrap a local AES key using RSA AES Wrap algo
std::vector<uint8_t> wrap_local_aes_key(
    azihsm_handle wrapping_pub_key,
    const std::vector<uint8_t> &local_key,
    uint32_t aes_key_bits,
    azihsm_algo_rsa_pkcs_oaep_params &oaep_params
)
{
    azihsm_algo_rsa_aes_wrap_params wrap_params{};
    wrap_params.oaep_params = &oaep_params;
    wrap_params.aes_key_bits = aes_key_bits;

    azihsm_algo wrap_algo{};
    wrap_algo.id = AZIHSM_ALGO_ID_RSA_AES_WRAP;
    wrap_algo.params = &wrap_params;
    wrap_algo.len = sizeof(wrap_params);

    azihsm_buffer local_key_buf{};
    local_key_buf.ptr = const_cast<uint8_t *>(local_key.data());
    local_key_buf.len = static_cast<uint32_t>(local_key.size());

    azihsm_buffer wrapped_buf{};
    wrapped_buf.ptr = nullptr;
    wrapped_buf.len = 0;

    azihsm_status err =
        azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &local_key_buf, &wrapped_buf);
    EXPECT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    EXPECT_GT(wrapped_buf.len, 0);

    std::vector<uint8_t> wrapped_data(wrapped_buf.len);
    wrapped_buf.ptr = wrapped_data.data();

    err = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub_key, &local_key_buf, &wrapped_buf);
    EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);

    return wrapped_data;
}

// Helper function to verify properties of a generated AES key
void verify_generated_aes_key_properties(
    azihsm_handle key_handle,
    azihsm_key_kind key_kind,
    uint32_t bits,
    bool is_session,
    bool expected_local
)
{
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_CLASS, AZIHSM_KEY_CLASS_SECRET);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_KIND, key_kind);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_BIT_LEN, bits);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_LOCAL, expected_local);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_SESSION, is_session);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_SENSITIVE, true);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_EXTRACTABLE, true);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_ENCRYPT, true);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_DECRYPT, true);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_SIGN, false);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_VERIFY, false);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_WRAP, false);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_UNWRAP, false);
    verify_key_property(key_handle, AZIHSM_KEY_PROP_ID_DERIVE, false);
}

// Helper function to compare properties of two keys
void compare_key_properties(azihsm_handle key_handle1, azihsm_handle key_handle2)
{
    compare_key_property<uint32_t>(key_handle1, key_handle2, AZIHSM_KEY_PROP_ID_CLASS);
    compare_key_property<azihsm_key_kind>(key_handle1, key_handle2, AZIHSM_KEY_PROP_ID_KIND);
    compare_key_property<uint32_t>(key_handle1, key_handle2, AZIHSM_KEY_PROP_ID_BIT_LEN);
    compare_key_property<bool>(key_handle1, key_handle2, AZIHSM_KEY_PROP_ID_SESSION);
    compare_key_property<bool>(key_handle1, key_handle2, AZIHSM_KEY_PROP_ID_SENSITIVE);
    compare_key_property<bool>(key_handle1, key_handle2, AZIHSM_KEY_PROP_ID_EXTRACTABLE);
    compare_key_property<bool>(key_handle1, key_handle2, AZIHSM_KEY_PROP_ID_ENCRYPT);
    compare_key_property<bool>(key_handle1, key_handle2, AZIHSM_KEY_PROP_ID_DECRYPT);
    compare_key_property<bool>(key_handle1, key_handle2, AZIHSM_KEY_PROP_ID_SIGN);
    compare_key_property<bool>(key_handle1, key_handle2, AZIHSM_KEY_PROP_ID_VERIFY);
    compare_key_property<bool>(key_handle1, key_handle2, AZIHSM_KEY_PROP_ID_WRAP);
    compare_key_property<bool>(key_handle1, key_handle2, AZIHSM_KEY_PROP_ID_UNWRAP);
    compare_key_property<bool>(key_handle1, key_handle2, AZIHSM_KEY_PROP_ID_DERIVE);
}

// Common test function to test AES key generation and verify properties
void session_aes_key_generation_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    // Step 1: Generate AES key
    azihsm_algo keygen_algo{};
    keygen_algo.id = algo_id;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
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

    azihsm_key_prop_list prop_list{ .props = props_vec.data(),
                                    .count = static_cast<uint32_t>(props_vec.size()) };

    auto_key original_key;
    azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, original_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_key, 0);

    // Step 2: Verify key properties
    verify_generated_aes_key_properties(original_key, key_kind, bits, is_session, true);

    // Step 3: Delete the key
    err = azihsm_key_delete(original_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    original_key.release();
}

// Common test function to test AES key generation with invalid properties and expect failure
void aes_key_gen_invalid_props_fail_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits,
    std::vector<azihsm_key_prop_id> flag_prop_ids
)
{
    // Step 1: Attempt to generate invalid AES key
    azihsm_algo keygen_algo{};
    keygen_algo.id = algo_id;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
    bool is_session = true;

    std::vector<azihsm_key_prop> props_vec = {
        { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) },
        { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) },
        { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) },
        { .id = AZIHSM_KEY_PROP_ID_SESSION, .val = &is_session, .len = sizeof(is_session) }
    };

    // Add flag properties
    std::vector<uint8_t> flag_values(flag_prop_ids.size(), 1);
    for (size_t i = 0; i < flag_prop_ids.size(); i++)
    {
        props_vec.push_back(
            { .id = flag_prop_ids[i], .val = &flag_values[i], .len = sizeof(flag_values[i]) }
        );
    }

    azihsm_key_prop_list prop_list{ .props = props_vec.data(),
                                    .count = static_cast<uint32_t>(props_vec.size()) };

    auto_key original_key;
    azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, original_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
    ASSERT_EQ(original_key, 0);
}

// Common test function to test AES key generation with multiple invalid flag combinations and
// expect failure
void aes_key_gen_multiple_invalid_capabilities_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    bool invalid_flag_sets[16][5] = {
        { true, false, false, false, false }, // sign
        { false, true, false, false, false }, // verify
        { false, false, true, false, false }, // wrap
        { false, false, false, true, false }, // unwrap
        { false, false, false, false, true }, // derive
        { true, true, false, false, false },  // sign + verify
        { true, false, true, false, false },  // sign + wrap
        { true, false, false, true, false },  // sign + unwrap
        { true, false, false, false, true },  // sign + derive
        { false, true, true, false, false },  // verify + wrap
        { false, true, false, true, false },  // verify + unwrap
        { false, true, false, false, true },  // verify + derive
        { false, false, true, true, false },  // wrap + unwrap
        { false, false, true, false, true },  // wrap + derive
        { false, false, false, true, true },  // unwrap + derive
        { true, true, true, true, true },     // all invalid flags
    };

    for (bool *flag_set : invalid_flag_sets)
    {
        std::vector<azihsm_key_prop_id> invalid_props;
        invalid_props.push_back(AZIHSM_KEY_PROP_ID_ENCRYPT);
        invalid_props.push_back(AZIHSM_KEY_PROP_ID_DECRYPT);
        if (flag_set[0])
            invalid_props.push_back(AZIHSM_KEY_PROP_ID_SIGN);
        if (flag_set[1])
            invalid_props.push_back(AZIHSM_KEY_PROP_ID_VERIFY);
        if (flag_set[2])
            invalid_props.push_back(AZIHSM_KEY_PROP_ID_WRAP);
        if (flag_set[3])
            invalid_props.push_back(AZIHSM_KEY_PROP_ID_UNWRAP);
        if (flag_set[4])
            invalid_props.push_back(AZIHSM_KEY_PROP_ID_DERIVE);

        aes_key_gen_invalid_props_fail_common(session, algo_id, key_kind, bits, invalid_props);
    }
}

// Common test function to test persistent AES key generation and verify properties
void aes_key_gen_persistent_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    // Step 1: Generate AES key with non-session persistence
    azihsm_algo keygen_algo{};
    keygen_algo.id = algo_id;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
    bool is_session = false;
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

    azihsm_key_prop_list prop_list{ .props = props_vec.data(),
                                    .count = static_cast<uint32_t>(props_vec.size()) };

    auto_key original_key;
    azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, original_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_key, 0);

    // Step 2: Verify key has correct AZIHSM_KEY_PROP_ID_SESSION property
    verify_key_property(original_key, AZIHSM_KEY_PROP_ID_SESSION, false);

    // Step 3: Delete the key
    err = azihsm_key_delete(original_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    original_key.release();
}

// Common test function to test AES key unwrapping and verify properties of unwrapped key
void aes_key_unwrap_common(azihsm_handle session, azihsm_key_kind key_kind, uint32_t bits)
{
    // Step 1: Generate an RSA key pair for wrapping/unwrapping
    auto_key wrapping_priv_key;
    auto_key wrapping_pub_key;
    auto err = generate_rsa_unwrapping_keypair(
        session,
        wrapping_priv_key.get_ptr(),
        wrapping_pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(wrapping_priv_key.get(), 0);
    ASSERT_NE(wrapping_pub_key.get(), 0);

    azihsm_algo_rsa_pkcs_oaep_params oaep_params = build_oaep_sha256_params();

    // Step 2: Generate key material to wrap
    std::vector<uint8_t> wrapped_data;

    if (key_kind == AZIHSM_KEY_KIND_AES_XTS)
    {
        constexpr size_t key_bytes = 32;
        std::vector<uint8_t> key1_plain(key_bytes, 0x11);
        std::vector<uint8_t> key2_plain(key_bytes, 0x22);
        wrapped_data = build_xts_wrapped_blob(wrapping_pub_key, key1_plain, key2_plain);
    }
    else
    {
        std::vector<uint8_t> local_aes_key(bits / 8, 0x00);

        wrapped_data = wrap_local_aes_key(wrapping_pub_key, local_aes_key, bits, oaep_params);
    }

    ASSERT_FALSE(wrapped_data.empty());

    // Step 3: Unwrap the wrapped key material into a new key handle
    azihsm_algo_rsa_aes_key_wrap_params unwrap_params =
        build_rsa_aes_key_unwrap_params(oaep_params, key_kind, bits);

    azihsm_algo unwrap_algo = build_rsa_aes_key_unwrap_algo(unwrap_params);

    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
    bool can_encrypt = true;
    bool can_decrypt = true;

    std::vector<azihsm_key_prop> unwrap_props_vec;
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) });

    azihsm_key_prop_list unwrap_prop_list{ unwrap_props_vec.data(),
                                           static_cast<uint32_t>(unwrap_props_vec.size()) };

    azihsm_buffer wrapped_key_buf{};
    wrapped_key_buf.ptr = wrapped_data.data();
    wrapped_key_buf.len = static_cast<uint32_t>(wrapped_data.size());

    auto_key unwrapped_key;
    err = azihsm_key_unwrap(
        &unwrap_algo,
        wrapping_priv_key,
        &wrapped_key_buf,
        &unwrap_prop_list,
        unwrapped_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(unwrapped_key, 0);

    // Step 4: Verify unwrapped key properties
    verify_generated_aes_key_properties(unwrapped_key, key_kind, bits, false, false);

    // Step 5: Clean up unwrapped key
    err = azihsm_key_delete(unwrapped_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    unwrapped_key.release();

    // Step 6: Clean up wrapping keys
    err = azihsm_key_delete(wrapping_priv_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    wrapping_priv_key.release();

    err = azihsm_key_delete(wrapping_pub_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    wrapping_pub_key.release();
}

// Common test function to test AES key unmasking and verify properties of the unmasked key
void aes_key_unmask_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    // Step 1: Generate AES key
    azihsm_algo keygen_algo{};
    keygen_algo.id = algo_id;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
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

    azihsm_key_prop_list prop_list{ .props = props_vec.data(),
                                    .count = static_cast<uint32_t>(props_vec.size()) };

    auto_key original_key;
    azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, original_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_key, 0);

    // Step 2: Get masked key via property (probe-then-fetch)
    azihsm_key_prop masked_prop{};
    masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
    masked_prop.val = nullptr;
    masked_prop.len = 0;

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

    auto_key unmasked_key;
    err = azihsm_key_unmask(session, key_kind, &masked_key_buf, unmasked_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(unmasked_key, 0);

    // Step 4: Verify unmasked key properties match original key properties
    compare_key_properties(original_key, unmasked_key);

    // Step 5: Clean up keys
    err = azihsm_key_delete(unmasked_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    unmasked_key.release();

    err = azihsm_key_delete(original_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    original_key.release();
}

// Common test function to test AES key unmasking with wrong key kind and expect failure
void aes_unmask_wrong_kind_fails_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits,
    azihsm_key_kind wrong_kind
)
{
    // Generate a key
    azihsm_algo keygen_algo{};
    keygen_algo.id = algo_id;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
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

    azihsm_key_prop_list prop_list{ .props = props_vec.data(),
                                    .count = static_cast<uint32_t>(props_vec.size()) };

    auto_key original_key;
    azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, original_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_key, 0);

    // Get masked key blob
    azihsm_key_prop masked_prop{};
    masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
    masked_prop.val = nullptr;
    masked_prop.len = 0;

    err = azihsm_key_get_prop(original_key, &masked_prop);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    ASSERT_GT(masked_prop.len, 0);

    std::vector<uint8_t> masked_key_data(masked_prop.len);
    masked_prop.val = masked_key_data.data();

    err = azihsm_key_get_prop(original_key, &masked_prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    // Try to unmask with wrong key kind
    azihsm_buffer masked_key_buf{};
    masked_key_buf.ptr = masked_key_data.data();
    masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

    auto_key unmasked_key;
    err = azihsm_key_unmask(session, wrong_kind, &masked_key_buf, unmasked_key.get_ptr());
    ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(unmasked_key, 0);

    // Clean up
    err = azihsm_key_delete(original_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    original_key.release();
}

// Common test function to test AES key unmasking with corrupted masked blob and expect failure
void aes_unmask_corrupted_blob_fails_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    // Generate a key
    azihsm_algo keygen_algo{};
    keygen_algo.id = algo_id;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
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

    azihsm_key_prop_list prop_list{ .props = props_vec.data(),
                                    .count = static_cast<uint32_t>(props_vec.size()) };

    auto_key original_key;
    azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, original_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_key, 0);

    // Get masked key blob
    azihsm_key_prop masked_prop{};
    masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
    masked_prop.val = nullptr;
    masked_prop.len = 0;

    err = azihsm_key_get_prop(original_key, &masked_prop);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    ASSERT_GT(masked_prop.len, 0);

    std::vector<uint8_t> masked_key_data(masked_prop.len);
    masked_prop.val = masked_key_data.data();

    err = azihsm_key_get_prop(original_key, &masked_prop);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    // Corrupt the masked key blob
    masked_key_data[0] ^= 0xFF;

    // Try to unmask the corrupted blob
    azihsm_buffer masked_key_buf{};
    masked_key_buf.ptr = masked_key_data.data();
    masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

    auto_key unmasked_key;
    err = azihsm_key_unmask(session, key_kind, &masked_key_buf, unmasked_key.get_ptr());
    ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(unmasked_key, 0);

    // Clean up
    err = azihsm_key_delete(original_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    original_key.release();
}

// Common test function to test AES key unwrapping with corrupted wrapped blob and expect failure
void aes_key_unwrap_corrupted_fails_common(
    azihsm_handle session,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    // Step 1: Generate an RSA key pair for wrapping/unwrapping
    auto_key wrapping_priv_key;
    auto_key wrapping_pub_key;
    auto err = generate_rsa_unwrapping_keypair(
        session,
        wrapping_priv_key.get_ptr(),
        wrapping_pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(wrapping_priv_key.get(), 0);
    ASSERT_NE(wrapping_pub_key.get(), 0);

    azihsm_algo_rsa_pkcs_oaep_params oaep_params = build_oaep_sha256_params();

    std::vector<uint8_t> wrapped_data;

    if (key_kind == AZIHSM_KEY_KIND_AES_XTS)
    {
        constexpr size_t key_bytes = 32;
        std::vector<uint8_t> key1_plain(key_bytes, 0x11);
        std::vector<uint8_t> key2_plain(key_bytes, 0x22);
        wrapped_data = build_xts_wrapped_blob(wrapping_pub_key, key1_plain, key2_plain);
    }
    else if (key_kind == AZIHSM_KEY_KIND_AES_GCM)
    {
        std::vector<uint8_t> local_aes_gcm_key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                                   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                                   0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

        wrapped_data = wrap_local_aes_key(wrapping_pub_key, local_aes_gcm_key, bits, oaep_params);
    }
    else
    {
        std::vector<uint8_t> local_aes_key(32, 0x55);

        wrapped_data = wrap_local_aes_key(wrapping_pub_key, local_aes_key, bits, oaep_params);
    }

    ASSERT_FALSE(wrapped_data.empty());

    // Corrupt wrapped data (corrupts header in case of XTS)
    wrapped_data[0] ^= 0xFF;

    azihsm_algo_rsa_aes_key_wrap_params unwrap_params =
        build_rsa_aes_key_unwrap_params(oaep_params, key_kind, bits);

    azihsm_algo unwrap_algo = build_rsa_aes_key_unwrap_algo(unwrap_params);

    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
    bool can_encrypt = true;
    bool can_decrypt = true;

    std::vector<azihsm_key_prop> unwrap_props_vec;
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) });

    azihsm_key_prop_list unwrap_prop_list{ unwrap_props_vec.data(),
                                           static_cast<uint32_t>(unwrap_props_vec.size()) };

    azihsm_buffer wrapped_key_buf{};
    wrapped_key_buf.ptr = wrapped_data.data();
    wrapped_key_buf.len = static_cast<uint32_t>(wrapped_data.size());

    auto_key unwrapped_key;
    err = azihsm_key_unwrap(
        &unwrap_algo,
        wrapping_priv_key,
        &wrapped_key_buf,
        &unwrap_prop_list,
        unwrapped_key.get_ptr()
    );
    ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(unwrapped_key, 0);

    // Clean up
    err = azihsm_key_delete(wrapping_priv_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    wrapping_priv_key.release();

    err = azihsm_key_delete(wrapping_pub_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    wrapping_pub_key.release();
}

// Common test function to test AES key unwrapping with wrong algorithm parameters and expect
// failure
void aes_unwrap_wrong_algo_fails_common(
    azihsm_handle session,
    azihsm_key_kind key_kind,
    uint32_t bits,
    azihsm_algo_id wrong_algo_id
)
{
    auto_key wrapping_priv_key;
    auto_key wrapping_pub_key;
    auto err = generate_rsa_unwrapping_keypair(
        session,
        wrapping_priv_key.get_ptr(),
        wrapping_pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(wrapping_priv_key.get(), 0);
    ASSERT_NE(wrapping_pub_key.get(), 0);

    azihsm_algo_rsa_pkcs_oaep_params oaep_params = build_oaep_sha256_params();

    std::vector<uint8_t> wrapped_data;

    if (key_kind == AZIHSM_KEY_KIND_AES_XTS)
    {
        constexpr size_t key_bytes = 32;
        std::vector<uint8_t> key1_plain(key_bytes, 0x11);
        std::vector<uint8_t> key2_plain(key_bytes, 0x22);
        wrapped_data = build_xts_wrapped_blob(wrapping_pub_key, key1_plain, key2_plain);
    }
    else
    {
        std::vector<uint8_t> local_aes_key(32, 0x11);

        wrapped_data = wrap_local_aes_key(wrapping_pub_key, local_aes_key, bits, oaep_params);
    }

    ASSERT_FALSE(wrapped_data.empty());

    azihsm_algo wrong_algo{};
    wrong_algo.id = wrong_algo_id;
    wrong_algo.params = nullptr;
    wrong_algo.len = 0;

    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
    bool can_encrypt = true;
    bool can_decrypt = true;

    std::vector<azihsm_key_prop> unwrap_props_vec;
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) });

    azihsm_key_prop_list unwrap_prop_list{ unwrap_props_vec.data(),
                                           static_cast<uint32_t>(unwrap_props_vec.size()) };

    azihsm_buffer wrapped_key_buf{};
    wrapped_key_buf.ptr = wrapped_data.data();
    wrapped_key_buf.len = static_cast<uint32_t>(wrapped_data.size());

    auto_key unwrapped_key;
    err = azihsm_key_unwrap(
        &wrong_algo,
        wrapping_priv_key,
        &wrapped_key_buf,
        &unwrap_prop_list,
        unwrapped_key.get_ptr()
    );
    ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(unwrapped_key, 0);

    // Clean up
    err = azihsm_key_delete(wrapping_priv_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    wrapping_priv_key.release();

    err = azihsm_key_delete(wrapping_pub_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    wrapping_pub_key.release();
}

// Common test function to test unmasked key is functional and independent of the original key
void aes_unmasked_key_independent_handle_common(
    azihsm_handle session,
    azihsm_algo_id algo_id,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    // Step 1: Generate key
    azihsm_algo keygen_algo{};
    keygen_algo.id = algo_id;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
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

    azihsm_key_prop_list prop_list{ props_vec.data(), static_cast<uint32_t>(props_vec.size()) };

    auto_key original_key;
    azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, original_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(original_key, 0);

    // Step 2: Get masked key via property
    azihsm_key_prop masked_prop{};
    masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
    masked_prop.val = nullptr;
    masked_prop.len = 0;

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

    auto_key unmasked_key;
    err = azihsm_key_unmask(session, key_kind, &masked_key_buf, unmasked_key.get_ptr());
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(unmasked_key, 0);

    // Step 4: Delete the original key before using the unmasked key
    // to prove the unmasked key is independent
    err = azihsm_key_delete(original_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    original_key.release();

    // Step 5: Encrypt with the unmasked key using AES-CBC with padding
    std::vector<uint8_t> plaintext(128, 0x11);
    std::vector<uint8_t> iv;
    azihsm_algo_aes_xts_params xts_params{};
    azihsm_algo_aes_cbc_params cbc_params{};
    azihsm_algo_aes_gcm_params gcm_params{};
    azihsm_algo enc_algo{};

    if (key_kind == AZIHSM_KEY_KIND_AES_XTS)
    {
        // Encrypt with AES-XTS (tweak is all zero)
        constexpr size_t dul = 64;
        ASSERT_EQ(plaintext.size(), dul * 2);

        uint8_t tweak[16] = { 0 };

        // One-shot encrypt of 2 data units.
        std::memcpy(xts_params.sector_num, tweak, 16);
        xts_params.data_unit_length = static_cast<uint32_t>(dul); // per-data-unit length (DUL)

        enc_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        enc_algo.params = &xts_params;
        enc_algo.len = sizeof(xts_params);
    }
    else if (key_kind == AZIHSM_KEY_KIND_AES)
    {
        // Encrypt with AES-CBC with padding
        iv = std::vector<uint8_t>(16, 0);
        std::memcpy(cbc_params.iv, iv.data(), iv.size());

        enc_algo.id = AZIHSM_ALGO_ID_AES_CBC_PAD;
        enc_algo.params = &cbc_params;
        enc_algo.len = sizeof(cbc_params);
    }
    else if (key_kind == AZIHSM_KEY_KIND_AES_GCM)
    {
        // Configure AES-GCM encryption parameters (IV and tag)
        iv = std::vector<uint8_t>(12, 0xA1);
        std::memcpy(gcm_params.iv, iv.data(), iv.size());
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        enc_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        enc_algo.params = &gcm_params;
        enc_algo.len = sizeof(gcm_params);
    }
    else
    {
        FAIL() << "Unsupported key kind";
    }

    azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
    azihsm_buffer output{ nullptr, 0 };

    // Query required output buffer size
    err = azihsm_crypt_encrypt(&enc_algo, unmasked_key, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    ASSERT_GT(output.len, 0);

    // Perform encryption
    std::vector<uint8_t> ciphertext(output.len);
    output.ptr = ciphertext.data();
    err = azihsm_crypt_encrypt(&enc_algo, unmasked_key, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    // Clean up
    err = azihsm_key_delete(unmasked_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    unmasked_key.release();
}

// Common test function to test AES key unwrapping with truncated wrapped blob and expect failure
void aes_unwrap_truncated_blob_fails_common(
    azihsm_handle session,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    auto_key wrapping_priv_key;
    auto_key wrapping_pub_key;
    auto err = generate_rsa_unwrapping_keypair(
        session,
        wrapping_priv_key.get_ptr(),
        wrapping_pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(wrapping_priv_key.get(), 0);
    ASSERT_NE(wrapping_pub_key.get(), 0);

    azihsm_algo_rsa_pkcs_oaep_params oaep_params = build_oaep_sha256_params();

    std::vector<uint8_t> wrapped_data;

    if (key_kind == AZIHSM_KEY_KIND_AES_XTS)
    {
        constexpr size_t key_bytes = 32;
        std::vector<uint8_t> key1_plain(key_bytes, 0x11);
        std::vector<uint8_t> key2_plain(key_bytes, 0x22);
        wrapped_data = build_xts_wrapped_blob(wrapping_pub_key, key1_plain, key2_plain);
    }
    else
    {
        std::vector<uint8_t> local_aes_key(32, 0x11);

        wrapped_data = wrap_local_aes_key(wrapping_pub_key, local_aes_key, bits, oaep_params);
    }

    ASSERT_FALSE(wrapped_data.empty());

    // Truncate the wrapped blob
    wrapped_data.resize(wrapped_data.size() - 8);

    azihsm_algo_rsa_aes_key_wrap_params unwrap_params =
        build_rsa_aes_key_unwrap_params(oaep_params, key_kind, bits);

    azihsm_algo unwrap_algo = build_rsa_aes_key_unwrap_algo(unwrap_params);

    azihsm_key_class aes_class = AZIHSM_KEY_CLASS_SECRET;
    bool can_encrypt = true;
    bool can_decrypt = true;

    std::vector<azihsm_key_prop> unwrap_props_vec;
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &aes_class, sizeof(aes_class) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) });

    azihsm_key_prop_list unwrap_prop_list{ unwrap_props_vec.data(),
                                           static_cast<uint32_t>(unwrap_props_vec.size()) };

    azihsm_buffer wrapped_key_buf{};
    wrapped_key_buf.ptr = wrapped_data.data();
    wrapped_key_buf.len = static_cast<uint32_t>(wrapped_data.size());

    auto_key unwrapped_key;
    err = azihsm_key_unwrap(
        &unwrap_algo,
        wrapping_priv_key,
        &wrapped_key_buf,
        &unwrap_prop_list,
        unwrapped_key.get_ptr()
    );
    ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(unwrapped_key, 0);

    // Clean up
    err = azihsm_key_delete(wrapping_priv_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    wrapping_priv_key.release();

    err = azihsm_key_delete(wrapping_pub_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    wrapping_pub_key.release();
}

// Common test function to test AES key unwrapping with mismatched bit length and expect failure
void aes_unwrap_bits_mismatch_fails_common(
    azihsm_handle session,
    azihsm_key_kind key_kind,
    uint32_t bits,
    uint32_t wrong_bits
)
{
    auto_key wrapping_priv_key;
    auto_key wrapping_pub_key;
    auto err = generate_rsa_unwrapping_keypair(
        session,
        wrapping_priv_key.get_ptr(),
        wrapping_pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(wrapping_priv_key.get(), 0);
    ASSERT_NE(wrapping_pub_key.get(), 0);

    azihsm_algo_rsa_pkcs_oaep_params oaep_params = build_oaep_sha256_params();

    std::vector<uint8_t> wrapped_data;

    if (key_kind == AZIHSM_KEY_KIND_AES_XTS)
    {
        constexpr size_t key_bytes = 32;
        std::vector<uint8_t> key1_plain(key_bytes, 0x11);
        std::vector<uint8_t> key2_plain(key_bytes, 0x22);
        wrapped_data = build_xts_wrapped_blob(wrapping_pub_key, key1_plain, key2_plain);
    }
    else
    {
        std::vector<uint8_t> local_aes_key(32, 0x11);

        wrapped_data = wrap_local_aes_key(wrapping_pub_key, local_aes_key, bits, oaep_params);
    }

    ASSERT_FALSE(wrapped_data.empty());

    // Unwrap with mismatched bit length (wrong size in unwrapped key properties)
    azihsm_algo_rsa_aes_key_wrap_params unwrap_params =
        build_rsa_aes_key_unwrap_params(oaep_params, key_kind, bits);

    azihsm_algo unwrap_algo = build_rsa_aes_key_unwrap_algo(unwrap_params);

    azihsm_key_class aes_class = AZIHSM_KEY_CLASS_SECRET;
    bool can_encrypt = true;
    bool can_decrypt = true;

    std::vector<azihsm_key_prop> unwrap_props_vec;
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &aes_class, sizeof(aes_class) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &wrong_bits, sizeof(wrong_bits) }
    ); // wrong size
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) });

    azihsm_key_prop_list unwrap_prop_list{ unwrap_props_vec.data(),
                                           static_cast<uint32_t>(unwrap_props_vec.size()) };

    azihsm_buffer wrapped_key_buf{};
    wrapped_key_buf.ptr = wrapped_data.data();
    wrapped_key_buf.len = static_cast<uint32_t>(wrapped_data.size());

    auto_key unwrapped_key;
    err = azihsm_key_unwrap(
        &unwrap_algo,
        wrapping_priv_key,
        &wrapped_key_buf,
        &unwrap_prop_list,
        unwrapped_key.get_ptr()
    );
    ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(unwrapped_key, 0);

    // Clean up
    err = azihsm_key_delete(wrapping_priv_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    wrapping_priv_key.release();

    err = azihsm_key_delete(wrapping_pub_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    wrapping_pub_key.release();
}

// Common test function to test AES key unwrapping with correct parameters and verify the unwrapped
// key is functional
void aes_unwrapped_key_roundtrip_common(
    azihsm_handle session,
    azihsm_key_kind key_kind,
    uint32_t bits
)
{
    auto_key wrapping_priv_key;
    auto_key wrapping_pub_key;
    auto err = generate_rsa_unwrapping_keypair(
        session,
        wrapping_priv_key.get_ptr(),
        wrapping_pub_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(wrapping_priv_key.get(), 0);
    ASSERT_NE(wrapping_pub_key.get(), 0);

    // Configure OAEP parameters and wrap the local key
    azihsm_algo_rsa_pkcs_oaep_params oaep_params = build_oaep_sha256_params();

    std::vector<uint8_t> wrapped_data;

    if (key_kind == AZIHSM_KEY_KIND_AES_XTS)
    {
        constexpr size_t key_bytes = 32;
        std::vector<uint8_t> key1_plain(key_bytes, 0x11);
        std::vector<uint8_t> key2_plain(key_bytes, 0x22);
        wrapped_data = build_xts_wrapped_blob(wrapping_pub_key, key1_plain, key2_plain);
    }
    else
    {
        std::vector<uint8_t> local_aes_key;

        if (key_kind == AZIHSM_KEY_KIND_AES_GCM)
        {
            // Create a local AES-GCM-256 key (32 bytes) to be imported into the HSM
            local_aes_key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                              0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                              0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
        }
        else
        {
            local_aes_key = std::vector<uint8_t>(32, 0x11);
        }

        wrapped_data = wrap_local_aes_key(wrapping_pub_key, local_aes_key, bits, oaep_params);
    }

    ASSERT_FALSE(wrapped_data.empty());

    // Unwrap the key into the HSM
    azihsm_algo_rsa_aes_key_wrap_params unwrap_params =
        build_rsa_aes_key_unwrap_params(oaep_params, key_kind, bits);

    azihsm_algo unwrap_algo = build_rsa_aes_key_unwrap_algo(unwrap_params);

    azihsm_key_class aes_class = AZIHSM_KEY_CLASS_SECRET;
    bool aes_is_session = true;
    bool can_encrypt = true;
    bool can_decrypt = true;

    std::vector<azihsm_key_prop> unwrap_props_vec;
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &aes_class, sizeof(aes_class) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) });
    unwrap_props_vec.push_back(
        { AZIHSM_KEY_PROP_ID_SESSION, &aes_is_session, sizeof(aes_is_session) }
    );
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) });
    unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) });

    azihsm_key_prop_list unwrap_prop_list{ unwrap_props_vec.data(),
                                           static_cast<uint32_t>(unwrap_props_vec.size()) };

    azihsm_buffer wrapped_key_buf{};
    wrapped_key_buf.ptr = wrapped_data.data();
    wrapped_key_buf.len = static_cast<uint32_t>(wrapped_data.size());

    auto_key aes_key;
    err = azihsm_key_unwrap(
        &unwrap_algo,
        wrapping_priv_key,
        &wrapped_key_buf,
        &unwrap_prop_list,
        aes_key.get_ptr()
    );
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ASSERT_NE(aes_key, 0);

    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> iv;
    azihsm_algo_aes_xts_params xts_params{};
    azihsm_algo_aes_cbc_params cbc_params{};
    azihsm_algo_aes_gcm_params gcm_params{};
    azihsm_algo enc_algo{};

    if (key_kind == AZIHSM_KEY_KIND_AES_XTS)
    {
        // Encrypt with AES-XTS (tweak is all zero)
        constexpr size_t dul = 64;
        plaintext.insert(plaintext.begin(), 128, 0x11);
        ASSERT_EQ(plaintext.size(), dul * 2);

        uint8_t tweak[16] = { 0 };

        // One-shot encrypt of 2 data units.
        std::memcpy(xts_params.sector_num, tweak, 16);
        xts_params.data_unit_length = static_cast<uint32_t>(dul); // per-data-unit length (DUL)

        enc_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        enc_algo.params = &xts_params;
        enc_algo.len = sizeof(xts_params);
    }
    else if (key_kind == AZIHSM_KEY_KIND_AES)
    {
        // Encrypt with AES-CBC with padding
        plaintext = { 'h', 'e', 'l', 'l', 'o', ' ', 'a', 'e', 's', ' ', 'c', 'b', 'c' };

        iv = std::vector<uint8_t>(16, 0);
        std::memcpy(cbc_params.iv, iv.data(), iv.size());

        enc_algo.id = AZIHSM_ALGO_ID_AES_CBC_PAD;
        enc_algo.params = &cbc_params;
        enc_algo.len = sizeof(cbc_params);
    }
    else if (key_kind == AZIHSM_KEY_KIND_AES_GCM)
    {
        // Prepare plaintext for encryption test
        plaintext.insert(plaintext.begin(), 64, 0x5A);

        // Configure AES-GCM encryption parameters (IV and tag)
        iv = std::vector<uint8_t>(12, 0xA1);
        std::memcpy(gcm_params.iv, iv.data(), iv.size());
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        enc_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        enc_algo.params = &gcm_params;
        enc_algo.len = sizeof(gcm_params);
    }
    else
    {
        FAIL() << "Unsupported key kind";
    }

    azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
    azihsm_buffer output{ nullptr, 0 };

    // Query required output buffer size
    err = azihsm_crypt_encrypt(&enc_algo, aes_key, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    ASSERT_GT(output.len, 0);

    // Perform encryption
    std::vector<uint8_t> ciphertext(output.len);
    output.ptr = ciphertext.data();
    err = azihsm_crypt_encrypt(&enc_algo, aes_key, &input, &output);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    ciphertext.resize(output.len);

    azihsm_algo_aes_cbc_params dec_cbc_params{};
    azihsm_algo dec_algo{};

    if (key_kind == AZIHSM_KEY_KIND_AES_XTS)
    {
        constexpr size_t dul = 64;
        uint8_t tweak[16] = { 0 };

        std::memcpy(xts_params.sector_num, tweak, 16);
        xts_params.data_unit_length = static_cast<uint32_t>(dul);

        // Decrypt with AES-XTS (tweak is all zero)
        dec_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        dec_algo.params = &xts_params;
        dec_algo.len = sizeof(xts_params);
    }
    else if (key_kind == AZIHSM_KEY_KIND_AES)
    {
        // Decrypt with AES-CBC with padding (reset IV)
        std::memcpy(dec_cbc_params.iv, iv.data(), iv.size());

        dec_algo.id = AZIHSM_ALGO_ID_AES_CBC_PAD;
        dec_algo.params = &dec_cbc_params;
        dec_algo.len = sizeof(dec_cbc_params);
    }
    else if (key_kind == AZIHSM_KEY_KIND_AES_GCM)
    {
        // Save the authentication tag generated during encryption
        uint8_t saved_tag[16];
        std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));

        // Reset GCM parameters with same IV and authentication tag for decryption
        std::memcpy(gcm_params.iv, iv.data(), iv.size());
        std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

        dec_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        dec_algo.params = &gcm_params;
        dec_algo.len = sizeof(gcm_params);
    }
    else
    {
        FAIL() << "Unsupported key kind";
    }

    azihsm_buffer cipher_buf{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
    azihsm_buffer plain_buf{ nullptr, 0 };

    // Query required output buffer size
    err = azihsm_crypt_decrypt(&dec_algo, aes_key, &cipher_buf, &plain_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
    ASSERT_GT(plain_buf.len, 0);

    // Perform decryption
    std::vector<uint8_t> decrypted(plain_buf.len);
    plain_buf.ptr = decrypted.data();
    err = azihsm_crypt_decrypt(&dec_algo, aes_key, &cipher_buf, &plain_buf);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    decrypted.resize(plain_buf.len);

    // Verify roundtrip
    ASSERT_EQ(decrypted.size(), plaintext.size());
    ASSERT_EQ(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()), 0);

    // Clean up
    err = azihsm_key_delete(wrapping_priv_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    wrapping_priv_key.release();

    err = azihsm_key_delete(wrapping_pub_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    wrapping_pub_key.release();

    err = azihsm_key_delete(aes_key);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
    aes_key.release();
}
