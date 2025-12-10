// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <vector>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include "helpers.h"

static std::once_flag partition_init_flag;

std::vector<AzihsmCharType> get_partition_path(azihsm_handle handle, uint32_t part_index) {
    AzihsmStr path = {nullptr, 0};
    auto      err  = azihsm_part_get_path(handle, part_index, &path);
    EXPECT_EQ(err, AZIHSM_ERROR_INSUFFICIENT_BUFFER);
    EXPECT_NE(path.len, 0);

    std::vector<AzihsmCharType> buffer(path.len);
    path.str = &buffer[0];
    err      = azihsm_part_get_path(handle, part_index, &path);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);

    return std::move(buffer);
}

std::pair<azihsm_handle, std::vector<AzihsmCharType> > open_partition(uint32_t part_index) {
    azihsm_handle list_handle = 0;
    auto          err         = azihsm_part_get_list(&list_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(list_handle, 0);

    auto list_guard = scope_guard::make_scope_exit(
        [list_handle]() { EXPECT_EQ(azihsm_part_free_list(list_handle), AZIHSM_ERROR_SUCCESS); });

    std::vector<AzihsmCharType> path_vec = get_partition_path(list_handle, part_index);

    azihsm_handle part_handle = 0;
    AzihsmStr     path        = {path_vec.data(), static_cast<uint32_t>(path_vec.size())};
    err                       = azihsm_part_open(&path, &part_handle);
    EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    EXPECT_NE(part_handle, 0);

    std::call_once(partition_init_flag, [part_handle, &err]() {
        azihsm_app_creds creds;
        memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));
        err = azihsm_part_init(part_handle, &creds);
        EXPECT_EQ(err, AZIHSM_ERROR_SUCCESS);
    });

    return {part_handle, std::move(path_vec)};
}

std::vector<AzihsmCharType> create_azihsm_str(const char *str) {
    size_t                      len = strlen(str) + 1;
    std::vector<AzihsmCharType> result(len);

    // Convert char to AzihsmCharType (handles both u8 and u16)
    for (size_t i = 0; i < len; ++i)
    {
        result[i] = static_cast<AzihsmCharType>(str[i]);
    }

    return result;
}

// Helper function to open a session
std::pair<azihsm_handle, azihsm_handle> open_session() {
    auto [part_handle, path] = open_partition();

    azihsm_handle  session_handle = 0;
    azihsm_api_rev api_rev;
    api_rev.major = 1;
    api_rev.minor = 0;

    azihsm_app_creds creds;
    memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
    memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

    auto err = azihsm_sess_open(part_handle, AZIHSM_SESS_TYPE_CLEAR, &api_rev, &creds, &session_handle);
    if (err != AZIHSM_ERROR_SUCCESS)
    {
        azihsm_part_close(part_handle);
        return {0, 0};
    }

    return {part_handle, session_handle};
}

// RSA Key Wrapping Helper Implementation
azihsm_error rsa_wrap_data_helper(azihsm_handle session_handle, azihsm_handle pub_key_handle, const uint8_t *user_data,
                                  uint32_t user_data_len, uint32_t aes_key_bits, uint8_t *wrapped_data,
                                  uint32_t *wrapped_data_len) {
    //check if we got any null pointers
    if (wrapped_data_len == nullptr)
    {
        return AZIHSM_ERROR_INVALID_ARGUMENT;
    }
    // Set up the RSA AES Key Wrap algorithm
    struct azihsm_buffer label = {
        .buf = NULL,
        .len = 0,
    };

    struct azihsm_algo_rsa_pkcs_oaep_params oaep_params = {
        .hash_algo_id      = AZIHSM_ALGO_ID_SHA256,
        .mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256,
        .label             = &label,
    };

    struct azihsm_algo_rsa_aes_key_wrap_params wrap_params = {
        .aes_key_bits = aes_key_bits,
        .key_type     = AZIHSM_KEY_TYPE_AES,
        .oaep_params  = &oaep_params,
    };

    struct azihsm_algo wrap_algo = {
        .id     = AZIHSM_ALGO_ID_RSA_AES_KEYWRAP,
        .params = &wrap_params,
        .len    = sizeof(struct azihsm_algo_rsa_aes_key_wrap_params),
    };

    // Set up user data buffer
    struct azihsm_buffer user_data_buffer = {.buf = const_cast<uint8_t *>(user_data), .len = user_data_len};

    // Set up wrapped data buffer
    struct azihsm_buffer wrapped_data_buffer = {.buf = wrapped_data, .len = *wrapped_data_len};

    // Call the azihsm_key_wrap function
    auto err = azihsm_key_wrap(session_handle, &wrap_algo, pub_key_handle, &user_data_buffer, &wrapped_data_buffer);

    // Update the wrapped data length
    *wrapped_data_len = wrapped_data_buffer.len;

    return err;
}


/*
*  Helper function to generate EC key pair with DERIVE capability
*  @param pub_key_handle - Output handle for public key
*  @param priv_key_handle - Output handle for private key
*  @param curve - EC curve to use (AZIHSM_EC_CURVE_ID_P256, P384, or P521)
*/

azihsm_error generate_ec_key_pair_for_derive(azihsm_handle session_handle, azihsm_handle &pub_key_handle, azihsm_handle &priv_key_handle,
                                             azihsm_ec_curve_id curve) {
    azihsm_algo ec_keygen_algo = {.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN, .params = nullptr, .len = 0};
    bool        derive_prop    = true;

    azihsm_key_prop      pub_props[]    = {{.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve, .len = sizeof(curve)}};
    azihsm_key_prop      priv_props[]   = {{.id = AZIHSM_KEY_PROP_ID_EC_CURVE, .val = &curve, .len = sizeof(curve)},
                                           {.id = AZIHSM_KEY_PROP_ID_DERIVE, .val = &derive_prop, .len = sizeof(derive_prop)}};
    azihsm_key_prop_list pub_prop_list  = {.props = pub_props, .count = 1};
    azihsm_key_prop_list priv_prop_list = {.props = priv_props, .count = 2};

    return azihsm_key_gen_pair(
        session_handle, &ec_keygen_algo, &pub_prop_list, &priv_prop_list, &pub_key_handle, &priv_key_handle);
}

/**
*  Helper function to derive HMAC key using ECDH + HKDF
*  @param server_priv_key - Server's private EC key for ECDH
*  @param client_pub_key - Client's public EC key for ECDH
*  @param hmac_key_type - Type of HMAC key to derive (SHA256/384/512)
*  @param hmac_key_handle - Output handle for derived HMAC key
*  @param base_secret_handle - Optional output handle for intermediate base secret (for debugging)
*  @return AZIHSM_ERROR_SUCCESS on success, error code otherwise
*/
azihsm_error derive_hmac_key_via_ecdh_hkdf(azihsm_handle session_handle, azihsm_handle server_priv_key, azihsm_handle client_pub_key,
                                           azihsm_key_type hmac_key_type, azihsm_handle &hmac_key_handle,
                                           azihsm_handle *base_secret_handle) {
    azihsm_error err;

    // Step 1: Get client's public key in DER format for ECDH
    std::vector<uint8_t> client_pub_key_data(256);
    uint32_t             client_pub_key_len = static_cast<uint32_t>(client_pub_key_data.size());

    azihsm_buffer pub_key_buffer = {.buf = client_pub_key_data.data(), .len = client_pub_key_len};

    azihsm_key_prop pub_key_prop = {.id  = AZIHSM_KEY_PROP_ID_PUB_KEY_INFO,
                                    .val = client_pub_key_data.data(),
                                    .len = client_pub_key_len};

    err = azihsm_key_get_prop(session_handle, client_pub_key, &pub_key_prop);
    if (err != AZIHSM_ERROR_SUCCESS)
    {
        return err;
    }

    // Update the actual length returned
    client_pub_key_len = pub_key_prop.len;
    pub_key_buffer.len = client_pub_key_len;

    // Step 2: Perform ECDH derivation to get base secret
    struct
    {
        const azihsm_buffer *pub_key;
    } ecdh_params         = {.pub_key = &pub_key_buffer};
    azihsm_algo ecdh_algo = {.id = AZIHSM_ALGO_ID_ECDH, .params = &ecdh_params, .len = sizeof(ecdh_params)};

    // Properties for the secret key from ECDH

    azihsm_handle   temp_base_secret    = 0;
    bool            ecdh_derive_prop    = true;
    azihsm_key_prop base_secret_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_DERIVE, .val = &ecdh_derive_prop, .len = sizeof(ecdh_derive_prop)}};
    azihsm_key_prop_list base_secret_prop_list = {.props = base_secret_props, .count = 1};

    err = azihsm_key_derive(session_handle, &ecdh_algo, server_priv_key, &base_secret_prop_list, &temp_base_secret);
    if (err != AZIHSM_ERROR_SUCCESS)
    {
        return err;
    }

    // Save base secret handle if requested
    if (base_secret_handle != nullptr)
    {
        *base_secret_handle = temp_base_secret;
    }

    // Step 3: Use HKDF to derive HMAC key from base secret
    const char *salt = "test-salt-hmac-key";
    const char *info = "test-info-hmac-key";

    azihsm_buffer salt_buf = {.buf = (uint8_t *) salt, .len = static_cast<uint32_t>(strlen(salt))};
    azihsm_buffer info_buf = {.buf = (uint8_t *) info, .len = static_cast<uint32_t>(strlen(info))};

    azihsm_algo_hkdf_params hkdf_params = {.hmac_algo_id = AZIHSM_ALGO_ID_HMAC_SHA256,
                                           .salt         = &salt_buf,
                                           .info         = &info_buf};

    azihsm_algo hkdf_algo = {.id = AZIHSM_ALGO_ID_HKDF_DERIVE, .params = &hkdf_params, .len = sizeof(hkdf_params)};

    bool            hmac_sign_prop   = true;
    bool            hmac_verify_prop = true;
    azihsm_key_type hmac_kind        = AZIHSM_KEY_TYPE_HMAC_SHA256;
    azihsm_key_prop hmac_key_props[] = {
        {.id = AZIHSM_KEY_PROP_ID_KIND, .val = &hmac_kind, .len = sizeof(hmac_kind)},
        {.id = AZIHSM_KEY_PROP_ID_SIGN, .val = &hmac_sign_prop, .len = sizeof(hmac_sign_prop)},
        {.id = AZIHSM_KEY_PROP_ID_VERIFY, .val = &hmac_verify_prop, .len = sizeof(hmac_verify_prop)}};
    azihsm_key_prop_list hmac_key_prop_list = {.props = hmac_key_props, .count = 3};

    err = azihsm_key_derive(session_handle, &hkdf_algo, temp_base_secret, &hmac_key_prop_list, &hmac_key_handle);

    // Clean up base secret if not requested to be saved
    if (base_secret_handle == nullptr && temp_base_secret != 0)
    {
        azihsm_key_delete(session_handle, temp_base_secret);
    }

    return err;
}