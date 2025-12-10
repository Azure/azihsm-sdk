// Copyright (C) Microsoft Corporation. All rights reserved.

#include <azihsm.h>
#include <stdint.h>
#include <vector>

// Platform-specific character type alias
#if defined(_WIN32)
using AzihsmCharType = AzihsmWideChar;
#else
using AzihsmCharType = AzihsmChar;
#endif

extern uint8_t TEST_CRED_ID[16];

extern uint8_t TEST_CRED_PIN[16];

std::vector<AzihsmCharType>                            get_partition_path(azihsm_handle handle, uint32_t part_index);
std::pair<azihsm_handle, std::vector<AzihsmCharType> > open_partition(uint32_t part_index = 0);
std::vector<AzihsmCharType>                            create_azihsm_str(const char *str);
std::pair<azihsm_handle, azihsm_handle>                open_session();

// RSA Key Wrapping Helper Functions

/**
 * Helper function to wrap data using RSA + AES key wrapping
 * @param session_handle Active session handle
 * @param pub_key_handle RSA public key handle for wrapping
 * @param user_data Data to wrap
 * @param user_data_len Length of user data
 * @param aes_key_bits AES key size in bits (128, 192, or 256)
 * @param wrapped_data Output buffer for wrapped data (caller allocates)
 * @param wrapped_data_len Input/output parameter for wrapped data buffer size
 * @return AZIHSM_ERROR_SUCCESS on success, error code on failure
 * 
 * Example usage:
 *   // 1. Generate RSA key pair with wrap/unwrap capabilities
 *   // 2. Prepare data to wrap
 *   uint8_t test_data[] = {0x01, 0x02, 0x03, 0x04, ...};
 *   
 *   // 3. Query required buffer size
 *   uint32_t required_size = 0;
 *   auto err = rsa_wrap_data_helper(session, pub_key, test_data, sizeof(test_data), 
 *                                   256, nullptr, &required_size);
 *   
 *   // 4. Allocate buffer and perform wrapping
 *   std::vector<uint8_t> wrapped_buffer(required_size);
 *   uint32_t wrapped_len = required_size;
 *   err = rsa_wrap_data_helper(session, pub_key, test_data, sizeof(test_data),
 *                              256, wrapped_buffer.data(), &wrapped_len);
 */
azihsm_error rsa_wrap_data_helper(azihsm_handle session_handle, azihsm_handle pub_key_handle, const uint8_t *user_data,
                                  uint32_t user_data_len, uint32_t aes_key_bits, uint8_t *wrapped_data,
                                  uint32_t *wrapped_data_len);

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
                                           azihsm_handle *base_secret_handle = nullptr);

/*
*  Helper function to generate EC key pair with DERIVE capability
*  @param pub_key_handle - Output handle for public key
*  @param priv_key_handle - Output handle for private key
*  @param curve - EC curve to use (AZIHSM_EC_CURVE_ID_P256, P384, or P521)
*/
azihsm_error generate_ec_key_pair_for_derive(azihsm_handle session_handle, azihsm_handle &pub_key_handle, azihsm_handle &priv_key_handle,
                                             azihsm_ec_curve_id curve = AZIHSM_EC_CURVE_ID_P256);