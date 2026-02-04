// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Custom OpenSSL Parameters (keymgmt)
 * */

#define AZIHSM_OSSL_PKEY_PARAM_KEY_USAGE "azihsm.key_usage"
#define AZIHSM_OSSL_PKEY_PARAM_MASKED_KEY "azihsm.masked_key"
#define AZIHSM_OSSL_PKEY_PARAM_SESSION "azihsm.session"

/* Key usage types - single usage for the entire key pair */
typedef enum
{
    KEY_USAGE_DIGITAL_SIGNATURE = 0, /* Private: sign, Public: verify */
    KEY_USAGE_KEY_AGREEMENT = 1,     /* Both: derive */
} AZIHSM_KEY_USAGE_TYPE;

/*
 * Parse a key usage string and return the corresponding type
 * @value   string containing key usage ("digitalSignature" or "keyAgreement")
 * @usage_type output parameter for the key usage type
 *
 * @returns 0 on success, -1 on failure
 * */
int azihsm_ossl_key_usage_from_str(const char *value, AZIHSM_KEY_USAGE_TYPE *usage_type);

/*
 * Convert key usage type to string representation
 * @usage_type the key usage type to convert
 * @returns string representation ("digitalSignature" or "keyAgreement"), or "unknown"
 * */
const char *azihsm_ossl_key_usage_to_str(AZIHSM_KEY_USAGE_TYPE usage_type);

/*
 * parse a session parameter string and return a boolean value
 * @value   string containing session preference ("true", "false", "1", "0", "yes", "no")
 *
 * @returns 1 for session key, 0 for persistent key, -1 on failure
 * */
int azihsm_ossl_session_from_str(const char *value);

/*
 * validate a masked key file path parameter
 * @filepath   string containing the file path where masked key should be written
 *
 * @returns 0 on success (valid path), -1 on failure (invalid path)
 * */
int azihsm_ossl_masked_key_filepath_validate(const char *filepath);

/*
 * Get private key property ID for a given key usage type
 * @usage_type the key usage type
 * @returns the private key property ID (SIGN or DERIVE)
 * */
uint32_t azihsm_ossl_get_priv_key_property(AZIHSM_KEY_USAGE_TYPE usage_type);

/*
 * Get public key property ID for a given key usage type
 * @usage_type the key usage type
 * @returns the public key property ID (VERIFY or DERIVE)
 * */
uint32_t azihsm_ossl_get_pub_key_property(AZIHSM_KEY_USAGE_TYPE usage_type);

#ifdef __cplusplus
}
#endif
