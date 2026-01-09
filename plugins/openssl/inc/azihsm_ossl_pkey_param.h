// Copyright (C) Microsoft Corporation. All rights reserved.
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Custom OpenSSL Parameters (keymgmt)
 * */

#define AZIHSM_OSSL_PKEY_PARAM_PRIV_KEY_USAGE "azihsm.priv_key_usage"
#define AZIHSM_OSSL_PKEY_PARAM_PUB_KEY_USAGE  "azihsm.pub_key_usage"

#define KEY_USAGE_LIST_MAX 8

/*
 * Container for KeyUsage Properties (sign, verify,...).
 * Can be embedded into genctx
 * */
typedef struct {
    int count;
    int elements[KEY_USAGE_LIST_MAX];
} AIHSM_KEY_USAGE_LIST;

/*
 * parse a KeyUsage param string and generate a list of KeyUsage properties
 * @value   comma delimited string containing KeyUsage properties (ex. "sign,verify")
 * @ulist   resulting list of KeyUsage properties
 *
 * @returns 0 on success, -1 on failure
 * */
int azihsm_ossl_key_usage_list_from_str(const char* value, AIHSM_KEY_USAGE_LIST* ulist);

/*
 * parse a KeyUsage list and generate a comma delimited string with key usage properties
 * @ulist   list of KeyUsage properties
 * @out     output buffer - managed by caller
 * @out_len size of output buffer in bytes
 * */
void azihsm_ossl_key_usage_list_to_str(const AIHSM_KEY_USAGE_LIST* ulist, char* out, const size_t out_len);

#ifdef __cplusplus
}
#endif
