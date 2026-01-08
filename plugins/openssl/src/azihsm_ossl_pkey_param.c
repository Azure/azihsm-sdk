//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <azihsm.h>

#include "azihsm_ossl_pkey_param.h"
#include "azihsm_ossl_helpers.h"

typedef struct {
    char* name;
    int id;
} KEY_USAGE_MAPPING_ENTRY;

static const KEY_USAGE_MAPPING_ENTRY key_usecases[] = {
    { "sign",   AZIHSM_KEY_PROP_ID_SIGN   },
    { "verify", AZIHSM_KEY_PROP_ID_VERIFY },
    { "unwrap", AZIHSM_KEY_PROP_ID_UNWRAP },
    { "derive", AZIHSM_KEY_PROP_ID_DERIVE },
    { "null",   -1                        }
};

static int get_key_usage_id(const char* usage)
{
    for (const KEY_USAGE_MAPPING_ENTRY* it = key_usecases; it->id != -1; it++) {

        if (strcmp(it->name, usage) == 0) {
            return it->id;
        }
    }

    return -1;
}

static const char* get_key_usage_str(const int id)
{
    for (const KEY_USAGE_MAPPING_ENTRY* it = key_usecases; it->id != -1; it++) {

        if (it->id == id) {
            return it->name;
        }
    }

    return "unknown";
}

void azihsm_ossl_key_usage_list_to_str(const AIHSM_KEY_USAGE_LIST* ulist, char* out, const size_t out_len)
{
    for (int i = 0; i < ulist->count; i++) {

        if (i > 0) {
            strlcat(out, ",", out_len);
        }

        strlcat(out, get_key_usage_str(ulist->elements[i]), out_len);
    }
}

int azihsm_ossl_key_usage_list_from_str(const char* value, AIHSM_KEY_USAGE_LIST* ulist)
{
    char* token;
    char  param_value[256];

    strncpy(param_value, value, sizeof(param_value) - 1);
    param_value[sizeof(param_value) - 1] = '\0';

    token = strtok(param_value, ",");
    ulist->count = 0;

    while(token != NULL && ulist->count < KEY_USAGE_LIST_MAX) {

        int id;

        if ((id = get_key_usage_id(token)) < 0) {
            return -1;
        }

        ulist->elements[ulist->count] = id;
        ulist->count += 1;

        token = strtok(NULL, ",");
    }

    return 0;
}
