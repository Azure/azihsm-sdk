// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#define _DEFAULT_SOURCE
#include <azihsm.h>
#include <bsd/string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>

#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_pkey_param.h"

typedef struct
{
    const char *name;
    AZIHSM_KEY_USAGE_TYPE type;
} KEY_USAGE_MAPPING_ENTRY;

static const KEY_USAGE_MAPPING_ENTRY key_usage_map[] = {
    { "digitalSignature", KEY_USAGE_DIGITAL_SIGNATURE },
    { "keyAgreement", KEY_USAGE_KEY_AGREEMENT },
    { NULL, -1 }
};

static AZIHSM_KEY_USAGE_TYPE get_key_usage_type(const char *usage)
{
    for (const KEY_USAGE_MAPPING_ENTRY *it = key_usage_map; it->name != NULL; it++)
    {
        if (strcmp(it->name, usage) == 0)
        {
            return it->type;
        }
    }

    return -1;
}

static const char *get_key_usage_str(AZIHSM_KEY_USAGE_TYPE type)
{
    for (const KEY_USAGE_MAPPING_ENTRY *it = key_usage_map; it->name != NULL; it++)
    {
        if (it->type == type)
        {
            return it->name;
        }
    }

    return "unknown";
}

const char *azihsm_ossl_key_usage_to_str(AZIHSM_KEY_USAGE_TYPE usage_type)
{
    return get_key_usage_str(usage_type);
}

int azihsm_ossl_key_usage_from_str(const char *value, AZIHSM_KEY_USAGE_TYPE *usage_type)
{
    if (value == NULL || usage_type == NULL)
    {
        return -1;
    }

    /* Directly check the return value as int before converting to enum */
    int type_int = (int)get_key_usage_type(value);
    if (type_int < 0)
    {
        return -1;
    }

    *usage_type = (AZIHSM_KEY_USAGE_TYPE)type_int;
    return 0;
}

uint32_t azihsm_ossl_get_priv_key_property(AZIHSM_KEY_USAGE_TYPE usage_type)
{
    switch (usage_type)
    {
    case KEY_USAGE_DIGITAL_SIGNATURE:
        return AZIHSM_KEY_PROP_ID_SIGN;
    case KEY_USAGE_KEY_AGREEMENT:
        return AZIHSM_KEY_PROP_ID_DERIVE;
    default:
        return AZIHSM_KEY_PROP_ID_SIGN; /* Default to SIGN */
    }
}

uint32_t azihsm_ossl_get_pub_key_property(AZIHSM_KEY_USAGE_TYPE usage_type)
{
    switch (usage_type)
    {
    case KEY_USAGE_DIGITAL_SIGNATURE:
        return AZIHSM_KEY_PROP_ID_VERIFY;
    case KEY_USAGE_KEY_AGREEMENT:
        return AZIHSM_KEY_PROP_ID_DERIVE;
    default:
        return AZIHSM_KEY_PROP_ID_VERIFY; /* Default to VERIFY */
    }
}

int azihsm_ossl_session_from_str(const char *value)
{
    if (value == NULL)
    {
        return -1;
    }

    if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0 || strcmp(value, "yes") == 0)
    {
        return 1;
    }

    if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0 || strcmp(value, "no") == 0)
    {
        return 0;
    }

    return -1;
}

int azihsm_ossl_masked_key_filepath_validate(const char *filepath)
{
    if (filepath == NULL || filepath[0] == '\0')
    {
        return -1;
    }

    /* Check for reasonable path length (prevent path traversal issues) */
    if (strlen(filepath) > 4096)
    {
        return -1;
    }

    return 0;
}
