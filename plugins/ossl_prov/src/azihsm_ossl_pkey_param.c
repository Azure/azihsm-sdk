// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _DEFAULT_SOURCE
#include <azihsm.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/proverr.h>
#include <string.h>

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
    { "keyEncipherment", KEY_USAGE_KEY_ENCIPHERMENT },
    { "keyWrapping", KEY_USAGE_KEY_WRAPPING },
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
    case KEY_USAGE_KEY_ENCIPHERMENT:
        return AZIHSM_KEY_PROP_ID_DECRYPT;
    case KEY_USAGE_KEY_WRAPPING:
        return AZIHSM_KEY_PROP_ID_UNWRAP;
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
    case KEY_USAGE_KEY_ENCIPHERMENT:
        return AZIHSM_KEY_PROP_ID_ENCRYPT;
    case KEY_USAGE_KEY_WRAPPING:
        return AZIHSM_KEY_PROP_ID_WRAP;
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

    /* Must leave room for null terminator in 4096-byte destination buffers */
    if (strlen(filepath) >= 4096)
    {
        return -1;
    }

    return 0;
}

int azihsm_ossl_get_str_param(
    const OSSL_PARAM params[],
    const char *key,
    char *out,
    size_t out_size
)
{
    const OSSL_PARAM *p;
    size_t len;

    if (params == NULL || key == NULL || out == NULL || out_size == 0)
    {
        return -1;
    }

    /* Leave out untouched when absent: callers accumulate into context fields
     * across the repeated set_params calls one per -pkeyopt produces, so an
     * absent parameter must not clear a value an earlier call stored. */
    if ((p = OSSL_PARAM_locate_const(params, key)) == NULL)
    {
        return 0;
    }

    if (p->data_type != OSSL_PARAM_UTF8_STRING || p->data == NULL)
    {
        return -1;
    }

    /*
     * data_size carries the value length, but the OSSL_PARAM_utf8_string()
     * initializer macro leaves it zero for a C string, unlike
     * OSSL_PARAM_construct_utf8_string(), which fills in strlen().  When
     * data_size is set it may still be the full backing buffer rather than the
     * string length, so bound the scan by the destination as well: anything at
     * least out_size long is rejected below regardless.  This never reads past
     * the value while avoiding scanning arbitrarily large buffers.
     */
    size_t scan = (p->data_size != 0 && p->data_size < out_size) ? p->data_size : out_size;
    len = OPENSSL_strnlen(p->data, scan);

    if (len >= out_size)
    {
        return -1;
    }

    memcpy(out, p->data, len);
    out[len] = '\0';

    return 1;
}

int azihsm_ossl_input_key_filepath_validate(const char *filepath)
{
    if (filepath == NULL || filepath[0] == '\0')
    {
        return -1;
    }

    /* Must leave room for null terminator in 4096-byte destination buffers */
    if (strlen(filepath) >= 4096)
    {
        return -1;
    }

    return 0;
}

OSSL_STATUS azihsm_ossl_normalize_der_to_pkcs8(
    const uint8_t *in_buf,
    long in_len,
    uint8_t **out_buf,
    int *out_len
)
{
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    BUF_MEM *bptr = NULL;
    const uint8_t *p;

    /* Validate arguments */
    if (in_buf == NULL || in_len <= 0 || out_buf == NULL || out_len == NULL)
    {
        return OSSL_FAILURE;
    }

    /* Initialize outputs to safe defaults */
    *out_buf = NULL;
    *out_len = 0;

    p = in_buf;

    /* Auto-detect format: d2i_AutoPrivateKey handles both SEC1 and PKCS#8 */
    pkey = d2i_AutoPrivateKey(NULL, &p, in_len);
    if (pkey == NULL)
    {
        return OSSL_FAILURE;
    }

    /* Write as unencrypted PKCS#8 DER to a memory BIO */
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        EVP_PKEY_free(pkey);
        return OSSL_FAILURE;
    }

    if (i2d_PKCS8PrivateKey_bio(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1)
    {
        EVP_PKEY_free(pkey);
        BIO_free(bio);
        return OSSL_FAILURE;
    }
    EVP_PKEY_free(pkey);

    /* Extract the DER bytes from the BIO */
    BIO_get_mem_ptr(bio, &bptr);
    if (bptr == NULL || bptr->length <= 0)
    {
        BIO_free(bio);
        return OSSL_FAILURE;
    }

    *out_buf = OPENSSL_malloc(bptr->length);
    if (*out_buf == NULL)
    {
        OPENSSL_cleanse(bptr->data, bptr->length);
        BIO_free(bio);
        return OSSL_FAILURE;
    }

    memcpy(*out_buf, bptr->data, bptr->length);
    *out_len = (int)bptr->length;

    OPENSSL_cleanse(bptr->data, bptr->length);
    BIO_free(bio);

    return OSSL_SUCCESS;
}
