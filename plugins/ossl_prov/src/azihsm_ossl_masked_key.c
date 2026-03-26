// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

#include "azihsm_ossl_file_io.h"
#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_masked_key.h"

int azihsm_ossl_extract_masked_key(
    azihsm_handle derived_handle,
    uint8_t **out_buf,
    uint32_t *out_len
)
{
    uint8_t *buffer = NULL;
    uint32_t alloc_len = 0;
    azihsm_status status;

    struct azihsm_key_prop masked_prop = {
        .id = AZIHSM_KEY_PROP_ID_MASKED_KEY,
        .val = NULL,
        .len = 0,
    };

    /* First call to get required size (expect BUFFER_TOO_SMALL, which sets len) */
    status = azihsm_key_get_prop(derived_handle, &masked_prop);
    if (status != AZIHSM_STATUS_BUFFER_TOO_SMALL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return OSSL_FAILURE;
    }

    if (masked_prop.len == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return OSSL_FAILURE;
    }

    alloc_len = masked_prop.len;
    buffer = OPENSSL_malloc(alloc_len);
    if (buffer == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return OSSL_FAILURE;
    }

    /* Second call to get the actual masked key data */
    masked_prop.val = buffer;
    status = azihsm_key_get_prop(derived_handle, &masked_prop);
    if (status != AZIHSM_STATUS_SUCCESS || masked_prop.len == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        OPENSSL_cleanse(buffer, alloc_len);
        OPENSSL_free(buffer);
        return OSSL_FAILURE;
    }

    *out_buf = buffer;
    *out_len = masked_prop.len;
    return OSSL_SUCCESS;
}

int azihsm_ossl_write_masked_key_to_file(
    const uint8_t *buffer,
    uint32_t len,
    const char *output_file
)
{
    if (azihsm_file_write(output_file, buffer, len) != AZIHSM_STATUS_SUCCESS)
    {
        return OSSL_FAILURE;
    }
    return OSSL_SUCCESS;
}
