// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <sys/stat.h>
#include <unistd.h>

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
    int fd;

    fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_SYS_LIB);
        return OSSL_FAILURE;
    }

    /* Write all bytes, retrying on short writes and EINTR */
    uint32_t total_written = 0;
    while (total_written < len)
    {
        ssize_t written = write(fd, buffer + total_written, len - total_written);
        if (written <= 0)
        {
            if (written < 0 && errno == EINTR)
            {
                continue;
            }
            ERR_raise(ERR_LIB_PROV, ERR_R_SYS_LIB);
            close(fd);
            unlink(output_file);
            return OSSL_FAILURE;
        }
        total_written += (uint32_t)written;
    }

    close(fd);
    return OSSL_SUCCESS;
}
