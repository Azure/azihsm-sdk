// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "azihsm_ossl_file_io.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

#define AZIHSM_MAX_KEY_FILE_SIZE (64 * 1024)

/*
 * Load file contents into an azihsm_buffer.
 * See azihsm_ossl_file_io.h for semantics.
 */
azihsm_status azihsm_file_load(const char *path, struct azihsm_buffer *buffer)
{
    FILE *file = NULL;
    long file_size = 0;
    size_t bytes_read = 0;

    if (path == NULL || buffer == NULL)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_PASSED_NULL_PARAMETER,
            "azihsm_file_load: path or buffer is NULL"
        );
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    buffer->ptr = NULL;
    buffer->len = 0;

    file = fopen(path, "rb");
    if (file == NULL)
    {
        if (errno == ENOENT)
        {
            // File doesn't exist - not an error
            return AZIHSM_STATUS_SUCCESS;
        }
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "failed to open key file '%s': %s",
            path,
            strerror(errno)
        );
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (fseek(file, 0, SEEK_END) != 0)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "fseek(SEEK_END) failed for '%s': %s",
            path,
            strerror(errno)
        );
        fclose(file);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    file_size = ftell(file);
    if (file_size < 0)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "ftell failed for '%s': %s",
            path,
            strerror(errno)
        );
        fclose(file);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (fseek(file, 0, SEEK_SET) != 0)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "fseek(SEEK_SET) failed for '%s': %s",
            path,
            strerror(errno)
        );
        fclose(file);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (file_size == 0)
    {
        fclose(file);
        return AZIHSM_STATUS_SUCCESS;
    }

    if (file_size > AZIHSM_MAX_KEY_FILE_SIZE)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "key file '%s' exceeds maximum size of %d bytes",
            path,
            AZIHSM_MAX_KEY_FILE_SIZE
        );
        fclose(file);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    buffer->ptr = OPENSSL_malloc((size_t)file_size);
    if (buffer->ptr == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        fclose(file);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    bytes_read = fread(buffer->ptr, 1, (size_t)file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "short read from key file '%s': got %zu of %ld bytes",
            path,
            bytes_read,
            file_size
        );
        OPENSSL_cleanse(buffer->ptr, (size_t)file_size);
        OPENSSL_free(buffer->ptr);
        buffer->ptr = NULL;
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    buffer->len = (uint32_t)file_size;
    return AZIHSM_STATUS_SUCCESS;
}

/*
 * Write data to a file with restricted permissions.
 * See azihsm_ossl_file_io.h for semantics.
 */
azihsm_status azihsm_file_write(const char *path, const uint8_t *data, uint32_t len)
{
    int fd;
    uint32_t total_written = 0;

    if (path == NULL || data == NULL || len == 0)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_PASSED_NULL_PARAMETER,
            "azihsm_file_write: invalid arguments"
        );
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "failed to open '%s' for writing: %s",
            path,
            strerror(errno)
        );
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    while (total_written < len)
    {
        ssize_t written = write(fd, data + total_written, len - total_written);
        if (written <= 0)
        {
            if (written < 0 && errno == EINTR)
            {
                continue;
            }
            ERR_raise_data(
                ERR_LIB_PROV,
                ERR_R_INIT_FAIL,
                "write failed for '%s': %s",
                path,
                strerror(errno)
            );
            close(fd);
            unlink(path);
            return AZIHSM_STATUS_INTERNAL_ERROR;
        }
        total_written += (uint32_t)written;
    }

    close(fd);
    return AZIHSM_STATUS_SUCCESS;
}
