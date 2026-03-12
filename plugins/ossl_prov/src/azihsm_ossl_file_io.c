// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "azihsm_ossl_file_io.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

#define AZIHSM_MAX_KEY_FILE_SIZE (64 * 1024)

/*
 * azihsm_file_load - read a file into a heap-allocated azihsm_buffer.
 *
 * Parameters:
 *   path   - NUL-terminated path to the file to read.
 *   buffer - output buffer; always initialised to {NULL, 0} on entry,
 *            populated on success, left as {NULL, 0} on any error.
 *
 * Return values and special cases:
 *   AZIHSM_STATUS_SUCCESS with buffer->ptr == NULL
 *     The file does not exist (ENOENT). Callers treat absence as
 *     "not yet created" rather than a hard error.
 *   AZIHSM_STATUS_SUCCESS with buffer->ptr != NULL
 *     The file was read. buffer->ptr is an OPENSSL_malloc'd region of
 *     buffer->len bytes. The caller is responsible for
 *     OPENSSL_cleanse(buffer->ptr, buffer->len) + OPENSSL_free(buffer->ptr).
 *   AZIHSM_STATUS_INTERNAL_ERROR
 *     Any other failure (permission denied, I/O error, file too large,
 *     not a regular file, allocation failure). The OpenSSL error stack is
 *     populated with a descriptive message including the path and
 *     strerror(errno) where applicable. buffer is left as {NULL, 0}.
 *
 * Size limit: files larger than AZIHSM_MAX_KEY_FILE_SIZE (64 KB) are
 * rejected to prevent runaway allocations on corrupt or malicious paths.
 */
azihsm_status azihsm_file_load(const char *path, struct azihsm_buffer *buffer)
{
    int fd = -1;
    struct stat st;
    size_t total_read = 0;

    // Both arguments are required; a NULL path or output buffer is a caller bug.
    if (path == NULL || buffer == NULL)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_PASSED_NULL_PARAMETER,
            "azihsm_file_load: path or buffer is NULL"
        );
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Guarantee a clean output state before any early return.
    buffer->ptr = NULL;
    buffer->len = 0;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
    {
        // ENOENT means the file has not been created yet (first-use path).
        // All other errors are genuine failures.
        if (errno == ENOENT)
        {
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

    // Validate that the path refers to a regular file before reading.
    if (fstat(fd, &st) != 0)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "fstat failed for key file '%s': %s",
            path,
            strerror(errno)
        );
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (!S_ISREG(st.st_mode))
    {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INIT_FAIL, "key file '%s' is not a regular file", path);
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // An empty file is valid (buffer stays {NULL, 0}); nothing to read.
    if (st.st_size == 0)
    {
        close(fd);
        return AZIHSM_STATUS_SUCCESS;
    }

    // Reject oversized files before allocating to avoid runaway memory use.
    if (st.st_size > AZIHSM_MAX_KEY_FILE_SIZE)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "key file '%s' exceeds maximum size of %d bytes",
            path,
            AZIHSM_MAX_KEY_FILE_SIZE
        );
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    buffer->ptr = OPENSSL_malloc((size_t)st.st_size);
    if (buffer->ptr == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Read in a loop to handle partial reads and EINTR.
    while (total_read < (size_t)st.st_size)
    {
        ssize_t n = read(fd, buffer->ptr + total_read, (size_t)st.st_size - total_read);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            ERR_raise_data(
                ERR_LIB_PROV,
                ERR_R_INIT_FAIL,
                "error reading key file '%s': %s",
                path,
                strerror(errno)
            );
            OPENSSL_cleanse(buffer->ptr, (size_t)st.st_size);
            OPENSSL_free(buffer->ptr);
            buffer->ptr = NULL;
            close(fd);
            return AZIHSM_STATUS_INTERNAL_ERROR;
        }
        if (n == 0)
        {
            break;
        }
        total_read += (size_t)n;
    }

    close(fd);

    if (total_read != (size_t)st.st_size)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "short read from key file '%s': got %zu of %ld bytes",
            path,
            total_read,
            (long)st.st_size
        );
        // Wipe any partial data before freeing to avoid leaving key material on the heap.
        OPENSSL_cleanse(buffer->ptr, (size_t)st.st_size);
        OPENSSL_free(buffer->ptr);
        buffer->ptr = NULL;
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    buffer->len = (uint32_t)st.st_size;
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
    struct stat st;

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

    // Reject non-regular files.
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
    {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INIT_FAIL, "'%s' is not a regular file", path);
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Restrict file to owner read/write only.
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            ERR_R_INIT_FAIL,
            "fchmod failed for '%s': %s",
            path,
            strerror(errno)
        );
        close(fd);
        unlink(path);
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
