// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Two-call pattern for masked key extraction.
 *
 * First call with NULL buffer to query the required size, then allocate
 * and retrieve the masked key data. On success, *out_buf and *out_len
 * are set and the caller must OPENSSL_cleanse + OPENSSL_free the buffer.
 *
 * @derived_handle  HSM handle for the derived key
 * @out_buf         On success, set to a newly allocated buffer (OPENSSL_malloc)
 * @out_len         On success, set to the length of the buffer in bytes
 *
 * @returns OSSL_SUCCESS (1) on success, OSSL_FAILURE (0) on failure
 */
int azihsm_ossl_extract_masked_key(
    azihsm_handle derived_handle,
    uint8_t **out_buf,
    uint32_t *out_len
);

/*
 * Write a buffer to a file with proper error handling.
 *
 * Opens the file with O_NOFOLLOW and 0600 permissions. Loops write() to
 * handle short writes and EINTR. On failure, removes the partially written
 * file.
 *
 * @buffer       Data to write
 * @len          Number of bytes to write
 * @output_file  Destination file path
 *
 * @returns OSSL_SUCCESS (1) on success, OSSL_FAILURE (0) on failure
 */
int azihsm_ossl_write_masked_key_to_file(
    const uint8_t *buffer,
    uint32_t len,
    const char *output_file
);

#ifdef __cplusplus
}
#endif
