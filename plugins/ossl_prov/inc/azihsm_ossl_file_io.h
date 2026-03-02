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
 * Load file contents into an azihsm_buffer.
 *
 * Returns AZIHSM_STATUS_SUCCESS with buffer->ptr == NULL when the file does not
 * exist (ENOENT) — absence is treated as "not yet created", not an error.
 * Returns AZIHSM_STATUS_SUCCESS with buffer->ptr != NULL on success.
 * Returns AZIHSM_STATUS_INTERNAL_ERROR on all other failures and sets the
 * OpenSSL error stack with a descriptive message.
 *
 * On success with a non-empty file, the caller must
 * OPENSSL_cleanse(buffer->ptr, buffer->len) + OPENSSL_free(buffer->ptr).
 */
azihsm_status azihsm_file_load(const char *path, struct azihsm_buffer *buffer);

/*
 * Write data to a file with restricted permissions (0600, O_NOFOLLOW).
 *
 * Uses a write() loop to handle short writes and EINTR. Unlinks the
 * partially written file on failure. Sets the OpenSSL error stack with a
 * descriptive message on failure.
 *
 * Returns AZIHSM_STATUS_SUCCESS on success, AZIHSM_STATUS_INTERNAL_ERROR on error.
 */
azihsm_status azihsm_file_write(const char *path, const uint8_t *data, uint32_t len);

#ifdef __cplusplus
}
#endif
