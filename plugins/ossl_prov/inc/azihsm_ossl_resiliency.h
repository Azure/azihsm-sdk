// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <azihsm.h>
#include <stdbool.h>

/* Default directory for resiliency storage files */
#define AZIHSM_DEFAULT_RESILIENCY_STORAGE_DIR "/var/lib/azihsm/resiliency"

/* Environment variable to enable resiliency */
#define AZIHSM_RESILIENCY_ENABLED_ENV "AZIHSM_RESILIENCY_ENABLED"

/* Environment variable to override resiliency storage directory */
#define AZIHSM_RESILIENCY_STORAGE_DIR_ENV "AZIHSM_RESILIENCY_STORAGE_DIR"

/*
 * Opaque resiliency context.
 *
 * Holds all state needed by the resiliency callbacks (storage directory,
 * lock file descriptor, POTA key paths).
 * Defined in azihsm_ossl_resiliency.c.
 */
struct azihsm_resiliency_ctx;

/*
 * Creates a resiliency context and populates an azihsm_resiliency_config
 * struct that can be passed to azihsm_part_init().
 *
 * The returned context owns all resources referenced by the config
 * (storage directory state, lock file descriptor, POTA callback ops).
 * The context must outlive any use of the config and must be freed with
 * azihsm_resiliency_destroy().
 *
 * @param[in]  storage_dir  Path to the directory for resiliency key files.
 *                          Created with mode 0700 (owner-only access) if it
 *                          does not exist. If it already exists, ownership
 *                          and permissions are verified — the directory must
 *                          be owned by the current user with no group/other
 *                          access, or the call is rejected.
 * @param[in]  pota_priv_path  Path to POTA private key DER file (NULL for TPM).
 * @param[in]  pota_pub_path   Path to POTA public key DER file (NULL for TPM).
 * @param[in]  use_tpm_pota    True when POTA source is TPM (no callback needed).
 * @param[out] out_config   Populated with callback function pointers and
 *                          a context pointer referencing the new context.
 * @param[out] out_ctx      Receives the newly allocated context.
 *
 * @return AZIHSM_STATUS_SUCCESS on success, or a negative error code.
 */
azihsm_status azihsm_resiliency_create(
    const char *storage_dir,
    const char *pota_priv_path,
    const char *pota_pub_path,
    bool use_tpm_pota,
    struct azihsm_resiliency_config *out_config,
    struct azihsm_resiliency_ctx **out_ctx
);

/*
 * Destroys a resiliency context, releasing all resources (lock file
 * descriptor, allocated memory).
 *
 * After this call, any azihsm_resiliency_config that referenced this
 * context is invalid and must not be used.
 *
 * @param[in] ctx  Context to destroy (NULL is a no-op).
 */
void azihsm_resiliency_destroy(struct azihsm_resiliency_ctx *ctx);

#ifdef __cplusplus
}
#endif
