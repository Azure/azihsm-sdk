// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <azihsm.h>

#include "azihsm_ossl_base.h"

/* Maximum size of a partition device path buffer (including NUL). */
#define AZIHSM_DEVICE_PATH_SIZE 64

void azihsm_close_device_and_session(azihsm_handle device, azihsm_handle session);
azihsm_status azihsm_open_device_and_session(
    const AZIHSM_CONFIG *config,
    azihsm_handle *device,
    azihsm_handle *session,
    struct azihsm_resiliency_ctx **resiliency_ctx
);

/*
 * Lazy device+session open.
 *
 * Ensures the provider context has an open HSM device + session, opening it
 * on first call. After a successful return the caller may read provctx->session
 * directly.
 *
 * Must NOT be called from the provider's OSSL_FUNC_PROVIDER_QUERY_OPERATION
 * dispatch hook — see azihsm_ossl_query_operation() for the re-entrancy
 * rationale.
 */
azihsm_status azihsm_ensure_session(AZIHSM_OSSL_PROV_CTX *provctx);

/*
 * Compute POTA endorsement for the current device.
 *
 * Converts the provided PID public key DER to uncompressed EC point format
 * and signs it with the provided POTA private key using ECDSA-SHA384.
 * The signature is returned in raw r||s format.
 *
 * On success:
 *   - sig_out->ptr is allocated with OPENSSL_malloc and must be freed
 *     by the caller with OPENSSL_cleanse + OPENSSL_free.
 */
azihsm_status compute_pota_endorsement(
    const struct azihsm_buffer *pid_pub_key_der,
    const struct azihsm_buffer *priv_key_buf,
    struct azihsm_buffer *sig_out
);

/*
 * Get cached RSA unwrapping key pair handles for wrap/unwrap operations.
 * Returns cached handles from provctx if available, otherwise retrieves
 * the established unwrapping key from the HSM (generating on first use if needed).
 * The returned handles are owned by provctx and should NOT be deleted by caller.
 */
azihsm_status azihsm_get_unwrapping_key(
    AZIHSM_OSSL_PROV_CTX *provctx,
    azihsm_handle *out_pub,
    azihsm_handle *out_priv
);

/*
 * Import a plaintext DER-encoded private key file into the HSM.
 *
 * Reads the file at input_key_file, normalizes it to PKCS#8, wraps it with
 * RSA-AES, then unwraps into the HSM. The file must be a valid DER-encoded
 * private key in a "traditional" format (e.g., SEC1 for EC or PKCS#1 for RSA)
 * or in PKCS#8 format.
 *
 * For pre-wrapped blobs (produced by the wrap_key tool), use azihsm_unwrap_key_pair() instead.
 *
 * The caller provides key property lists that describe the target key attributes.
 * On success, out_priv and out_pub receive the HSM key handles.
 */
azihsm_status azihsm_import_key_pair(
    AZIHSM_OSSL_PROV_CTX *provctx,
    const char *input_key_file,
    const struct azihsm_key_prop_list *priv_key_prop_list,
    const struct azihsm_key_prop_list *pub_key_prop_list,
    azihsm_handle *out_priv,
    azihsm_handle *out_pub
);

/*
 * Import a pre-wrapped key blob into the HSM.
 *
 * Reads the file at wrapped_key_file (produced by the wrap_key tool) and
 * unwraps it directly into the HSM using the RSA-AES key unwrapping mechanism.
 * No DER normalization or wrapping is performed.
 *
 * The caller provides key property lists that describe the target key attributes.
 * On success, out_priv and out_pub receive the HSM key handles.
 */
azihsm_status azihsm_unwrap_key_pair(
    AZIHSM_OSSL_PROV_CTX *provctx,
    const char *wrapped_key_file,
    const struct azihsm_key_prop_list *priv_key_prop_list,
    const struct azihsm_key_prop_list *pub_key_prop_list,
    azihsm_handle *out_priv,
    azihsm_handle *out_pub
);

#ifdef __cplusplus
}
#endif
