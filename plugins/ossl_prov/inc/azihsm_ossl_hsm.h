// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <azihsm.h>

#include "azihsm_ossl_base.h"

void azihsm_close_device_and_session(azihsm_handle device, azihsm_handle session);
azihsm_status azihsm_open_device_and_session(
    const AZIHSM_CONFIG *config,
    azihsm_handle *device,
    azihsm_handle *session
);

/*
 * Get the RSA unwrapping key pair (MUK) handles.
 * Uses cached handles from provctx if available, otherwise retrieves from HSM.
 * The returned handles are owned by provctx and should NOT be deleted by caller.
 */
azihsm_status azihsm_get_unwrapping_key(
    AZIHSM_OSSL_PROV_CTX *provctx,
    azihsm_handle *out_pub,
    azihsm_handle *out_priv
);

#ifdef __cplusplus
}
#endif
