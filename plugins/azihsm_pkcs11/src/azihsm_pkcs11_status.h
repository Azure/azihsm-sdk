// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "azihsm_pkcs11_compat.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Translate an azihsm_status (int32; 0 = success, negative = error) to a CK_RV.
 * This is the single point where the AZIHSM error domain crosses into PKCS#11
 * space: call it only from the HSM-binding layer (azihsm_pkcs11_hsm.c) so every layer
 * above it deals purely in CK_RV.
 */
CK_RV azihsm_pkcs11_ckr_from_azihsm(int status);

#ifdef __cplusplus
}
#endif
