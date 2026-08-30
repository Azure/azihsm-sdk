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
 * space: call it only from the HSM-binding layer (azihsm_pkcs11_hsm.c,
 * azihsm_pkcs11_key.c) so every layer above it deals purely in CK_RV.
 */
CK_RV azihsm_pkcs11_ckr_from_azihsm(int status);

/*
 * As above, but with a caller-supplied translation for INVALID_HANDLE (-2):
 * that status names whichever azihsm handle the failing call was given — a
 * device key, session, or streaming context, never a PKCS#11 object — so only
 * the call site knows which CK_RV describes it (e.g. CKR_KEY_HANDLE_INVALID
 * for a key-op boundary). The plain variant defaults to
 * CKR_OBJECT_HANDLE_INVALID.
 */
CK_RV azihsm_pkcs11_ckr_from_azihsm_hint(int status, CK_RV invalid_handle);

#ifdef __cplusplus
}
#endif
