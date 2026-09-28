// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "azihsm_pkcs11_compat.h"

#include <stdbool.h>

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

/*
 * Translate a status from the FILL call of a one-shot AES-CBC operation (the
 * second device call; the sizing call takes the hint map directly). With
 * `unpad` — a CKM_AES_CBC_PAD decrypt — INTERNAL_ERROR (-5) is the SDK's
 * PKCS#7 padding check rejecting the ciphertext and becomes
 * CKR_ENCRYPTED_DATA_INVALID; every other status takes
 * azihsm_pkcs11_ckr_from_azihsm_hint with a stale device key handle reading as
 * CKR_KEY_HANDLE_INVALID. Why the remap is safe, and why it is this narrow, is
 * explained at the definition.
 */
CK_RV azihsm_pkcs11_ckr_from_cbc_fill(int status, bool unpad);

#ifdef __cplusplus
}
#endif
