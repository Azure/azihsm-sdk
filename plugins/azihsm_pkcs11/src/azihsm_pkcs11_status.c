// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "azihsm_pkcs11_status.h"

/*
 * The cases use the raw azihsm_status integer values (names in the comments)
 * rather than the AZIHSM_STATUS_* macros so this file also compiles in the
 * no-device build, which links no azihsm.h. The values are part of the C ABI
 * (api/native) and are stable.
 *
 * Administrative "already provisioned" statuses (PARTITION_ALREADY_PROVISIONED,
 * VAULT_APP_LIMIT_REACHED) are handled by the caller before mapping — the lazy
 * provisioning in azihsm_pkcs11_hsm_login treats them as "already established" and lets
 * the sess_open retry decide — so the conservative mapping here is only a
 * fallback should one reach a caller.
 */
CK_RV azihsm_pkcs11_ckr_from_azihsm_hint(int status, CK_RV invalid_handle)
{
    switch (status)
    {
    case 0: /* SUCCESS */
        return CKR_OK;
    case -1: /* INVALID_ARGUMENT */
    case -3: /* INDEX_OUT_OF_RANGE */
        return CKR_ARGUMENTS_BAD;
    case -2: /* INVALID_HANDLE — names whichever handle the caller passed */
        return invalid_handle;
    case -4: /* BUFFER_TOO_SMALL */
        return CKR_BUFFER_TOO_SMALL;
    case -6: /* RNG_ERROR */
        return CKR_DEVICE_ERROR;
    case -7: /* INVALID_KEY_SIZE */
        return CKR_KEY_SIZE_RANGE;
    case -9:  /* PROPERTY_NOT_PRESENT */
    case -17: /* UNSUPPORTED_PROPERTY */
        return CKR_ATTRIBUTE_TYPE_INVALID;
    case -10: /* KEY_CLASS_NOT_SPECIFIED */
    case -11: /* KEY_KIND_NOT_SPECIFIED */
        return CKR_TEMPLATE_INCOMPLETE;
    case -12: /* INVALID_KEY */
    case -16: /* INVALID_KEY_PROPS */
        return CKR_KEY_HANDLE_INVALID;
    case -13: /* UNSUPPORTED_KEY_KIND */
    case -14: /* UNSUPPORTED_ALGORITHM */
        return CKR_MECHANISM_INVALID;
    case -15: /* INVALID_SIGNATURE */
    case -27: /* ECC_VERIFY_FAILED */
        return CKR_SIGNATURE_INVALID;
    case -19: /* INVALID_TWEAK */
        return CKR_MECHANISM_PARAM_INVALID;
    case -20: /* NOT_FOUND */
    case -31: /* KEY_NOT_FOUND */
        return CKR_OBJECT_HANDLE_INVALID;
    case -23: /* CREDENTIALS_NOT_ESTABLISHED */
    case -25: /* PARTITION_NOT_PROVISIONED */
        return CKR_USER_NOT_LOGGED_IN;
    case -26: /* MASKED_KEY_DECODE_FAILED — the object's stored blob cannot be
               * materialised into a device key (corrupt, or bound to another
               * partition), so the PKCS#11 key it claims to back is unusable. */
        return CKR_KEY_HANDLE_INVALID;
    case -29: /* SESSION_NEEDS_RENEGOTIATION — a resiliency event (live
               * migration, firmware recovery) invalidated the device session;
               * recovery is a fresh C_Login, so surface it as the login domain
               * does until the resiliency callbacks land. */
        return CKR_USER_NOT_LOGGED_IN;
    case -30: /* PENDING_KEY_GENERATION — transient: the device is still
               * regenerating internal keys after a resiliency event. The spec
               * documents CKR_FUNCTION_FAILED as possibly-retryable, which is
               * exactly this. */
        return CKR_FUNCTION_FAILED;
    case -34: /* VAULT_APP_LIMIT_REACHED */
        return CKR_PIN_LOCKED;
    case -37: /* CANNOT_DELETE_INTERNAL_KEYS */
        return CKR_ACTION_PROHIBITED;
    case -36: /* DEVICE_NOT_READY */
    case -38: /* UNSUPPORTED_API_REVISION */
    case -39: /* DEVICE_NOT_ACCESSIBLE */
        return CKR_DEVICE_ERROR;
    case -40: /* INVALID_CONTEXT_STATE — a streaming crypto context was driven
               * out of order. */
        return CKR_OPERATION_NOT_INITIALIZED;
    default:
        return CKR_FUNCTION_FAILED;
    }
}

CK_RV azihsm_pkcs11_ckr_from_azihsm(int status)
{
    return azihsm_pkcs11_ckr_from_azihsm_hint(status, CKR_OBJECT_HANDLE_INVALID);
}
