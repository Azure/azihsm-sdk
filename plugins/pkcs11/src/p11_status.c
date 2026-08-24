// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "p11_status.h"

/*
 * The cases use the raw azihsm_status integer values (names in the comments)
 * rather than the AZIHSM_STATUS_* macros so this file also compiles in the
 * no-device build, which links no azihsm.h. The values are part of the C ABI
 * (api/native) and are stable.
 *
 * Administrative "already provisioned" statuses (PARTITION_ALREADY_PROVISIONED,
 * VAULT_APP_LIMIT_REACHED) are handled by the caller before mapping — the lazy
 * provisioning in p11_hsm_login treats them as "already established" and lets
 * the sess_open retry decide — so the conservative mapping here is only a
 * fallback should one reach a caller.
 */
CK_RV p11_ckr_from_azihsm(int status)
{
    switch (status)
    {
    case 0: /* SUCCESS */
        return CKR_OK;
    case -1: /* INVALID_ARGUMENT */
    case -3: /* INDEX_OUT_OF_RANGE */
        return CKR_ARGUMENTS_BAD;
    case -2: /* INVALID_HANDLE */
        return CKR_OBJECT_HANDLE_INVALID;
    case -4: /* BUFFER_TOO_SMALL */
        return CKR_BUFFER_TOO_SMALL;
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
    case -34: /* VAULT_APP_LIMIT_REACHED */
        return CKR_PIN_LOCKED;
    case -36: /* DEVICE_NOT_READY */
    case -38: /* UNSUPPORTED_API_REVISION */
    case -39: /* DEVICE_NOT_ACCESSIBLE */
        return CKR_DEVICE_ERROR;
    default:
        return CKR_FUNCTION_FAILED;
    }
}
