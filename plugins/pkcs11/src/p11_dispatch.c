// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * The C ABI shim: the two function-list tables and the entry points that hand
 * them out (C_GetFunctionList for legacy 2.40 callers, C_GetInterfaceList /
 * C_GetInterface for the PKCS#11 3.x interface mechanism). The shim is
 * deliberately dumb — static tables only; all logic lives behind the C_*
 * functions.
 */

#include "p11_internal.h"

/* The classic v2.40 function list (function pointers up to C_WaitForSlotEvent). */
CK_FUNCTION_LIST azihsm_p11_function_list = {
    .version = { AZIHSM_P11_CK_LEGACY_MAJOR, AZIHSM_P11_CK_LEGACY_MINOR },
    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo,
    .C_InitToken = C_InitToken,
    .C_InitPIN = C_InitPIN,
    .C_SetPIN = C_SetPIN,
    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = C_GetOperationState,
    .C_SetOperationState = C_SetOperationState,
    .C_Login = C_Login,
    .C_Logout = C_Logout,
    .C_CreateObject = C_CreateObject,
    .C_CopyObject = C_CopyObject,
    .C_DestroyObject = C_DestroyObject,
    .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue,
    .C_FindObjectsInit = C_FindObjectsInit,
    .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = C_EncryptInit,
    .C_Encrypt = C_Encrypt,
    .C_EncryptUpdate = C_EncryptUpdate,
    .C_EncryptFinal = C_EncryptFinal,
    .C_DecryptInit = C_DecryptInit,
    .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = C_DecryptUpdate,
    .C_DecryptFinal = C_DecryptFinal,
    .C_DigestInit = C_DigestInit,
    .C_Digest = C_Digest,
    .C_DigestUpdate = C_DigestUpdate,
    .C_DigestKey = C_DigestKey,
    .C_DigestFinal = C_DigestFinal,
    .C_SignInit = C_SignInit,
    .C_Sign = C_Sign,
    .C_SignUpdate = C_SignUpdate,
    .C_SignFinal = C_SignFinal,
    .C_SignRecoverInit = C_SignRecoverInit,
    .C_SignRecover = C_SignRecover,
    .C_VerifyInit = C_VerifyInit,
    .C_Verify = C_Verify,
    .C_VerifyUpdate = C_VerifyUpdate,
    .C_VerifyFinal = C_VerifyFinal,
    .C_VerifyRecoverInit = C_VerifyRecoverInit,
    .C_VerifyRecover = C_VerifyRecover,
    .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
    .C_GenerateKey = C_GenerateKey,
    .C_GenerateKeyPair = C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey,
    .C_UnwrapKey = C_UnwrapKey,
    .C_DeriveKey = C_DeriveKey,
    .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = C_GetFunctionStatus,
    .C_CancelFunction = C_CancelFunction,
    .C_WaitForSlotEvent = C_WaitForSlotEvent,
};

/* The v3.x function list (superset; used by C_GetInterface). */
CK_FUNCTION_LIST_3_0 azihsm_p11_function_list_3_0 = {
    .version = { AZIHSM_P11_CK_MAJOR, AZIHSM_P11_CK_MINOR },
    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo,
    .C_InitToken = C_InitToken,
    .C_InitPIN = C_InitPIN,
    .C_SetPIN = C_SetPIN,
    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = C_GetOperationState,
    .C_SetOperationState = C_SetOperationState,
    .C_Login = C_Login,
    .C_Logout = C_Logout,
    .C_CreateObject = C_CreateObject,
    .C_CopyObject = C_CopyObject,
    .C_DestroyObject = C_DestroyObject,
    .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue,
    .C_FindObjectsInit = C_FindObjectsInit,
    .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = C_EncryptInit,
    .C_Encrypt = C_Encrypt,
    .C_EncryptUpdate = C_EncryptUpdate,
    .C_EncryptFinal = C_EncryptFinal,
    .C_DecryptInit = C_DecryptInit,
    .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = C_DecryptUpdate,
    .C_DecryptFinal = C_DecryptFinal,
    .C_DigestInit = C_DigestInit,
    .C_Digest = C_Digest,
    .C_DigestUpdate = C_DigestUpdate,
    .C_DigestKey = C_DigestKey,
    .C_DigestFinal = C_DigestFinal,
    .C_SignInit = C_SignInit,
    .C_Sign = C_Sign,
    .C_SignUpdate = C_SignUpdate,
    .C_SignFinal = C_SignFinal,
    .C_SignRecoverInit = C_SignRecoverInit,
    .C_SignRecover = C_SignRecover,
    .C_VerifyInit = C_VerifyInit,
    .C_Verify = C_Verify,
    .C_VerifyUpdate = C_VerifyUpdate,
    .C_VerifyFinal = C_VerifyFinal,
    .C_VerifyRecoverInit = C_VerifyRecoverInit,
    .C_VerifyRecover = C_VerifyRecover,
    .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
    .C_GenerateKey = C_GenerateKey,
    .C_GenerateKeyPair = C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey,
    .C_UnwrapKey = C_UnwrapKey,
    .C_DeriveKey = C_DeriveKey,
    .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = C_GetFunctionStatus,
    .C_CancelFunction = C_CancelFunction,
    .C_WaitForSlotEvent = C_WaitForSlotEvent,
    .C_GetInterfaceList = C_GetInterfaceList,
    .C_GetInterface = C_GetInterface,
    .C_LoginUser = C_LoginUser,
    .C_SessionCancel = C_SessionCancel,
    .C_MessageEncryptInit = C_MessageEncryptInit,
    .C_EncryptMessage = C_EncryptMessage,
    .C_EncryptMessageBegin = C_EncryptMessageBegin,
    .C_EncryptMessageNext = C_EncryptMessageNext,
    .C_MessageEncryptFinal = C_MessageEncryptFinal,
    .C_MessageDecryptInit = C_MessageDecryptInit,
    .C_DecryptMessage = C_DecryptMessage,
    .C_DecryptMessageBegin = C_DecryptMessageBegin,
    .C_DecryptMessageNext = C_DecryptMessageNext,
    .C_MessageDecryptFinal = C_MessageDecryptFinal,
    .C_MessageSignInit = C_MessageSignInit,
    .C_SignMessage = C_SignMessage,
    .C_SignMessageBegin = C_SignMessageBegin,
    .C_SignMessageNext = C_SignMessageNext,
    .C_MessageSignFinal = C_MessageSignFinal,
    .C_MessageVerifyInit = C_MessageVerifyInit,
    .C_VerifyMessage = C_VerifyMessage,
    .C_VerifyMessageBegin = C_VerifyMessageBegin,
    .C_VerifyMessageNext = C_VerifyMessageNext,
    .C_MessageVerifyFinal = C_MessageVerifyFinal,
};

/* One advertised interface: "PKCS 11" -> the 3.x function list. */
static CK_INTERFACE azihsm_p11_interfaces[] = {
    {
        .pInterfaceName = (CK_CHAR_PTR) "PKCS 11",
        .pFunctionList = &azihsm_p11_function_list_3_0,
        .flags = 0,
    },
};
#define AZIHSM_P11_NUM_INTERFACES (sizeof(azihsm_p11_interfaces) / sizeof(azihsm_p11_interfaces[0]))

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (ppFunctionList == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    *ppFunctionList = &azihsm_p11_function_list;
    return CKR_OK;
}

CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfacesList, CK_ULONG_PTR pulCount)
{
    if (pulCount == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (pInterfacesList == NULL_PTR)
    {
        *pulCount = AZIHSM_P11_NUM_INTERFACES;
        return CKR_OK;
    }
    if (*pulCount < AZIHSM_P11_NUM_INTERFACES)
    {
        *pulCount = AZIHSM_P11_NUM_INTERFACES;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (CK_ULONG i = 0; i < AZIHSM_P11_NUM_INTERFACES; i++)
    {
        pInterfacesList[i] = azihsm_p11_interfaces[i];
    }
    *pulCount = AZIHSM_P11_NUM_INTERFACES;
    return CKR_OK;
}

CK_RV C_GetInterface(
    CK_UTF8CHAR_PTR pInterfaceName,
    CK_VERSION_PTR pVersion,
    CK_INTERFACE_PTR_PTR ppInterface,
    CK_FLAGS flags
)
{
    if (ppInterface == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    for (CK_ULONG i = 0; i < AZIHSM_P11_NUM_INTERFACES; i++)
    {
        CK_INTERFACE *iface = &azihsm_p11_interfaces[i];
        if (pInterfaceName != NULL_PTR &&
            strcmp((const char *)pInterfaceName, (const char *)iface->pInterfaceName) != 0)
        {
            continue;
        }
        if (pVersion != NULL_PTR)
        {
            CK_VERSION *v = &((CK_FUNCTION_LIST_3_0 *)iface->pFunctionList)->version;
            if (pVersion->major != v->major || pVersion->minor != v->minor)
            {
                continue;
            }
        }
        if ((iface->flags & flags) != flags)
        {
            continue;
        }
        *ppInterface = iface;
        return CKR_OK;
    }
    return CKR_ARGUMENTS_BAD;
}
