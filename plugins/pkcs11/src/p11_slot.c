// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Slot / token / mechanism enumeration over g_p11.slots[] (populated by the HSM
 * binding). The mechanism table reflects the AZIHSM SDK's actual capabilities:
 * no CKM_RSA_PKCS_KEY_PAIR_GEN (the device has no general RSA keygen, only an
 * internal unwrapping-key pair), no AES-ECB/CTR, no non-NIST curves, no SHA-3.
 */

#include "p11_internal.h"

/* ------------------------------------------------------------------------- */
/* Mechanism table (AZIHSM real capabilities)                                */
/* ------------------------------------------------------------------------- */

typedef struct
{
    CK_MECHANISM_TYPE type;
    CK_ULONG min_key;
    CK_ULONG max_key;
    CK_FLAGS flags;
} p11_mech_t;

/* AES key sizes expressed in bytes; RSA/EC in bits, per common convention. */
static const p11_mech_t g_mechs[] = {
    /* AES */
    { CKM_AES_KEY_GEN, 16, 32, CKF_GENERATE },
    { CKM_AES_CBC, 16, 32, CKF_ENCRYPT | CKF_DECRYPT },
    { CKM_AES_CBC_PAD, 16, 32, CKF_ENCRYPT | CKF_DECRYPT },
    { CKM_AES_GCM, 32, 32, CKF_ENCRYPT | CKF_DECRYPT },
    { CKM_AES_XTS, 64, 64, CKF_ENCRYPT | CKF_DECRYPT },
    { CKM_AES_XTS_KEY_GEN, 64, 64, CKF_GENERATE },
    /* RSA (no RSA_PKCS_KEY_PAIR_GEN — AZIHSM has no general RSA keygen) */
    { CKM_RSA_PKCS, 2048, 4096, CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY },
    { CKM_RSA_PKCS_OAEP, 2048, 4096, CKF_ENCRYPT | CKF_DECRYPT },
    { CKM_RSA_PKCS_PSS, 2048, 4096, CKF_SIGN | CKF_VERIFY },
    { CKM_SHA1_RSA_PKCS, 2048, 4096, CKF_SIGN | CKF_VERIFY },
    { CKM_SHA256_RSA_PKCS, 2048, 4096, CKF_SIGN | CKF_VERIFY },
    { CKM_SHA384_RSA_PKCS, 2048, 4096, CKF_SIGN | CKF_VERIFY },
    { CKM_SHA512_RSA_PKCS, 2048, 4096, CKF_SIGN | CKF_VERIFY },
    { CKM_SHA256_RSA_PKCS_PSS, 2048, 4096, CKF_SIGN | CKF_VERIFY },
    { CKM_SHA384_RSA_PKCS_PSS, 2048, 4096, CKF_SIGN | CKF_VERIFY },
    { CKM_SHA512_RSA_PKCS_PSS, 2048, 4096, CKF_SIGN | CKF_VERIFY },
    { CKM_RSA_AES_KEY_WRAP, 2048, 4096, CKF_WRAP | CKF_UNWRAP },
    /* ECC (NIST P-256/384/521 only) */
    { CKM_EC_KEY_PAIR_GEN, 256, 521, CKF_GENERATE_KEY_PAIR | CKF_EC_F_P },
    { CKM_ECDSA, 256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_F_P },
    { CKM_ECDSA_SHA1, 256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_F_P },
    { CKM_ECDSA_SHA256, 256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_F_P },
    { CKM_ECDSA_SHA384, 256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_F_P },
    { CKM_ECDSA_SHA512, 256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_F_P },
    { CKM_ECDH1_DERIVE, 256, 521, CKF_DERIVE | CKF_EC_F_P },
    /* Digests (host-side in AZIHSM) */
    { CKM_SHA_1, 0, 0, CKF_DIGEST },
    { CKM_SHA256, 0, 0, CKF_DIGEST },
    { CKM_SHA384, 0, 0, CKF_DIGEST },
    { CKM_SHA512, 0, 0, CKF_DIGEST },
    /* HMAC (SHA-2 only; HMAC-SHA1 is not a supported key kind) */
    { CKM_SHA256_HMAC, 32, 64, CKF_SIGN | CKF_VERIFY },
    { CKM_SHA384_HMAC, 48, 128, CKF_SIGN | CKF_VERIFY },
    { CKM_SHA512_HMAC, 64, 128, CKF_SIGN | CKF_VERIFY },
    { CKM_GENERIC_SECRET_KEY_GEN, 1, 128, CKF_GENERATE },
    /* KDF */
    { CKM_HKDF_DERIVE, 0, 0, CKF_DERIVE },
    { CKM_SP800_108_COUNTER_KDF, 0, 0, CKF_DERIVE },
};
#define AZIHSM_P11_NUM_MECHS (sizeof(g_mechs) / sizeof(g_mechs[0]))

/* ------------------------------------------------------------------------- */
/* Slot / token functions                                                    */
/* ------------------------------------------------------------------------- */

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pulCount == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    (void)tokenPresent; /* every discovered partition has a token present */

    CK_ULONG n = g_p11.slot_count;
    if (pSlotList == NULL_PTR)
    {
        *pulCount = n;
        return CKR_OK;
    }
    if (*pulCount < n)
    {
        *pulCount = n;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (CK_ULONG i = 0; i < n; i++)
    {
        pSlotList[i] = i; /* slot id == index */
    }
    *pulCount = n;
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pInfo == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (slotID >= g_p11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    p11_slot_t *slot = &g_p11.slots[slotID];
    memset(pInfo, 0, sizeof(*pInfo));

    char desc[600];
    snprintf(desc, sizeof(desc), "%s [%s]", AZIHSM_P11_SLOT_DESC, slot->device_path);
    p11_pad_str(pInfo->slotDescription, sizeof(pInfo->slotDescription), desc);
    p11_pad_str(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), AZIHSM_P11_MANUFACTURER);
    pInfo->flags = CKF_HW_SLOT;
    if (slot->present)
    {
        pInfo->flags |= CKF_TOKEN_PRESENT;
    }
    pInfo->hardwareVersion.major = 1;
    pInfo->firmwareVersion.major = (CK_BYTE)slot->api_rev_major;
    pInfo->firmwareVersion.minor = (CK_BYTE)slot->api_rev_minor;
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pInfo == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (slotID >= g_p11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    p11_slot_t *slot = &g_p11.slots[slotID];
    if (!slot->present)
    {
        return CKR_TOKEN_NOT_PRESENT;
    }
    memset(pInfo, 0, sizeof(*pInfo));

    p11_pad_str(pInfo->label, sizeof(pInfo->label), slot->label);
    p11_pad_str(pInfo->manufacturerID, sizeof(pInfo->manufacturerID), AZIHSM_P11_MANUFACTURER);
    p11_pad_str(pInfo->model, sizeof(pInfo->model), AZIHSM_P11_TOKEN_MODEL);
    p11_pad_str(pInfo->serialNumber, sizeof(pInfo->serialNumber), slot->serial);

    pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED;
    if (slot->token_initialized)
    {
        pInfo->flags |= CKF_TOKEN_INITIALIZED;
    }

    pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
    pInfo->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    /* AZIHSM credentials PIN is a fixed 16-byte value. */
    pInfo->ulMaxPinLen = AZIHSM_P11_MAX_PIN_LEN;
    pInfo->ulMinPinLen = AZIHSM_P11_MIN_PIN_LEN;
    pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    pInfo->hardwareVersion.major = 1;
    pInfo->firmwareVersion.major = (CK_BYTE)slot->api_rev_major;
    pInfo->firmwareVersion.minor = (CK_BYTE)slot->api_rev_minor;
    /* No on-token clock: leave utcTime blank (space-padded). */
    p11_pad_str(pInfo->utcTime, sizeof(pInfo->utcTime), "");
    return CKR_OK;
}

CK_RV C_GetMechanismList(
    CK_SLOT_ID slotID,
    CK_MECHANISM_TYPE_PTR pMechanismList,
    CK_ULONG_PTR pulCount
)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pulCount == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (slotID >= g_p11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    CK_ULONG n = AZIHSM_P11_NUM_MECHS;
    if (pMechanismList == NULL_PTR)
    {
        *pulCount = n;
        return CKR_OK;
    }
    if (*pulCount < n)
    {
        *pulCount = n;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (CK_ULONG i = 0; i < n; i++)
    {
        pMechanismList[i] = g_mechs[i].type;
    }
    *pulCount = n;
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pInfo == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (slotID >= g_p11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    for (CK_ULONG i = 0; i < AZIHSM_P11_NUM_MECHS; i++)
    {
        if (g_mechs[i].type == type)
        {
            pInfo->ulMinKeySize = g_mechs[i].min_key;
            pInfo->ulMaxKeySize = g_mechs[i].max_key;
            pInfo->flags = g_mechs[i].flags;
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_INVALID;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    /* pReserved is reserved and must be NULL, pSlot is the required output, and
     * CKF_DONT_BLOCK is the only defined flag. */
    if (pReserved != NULL_PTR || pSlot == NULL_PTR || (flags & ~(CK_FLAGS)CKF_DONT_BLOCK) != 0)
    {
        return CKR_ARGUMENTS_BAD;
    }
    /* AZIHSM partitions are not hot-pluggable, so no slot event ever occurs. */
    if (flags & CKF_DONT_BLOCK)
    {
        return CKR_NO_EVENT;
    }
    return CKR_FUNCTION_NOT_SUPPORTED;
}
