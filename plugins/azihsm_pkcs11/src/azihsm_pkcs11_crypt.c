// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Key-backed operations: C_GenerateKey (CKM_AES_KEY_GEN) and one-shot AES-CBC /
 * AES-CBC-PAD encrypt/decrypt.
 *
 * The AZIHSM device holds keys only as session-scoped handles; the durable form
 * is the opaque masked blob. So C_GenerateKey stores that blob as the object's
 * key body behind the object-store seam, and each C_EncryptInit/C_DecryptInit
 * unmasks it into a fresh device handle owned by the session's operation state
 * (released when the operation ends, wherever it ends — see
 * azihsm_pkcs11_session_reset_op). This file speaks CK_RV only; device calls
 * and status translation live in azihsm_pkcs11_key.c.
 */

#include "azihsm_pkcs11_internal.h"
#include "azihsm_pkcs11_key.h"

#include <stdint.h>
#include <stdlib.h>

/* AES_BLOCK_LEN (the CBC IV/block length) comes from azihsm_pkcs11_key.h. */

/* Supported AES key lengths, and the bits-per-byte used to turn CKA_VALUE_LEN
 * into the device's bit-length property. */
#define AES128_KEY_BYTES 16
#define AES192_KEY_BYTES 24
#define AES256_KEY_BYTES 32
#define AES_KEY_BITS_PER_BYTE 8

/*
 * Attributes C_GenerateKey appends to the caller template before storing:
 * CKA_CLASS, CKA_KEY_TYPE, CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_ENCRYPT,
 * CKA_DECRYPT (each only if absent), plus CKA_LOCAL, CKA_ALWAYS_SENSITIVE and
 * CKA_NEVER_EXTRACTABLE (always). Bounds the store buffer headroom.
 */
#define KEYGEN_APPENDED_ATTRS 9

/* Per-operation cipher state (s->op_ctx while op is P11_OP_ENCRYPT/_DECRYPT). */
typedef struct
{
    CK_MECHANISM_TYPE mech;    /* CKM_AES_CBC or CKM_AES_CBC_PAD */
    uint32_t hsm_key;          /* unmasked device key handle; owned, freed with the op */
    CK_BYTE iv[AES_BLOCK_LEN]; /* the operation's IV seed (owned copy) */
} cipher_op;

void azihsm_pkcs11_cipher_op_free(void *op_ctx)
{
    cipher_op *op = (cipher_op *)op_ctx;
    if (op == NULL)
    {
        return;
    }
    azihsm_pkcs11_key_release(op->hsm_key);
    azihsm_pkcs11_wipe(op, sizeof(*op));
    free(op);
}

/* ========================================================================= */
/* C_GenerateKey (CKM_AES_KEY_GEN)                                           */
/* ========================================================================= */

static const CK_ATTRIBUTE *tmpl_find(const CK_ATTRIBUTE *tmpl, CK_ULONG count, CK_ATTRIBUTE_TYPE t)
{
    for (CK_ULONG i = 0; i < count; i++)
    {
        if (tmpl[i].type == t)
        {
            return &tmpl[i];
        }
    }
    return NULL;
}

/* Read a CK_BBOOL template attribute into *out; length must be exactly 1. */
static CK_RV tmpl_bool(const CK_ATTRIBUTE *a, CK_BBOOL *out)
{
    if ((a == NULL) || (a->pValue == NULL) || (out == NULL))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (a->ulValueLen != sizeof(CK_BBOOL))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    *out = (*(const CK_BBOOL *)a->pValue != CK_FALSE) ? CK_TRUE : CK_FALSE;
    return CKR_OK;
}

/*
 * Validate the caller's CKM_AES_KEY_GEN template and extract what the device
 * needs. This is the CKA_ → key-property normaliser: the device prop list is
 * built from the extracted values only, never from the raw template — the SDK
 * hard-rejects SENSITIVE/EXTRACTABLE/LOCAL as inputs and takes u32/1-byte
 * property values where PKCS#11 has CK_ULONG/CK_BBOOL.
 */
static CK_RV keygen_check_template(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ULONG *value_len,
    CK_BBOOL *token
)
{
    CK_BBOOL have_value_len = CK_FALSE;
    *value_len = 0;
    *token = CK_FALSE;

    for (CK_ULONG i = 0; i < count; i++)
    {
        const CK_ATTRIBUTE *a = &tmpl[i];
        if ((a->ulValueLen > 0) && (a->pValue == NULL))
        {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        /* A type repeated with a different value is inconsistent, and would also
         * split the generation input (last value wins) from what is stored and
         * later read back (first value wins). */
        if (tmpl_find(tmpl, i, a->type) != NULL)
        {
            return CKR_TEMPLATE_INCONSISTENT;
        }
        CK_BBOOL b = CK_FALSE;
        CK_RV rv = CKR_OK;
        switch (a->type)
        {
        case CKA_CLASS:
            if (a->ulValueLen != sizeof(CK_OBJECT_CLASS))
            {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            if (*(const CK_OBJECT_CLASS *)a->pValue != CKO_SECRET_KEY)
            {
                return CKR_TEMPLATE_INCONSISTENT;
            }
            break;
        case CKA_KEY_TYPE:
            if (a->ulValueLen != sizeof(CK_KEY_TYPE))
            {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            if (*(const CK_KEY_TYPE *)a->pValue != CKK_AES)
            {
                return CKR_TEMPLATE_INCONSISTENT;
            }
            break;
        case CKA_VALUE_LEN:
            if (a->ulValueLen != sizeof(CK_ULONG))
            {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            *value_len = *(const CK_ULONG *)a->pValue;
            if ((*value_len != AES128_KEY_BYTES) && (*value_len != AES192_KEY_BYTES) &&
                (*value_len != AES256_KEY_BYTES))
            {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            have_value_len = CK_TRUE;
            break;
        case CKA_SENSITIVE:
            rv = tmpl_bool(a, &b);
            if (rv != CKR_OK)
            {
                return rv;
            }
            if (!b)
            {
                /* Device keys only ever exist masked; a non-sensitive (readable)
                 * key cannot be produced. */
                return CKR_TEMPLATE_INCONSISTENT;
            }
            break;
        case CKA_EXTRACTABLE:
            rv = tmpl_bool(a, &b);
            if (rv != CKR_OK)
            {
                return rv;
            }
            if (b)
            {
                return CKR_TEMPLATE_INCONSISTENT; /* see CKA_SENSITIVE */
            }
            break;
        case CKA_ENCRYPT:
        case CKA_DECRYPT:
            /* Direction policy is stored and enforced host-side at operation
             * init (the device key always carries both — see
             * azihsm_pkcs11_key.h); only the value's shape is checked here. */
            rv = tmpl_bool(a, &b);
            if (rv != CKR_OK)
            {
                return rv;
            }
            break;
        case CKA_TOKEN:
            rv = tmpl_bool(a, token);
            if (rv != CKR_OK)
            {
                return rv;
            }
            break;
        case CKA_LOCAL:
        case CKA_ALWAYS_SENSITIVE:
        case CKA_NEVER_EXTRACTABLE:
            return CKR_ATTRIBUTE_READ_ONLY; /* token-computed, never caller-set */
        case CKA_VALUE:
            return CKR_TEMPLATE_INCONSISTENT; /* generated keys take no material */
        default:
            break; /* stored verbatim on the object */
        }
    }
    /* CKM_AES_KEY_GEN derives the strength solely from CKA_VALUE_LEN. */
    return (have_value_len == CK_TRUE) ? CKR_OK : CKR_TEMPLATE_INCOMPLETE;
}

/* Append `a` unless the caller's template already carries the type. */
static void tmpl_append(
    CK_ATTRIBUTE *full,
    CK_ULONG *n,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ATTRIBUTE a
)
{
    if (tmpl_find(tmpl, count, a.type) == NULL)
    {
        full[(*n)++] = a;
    }
}

CK_RV C_GenerateKey(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phKey
)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if ((pMechanism == NULL_PTR) || (phKey == NULL_PTR) ||
        ((pTemplate == NULL_PTR) && (ulCount > 0)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (pMechanism->mechanism != CKM_AES_KEY_GEN)
    {
        return CKR_MECHANISM_INVALID;
    }
    if ((pMechanism->pParameter != NULL_PTR) || (pMechanism->ulParameterLen != 0))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    azihsm_pkcs11_lock();
    azihsm_pkcs11_session_t *s = azihsm_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        azihsm_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    azihsm_pkcs11_slot_t *slot = &g_azihsm_pkcs11.slots[s->slot];
    if (!slot->user_logged_in || (slot->hsm_session == 0))
    {
        azihsm_pkcs11_unlock();
        return CKR_USER_NOT_LOGGED_IN; /* generation runs in the device session */
    }

    CK_ULONG value_len = 0;
    CK_BBOOL token = CK_FALSE;
    CK_RV rv = keygen_check_template(pTemplate, ulCount, &value_len, &token);
    if ((rv == CKR_OK) && token && ((s->flags & CKF_RW_SESSION) == 0))
    {
        rv = CKR_SESSION_READ_ONLY;
    }
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_unlock();
        return rv;
    }

    CK_BYTE *blob = NULL;
    CK_ULONG blob_len = 0;
    CK_ATTRIBUTE *full = NULL;
    rv = azihsm_pkcs11_key_aes_generate(
        slot->hsm_session,
        (uint32_t)(value_len * AES_KEY_BITS_PER_BYTE),
        &blob,
        &blob_len
    );
    if (rv != CKR_OK)
    {
        goto cleanup;
    }

    /*
     * Store the caller's template plus the attributes this token decides:
     * class/type identify the object for search and C_GetAttributeValue,
     * the sensitivity quartet states the (only possible) key-protection
     * reality, and the usage defaults make an attribute-less template usable.
     */
    full = (CK_ATTRIBUTE *)malloc((ulCount + KEYGEN_APPENDED_ATTRS) * sizeof(CK_ATTRIBUTE));
    if (full == NULL)
    {
        rv = CKR_HOST_MEMORY;
        goto cleanup;
    }
    CK_ULONG n = 0;
    for (CK_ULONG i = 0; i < ulCount; i++)
    {
        full[n++] = pTemplate[i];
    }
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_AES;
    CK_BBOOL btrue = CK_TRUE;
    CK_BBOOL bfalse = CK_FALSE;
    tmpl_append(full, &n, pTemplate, ulCount, (CK_ATTRIBUTE){ CKA_CLASS, &cls, sizeof(cls) });
    tmpl_append(full, &n, pTemplate, ulCount, (CK_ATTRIBUTE){ CKA_KEY_TYPE, &kt, sizeof(kt) });
    tmpl_append(
        full,
        &n,
        pTemplate,
        ulCount,
        (CK_ATTRIBUTE){ CKA_SENSITIVE, &btrue, sizeof(btrue) }
    );
    tmpl_append(
        full,
        &n,
        pTemplate,
        ulCount,
        (CK_ATTRIBUTE){ CKA_EXTRACTABLE, &bfalse, sizeof(bfalse) }
    );
    tmpl_append(full, &n, pTemplate, ulCount, (CK_ATTRIBUTE){ CKA_ENCRYPT, &btrue, sizeof(btrue) });
    tmpl_append(full, &n, pTemplate, ulCount, (CK_ATTRIBUTE){ CKA_DECRYPT, &btrue, sizeof(btrue) });
    /* Rejected above as inputs, so always appended. */
    full[n++] = (CK_ATTRIBUTE){ CKA_LOCAL, &btrue, sizeof(btrue) };
    full[n++] = (CK_ATTRIBUTE){ CKA_ALWAYS_SENSITIVE, &btrue, sizeof(btrue) };
    full[n++] = (CK_ATTRIBUTE){ CKA_NEVER_EXTRACTABLE, &btrue, sizeof(btrue) };

    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    rv =
        g_azihsm_pkcs11.store.ops->create(g_azihsm_pkcs11.store.ctx, s->slot, CK_TRUE, full, n, &h);
    if (rv != CKR_OK)
    {
        goto cleanup;
    }
    rv = g_azihsm_pkcs11.store.ops
             ->set_key_body(g_azihsm_pkcs11.store.ctx, s->slot, CK_TRUE, h, blob, blob_len);
    if (rv != CKR_OK)
    {
        /* No half-object: a key object without its masked body is unusable. */
        (void)g_azihsm_pkcs11.store.ops->destroy(g_azihsm_pkcs11.store.ctx, s->slot, CK_TRUE, h);
        goto cleanup;
    }
    *phKey = h;
    AZIHSM_PKCS11_LOG(
        "C_GenerateKey: AES-%lu obj=%lu (blob %lu bytes)",
        (unsigned long)(value_len * AES_KEY_BITS_PER_BYTE),
        (unsigned long)h,
        (unsigned long)blob_len
    );

cleanup:
    if (blob != NULL)
    {
        azihsm_pkcs11_wipe(blob, blob_len);
        free(blob);
    }
    free(full);
    azihsm_pkcs11_unlock();
    return rv;
}

/* ========================================================================= */
/* One-shot AES-CBC encrypt / decrypt                                        */
/* ========================================================================= */

static CK_RV cipher_init(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey,
    azihsm_pkcs11_op_type_t want
)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pMechanism == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if ((pMechanism->mechanism != CKM_AES_CBC) && (pMechanism->mechanism != CKM_AES_CBC_PAD))
    {
        return CKR_MECHANISM_INVALID;
    }
    /* Both mechanisms take the raw 16-byte IV as their parameter. */
    if ((pMechanism->pParameter == NULL_PTR) || (pMechanism->ulParameterLen != AES_BLOCK_LEN))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }

    azihsm_pkcs11_lock();
    azihsm_pkcs11_session_t *s = azihsm_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        azihsm_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->op != P11_OP_NONE)
    {
        azihsm_pkcs11_unlock();
        return CKR_OPERATION_ACTIVE;
    }
    azihsm_pkcs11_slot_t *slot = &g_azihsm_pkcs11.slots[s->slot];
    if (!slot->user_logged_in || (slot->hsm_session == 0))
    {
        azihsm_pkcs11_unlock();
        return CKR_USER_NOT_LOGGED_IN; /* unmasking needs the device session */
    }

    CK_RV rv;
    CK_BYTE *body = NULL;
    CK_ULONG body_len = 0;
    cipher_op *op = NULL;

    rv = g_azihsm_pkcs11.store.ops
             ->get_key_body(g_azihsm_pkcs11.store.ctx, s->slot, CK_TRUE, hKey, NULL, &body_len);
    if (rv == CKR_OBJECT_HANDLE_INVALID)
    {
        rv = CKR_KEY_HANDLE_INVALID; /* the handle names a key at this entry point */
    }
    if (rv != CKR_OK)
    {
        goto cleanup;
    }
    if (body_len == 0)
    {
        /* An object with no masked body (e.g. a data object) backs no key. */
        rv = CKR_KEY_HANDLE_INVALID;
        goto cleanup;
    }

    /* Host-side attribute gates; the unmasked key enforces its own device-side
     * usage policy on top. An object without the attribute passes (unknowable
     * here, knowable on use). */
    CK_KEY_TYPE kt = 0;
    CK_ATTRIBUTE type_attr = { CKA_KEY_TYPE, &kt, sizeof(kt) };
    rv = g_azihsm_pkcs11.store.ops
             ->get_attr(g_azihsm_pkcs11.store.ctx, s->slot, CK_TRUE, hKey, &type_attr, 1);
    if ((rv == CKR_OK) && (kt != CKK_AES))
    {
        rv = CKR_KEY_TYPE_INCONSISTENT;
        goto cleanup;
    }
    CK_BBOOL allowed = CK_TRUE;
    CK_ATTRIBUTE use_attr = { (want == P11_OP_ENCRYPT) ? CKA_ENCRYPT : CKA_DECRYPT,
                              &allowed,
                              sizeof(allowed) };
    rv = g_azihsm_pkcs11.store.ops
             ->get_attr(g_azihsm_pkcs11.store.ctx, s->slot, CK_TRUE, hKey, &use_attr, 1);
    if ((rv == CKR_OK) && !allowed)
    {
        rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto cleanup;
    }

    body = (CK_BYTE *)malloc(body_len);
    if (body == NULL)
    {
        rv = CKR_HOST_MEMORY;
        goto cleanup;
    }
    rv = g_azihsm_pkcs11.store.ops
             ->get_key_body(g_azihsm_pkcs11.store.ctx, s->slot, CK_TRUE, hKey, body, &body_len);
    if (rv != CKR_OK)
    {
        goto cleanup;
    }

    op = (cipher_op *)malloc(sizeof(cipher_op));
    if (op == NULL)
    {
        rv = CKR_HOST_MEMORY;
        goto cleanup;
    }
    op->mech = pMechanism->mechanism;
    op->hsm_key = 0;
    memcpy(op->iv, pMechanism->pParameter, AES_BLOCK_LEN);
    rv = azihsm_pkcs11_key_aes_unmask(slot->hsm_session, body, body_len, &op->hsm_key);
    if (rv != CKR_OK)
    {
        goto cleanup;
    }

    s->op_ctx = op;
    s->op = want;
    op = NULL; /* ownership moved to the session */
    rv = CKR_OK;

cleanup:
    if (body != NULL)
    {
        azihsm_pkcs11_wipe(body, body_len);
        free(body);
    }
    azihsm_pkcs11_cipher_op_free(op);
    azihsm_pkcs11_unlock();
    return rv;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return cipher_init(hSession, pMechanism, hKey, P11_OP_ENCRYPT);
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return cipher_init(hSession, pMechanism, hKey, P11_OP_DECRYPT);
}

/*
 * Shared one-shot body. Follows the spec's operation-lifetime rules: a NULL
 * output buffer reports the required length and keeps the operation active, a
 * too-small buffer returns CKR_BUFFER_TOO_SMALL and keeps it active for the
 * retry, and every other outcome — success or failure — terminates it.
 */
static CK_RV cipher_oneshot(
    CK_SESSION_HANDLE hSession,
    bool encrypt,
    CK_BYTE_PTR in,
    CK_ULONG in_len,
    CK_BYTE_PTR out,
    CK_ULONG_PTR out_len
)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if ((out_len == NULL_PTR) || ((in == NULL_PTR) && (in_len > 0)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    azihsm_pkcs11_lock();
    azihsm_pkcs11_session_t *s = azihsm_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        azihsm_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    azihsm_pkcs11_op_type_t want = encrypt ? P11_OP_ENCRYPT : P11_OP_DECRYPT;
    if ((s->op != want) || (s->op_ctx == NULL))
    {
        azihsm_pkcs11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    cipher_op *op = (cipher_op *)s->op_ctx;
    bool pad = (op->mech == CKM_AES_CBC_PAD);

    /* Deterministic length policy, host-side (the device would reject these
     * too, but with statuses that don't map to the spec's *_LEN_RANGE). The
     * input length is also range-checked here before it is narrowed to the
     * device buffer's 32-bit length in azihsm_pkcs11_key_aes_cbc. */
    CK_RV rv = CKR_OK;
    if (in_len > (CK_ULONG)UINT32_MAX)
    {
        rv = encrypt ? CKR_DATA_LEN_RANGE : CKR_ENCRYPTED_DATA_LEN_RANGE;
    }
    else if (encrypt && !pad && ((in_len % AES_BLOCK_LEN) != 0))
    {
        rv = CKR_DATA_LEN_RANGE;
    }
    else if (!encrypt && (((in_len % AES_BLOCK_LEN) != 0) || (pad && (in_len == 0))))
    {
        rv = CKR_ENCRYPTED_DATA_LEN_RANGE;
    }
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_session_reset_op(s);
        azihsm_pkcs11_unlock();
        return rv;
    }

    if (out == NULL_PTR)
    {
        /* Sizing probe: report the required length, keep the operation. */
        CK_ULONG need = 0;
        rv = azihsm_pkcs11_key_aes_cbc(encrypt, pad, op->hsm_key, op->iv, in, in_len, NULL, &need);
        if (rv == CKR_OK)
        {
            *out_len = need;
            azihsm_pkcs11_unlock();
            return CKR_OK;
        }
        azihsm_pkcs11_session_reset_op(s);
        azihsm_pkcs11_unlock();
        return rv;
    }

    rv = azihsm_pkcs11_key_aes_cbc(encrypt, pad, op->hsm_key, op->iv, in, in_len, out, out_len);
    if (rv == CKR_BUFFER_TOO_SMALL)
    {
        azihsm_pkcs11_unlock();
        return rv; /* op stays active: the caller retries with a bigger buffer */
    }
    if (rv != CKR_OK)
    {
        *out_len = 0;
    }
    azihsm_pkcs11_session_reset_op(s);
    azihsm_pkcs11_unlock();
    return rv;
}

CK_RV C_Encrypt(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen
)
{
    return cipher_oneshot(hSession, true, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
}

CK_RV C_Decrypt(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen,
    CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen
)
{
    return cipher_oneshot(hSession, false, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
}
