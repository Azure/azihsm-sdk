// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Session lifecycle, login, the object entry points (which delegate to the
 * object-store seam), and the host-side digests (see azihsm_pkcs11_digest.h).
 * The digests need no partition provisioning, so they are the operations the
 * validation tools can drive end-to-end while the key-backed mechanisms are
 * still unimplemented.
 */

#include "azihsm_pkcs11_digest.h"
#include "azihsm_pkcs11_hsm.h"
#include "azihsm_pkcs11_internal.h"

/* ========================================================================= */
/* Operation state                                                           */
/* ========================================================================= */

CK_RV azihsm_pkcs11_session_reset_op(azihsm_pkcs11_session_t *s)
{
    if (s->op == P11_OP_DIGEST && s->op_ctx != NULL)
    {
        azihsm_pkcs11_digest_op_free(s->op_ctx);
    }
    s->op_ctx = NULL;
    if (s->op == P11_OP_FIND && s->find_cursor != NULL)
    {
        g_azihsm_pkcs11.store.ops->find_final(g_azihsm_pkcs11.store.ctx, s->find_cursor);
    }
    s->find_cursor = NULL;
    s->op = P11_OP_NONE;
    return CKR_OK;
}

/* ========================================================================= */
/* Sessions                                                                  */
/* ========================================================================= */

CK_RV C_OpenSession(
    CK_SLOT_ID slotID,
    CK_FLAGS flags,
    CK_VOID_PTR pApplication,
    CK_NOTIFY Notify,
    CK_SESSION_HANDLE_PTR phSession
)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (phSession == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (slotID >= g_azihsm_pkcs11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    if ((flags & CKF_SERIAL_SESSION) == 0)
    {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    azihsm_pkcs11_lock();
    /* An RO session may not be opened while the SO is logged in. */
    if ((flags & CKF_RW_SESSION) == 0 && g_azihsm_pkcs11.slots[slotID].so_logged_in)
    {
        azihsm_pkcs11_unlock();
        return CKR_SESSION_READ_WRITE_SO_EXISTS;
    }
    azihsm_pkcs11_session_t *s = NULL;
    for (size_t i = 0; i < AZIHSM_PKCS11_MAX_SESSIONS; i++)
    {
        if (!g_azihsm_pkcs11.sessions[i].in_use)
        {
            s = &g_azihsm_pkcs11.sessions[i];
            break;
        }
    }
    if (s == NULL)
    {
        azihsm_pkcs11_unlock();
        return CKR_SESSION_COUNT;
    }
    memset(s, 0, sizeof(*s));
    s->in_use = true;
    s->handle = g_azihsm_pkcs11.next_session_handle++;
    s->slot = slotID;
    s->flags = flags;
    s->app = pApplication;
    s->notify = Notify;
    s->op = P11_OP_NONE;
    *phSession = s->handle;
    azihsm_pkcs11_unlock();
    return CKR_OK;
}

static bool slot_has_sessions(CK_SLOT_ID slot)
{
    for (size_t i = 0; i < AZIHSM_PKCS11_MAX_SESSIONS; i++)
    {
        if (g_azihsm_pkcs11.sessions[i].in_use && g_azihsm_pkcs11.sessions[i].slot == slot)
        {
            return true;
        }
    }
    return false;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    azihsm_pkcs11_lock();
    azihsm_pkcs11_session_t *s = azihsm_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        azihsm_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    CK_SLOT_ID slot_id = s->slot;
    azihsm_pkcs11_session_reset_op(s);
    s->in_use = false;
    /* The HSM login is token-wide: close it only when the last session on the
     * slot goes away, not whenever any one session closes. */
    if (!slot_has_sessions(slot_id))
    {
        azihsm_pkcs11_slot_t *slot = &g_azihsm_pkcs11.slots[slot_id];
        azihsm_pkcs11_hsm_logout(slot->hsm_session);
        slot->hsm_session = 0;
        slot->user_logged_in = false;
        slot->so_logged_in = false;
    }
    azihsm_pkcs11_unlock();
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (slotID >= g_azihsm_pkcs11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    azihsm_pkcs11_lock();
    for (size_t i = 0; i < AZIHSM_PKCS11_MAX_SESSIONS; i++)
    {
        if (g_azihsm_pkcs11.sessions[i].in_use && g_azihsm_pkcs11.sessions[i].slot == slotID)
        {
            azihsm_pkcs11_session_reset_op(&g_azihsm_pkcs11.sessions[i]);
            g_azihsm_pkcs11.sessions[i].in_use = false;
        }
    }
    azihsm_pkcs11_slot_t *slot = &g_azihsm_pkcs11.slots[slotID];
    azihsm_pkcs11_hsm_logout(slot->hsm_session);
    slot->hsm_session = 0;
    slot->user_logged_in = false;
    slot->so_logged_in = false;
    azihsm_pkcs11_unlock();
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pInfo == NULL_PTR)
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
    azihsm_pkcs11_slot_t *slot = &g_azihsm_pkcs11.slots[s->slot];
    bool rw = (s->flags & CKF_RW_SESSION) != 0;

    CK_STATE state;
    if (slot->so_logged_in)
    {
        state = CKS_RW_SO_FUNCTIONS;
    }
    else if (slot->user_logged_in)
    {
        state = rw ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
    }
    else
    {
        state = rw ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
    }

    pInfo->slotID = s->slot;
    pInfo->state = state;
    pInfo->flags = s->flags;
    pInfo->ulDeviceError = 0;
    azihsm_pkcs11_unlock();
    return CKR_OK;
}

CK_RV C_Login(
    CK_SESSION_HANDLE hSession,
    CK_USER_TYPE userType,
    CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen
)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    azihsm_pkcs11_lock();
    azihsm_pkcs11_session_t *s = azihsm_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        azihsm_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    azihsm_pkcs11_slot_t *slot = &g_azihsm_pkcs11.slots[s->slot];
    CK_RV rv = CKR_OK;
    switch (userType)
    {
    case CKU_USER: {
        /*
         * Validate the PIN against the advertised range (C_GetTokenInfo) so the
         * outcome is deterministic: a NULL buffer with a non-zero length is a
         * caller error, and an out-of-range length is rejected rather than
         * silently truncated in the HSM binding. A zero-length PIN is the
         * "no PIN" case and falls back to the configured default.
         */
        if (pPin == NULL_PTR && ulPinLen > 0)
        {
            rv = CKR_ARGUMENTS_BAD;
            break;
        }
        if (ulPinLen > 0 &&
            (ulPinLen < AZIHSM_PKCS11_MIN_PIN_LEN || ulPinLen > AZIHSM_PKCS11_MAX_PIN_LEN))
        {
            rv = CKR_PIN_LEN_RANGE;
            break;
        }
        if (slot->user_logged_in)
        {
            rv = CKR_USER_ALREADY_LOGGED_IN;
            break;
        }
        uint32_t hs = 0;
        rv = azihsm_pkcs11_hsm_login(s->slot, pPin, ulPinLen, &hs);
        if (rv == CKR_OK)
        {
            slot->hsm_session = hs;
            slot->user_logged_in = true;
        }
        break;
    }
    case CKU_SO:
        /*
         * The AZIHSM DDI has no security-officer credential, so an SO login
         * cannot be authenticated. Accepting it unconditionally would let any
         * caller put the token into SO mode and lock out RO sessions, so reject
         * it until SO is backed by a real credential.
         */
        rv = CKR_USER_TYPE_INVALID;
        break;
    case CKU_CONTEXT_SPECIFIC:
        /*
         * Per-operation re-authentication (for CKA_ALWAYS_AUTHENTICATE keys).
         * No such operation can be active yet, so there is nothing to
         * re-authenticate.
         */
        rv = CKR_OPERATION_NOT_INITIALIZED;
        break;
    default:
        rv = CKR_USER_TYPE_INVALID;
        break;
    }
    azihsm_pkcs11_unlock();
    return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    azihsm_pkcs11_lock();
    azihsm_pkcs11_session_t *s = azihsm_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        azihsm_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    azihsm_pkcs11_slot_t *slot = &g_azihsm_pkcs11.slots[s->slot];
    if (!slot->user_logged_in && !slot->so_logged_in)
    {
        azihsm_pkcs11_unlock();
        return CKR_USER_NOT_LOGGED_IN;
    }
    /* Login is token-wide, so log the token out regardless of which session
     * calls C_Logout — including one that never called C_Login itself. */
    azihsm_pkcs11_hsm_logout(slot->hsm_session);
    slot->hsm_session = 0;
    slot->user_logged_in = false;
    slot->so_logged_in = false;
    azihsm_pkcs11_unlock();
    return CKR_OK;
}

/* ========================================================================= */
/* Objects (delegated to the object-store seam)                              */
/*                                                                           */
/* Each entry point validates its arguments and session, then hands off to   */
/* g_azihsm_pkcs11.store; slot isolation and private-object login-gating are enforced  */
/* by the store (see azihsm_pkcs11_objstore.h).                                        */
/* ========================================================================= */

CK_RV C_CreateObject(
    CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phObject
)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (phObject == NULL_PTR || (pTemplate == NULL_PTR && ulCount > 0))
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
    CK_BBOOL logged_in = g_azihsm_pkcs11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    CK_RV rv =
        g_azihsm_pkcs11.store.ops
            ->create(g_azihsm_pkcs11.store.ctx, s->slot, logged_in, pTemplate, ulCount, phObject);
    azihsm_pkcs11_unlock();
    return rv;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    azihsm_pkcs11_lock();
    azihsm_pkcs11_session_t *s = azihsm_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        azihsm_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    CK_BBOOL logged_in = g_azihsm_pkcs11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    CK_RV rv =
        g_azihsm_pkcs11.store.ops->destroy(g_azihsm_pkcs11.store.ctx, s->slot, logged_in, hObject);
    azihsm_pkcs11_unlock();
    return rv;
}

CK_RV C_GetAttributeValue(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount
)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pTemplate == NULL_PTR && ulCount > 0)
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
    CK_BBOOL logged_in = g_azihsm_pkcs11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    CK_RV rv =
        g_azihsm_pkcs11.store.ops
            ->get_attr(g_azihsm_pkcs11.store.ctx, s->slot, logged_in, hObject, pTemplate, ulCount);
    azihsm_pkcs11_unlock();
    return rv;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pTemplate == NULL_PTR && ulCount > 0)
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
    if (s->op != P11_OP_NONE)
    {
        azihsm_pkcs11_unlock();
        return CKR_OPERATION_ACTIVE;
    }
    CK_BBOOL logged_in = g_azihsm_pkcs11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    CK_RV rv = g_azihsm_pkcs11.store.ops->find_init(
        g_azihsm_pkcs11.store.ctx,
        s->slot,
        logged_in,
        pTemplate,
        ulCount,
        &s->find_cursor
    );
    if (rv == CKR_OK)
    {
        s->op = P11_OP_FIND;
    }
    azihsm_pkcs11_unlock();
    return rv;
}

CK_RV C_FindObjects(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount,
    CK_ULONG_PTR pulObjectCount
)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (phObject == NULL_PTR || pulObjectCount == NULL_PTR)
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
    if (s->op != P11_OP_FIND)
    {
        azihsm_pkcs11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    CK_RV rv = g_azihsm_pkcs11.store.ops->find(
        g_azihsm_pkcs11.store.ctx,
        s->find_cursor,
        phObject,
        ulMaxObjectCount,
        pulObjectCount
    );
    azihsm_pkcs11_unlock();
    return rv;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    azihsm_pkcs11_lock();
    azihsm_pkcs11_session_t *s = azihsm_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        azihsm_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->op != P11_OP_FIND)
    {
        azihsm_pkcs11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    azihsm_pkcs11_session_reset_op(s);
    azihsm_pkcs11_unlock();
    return CKR_OK;
}

/* ========================================================================= */
/* Digest (host-side; see azihsm_pkcs11_digest.h)                            */
/* ========================================================================= */

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pMechanism == NULL_PTR)
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
    if (s->op != P11_OP_NONE)
    {
        azihsm_pkcs11_unlock();
        return CKR_OPERATION_ACTIVE;
    }
    azihsm_pkcs11_digest_op_t *op = NULL;
    CK_RV rv = azihsm_pkcs11_digest_op_new(pMechanism->mechanism, &op);
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_unlock();
        return rv;
    }
    /* All supported digest mechanisms are parameterless. */
    if (pMechanism->pParameter != NULL_PTR || pMechanism->ulParameterLen != 0)
    {
        azihsm_pkcs11_digest_op_free(op);
        azihsm_pkcs11_unlock();
        return CKR_MECHANISM_PARAM_INVALID;
    }
    s->op_ctx = op;
    s->op = P11_OP_DIGEST;
    azihsm_pkcs11_unlock();
    return CKR_OK;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (ulPartLen > 0 && pPart == NULL_PTR)
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
    if (s->op != P11_OP_DIGEST)
    {
        azihsm_pkcs11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ulPartLen > 0)
    {
        azihsm_pkcs11_digest_op_update(s->op_ctx, pPart, ulPartLen);
    }
    azihsm_pkcs11_unlock();
    return CKR_OK;
}

static CK_RV digest_output(
    azihsm_pkcs11_session_t *s,
    CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen
)
{
    CK_ULONG len = azihsm_pkcs11_digest_op_len(s->op_ctx);
    if (pDigest == NULL_PTR)
    {
        *pulDigestLen = len; /* two-call: report length, keep op active */
        return CKR_OK;
    }
    if (*pulDigestLen < len)
    {
        *pulDigestLen = len;
        return CKR_BUFFER_TOO_SMALL; /* op stays active for retry */
    }
    azihsm_pkcs11_digest_op_final(s->op_ctx, pDigest);
    *pulDigestLen = len;
    azihsm_pkcs11_session_reset_op(s);
    return CKR_OK;
}

CK_RV C_Digest(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen
)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pulDigestLen == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (ulDataLen > 0 && pData == NULL_PTR)
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
    if (s->op != P11_OP_DIGEST)
    {
        azihsm_pkcs11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (pDigest != NULL_PTR && *pulDigestLen >= azihsm_pkcs11_digest_op_len(s->op_ctx) &&
        ulDataLen > 0)
    {
        azihsm_pkcs11_digest_op_update(s->op_ctx, pData, ulDataLen);
    }
    CK_RV rv = digest_output(s, pDigest, pulDigestLen);
    azihsm_pkcs11_unlock();
    return rv;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pulDigestLen == NULL_PTR)
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
    if (s->op != P11_OP_DIGEST)
    {
        azihsm_pkcs11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    CK_RV rv = digest_output(s, pDigest, pulDigestLen);
    azihsm_pkcs11_unlock();
    return rv;
}
