// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Session lifecycle, login, the object entry points (which delegate to the
 * object-store seam), and one host-side digest (SHA-256). The digest needs no
 * partition provisioning, so it is the operation the validation tools can drive
 * end-to-end while the key-backed mechanisms are still unimplemented.
 */

#include "p11_hsm.h"
#include "p11_internal.h"

#include <stdlib.h>

/* ========================================================================= */
/* SHA-256 (host-side)                                                       */
/*                                                                           */
/* A minimal, self-contained FIPS 180-4 implementation so the digest path    */
/* links no libcrypto (keeping the no-device build dependency-free).         */
/* ========================================================================= */

typedef struct
{
    uint32_t h[8];
    uint64_t len; /* total bytes */
    uint8_t buf[64];
    size_t buflen;
} sha256_ctx;

static uint32_t ror(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static void sha256_init(sha256_ctx *c)
{
    static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memcpy(c->h, iv, sizeof(iv));
    c->len = 0;
    c->buflen = 0;
}

static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2
    };
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
    {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | ((uint32_t)p[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++)
    {
        uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint32_t e = c->h[4], f = c->h[5], g = c->h[6], hh = c->h[7];
    for (int i = 0; i < 64; i++)
    {
        uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + S1 + ch + k[i] + w[i];
        uint32_t S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += hh;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t n)
{
    c->len += n;
    while (n > 0)
    {
        size_t take = 64 - c->buflen;
        if (take > n)
        {
            take = n;
        }
        memcpy(c->buf + c->buflen, data, take);
        c->buflen += take;
        data += take;
        n -= take;
        if (c->buflen == 64)
        {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56)
    {
        sha256_update(c, &zero, 1);
    }
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++)
    {
        lenb[i] = (uint8_t)(bits >> (56 - i * 8));
    }
    sha256_update(c, lenb, 8);
    for (int i = 0; i < 8; i++)
    {
        out[i * 4] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

/* ========================================================================= */
/* Operation state                                                           */
/* ========================================================================= */

CK_RV p11_session_reset_op(p11_session_t *s)
{
    if (s->op == P11_OP_DIGEST && s->op_ctx != NULL)
    {
        free(s->op_ctx);
    }
    s->op_ctx = NULL;
    if (s->op == P11_OP_FIND && s->find_cursor != NULL)
    {
        g_p11.store.ops->find_final(g_p11.store.ctx, s->find_cursor);
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
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (phSession == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (slotID >= g_p11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    if ((flags & CKF_SERIAL_SESSION) == 0)
    {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    p11_lock();
    /* An RO session may not be opened while the SO is logged in. */
    if ((flags & CKF_RW_SESSION) == 0 && g_p11.slots[slotID].so_logged_in)
    {
        p11_unlock();
        return CKR_SESSION_READ_WRITE_SO_EXISTS;
    }
    p11_session_t *s = NULL;
    for (size_t i = 0; i < AZIHSM_P11_MAX_SESSIONS; i++)
    {
        if (!g_p11.sessions[i].in_use)
        {
            s = &g_p11.sessions[i];
            break;
        }
    }
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_COUNT;
    }
    memset(s, 0, sizeof(*s));
    s->in_use = true;
    s->handle = g_p11.next_session_handle++;
    s->slot = slotID;
    s->flags = flags;
    s->app = pApplication;
    s->notify = Notify;
    s->op = P11_OP_NONE;
    *phSession = s->handle;
    p11_unlock();
    return CKR_OK;
}

static bool slot_has_sessions(CK_SLOT_ID slot)
{
    for (size_t i = 0; i < AZIHSM_P11_MAX_SESSIONS; i++)
    {
        if (g_p11.sessions[i].in_use && g_p11.sessions[i].slot == slot)
        {
            return true;
        }
    }
    return false;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    CK_SLOT_ID slot_id = s->slot;
    p11_session_reset_op(s);
    s->in_use = false;
    /* The HSM login is token-wide: close it only when the last session on the
     * slot goes away, not whenever any one session closes. */
    if (!slot_has_sessions(slot_id))
    {
        p11_slot_t *slot = &g_p11.slots[slot_id];
        p11_hsm_logout(slot->hsm_session);
        slot->hsm_session = 0;
        slot->user_logged_in = false;
        slot->so_logged_in = false;
    }
    p11_unlock();
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (slotID >= g_p11.slot_count)
    {
        return CKR_SLOT_ID_INVALID;
    }
    p11_lock();
    for (size_t i = 0; i < AZIHSM_P11_MAX_SESSIONS; i++)
    {
        if (g_p11.sessions[i].in_use && g_p11.sessions[i].slot == slotID)
        {
            p11_session_reset_op(&g_p11.sessions[i]);
            g_p11.sessions[i].in_use = false;
        }
    }
    p11_slot_t *slot = &g_p11.slots[slotID];
    p11_hsm_logout(slot->hsm_session);
    slot->hsm_session = 0;
    slot->user_logged_in = false;
    slot->so_logged_in = false;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pInfo == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    p11_slot_t *slot = &g_p11.slots[s->slot];
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
    p11_unlock();
    return CKR_OK;
}

CK_RV C_Login(
    CK_SESSION_HANDLE hSession,
    CK_USER_TYPE userType,
    CK_UTF8CHAR_PTR pPin,
    CK_ULONG ulPinLen
)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    p11_slot_t *slot = &g_p11.slots[s->slot];
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
            (ulPinLen < AZIHSM_P11_MIN_PIN_LEN || ulPinLen > AZIHSM_P11_MAX_PIN_LEN))
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
        rv = p11_hsm_login(s->slot, pPin, ulPinLen, &hs);
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
    p11_unlock();
    return rv;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    p11_slot_t *slot = &g_p11.slots[s->slot];
    if (!slot->user_logged_in && !slot->so_logged_in)
    {
        p11_unlock();
        return CKR_USER_NOT_LOGGED_IN;
    }
    /* Login is token-wide, so log the token out regardless of which session
     * calls C_Logout — including one that never called C_Login itself. */
    p11_hsm_logout(slot->hsm_session);
    slot->hsm_session = 0;
    slot->user_logged_in = false;
    slot->so_logged_in = false;
    p11_unlock();
    return CKR_OK;
}

/* ========================================================================= */
/* Objects (delegated to the object-store seam)                              */
/*                                                                           */
/* Each entry point validates its arguments and session, then hands off to   */
/* g_p11.store; slot isolation and private-object login-gating are enforced  */
/* by the store (see p11_objstore.h).                                        */
/* ========================================================================= */

CK_RV C_CreateObject(
    CK_SESSION_HANDLE hSession,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phObject
)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (phObject == NULL_PTR || (pTemplate == NULL_PTR && ulCount > 0))
    {
        return CKR_ARGUMENTS_BAD;
    }
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    CK_BBOOL logged_in = g_p11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    CK_RV rv =
        g_p11.store.ops->create(g_p11.store.ctx, s->slot, logged_in, pTemplate, ulCount, phObject);
    p11_unlock();
    return rv;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    CK_BBOOL logged_in = g_p11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    CK_RV rv = g_p11.store.ops->destroy(g_p11.store.ctx, s->slot, logged_in, hObject);
    p11_unlock();
    return rv;
}

CK_RV C_GetAttributeValue(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount
)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pTemplate == NULL_PTR && ulCount > 0)
    {
        return CKR_ARGUMENTS_BAD;
    }
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    CK_BBOOL logged_in = g_p11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    CK_RV rv =
        g_p11.store.ops->get_attr(g_p11.store.ctx, s->slot, logged_in, hObject, pTemplate, ulCount);
    p11_unlock();
    return rv;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pTemplate == NULL_PTR && ulCount > 0)
    {
        return CKR_ARGUMENTS_BAD;
    }
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->op != P11_OP_NONE)
    {
        p11_unlock();
        return CKR_OPERATION_ACTIVE;
    }
    CK_BBOOL logged_in = g_p11.slots[s->slot].user_logged_in ? CK_TRUE : CK_FALSE;
    CK_RV rv =
        g_p11.store.ops
            ->find_init(g_p11.store.ctx, s->slot, logged_in, pTemplate, ulCount, &s->find_cursor);
    if (rv == CKR_OK)
    {
        s->op = P11_OP_FIND;
    }
    p11_unlock();
    return rv;
}

CK_RV C_FindObjects(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE_PTR phObject,
    CK_ULONG ulMaxObjectCount,
    CK_ULONG_PTR pulObjectCount
)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (phObject == NULL_PTR || pulObjectCount == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->op != P11_OP_FIND)
    {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    CK_RV rv =
        g_p11.store.ops
            ->find(g_p11.store.ctx, s->find_cursor, phObject, ulMaxObjectCount, pulObjectCount);
    p11_unlock();
    return rv;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->op != P11_OP_FIND)
    {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    p11_session_reset_op(s);
    p11_unlock();
    return CKR_OK;
}

/* ========================================================================= */
/* Digest (host-side SHA-256)                                                */
/* ========================================================================= */

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pMechanism == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->op != P11_OP_NONE)
    {
        p11_unlock();
        return CKR_OPERATION_ACTIVE;
    }
    if (pMechanism->mechanism != CKM_SHA256)
    {
        p11_unlock();
        return CKR_MECHANISM_INVALID;
    }
    sha256_ctx *ctx = (sha256_ctx *)malloc(sizeof(sha256_ctx));
    if (ctx == NULL)
    {
        p11_unlock();
        return CKR_HOST_MEMORY;
    }
    sha256_init(ctx);
    s->op_ctx = ctx;
    s->op = P11_OP_DIGEST;
    p11_unlock();
    return CKR_OK;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (ulPartLen > 0 && pPart == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->op != P11_OP_DIGEST)
    {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ulPartLen > 0)
    {
        sha256_update((sha256_ctx *)s->op_ctx, pPart, ulPartLen);
    }
    p11_unlock();
    return CKR_OK;
}

static CK_RV digest_output(p11_session_t *s, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    if (pDigest == NULL_PTR)
    {
        *pulDigestLen = 32; /* two-call: report length, keep op active */
        return CKR_OK;
    }
    if (*pulDigestLen < 32)
    {
        *pulDigestLen = 32;
        return CKR_BUFFER_TOO_SMALL; /* op stays active for retry */
    }
    uint8_t out[32];
    sha256_final((sha256_ctx *)s->op_ctx, out);
    memcpy(pDigest, out, 32);
    *pulDigestLen = 32;
    p11_session_reset_op(s);
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
    if (!g_p11.initialized)
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
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->op != P11_OP_DIGEST)
    {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (pDigest != NULL_PTR && *pulDigestLen >= 32 && ulDataLen > 0)
    {
        sha256_update((sha256_ctx *)s->op_ctx, pData, ulDataLen);
    }
    CK_RV rv = digest_output(s, pDigest, pulDigestLen);
    p11_unlock();
    return rv;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    if (!g_p11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pulDigestLen == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    p11_lock();
    p11_session_t *s = p11_session_lookup(hSession);
    if (s == NULL)
    {
        p11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (s->op != P11_OP_DIGEST)
    {
        p11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    CK_RV rv = digest_output(s, pDigest, pulDigestLen);
    p11_unlock();
    return rv;
}
