// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Key-backed operations: C_GenerateKey (CKM_AES_KEY_GEN, CKM_AES_XTS_KEY_GEN)
 * and AES-CBC / AES-CBC-PAD / AES-GCM / AES-XTS encrypt/decrypt, one-shot and
 * multi-part.
 *
 * The AZIHSM device holds keys only as session-scoped handles; the durable form
 * is the opaque masked blob. So C_GenerateKey stores that blob as the object's
 * key body behind the object-store seam, and each C_EncryptInit/C_DecryptInit
 * unmasks it into a fresh device handle owned by the session's operation state
 * (released when the operation ends, wherever it ends — see
 * azihsm_pkcs11_session_reset_op). This file speaks CK_RV only; device calls
 * and status translation live in azihsm_pkcs11_key.c, and the pure template
 * logic (validation, defaults) in azihsm_pkcs11_template.c.
 */

#include "azihsm_pkcs11_internal.h"
#include "azihsm_pkcs11_key.h"
#include "azihsm_pkcs11_template.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* AES_BLOCK_LEN and the GCM/XTS widths come from azihsm_pkcs11_key.h; the key
 * lengths, template constants and mechanism policy from
 * azihsm_pkcs11_template.h. */

/* Turns CKA_VALUE_LEN (bytes) into the device's bit-length key property. */
#define AES_KEY_BITS_PER_BYTE 8

/* The CBC IV and the XTS tweak share one owned buffer in the operation. */
_Static_assert(AES_XTS_TWEAK_LEN <= AES_BLOCK_LEN, "the XTS tweak must fit the IV buffer");

/*
 * Per-operation cipher state (s->op_ctx while op is P11_OP_ENCRYPT/_DECRYPT).
 * Everything the mechanism parameters pointed at is copied in at init: the
 * caller may free its CK_MECHANISM as soon as C_*Init returns.
 */
typedef struct
{
    CK_MECHANISM_TYPE mech;         /* CKM_AES_CBC / _CBC_PAD / _GCM / _XTS */
    uint32_t hsm_key;               /* unmasked device key handle; owned, freed with the op */
    CK_BYTE iv[AES_BLOCK_LEN];      /* CBC IV seed or XTS tweak (owned copy) */
    CK_BYTE gcm_iv[AES_GCM_IV_LEN]; /* GCM IV (owned copy) */
    CK_BYTE *aad;                   /* GCM additional data (owned copy), NULL if none */
    CK_ULONG aad_len;

    /* Multi-part CBC: the SDK stream does the chaining, padding and block
     * buffering; the module keeps only what the PKCS#11 length rules and the
     * two-call convention need. */
    azihsm_pkcs11_aes_cbc_stream_t *cbc;        /* opened by the first multi-part call */
    CK_ULONG cbc_fed_mod;                       /* bytes fed, modulo AES_BLOCK_LEN */
    bool cbc_fed_any;                           /* any byte fed at all */
    bool cbc_finished;                          /* the stream's final call has run */
    CK_BYTE cbc_last[AES_CBC_STREAM_FINAL_MAX]; /* its output, kept until collected */
    CK_ULONG cbc_last_len;

    /* Multi-part GCM / XTS: the input, buffered for the final call. */
    CK_BYTE *buf;
    CK_ULONG buf_len;
    CK_ULONG buf_cap;
} cipher_op;

void azihsm_pkcs11_cipher_op_free(void *op_ctx)
{
    cipher_op *op = (cipher_op *)op_ctx;
    if (op == NULL)
    {
        return;
    }
    /* The stream first: it references the device key. */
    azihsm_pkcs11_key_aes_cbc_stream_free(op->cbc);
    azihsm_pkcs11_key_release(op->hsm_key);
    if (op->aad != NULL)
    {
        azihsm_pkcs11_wipe(op->aad, op->aad_len);
        free(op->aad);
    }
    if (op->buf != NULL)
    {
        azihsm_pkcs11_wipe(op->buf, op->buf_len);
        free(op->buf);
    }
    azihsm_pkcs11_wipe(op, sizeof(*op));
    free(op);
}

/* ========================================================================= */
/* C_GenerateKey (CKM_AES_KEY_GEN, CKM_AES_XTS_KEY_GEN)                      */
/* ========================================================================= */

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
    azihsm_pkcs11_lock();
    azihsm_pkcs11_session_t *s = azihsm_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        azihsm_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    /* Precedence: bad handle, then bad arguments and mechanism, then login
     * state — so a logged-out caller is told about a malformed request rather
     * than about its login. */
    CK_RV rv = CKR_OK;
    if ((pMechanism == NULL_PTR) || (phKey == NULL_PTR) ||
        ((pTemplate == NULL_PTR) && (ulCount > 0)))
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else if ((pMechanism->mechanism != CKM_AES_KEY_GEN) &&
             (pMechanism->mechanism != CKM_AES_XTS_KEY_GEN))
    {
        rv = CKR_MECHANISM_INVALID;
    }
    else if ((pMechanism->pParameter != NULL_PTR) || (pMechanism->ulParameterLen != 0))
    {
        rv = CKR_MECHANISM_PARAM_INVALID;
    }
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_unlock();
        return rv;
    }
    azihsm_pkcs11_slot_t *slot = &g_azihsm_pkcs11.slots[s->slot];
    if (!slot->user_logged_in || (slot->hsm_session == 0))
    {
        azihsm_pkcs11_unlock();
        return CKR_USER_NOT_LOGGED_IN; /* generation runs in the device session */
    }

    const azihsm_pkcs11_keygen_policy *policy = NULL;
    CK_ULONG value_len = 0;
    CK_BBOOL token = CK_FALSE;
    rv = azihsm_pkcs11_keygen_check_template(
        pMechanism->mechanism,
        pTemplate,
        ulCount,
        &policy,
        &value_len,
        &token
    );
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
        policy->kind,
        (uint32_t)(value_len * AES_KEY_BITS_PER_BYTE),
        &blob,
        &blob_len
    );
    if (rv != CKR_OK)
    {
        goto cleanup;
    }

    /* Store the caller's template plus the attributes this token decides (see
     * azihsm_pkcs11_keygen_build_template); `fill` backs the appended values
     * and must live until the store call has copied them. */
    full = (CK_ATTRIBUTE *)malloc((ulCount + KEYGEN_APPENDED_ATTRS) * sizeof(CK_ATTRIBUTE));
    if (full == NULL)
    {
        rv = CKR_HOST_MEMORY;
        goto cleanup;
    }
    azihsm_pkcs11_keygen_fill fill;
    CK_ULONG n = 0;
    rv = azihsm_pkcs11_keygen_build_template(policy, pTemplate, ulCount, &fill, full, &n);
    if (rv != CKR_OK)
    {
        goto cleanup;
    }

    CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
    rv =
        g_azihsm_pkcs11.store.ops->create(g_azihsm_pkcs11.store.ctx, s->slot, CK_TRUE, full, n, &h);
    if (rv != CKR_OK)
    {
        goto cleanup;
    }
    rv = g_azihsm_pkcs11.store.ops
             ->set_key_body(g_azihsm_pkcs11.store.ctx, s->slot, CK_TRUE, h, blob, blob_len);
    if ((rv == CKR_OK) && !token)
    {
        /* A session object dies with this session (the C_CloseSession rule). */
        rv = azihsm_pkcs11_session_own_object(s, h);
    }
    if (rv != CKR_OK)
    {
        /* No half-object: a key object without its masked body, or one the
         * session cannot track, is not handed out. */
        (void)g_azihsm_pkcs11.store.ops->destroy(g_azihsm_pkcs11.store.ctx, s->slot, CK_TRUE, h);
        goto cleanup;
    }
    *phKey = h;
    AZIHSM_PKCS11_LOG(
        "C_GenerateKey: kind %d, %lu bits, obj=%lu (blob %lu bytes)",
        (int)policy->kind,
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
/* AES-CBC / AES-GCM / AES-XTS: init and one-shot encrypt / decrypt          */
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
    azihsm_pkcs11_lock();
    azihsm_pkcs11_session_t *s = azihsm_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        azihsm_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    /* Precedence as in C_GenerateKey — handle, arguments, mechanism, then login
     * state — with the operation-state check between arguments and mechanism,
     * as in C_DigestInit. */
    CK_RV rv = CKR_OK;
    const azihsm_pkcs11_cipher_mech *cm = NULL;
    CK_GCM_PARAMS gcm;
    memset(&gcm, 0, sizeof(gcm));
    if (pMechanism == NULL_PTR)
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else if (s->op != P11_OP_NONE)
    {
        rv = CKR_OPERATION_ACTIVE;
    }
    else if ((cm = azihsm_pkcs11_cipher_mech_find(pMechanism->mechanism)) == NULL)
    {
        rv = CKR_MECHANISM_INVALID;
    }
    else if (cm->mech == CKM_AES_GCM)
    {
        rv = azihsm_pkcs11_gcm_params_check(
            pMechanism->pParameter,
            pMechanism->ulParameterLen,
            &gcm
        );
    }
    else if (cm->mech == CKM_AES_XTS)
    {
        rv = azihsm_pkcs11_xts_tweak_check(pMechanism->pParameter, pMechanism->ulParameterLen);
    }
    else if ((pMechanism->pParameter == NULL_PTR) || (pMechanism->ulParameterLen != AES_BLOCK_LEN))
    {
        rv = CKR_MECHANISM_PARAM_INVALID; /* the raw 16-byte CBC IV */
    }
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_unlock();
        return rv;
    }
    azihsm_pkcs11_slot_t *slot = &g_azihsm_pkcs11.slots[s->slot];
    if (!slot->user_logged_in || (slot->hsm_session == 0))
    {
        azihsm_pkcs11_unlock();
        return CKR_USER_NOT_LOGGED_IN; /* unmasking needs the device session */
    }

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
    if ((rv == CKR_OK) && (kt != cm->key_type))
    {
        rv = CKR_KEY_TYPE_INCONSISTENT;
        goto cleanup;
    }
    /* A GCM key and a CBC key are both CKK_AES; the allowed-mechanism list
     * recorded at generation tells them apart, so a family mismatch is caught
     * here rather than as the device's refusal of a blob unmasked under the
     * wrong kind (a key-handle error). The rules, including keys that predate
     * the list, are in azihsm_pkcs11_key_mech_permitted. */
    CK_MECHANISM_TYPE mechs[KEYGEN_MAX_ALLOWED_MECHS];
    CK_ATTRIBUTE mechs_attr = { CKA_ALLOWED_MECHANISMS, mechs, sizeof(mechs) };
    rv = g_azihsm_pkcs11.store.ops
             ->get_attr(g_azihsm_pkcs11.store.ctx, s->slot, CK_TRUE, hKey, &mechs_attr, 1);
    /* Only an absent or over-long list is a policy verdict; a store failure
     * is reported as itself. */
    if ((rv != CKR_OK) && (rv != CKR_ATTRIBUTE_TYPE_INVALID) && (rv != CKR_BUFFER_TOO_SMALL))
    {
        if (rv == CKR_OBJECT_HANDLE_INVALID)
        {
            rv = CKR_KEY_HANDLE_INVALID;
        }
        goto cleanup;
    }
    if (!azihsm_pkcs11_key_mech_permitted(rv, mechs, mechs_attr.ulValueLen, cm->mech))
    {
        rv = CKR_KEY_FUNCTION_NOT_PERMITTED;
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

    /* Zeroed, so the free on any later failure sees no handle and no AAD. */
    op = (cipher_op *)calloc(1, sizeof(cipher_op));
    if (op == NULL)
    {
        rv = CKR_HOST_MEMORY;
        goto cleanup;
    }
    op->mech = cm->mech;
    if (cm->mech == CKM_AES_GCM)
    {
        memcpy(op->gcm_iv, gcm.pIv, AES_GCM_IV_LEN);
        if (gcm.ulAADLen > 0)
        {
            op->aad = (CK_BYTE *)malloc(gcm.ulAADLen);
            if (op->aad == NULL)
            {
                rv = CKR_HOST_MEMORY;
                goto cleanup;
            }
            memcpy(op->aad, gcm.pAAD, gcm.ulAADLen);
            op->aad_len = gcm.ulAADLen;
        }
    }
    else
    {
        memcpy(op->iv, pMechanism->pParameter, pMechanism->ulParameterLen);
    }
    rv = azihsm_pkcs11_key_aes_unmask(slot->hsm_session, cm->kind, body, body_len, &op->hsm_key);
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
 * The GCM and XTS device half, shared by the one-shot calls and the
 * multi-part final call (which runs it over the input the updates buffered).
 * The output length follows from the input length alone, so sizing needs no
 * device call, and GCM's tag moves between the device's params struct and the
 * end of the PKCS#11 ciphertext here. *active is set when the operation must
 * stay active afterwards: after a sizing probe (out == NULL) or a too-small
 * buffer; every other outcome ends it.
 */
static CK_RV fixed_crypt(
    cipher_op *op,
    bool encrypt,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE_PTR out,
    CK_ULONG_PTR out_len,
    bool *active
)
{
    *active = false;
    CK_ULONG need = 0;
    CK_RV rv = azihsm_pkcs11_cipher_out_len(op->mech, encrypt, in_len, &need);
    if ((rv == CKR_OK) && (op->mech == CKM_AES_GCM) &&
        !azihsm_pkcs11_gcm_fits(op->aad_len, encrypt ? in_len : need))
    {
        rv = encrypt ? CKR_DATA_LEN_RANGE : CKR_ENCRYPTED_DATA_LEN_RANGE;
    }
    if (rv != CKR_OK)
    {
        return rv;
    }

    if (out == NULL_PTR)
    {
        *out_len = need; /* sizing probe: report, keep the operation */
        *active = true;
        return CKR_OK;
    }
    if (*out_len < need)
    {
        *out_len = need;
        *active = true;
        return CKR_BUFFER_TOO_SMALL; /* op stays active for the retry */
    }

    CK_ULONG written = need;
    if (op->mech == CKM_AES_XTS)
    {
        rv = azihsm_pkcs11_key_aes_xts(encrypt, op->hsm_key, op->iv, in, in_len, out, &written);
    }
    else if (op->mech != CKM_AES_GCM)
    {
        rv = CKR_MECHANISM_INVALID; /* unreachable: cipher_out_len admits only GCM and XTS */
    }
    else if (encrypt)
    {
        /* Ciphertext first, then the tag the device handed back appended to
         * it, as PKCS#11 lays out a GCM ciphertext. */
        CK_BYTE tag[AES_GCM_TAG_LEN];
        written = in_len;
        rv = azihsm_pkcs11_key_aes_gcm(
            true,
            op->hsm_key,
            op->gcm_iv,
            op->aad,
            op->aad_len,
            in,
            in_len,
            tag,
            out,
            &written
        );
        if ((rv == CKR_OK) && (written != in_len))
        {
            /* GCM ciphertext is exactly as long as the plaintext; anything
             * else would put the tag at the wrong offset. */
            azihsm_pkcs11_wipe(out, need);
            rv = CKR_FUNCTION_FAILED;
        }
        if (rv == CKR_OK)
        {
            memcpy(out + written, tag, AES_GCM_TAG_LEN);
            written += AES_GCM_TAG_LEN;
        }
    }
    else
    {
        /* The trailing tag is taken out before the call: the plaintext may be
         * written over the very bytes that held it when the buffers overlap. */
        CK_BYTE tag[AES_GCM_TAG_LEN];
        CK_ULONG ct_len = in_len - AES_GCM_TAG_LEN;
        memcpy(tag, in + ct_len, AES_GCM_TAG_LEN);
        written = need;
        rv = azihsm_pkcs11_key_aes_gcm(
            false,
            op->hsm_key,
            op->gcm_iv,
            op->aad,
            op->aad_len,
            in,
            ct_len,
            tag,
            out,
            &written
        );
    }
    *out_len = (rv == CKR_OK) ? written : 0;
    return rv;
}

/*
 * Shared one-shot body. Follows the spec's operation-lifetime rules: a NULL
 * output buffer reports the required length and keeps the operation active, a
 * too-small buffer returns CKR_BUFFER_TOO_SMALL and keeps it active for the
 * retry, and every other outcome — success or any failure, bad arguments
 * included — terminates it. Hence the arguments are checked only once the
 * operation has been found: with no operation there is nothing to terminate,
 * and CKR_OPERATION_NOT_INITIALIZED is the answer.
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
    CK_RV rv = CKR_OK;
    if ((out_len == NULL_PTR) || ((in == NULL_PTR) && (in_len > 0)))
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else if (s->op_mode == P11_OP_MODE_MULTIPART)
    {
        rv = CKR_OPERATION_ACTIVE; /* only C_EncryptFinal / C_DecryptFinal may finish it now */
    }
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_session_reset_op(s);
        azihsm_pkcs11_unlock();
        return rv;
    }
    if ((op->mech == CKM_AES_GCM) || (op->mech == CKM_AES_XTS))
    {
        s->op_mode = P11_OP_MODE_ONESHOT;
        bool active = false;
        rv = fixed_crypt(op, encrypt, in, in_len, out, out_len, &active);
        if (!active)
        {
            azihsm_pkcs11_session_reset_op(s);
        }
        azihsm_pkcs11_unlock();
        return rv;
    }
    bool pad = (op->mech == CKM_AES_CBC_PAD);

    /* The deterministic length policy, host-side (the device would reject
     * these too, but with statuses that don't map to the spec's *_LEN_RANGE).
     * The input length is also range-checked here before it is narrowed to the
     * device buffer's 32-bit length in azihsm_pkcs11_key_aes_cbc. */
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
    /* Recorded so the multi-part calls refuse to join a one-shot operation
     * with CKR_OPERATION_ACTIVE, as the digests do. */
    s->op_mode = P11_OP_MODE_ONESHOT;

    if (!pad && (in_len == 0))
    {
        /* The empty message is a whole number of blocks, but the SDK refuses
         * an unpadded call over no data; the empty result needs no device. */
        *out_len = 0;
        if (out != NULL_PTR)
        {
            azihsm_pkcs11_session_reset_op(s);
        }
        azihsm_pkcs11_unlock();
        return CKR_OK;
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

/* ========================================================================= */
/* Multi-part AES-CBC / AES-GCM / AES-XTS encrypt / decrypt                  */
/* ========================================================================= */

/*
 * CBC streams through the SDK's stream context, which does the chaining, the
 * padding and the block buffering. GCM and XTS cannot: the device runs each as
 * one operation over the whole message, the SDK's GCM decrypt stream takes the
 * tag at init while PKCS#11 appends it to the ciphertext, and its XTS stream
 * wants whole data units of a length fixed at init while a PKCS#11 XTS
 * operation is a single data unit. So their updates buffer the input and the
 * final call runs the one-shot path over it. The OpenSSL provider meets the
 * same SDK constraints (plugins/ossl_prov/src/azihsm_ossl_cipher.c).
 */

/* A multi-part GCM / XTS buffer starts this large and doubles as needed. */
#define MULTIPART_BUF_MIN 256

/* Append `in` to the operation's GCM / XTS buffer. The old copy is wiped
 * rather than realloc'd, since realloc may leave it behind in freed memory. */
static CK_RV buf_append(cipher_op *op, const CK_BYTE *in, CK_ULONG in_len)
{
    if ((op == NULL) || ((in == NULL) && (in_len > 0)) ||
        (in_len > ((CK_ULONG)UINT32_MAX - op->buf_len)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (in_len == 0)
    {
        return CKR_OK;
    }
    CK_ULONG need = op->buf_len + in_len;
    if (need > op->buf_cap)
    {
        CK_ULONG cap = (op->buf_cap < MULTIPART_BUF_MIN) ? MULTIPART_BUF_MIN : op->buf_cap;
        while (cap < need)
        {
            cap = (cap <= (need / 2)) ? (cap * 2) : need;
        }
        CK_BYTE *grown = (CK_BYTE *)malloc(cap);
        if (grown == NULL)
        {
            return CKR_HOST_MEMORY;
        }
        if (op->buf != NULL)
        {
            memcpy(grown, op->buf, op->buf_len);
            azihsm_pkcs11_wipe(op->buf, op->buf_len);
            free(op->buf);
        }
        op->buf = grown;
        op->buf_cap = cap;
    }
    memcpy(op->buf + op->buf_len, in, in_len);
    op->buf_len = need;
    return CKR_OK;
}

static CK_RV cbc_open(cipher_op *op, bool encrypt)
{
    if (op->cbc != NULL)
    {
        return CKR_OK;
    }
    return azihsm_pkcs11_key_aes_cbc_stream_new(
        encrypt,
        op->mech == CKM_AES_CBC_PAD,
        op->hsm_key,
        op->iv,
        &op->cbc
    );
}

/*
 * The mechanism halves of cipher_update and cipher_final, called with the lock
 * held, the operation found and the arguments judged. Each sets *active when
 * the operation stays active afterwards; the caller ends it otherwise.
 */

static CK_RV cbc_update(
    cipher_op *op,
    bool encrypt,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE_PTR out,
    CK_ULONG_PTR out_len,
    bool *active
)
{
    *active = false;
    if (op->cbc_finished)
    {
        return CKR_OPERATION_ACTIVE; /* the final call has run; only its retry may follow */
    }
    if (in_len > AES_CBC_STREAM_MAX_PART)
    {
        return encrypt ? CKR_DATA_LEN_RANGE : CKR_ENCRYPTED_DATA_LEN_RANGE;
    }
    if (out == NULL_PTR)
    {
        /* The SDK's sizing call runs the update whenever no output is due, so
         * a sizing probe never reaches it. PKCS#11 lets the probe report an
         * upper bound: the stream releases at most the block it holds back
         * plus the new input, in whole blocks. */
        *out_len = ((in_len / AES_BLOCK_LEN) + 1) * AES_BLOCK_LEN;
        *active = true;
        return CKR_OK;
    }
    CK_RV rv = cbc_open(op, encrypt);
    if (rv == CKR_OK)
    {
        rv = azihsm_pkcs11_key_aes_cbc_stream_update(op->cbc, in, in_len, out, out_len);
    }
    if (rv == CKR_BUFFER_TOO_SMALL)
    {
        *active = true; /* nothing was consumed */
        return rv;
    }
    if (rv != CKR_OK)
    {
        *out_len = 0;
        return rv;
    }
    op->cbc_fed_mod = (op->cbc_fed_mod + (in_len % AES_BLOCK_LEN)) % AES_BLOCK_LEN;
    op->cbc_fed_any = op->cbc_fed_any || (in_len > 0);
    *active = true;
    return CKR_OK;
}

static CK_RV cbc_final(
    cipher_op *op,
    bool encrypt,
    CK_BYTE_PTR out,
    CK_ULONG_PTR out_len,
    bool *active
)
{
    *active = false;
    if (!op->cbc_finished)
    {
        bool run = false;
        CK_RV rv = azihsm_pkcs11_cbc_final_check(
            encrypt,
            op->mech == CKM_AES_CBC_PAD,
            op->cbc_fed_mod,
            op->cbc_fed_any,
            &run
        );
        if (rv != CKR_OK)
        {
            return rv;
        }
        if (out == NULL_PTR)
        {
            /* Finishing the stream cannot be undone, so only a call with a
             * buffer runs it; a probe before that gets the most it can write. */
            *out_len = run ? AES_CBC_STREAM_FINAL_MAX : 0;
            *active = true;
            return CKR_OK;
        }
        if (run)
        {
            CK_ULONG n = sizeof(op->cbc_last);
            rv = cbc_open(op, encrypt);
            if (rv == CKR_OK)
            {
                rv = azihsm_pkcs11_key_aes_cbc_stream_final(op->cbc, op->cbc_last, &n);
            }
            if (rv != CKR_OK)
            {
                *out_len = 0;
                return rv;
            }
            op->cbc_last_len = n;
        }
        /* Kept until collected: the SDK wants more room than a padded decrypt
         * returns, and a too-small caller buffer must be able to retry. */
        op->cbc_finished = true;
    }
    if (out == NULL_PTR)
    {
        *out_len = op->cbc_last_len;
        *active = true;
        return CKR_OK;
    }
    if (*out_len < op->cbc_last_len)
    {
        *out_len = op->cbc_last_len;
        *active = true;
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(out, op->cbc_last, op->cbc_last_len);
    *out_len = op->cbc_last_len;
    return CKR_OK;
}

static CK_RV fixed_update(
    cipher_op *op,
    bool encrypt,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE_PTR out,
    CK_ULONG_PTR out_len,
    bool *active
)
{
    *active = false;
    /* buf_len never passes 32 bits (multipart_fits), which makes the first
     * test the overflow guard for the sum. */
    if ((in_len > ((CK_ULONG)UINT32_MAX - op->buf_len)) ||
        !azihsm_pkcs11_multipart_fits(op->mech, encrypt, op->aad_len, op->buf_len + in_len))
    {
        return encrypt ? CKR_DATA_LEN_RANGE : CKR_ENCRYPTED_DATA_LEN_RANGE;
    }
    /* Nothing comes out before the final call, which also keeps a GCM decrypt
     * from releasing plaintext before its tag is checked. */
    *out_len = 0;
    if (out == NULL_PTR)
    {
        *active = true; /* a sizing probe consumes nothing */
        return CKR_OK;
    }
    CK_RV rv = buf_append(op, in, in_len);
    *active = (rv == CKR_OK);
    return rv;
}

/*
 * Shared C_EncryptUpdate / C_DecryptUpdate body. Same lifetime rules as
 * cipher_oneshot, plus the mode rule: a one-shot call in progress refuses the
 * multi-part calls, and the other way round.
 */
static CK_RV cipher_update(
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
    bool active = false;
    CK_RV rv = CKR_OK;
    if ((out_len == NULL_PTR) || ((in == NULL_PTR) && (in_len > 0)))
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else if (s->op_mode == P11_OP_MODE_ONESHOT)
    {
        rv = CKR_OPERATION_ACTIVE; /* a one-shot call is in progress */
    }
    else
    {
        s->op_mode = P11_OP_MODE_MULTIPART;
        rv = ((op->mech == CKM_AES_GCM) || (op->mech == CKM_AES_XTS))
                 ? fixed_update(op, encrypt, in, in_len, out, out_len, &active)
                 : cbc_update(op, encrypt, in, in_len, out, out_len, &active);
    }
    if (!active)
    {
        azihsm_pkcs11_session_reset_op(s);
    }
    azihsm_pkcs11_unlock();
    return rv;
}

/* Shared C_EncryptFinal / C_DecryptFinal body; lifetime rules as above. */
static CK_RV cipher_final(
    CK_SESSION_HANDLE hSession,
    bool encrypt,
    CK_BYTE_PTR out,
    CK_ULONG_PTR out_len
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
    azihsm_pkcs11_op_type_t want = encrypt ? P11_OP_ENCRYPT : P11_OP_DECRYPT;
    if ((s->op != want) || (s->op_ctx == NULL))
    {
        azihsm_pkcs11_unlock();
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    cipher_op *op = (cipher_op *)s->op_ctx;
    bool active = false;
    CK_RV rv = CKR_OK;
    if (out_len == NULL_PTR)
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else if (s->op_mode == P11_OP_MODE_ONESHOT)
    {
        rv = CKR_OPERATION_ACTIVE; /* a one-shot call is in progress */
    }
    else
    {
        /* Straight after the init this is the (allowed) zero-part case. */
        s->op_mode = P11_OP_MODE_MULTIPART;
        rv = ((op->mech == CKM_AES_GCM) || (op->mech == CKM_AES_XTS))
                 ? fixed_crypt(op, encrypt, op->buf, op->buf_len, out, out_len, &active)
                 : cbc_final(op, encrypt, out, out_len, &active);
    }
    if (!active)
    {
        azihsm_pkcs11_session_reset_op(s);
    }
    azihsm_pkcs11_unlock();
    return rv;
}

CK_RV C_EncryptUpdate(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen
)
{
    return cipher_update(hSession, true, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
}

CK_RV C_EncryptFinal(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastEncryptedPart,
    CK_ULONG_PTR pulLastEncryptedPartLen
)
{
    return cipher_final(hSession, true, pLastEncryptedPart, pulLastEncryptedPartLen);
}

CK_RV C_DecryptUpdate(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen
)
{
    return cipher_update(hSession, false, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
    return cipher_final(hSession, false, pLastPart, pulLastPartLen);
}
