// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <stdint.h>
#include <string.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_hsm.h"
#include "azihsm_ossl_skeymgmt.h"

/*
 * AES Cipher (CBC / GCM / XTS) Implementation
 *
 * Keys are delivered exclusively through the OpenSSL 3.5 EVP_SKEY API: the
 * cipher's *_skey_init hooks receive an AZIHSM_SKEY (an opaque HSM key handle)
 * produced by the AES SKEYMGMT in the same provider.  Raw-key init is rejected,
 * so no key material is ever handed to the cipher.
 *
 * Output is split to match the EVP contract: a block cipher may emit at
 * cipher_final(), a stream cipher (block size 1) cannot.
 * - CBC (block size 16): streamed through the HSM, padded final block at final
 * - GCM/XTS: one-shot in the (single) data update; final emits nothing
 */

/* Opaque-key cipher mode discriminator. */
typedef enum
{
    AZIHSM_CIPHER_MODE_CBC = 0,
    AZIHSM_CIPHER_MODE_GCM,
    AZIHSM_CIPHER_MODE_XTS,
} AZIHSM_CIPHER_MODE_KIND;

typedef struct
{
    AZIHSM_OSSL_PROV_CTX *provctx;

    /* Static per-variant configuration (set by newctx). */
    AZIHSM_CIPHER_MODE_KIND mode;  /* CBC / GCM / XTS                       */
    unsigned int evp_mode;         /* EVP_CIPH_*_MODE (for get_params)      */
    azihsm_key_kind expected_kind; /* SKEY kind this cipher accepts         */
    size_t keylen;                 /* advertised key length (bytes)         */
    size_t ivlen;                  /* IV length (bytes): CBC/XTS 16, GCM 12 */

    /* Bound at *_skey_init (handle is owned by the EVP_SKEY, not by us). */
    azihsm_handle key_handle;
    bool have_key;
    int enc; /* 1 encrypt, 0 decrypt, -1 uninitialised */

    /* IV / tweak. */
    unsigned char iv[16];
    bool have_iv;

    /* CBC.  Encryption is provider-driven (no-pad blocks + an explicit pad
     * block at final): the HSM's padded streaming would emit two blocks at
     * finish() for block-aligned input, which EVP's one-block final cannot
     * accept.  Decryption streams through the HSM directly. */
    int pad;                  /* PKCS#7 padding flag           */
    azihsm_handle stream_ctx; /* HSM streaming ctx (decrypt)   */
    bool stream_active;
    struct azihsm_algo_aes_cbc_params cbc_params; /* IV chain (enc) / writeback    */
    bool cbc_iv_init;                             /* cbc_params.iv seeded          */
    unsigned char part[16];                       /* pending plaintext (< 1 block) */
    size_t part_len;

    /* GCM */
    unsigned char tag[AZIHSM_AES_GCM_TAG_SIZE];
    bool tag_set;   /* caller supplied a tag (decrypt)        */
    bool tag_avail; /* a tag has been produced (encrypt)      */
    unsigned char *aad;
    size_t aad_len;

    /* GCM/XTS: guards against multi-call one-shot misuse. */
    bool oneshot_done;
} AZIHSM_CIPHER_CTX;

/* Context management */

static void *azihsm_ossl_cipher_newctx_common(
    void *provctx,
    AZIHSM_CIPHER_MODE_KIND mode,
    unsigned int evp_mode,
    azihsm_key_kind expected_kind,
    size_t keylen,
    size_t ivlen
)
{
    AZIHSM_CIPHER_CTX *ctx;

    /* Lazy HSM session open (must not happen in query_operation). */
    if (azihsm_ensure_session((AZIHSM_OSSL_PROV_CTX *)provctx) != AZIHSM_STATUS_SUCCESS)
    {
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(AZIHSM_CIPHER_CTX));
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = (AZIHSM_OSSL_PROV_CTX *)provctx;
    ctx->mode = mode;
    ctx->evp_mode = evp_mode;
    ctx->expected_kind = expected_kind;
    ctx->keylen = keylen;
    ctx->ivlen = ivlen;
    ctx->enc = -1;
    ctx->pad = 1; /* OpenSSL default is padding enabled */

    return ctx;
}

static void azihsm_ossl_cipher_freectx(void *vctx)
{
    AZIHSM_CIPHER_CTX *ctx = (AZIHSM_CIPHER_CTX *)vctx;

    if (ctx == NULL)
    {
        return;
    }

    /* Release the streaming HSM context (no-op if inactive). */
    azihsm_ossl_release_hsm_ctx(&ctx->stream_ctx);

    if (ctx->aad != NULL)
    {
        OPENSSL_clear_free(ctx->aad, ctx->aad_len);
    }

    /* key_handle is owned by the EVP_SKEY; do NOT delete it here. */
    OPENSSL_clear_free(ctx, sizeof(AZIHSM_CIPHER_CTX));
}

static void *azihsm_ossl_cipher_dupctx(void *vctx)
{
    AZIHSM_CIPHER_CTX *src = (AZIHSM_CIPHER_CTX *)vctx;
    AZIHSM_CIPHER_CTX *dst;

    if (src == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    /* A context that has begun processing carries state that cannot be cloned
     * faithfully: CBC's chaining IV + buffered sub-block, an open HSM streaming
     * context (decrypt), accumulated GCM AAD, or a completed one-shot.  Rather
     * than emit a half-copied (and therefore wrong) duplicate, refuse to dup once
     * any data has been fed; duplicating a freshly-initialised context is fine. */
    if (src->cbc_iv_init || src->part_len != 0 || src->stream_active || src->oneshot_done ||
        src->aad != NULL)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_NOT_SUPPORTED,
            "cannot duplicate a cipher context after data processing has begun"
        );
        return NULL;
    }

    dst = OPENSSL_zalloc(sizeof(AZIHSM_CIPHER_CTX));
    if (dst == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* Copy configuration + key binding + IV + any pre-set GCM tag.  Reachable
     * only before data processing (see the guard above), so there is no in-flight
     * CBC chain, AAD, or streaming context to carry over. */
    dst->provctx = src->provctx;
    dst->mode = src->mode;
    dst->evp_mode = src->evp_mode;
    dst->expected_kind = src->expected_kind;
    dst->keylen = src->keylen;
    dst->ivlen = src->ivlen;
    dst->key_handle = src->key_handle;
    dst->have_key = src->have_key;
    dst->enc = src->enc;
    dst->pad = src->pad;
    dst->have_iv = src->have_iv;
    memcpy(dst->iv, src->iv, sizeof(dst->iv));
    memcpy(dst->tag, src->tag, sizeof(dst->tag));
    dst->tag_set = src->tag_set;
    dst->tag_avail = src->tag_avail;

    /* Fresh streaming/one-shot state. */
    dst->stream_ctx = 0;
    dst->stream_active = false;
    dst->aad = NULL;
    dst->aad_len = 0;
    dst->oneshot_done = false;

    return dst;
}

/* Key binding (EVP_SKEY) — OpenSSL 3.5+ only */

#if OPENSSL_VERSION_NUMBER >= 0x30500000L

/* Forward declaration */
static int azihsm_ossl_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int azihsm_ossl_cipher_skey_init(
    void *vctx,
    void *skeydata,
    const unsigned char *iv,
    size_t ivlen,
    const OSSL_PARAM params[],
    int enc
)
{
    AZIHSM_CIPHER_CTX *ctx = (AZIHSM_CIPHER_CTX *)vctx;
    AZIHSM_SKEY *skey = (AZIHSM_SKEY *)skeydata;

    if (ctx == NULL || skey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* The opaque key must match the cipher's mode/kind. */
    if (skey->key_kind != ctx->expected_kind)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_KEY,
            "AES key kind does not match the requested cipher"
        );
        return OSSL_FAILURE;
    }

    /* When the key length is known, it must match the cipher variant so that, for
     * example, an AES-256 key cannot be bound to AES-128-CBC.  Imported opaque
     * keys may report 0 (unknown), in which case this check is skipped. */
    if (skey->key_bytes != 0 && skey->key_bytes != ctx->keylen)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_KEY_LENGTH,
            "AES key length does not match the requested cipher"
        );
        return OSSL_FAILURE;
    }

    /* Re-init: drop every per-operation state so a reused EVP_CIPHER_CTX starts
     * clean — no stale CBC chaining IV / buffered sub-block, and no carried-over
     * GCM tag or IV from the previous operation. */
    azihsm_ossl_release_hsm_ctx(&ctx->stream_ctx);
    ctx->stream_active = false;
    ctx->oneshot_done = false;
    ctx->have_iv = false;
    ctx->tag_avail = false;
    ctx->tag_set = false;
    ctx->cbc_iv_init = false;
    ctx->part_len = 0;
    OPENSSL_cleanse(ctx->part, sizeof(ctx->part));
    if (ctx->aad != NULL)
    {
        OPENSSL_clear_free(ctx->aad, ctx->aad_len);
        ctx->aad = NULL;
        ctx->aad_len = 0;
    }

    ctx->key_handle = skey->key_handle;
    ctx->have_key = true;
    ctx->enc = enc;

    if (iv != NULL)
    {
        if (ivlen != ctx->ivlen)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return OSSL_FAILURE;
        }
        memcpy(ctx->iv, iv, ivlen);
        ctx->have_iv = true;
    }
    else
    {
        /* Every mode binds its IV/nonce/tweak at init; this provider exposes no
         * post-init IV-setting parameter, so a missing IV is unrecoverable.  For
         * GCM in particular, proceeding with an unset (all-zero) nonce would be a
         * silent nonce-reuse hazard, so reject it here rather than fail open. */
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
        return OSSL_FAILURE;
    }

    if (params != NULL && !azihsm_ossl_cipher_set_ctx_params(ctx, params))
    {
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_cipher_encrypt_skey_init(
    void *vctx,
    void *skeydata,
    const unsigned char *iv,
    size_t ivlen,
    const OSSL_PARAM params[]
)
{
    return azihsm_ossl_cipher_skey_init(vctx, skeydata, iv, ivlen, params, 1);
}

static int azihsm_ossl_cipher_decrypt_skey_init(
    void *vctx,
    void *skeydata,
    const unsigned char *iv,
    size_t ivlen,
    const OSSL_PARAM params[]
)
{
    return azihsm_ossl_cipher_skey_init(vctx, skeydata, iv, ivlen, params, 0);
}

#define AZIHSM_CIPHER_SKEY_DISPATCH                                                                \
    { OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT, (void (*)(void))azihsm_ossl_cipher_encrypt_skey_init },  \
        { OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT,                                                      \
          (void (*)(void))azihsm_ossl_cipher_decrypt_skey_init },

#else /* OpenSSL < 3.5: no EVP_SKEY support */

#define AZIHSM_CIPHER_SKEY_DISPATCH

#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

/* Raw-key init — refused: this provider only accepts opaque EVP_SKEY keys. */

static int azihsm_ossl_cipher_encrypt_init(
    ossl_unused void *cctx,
    ossl_unused const unsigned char *key,
    ossl_unused size_t keylen,
    ossl_unused const unsigned char *iv,
    ossl_unused size_t ivlen,
    ossl_unused const OSSL_PARAM params[]
)
{
    ERR_raise_data(
        ERR_LIB_PROV,
        PROV_R_NOT_SUPPORTED,
        "raw key init is not supported; bind an opaque EVP_SKEY (EVP_CipherInit_SKEY)"
    );
    return OSSL_FAILURE;
}

static int azihsm_ossl_cipher_decrypt_init(
    ossl_unused void *cctx,
    ossl_unused const unsigned char *key,
    ossl_unused size_t keylen,
    ossl_unused const unsigned char *iv,
    ossl_unused size_t ivlen,
    ossl_unused const OSSL_PARAM params[]
)
{
    ERR_raise_data(
        ERR_LIB_PROV,
        PROV_R_NOT_SUPPORTED,
        "raw key init is not supported; bind an opaque EVP_SKEY (EVP_CipherInit_SKEY)"
    );
    return OSSL_FAILURE;
}

/* CBC streaming helpers */

/* Seed the chaining IV from the bound IV exactly once. */
static void azihsm_ossl_cbc_seed_iv(AZIHSM_CIPHER_CTX *ctx)
{
    if (!ctx->cbc_iv_init)
    {
        memcpy(ctx->cbc_params.iv, ctx->iv, sizeof(ctx->cbc_params.iv));
        ctx->cbc_iv_init = true;
    }
}

/* One-shot, no-padding CBC encryption of a block-aligned buffer.  The HSM
 * updates cbc_params.iv to the last ciphertext block, so successive calls
 * continue the CBC chain. */
static int azihsm_ossl_cbc_encrypt_blocks(
    AZIHSM_CIPHER_CTX *ctx,
    const unsigned char *in,
    size_t inl,
    unsigned char *out,
    size_t outsize,
    size_t *written
)
{
    struct azihsm_algo algo;
    struct azihsm_buffer in_buf;
    struct azihsm_buffer out_buf;
    azihsm_status status;

    *written = 0;
    if (inl == 0)
    {
        return OSSL_SUCCESS;
    }
    /* No-padding CBC does not expand: the ciphertext length equals the input
     * length, and the azihsm FFI requires the output buffer length to be
     * exactly that (not merely large enough). */
    if (inl > UINT32_MAX || outsize < inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return OSSL_FAILURE;
    }

    algo.id = AZIHSM_ALGO_ID_AES_CBC; /* no padding: provider adds it at final */
    algo.params = &ctx->cbc_params;
    algo.len = (uint32_t)sizeof(ctx->cbc_params);

    in_buf.ptr = (void *)(uintptr_t)in;
    in_buf.len = (uint32_t)inl;
    out_buf.ptr = out;
    out_buf.len = (uint32_t)inl;

    status = azihsm_crypt_encrypt(&algo, ctx->key_handle, &in_buf, &out_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    *written = (size_t)out_buf.len;
    return OSSL_SUCCESS;
}

/* Provider-driven CBC encryption update: emit complete blocks, retain a
 * sub-block remainder for the padding step at final(). */
static int azihsm_ossl_cbc_encrypt_update(
    AZIHSM_CIPHER_CTX *ctx,
    unsigned char *out,
    size_t *outl,
    size_t outsize,
    const unsigned char *in,
    size_t inl
)
{
    size_t produced = 0;
    size_t w = 0;

    if (!ctx->have_iv)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
        return OSSL_FAILURE;
    }
    azihsm_ossl_cbc_seed_iv(ctx);

    /* Complete a pending partial block from the new input. */
    if (ctx->part_len > 0 && inl > 0)
    {
        size_t need = sizeof(ctx->part) - ctx->part_len;
        if (inl >= need)
        {
            unsigned char block[16];
            memcpy(block, ctx->part, ctx->part_len);
            memcpy(block + ctx->part_len, in, need);
            if (!azihsm_ossl_cbc_encrypt_blocks(ctx, block, sizeof(block), out, outsize, &w))
            {
                return OSSL_FAILURE;
            }
            produced += w;
            in += need;
            inl -= need;
            ctx->part_len = 0;
        }
        else
        {
            memcpy(ctx->part + ctx->part_len, in, inl);
            ctx->part_len += inl;
            *outl = produced;
            return OSSL_SUCCESS;
        }
    }

    /* Encrypt the block-aligned bulk directly from the input. */
    if (inl >= sizeof(ctx->part))
    {
        size_t bulk = inl - (inl % sizeof(ctx->part));
        if (!azihsm_ossl_cbc_encrypt_blocks(ctx, in, bulk, out + produced, outsize - produced, &w))
        {
            return OSSL_FAILURE;
        }
        produced += w;
        in += bulk;
        inl -= bulk;
    }

    /* Stash the remaining sub-block. */
    if (inl > 0)
    {
        memcpy(ctx->part + ctx->part_len, in, inl);
        ctx->part_len += inl;
    }

    *outl = produced;
    return OSSL_SUCCESS;
}

/* Provider-driven CBC encryption final: emit at most one (padding) block. */
static int azihsm_ossl_cbc_encrypt_final(
    AZIHSM_CIPHER_CTX *ctx,
    unsigned char *out,
    size_t *outl,
    size_t outsize
)
{
    unsigned char block[16];
    size_t pad;
    size_t w = 0;

    azihsm_ossl_cbc_seed_iv(ctx);

    if (!ctx->pad)
    {
        if (ctx->part_len != 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            return OSSL_FAILURE;
        }
        *outl = 0;
        return OSSL_SUCCESS;
    }

    /* PKCS#7: pad the remainder up to a full block (a full block when empty). */
    pad = sizeof(block) - ctx->part_len;
    memcpy(block, ctx->part, ctx->part_len);
    memset(block + ctx->part_len, (int)pad, pad);

    if (!azihsm_ossl_cbc_encrypt_blocks(ctx, block, sizeof(block), out, outsize, &w))
    {
        return OSSL_FAILURE;
    }
    ctx->part_len = 0;
    *outl = w;
    return OSSL_SUCCESS;
}

/* Lazily open the HSM streaming context for CBC decryption. */
static int azihsm_ossl_cbc_decrypt_ensure_stream(AZIHSM_CIPHER_CTX *ctx)
{
    struct azihsm_algo algo;
    azihsm_status status;

    if (ctx->stream_active)
    {
        return OSSL_SUCCESS;
    }
    if (!ctx->have_key || !ctx->have_iv)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
        return OSSL_FAILURE;
    }

    memcpy(ctx->cbc_params.iv, ctx->iv, sizeof(ctx->cbc_params.iv));
    /* Mark the chaining IV live so UPDATED_IV tracks decrypt as well: the FFI
     * advances cbc_params.iv on every streamed update/finish. */
    ctx->cbc_iv_init = true;

    /* Stream in no-padding mode and strip PKCS#7 at final(): the HSM's padded
     * decrypt finish needs a two-block output buffer that EVP's final cannot
     * satisfy. */
    algo.id = AZIHSM_ALGO_ID_AES_CBC;
    algo.params = &ctx->cbc_params;
    algo.len = (uint32_t)sizeof(ctx->cbc_params);

    status = azihsm_crypt_decrypt_init(&algo, ctx->key_handle, &ctx->stream_ctx);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    ctx->stream_active = true;
    return OSSL_SUCCESS;
}

/* GCM / XTS one-shot helper (performed in the single data update) */

static int azihsm_ossl_cipher_oneshot(
    AZIHSM_CIPHER_CTX *ctx,
    unsigned char *out,
    size_t *outl,
    size_t outsize,
    const unsigned char *in,
    size_t inl
)
{
    struct azihsm_algo algo;
    struct azihsm_buffer in_buf;
    struct azihsm_buffer out_buf;
    struct azihsm_algo_aes_gcm_params gcm_params;
    struct azihsm_algo_aes_xts_params xts_params;
    struct azihsm_buffer aad_buf;
    azihsm_status status;

    if (ctx->oneshot_done)
    {
        /* The HSM performs GCM/XTS as a single shot; chunked data updates are
         * not supported because each call would re-run the whole transform. */
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_NOT_SUPPORTED,
            "GCM/XTS requires the data to be supplied in a single update"
        );
        return OSSL_FAILURE;
    }
    /* The IV/nonce/tweak is bound at skey_init; never run the transform with an
     * unset (zero) IV (mirrors the CBC have_iv guards). */
    if (!ctx->have_iv)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
        return OSSL_FAILURE;
    }
    /* GCM and XTS do not expand: output length equals input length, and the
     * azihsm FFI requires the output buffer length to be exactly that. */
    if (inl > UINT32_MAX || outsize < inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return OSSL_FAILURE;
    }

    in_buf.ptr = (void *)(uintptr_t)in;
    in_buf.len = (uint32_t)inl;
    out_buf.ptr = out;
    out_buf.len = (uint32_t)inl;

    if (ctx->mode == AZIHSM_CIPHER_MODE_GCM)
    {
        memcpy(gcm_params.iv, ctx->iv, sizeof(gcm_params.iv));
        memcpy(gcm_params.tag, ctx->tag, sizeof(gcm_params.tag));
        if (ctx->aad != NULL && ctx->aad_len > 0)
        {
            aad_buf.ptr = ctx->aad;
            aad_buf.len = (uint32_t)ctx->aad_len;
            gcm_params.aad = &aad_buf;
        }
        else
        {
            gcm_params.aad = NULL;
        }
        algo.id = AZIHSM_ALGO_ID_AES_GCM;
        algo.params = &gcm_params;
        algo.len = (uint32_t)sizeof(gcm_params);
    }
    else /* XTS */
    {
        memcpy(xts_params.sector_num, ctx->iv, sizeof(xts_params.sector_num));
        xts_params.data_unit_length = (uint32_t)inl;
        algo.id = AZIHSM_ALGO_ID_AES_XTS;
        algo.params = &xts_params;
        algo.len = (uint32_t)sizeof(xts_params);
    }

    status = ctx->enc ? azihsm_crypt_encrypt(&algo, ctx->key_handle, &in_buf, &out_buf)
                      : azihsm_crypt_decrypt(&algo, ctx->key_handle, &in_buf, &out_buf);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        /* For GCM decrypt this includes tag-verification failure. */
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    if (ctx->mode == AZIHSM_CIPHER_MODE_GCM && ctx->enc)
    {
        memcpy(ctx->tag, gcm_params.tag, sizeof(ctx->tag));
        ctx->tag_avail = true;
    }

    ctx->oneshot_done = true;
    *outl = (size_t)out_buf.len;
    return OSSL_SUCCESS;
}

/* Update / Final / one-shot cipher */

static int azihsm_ossl_gcm_accumulate_aad(
    AZIHSM_CIPHER_CTX *ctx,
    const unsigned char *in,
    size_t inl
)
{
    unsigned char *grown;
    size_t new_len;

    if (inl == 0)
    {
        return OSSL_SUCCESS;
    }
    if (inl > UINT32_MAX || ctx->aad_len > UINT32_MAX - inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    new_len = ctx->aad_len + inl;
    grown = OPENSSL_realloc(ctx->aad, new_len);
    if (grown == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return OSSL_FAILURE;
    }
    memcpy(grown + ctx->aad_len, in, inl);
    ctx->aad = grown;
    ctx->aad_len = new_len;
    return OSSL_SUCCESS;
}

static int azihsm_ossl_cipher_update(
    void *vctx,
    unsigned char *out,
    size_t *outl,
    size_t outsize,
    const unsigned char *in,
    size_t inl
)
{
    AZIHSM_CIPHER_CTX *ctx = (AZIHSM_CIPHER_CTX *)vctx;
    struct azihsm_buffer in_buf;
    struct azihsm_buffer out_buf;
    azihsm_status status;

    if (ctx == NULL || outl == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }
    if (!ctx->have_key)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
        return OSSL_FAILURE;
    }

    *outl = 0;

    /* GCM AAD is fed as an update with a NULL output buffer. */
    if (ctx->mode == AZIHSM_CIPHER_MODE_GCM && out == NULL)
    {
        /* The one-shot already authenticated the AAD captured so far; AAD added
         * afterwards would never enter the tag, so reject it instead of silently
         * accepting it. */
        if (ctx->oneshot_done)
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                PROV_R_NOT_SUPPORTED,
                "AAD cannot be supplied after the AES-GCM data has been processed"
            );
            return OSSL_FAILURE;
        }
        return azihsm_ossl_gcm_accumulate_aad(ctx, in, inl);
    }

    if (ctx->mode == AZIHSM_CIPHER_MODE_CBC)
    {
        if (ctx->enc)
        {
            return azihsm_ossl_cbc_encrypt_update(ctx, out, outl, outsize, in, inl);
        }

        /* Decryption is streamed through the HSM. */
        if (!azihsm_ossl_cbc_decrypt_ensure_stream(ctx))
        {
            return OSSL_FAILURE;
        }
        if (in == NULL || inl == 0)
        {
            return OSSL_SUCCESS;
        }
        if (inl > UINT32_MAX || outsize > UINT32_MAX)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            return OSSL_FAILURE;
        }

        in_buf.ptr = (void *)(uintptr_t)in;
        in_buf.len = (uint32_t)inl;
        out_buf.ptr = out;
        out_buf.len = (uint32_t)outsize;

        status = azihsm_crypt_decrypt_update(ctx->stream_ctx, &in_buf, &out_buf);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }
        *outl = (size_t)out_buf.len;
        return OSSL_SUCCESS;
    }

    /* GCM decrypt verifies the tag inside the single HSM operation, so the tag
     * must already be set when the ciphertext arrives.  Unlike software GCM, we
     * cannot decrypt now and verify a tag supplied later at final(); fail clearly
     * rather than run the one-shot against an unset (zero) tag. */
    if (ctx->mode == AZIHSM_CIPHER_MODE_GCM && !ctx->enc && !ctx->tag_set)
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_TAG,
            "AES-GCM decrypt requires the authentication tag to be set before the ciphertext"
        );
        return OSSL_FAILURE;
    }

    /* GCM / XTS: one-shot over the supplied data. */
    return azihsm_ossl_cipher_oneshot(ctx, out, outl, outsize, in, inl);
}

static int azihsm_ossl_cipher_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    AZIHSM_CIPHER_CTX *ctx = (AZIHSM_CIPHER_CTX *)vctx;
    azihsm_status status;

    if (ctx == NULL || outl == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    *outl = 0;

    /* GCM/XTS emit everything during update(); nothing remains at final. */
    if (ctx->mode != AZIHSM_CIPHER_MODE_CBC)
    {
        return OSSL_SUCCESS;
    }

    if (!ctx->have_key)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_INSTANTIATED);
        return OSSL_FAILURE;
    }

    /* Encryption emits the (single) padding block here. */
    if (ctx->enc)
    {
        return azihsm_ossl_cbc_encrypt_final(ctx, out, outl, outsize);
    }

    /* Decryption: the stream runs in no-padding mode, so finish() yields the
     * decrypted final block; we strip PKCS#7 padding here and emit at most one
     * block (which fits EVP's one-block final buffer). */
    {
        unsigned char last[16];
        struct azihsm_buffer last_buf = { last, (uint32_t)sizeof(last) };
        size_t last_len;

        if (!azihsm_ossl_cbc_decrypt_ensure_stream(ctx))
        {
            return OSSL_FAILURE;
        }

        status = azihsm_crypt_decrypt_finish(ctx->stream_ctx, &last_buf);
        azihsm_ossl_release_hsm_ctx(&ctx->stream_ctx);
        ctx->stream_active = false;

        if (status != AZIHSM_STATUS_SUCCESS)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }

        last_len = (size_t)last_buf.len;

        if (ctx->pad)
        {
            unsigned int padv;
            size_t i;

            if (last_len == 0 || last_len > sizeof(last))
            {
                OPENSSL_cleanse(last, sizeof(last));
                ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
                return OSSL_FAILURE;
            }
            padv = last[last_len - 1];
            if (padv == 0 || (size_t)padv > last_len)
            {
                OPENSSL_cleanse(last, sizeof(last));
                ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
                return OSSL_FAILURE;
            }
            for (i = last_len - padv; i < last_len; ++i)
            {
                if (last[i] != (unsigned char)padv)
                {
                    OPENSSL_cleanse(last, sizeof(last));
                    ERR_raise(ERR_LIB_PROV, PROV_R_BAD_DECRYPT);
                    return OSSL_FAILURE;
                }
            }
            last_len -= padv;
        }

        if (last_len > outsize)
        {
            OPENSSL_cleanse(last, sizeof(last));
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return OSSL_FAILURE;
        }
        if (last_len > 0)
        {
            memcpy(out, last, last_len);
        }
        OPENSSL_cleanse(last, sizeof(last));
        *outl = last_len;
        return OSSL_SUCCESS;
    }
}

static int azihsm_ossl_cipher_cipher(
    void *vctx,
    unsigned char *out,
    size_t *outl,
    size_t outsize,
    const unsigned char *in,
    size_t inl
)
{
    AZIHSM_CIPHER_CTX *ctx = (AZIHSM_CIPHER_CTX *)vctx;

    if (ctx == NULL || outl == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* One-shot path used by EVP_Cipher(): delegate to update() + final(). */
    if (!azihsm_ossl_cipher_update(ctx, out, outl, outsize, in, inl))
    {
        return OSSL_FAILURE;
    }

    if (ctx->mode == AZIHSM_CIPHER_MODE_CBC)
    {
        size_t finl = 0;
        size_t produced = *outl;
        if (!azihsm_ossl_cipher_final(ctx, out + produced, &finl, outsize - produced))
        {
            return OSSL_FAILURE;
        }
        *outl = produced + finl;
    }

    return OSSL_SUCCESS;
}

/* Fixed (algorithm-level) parameters */

static int azihsm_ossl_cipher_get_params(
    OSSL_PARAM params[],
    unsigned int mode,
    size_t keylen,
    size_t blksize,
    size_t ivlen,
    int aead,
    int custom_iv
)
{
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, mode))
    {
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL && !OSSL_PARAM_set_int(p, aead))
    {
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL && !OSSL_PARAM_set_int(p, custom_iv))
    {
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, keylen))
    {
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksize))
    {
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivlen))
    {
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

/* AES-128-CBC */
static int azihsm_ossl_aes128cbc_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_cipher_get_params(params, EVP_CIPH_CBC_MODE, 16, 16, 16, 0, 0);
}

/* AES-192-CBC */
static int azihsm_ossl_aes192cbc_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_cipher_get_params(params, EVP_CIPH_CBC_MODE, 24, 16, 16, 0, 0);
}

/* AES-256-CBC */
static int azihsm_ossl_aes256cbc_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_cipher_get_params(params, EVP_CIPH_CBC_MODE, 32, 16, 16, 0, 0);
}

/* AES-256-GCM: stream cipher (block size 1), 12-byte IV, AEAD + custom IV. */
static int azihsm_ossl_aes256gcm_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_cipher_get_params(params, EVP_CIPH_GCM_MODE, 32, 1, 12, 1, 1);
}

/* AES-128-XTS: 2x key (32 bytes), 16-byte tweak, custom IV. */
static int azihsm_ossl_aes128xts_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_cipher_get_params(params, EVP_CIPH_XTS_MODE, 32, 1, 16, 0, 1);
}

/* AES-256-XTS: 2x key (64 bytes), 16-byte tweak, custom IV. */
static int azihsm_ossl_aes256xts_get_params(OSSL_PARAM params[])
{
    return azihsm_ossl_cipher_get_params(params, EVP_CIPH_XTS_MODE, 64, 1, 16, 0, 1);
}

/* Per-context parameters */

static int azihsm_ossl_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    AZIHSM_CIPHER_CTX *ctx = (AZIHSM_CIPHER_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
    {
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
    {
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen))
    {
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, (unsigned int)ctx->pad))
    {
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL && ctx->have_iv && !OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen))
    {
        return OSSL_FAILURE;
    }

    /* UPDATED_IV reflects the IV *after* the data processed so far.  For CBC the
     * HSM rewrites cbc_params.iv to the last ciphertext block on each update, so
     * once chaining has started that is the live value; before any update (and
     * for GCM/XTS) it equals the original IV. */
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL && ctx->have_iv)
    {
        const unsigned char *updated_iv = (ctx->mode == AZIHSM_CIPHER_MODE_CBC && ctx->cbc_iv_init)
                                              ? ctx->cbc_params.iv
                                              : ctx->iv;
        if (!OSSL_PARAM_set_octet_string(p, updated_iv, ctx->ivlen))
        {
            return OSSL_FAILURE;
        }
    }

    if (ctx->mode == AZIHSM_CIPHER_MODE_GCM)
    {
        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
        if (p != NULL && !OSSL_PARAM_set_size_t(p, AZIHSM_AES_GCM_TAG_SIZE))
        {
            return OSSL_FAILURE;
        }

        p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
        if (p != NULL)
        {
            if (!ctx->enc || !ctx->tag_avail)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
                return OSSL_FAILURE;
            }
            /* GCM tags may be truncated to a leading prefix; the HSM always
             * produces the full 16-byte tag, so honour any request in (0, 16]. */
            if (p->data_size == 0 || p->data_size > AZIHSM_AES_GCM_TAG_SIZE ||
                !OSSL_PARAM_set_octet_string(p, ctx->tag, p->data_size))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
                return OSSL_FAILURE;
            }
        }
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    AZIHSM_CIPHER_CTX *ctx = (AZIHSM_CIPHER_CTX *)vctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
    {
        return OSSL_FAILURE;
    }
    if (params == NULL)
    {
        return OSSL_SUCCESS;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL)
    {
        unsigned int pad = 0;
        if (!OSSL_PARAM_get_uint(p, &pad))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }
        ctx->pad = pad ? 1 : 0;
    }

    /* GCM IV length is fixed at 12 bytes by the HSM. */
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if (p != NULL)
    {
        size_t ivlen = 0;
        if (!OSSL_PARAM_get_size_t(p, &ivlen))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }
        if (ivlen != ctx->ivlen)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return OSSL_FAILURE;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL)
    {
        void *tagptr = ctx->tag;

        if (ctx->mode != AZIHSM_CIPHER_MODE_GCM)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
            return OSSL_FAILURE;
        }
        if (p->data_size != AZIHSM_AES_GCM_TAG_SIZE ||
            !OSSL_PARAM_get_octet_string(p, &tagptr, AZIHSM_AES_GCM_TAG_SIZE, NULL))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
            return OSSL_FAILURE;
        }
        ctx->tag_set = true;
    }

    return OSSL_SUCCESS;
}

/* Parameter descriptors */

static const OSSL_PARAM *azihsm_ossl_cipher_gettable_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
        OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_cipher_gettable_ctx_params(
    ossl_unused void *cctx,
    ossl_unused void *provctx
)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

static const OSSL_PARAM *azihsm_ossl_cipher_settable_ctx_params(
    ossl_unused void *cctx,
    ossl_unused void *provctx
)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
        OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
        OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
        OSSL_PARAM_END,
    };
    return params;
}

/* Dispatch tables */

#define IMPLEMENT_AZIHSM_OSSL_CIPHER(alg)                                                          \
    const OSSL_DISPATCH azihsm_ossl_##alg##_functions[] = {                                        \
        { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))azihsm_ossl_##alg##_newctx },                   \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))azihsm_ossl_cipher_freectx },                  \
        { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))azihsm_ossl_cipher_dupctx },                    \
                                                                                                   \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))azihsm_ossl_cipher_encrypt_init },        \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))azihsm_ossl_cipher_decrypt_init },        \
        AZIHSM_CIPHER_SKEY_DISPATCH{ OSSL_FUNC_CIPHER_UPDATE,                                      \
                                     (void (*)(void))azihsm_ossl_cipher_update },                  \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))azihsm_ossl_cipher_final },                      \
        { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))azihsm_ossl_cipher_cipher },                    \
                                                                                                   \
        { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))azihsm_ossl_##alg##_get_params },           \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_cipher_get_ctx_params },    \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_cipher_set_ctx_params },    \
                                                                                                   \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_cipher_gettable_params },  \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                                    \
          (void (*)(void))azihsm_ossl_cipher_gettable_ctx_params },                                \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                                    \
          (void (*)(void))azihsm_ossl_cipher_settable_ctx_params },                                \
        { 0, NULL }                                                                                \
    };

/* Per-variant newctx wrappers wire the static configuration. */
static void *azihsm_ossl_aes128cbc_newctx(void *provctx)
{
    return azihsm_ossl_cipher_newctx_common(
        provctx,
        AZIHSM_CIPHER_MODE_CBC,
        EVP_CIPH_CBC_MODE,
        AZIHSM_KEY_KIND_AES,
        16,
        16
    );
}
static void *azihsm_ossl_aes192cbc_newctx(void *provctx)
{
    return azihsm_ossl_cipher_newctx_common(
        provctx,
        AZIHSM_CIPHER_MODE_CBC,
        EVP_CIPH_CBC_MODE,
        AZIHSM_KEY_KIND_AES,
        24,
        16
    );
}
static void *azihsm_ossl_aes256cbc_newctx(void *provctx)
{
    return azihsm_ossl_cipher_newctx_common(
        provctx,
        AZIHSM_CIPHER_MODE_CBC,
        EVP_CIPH_CBC_MODE,
        AZIHSM_KEY_KIND_AES,
        32,
        16
    );
}
static void *azihsm_ossl_aes256gcm_newctx(void *provctx)
{
    return azihsm_ossl_cipher_newctx_common(
        provctx,
        AZIHSM_CIPHER_MODE_GCM,
        EVP_CIPH_GCM_MODE,
        AZIHSM_KEY_KIND_AES_GCM,
        32,
        12
    );
}
static void *azihsm_ossl_aes128xts_newctx(void *provctx)
{
    return azihsm_ossl_cipher_newctx_common(
        provctx,
        AZIHSM_CIPHER_MODE_XTS,
        EVP_CIPH_XTS_MODE,
        AZIHSM_KEY_KIND_AES_XTS,
        32,
        16
    );
}
static void *azihsm_ossl_aes256xts_newctx(void *provctx)
{
    return azihsm_ossl_cipher_newctx_common(
        provctx,
        AZIHSM_CIPHER_MODE_XTS,
        EVP_CIPH_XTS_MODE,
        AZIHSM_KEY_KIND_AES_XTS,
        64,
        16
    );
}

IMPLEMENT_AZIHSM_OSSL_CIPHER(aes128cbc)
IMPLEMENT_AZIHSM_OSSL_CIPHER(aes192cbc)
IMPLEMENT_AZIHSM_OSSL_CIPHER(aes256cbc)
IMPLEMENT_AZIHSM_OSSL_CIPHER(aes256gcm)
IMPLEMENT_AZIHSM_OSSL_CIPHER(aes128xts)
IMPLEMENT_AZIHSM_OSSL_CIPHER(aes256xts)
