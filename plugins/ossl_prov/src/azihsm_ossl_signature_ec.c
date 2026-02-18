// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <string.h>

#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_signature_ec.h"

/*
 * Raw ECDSA signature size (r || s) for a given curve.
 * Used internally for the HSM buffer allocation.
 */
static size_t azihsm_ossl_curve_raw_sig_size(int curve_id)
{
    switch (curve_id)
    {
    case AZIHSM_ECC_CURVE_P256:
        return AZIHSM_EC_P256_SIG_SIZE;
    case AZIHSM_ECC_CURVE_P384:
        return AZIHSM_EC_P384_SIG_SIZE;
    case AZIHSM_ECC_CURVE_P521:
        return AZIHSM_EC_P521_SIG_SIZE;
    default:
        return 0;
    }
}

/*
 * Maximum DER-encoded ECDSA-Sig-Value size for a given curve.
 * SEQUENCE { INTEGER r, INTEGER s } where each INTEGER may have
 * a leading zero byte for positive sign.  This is the size OpenSSL
 * expects from EVP_PKEY_get_size / sign size queries.
 */
static size_t azihsm_ossl_curve_der_sig_max(int curve_id)
{
    size_t raw = azihsm_ossl_curve_raw_sig_size(curve_id);
    size_t coord;

    if (raw == 0)
    {
        return 0;
    }

    coord = raw / 2;

    /*
     * Each INTEGER: 1 tag + 1 length + 1 possible leading 0x00 + coord bytes.
     * SEQUENCE:     1 tag + 1-2 length bytes.
     * Total max  =  2*(coord + 3) + 3.
     */
    return 2 * (coord + 3) + 3;
}

/*
 * Convert a raw ECDSA signature (r || s, fixed-width) to DER-encoded
 * ECDSA-Sig-Value (SEQUENCE { INTEGER r, INTEGER s }).
 *
 * Returns OSSL_SUCCESS (DER length written to *out_der_len), OSSL_FAILURE on error.
 * Caller must OPENSSL_free(*out_der).
 */
static int ecdsa_raw_to_der(
    const unsigned char *raw,
    size_t raw_len,
    unsigned char **out_der,
    size_t *out_der_len
)
{
    ECDSA_SIG *esig = NULL;
    BIGNUM *r = NULL, *s = NULL;
    size_t half = raw_len / 2;
    unsigned char *der = NULL;
    int der_len;

    if (raw_len == 0 || (raw_len & 1) != 0)
    {
        return OSSL_FAILURE;
    }

    r = BN_bin2bn(raw, (int)half, NULL);
    s = BN_bin2bn(raw + half, (int)half, NULL);
    if (r == NULL || s == NULL)
    {
        goto err;
    }

    esig = ECDSA_SIG_new();
    if (esig == NULL)
    {
        goto err;
    }

    /* ECDSA_SIG_set0 takes ownership of r and s on success. */
    if (!ECDSA_SIG_set0(esig, r, s))
    {
        goto err;
    }
    r = NULL;
    s = NULL;

    der_len = i2d_ECDSA_SIG(esig, &der);
    if (der_len <= 0)
    {
        goto err;
    }

    *out_der = der;
    *out_der_len = (size_t)der_len;
    ECDSA_SIG_free(esig);
    return OSSL_SUCCESS;

err:
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(esig);
    return OSSL_FAILURE;
}

/*
 * Convert a DER-encoded ECDSA-Sig-Value to raw fixed-width (r || s) format.
 * The raw output is sized according to the curve's coordinate size.
 *
 * Returns OSSL_SUCCESS, or OSSL_FAILURE on error.
 * Caller must OPENSSL_free(*out_raw).
 */
static int ecdsa_der_to_raw(
    const unsigned char *der,
    size_t der_len,
    size_t coord_size,
    unsigned char **out_raw,
    size_t *out_raw_len
)
{
    ECDSA_SIG *esig = NULL;
    const BIGNUM *r = NULL, *s = NULL;
    unsigned char *raw = NULL;
    size_t raw_len = coord_size * 2;
    int r_len, s_len;

    if (der == NULL || der_len == 0 || coord_size == 0)
    {
        return OSSL_FAILURE;
    }

    esig = d2i_ECDSA_SIG(NULL, &der, (long)der_len);
    if (esig == NULL)
    {
        return OSSL_FAILURE;
    }

    ECDSA_SIG_get0(esig, &r, &s);
    if (r == NULL || s == NULL)
    {
        ECDSA_SIG_free(esig);
        return OSSL_FAILURE;
    }

    r_len = BN_num_bytes(r);
    s_len = BN_num_bytes(s);

    if ((size_t)r_len > coord_size || (size_t)s_len > coord_size)
    {
        ECDSA_SIG_free(esig);
        return OSSL_FAILURE;
    }

    raw = OPENSSL_zalloc(raw_len);
    if (raw == NULL)
    {
        ECDSA_SIG_free(esig);
        return OSSL_FAILURE;
    }

    /* Write r and s right-aligned (zero-padded on the left) */
    BN_bn2bin(r, raw + (coord_size - (size_t)r_len));
    BN_bn2bin(s, raw + coord_size + (coord_size - (size_t)s_len));

    ECDSA_SIG_free(esig);

    *out_raw = raw;
    *out_raw_len = raw_len;
    return OSSL_SUCCESS;
}

/*
 * Map a digest EVP_MD to the NID of the combined ECDSA+hash
 * AlgorithmIdentifier (for X.509 signatureAlgorithm).
 */
static int azihsm_ossl_ecdsa_sig_nid(const EVP_MD *md)
{
    if (md == NULL)
    {
        return NID_undef;
    }

    switch (EVP_MD_type(md))
    {
    case NID_sha1:
        return NID_ecdsa_with_SHA1;
    case NID_sha256:
        return NID_ecdsa_with_SHA256;
    case NID_sha384:
        return NID_ecdsa_with_SHA384;
    case NID_sha512:
        return NID_ecdsa_with_SHA512;
    default:
        return NID_undef;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
   ECDSA CONTEXT LIFECYCLE
   ═══════════════════════════════════════════════════════════════════════════ */

static void *azihsm_ossl_ecdsa_newctx(void *provctx, ossl_unused const char *propq)
{
    azihsm_ec_sig_ctx *ctx;
    AZIHSM_OSSL_PROV_CTX *prov = (AZIHSM_OSSL_PROV_CTX *)provctx;

    if (prov == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->provctx = prov;
    ctx->sign_ctx = 0; /* No streaming context yet */

    return ctx;
}

static void azihsm_ossl_ecdsa_freectx(void *sctx)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;

    if (ctx == NULL)
        return;

    /* Note: Don't free key - caller owns it */
    OPENSSL_free(ctx);
}

static void *azihsm_ossl_ecdsa_dupctx(void *sctx)
{
    azihsm_ec_sig_ctx *src_ctx = (azihsm_ec_sig_ctx *)sctx;
    azihsm_ec_sig_ctx *dst_ctx;

    if (src_ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    dst_ctx = OPENSSL_zalloc(sizeof(*dst_ctx));
    if (dst_ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* Copy all fields INCLUDING sign_ctx handle */
    *dst_ctx = *src_ctx;

    return dst_ctx;
}

/* ═══════════════════════════════════════════════════════════════════════════
   ECDSA ONE-SHOT OPERATIONS
   ═══════════════════════════════════════════════════════════════════════════ */

static int azihsm_ossl_ecdsa_sign_init(void *sctx, void *provkey, const OSSL_PARAM params[])
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;

    if (ctx == NULL || provkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Extract key from provider key object */
    ctx->key = (AZIHSM_EC_KEY *)provkey;

    /* Verify the key has a private component for signing */
    if (!ctx->key->has_private)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return OSSL_FAILURE;
    }

    ctx->operation = 1; /* Sign */

    /* Set default hash algorithm if not already set */
    if (ctx->md == NULL)
    {
        ctx->md = EVP_sha256();
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_ecdsa_sign(
    void *sctx,
    unsigned char *sig,
    size_t *siglen,
    size_t sigsize,
    const unsigned char *tbs,
    size_t tbslen
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    struct azihsm_algo algo = { 0 };
    struct azihsm_buffer data_buf, sig_buf;
    azihsm_status status;
    size_t raw_sig_size;

    if (ctx == NULL || ctx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Bounds check to prevent truncation when casting to uint32_t */
    if (tbslen > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    /* Size query: return maximum DER ECDSA-Sig-Value size. */
    if (sig == NULL)
    {
        *siglen = azihsm_ossl_curve_der_sig_max((int)ctx->key->genctx.ec_curve_id);
        return (*siglen > 0) ? OSSL_SUCCESS : OSSL_FAILURE;
    }

    /* Use raw ECDSA algorithm — data has to come in already hashed by the user */
    algo.id = AZIHSM_ALGO_ID_ECDSA;
    algo.params = NULL;
    algo.len = 0;

    /* Set up data buffer */
    data_buf.ptr = (uint8_t *)tbs;
    data_buf.len = (uint32_t)tbslen;

    /* Ask the HSM for the required raw signature buffer size */
    sig_buf.ptr = NULL;
    sig_buf.len = 0;
    status = azihsm_crypt_sign(&algo, ctx->key->key.priv, &data_buf, &sig_buf);
    if (status != AZIHSM_STATUS_BUFFER_TOO_SMALL || sig_buf.len == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return OSSL_FAILURE;
    }

    raw_sig_size = sig_buf.len;

    /* Allocate temporary buffer for the raw signature from the HSM. */
    {
        unsigned char *raw_buf = OPENSSL_zalloc(raw_sig_size);
        unsigned char *der = NULL;
        size_t der_len = 0;

        if (raw_buf == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return OSSL_FAILURE;
        }

        sig_buf.ptr = raw_buf;
        sig_buf.len = (uint32_t)raw_sig_size;

        status = azihsm_crypt_sign(&algo, ctx->key->key.priv, &data_buf, &sig_buf);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            OPENSSL_clear_free(raw_buf, raw_sig_size);
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }

        /* Convert raw (r || s) to DER ECDSA-Sig-Value. */
        if (ecdsa_raw_to_der(raw_buf, sig_buf.len, &der, &der_len) != OSSL_SUCCESS)
        {
            OPENSSL_clear_free(raw_buf, raw_sig_size);
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return OSSL_FAILURE;
        }
        OPENSSL_clear_free(raw_buf, raw_sig_size);

        if (der_len > sigsize)
        {
            OPENSSL_free(der);
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return OSSL_FAILURE;
        }

        memcpy(sig, der, der_len);
        *siglen = der_len;
        OPENSSL_free(der);
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_ecdsa_verify_init(void *sctx, void *provkey, const OSSL_PARAM params[])
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;

    if (ctx == NULL || provkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Extract key from provider key object */
    ctx->key = (AZIHSM_EC_KEY *)provkey;
    ctx->operation = 0; /* Verify */

    /* Set default hash algorithm if not already set */
    if (ctx->md == NULL)
    {
        ctx->md = EVP_sha256();
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_ecdsa_verify(
    void *sctx,
    const unsigned char *sig,
    size_t siglen,
    const unsigned char *tbs,
    size_t tbslen
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    struct azihsm_algo algo = { 0 };
    struct azihsm_buffer data_buf, sig_buf;
    azihsm_status status;
    unsigned char *raw_sig = NULL;
    size_t raw_sig_len = 0;
    size_t coord_size;
    int result;

    if (ctx == NULL || ctx->key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Bounds check to prevent truncation when casting to uint32_t */
    if (tbslen > UINT32_MAX || siglen > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    /* Get coordinate size for the curve to determine raw signature size */
    coord_size = azihsm_ossl_curve_raw_sig_size((int)ctx->key->genctx.ec_curve_id) / 2;
    if (coord_size == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return OSSL_FAILURE;
    }

    /* Convert DER signature to raw (r || s) format expected by HSM */
    if (ecdsa_der_to_raw(sig, siglen, coord_size, &raw_sig, &raw_sig_len) != OSSL_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return OSSL_FAILURE;
    }

    algo.id = AZIHSM_ALGO_ID_ECDSA;
    algo.params = NULL;
    algo.len = 0;

    /* Set up buffers */
    data_buf.ptr = (uint8_t *)tbs;
    data_buf.len = (uint32_t)tbslen;
    sig_buf.ptr = raw_sig;
    sig_buf.len = (uint32_t)raw_sig_len;

    status = azihsm_crypt_verify(&algo, ctx->key->key.pub, &data_buf, &sig_buf);

    OPENSSL_free(raw_sig);

    if (status == AZIHSM_STATUS_SUCCESS)
    {
        result = OSSL_SUCCESS;
    }
    else if (status == AZIHSM_STATUS_INVALID_SIGNATURE)
    {
        result = OSSL_FAILURE;
    }
    else
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        result = OSSL_FAILURE;
    }

    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
   ECDSA STREAMING OPERATIONS
   ═══════════════════════════════════════════════════════════════════════════ */

static int azihsm_ossl_ecdsa_digest_sign_init(
    void *sctx,
    const char *mdname,
    void *provkey,
    const OSSL_PARAM params[]
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    azihsm_algo_id algo_id;
    struct azihsm_algo algo = { 0 };
    azihsm_status status;

    if (provkey == NULL)
    {
        /* Silently succeed - this is a cleanup/reset operation, not an active signing operation */
        return OSSL_SUCCESS;
    }

    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Extract key from provider key object */
    ctx->key = (AZIHSM_EC_KEY *)provkey;

    /* Verify the key has a private component for signing */
    if (!ctx->key->has_private)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return OSSL_FAILURE;
    }

    ctx->operation = 1; /* Sign */

    /* Get hash algorithm by name */
    ctx->md = EVP_get_digestbyname(mdname);
    if (ctx->md == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    /* Map hash algorithm to EcdsaSha* combined algorithm ID */
    algo_id = azihsm_ossl_evp_md_to_ecdsa_algo_id(ctx->md);

    if (algo_id == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    /* Create algorithm structure */
    algo.id = algo_id;

    status = azihsm_crypt_sign_init(&algo, ctx->key->key.priv, &ctx->sign_ctx);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_ecdsa_digest_sign_update(
    void *sctx,
    const unsigned char *data,
    size_t datalen
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    struct azihsm_buffer data_buf;
    azihsm_status status;

    if (ctx == NULL || ctx->sign_ctx == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Bounds check to prevent truncation when casting to uint32_t */
    if (datalen > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    /* Set up buffer */
    data_buf.ptr = (uint8_t *)data;
    data_buf.len = (uint32_t)datalen;

    /* Update streaming sign with raw data */
    status = azihsm_crypt_sign_update(ctx->sign_ctx, &data_buf);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_ecdsa_digest_sign_final(
    void *sctx,
    unsigned char *sig,
    size_t *siglen,
    size_t sigsize
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    struct azihsm_buffer sig_buf;
    azihsm_status status;

    if (ctx == NULL || ctx->sign_ctx == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Size query: return maximum DER ECDSA-Sig-Value size. */
    if (sig == NULL)
    {
        *siglen = azihsm_ossl_curve_der_sig_max((int)ctx->key->genctx.ec_curve_id);
        return (*siglen > 0) ? OSSL_SUCCESS : OSSL_FAILURE;
    }

    /* Ask the HSM for the required raw signature buffer size */
    sig_buf.ptr = NULL;
    sig_buf.len = 0;
    status = azihsm_crypt_sign_finish(ctx->sign_ctx, &sig_buf);
    if (status != AZIHSM_STATUS_BUFFER_TOO_SMALL || sig_buf.len == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        ctx->sign_ctx = 0;
        return OSSL_FAILURE;
    }

    /* Verify OpenSSL provided enough space for the DER output */
    {
        size_t der_max = azihsm_ossl_curve_der_sig_max((int)ctx->key->genctx.ec_curve_id);
        if (sigsize < der_max)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            ctx->sign_ctx = 0;
            return OSSL_FAILURE;
        }
    }

    /* Finalize streaming sign, then convert raw to DER. */
    {
        uint32_t raw_size = sig_buf.len;
        unsigned char *raw_buf = OPENSSL_zalloc(raw_size);
        unsigned char *der = NULL;
        size_t der_len = 0;

        if (raw_buf == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            ctx->sign_ctx = 0;
            return OSSL_FAILURE;
        }

        sig_buf.ptr = raw_buf;
        sig_buf.len = raw_size;

        status = azihsm_crypt_sign_final(ctx->sign_ctx, &sig_buf);
        ctx->sign_ctx = 0; /* Context consumed */

        if (status != AZIHSM_STATUS_SUCCESS)
        {
            OPENSSL_clear_free(raw_buf, raw_size);
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }

        /* Convert raw (r || s) to DER ECDSA-Sig-Value. */
        if (ecdsa_raw_to_der(raw_buf, sig_buf.len, &der, &der_len) != OSSL_SUCCESS)
        {
            OPENSSL_clear_free(raw_buf, raw_size);
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return OSSL_FAILURE;
        }
        OPENSSL_clear_free(raw_buf, raw_size);

        memcpy(sig, der, der_len);
        *siglen = der_len;
        OPENSSL_free(der);
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_ecdsa_digest_verify_init(
    void *sctx,
    const char *mdname,
    void *provkey,
    const OSSL_PARAM params[]
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    struct azihsm_algo algo = { 0 };
    azihsm_status status;

    if (ctx == NULL || provkey == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Extract key from provider key object */
    ctx->key = (AZIHSM_EC_KEY *)provkey;
    ctx->operation = 0; /* Verify */

    /* Get hash algorithm by name */
    ctx->md = EVP_get_digestbyname(mdname);
    if (ctx->md == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    /* Map hash algorithm to EcdsaSha* combined algorithm ID */
    algo.id = azihsm_ossl_evp_md_to_ecdsa_algo_id(ctx->md);
    if (algo.id == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    /* Initialize streaming verify context */
    status = azihsm_crypt_verify_init(&algo, ctx->key->key.pub, &ctx->sign_ctx);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_ecdsa_digest_verify_update(
    void *sctx,
    const unsigned char *data,
    size_t datalen
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    struct azihsm_buffer data_buf;
    azihsm_status status;

    if (ctx == NULL || ctx->sign_ctx == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Bounds check to prevent truncation when casting to uint32_t */
    if (datalen > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    /* Set up buffer */
    data_buf.ptr = (uint8_t *)data;
    data_buf.len = (uint32_t)datalen;

    /* Update streaming verify with raw data */
    status = azihsm_crypt_verify_update(ctx->sign_ctx, &data_buf);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_ecdsa_digest_verify_final(
    void *sctx,
    const unsigned char *sig,
    size_t siglen
)
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    struct azihsm_buffer sig_buf;
    azihsm_status status;
    unsigned char *raw_sig = NULL;
    size_t raw_sig_len = 0;
    size_t coord_size;
    int result;

    if (ctx == NULL || ctx->sign_ctx == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return OSSL_FAILURE;
    }

    /* Bounds check to prevent truncation when casting to uint32_t */
    if (siglen > UINT32_MAX)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return OSSL_FAILURE;
    }

    /* Get coordinate size for the curve to determine raw signature size */
    coord_size = azihsm_ossl_curve_raw_sig_size((int)ctx->key->genctx.ec_curve_id) / 2;
    if (coord_size == 0)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        ctx->sign_ctx = 0;
        return OSSL_FAILURE;
    }

    /* Convert DER signature to raw (r || s) format expected by HSM */
    if (ecdsa_der_to_raw(sig, siglen, coord_size, &raw_sig, &raw_sig_len) != OSSL_SUCCESS)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        ctx->sign_ctx = 0;
        return OSSL_FAILURE;
    }

    /* Set up buffer */
    sig_buf.ptr = raw_sig;
    sig_buf.len = (uint32_t)raw_sig_len;

    /* Finalize streaming verify */
    status = azihsm_crypt_verify_finish(ctx->sign_ctx, &sig_buf);
    ctx->sign_ctx = 0;

    OPENSSL_free(raw_sig);

    if (status == AZIHSM_STATUS_SUCCESS)
    {
        result = OSSL_SUCCESS;
    }
    else if (status == AZIHSM_STATUS_INVALID_SIGNATURE)
    {
        result = OSSL_FAILURE;
    }
    else
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
        result = OSSL_FAILURE;
    }

    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
   ECDSA PARAMETER HANDLING
   ═══════════════════════════════════════════════════════════════════════════ */

static int azihsm_ossl_ecdsa_set_ctx_params(void *sctx, const OSSL_PARAM params[])
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    const OSSL_PARAM *p;

    if (ctx == NULL || params == NULL)
        return OSSL_SUCCESS;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL)
    {
        /* Get digest algorithm by name */
        const char *mdname = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &mdname) || mdname == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }

        ctx->md = EVP_get_digestbyname(mdname);
        if (ctx->md == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_ecdsa_get_ctx_params(void *sctx, OSSL_PARAM params[])
{
    azihsm_ec_sig_ctx *ctx = (azihsm_ec_sig_ctx *)sctx;
    OSSL_PARAM *p;

    if (ctx == NULL || params == NULL)
        return OSSL_SUCCESS;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL)
    {
        const char *mdname = (ctx->md != NULL) ? EVP_MD_name(ctx->md) : NULL;
        if (!OSSL_PARAM_set_utf8_string(p, mdname))
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL)
    {
        /*
         * Return the DER-encoded AlgorithmIdentifier for the combined
         * ECDSA+hash signature (e.g., ecdsa-with-SHA384).  OpenSSL needs
         * this to embed the signatureAlgorithm in X.509 certificates.
         */
        int sig_nid = azihsm_ossl_ecdsa_sig_nid(ctx->md);
        X509_ALGOR *algor = NULL;
        unsigned char *aid_der = NULL;
        int aid_len;

        if (sig_nid == NID_undef)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }

        algor = X509_ALGOR_new();
        if (algor == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return OSSL_FAILURE;
        }

        X509_ALGOR_set0(algor, OBJ_nid2obj(sig_nid), V_ASN1_UNDEF, NULL);
        aid_len = i2d_X509_ALGOR(algor, &aid_der);
        X509_ALGOR_free(algor);

        if (aid_len <= 0)
        {
            OPENSSL_free(aid_der);
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return OSSL_FAILURE;
        }

        if (!OSSL_PARAM_set_octet_string(p, aid_der, (size_t)aid_len))
        {
            OPENSSL_free(aid_der);
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return OSSL_FAILURE;
        }

        OPENSSL_free(aid_der);
    }

    return OSSL_SUCCESS;
}

static const OSSL_PARAM *azihsm_ossl_ecdsa_settable_ctx_params(void *sctx, void *provctx)
{
    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_END,
    };
    return settable;
}

static const OSSL_PARAM *azihsm_ossl_ecdsa_gettable_ctx_params(void *sctx, void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END,
    };
    return gettable;
}

const OSSL_DISPATCH azihsm_ossl_ecdsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))azihsm_ossl_ecdsa_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))azihsm_ossl_ecdsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))azihsm_ossl_ecdsa_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))azihsm_ossl_ecdsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))azihsm_ossl_ecdsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))azihsm_ossl_ecdsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))azihsm_ossl_ecdsa_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))azihsm_ossl_ecdsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))azihsm_ossl_ecdsa_digest_sign_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))azihsm_ossl_ecdsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))azihsm_ossl_ecdsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))azihsm_ossl_ecdsa_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))azihsm_ossl_ecdsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))azihsm_ossl_ecdsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))azihsm_ossl_ecdsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))azihsm_ossl_ecdsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))azihsm_ossl_ecdsa_gettable_ctx_params },
    { 0, NULL },
};
