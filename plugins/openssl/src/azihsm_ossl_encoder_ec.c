// Copyright (C) Microsoft Corporation. All rights reserved.
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_ec.h"

typedef struct {
    const OSSL_CORE_HANDLE* handle;
    OSSL_LIB_CTX* libctx;
    azihsm_handle session;
} AIHSM_ENCODER_CTX;

static const char* curve_id_to_str(azihsm_ec_curve_id curve_id)
{
    switch (curve_id) {

        case AZIHSM_EC_CURVE_ID_P256:
            return "P256";
        case AZIHSM_EC_CURVE_ID_P384:
            return "P384";
        case AZIHSM_EC_CURVE_ID_P521:
            return "P521";
        default:
            break;
    }

    return "unknown";
}

/* --- ENCODER (TEXT) --- */

static AIHSM_ENCODER_CTX* azihsm_ossl_encoder_newctx(AZIHSM_OSSL_PROV_CTX* provctx)
{
    AIHSM_ENCODER_CTX* ectx;

    if ((ectx = OPENSSL_zalloc(sizeof(AIHSM_ENCODER_CTX))) == NULL) {
        return NULL;
    }

    ectx->handle  = provctx->handle;
    ectx->libctx  = provctx->libctx;
    ectx->session = provctx->session;

    return ectx;
}

static void azihsm_ossl_encoder_freectx(AIHSM_ENCODER_CTX* ctx)
{
    if (ctx == NULL) {
        return;
    }

    OPENSSL_clear_free(ctx, sizeof(AIHSM_ENCODER_CTX));
}

static int azihsm_ossl_encoder_encode(AIHSM_ENCODER_CTX* ctx, OSSL_CORE_BIO* out, const AZIHSM_EC_KEY* ec_key,
                                     ossl_unused const OSSL_PARAM key_abstract[], ossl_unused int selection,
                                     ossl_unused OSSL_PASSPHRASE_CALLBACK* cb, ossl_unused void* cbarg)
{
    BIO*                    bio;
    const AIHSM_EC_GEN_CTX* genctx = &ec_key->genctx;
    char                    pub_usage[256] = { }, priv_usage[256] = { };

    if ((bio = BIO_new_from_core_bio(ctx->libctx, out)) == NULL) {
        return 0;
    }

    azihsm_ossl_key_usage_list_to_str(&genctx->pub_key_usage, pub_usage, sizeof(pub_usage));
    azihsm_ossl_key_usage_list_to_str(&genctx->priv_key_usage, priv_usage, sizeof(priv_usage));

    BIO_printf(bio, "\n");
    BIO_printf(bio, "==== Key Generation Details ====\n");
    BIO_printf(bio, "provider             : azihsm\n");
    BIO_printf(bio, "algorithm            : EC\n");
    BIO_printf(bio, "curve                : %s\n", curve_id_to_str(genctx->ec_curve_id));
    BIO_printf(bio, "public-key usage     : %s\n", pub_usage);
    BIO_printf(bio, "private-key usage    : %s\n", priv_usage);
    BIO_printf(bio, "handle (public-key)  : %"PRIu32"\n", ec_key->key.public);
    BIO_printf(bio, "handle (private-key) : %"PRIu32"\n", ec_key->key.private);

    BIO_free(bio);
    return 1;
}

const OSSL_DISPATCH azihsm_ossl_ec_text_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,  (void (*)(void)) azihsm_ossl_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void)) azihsm_ossl_encoder_freectx },
    { OSSL_FUNC_ENCODER_ENCODE,  (void (*)(void)) azihsm_ossl_encoder_encode },
    { 0, NULL }
};

/* --- ENCODER (DER) --- */

static uint8_t* azihsm_ossl_get_der_spki(azihsm_handle session, azihsm_handle key_handle, uint32_t* nbytes)
{
    void*          spki;
    const uint32_t spki_max_len = 2048;

    if ((spki = OPENSSL_zalloc(spki_max_len)) == NULL) {
        return NULL;
    }

    struct azihsm_key_prop prop = {
        .id  = AZIHSM_KEY_PROP_ID_PUB_KEY_INFO,
        .val = spki,
        .len = spki_max_len
    };

    if (azihsm_key_get_prop(session, key_handle, &prop) != AZIHSM_ERROR_SUCCESS) {
        OPENSSL_free(spki);
        return NULL;
    }

    *nbytes = prop.len;
    return (uint8_t*) prop.val;
}

static int azihsm_ossl_encoder_der_spki_encode(AIHSM_ENCODER_CTX* ctx, OSSL_CORE_BIO* out, const AZIHSM_EC_KEY* ec_key,
                                              ossl_unused const OSSL_PARAM key_abstract[], ossl_unused int selection,
                                              ossl_unused OSSL_PASSPHRASE_CALLBACK* cb, ossl_unused void* cbarg)
{
    BIO*     bio;
    uint8_t* spki;
    uint32_t nbytes = 0;
    int      rc = 0;

    if ((bio = BIO_new_from_core_bio(ctx->libctx, out)) == NULL) {
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {

        if ((spki = azihsm_ossl_get_der_spki(ctx->session, ec_key->key.public, &nbytes)) != NULL) {
            BIO_write(bio, (const void*) spki, (int) nbytes);
            OPENSSL_clear_free(spki, nbytes);
            rc = 1;
        }

    } else if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {

        BIO_printf(bio, "info: DER-encoded SPKI not available for private keys\n");
        rc = 1;
    }

    BIO_free(bio);
    return rc;
}

static int azihsm_ossl_encoder_der_spki_does_selection(ossl_unused void* provctx, int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        /*
         * technically, there is no SPKI for private keys,
         * but we still have to advertise it since OpenSSL requires it.
         *
         * If the encoding of OSSL_KEYMGMT_SELECT_PRIVATE_KEY
         * is ever requested, we will notify the caller.
         * */
        return 1;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return 1;
    }

    return 0;
}

const OSSL_DISPATCH azihsm_ossl_ec_der_spki_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (void (*)(void)) azihsm_ossl_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX,        (void (*)(void)) azihsm_ossl_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void)) azihsm_ossl_encoder_der_spki_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,         (void (*)(void)) azihsm_ossl_encoder_der_spki_encode },
    { 0, NULL }
};

static int azihsm_ossl_encoder_der_pki_encode(AIHSM_ENCODER_CTX* ctx, OSSL_CORE_BIO* out, const AZIHSM_EC_KEY* ec_key,
                                              ossl_unused const OSSL_PARAM key_abstract[], ossl_unused int selection,
                                              ossl_unused OSSL_PASSPHRASE_CALLBACK* cb, ossl_unused void* cbarg)
{
    BIO*                    bio;
    const AIHSM_EC_GEN_CTX* genctx = &ec_key->genctx;
    char                    pub_usage[256] = { }, priv_usage[256] = { };

    if ((bio = BIO_new_from_core_bio(ctx->libctx, out)) == NULL) {
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {

        azihsm_ossl_key_usage_list_to_str(&genctx->pub_key_usage, pub_usage, sizeof(pub_usage));
        azihsm_ossl_key_usage_list_to_str(&genctx->priv_key_usage, priv_usage, sizeof(priv_usage));

        BIO_printf(bio, "\n");
        BIO_printf(bio, "==== PrivateKeyInfo (PKCS#8) ====\n");
        BIO_printf(bio, "provider             : azihsm\n");
        BIO_printf(bio, "algorithm            : EC\n");
        BIO_printf(bio, "curve                : %s\n", curve_id_to_str(genctx->ec_curve_id));
        BIO_printf(bio, "public-key usage     : %s\n", pub_usage);
        BIO_printf(bio, "private-key usage    : %s\n", priv_usage);
        BIO_printf(bio, "handle (public-key)  : %"PRIu32"\n", ec_key->key.public);
        BIO_printf(bio, "handle (private-key) : %"PRIu32"\n", ec_key->key.private);
        BIO_printf(bio, "\n");
        BIO_printf(bio, "NOTE: Full PKCS#8 DER encoding is not implemented.\n");
        BIO_printf(bio, "      Keys remain in HSM and cannot be exported.\n");

    } else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        BIO_printf(bio, "info: DER-encoded PrivateKeyInfo not available for public keys\n");
    }

    BIO_free(bio);
    return 1;
}

static int azihsm_ossl_encoder_der_pki_does_selection(ossl_unused void* provctx, int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        return 1;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        return 1;
    }

    return 0;
}

const OSSL_DISPATCH azihsm_ossl_ec_der_pki_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (void (*)(void)) azihsm_ossl_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX,        (void (*)(void)) azihsm_ossl_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void)) azihsm_ossl_encoder_der_pki_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,         (void (*)(void)) azihsm_ossl_encoder_der_pki_encode },
    { 0, NULL }
};
