// Copyright (C) Microsoft Corporation. All rights reserved.
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_rsa.h"

typedef struct
{
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
    azihsm_handle session;
} AIHSM_ENCODER_CTX;

/* --- Internal Helpers --- */

static const char *key_type_to_str(const int key_type)
{
    if (key_type == AIHSM_KEY_TYPE_RSA)
    {
        return "RSA";
    }

    if (key_type == AIHSM_KEY_TYPE_RSA_PSS)
    {
        return "RSA-PSS";
    }

    return "unknown";
}

/* --- ENCODER (TEXT) --- */

static AIHSM_ENCODER_CTX *azihsm_ossl_encoder_newctx(AZIHSM_OSSL_PROV_CTX *provctx)
{
    AIHSM_ENCODER_CTX *ectx;

    if ((ectx = OPENSSL_zalloc(sizeof(AIHSM_ENCODER_CTX))) == NULL)
    {
        return NULL;
    }

    ectx->handle = provctx->handle;
    ectx->libctx = provctx->libctx;
    ectx->session = provctx->session;

    return ectx;
}

static void azihsm_ossl_encoder_freectx(AIHSM_ENCODER_CTX *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    OPENSSL_clear_free(ctx, sizeof(AIHSM_ENCODER_CTX));
}

static int azihsm_ossl_encoder_encode(
    AIHSM_ENCODER_CTX *ctx,
    OSSL_CORE_BIO *out,
    const AZIHSM_RSA_KEY *rsa_key,
    ossl_unused const OSSL_PARAM key_abstract[],
    ossl_unused int selection,
    ossl_unused OSSL_PASSPHRASE_CALLBACK *cb,
    ossl_unused void *cbarg
)
{
    BIO *bio;

    if ((bio = BIO_new_from_core_bio(ctx->libctx, out)) == NULL)
    {
        return 0;
    }

    BIO_printf(bio, "\n");
    BIO_printf(bio, "==== Key Generation Details ====\n");
    BIO_printf(bio, "provider             : azihsm\n");
    BIO_printf(bio, "algorithm            : %s\n", key_type_to_str(rsa_key->genctx.key_type));
    BIO_printf(bio, "public-key bit length: %" PRIu32 "\n", rsa_key->genctx.pubkey_bits);
    BIO_printf(bio, "handle (public-key)  : %" PRIu32 "\n", rsa_key->key.pub);
    BIO_printf(bio, "handle (private-key) : %" PRIu32 "\n", rsa_key->key.priv);

    BIO_free(bio);
    return 1;
}

const OSSL_DISPATCH azihsm_ossl_rsa_text_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))azihsm_ossl_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))azihsm_ossl_encoder_freectx },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))azihsm_ossl_encoder_encode },
    { 0, NULL }
};

/* --- ENCODER (DER) --- */

static int azihsm_ossl_encoder_der_spki_encode(
    AIHSM_ENCODER_CTX *ctx,
    OSSL_CORE_BIO *out,
    ossl_unused const AZIHSM_RSA_KEY *rsa_key,
    ossl_unused const OSSL_PARAM key_abstract[],
    ossl_unused int selection,
    ossl_unused OSSL_PASSPHRASE_CALLBACK *cb,
    ossl_unused void *cbarg
)
{
    BIO *bio;
    int rc = 0;

    if ((bio = BIO_new_from_core_bio(ctx->libctx, out)) == NULL)
    {
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {

        /*
         * There is currently no way to retrieve DER-encoded
         * SPKI for RSA keys.
         *
         * Calls to azihsm_key_get_prop with AZIHSM_KEY_PROP_ID_PUB_KEY_INFO
         * fail with -2 on RSA keys but succeed on EC keys. That might be a
         * limitation of the libazihsm-mock library or it was never intended to
         * be used on RSA keys - we currently don't know.
         *
         * If we ever manage to retrieve the DER-encoded SPKI for RSA keys,
         * we could implement it analogously to the EC encoder, but right now,
         * it is ok to print a small info message.
         * */

        BIO_printf(bio, "info: DER-encoded SPKI not available for RSA/RSA-PSS\n");
        rc = 1;
    }
    else if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {

        BIO_printf(bio, "info: DER-encoded SPKI not available for private keys\n");
        rc = 1;
    }

    BIO_free(bio);
    return rc;
}

static int azihsm_ossl_encoder_der_spki_does_selection(ossl_unused void *provctx, int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {
        /*
         * technically, there is no SPKI for private keys,
         * but we still have to advertise it since OpenSSL requires it.
         *
         * If the encoding of OSSL_KEYMGMT_SELECT_PRIVATE_KEY
         * is ever requested, we will notify the caller.
         * */
        return 1;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        return 1;
    }

    return 0;
}

const OSSL_DISPATCH azihsm_ossl_rsa_der_spki_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))azihsm_ossl_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))azihsm_ossl_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))azihsm_ossl_encoder_der_spki_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))azihsm_ossl_encoder_der_spki_encode },
    { 0, NULL }
};

/* --- ENCODER (DER PRIVATEKEY INFO) --- */

static int azihsm_ossl_encoder_der_pki_encode(
    AIHSM_ENCODER_CTX *ctx,
    OSSL_CORE_BIO *out,
    const AZIHSM_RSA_KEY *rsa_key,
    ossl_unused const OSSL_PARAM key_abstract[],
    ossl_unused int selection,
    ossl_unused OSSL_PASSPHRASE_CALLBACK *cb,
    ossl_unused void *cbarg
)
{
    BIO *bio;

    if ((bio = BIO_new_from_core_bio(ctx->libctx, out)) == NULL)
    {
        return 0;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {
        BIO_printf(bio, "\n");
        BIO_printf(bio, "==== PrivateKeyInfo (PKCS#8) ====\n");
        BIO_printf(bio, "provider             : azihsm\n");
        BIO_printf(bio, "algorithm            : %s\n", key_type_to_str(rsa_key->genctx.key_type));
        BIO_printf(bio, "public-key bit length: %" PRIu32 "\n", rsa_key->genctx.pubkey_bits);
        BIO_printf(bio, "handle (public-key)  : %" PRIu32 "\n", rsa_key->key.pub);
        BIO_printf(bio, "handle (private-key) : %" PRIu32 "\n", rsa_key->key.priv);
        BIO_printf(bio, "\n");
        BIO_printf(bio, "NOTE: Full PKCS#8 DER encoding is not implemented.\n");
        BIO_printf(bio, "      Keys remain in HSM and cannot be exported.\n");
    }
    else if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        BIO_printf(bio, "info: DER-encoded PrivateKeyInfo not available for public keys\n");
    }

    BIO_free(bio);
    return 1;
}

static int azihsm_ossl_encoder_der_pki_does_selection(ossl_unused void *provctx, int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
    {
        return 1;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        return 1;
    }

    return 0;
}

const OSSL_DISPATCH azihsm_ossl_rsa_der_pki_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))azihsm_ossl_encoder_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))azihsm_ossl_encoder_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))azihsm_ossl_encoder_der_pki_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))azihsm_ossl_encoder_der_pki_encode },
    { 0, NULL }
};
