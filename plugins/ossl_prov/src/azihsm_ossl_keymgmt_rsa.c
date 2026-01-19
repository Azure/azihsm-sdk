// Copyright (C) Microsoft Corporation. All rights reserved.
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_hsm.h"
#include "azihsm_ossl_rsa.h"

/*
 * RSA/RSA-PSS KeyManagement
 *
 * supported parameters (pkeyopt):
 *
 *   @bits
 *   Description: RSA public key bit length
 *   Accepted values: 2048, ??
 *   Default: 2048
 *   Example:
 *      -pkeyopt group:2048
 *
 * */

#define AIHSM_RSA_POSSIBLE_SELECTIONS                                                              \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)

#define AIHSM_RSA_PUBKEY_BITS_MIN 2048
#define AIHSM_RSA_PUBKEY_BITS_DEFAULT AIHSM_RSA_PUBKEY_BITS_MIN

/* Key Management Functions */

static AZIHSM_RSA_KEY *azihsm_ossl_keymgmt_gen(
    AZIHSM_RSA_GEN_CTX *genctx,
    ossl_unused OSSL_CALLBACK *cb,
    ossl_unused void *cbarg
)
{
    AZIHSM_RSA_KEY *rsa_key;
    azihsm_handle public, private;
    azihsm_status status;

    printf("azihsm_ossl_keymgmt_gen: Generating RSA keypair with %u bits\n", genctx->pubkey_bits);

    struct azihsm_algo algo = {
        .id = AZIHSM_ALGO_ID_RSA_KEY_UNWRAPPING_KEY_PAIR_GEN,
        .params = NULL,
        .len = 0,
    };

    struct azihsm_key_prop pub_key_prop = {
        .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
        .val = (void *)&genctx->pubkey_bits,
        .len = sizeof(genctx->pubkey_bits),
    };

    struct azihsm_key_prop_list pub_key_prop_list = {

        .props = &pub_key_prop,
        .count = 1
    };

    if ((rsa_key = OPENSSL_zalloc(sizeof(AZIHSM_RSA_KEY))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    status =
        azihsm_key_gen_pair(genctx->session, &algo, &pub_key_prop_list, NULL, &public, &private);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_free(rsa_key);
        return NULL;
    }

    rsa_key->genctx = *genctx;
    rsa_key->key.public = public;
    rsa_key->has_public = true;
    rsa_key->key.private = private;
    rsa_key->has_private = true;

    return rsa_key;
}

static void azihsm_ossl_keymgmt_free(AZIHSM_RSA_KEY *rsa_key)
{
    if (rsa_key == NULL)
    {
        return;
    }

    azihsm_key_delete(rsa_key->key.public);
    azihsm_key_delete(rsa_key->key.private);

    OPENSSL_free(rsa_key);
}

static void azihsm_ossl_keymgmt_gen_cleanup(AZIHSM_RSA_GEN_CTX *genctx)
{
    if (genctx == NULL)
    {
        return;
    }

    OPENSSL_clear_free(genctx, sizeof(AZIHSM_RSA_GEN_CTX));
}

static int azihsm_ossl_keymgmt_gen_set_params(AZIHSM_RSA_GEN_CTX *genctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (params == NULL)
    {
        return 1;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL)
    {

        uint32_t bits;

        if (!OSSL_PARAM_get_uint32(p, &bits))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        if (bits < AIHSM_RSA_PUBKEY_BITS_MIN)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SIZE_TOO_SMALL);
            return 0;
        }

        genctx->pubkey_bits = bits;
    }

    return 1;
}

static AZIHSM_RSA_GEN_CTX *azihsm_ossl_keymgmt_gen_init_common(
    void *ctx,
    int selection,
    const OSSL_PARAM params[],
    int key_type
)
{
    AZIHSM_RSA_GEN_CTX *genctx;
    AZIHSM_OSSL_PROV_CTX *provctx = ctx;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
    {
        return NULL;
    }

    genctx = OPENSSL_zalloc(sizeof(AZIHSM_RSA_GEN_CTX));

    if (genctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    genctx->session = provctx->session;

    genctx->key_type = key_type;
    genctx->pubkey_bits = AIHSM_RSA_PUBKEY_BITS_DEFAULT;

    if (azihsm_ossl_keymgmt_gen_set_params(genctx, params) == 0)
    {
        azihsm_ossl_keymgmt_gen_cleanup(genctx);
        return NULL;
    }

    return genctx;
}

static AZIHSM_RSA_GEN_CTX *azihsm_ossl_keymgmt_gen_init_rsa(
    void *ctx,
    int selection,
    const OSSL_PARAM params[]
)
{
    return azihsm_ossl_keymgmt_gen_init_common(ctx, selection, params, AIHSM_KEY_TYPE_RSA);
}

static AZIHSM_RSA_GEN_CTX *azihsm_ossl_keymgmt_gen_init_rsa_pss(
    void *ctx,
    int selection,
    const OSSL_PARAM params[]
)
{
    return azihsm_ossl_keymgmt_gen_init_common(ctx, selection, params, AIHSM_KEY_TYPE_RSA_PSS);
}

static int azihsm_ossl_keymgmt_has(const AZIHSM_RSA_KEY *rsa_key, int selection)
{
    int has_selection = 1;

    if (rsa_key == NULL)
    {
        return 0;
    }

    if ((selection & AIHSM_RSA_POSSIBLE_SELECTIONS) == 0)
    {
        return 1;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        has_selection &= rsa_key->has_private;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        has_selection &= rsa_key->has_public;
    }

    return has_selection;
}

static int azihsm_ossl_keymgmt_match(
    const AZIHSM_RSA_KEY *rsa_key1,
    const AZIHSM_RSA_KEY *rsa_key2,
    ossl_unused int selection
)
{
    /*
     * todo: implement selection bits?
     * */

    if (rsa_key1 == NULL || rsa_key2 == NULL)
    {
        return 0;
    }

    if (rsa_key1->key.public != rsa_key2->key.public)
    {
        return 0;
    }

    if (rsa_key1->key.private != rsa_key2->key.private)
    {
        return 0;
    }

    return 1;
}

static int azihsm_ossl_keymgmt_import(
    ossl_unused void *keydata,
    ossl_unused int selection,
    ossl_unused const OSSL_PARAM params[]
)
{
    // TODO: Import key from parameters
    return 0;
}

static int azihsm_ossl_keymgmt_export(
    ossl_unused const void *keydata,
    ossl_unused int selection,
    ossl_unused OSSL_CALLBACK *param_cb,
    ossl_unused void *cbarg
)
{
    // TODO: Export key to parameters
    return 0;
}

static const OSSL_PARAM *azihsm_ossl_keymgmt_import_types(ossl_unused int selection)
{
    // TODO: Return importable parameter types
    return NULL;
}

static const OSSL_PARAM *azihsm_ossl_keymgmt_export_types(ossl_unused int selection)
{
    // TODO: Return exportable parameter types
    return NULL;
}

static int azihsm_ossl_keymgmt_get_params(AZIHSM_RSA_KEY *key, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
        !OSSL_PARAM_set_uint32(p, key->genctx.pubkey_bits))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *azihsm_ossl_keymgmt_gettable_params(ossl_unused void *ctx)
{
    static const OSSL_PARAM gettable_params[] = { OSSL_PARAM_uint32(OSSL_PKEY_PARAM_BITS, NULL),
                                                  OSSL_PARAM_END };

    return gettable_params;
}

static const OSSL_PARAM *azihsm_ossl_keymgmt_gen_settable_params(
    ossl_unused void *genctx,
    ossl_unused void *ctx
)
{
    static const OSSL_PARAM settable_params[] = { OSSL_PARAM_uint32(OSSL_PKEY_PARAM_RSA_BITS, NULL),
                                                  OSSL_PARAM_END };

    return settable_params;
}

/* RSA Key Management */
const OSSL_DISPATCH azihsm_ossl_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))azihsm_ossl_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))azihsm_ossl_keymgmt_gen_init_rsa },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))azihsm_ossl_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))azihsm_ossl_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))azihsm_ossl_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))azihsm_ossl_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))azihsm_ossl_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))azihsm_ossl_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))azihsm_ossl_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))azihsm_ossl_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))azihsm_ossl_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_gettable_params },
    { 0, NULL }
};

const OSSL_DISPATCH azihsm_ossl_rsa_pss_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))azihsm_ossl_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))azihsm_ossl_keymgmt_gen_init_rsa_pss },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))azihsm_ossl_keymgmt_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))azihsm_ossl_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))azihsm_ossl_keymgmt_free },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))azihsm_ossl_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))azihsm_ossl_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))azihsm_ossl_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))azihsm_ossl_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))azihsm_ossl_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))azihsm_ossl_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_gettable_params },
    { 0, NULL }
};
