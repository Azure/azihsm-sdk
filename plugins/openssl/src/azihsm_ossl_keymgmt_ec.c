//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/objects.h>
#include <openssl/ec.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_hsm.h"
#include "azihsm_ossl_pkey_param.h"
#include "azihsm_ossl_ec.h"

/*
 * EC KeyManagement
 *
 * supported parameters (pkeyopt):
 *
 *   @group
 *   Description: EC curve
 *   Accepted values: P-256, P-384, P-521
 *   Example:
 *      -pkeyopt group:P-384
 *
 *   @aihsm.pub_key_usage
 *   Description: Comma-delimited list of key usage attributes of public key
 *   Accepted values: sign, verify, unwrap, derive, ...
 *   Default value: verify
 *   Example:
 *      -pkeyopt aihsm.priv_key_usage:derive,verify
 *
 *   @aihsm.priv_key_usage [mandatory]
 *   Description: Comma-delimited list of key usage attributes of private key
 *   Accepted values: sign, verify, unwrap, derive, ...
 *   Default value: sign
 *   Example:
 *      -pkeyopt aihsm.priv_key_usage:sign
 *
 * */

#define AIHSM_EC_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_PUBLIC_KEY  | \
                                      OSSL_KEYMGMT_SELECT_PRIVATE_KEY | \
                                      OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

#define AIHSM_EC_CURVE_ID_DEFAULT AZIHSM_EC_CURVE_ID_P256
#define AIHSM_EC_CURVE_ID_NONE    -1

#define AIHSM_PUB_KEY_USAGE_DEFAULT  AZIHSM_KEY_PROP_ID_VERIFY
#define AIHSM_PRIV_KEY_USAGE_DEFAULT AZIHSM_KEY_PROP_ID_SIGN

typedef struct {
    int nid;
    int curve_id;
} CURVE_MAPPING_ENTRY;

static const CURVE_MAPPING_ENTRY curves[] = {
    { NID_X9_62_prime256v1, AZIHSM_EC_CURVE_ID_P256 },
    { NID_secp384r1,        AZIHSM_EC_CURVE_ID_P384 },
    { NID_secp521r1,        AZIHSM_EC_CURVE_ID_P521 },
    { NID_undef,            AIHSM_EC_CURVE_ID_NONE  }
};

/* Internal Helpers */

static int azihsm_ossl_name_to_curve_id(const char* name)
{
    int nid;

    nid = EC_curve_nist2nid(name);

    if (nid == NID_undef) {
        nid = OBJ_sn2nid(name);
    }

    if (nid == NID_undef) {
        return AIHSM_EC_CURVE_ID_NONE;
    }

    for (const CURVE_MAPPING_ENTRY* it = curves; it->nid != NID_undef; it++) {

        if (it->nid == nid) {
            return it->curve_id;
        }
    }

    return AIHSM_EC_CURVE_ID_NONE;
}

static int azihsm_ossl_curve_id_to_nid(const int curve_id)
{
    for (const CURVE_MAPPING_ENTRY* it = curves; it->nid != NID_undef; it++) {

        if (it->curve_id == curve_id)
            return it->nid;
    }

    return NID_undef;
}

/* Key Management Functions */

static AZIHSM_EC_KEY* azihsm_ossl_keymgmt_gen(AIHSM_EC_GEN_CTX* genctx, ossl_unused OSSL_CALLBACK* cb, ossl_unused void* cbarg)
{
    AZIHSM_EC_KEY* ec_key;
    azihsm_handle public, private;
    azihsm_error  status;
    const bool    enable = true;

    struct azihsm_algo algo = {

        .id     = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = NULL,
        .len    = 0
    };

    struct azihsm_key_prop pub_key_props[KEY_USAGE_LIST_MAX + 1] = {

        [0] = {
            .id  = AZIHSM_KEY_PROP_ID_EC_CURVE,
            .val = (void*) &genctx->ec_curve_id,
            .len = sizeof(genctx->ec_curve_id)
        }
    };

    struct azihsm_key_prop priv_key_props[KEY_USAGE_LIST_MAX + 1] = {

        [0] = {
            .id  = AZIHSM_KEY_PROP_ID_EC_CURVE,
            .val = (void*) &genctx->ec_curve_id,
            .len = sizeof(genctx->ec_curve_id)
        }
    };

    for (int i = 0; i < genctx->pub_key_usage.count; i++) {

        pub_key_props[1 + i].id  = genctx->pub_key_usage.elements[i];
        pub_key_props[1 + i].val = (void*) &enable;
        pub_key_props[1 + i].len = sizeof(bool);
    }

    for (int i = 0; i < genctx->priv_key_usage.count; i++) {

        priv_key_props[1 + i].id  = genctx->priv_key_usage.elements[i];
        priv_key_props[1 + i].val = (void*) &enable;
        priv_key_props[1 + i].len = sizeof(bool);
    }

    struct azihsm_key_prop_list pub_key_prop_list = {

        .props = pub_key_props,
        .count = genctx->pub_key_usage.count + 1
    };

    struct azihsm_key_prop_list priv_key_prop_list = {

        .props = priv_key_props,
        .count = genctx->priv_key_usage.count + 1
    };

    if ((ec_key = OPENSSL_zalloc(sizeof(AZIHSM_EC_KEY))) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    status = azihsm_key_gen_pair(genctx->session, &algo, &pub_key_prop_list,
                                 &priv_key_prop_list, &public, &private);

    if (status != AZIHSM_ERROR_SUCCESS) {
        OPENSSL_free(ec_key);
        return NULL;
    }

    ec_key->genctx      = *genctx;
    ec_key->key.public  = public;
    ec_key->has_public  = true;
    ec_key->key.private = private;
    ec_key->has_private = true;

    return ec_key;
}

static void azihsm_ossl_keymgmt_free(AZIHSM_EC_KEY* ec_key)
{
    if (ec_key == NULL) {
        return;
    }

    azihsm_key_delete(ec_key->genctx.session, ec_key->key.public);
    azihsm_key_delete(ec_key->genctx.session, ec_key->key.private);

    OPENSSL_free(ec_key);
}

static void azihsm_ossl_keymgmt_gen_cleanup(AIHSM_EC_GEN_CTX* genctx)
{
    if (genctx == NULL) {
        return;
    }

    OPENSSL_clear_free(genctx, sizeof(AIHSM_EC_GEN_CTX));
}

static int azihsm_ossl_keymgmt_gen_set_params(AIHSM_EC_GEN_CTX* genctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM* p;

    if (params == NULL) {
        return 1;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL) {

        int curve_id;

        if (p->data_type != OSSL_PARAM_UTF8_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        if ((curve_id = azihsm_ossl_name_to_curve_id(p->data)) == AIHSM_EC_CURVE_ID_NONE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
            return 0;
        }

        genctx->ec_curve_id = curve_id;
    }

    if ((p = OSSL_PARAM_locate_const(params, AZIHSM_OSSL_PKEY_PARAM_PUB_KEY_USAGE)) != NULL) {

        if (p->data_type != OSSL_PARAM_UTF8_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        if (azihsm_ossl_key_usage_list_from_str(p->data, &genctx->pub_key_usage) < 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, AZIHSM_OSSL_PKEY_PARAM_PRIV_KEY_USAGE)) != NULL) {

        if (p->data_type != OSSL_PARAM_UTF8_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        if (azihsm_ossl_key_usage_list_from_str(p->data, &genctx->priv_key_usage) < 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }

    return 1;
}

static AIHSM_EC_GEN_CTX* azihsm_ossl_keymgmt_gen_init(void* ctx, int selection, const OSSL_PARAM params[])
{
    AIHSM_EC_GEN_CTX*    genctx;
    AZIHSM_OSSL_PROV_CTX* provctx = ctx;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
        return NULL;
    }

    genctx = OPENSSL_zalloc(sizeof(AIHSM_EC_GEN_CTX));

    if (genctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    genctx->session = provctx->session;

    genctx->pub_key_usage.count        = 1;
    genctx->pub_key_usage.elements[0]  = AIHSM_PUB_KEY_USAGE_DEFAULT;
    genctx->priv_key_usage.count       = 1;
    genctx->priv_key_usage.elements[0] = AIHSM_PRIV_KEY_USAGE_DEFAULT;
    genctx->ec_curve_id                = AIHSM_EC_CURVE_ID_DEFAULT;

    if (azihsm_ossl_keymgmt_gen_set_params(genctx, params) == 0) {
        azihsm_ossl_keymgmt_gen_cleanup(genctx);
        return NULL;
    }

    return genctx;
}

static int azihsm_ossl_keymgmt_has(const AZIHSM_EC_KEY* ec_key, int selection)
{
    int has_selection = 1;

    if (ec_key == NULL) {
        return 0;
    }

    if ((selection & AIHSM_EC_POSSIBLE_SELECTIONS) == 0) {
        return 1;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        has_selection &= ec_key->has_private;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        has_selection &= ec_key->has_public;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        has_selection &= 1; // EC curve is a mandatory property
    }

    return has_selection;
}

static int azihsm_ossl_keymgmt_match(const AZIHSM_EC_KEY* ec_key1, const AZIHSM_EC_KEY* ec_key2, ossl_unused int selection)
{
    if (ec_key1 == NULL || ec_key2 == NULL) {
        return 0;
    }

    if (ec_key1->key.public != ec_key2->key.public) {
        return 0;
    }

    if (ec_key1->key.private != ec_key2->key.private) {
        return 0;
    }

    return 1;
}

static int azihsm_ossl_keymgmt_import(ossl_unused void *keydata, ossl_unused int selection,
                                     ossl_unused const OSSL_PARAM params[])
{
    // TODO: Import key from parameters
    return 0;
}

static int azihsm_ossl_keymgmt_export(ossl_unused const void *keydata, ossl_unused int selection,
                                     ossl_unused OSSL_CALLBACK *param_cb, ossl_unused void *cbarg)
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

static int azihsm_ossl_keymgmt_get_params(AZIHSM_EC_KEY* key, OSSL_PARAM params[])
{
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);

    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, OBJ_nid2sn(azihsm_ossl_curve_id_to_nid(key->genctx.ec_curve_id)))) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *azihsm_ossl_keymgmt_gettable_params(ossl_unused void* ctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END
    };

    return params;
}

static const OSSL_PARAM* azihsm_ossl_keymgmt_gen_settable_params(ossl_unused void* genctx, ossl_unused void* ctx)
{
    static const OSSL_PARAM settable_params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_PUB_KEY_USAGE, NULL, 0),
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_PRIV_KEY_USAGE, NULL, 0),
        OSSL_PARAM_END
    };

    return settable_params;
}

/* EC Key Management */
const OSSL_DISPATCH azihsm_ossl_ec_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))azihsm_ossl_keymgmt_gen},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))azihsm_ossl_keymgmt_gen_init},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))azihsm_ossl_keymgmt_gen_cleanup},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_gen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_gen_settable_params},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))azihsm_ossl_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))azihsm_ossl_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))azihsm_ossl_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))azihsm_ossl_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))azihsm_ossl_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))azihsm_ossl_keymgmt_import_types},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))azihsm_ossl_keymgmt_export_types},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_gettable_params},
    {0, NULL}};
