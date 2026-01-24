// Copyright (C) Microsoft Corporation. All rights reserved.
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <string.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_ec.h"
#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_hsm.h"
#include "azihsm_ossl_pkey_param.h"

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
 *   @azihsm.key_usage
 *   Description: Key usage type for the key pair
 *   Accepted values: digitalSignature (private: sign, public: verify) or keyAgreement (both:
 * derive) Default value: digitalSignature Example: -pkeyopt azihsm.key_usage:digitalSignature
 *      -pkeyopt azihsm.key_usage:keyAgreement
 *
 *   @azihsm.session
 *   Description: Whether to create a session key or persistent key
 *   Accepted values: true, false, 1, 0, yes, no
 *   Default value: false
 *   Example:
 *      -pkeyopt azihsm.session:true
 *
 * */

#define AIHSM_EC_POSSIBLE_SELECTIONS                                                               \
    (OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_PRIVATE_KEY |                            \
     OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

#define AIHSM_EC_CURVE_ID_DEFAULT AZIHSM_ECC_CURVE_P256
#define AIHSM_EC_CURVE_ID_NONE -1

#define AIHSM_KEY_USAGE_DEFAULT KEY_USAGE_DIGITAL_SIGNATURE

typedef struct
{
    int nid;
    int curve_id;
} CURVE_MAPPING_ENTRY;

static const CURVE_MAPPING_ENTRY curves[] = {
    { NID_X9_62_prime256v1, AZIHSM_ECC_CURVE_P256 },
    { NID_secp384r1, AZIHSM_ECC_CURVE_P384 },
    { NID_secp521r1, AZIHSM_ECC_CURVE_P521 },
    { NID_undef, AIHSM_EC_CURVE_ID_NONE },
};

/* Internal Helpers */

static int azihsm_ossl_name_to_curve_id(const char *name)
{
    int nid;

    nid = EC_curve_nist2nid(name);

    if (nid == NID_undef)
    {
        nid = OBJ_sn2nid(name);
    }

    if (nid == NID_undef)
    {
        return AIHSM_EC_CURVE_ID_NONE;
    }

    for (const CURVE_MAPPING_ENTRY *it = curves; it->nid != NID_undef; it++)
    {

        if (it->nid == nid)
        {
            return it->curve_id;
        }
    }

    return AIHSM_EC_CURVE_ID_NONE;
}

static int azihsm_ossl_curve_id_to_nid(const int curve_id)
{
    for (const CURVE_MAPPING_ENTRY *it = curves; it->nid != NID_undef; it++)
    {

        if (it->curve_id == curve_id)
            return it->nid;
    }

    return NID_undef;
}

/* Key Management Functions */

static AZIHSM_EC_KEY *azihsm_ossl_keymgmt_gen(
    AIHSM_EC_GEN_CTX *genctx,
    ossl_unused OSSL_CALLBACK *cb,
    ossl_unused void *cbarg
)
{
    AZIHSM_EC_KEY *ec_key;
    azihsm_handle public, private;
    azihsm_status status;
    const bool enable = true;
    const azihsm_key_class priv_class = AZIHSM_KEY_CLASS_PRIVATE;
    const azihsm_key_class pub_class = AZIHSM_KEY_CLASS_PUBLIC;
    const azihsm_key_kind key_kind = AZIHSM_KEY_KIND_ECC;

    struct azihsm_algo algo = {

        .id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN,
        .params = NULL,
        .len = 0
    };

/* Now we only need 4 properties: class, kind, curve, and usage */
#define AZIHSM_KEY_PROPS_SIZE 5
    struct azihsm_key_prop pub_key_props[AZIHSM_KEY_PROPS_SIZE] = {
        [0] = { .id = AZIHSM_KEY_PROP_ID_CLASS,
                .val = (void *)&pub_class,
                .len = sizeof(pub_class), },
        [1] = { .id = AZIHSM_KEY_PROP_ID_KIND,
                .val = (void *)&key_kind,
                .len = sizeof(key_kind), },
        [2] = { .id = AZIHSM_KEY_PROP_ID_EC_CURVE,
                .val = (void *)&genctx->ec_curve_id,
                .len = sizeof(genctx->ec_curve_id), },
        [3] = { .id = (azihsm_key_prop_id)azihsm_ossl_get_pub_key_property(genctx->key_usage),
                .val = (void *)&enable,
                .len = sizeof(bool), },
    };

    struct azihsm_key_prop priv_key_props[AZIHSM_KEY_PROPS_SIZE] = {
        [0] = { .id = AZIHSM_KEY_PROP_ID_CLASS,
                .val = (void *)&priv_class,
                .len = sizeof(priv_class), },
        [1] = { .id = AZIHSM_KEY_PROP_ID_KIND,
                .val = (void *)&key_kind,
                .len = sizeof(key_kind), },
        [2] = { .id = AZIHSM_KEY_PROP_ID_EC_CURVE,
                .val = (void *)&genctx->ec_curve_id,
                .len = sizeof(genctx->ec_curve_id), },
        [3] = { .id = (azihsm_key_prop_id)azihsm_ossl_get_priv_key_property(genctx->key_usage),
                .val = (void *)&enable,
                .len = sizeof(bool), },
    };

    uint32_t pub_key_prop_count = 4;
    uint32_t priv_key_prop_count = 4;

    /* Add SESSION property if requested */
    if (genctx->session_flag)
    {
        pub_key_props[4] = (struct azihsm_key_prop){
            .id = AZIHSM_KEY_PROP_ID_SESSION,
            .val = (void *)&enable,
            .len = sizeof(bool),
        };
        pub_key_prop_count++;

        priv_key_props[4] = (struct azihsm_key_prop){
            .id = AZIHSM_KEY_PROP_ID_SESSION,
            .val = (void *)&enable,
            .len = sizeof(bool),
        };
        priv_key_prop_count++;
    }

    struct azihsm_key_prop_list pub_key_prop_list = {
        .props = pub_key_props,
        .count = pub_key_prop_count,
    };

    struct azihsm_key_prop_list priv_key_prop_list = {

        .props = priv_key_props,
        .count = priv_key_prop_count,
    };

    if ((ec_key = OPENSSL_zalloc(sizeof(AZIHSM_EC_KEY))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    status = azihsm_key_gen_pair(
        genctx->session,
        &algo,
        &priv_key_prop_list,
        &pub_key_prop_list,
        &private,
        &public
    );

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_free(ec_key);

        printf("azihsm_ossl_keymgmt_gen: azihsm_key_gen_pair failed with error code %d\n", status);

        return NULL;
    }

    ec_key->genctx = *genctx;
    ec_key->key.pub = public;
    ec_key->has_public = true;
    ec_key->key.priv = private;
    ec_key->has_private = true;

    /* Handle masked key file output if requested */
    if (genctx->masked_key_file[0] != '\0')
    {
        /* Allocate a 8192-byte buffer for the masked key */
        const uint32_t masked_key_buffer_size = 8192;
        uint8_t *masked_key_buffer = OPENSSL_malloc(masked_key_buffer_size);
        if (masked_key_buffer == NULL)
        {
            printf(
                "azihsm_ossl_keymgmt_gen: Failed to allocate masked key buffer (%u bytes)\n",
                masked_key_buffer_size
            );

            azihsm_key_delete(private);
            azihsm_key_delete(public);

            OPENSSL_free(ec_key);
            return NULL;
        }

        /* Retrieve masked key with the allocated buffer */
        struct azihsm_key_prop prop = { .id = AZIHSM_KEY_PROP_ID_MASKED_KEY,
                                        .val = masked_key_buffer,
                                        .len = masked_key_buffer_size };

        azihsm_status retrieve_status = azihsm_key_get_prop(private, &prop);

        /* Check if we got the masked key */
        if (retrieve_status == AZIHSM_STATUS_SUCCESS && prop.len > 0)
        {
            /* Write masked key to file */
            FILE *f = fopen(genctx->masked_key_file, "wb");
            if (f == NULL)
            {
                printf(
                    "azihsm_ossl_keymgmt_gen: Failed to open masked key file: %s\n",
                    genctx->masked_key_file
                );

                azihsm_key_delete(private);
                azihsm_key_delete(public);

                OPENSSL_free(masked_key_buffer);
                OPENSSL_free(ec_key);
                return NULL;
            }

            size_t written = fwrite(masked_key_buffer, 1, prop.len, f);
            fclose(f);

            if (written != prop.len)
            {
                printf(
                    "azihsm_ossl_keymgmt_gen: Failed to write complete masked key to file (%zu/%u "
                    "bytes)\n",
                    written,
                    prop.len
                );

                azihsm_key_delete(private);
                azihsm_key_delete(public);

                OPENSSL_free(masked_key_buffer);
                OPENSSL_free(ec_key);
                return NULL;
            }
        }
        else if (retrieve_status != AZIHSM_STATUS_KEY_PROPERTY_NOT_PRESENT)
        {
            printf(
                "azihsm_ossl_keymgmt_gen: Failed to retrieve masked key (status: %d)\n",
                retrieve_status
            );
            OPENSSL_free(masked_key_buffer);
            OPENSSL_free(ec_key);
            return NULL;
        }
        /* If KEY_PROPERTY_NOT_PRESENT, just continue without masked key */

        OPENSSL_free(masked_key_buffer);
    }

    return ec_key;
}

static void azihsm_ossl_keymgmt_free(AZIHSM_EC_KEY *ec_key)
{
    if (ec_key == NULL)
    {
        return;
    }

    azihsm_key_delete(ec_key->key.pub);
    azihsm_key_delete(ec_key->key.priv);

    OPENSSL_free(ec_key);
}

static void azihsm_ossl_keymgmt_gen_cleanup(AIHSM_EC_GEN_CTX *genctx)
{
    if (genctx == NULL)
    {
        return;
    }

    OPENSSL_clear_free(genctx, sizeof(AIHSM_EC_GEN_CTX));
}

static int azihsm_ossl_keymgmt_gen_set_params(AIHSM_EC_GEN_CTX *genctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (params == NULL)
    {
        return 1;
    }

    /* Check for key_usage parameter specifically */
    if ((p = OSSL_PARAM_locate_const(params, AZIHSM_OSSL_PKEY_PARAM_KEY_USAGE)) != NULL)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        if (azihsm_ossl_key_usage_from_str(p->data, &genctx->key_usage) < 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return 0;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {

        int curve_id;

        if (p->data_type != OSSL_PARAM_UTF8_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        if ((curve_id = azihsm_ossl_name_to_curve_id(p->data)) == AIHSM_EC_CURVE_ID_NONE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
            return 0;
        }

        genctx->ec_curve_id = (uint32_t)curve_id;
    }

    if ((p = OSSL_PARAM_locate_const(params, AZIHSM_OSSL_PKEY_PARAM_SESSION)) != NULL)
    {

        int session_result;

        if (p->data_type != OSSL_PARAM_UTF8_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        if ((session_result = azihsm_ossl_session_from_str(p->data)) < 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        genctx->session_flag = (bool)session_result;
    }

    if ((p = OSSL_PARAM_locate_const(params, AZIHSM_OSSL_PKEY_PARAM_MASKED_KEY)) != NULL)
    {

        if (p->data_type != OSSL_PARAM_UTF8_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        if (azihsm_ossl_masked_key_filepath_validate(p->data) < 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        strncpy(genctx->masked_key_file, p->data, sizeof(genctx->masked_key_file) - 1);
        genctx->masked_key_file[sizeof(genctx->masked_key_file) - 1] = '\0';
    }

    return 1;
}

static AIHSM_EC_GEN_CTX *azihsm_ossl_keymgmt_gen_init(
    void *ctx,
    int selection,
    const OSSL_PARAM params[]
)
{
    AIHSM_EC_GEN_CTX *genctx;
    AZIHSM_OSSL_PROV_CTX *provctx = ctx;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
    {
        return NULL;
    }

    genctx = OPENSSL_zalloc(sizeof(AIHSM_EC_GEN_CTX));

    if (genctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    genctx->session = provctx->session;

    genctx->key_usage = AIHSM_KEY_USAGE_DEFAULT;
    genctx->ec_curve_id = AIHSM_EC_CURVE_ID_DEFAULT;
    genctx->session_flag = false;
    genctx->masked_key_file[0] = '\0';

    if (azihsm_ossl_keymgmt_gen_set_params(genctx, params) == 0)
    {
        azihsm_ossl_keymgmt_gen_cleanup(genctx);
        return NULL;
    }

    return genctx;
}

static int azihsm_ossl_keymgmt_has(const AZIHSM_EC_KEY *ec_key, int selection)
{
    int has_selection = 1;

    if (ec_key == NULL)
    {
        return 0;
    }

    if ((selection & AIHSM_EC_POSSIBLE_SELECTIONS) == 0)
    {
        return 1;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        has_selection &= ec_key->has_private;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        has_selection &= ec_key->has_public;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
    {
        has_selection &= 1; // EC curve is a mandatory property
    }

    return has_selection;
}

static int azihsm_ossl_keymgmt_match(
    const AZIHSM_EC_KEY *ec_key1,
    const AZIHSM_EC_KEY *ec_key2,
    ossl_unused int selection
)
{
    if (ec_key1 == NULL || ec_key2 == NULL)
    {
        return 0;
    }

    if (ec_key1->key.pub != ec_key2->key.pub)
    {
        return 0;
    }

    if (ec_key1->key.priv != ec_key2->key.priv)
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

static int azihsm_ossl_keymgmt_get_params(AZIHSM_EC_KEY *key, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);

    if (p != NULL && !OSSL_PARAM_set_utf8_string(
                         p,
                         OBJ_nid2sn(azihsm_ossl_curve_id_to_nid((int)key->genctx.ec_curve_id))
                     ))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    return 1;
}

static const OSSL_PARAM *azihsm_ossl_keymgmt_gettable_params(ossl_unused void *ctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_END
    };

    return params;
}

static const OSSL_PARAM *azihsm_ossl_keymgmt_gen_settable_params(
    ossl_unused void *genctx,
    ossl_unused void *ctx
)
{
    static const OSSL_PARAM settable_params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_KEY_USAGE, NULL, 0),
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_SESSION, NULL, 0),
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_MASKED_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    return settable_params;
}

/* EC Key Management */
const OSSL_DISPATCH azihsm_ossl_ec_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))azihsm_ossl_keymgmt_gen },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))azihsm_ossl_keymgmt_gen_init },
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
