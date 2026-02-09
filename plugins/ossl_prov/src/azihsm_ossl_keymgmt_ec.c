// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <string.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_ec.h"
#include "azihsm_ossl_helpers.h"
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
 *   @azihsm.input_key
 *   Description: Path to an external DER-encoded EC private key to import.
 *   When set, the key is wrapped (RSA-AES) and unwrapped into the HSM
 *   instead of generating a new key pair.
 *   Example:
 *      -pkeyopt azihsm.input_key:/path/to/ec_key.der
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

/**
 * Get the key size in bits for a given curve.
 */
static int azihsm_ossl_curve_id_to_bits(const int curve_id)
{
    switch (curve_id)
    {
    case AZIHSM_ECC_CURVE_P256:
        return AZIHSM_EC_P256_KEY_BITS;
    case AZIHSM_ECC_CURVE_P384:
        return AZIHSM_EC_P384_KEY_BITS;
    case AZIHSM_ECC_CURVE_P521:
        return AZIHSM_EC_P521_KEY_BITS;
    default:
        return 0;
    }
}

/**
 * Get the ECDSA signature size for a given curve.
 * Returns the raw signature size (r || s concatenated).
 */
static size_t azihsm_ossl_curve_id_to_sig_size(const int curve_id)
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

/* Key Management Functions */

#define MAX_INPUT_KEY_SIZE (64 * 1024)

/*
 * Import an external DER-encoded EC private key into the HSM via wrap-then-unwrap.
 *
 * Flow:
 *   1. Read the DER file from disk
 *   2. Get the RSA wrapping key pair from the HSM
 *   3. Wrap the DER blob with azihsm_crypt_encrypt (RSA-AES-WRAP)
 *   4. Unwrap into the HSM with azihsm_key_unwrap_pair (RSA-AES-KEY-WRAP)
 *   5. Return the resulting key handles
 */
static azihsm_status azihsm_ossl_keymgmt_gen_import(
    AIHSM_EC_GEN_CTX *genctx,
    const struct azihsm_key_prop_list *priv_key_prop_list,
    const struct azihsm_key_prop_list *pub_key_prop_list,
    azihsm_handle *out_priv,
    azihsm_handle *out_pub
)
{
    azihsm_status status;
    azihsm_handle wrapping_pub = 0, wrapping_priv = 0;
    uint8_t *input_buf = NULL;
    long input_size = 0;
    FILE *f = NULL;

    /* 1. Read the input DER file */
    f = fopen(genctx->input_key_file, "rb");
    if (f == NULL)
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    input_size = ftell(f);
    if (input_size <= 0 || input_size > MAX_INPUT_KEY_SIZE)
    {
        fclose(f);
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    if (fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    input_buf = OPENSSL_malloc((size_t)input_size);
    if (input_buf == NULL)
    {
        fclose(f);
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    if (fread(input_buf, 1, (size_t)input_size, f) != (size_t)input_size)
    {
        fclose(f);
        OPENSSL_cleanse(input_buf, (size_t)input_size);
        OPENSSL_free(input_buf);
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }
    fclose(f);

    /* Normalize to PKCS#8 DER (handles both SEC1 and PKCS#8 input) */
    {
        uint8_t *pkcs8_buf = NULL;
        int pkcs8_len = 0;

        if (azihsm_ossl_normalize_der_to_pkcs8(input_buf, input_size, &pkcs8_buf, &pkcs8_len) !=
            OSSL_SUCCESS)
        {
            OPENSSL_cleanse(input_buf, (size_t)input_size);
            OPENSSL_free(input_buf);
            return AZIHSM_STATUS_INVALID_ARGUMENT;
        }

        /* Replace input buffer with PKCS#8 version */
        OPENSSL_cleanse(input_buf, (size_t)input_size);
        OPENSSL_free(input_buf);
        input_buf = pkcs8_buf;
        input_size = pkcs8_len;
    }

    /* 2. Retrieve the RSA unwrapping key pair from the HSM */
    {
        struct azihsm_algo rsa_keygen_algo = {
            .id = AZIHSM_ALGO_ID_RSA_KEY_UNWRAPPING_KEY_PAIR_GEN,
            .params = NULL,
            .len = 0,
        };

        const uint32_t rsa_bits = 2048;
        const azihsm_key_class rsa_priv_class = AZIHSM_KEY_CLASS_PRIVATE;
        const azihsm_key_class rsa_pub_class = AZIHSM_KEY_CLASS_PUBLIC;
        const azihsm_key_kind rsa_kind = AZIHSM_KEY_KIND_RSA;
        const bool rsa_enable = true;

        struct azihsm_key_prop rsa_priv_props[] = {
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = (void *)&rsa_bits, .len = sizeof(rsa_bits) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS,
              .val = (void *)&rsa_priv_class,
              .len = sizeof(rsa_priv_class) },
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = (void *)&rsa_kind, .len = sizeof(rsa_kind) },
            { .id = AZIHSM_KEY_PROP_ID_UNWRAP,
              .val = (void *)&rsa_enable,
              .len = sizeof(rsa_enable) },
        };

        struct azihsm_key_prop rsa_pub_props[] = {
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = (void *)&rsa_bits, .len = sizeof(rsa_bits) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS,
              .val = (void *)&rsa_pub_class,
              .len = sizeof(rsa_pub_class) },
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = (void *)&rsa_kind, .len = sizeof(rsa_kind) },
            { .id = AZIHSM_KEY_PROP_ID_WRAP,
              .val = (void *)&rsa_enable,
              .len = sizeof(rsa_enable) },
        };

        struct azihsm_key_prop_list rsa_priv_prop_list = {
            .props = rsa_priv_props,
            .count = 4,
        };

        struct azihsm_key_prop_list rsa_pub_prop_list = {
            .props = rsa_pub_props,
            .count = 4,
        };

        status = azihsm_key_gen_pair(
            genctx->session,
            &rsa_keygen_algo,
            &rsa_priv_prop_list,
            &rsa_pub_prop_list,
            &wrapping_priv,
            &wrapping_pub
        );
    }
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_cleanse(input_buf, (size_t)input_size);
        OPENSSL_free(input_buf);
        return status;
    }

    /* 3. Wrap the DER blob */
    struct azihsm_algo_rsa_pkcs_oaep_params oaep_params = {
        .hash_algo_id = AZIHSM_ALGO_ID_SHA256,
        .mgf1_hash_algo_id = AZIHSM_MGF1_ID_SHA256,
        .label = NULL,
    };

    struct azihsm_algo_rsa_aes_wrap_params wrap_params = {
        .oaep_params = &oaep_params,
        .aes_key_bits = 256,
    };

    struct azihsm_algo wrap_algo = {
        .id = AZIHSM_ALGO_ID_RSA_AES_WRAP,
        .params = &wrap_params,
        .len = sizeof(wrap_params),
    };

    struct azihsm_buffer plain_buf = {
        .ptr = input_buf,
        .len = (uint32_t)input_size,
    };

    /* Two-call pattern: first query required size */
    struct azihsm_buffer wrapped_buf = {
        .ptr = NULL,
        .len = 0,
    };

    status = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub, &plain_buf, &wrapped_buf);
    if (status != AZIHSM_STATUS_BUFFER_TOO_SMALL || wrapped_buf.len == 0)
    {
        OPENSSL_cleanse(input_buf, (size_t)input_size);
        OPENSSL_free(input_buf);
        azihsm_key_delete(wrapping_pub);
        azihsm_key_delete(wrapping_priv);
        return (status == AZIHSM_STATUS_SUCCESS) ? AZIHSM_STATUS_INTERNAL_ERROR : status;
    }

    /* Allocate buffer for wrapped data */
    uint32_t wrapped_size = wrapped_buf.len;
    uint8_t *wrapped_data = OPENSSL_malloc(wrapped_size);
    if (wrapped_data == NULL)
    {
        OPENSSL_cleanse(input_buf, (size_t)input_size);
        OPENSSL_free(input_buf);
        azihsm_key_delete(wrapping_pub);
        azihsm_key_delete(wrapping_priv);
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    /* Second call: perform actual wrap */
    wrapped_buf.ptr = wrapped_data;
    wrapped_buf.len = wrapped_size;

    status = azihsm_crypt_encrypt(&wrap_algo, wrapping_pub, &plain_buf, &wrapped_buf);
    OPENSSL_cleanse(input_buf, (size_t)input_size);
    OPENSSL_free(input_buf);

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_cleanse(wrapped_data, wrapped_size);
        OPENSSL_free(wrapped_data);
        azihsm_key_delete(wrapping_pub);
        azihsm_key_delete(wrapping_priv);
        return status;
    }

    /* 4. Unwrap into the HSM */
    struct azihsm_algo_rsa_aes_key_wrap_params unwrap_params = {
        .oaep_params = &oaep_params,
    };

    struct azihsm_algo unwrap_algo = {
        .id = AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP,
        .params = &unwrap_params,
        .len = sizeof(unwrap_params),
    };

    status = azihsm_key_unwrap_pair(
        &unwrap_algo,
        wrapping_priv,
        &wrapped_buf,
        priv_key_prop_list,
        pub_key_prop_list,
        out_priv,
        out_pub
    );
    azihsm_key_delete(wrapping_pub);
    azihsm_key_delete(wrapping_priv);

    OPENSSL_cleanse(wrapped_data, wrapped_size);
    OPENSSL_free(wrapped_data);

    return status;
}

static AZIHSM_EC_KEY *azihsm_ossl_keymgmt_gen(
    AIHSM_EC_GEN_CTX *genctx,
    ossl_unused OSSL_CALLBACK *cb,
    ossl_unused void *cbarg
)
{
    AZIHSM_EC_KEY *ec_key;
    azihsm_handle public = 0, private = 0;
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

    if (genctx->input_key_file[0] != '\0')
    {
        /* Import path: wrap external DER key, then unwrap into HSM */
        status = azihsm_ossl_keymgmt_gen_import(
            genctx,
            &priv_key_prop_list,
            &pub_key_prop_list,
            &private,
            &public
        );
    }
    else
    {
        /* Normal generation path */
        status = azihsm_key_gen_pair(
            genctx->session,
            &algo,
            &priv_key_prop_list,
            &pub_key_prop_list,
            &private,
            &public
        );
    }

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        if (public != 0)
        {
            azihsm_key_delete(public);
        }
        if (private != 0)
        {
            azihsm_key_delete(private);
        }
        OPENSSL_free(ec_key);
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
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
            azihsm_key_delete(private);
            azihsm_key_delete(public);

            OPENSSL_free(ec_key);
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
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
                azihsm_key_delete(private);
                azihsm_key_delete(public);

                OPENSSL_cleanse(masked_key_buffer, masked_key_buffer_size);
                OPENSSL_free(masked_key_buffer);
                OPENSSL_free(ec_key);
                ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
                return NULL;
            }

            size_t written = fwrite(masked_key_buffer, 1, prop.len, f);
            fclose(f);

            if (written != prop.len)
            {
                azihsm_key_delete(private);
                azihsm_key_delete(public);

                OPENSSL_cleanse(masked_key_buffer, masked_key_buffer_size);
                OPENSSL_free(masked_key_buffer);
                OPENSSL_free(ec_key);
                ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
                return NULL;
            }
        }
        else if (retrieve_status != AZIHSM_STATUS_PROPERTY_NOT_PRESENT)
        {
            azihsm_key_delete(private);
            azihsm_key_delete(public);

            OPENSSL_cleanse(masked_key_buffer, masked_key_buffer_size);
            OPENSSL_free(masked_key_buffer);
            OPENSSL_free(ec_key);
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return NULL;
        }
        /* If KEY_PROPERTY_NOT_PRESENT, just continue without masked key */

        OPENSSL_cleanse(masked_key_buffer, masked_key_buffer_size);
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

    if (ec_key->key.pub != 0)
    {
        azihsm_key_delete(ec_key->key.pub);
    }
    if (ec_key->key.priv != 0)
    {
        azihsm_key_delete(ec_key->key.priv);
    }

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
        return OSSL_SUCCESS;
    }

    /* Check for key_usage parameter specifically */
    if ((p = OSSL_PARAM_locate_const(params, AZIHSM_OSSL_PKEY_PARAM_KEY_USAGE)) != NULL)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        if (azihsm_ossl_key_usage_from_str(p->data, &genctx->key_usage) < 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return OSSL_FAILURE;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL)
    {

        int curve_id;

        if (p->data_type != OSSL_PARAM_UTF8_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        if ((curve_id = azihsm_ossl_name_to_curve_id(p->data)) == AIHSM_EC_CURVE_ID_NONE)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
            return OSSL_FAILURE;
        }

        genctx->ec_curve_id = (uint32_t)curve_id;
    }

    if ((p = OSSL_PARAM_locate_const(params, AZIHSM_OSSL_PKEY_PARAM_SESSION)) != NULL)
    {

        int session_result;

        if (p->data_type != OSSL_PARAM_UTF8_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        if ((session_result = azihsm_ossl_session_from_str(p->data)) < 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        genctx->session_flag = (bool)session_result;
    }

    if ((p = OSSL_PARAM_locate_const(params, AZIHSM_OSSL_PKEY_PARAM_MASKED_KEY)) != NULL)
    {

        if (p->data_type != OSSL_PARAM_UTF8_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        if (azihsm_ossl_masked_key_filepath_validate(p->data) < 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        strncpy(genctx->masked_key_file, p->data, sizeof(genctx->masked_key_file) - 1);
        genctx->masked_key_file[sizeof(genctx->masked_key_file) - 1] = '\0';
    }

    if ((p = OSSL_PARAM_locate_const(params, AZIHSM_OSSL_PKEY_PARAM_INPUT_KEY)) != NULL)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        if (azihsm_ossl_input_key_filepath_validate(p->data) < 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        strncpy(genctx->input_key_file, p->data, sizeof(genctx->input_key_file) - 1);
        genctx->input_key_file[sizeof(genctx->input_key_file) - 1] = '\0';
    }

    return OSSL_SUCCESS;
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
    genctx->input_key_file[0] = '\0';

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
        return OSSL_FAILURE;
    }

    if ((selection & AIHSM_EC_POSSIBLE_SELECTIONS) == 0)
    {
        return OSSL_SUCCESS;
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
        return OSSL_FAILURE;
    }

    if (ec_key1->key.pub != ec_key2->key.pub)
    {
        return OSSL_FAILURE;
    }

    if (ec_key1->key.priv != ec_key2->key.priv)
    {
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static void *azihsm_ossl_keymgmt_load(const void *reference, size_t reference_sz)
{
    AZIHSM_EC_KEY *dst_key;

    /* Validate reference size matches our key object */
    if (reference == NULL || reference_sz != sizeof(AZIHSM_EC_KEY))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    /* Create a copy of the key - reference contains the raw bytes of AZIHSM_EC_KEY */
    dst_key = OPENSSL_zalloc(sizeof(AZIHSM_EC_KEY));
    if (dst_key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* Copy the key structure from reference */
    memcpy(dst_key, reference, sizeof(AZIHSM_EC_KEY));

    return dst_key;
}

static int azihsm_ossl_keymgmt_import(
    ossl_unused void *keydata,
    ossl_unused int selection,
    ossl_unused const OSSL_PARAM params[]
)
{
    return OSSL_FAILURE;
}

static int azihsm_ossl_keymgmt_export(
    ossl_unused const void *keydata,
    ossl_unused int selection,
    ossl_unused OSSL_CALLBACK *param_cb,
    ossl_unused void *cbarg
)
{
    /* Export not supported — public-key DER encoding is handled by the
     * SubjectPublicKeyInfo encoder registered in azihsm_ossl_base.c. */
    return OSSL_FAILURE;
}

static const OSSL_PARAM *azihsm_ossl_keymgmt_import_types(ossl_unused int selection)
{
    return NULL;
}

static const OSSL_PARAM *azihsm_ossl_keymgmt_export_types(ossl_unused int selection)
{
    return NULL;
}

static int azihsm_ossl_keymgmt_get_params(AZIHSM_EC_KEY *key, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if (key == NULL)
    {
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(
                         p,
                         OBJ_nid2sn(azihsm_ossl_curve_id_to_nid((int)key->genctx.ec_curve_id))
                     ))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return OSSL_FAILURE;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL)
    {
        int bits = azihsm_ossl_curve_id_to_bits((int)key->genctx.ec_curve_id);
        if (bits == 0 || !OSSL_PARAM_set_int(p, bits))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return OSSL_FAILURE;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL)
    {
        /*
         * Report the maximum DER-encoded ECDSA-Sig-Value size.
         * SEQUENCE { INTEGER r, INTEGER s } — each INTEGER may have a
         * leading zero byte.  OpenSSL uses this for buffer allocation.
         */
        size_t raw = azihsm_ossl_curve_id_to_sig_size((int)key->genctx.ec_curve_id);
        size_t coord = raw / 2;
        size_t der_max = 2 * (coord + 3) + 3;
        if (raw == 0 || !OSSL_PARAM_set_size_t(p, der_max))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return OSSL_FAILURE;
        }
    }

    return OSSL_SUCCESS;
}

static const OSSL_PARAM *azihsm_ossl_keymgmt_gettable_params(ossl_unused void *ctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
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
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_INPUT_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    return settable_params;
}

static const char *azihsm_ossl_keymgmt_ec_query_operation_name(int operation_id)
{
    switch (operation_id)
    {
    case OSSL_OP_KEYEXCH:
        return "ECDH";
    case OSSL_OP_SIGNATURE:
        return "ECDSA";
    }
    return "EC";
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
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))azihsm_ossl_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))azihsm_ossl_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))azihsm_ossl_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))azihsm_ossl_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))azihsm_ossl_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))azihsm_ossl_keymgmt_ec_query_operation_name },
    { 0, NULL }
};
