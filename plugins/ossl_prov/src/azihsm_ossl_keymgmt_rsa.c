// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <string.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_hsm.h"
#include "azihsm_ossl_pkey_param.h"
#include "azihsm_ossl_rsa.h"

/*
 * RSA/RSA-PSS KeyManagement
 *
 * NOTE: The HSM is not capable of generating RSA keys natively.
 * All RSA keys must be provided externally and imported into the HSM
 * via the azihsm.input_key parameter.
 *
 * supported parameters (pkeyopt):
 *
 *   @rsa_keygen_bits
 *   Description: RSA public key bit length
 *   Accepted values: 2048, 3072, 4096
 *   Default: 2048
 *   Example:
 *      -pkeyopt rsa_keygen_bits:2048
 *
 *   @azihsm.key_usage
 *   Description: Key usage type for the key pair
 *   Accepted values: digitalSignature (private: sign, public: verify)
 *   Default value: digitalSignature
 *   Example:
 *      -pkeyopt azihsm.key_usage:digitalSignature
 *
 *   @azihsm.session
 *   Description: Whether to create a session key or persistent key
 *   Accepted values: true, false, 1, 0, yes, no
 *   Default value: false
 *   Example:
 *      -pkeyopt azihsm.session:true
 *
 *   @azihsm.input_key
 *   Description: Path to an external DER-encoded RSA private key to import.
 *   When set, the key is wrapped (RSA-AES) and unwrapped into the HSM.
 *   THIS PARAMETER IS REQUIRED - the HSM cannot generate RSA keys natively.
 *   Example:
 *      -pkeyopt azihsm.input_key:/path/to/rsa_key.der
 *
 *   @azihsm.masked_key
 *   Description: Path to write the masked key blob for later reload via store
 *   Example:
 *      -pkeyopt azihsm.masked_key:/path/to/masked.bin
 *
 * */

#define AIHSM_RSA_POSSIBLE_SELECTIONS                                                              \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)

#define AIHSM_RSA_PUBKEY_BITS_MIN 2048
#define AIHSM_RSA_PUBKEY_BITS_DEFAULT AIHSM_RSA_PUBKEY_BITS_MIN

#define AIHSM_KEY_USAGE_DEFAULT KEY_USAGE_DIGITAL_SIGNATURE

#define MAX_INPUT_KEY_SIZE (64 * 1024)

/* Key Management Functions */

/*
 * Import an external DER-encoded RSA private key into the HSM via wrap-then-unwrap.
 *
 * Flow:
 *   1. Read the DER file from disk
 *   2. Get the RSA wrapping key pair from the HSM
 *   3. Wrap the DER blob with azihsm_crypt_encrypt (RSA-AES-WRAP)
 *   4. Unwrap into the HSM with azihsm_key_unwrap_pair (RSA-AES-KEY-WRAP)
 *   5. Return the resulting key handles
 */
static azihsm_status azihsm_ossl_rsa_keymgmt_gen_import(
    AZIHSM_RSA_GEN_CTX *genctx,
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

    /* Normalize to PKCS#8 DER (handles both PKCS#1 and PKCS#8 input) */
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
        OPENSSL_cleanse(input_buf, input_size);
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

static AZIHSM_RSA_KEY *azihsm_ossl_keymgmt_gen(
    AZIHSM_RSA_GEN_CTX *genctx,
    ossl_unused OSSL_CALLBACK *cb,
    ossl_unused void *cbarg
)
{
    AZIHSM_RSA_KEY *rsa_key;
    azihsm_handle public = 0, private = 0;
    azihsm_status status;
    const bool enable = true;
    const azihsm_key_class priv_class = AZIHSM_KEY_CLASS_PRIVATE;
    const azihsm_key_class pub_class = AZIHSM_KEY_CLASS_PUBLIC;
    const azihsm_key_kind key_kind = AZIHSM_KEY_KIND_RSA;

    /*
     * The HSM cannot generate RSA keys natively.
     * RSA keys must be provided externally via the azihsm.input_key parameter.
     */
    if (genctx->input_key_file[0] == '\0')
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_MISSING_KEY,
            "azihsm: RSA key generation requires azihsm.input_key parameter. "
            "The HSM cannot generate RSA keys natively. "
            "Please provide an external DER-encoded RSA private key: "
            "-pkeyopt azihsm.input_key:/path/to/rsa_key.der"
        );
        return NULL;
    }

    /* RSA key properties: class, kind, bit_len, usage, and optionally session */
#define AZIHSM_RSA_KEY_PROPS_SIZE 5
    struct azihsm_key_prop pub_key_props[AZIHSM_RSA_KEY_PROPS_SIZE] = {
        [0] = { .id = AZIHSM_KEY_PROP_ID_CLASS,
                .val = (void *)&pub_class,
                .len = sizeof(pub_class) },
        [1] = { .id = AZIHSM_KEY_PROP_ID_KIND, .val = (void *)&key_kind, .len = sizeof(key_kind) },
        [2] = { .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
                .val = (void *)&genctx->pubkey_bits,
                .len = sizeof(genctx->pubkey_bits) },
        [3] = { .id = (azihsm_key_prop_id)azihsm_ossl_get_pub_key_property(genctx->key_usage),
                .val = (void *)&enable,
                .len = sizeof(bool) },
    };

    struct azihsm_key_prop priv_key_props[AZIHSM_RSA_KEY_PROPS_SIZE] = {
        [0] = { .id = AZIHSM_KEY_PROP_ID_CLASS,
                .val = (void *)&priv_class,
                .len = sizeof(priv_class) },
        [1] = { .id = AZIHSM_KEY_PROP_ID_KIND, .val = (void *)&key_kind, .len = sizeof(key_kind) },
        [2] = { .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
                .val = (void *)&genctx->pubkey_bits,
                .len = sizeof(genctx->pubkey_bits) },
        [3] = { .id = (azihsm_key_prop_id)azihsm_ossl_get_priv_key_property(genctx->key_usage),
                .val = (void *)&enable,
                .len = sizeof(bool) },
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

    if ((rsa_key = OPENSSL_zalloc(sizeof(AZIHSM_RSA_KEY))) == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* Import external key via wrap-unwrap */
    status = azihsm_ossl_rsa_keymgmt_gen_import(
        genctx,
        &priv_key_prop_list,
        &pub_key_prop_list,
        &private,
        &public
    );

    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_free(rsa_key);
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        return NULL;
    }

    rsa_key->genctx = *genctx;
    rsa_key->key.pub = public;
    rsa_key->has_public = true;
    rsa_key->key.priv = private;
    rsa_key->has_private = true;

    /* Handle masked key file output if requested */
    if (genctx->masked_key_file[0] != '\0')
    {
        /* First call to get required buffer size */
        struct azihsm_key_prop prop = { .id = AZIHSM_KEY_PROP_ID_MASKED_KEY,
                                        .val = NULL,
                                        .len = 0 };

        azihsm_status retrieve_status = azihsm_key_get_prop(private, &prop);

        if (retrieve_status == AZIHSM_STATUS_BUFFER_TOO_SMALL && prop.len > 0)
        {
            /* Allocate buffer of exact size */
            uint32_t masked_key_buffer_size = prop.len;
            uint8_t *masked_key_buffer = OPENSSL_malloc(masked_key_buffer_size);
            if (masked_key_buffer == NULL)
            {
                azihsm_key_delete(private);
                azihsm_key_delete(public);
                OPENSSL_free(rsa_key);
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                return NULL;
            }

            /* Second call to retrieve the masked key */
            prop.val = masked_key_buffer;
            retrieve_status = azihsm_key_get_prop(private, &prop);

            if (retrieve_status != AZIHSM_STATUS_SUCCESS)
            {
                azihsm_key_delete(private);
                azihsm_key_delete(public);
                OPENSSL_cleanse(masked_key_buffer, masked_key_buffer_size);
                OPENSSL_free(masked_key_buffer);
                OPENSSL_free(rsa_key);
                ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
                return NULL;
            }

            /* Write masked key to file */
            FILE *f = fopen(genctx->masked_key_file, "wb");
            if (f == NULL)
            {
                azihsm_key_delete(private);
                azihsm_key_delete(public);
                OPENSSL_cleanse(masked_key_buffer, masked_key_buffer_size);
                OPENSSL_free(masked_key_buffer);
                OPENSSL_free(rsa_key);
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
                OPENSSL_free(rsa_key);
                ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
                return NULL;
            }

            OPENSSL_cleanse(masked_key_buffer, masked_key_buffer_size);
            OPENSSL_free(masked_key_buffer);
        }
        else if (retrieve_status != AZIHSM_STATUS_PROPERTY_NOT_PRESENT)
        {
            /* Unexpected error - not BUFFER_TOO_SMALL and not PROPERTY_NOT_PRESENT */
            azihsm_key_delete(private);
            azihsm_key_delete(public);
            OPENSSL_free(rsa_key);
            ERR_raise(ERR_LIB_PROV, ERR_R_OPERATION_FAIL);
            return NULL;
        }
        /* If PROPERTY_NOT_PRESENT, continue without masked key */
    }

    return rsa_key;
}

static void azihsm_ossl_keymgmt_free(AZIHSM_RSA_KEY *rsa_key)
{
    if (rsa_key == NULL)
    {
        return;
    }

    if (rsa_key->key.pub != 0)
    {
        azihsm_key_delete(rsa_key->key.pub);
    }
    if (rsa_key->key.priv != 0)
    {
        azihsm_key_delete(rsa_key->key.priv);
    }

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
        return OSSL_SUCCESS;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL)
    {
        uint32_t bits;

        if (!OSSL_PARAM_get_uint32(p, &bits))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return OSSL_FAILURE;
        }

        if (bits < AIHSM_RSA_PUBKEY_BITS_MIN)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_KEY_SIZE_TOO_SMALL);
            return OSSL_FAILURE;
        }

        genctx->pubkey_bits = bits;
    }

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
    genctx->key_usage = AIHSM_KEY_USAGE_DEFAULT;
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
        return OSSL_FAILURE;
    }

    if ((selection & AIHSM_RSA_POSSIBLE_SELECTIONS) == 0)
    {
        return OSSL_SUCCESS;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        has_selection &= rsa_key->has_private;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        has_selection &= rsa_key->has_public;
    }

    return has_selection ? OSSL_SUCCESS : OSSL_FAILURE;
}

static int azihsm_ossl_keymgmt_match(
    const AZIHSM_RSA_KEY *rsa_key1,
    const AZIHSM_RSA_KEY *rsa_key2,
    ossl_unused int selection
)
{
    if (rsa_key1 == NULL || rsa_key2 == NULL)
    {
        return OSSL_FAILURE;
    }

    if (rsa_key1->key.pub != rsa_key2->key.pub)
    {
        return OSSL_FAILURE;
    }

    if (rsa_key1->key.priv != rsa_key2->key.priv)
    {
        return OSSL_FAILURE;
    }

    return OSSL_SUCCESS;
}

static void *azihsm_ossl_keymgmt_load(const void *reference, size_t reference_sz)
{
    AZIHSM_RSA_KEY *dst_key;

    /* Validate reference size matches our key object */
    if (reference == NULL || reference_sz != sizeof(AZIHSM_RSA_KEY))
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    /* Create a copy of the key - reference contains the raw bytes of AZIHSM_RSA_KEY */
    dst_key = OPENSSL_zalloc(sizeof(AZIHSM_RSA_KEY));
    if (dst_key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /* Copy the key structure from reference */
    memcpy(dst_key, reference, sizeof(AZIHSM_RSA_KEY));

    return dst_key;
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

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL)
    {
        /* RSA signature size equals key size in bytes */
        size_t sig_size = key->genctx.pubkey_bits / 8;
        if (!OSSL_PARAM_set_size_t(p, sig_size))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM *azihsm_ossl_keymgmt_gettable_params(ossl_unused void *ctx)
{
    static const OSSL_PARAM gettable_params[] = { OSSL_PARAM_uint32(OSSL_PKEY_PARAM_BITS, NULL),
                                                  OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
                                                  OSSL_PARAM_END };

    return gettable_params;
}

static const OSSL_PARAM *azihsm_ossl_keymgmt_gen_settable_params(
    ossl_unused void *genctx,
    ossl_unused void *ctx
)
{
    static const OSSL_PARAM settable_params[] = {
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_RSA_BITS, NULL),
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_KEY_USAGE, NULL, 0),
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_SESSION, NULL, 0),
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_MASKED_KEY, NULL, 0),
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_INPUT_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    return settable_params;
}

/* For any RSA key, we use the "RSA" algorithms regardless of sub-type. */
static const char *azihsm_ossl_keymgmt_rsa_query_operation_name(
    ossl_unused int operation_id
)
{
    return "RSA";
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
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))azihsm_ossl_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))azihsm_ossl_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))azihsm_ossl_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))azihsm_ossl_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))azihsm_ossl_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))azihsm_ossl_keymgmt_rsa_query_operation_name },
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
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))azihsm_ossl_keymgmt_load },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))azihsm_ossl_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))azihsm_ossl_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))azihsm_ossl_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))azihsm_ossl_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))azihsm_ossl_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))azihsm_ossl_keymgmt_rsa_query_operation_name },
    { 0, NULL }
};
