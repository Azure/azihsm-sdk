// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <string.h>

#include "azihsm_ossl_base.h"
#include "azihsm_ossl_file_io.h"
#include "azihsm_ossl_helpers.h"
#include "azihsm_ossl_hsm.h"
#include "azihsm_ossl_masked_key.h"
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
 *                    keyWrapping (export HSM's internal unwrapping public key;
 *                                rsa_keygen_bits must be 2048 or omitted)
 *   Default value: digitalSignature
 *   Example:
 *      -pkeyopt azihsm.key_usage:digitalSignature
 *      -pkeyopt azihsm.key_usage:keyWrapping
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
 *   @azihsm.wrapped_key
 *   Description: Path to a pre-wrapped key blob (produced by the wrap_key tool).
 *   When set, the blob is unwrapped directly into the HSM without DER normalization.
 *   Mutually exclusive with azihsm.input_key.
 *   Example:
 *      -pkeyopt azihsm.wrapped_key:/path/to/wrapped.bin
 *
 * */

#define AIHSM_RSA_POSSIBLE_SELECTIONS                                                              \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)

#define AIHSM_RSA_PUBKEY_BITS_MIN 2048
#define AIHSM_RSA_PUBKEY_BITS_DEFAULT AIHSM_RSA_PUBKEY_BITS_MIN
#define AIHSM_RSA_WRAPPING_KEY_BITS 2048

#define AIHSM_KEY_USAGE_DEFAULT KEY_USAGE_DIGITAL_SIGNATURE

/* Key Management Functions */

/*
 * Import a plaintext DER key file into the HSM.
 * Delegates to the shared azihsm_import_key_pair() helper.
 */
static azihsm_status azihsm_ossl_rsa_keymgmt_gen_import(
    AZIHSM_RSA_GEN_CTX *genctx,
    const struct azihsm_key_prop_list *priv_key_prop_list,
    const struct azihsm_key_prop_list *pub_key_prop_list,
    azihsm_handle *out_priv,
    azihsm_handle *out_pub
)
{
    return azihsm_import_key_pair(
        genctx->provctx,
        genctx->input_key_file,
        priv_key_prop_list,
        pub_key_prop_list,
        out_priv,
        out_pub
    );
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
     * keyWrapping usage: retrieve the HSM's internal unwrapping key pair.
     * This key is generated and cached by the HSM — we only expose the public half
     * so callers can export it for offline key wrapping (RSA-AES Key Wrap).
     */
    if (genctx->key_usage == KEY_USAGE_KEY_WRAPPING)
    {
        azihsm_handle wrap_pub = 0, wrap_priv = 0;

        /* The HSM's unwrapping key is fixed at 2048 bits. Reject mismatched sizes
         * so that keymgmt_get_params() reports the correct bit length. */
        if (genctx->pubkey_bits != AIHSM_RSA_WRAPPING_KEY_BITS)
        {
            ERR_raise_data(
                ERR_LIB_PROV,
                PROV_R_KEY_SIZE_TOO_SMALL,
                "keyWrapping usage requires rsa_keygen_bits=%u "
                "(the HSM unwrapping key is fixed at %u bits)",
                AIHSM_RSA_WRAPPING_KEY_BITS,
                AIHSM_RSA_WRAPPING_KEY_BITS
            );
            return NULL;
        }

        status = azihsm_get_unwrapping_key(genctx->provctx, &wrap_pub, &wrap_priv);
        if (status != AZIHSM_STATUS_SUCCESS)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
            return NULL;
        }

        if ((rsa_key = OPENSSL_zalloc(sizeof(AZIHSM_RSA_KEY))) == NULL)
        {
            ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
            return NULL;
        }

        rsa_key->genctx = *genctx;
        rsa_key->key.pub = wrap_pub;
        rsa_key->has_public = true;
        rsa_key->key.priv = 0;
        rsa_key->has_private = false;

        return rsa_key;
    }

    /*
     * The HSM cannot generate RSA keys natively.
     * RSA keys must be provided externally via azihsm.input_key or azihsm.wrapped_key.
     */
    if (genctx->input_key_file[0] == '\0' && genctx->wrapped_key_file[0] == '\0')
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_MISSING_KEY,
            "azihsm: RSA key generation requires azihsm.input_key or azihsm.wrapped_key parameter. "
            "The HSM cannot generate RSA keys natively. "
            "Please provide an external DER-encoded RSA private key: "
            "-pkeyopt azihsm.input_key:/path/to/rsa_key.der "
            "or a pre-wrapped blob: "
            "-pkeyopt azihsm.wrapped_key:/path/to/wrapped.bin"
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

    if (genctx->wrapped_key_file[0] != '\0')
    {
        /* Pre-wrapped blob path: unwrap directly into HSM */
        status = azihsm_unwrap_key_pair(
            genctx->provctx,
            genctx->wrapped_key_file,
            &priv_key_prop_list,
            &pub_key_prop_list,
            &private,
            &public
        );
    }
    else
    {
        /* Import external DER key via wrap-unwrap */
        status = azihsm_ossl_rsa_keymgmt_gen_import(
            genctx,
            &priv_key_prop_list,
            &pub_key_prop_list,
            &private,
            &public
        );
    }

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

            /* Write masked key to file with restricted permissions (owner-only) */
            if (azihsm_ossl_write_masked_key_to_file(
                    masked_key_buffer,
                    prop.len,
                    genctx->masked_key_file
                ) != OSSL_SUCCESS)
            {
                azihsm_key_delete(private);
                azihsm_key_delete(public);
                OPENSSL_cleanse(masked_key_buffer, masked_key_buffer_size);
                OPENSSL_free(masked_key_buffer);
                OPENSSL_free(rsa_key);
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

static AZIHSM_RSA_KEY *azihsm_ossl_keymgmt_new(ossl_unused void *provctx)
{
    AZIHSM_RSA_KEY *key = OPENSSL_zalloc(sizeof(AZIHSM_RSA_KEY));
    if (key == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    return key;
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

    if ((p = OSSL_PARAM_locate_const(params, AZIHSM_OSSL_PKEY_PARAM_WRAPPED_KEY)) != NULL)
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

        strncpy(genctx->wrapped_key_file, p->data, sizeof(genctx->wrapped_key_file) - 1);
        genctx->wrapped_key_file[sizeof(genctx->wrapped_key_file) - 1] = '\0';
    }

    /* Reject if both input_key and wrapped_key are set */
    if (genctx->input_key_file[0] != '\0' && genctx->wrapped_key_file[0] != '\0')
    {
        ERR_raise_data(
            ERR_LIB_PROV,
            PROV_R_INVALID_KEY,
            "azihsm: azihsm.input_key and azihsm.wrapped_key are mutually exclusive"
        );
        return OSSL_FAILURE;
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

    genctx->provctx = provctx;
    genctx->session = provctx->session;
    genctx->key_type = key_type;
    genctx->pubkey_bits = AIHSM_RSA_PUBKEY_BITS_DEFAULT;
    genctx->key_usage = AIHSM_KEY_USAGE_DEFAULT;
    genctx->session_flag = false;
    genctx->masked_key_file[0] = '\0';
    genctx->input_key_file[0] = '\0';
    genctx->wrapped_key_file[0] = '\0';

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
    int selection
)
{
    if (rsa_key1 == NULL || rsa_key2 == NULL)
    {
        return OSSL_FAILURE;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        if (rsa_key1->key.pub != rsa_key2->key.pub)
        {
            return OSSL_FAILURE;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        if (rsa_key1->key.priv != rsa_key2->key.priv)
        {
            return OSSL_FAILURE;
        }
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

static int azihsm_ossl_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    AZIHSM_RSA_KEY *rsa_key = keydata;

    if (rsa_key == NULL || params == NULL)
    {
        return OSSL_FAILURE;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        const OSSL_PARAM *p;

        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS);
        if (p != NULL)
        {
            if (!OSSL_PARAM_get_uint32(p, &rsa_key->genctx.pubkey_bits))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return OSSL_FAILURE;
            }
        }

        rsa_key->has_public = true;
    }

    return OSSL_SUCCESS;
}

static int azihsm_ossl_keymgmt_export(
    ossl_unused const void *keydata,
    ossl_unused int selection,
    ossl_unused OSSL_CALLBACK *param_cb,
    ossl_unused void *cbarg
)
{
    return OSSL_FAILURE;
}

static const OSSL_PARAM *azihsm_ossl_keymgmt_import_types(int selection)
{
    static const OSSL_PARAM import_types[] = { OSSL_PARAM_uint32(OSSL_PKEY_PARAM_RSA_BITS, NULL),
                                               OSSL_PARAM_END };

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
    {
        return import_types;
    }

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
        OSSL_PARAM_utf8_string(AZIHSM_OSSL_PKEY_PARAM_WRAPPED_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    return settable_params;
}

static const char *azihsm_ossl_keymgmt_rsa_query_operation_name(int operation_id)
{
    switch (operation_id)
    {
    case OSSL_OP_SIGNATURE:
        return "RSA";
    case OSSL_OP_ASYM_CIPHER:
        return "RSA";
    }
    return "RSA";
}

static const char *azihsm_ossl_keymgmt_rsa_pss_query_operation_name(int operation_id)
{
    switch (operation_id)
    {
    case OSSL_OP_SIGNATURE:
        return "RSA-PSS";
    }
    return "RSA-PSS";
}

/* RSA Key Management */
const OSSL_DISPATCH azihsm_ossl_rsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))azihsm_ossl_keymgmt_new },
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
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))azihsm_ossl_keymgmt_new },
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
      (void (*)(void))azihsm_ossl_keymgmt_rsa_pss_query_operation_name },
    { 0, NULL }
};
