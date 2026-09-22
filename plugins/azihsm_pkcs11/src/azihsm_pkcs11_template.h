// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "azihsm_pkcs11_compat.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * CKM_AES_KEY_GEN template handling: the CK_ATTRIBUTE logic C_GenerateKey runs
 * before it touches the device or the object store. It depends on neither, so
 * it is unit-tested on its own (tests/aes_template_test.c) and reused by
 * azihsm_pkcs11_crypt.c. Everything here speaks CK_RV only.
 */

/* Supported AES key lengths (CKA_VALUE_LEN values). */
#define AES128_KEY_BYTES 16
#define AES192_KEY_BYTES 24
#define AES256_KEY_BYTES 32

/*
 * Ceiling on the caller's template length. PKCS#11 defines some forty
 * attributes for a secret-key object, so anything longer is treated as a bogus
 * ulCount and refused with CKR_ARGUMENTS_BAD before the O(n²) duplicate scan
 * runs over it and before the store buffer in C_GenerateKey is sized from it.
 */
#define KEYGEN_MAX_TEMPLATE_ATTRS 64

/*
 * Attributes azihsm_pkcs11_keygen_build_template appends to the caller's
 * template: CKA_CLASS, CKA_KEY_TYPE, CKA_SENSITIVE, CKA_EXTRACTABLE,
 * CKA_ENCRYPT, CKA_DECRYPT (each only if absent), plus CKA_LOCAL,
 * CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE (always). Bounds the headroom
 * the caller must reserve in the output array.
 */
#define KEYGEN_APPENDED_ATTRS 9

/* First attribute of type `t` in `tmpl`, or NULL. A NULL `tmpl` yields NULL
 * whatever `count` is. */
const CK_ATTRIBUTE *azihsm_pkcs11_tmpl_find(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ATTRIBUTE_TYPE t
);

/* Read a CK_BBOOL attribute into *out (normalised to CK_TRUE/CK_FALSE); the
 * value length must be exactly sizeof(CK_BBOOL). CKR_ATTRIBUTE_VALUE_INVALID
 * otherwise, including for a NULL attribute, value or `out`. */
CK_RV azihsm_pkcs11_tmpl_bool(const CK_ATTRIBUTE *a, CK_BBOOL *out);

/*
 * Validate a CKM_AES_KEY_GEN template and extract what the device needs: the
 * key length in bytes (*value_len, one of AES128/192/256_KEY_BYTES) and whether
 * the caller asked for a token object (*token). Both outputs are zeroed first
 * and are meaningful only on CKR_OK. Returns:
 *   CKR_ARGUMENTS_BAD             NULL outputs, NULL tmpl with count > 0, or
 *                                 count > KEYGEN_MAX_TEMPLATE_ATTRS
 *   CKR_ATTRIBUTE_VALUE_INVALID   NULL value with a non-zero length, a wrongly
 *                                 sized CLASS/KEY_TYPE/VALUE_LEN/CK_BBOOL value,
 *                                 or a CKA_VALUE_LEN that is not 16/24/32
 *   CKR_TEMPLATE_INCONSISTENT     a repeated attribute type, CKA_CLASS other
 *                                 than CKO_SECRET_KEY, CKA_KEY_TYPE other than
 *                                 CKK_AES, CKA_SENSITIVE=FALSE,
 *                                 CKA_EXTRACTABLE=TRUE (device keys only ever
 *                                 exist masked), or CKA_VALUE (generated keys
 *                                 take no material)
 *   CKR_ATTRIBUTE_READ_ONLY       CKA_LOCAL / CKA_ALWAYS_SENSITIVE /
 *                                 CKA_NEVER_EXTRACTABLE (token-computed)
 *   CKR_TEMPLATE_INCOMPLETE       no CKA_VALUE_LEN
 *   CKR_OK                        otherwise; unknown types are accepted and
 *                                 later stored verbatim
 * Attributes are checked in template order; the first failure wins.
 */
CK_RV azihsm_pkcs11_keygen_check_template(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ULONG *value_len,
    CK_BBOOL *token
);

/* Storage for the values of the appended attributes; the built template points
 * into it, so it must outlive the template's use. */
typedef struct
{
    CK_OBJECT_CLASS cls;
    CK_KEY_TYPE kt;
    CK_BBOOL btrue;
    CK_BBOOL bfalse;
} azihsm_pkcs11_keygen_fill;

/*
 * Build the template C_GenerateKey stores: the caller's `tmpl` copied verbatim,
 * then the token-decided attributes (see KEYGEN_APPENDED_ATTRS) — class/type
 * identify the object for search and C_GetAttributeValue, the sensitivity
 * quartet states the only possible key-protection reality, and the usage
 * defaults make an attribute-less template usable. `full` must have room for
 * count + KEYGEN_APPENDED_ATTRS entries; *n receives the number written.
 * `tmpl` is expected to have passed azihsm_pkcs11_keygen_check_template.
 * CKR_ARGUMENTS_BAD for NULL fill/full/n or a NULL tmpl with count > 0.
 */
CK_RV azihsm_pkcs11_keygen_build_template(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    azihsm_pkcs11_keygen_fill *fill,
    CK_ATTRIBUTE *full,
    CK_ULONG *n
);

#ifdef __cplusplus
}
#endif
