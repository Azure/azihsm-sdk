// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "azihsm_pkcs11_compat.h"
#include "azihsm_pkcs11_key.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * AES key-generation template handling and the per-mechanism cipher policy:
 * the CK_ATTRIBUTE and CK_MECHANISM logic the key-backed entry points run
 * before they touch the device or the object store. It depends on neither, so
 * it is unit-tested on its own (tests/aes_template_test.c) and reused by
 * azihsm_pkcs11_crypt.c. Everything here speaks CK_RV only.
 */

/* Supported AES key lengths (CKA_VALUE_LEN values). An XTS key is two AES-256
 * subkeys; the device takes it only at that size, and GCM keys only at 256. */
#define AES128_KEY_BYTES 16
#define AES192_KEY_BYTES 24
#define AES256_KEY_BYTES 32
#define AES_XTS_KEY_BYTES 64

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
 * CKA_ENCRYPT, CKA_DECRYPT, CKA_ALLOWED_MECHANISMS (each only if absent), plus
 * CKA_LOCAL, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE and
 * CKA_KEY_GEN_MECHANISM (always). Bounds the headroom the caller must reserve
 * in the output array.
 */
#define KEYGEN_APPENDED_ATTRS 11

/*
 * Ceiling on the entries of a caller's CKA_ALLOWED_MECHANISMS. No key this
 * token generates serves more than two distinct mechanisms, so a real list is
 * short. The bound caps the decode loops and sizes the buffer the cipher init
 * reads the stored list back into, so every list stored here fits it.
 */
#define KEYGEN_MAX_ALLOWED_MECHS 16

/* Most mechanisms one generated key may serve (the CBC family has two). */
#define KEYGEN_MAX_KEY_MECHS 2

/*
 * What C_GenerateKey produces for one family of keys. The device has three
 * disjoint AES key kinds while PKCS#11 has CKK_AES and CKK_AES_XTS, so:
 *   CKM_AES_XTS_KEY_GEN                            -> AES-XTS, CKK_AES_XTS, 64
 *   CKM_AES_KEY_GEN + CKA_ALLOWED_MECHANISMS {GCM} -> AES-GCM, CKK_AES, 32
 *   CKM_AES_KEY_GEN otherwise                      -> AES,     CKK_AES, 16/24/32
 * The key is stored with the family as CKA_ALLOWED_MECHANISMS, which is what
 * later lets the cipher gate tell a GCM key from a CBC key of the same type.
 */
typedef struct
{
    CK_MECHANISM_TYPE keygen_mech; /* recorded as CKA_KEY_GEN_MECHANISM */
    azihsm_pkcs11_key_kind_t kind;
    CK_KEY_TYPE key_type;
    CK_ULONG value_lens[4];                        /* accepted CKA_VALUE_LEN, 0-terminated */
    CK_MECHANISM_TYPE mechs[KEYGEN_MAX_KEY_MECHS]; /* the family */
    CK_ULONG mech_count;
} azihsm_pkcs11_keygen_policy;

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
 * Validate an AES key-generation template for `mech` (CKM_AES_KEY_GEN or
 * CKM_AES_XTS_KEY_GEN), pick the key family it asks for (*policy), and
 * extract what the device needs: the key length in bytes (*value_len) and
 * whether the caller asked for a token object (*token). All outputs are
 * cleared first and are meaningful only on CKR_OK. Returns:
 *   CKR_ARGUMENTS_BAD             NULL outputs, NULL tmpl with count > 0, or
 *                                 count > KEYGEN_MAX_TEMPLATE_ATTRS
 *   CKR_MECHANISM_INVALID         `mech` is not an AES key-generation mechanism
 *   CKR_ATTRIBUTE_VALUE_INVALID   NULL value with a non-zero length, a wrongly
 *                                 sized CLASS/KEY_TYPE/VALUE_LEN/CK_BBOOL value,
 *                                 a CKA_ALLOWED_MECHANISMS that is empty, not a
 *                                 whole number of entries or longer than
 *                                 KEYGEN_MAX_ALLOWED_MECHS, or a CKA_VALUE_LEN
 *                                 the chosen family cannot be generated at
 *   CKR_TEMPLATE_INCONSISTENT     a repeated attribute type, CKA_CLASS other
 *                                 than CKO_SECRET_KEY, CKA_KEY_TYPE other than
 *                                 the family's, a CKA_ALLOWED_MECHANISMS no
 *                                 single family satisfies (mixing GCM with CBC,
 *                                 or naming any mechanism outside the family
 *                                 `mech` produces), CKA_SENSITIVE=FALSE,
 *                                 CKA_EXTRACTABLE=TRUE (device keys only ever
 *                                 exist masked), or CKA_VALUE (generated keys
 *                                 take no material)
 *   CKR_ATTRIBUTE_READ_ONLY       CKA_LOCAL / CKA_ALWAYS_SENSITIVE /
 *                                 CKA_NEVER_EXTRACTABLE / CKA_KEY_GEN_MECHANISM
 *                                 (token-computed)
 *   CKR_TEMPLATE_INCOMPLETE       no CKA_VALUE_LEN
 *   CKR_OK                        otherwise; unknown types are accepted and
 *                                 later stored verbatim
 * Attribute shapes are checked in template order and the first failure wins;
 * the checks that depend on the family (it can be named by an attribute later
 * in the template) run after that pass.
 */
CK_RV azihsm_pkcs11_keygen_check_template(
    CK_MECHANISM_TYPE mech,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    const azihsm_pkcs11_keygen_policy **policy,
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
    CK_MECHANISM_TYPE kgm;
    CK_MECHANISM_TYPE mechs[KEYGEN_MAX_KEY_MECHS];
} azihsm_pkcs11_keygen_fill;

/*
 * Build the template C_GenerateKey stores: the caller's `tmpl` copied verbatim,
 * then the token-decided attributes (see KEYGEN_APPENDED_ATTRS) — class/type
 * identify the object for search and C_GetAttributeValue, the allowed
 * mechanisms record the key family `policy` chose, the sensitivity quartet
 * states the only possible key-protection reality, CKA_LOCAL and
 * CKA_KEY_GEN_MECHANISM say how the key came to be, and the usage defaults
 * make an attribute-less template usable. A caller's own
 * CKA_ALLOWED_MECHANISMS (already checked to lie within the family) is kept
 * as the narrower list. `full` must have room for count +
 * KEYGEN_APPENDED_ATTRS entries; *n receives the number written. `tmpl` is
 * expected to have passed azihsm_pkcs11_keygen_check_template.
 * CKR_ARGUMENTS_BAD for NULL policy/fill/full/n, a NULL tmpl with count > 0,
 * or a policy whose mech_count is 0 or above KEYGEN_MAX_KEY_MECHS.
 */
CK_RV azihsm_pkcs11_keygen_build_template(
    const azihsm_pkcs11_keygen_policy *policy,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    azihsm_pkcs11_keygen_fill *fill,
    CK_ATTRIBUTE *full,
    CK_ULONG *n
);

/*
 * The cipher mechanisms and what each needs from a key: the device kind to
 * unmask the blob as, and the CKA_KEY_TYPE the key object must carry.
 */
typedef struct
{
    CK_MECHANISM_TYPE mech;
    azihsm_pkcs11_key_kind_t kind;
    CK_KEY_TYPE key_type;
} azihsm_pkcs11_cipher_mech;

/* The table entry for `mech`, or NULL for any mechanism this token cannot run
 * through C_Encrypt/C_Decrypt. */
const azihsm_pkcs11_cipher_mech *azihsm_pkcs11_cipher_mech_find(CK_MECHANISM_TYPE mech);

/*
 * Whether a key may run `mech`, given how reading its CKA_ALLOWED_MECHANISMS
 * went: `get_rv` is the object store's verdict and `value`/`len` what it read.
 *   CKR_OK                      the list decides; a malformed value (not a
 *                               whole number of entries) permits nothing
 *   CKR_ATTRIBUTE_TYPE_INVALID  the key has no list: it was stored before keys
 *                               recorded one, when every key was the plain AES
 *                               kind, so it serves exactly the CBC family
 *   anything else               refused (fail closed; e.g. a list longer than
 *                               any this token writes)
 * Keys from then also kept a caller-supplied list verbatim, so such a CBC-kind
 * key may carry {CKM_AES_GCM}. Nothing stored tells it from a real GCM key;
 * such a request passes here and the device then refuses the blob under the
 * GCM kind, which surfaces as CKR_KEY_HANDLE_INVALID.
 */
bool azihsm_pkcs11_key_mech_permitted(
    CK_RV get_rv,
    const void *value,
    CK_ULONG len,
    CK_MECHANISM_TYPE mech
);

/*
 * Validate a CKM_AES_XTS parameter, the raw 16-byte tweak. CKR_OK, or
 * CKR_MECHANISM_PARAM_INVALID for a NULL or wrongly sized parameter, or for
 * the one tweak the device cannot use: all bytes 0xFF, the 128-bit maximum,
 * which the SDK must be able to advance past the data unit it encrypts.
 */
CK_RV azihsm_pkcs11_xts_tweak_check(const void *param, CK_ULONG param_len);

/*
 * Decode and validate a CKM_AES_GCM parameter block into *out. The device
 * supports exactly a 12-byte IV and a 128-bit tag, so every other shape is
 * refused rather than silently altered. CKR_MECHANISM_PARAM_INVALID for a
 * NULL or wrongly sized block, a NULL or non-12-byte IV, ulTagBits other than
 * 128, a NULL pAAD with a non-zero ulAADLen, or an AAD beyond the device's
 * 32-bit length. ulIvBits is not read: v3.0 says to use ulIvLen for the IV
 * length, and callers fill ulIvBits inconsistently. CKR_ARGUMENTS_BAD for a
 * NULL `out`.
 */
CK_RV azihsm_pkcs11_gcm_params_check(const void *param, CK_ULONG param_len, CK_GCM_PARAMS *out);

/*
 * Output length of a one-shot GCM or XTS call over `in_len` input bytes, or
 * the *_LEN_RANGE error the input length earns (CKR_DATA_LEN_RANGE on encrypt,
 * CKR_ENCRYPTED_DATA_LEN_RANGE on decrypt):
 *   CKM_AES_GCM  encrypt appends the 16-byte tag; decrypt needs at least the
 *                tag and returns the rest; both stay within 32 bits
 *   CKM_AES_XTS  one data unit: a non-zero multiple of 16 bytes, at most
 *                AES_XTS_MAX_DATA_LEN, and the output is as long as the input
 * CKR_MECHANISM_INVALID for any other mechanism (CBC's output length depends
 * on its padding and comes from the device), CKR_ARGUMENTS_BAD for a NULL
 * `out_len`.
 */
CK_RV azihsm_pkcs11_cipher_out_len(
    CK_MECHANISM_TYPE mech,
    bool encrypt,
    CK_ULONG in_len,
    CK_ULONG *out_len
);

/*
 * Whether a GCM call over `data_len` bytes with `aad_len` bytes of AAD fits
 * the device: the AAD padded to AES_GCM_AAD_ALIGN plus the data must stay
 * within 32 bits, which the SDK does not check before narrowing.
 */
bool azihsm_pkcs11_gcm_fits(CK_ULONG aad_len, CK_ULONG data_len);

#ifdef __cplusplus
}
#endif
