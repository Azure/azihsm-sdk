// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "azihsm_pkcs11_compat.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * C_SetAttributeValue policy: which attributes of an existing object may change,
 * and to what. The object store applies whatever it is handed, so this is the
 * only gate between a caller and a stored object. It depends on neither the
 * device nor the store (the object is read through a callback), so it is
 * unit-tested on its own (tests/attr_policy_test.c).
 *
 * The rules are PKCS#11 v3.1's footnote-8 attributes ("may be modified after
 * the object is created"), per object class, and nothing else: an attribute is
 * modifiable only if it is listed for the object's class. Keys exist on the
 * device only as masked blobs, so the latches matter here: CKA_SENSITIVE and
 * CKA_WRAP_WITH_TRUSTED can only become TRUE, CKA_EXTRACTABLE only FALSE.
 */

/*
 * Ceiling on the caller's template length, for the same reason as
 * KEYGEN_MAX_TEMPLATE_ATTRS: no object has more modifiable attributes than
 * this, and the duplicate scan is O(n²).
 */
#define SETATTR_MAX_TEMPLATE_ATTRS 64

/*
 * Reads one attribute of the target object, with C_GetAttributeValue semantics
 * for a single-entry template: CKR_OK fills a->pValue (or only a->ulValueLen
 * when pValue is NULL), CKR_ATTRIBUTE_TYPE_INVALID means the object does not
 * carry the type, and CKR_ATTRIBUTE_SENSITIVE means it does but will not reveal
 * it. Any other result (CKR_OBJECT_HANDLE_INVALID above all) is passed through.
 */
typedef CK_RV (*azihsm_pkcs11_attr_reader)(void *ctx, CK_ATTRIBUTE *a);

/*
 * Decide whether `tmpl` may be applied to the object `read` sees. Nothing is
 * changed; on CKR_OK the whole template is acceptable. Returns, checking in
 * this order:
 *   CKR_ARGUMENTS_BAD             NULL `read`, NULL tmpl with count > 0, or
 *                                 count > SETATTR_MAX_TEMPLATE_ATTRS
 *   (from `read`)                 e.g. CKR_OBJECT_HANDLE_INVALID
 *   CKR_SESSION_READ_ONLY         a token object and !rw_session
 *   CKR_ACTION_PROHIBITED         the object has CKA_MODIFIABLE = FALSE
 *   then per attribute, in template order, first failure wins:
 *   CKR_ATTRIBUTE_VALUE_INVALID   NULL value with a non-zero length, a CK_BBOOL
 *                                 not sizeof(CK_BBOOL) wide, a CK_DATE neither
 *                                 empty nor sizeof(CK_DATE) wide
 *   CKR_TEMPLATE_INCONSISTENT     a repeated attribute type
 *   CKR_ATTRIBUTE_READ_ONLY       an attribute the class defines as fixed
 *                                 (CKA_CLASS, CKA_TOKEN, CKA_PRIVATE,
 *                                 CKA_VALUE, CKA_KEY_TYPE, ...), any other
 *                                 attribute the object carries but its class
 *                                 does not let change, or a latch moved back
 *                                 (SENSITIVE / WRAP_WITH_TRUSTED to FALSE,
 *                                 EXTRACTABLE to TRUE)
 *   CKR_ATTRIBUTE_TYPE_INVALID    an attribute the object neither carries nor
 *                                 may gain
 * A stored value the store accepted malformed (a CK_BBOOL of the wrong width,
 * say) is read as its most restrictive meaning.
 */
CK_RV azihsm_pkcs11_setattr_check(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_BBOOL rw_session,
    azihsm_pkcs11_attr_reader read,
    void *ctx
);

#ifdef __cplusplus
}
#endif
