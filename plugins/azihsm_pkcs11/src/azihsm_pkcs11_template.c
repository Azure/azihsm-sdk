// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * CKM_AES_KEY_GEN template handling (see azihsm_pkcs11_template.h). This is
 * the CKA_ → key-property normaliser: the device prop list is built from the
 * extracted values only, never from the raw template — the SDK hard-rejects
 * SENSITIVE/EXTRACTABLE/LOCAL as inputs and takes u32/1-byte property values
 * where PKCS#11 has CK_ULONG/CK_BBOOL.
 */

#include "azihsm_pkcs11_template.h"

#include <stddef.h>
#include <string.h>

const CK_ATTRIBUTE *azihsm_pkcs11_tmpl_find(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ATTRIBUTE_TYPE t
)
{
    if (tmpl == NULL)
    {
        return NULL;
    }
    for (CK_ULONG i = 0; i < count; i++)
    {
        if (tmpl[i].type == t)
        {
            return &tmpl[i];
        }
    }
    return NULL;
}

CK_RV azihsm_pkcs11_tmpl_bool(const CK_ATTRIBUTE *a, CK_BBOOL *out)
{
    if ((a == NULL) || (a->pValue == NULL) || (out == NULL))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (a->ulValueLen != sizeof(CK_BBOOL))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    *out = (*(const CK_BBOOL *)a->pValue != CK_FALSE) ? CK_TRUE : CK_FALSE;
    return CKR_OK;
}

/* CKA_CLASS, CKA_KEY_TYPE and CKA_VALUE_LEN are all CK_ULONG-wide, so one
 * decoder serves all three; the call sites keep naming their own type. */
_Static_assert(sizeof(CK_OBJECT_CLASS) == sizeof(CK_ULONG), "CKA_CLASS is CK_ULONG-wide");
_Static_assert(sizeof(CK_KEY_TYPE) == sizeof(CK_ULONG), "CKA_KEY_TYPE is CK_ULONG-wide");

/*
 * Read a CK_ULONG-wide template attribute into *out; length must match exactly.
 * pValue is whatever pointer the caller handed us and carries no alignment
 * guarantee (a template packed into a byte buffer is enough to misalign it),
 * so the value is copied out instead of dereferenced through a cast. Reading
 * a CK_BBOOL needs no such care: it is one byte wide.
 */
static CK_RV tmpl_ulong(const CK_ATTRIBUTE *a, CK_ULONG *out)
{
    if ((a == NULL) || (a->pValue == NULL) || (out == NULL))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (a->ulValueLen != sizeof(CK_ULONG))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    memcpy(out, a->pValue, sizeof(*out));
    return CKR_OK;
}

CK_RV azihsm_pkcs11_keygen_check_template(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ULONG *value_len,
    CK_BBOOL *token
)
{
    if ((value_len == NULL) || (token == NULL) || ((tmpl == NULL) && (count > 0)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    CK_BBOOL have_value_len = CK_FALSE;
    *value_len = 0;
    *token = CK_FALSE;

    if (count > KEYGEN_MAX_TEMPLATE_ATTRS)
    {
        return CKR_ARGUMENTS_BAD;
    }
    for (CK_ULONG i = 0; i < count; i++)
    {
        const CK_ATTRIBUTE *a = &tmpl[i];
        if ((a->ulValueLen > 0) && (a->pValue == NULL))
        {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        /* A type repeated with a different value is inconsistent, and would also
         * split the generation input (last value wins) from what is stored and
         * later read back (first value wins). */
        if (azihsm_pkcs11_tmpl_find(tmpl, i, a->type) != NULL)
        {
            return CKR_TEMPLATE_INCONSISTENT;
        }
        CK_BBOOL b = CK_FALSE;
        CK_ULONG scalar = 0;
        CK_RV rv = CKR_OK;
        switch (a->type)
        {
        case CKA_CLASS:
            rv = tmpl_ulong(a, &scalar);
            if (rv != CKR_OK)
            {
                return rv;
            }
            if ((CK_OBJECT_CLASS)scalar != CKO_SECRET_KEY)
            {
                return CKR_TEMPLATE_INCONSISTENT;
            }
            break;
        case CKA_KEY_TYPE:
            rv = tmpl_ulong(a, &scalar);
            if (rv != CKR_OK)
            {
                return rv;
            }
            if ((CK_KEY_TYPE)scalar != CKK_AES)
            {
                return CKR_TEMPLATE_INCONSISTENT;
            }
            break;
        case CKA_VALUE_LEN:
            rv = tmpl_ulong(a, value_len);
            if (rv != CKR_OK)
            {
                return rv;
            }
            if ((*value_len != AES128_KEY_BYTES) && (*value_len != AES192_KEY_BYTES) &&
                (*value_len != AES256_KEY_BYTES))
            {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            have_value_len = CK_TRUE;
            break;
        case CKA_SENSITIVE:
            rv = azihsm_pkcs11_tmpl_bool(a, &b);
            if (rv != CKR_OK)
            {
                return rv;
            }
            if (!b)
            {
                /* Device keys only ever exist masked; a non-sensitive (readable)
                 * key cannot be produced. */
                return CKR_TEMPLATE_INCONSISTENT;
            }
            break;
        case CKA_EXTRACTABLE:
            rv = azihsm_pkcs11_tmpl_bool(a, &b);
            if (rv != CKR_OK)
            {
                return rv;
            }
            if (b)
            {
                return CKR_TEMPLATE_INCONSISTENT; /* see CKA_SENSITIVE */
            }
            break;
        case CKA_ENCRYPT:
        case CKA_DECRYPT:
            /* Direction policy is stored and enforced host-side at operation
             * init (the device key always carries both — see
             * azihsm_pkcs11_key.h); only the value's shape is checked here. */
            rv = azihsm_pkcs11_tmpl_bool(a, &b);
            if (rv != CKR_OK)
            {
                return rv;
            }
            break;
        case CKA_TOKEN:
            rv = azihsm_pkcs11_tmpl_bool(a, token);
            if (rv != CKR_OK)
            {
                return rv;
            }
            break;
        case CKA_LOCAL:
        case CKA_ALWAYS_SENSITIVE:
        case CKA_NEVER_EXTRACTABLE:
            return CKR_ATTRIBUTE_READ_ONLY; /* token-computed, never caller-set */
        case CKA_VALUE:
            return CKR_TEMPLATE_INCONSISTENT; /* generated keys take no material */
        default:
            break; /* stored verbatim on the object */
        }
    }
    /* CKM_AES_KEY_GEN derives the strength solely from CKA_VALUE_LEN. */
    return (have_value_len == CK_TRUE) ? CKR_OK : CKR_TEMPLATE_INCOMPLETE;
}

/* Append `a` unless the caller's template already carries the type. */
static void tmpl_append(
    CK_ATTRIBUTE *full,
    CK_ULONG *n,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ATTRIBUTE a
)
{
    if (azihsm_pkcs11_tmpl_find(tmpl, count, a.type) == NULL)
    {
        full[(*n)++] = a;
    }
}

CK_RV azihsm_pkcs11_keygen_build_template(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    azihsm_pkcs11_keygen_fill *fill,
    CK_ATTRIBUTE *full,
    CK_ULONG *n
)
{
    if ((fill == NULL) || (full == NULL) || (n == NULL) || ((tmpl == NULL) && (count > 0)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    fill->cls = CKO_SECRET_KEY;
    fill->kt = CKK_AES;
    fill->btrue = CK_TRUE;
    fill->bfalse = CK_FALSE;

    CK_ULONG k = 0;
    for (CK_ULONG i = 0; i < count; i++)
    {
        full[k++] = tmpl[i];
    }
    tmpl_append(full, &k, tmpl, count, (CK_ATTRIBUTE){ CKA_CLASS, &fill->cls, sizeof(fill->cls) });
    tmpl_append(full, &k, tmpl, count, (CK_ATTRIBUTE){ CKA_KEY_TYPE, &fill->kt, sizeof(fill->kt) });
    tmpl_append(
        full,
        &k,
        tmpl,
        count,
        (CK_ATTRIBUTE){ CKA_SENSITIVE, &fill->btrue, sizeof(fill->btrue) }
    );
    tmpl_append(
        full,
        &k,
        tmpl,
        count,
        (CK_ATTRIBUTE){ CKA_EXTRACTABLE, &fill->bfalse, sizeof(fill->bfalse) }
    );
    tmpl_append(
        full,
        &k,
        tmpl,
        count,
        (CK_ATTRIBUTE){ CKA_ENCRYPT, &fill->btrue, sizeof(fill->btrue) }
    );
    tmpl_append(
        full,
        &k,
        tmpl,
        count,
        (CK_ATTRIBUTE){ CKA_DECRYPT, &fill->btrue, sizeof(fill->btrue) }
    );
    /* Rejected by the check as inputs, so always appended. */
    full[k++] = (CK_ATTRIBUTE){ CKA_LOCAL, &fill->btrue, sizeof(fill->btrue) };
    full[k++] = (CK_ATTRIBUTE){ CKA_ALWAYS_SENSITIVE, &fill->btrue, sizeof(fill->btrue) };
    full[k++] = (CK_ATTRIBUTE){ CKA_NEVER_EXTRACTABLE, &fill->btrue, sizeof(fill->btrue) };
    *n = k;
    return CKR_OK;
}
