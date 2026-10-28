// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * C_SetAttributeValue policy (see azihsm_pkcs11_attr_policy.h).
 */

#include "azihsm_pkcs11_attr_policy.h"
#include "azihsm_pkcs11_template.h"

#include <stddef.h>
#include <string.h>

/* Object classes a rule applies to. */
#define P11_CLS_DATA 0x01u
#define P11_CLS_SECRET 0x02u
#define P11_CLS_PUBLIC 0x04u
#define P11_CLS_PRIVATE 0x08u
#define P11_CLS_OTHER 0x10u /* any other class, or none recorded */
#define P11_CLS_KEY (P11_CLS_SECRET | P11_CLS_PUBLIC | P11_CLS_PRIVATE)
#define P11_CLS_ANY (P11_CLS_DATA | P11_CLS_KEY | P11_CLS_OTHER)

typedef enum
{
    P11_VAL_BYTES = 0,   /* any value */
    P11_VAL_BOOL,        /* a CK_BBOOL */
    P11_VAL_DATE,        /* a CK_DATE, or empty */
    P11_VAL_LATCH_TRUE,  /* a CK_BBOOL that, once TRUE, stays TRUE */
    P11_VAL_LATCH_FALSE, /* a CK_BBOOL that, once FALSE, stays FALSE */
    P11_VAL_FIXED,       /* defined for the class, never modifiable */
} value_rule;

typedef struct
{
    CK_ATTRIBUTE_TYPE type;
    unsigned classes;
    value_rule rule;
} attr_rule;

/*
 * The footnote-8 attributes of PKCS#11 v3.1 §4 for the classes this module
 * stores, then the attributes those classes define as fixed. Storage-object
 * attributes other than CKA_LABEL change only through C_CopyObject, and
 * data-object attributes carry no footnote 8. Listing the fixed ones keeps the
 * answer CKR_ATTRIBUTE_READ_ONLY even when the store never recorded the
 * attribute (a CKA_TOKEN left to its default, say); an attribute on neither list
 * is read-only if the object carries it and invalid if it does not.
 */
static const attr_rule ATTR_RULES[] = {
    { CKA_LABEL, P11_CLS_ANY, P11_VAL_BYTES },
    { CKA_ID, P11_CLS_KEY, P11_VAL_BYTES },
    { CKA_START_DATE, P11_CLS_KEY, P11_VAL_DATE },
    { CKA_END_DATE, P11_CLS_KEY, P11_VAL_DATE },
    { CKA_DERIVE, P11_CLS_KEY, P11_VAL_BOOL },
    { CKA_SUBJECT, P11_CLS_PUBLIC | P11_CLS_PRIVATE, P11_VAL_BYTES },
    { CKA_ENCRYPT, P11_CLS_SECRET | P11_CLS_PUBLIC, P11_VAL_BOOL },
    { CKA_VERIFY, P11_CLS_SECRET | P11_CLS_PUBLIC, P11_VAL_BOOL },
    { CKA_WRAP, P11_CLS_SECRET | P11_CLS_PUBLIC, P11_VAL_BOOL },
    { CKA_VERIFY_RECOVER, P11_CLS_PUBLIC, P11_VAL_BOOL },
    { CKA_DECRYPT, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_BOOL },
    { CKA_SIGN, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_BOOL },
    { CKA_UNWRAP, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_BOOL },
    { CKA_SIGN_RECOVER, P11_CLS_PRIVATE, P11_VAL_BOOL },
    { CKA_SENSITIVE, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_LATCH_TRUE },
    { CKA_WRAP_WITH_TRUSTED, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_LATCH_TRUE },
    { CKA_EXTRACTABLE, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_LATCH_FALSE },

    { CKA_CLASS, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_TOKEN, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_PRIVATE, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_MODIFIABLE, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_COPYABLE, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_DESTROYABLE, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_UNIQUE_ID, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_APPLICATION, P11_CLS_DATA, P11_VAL_FIXED },
    { CKA_OBJECT_ID, P11_CLS_DATA, P11_VAL_FIXED },
    { CKA_VALUE, P11_CLS_DATA | P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_FIXED },
    { CKA_KEY_TYPE, P11_CLS_KEY, P11_VAL_FIXED },
    { CKA_LOCAL, P11_CLS_KEY, P11_VAL_FIXED },
    { CKA_KEY_GEN_MECHANISM, P11_CLS_KEY, P11_VAL_FIXED },
    { CKA_ALLOWED_MECHANISMS, P11_CLS_KEY, P11_VAL_FIXED },
    { CKA_VALUE_LEN, P11_CLS_SECRET, P11_VAL_FIXED },
    { CKA_CHECK_VALUE, P11_CLS_SECRET, P11_VAL_FIXED },
    { CKA_ALWAYS_SENSITIVE, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_FIXED },
    { CKA_NEVER_EXTRACTABLE, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_FIXED },
};

static const attr_rule *find_rule(CK_ATTRIBUTE_TYPE type, unsigned cls)
{
    for (size_t i = 0; i < sizeof(ATTR_RULES) / sizeof(ATTR_RULES[0]); i++)
    {
        if ((ATTR_RULES[i].type == type) && ((ATTR_RULES[i].classes & cls) != 0))
        {
            return &ATTR_RULES[i];
        }
    }
    return NULL;
}

/*
 * The object's current CK_BBOOL `type`: `absent` when it does not carry one,
 * `malformed` when the stored value is not a CK_BBOOL. Callers pass the
 * restrictive reading as `malformed`, so a bad stored value never loosens a
 * rule.
 */
static CK_RV read_bool(
    azihsm_pkcs11_attr_reader read,
    void *ctx,
    CK_ATTRIBUTE_TYPE type,
    CK_BBOOL absent,
    CK_BBOOL malformed,
    CK_BBOOL *out
)
{
    CK_BBOOL b = CK_FALSE;
    CK_ATTRIBUTE a = { type, &b, sizeof(b) };
    CK_RV rv = read(ctx, &a);
    if (rv == CKR_ATTRIBUTE_TYPE_INVALID)
    {
        *out = absent;
        return CKR_OK;
    }
    if ((rv == CKR_OK) && (a.ulValueLen == sizeof(b)))
    {
        *out = (b != CK_FALSE) ? CK_TRUE : CK_FALSE;
        return CKR_OK;
    }
    if ((rv == CKR_OK) || (rv == CKR_BUFFER_TOO_SMALL) || (rv == CKR_ATTRIBUTE_SENSITIVE))
    {
        *out = malformed;
        return CKR_OK;
    }
    return rv;
}

/*
 * Map CKA_CLASS to the rule-table bit. An object with no CKA_CLASS, or with one
 * that is not a CK_OBJECT_CLASS (C_CreateObject does not validate the class),
 * is still a valid target: it gets P11_CLS_OTHER, the most restrictive class
 * (only CKA_LABEL may change), and the read outcome that says so is not an
 * error of the call. Only a failure to read the object at all, such as
 * CKR_OBJECT_HANDLE_INVALID, is returned.
 */
static CK_RV read_class(azihsm_pkcs11_attr_reader read, void *ctx, unsigned *out)
{
    *out = P11_CLS_OTHER;
    CK_OBJECT_CLASS cls = 0;
    CK_ATTRIBUTE a = { CKA_CLASS, &cls, sizeof(cls) };
    CK_RV rv = read(ctx, &a);
    if ((rv == CKR_ATTRIBUTE_TYPE_INVALID) || (rv == CKR_BUFFER_TOO_SMALL) ||
        (rv == CKR_ATTRIBUTE_SENSITIVE))
    {
        return CKR_OK; /* absent, too wide, or unreadable: no usable class */
    }
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (a.ulValueLen != sizeof(cls))
    {
        return CKR_OK; /* too narrow: no usable class */
    }
    switch (cls)
    {
    case CKO_DATA:
        *out = P11_CLS_DATA;
        break;
    case CKO_SECRET_KEY:
        *out = P11_CLS_SECRET;
        break;
    case CKO_PUBLIC_KEY:
        *out = P11_CLS_PUBLIC;
        break;
    case CKO_PRIVATE_KEY:
        *out = P11_CLS_PRIVATE;
        break;
    default:
        break; /* a class this module stores no rules for */
    }
    return CKR_OK;
}

/* Whether the object carries `type` at all (a sensitive value counts). */
static CK_RV carries(
    azihsm_pkcs11_attr_reader read,
    void *ctx,
    CK_ATTRIBUTE_TYPE type,
    CK_BBOOL *out
)
{
    CK_ATTRIBUTE a = { type, NULL, 0 };
    CK_RV rv = read(ctx, &a);
    if ((rv == CKR_OK) || (rv == CKR_ATTRIBUTE_SENSITIVE))
    {
        *out = CK_TRUE;
        return CKR_OK;
    }
    if (rv == CKR_ATTRIBUTE_TYPE_INVALID)
    {
        *out = CK_FALSE;
        return CKR_OK;
    }
    return rv;
}

/* Parse `n` ASCII digits; -1 if any is not a digit. */
static int parse_digits(const CK_CHAR *p, size_t n)
{
    int v = 0;
    for (size_t i = 0; i < n; i++)
    {
        if ((p[i] < '0') || (p[i] > '9'))
        {
            return -1;
        }
        v = (v * 10) + (p[i] - '0');
    }
    return v;
}

/*
 * An empty value (no date), or a CK_DATE whose fields are in the ranges
 * pkcs11t.h gives: year 1900-9999, month 01-12, day 01-31. The day is not
 * checked against the month; the spec defines only the ranges.
 */
static CK_BBOOL date_ok(const CK_ATTRIBUTE *a)
{
    if (a->ulValueLen == 0)
    {
        return CK_TRUE;
    }
    if ((a->ulValueLen != sizeof(CK_DATE)) || (a->pValue == NULL))
    {
        return CK_FALSE;
    }
    CK_DATE d;
    memcpy(&d, a->pValue, sizeof(d));
    int year = parse_digits(d.year, sizeof(d.year));
    int month = parse_digits(d.month, sizeof(d.month));
    int day = parse_digits(d.day, sizeof(d.day));
    return ((year >= 1900) && (month >= 1) && (month <= 12) && (day >= 1) && (day <= 31))
               ? CK_TRUE
               : CK_FALSE;
}

static CK_RV check_value(
    const attr_rule *r,
    const CK_ATTRIBUTE *a,
    azihsm_pkcs11_attr_reader read,
    void *ctx
)
{
    CK_BBOOL want = CK_FALSE;
    CK_BBOOL cur = CK_FALSE;
    CK_RV rv = CKR_OK;
    switch (r->rule)
    {
    case P11_VAL_FIXED:
        return CKR_ATTRIBUTE_READ_ONLY;
    case P11_VAL_BYTES:
        return CKR_OK;
    case P11_VAL_DATE:
        return date_ok(a) ? CKR_OK : CKR_ATTRIBUTE_VALUE_INVALID;
    case P11_VAL_BOOL:
        return azihsm_pkcs11_tmpl_bool(a, &want);
    case P11_VAL_LATCH_TRUE:
        rv = azihsm_pkcs11_tmpl_bool(a, &want);
        if (rv == CKR_OK)
        {
            rv = read_bool(read, ctx, a->type, CK_FALSE, CK_TRUE, &cur);
        }
        if ((rv == CKR_OK) && cur && !want)
        {
            rv = CKR_ATTRIBUTE_READ_ONLY;
        }
        return rv;
    case P11_VAL_LATCH_FALSE:
        rv = azihsm_pkcs11_tmpl_bool(a, &want);
        if (rv == CKR_OK)
        {
            /* Absent reads as TRUE, as C_GetAttributeValue's sensitivity gate
             * treats a missing CKA_EXTRACTABLE. */
            rv = read_bool(read, ctx, a->type, CK_TRUE, CK_FALSE, &cur);
        }
        if ((rv == CKR_OK) && !cur && want)
        {
            rv = CKR_ATTRIBUTE_READ_ONLY;
        }
        return rv;
    }
    return CKR_GENERAL_ERROR; /* unreachable: every rule is handled above */
}

CK_RV azihsm_pkcs11_setattr_check(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_BBOOL rw_session,
    azihsm_pkcs11_attr_reader read,
    void *ctx
)
{
    if ((read == NULL) || ((tmpl == NULL) && (count > 0)) || (count > SETATTR_MAX_TEMPLATE_ATTRS))
    {
        return CKR_ARGUMENTS_BAD;
    }
    /* Read first even for an empty template: it is also what proves the handle. */
    CK_BBOOL token = CK_FALSE;
    CK_RV rv = read_bool(read, ctx, CKA_TOKEN, CK_FALSE, CK_TRUE, &token);
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (token && !rw_session)
    {
        return CKR_SESSION_READ_ONLY;
    }
    CK_BBOOL modifiable = CK_TRUE;
    rv = read_bool(read, ctx, CKA_MODIFIABLE, CK_TRUE, CK_FALSE, &modifiable);
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (!modifiable)
    {
        return CKR_ACTION_PROHIBITED;
    }
    unsigned cls = P11_CLS_OTHER;
    rv = read_class(read, ctx, &cls);
    if (rv != CKR_OK)
    {
        return rv;
    }

    for (CK_ULONG i = 0; i < count; i++)
    {
        const CK_ATTRIBUTE *a = &tmpl[i];
        if ((a->ulValueLen > 0) && (a->pValue == NULL))
        {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (azihsm_pkcs11_tmpl_find(tmpl, i, a->type) != NULL)
        {
            return CKR_TEMPLATE_INCONSISTENT;
        }
        const attr_rule *r = find_rule(a->type, cls);
        if (r == NULL)
        {
            CK_BBOOL has = CK_FALSE;
            rv = carries(read, ctx, a->type, &has);
            if (rv != CKR_OK)
            {
                return rv;
            }
            return has ? CKR_ATTRIBUTE_READ_ONLY : CKR_ATTRIBUTE_TYPE_INVALID;
        }
        rv = check_value(r, a, read, ctx);
        if (rv != CKR_OK)
        {
            return rv;
        }
    }
    return CKR_OK;
}
