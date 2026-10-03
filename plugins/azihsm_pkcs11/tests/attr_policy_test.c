// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the C_SetAttributeValue policy
 * (src/azihsm_pkcs11_attr_policy.c). No device, no store, no module load: the
 * target object is a fake whose reader mimics the store's get_attr for one
 * attribute, including the sensitive-value refusal:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src attr_policy_test.c \
 *       ../src/azihsm_pkcs11_attr_policy.c ../src/azihsm_pkcs11_template.c \
 *       -o attr_policy_test && ./attr_policy_test
 *
 * Covers the argument and handle checks, the read-only-session and
 * CKA_MODIFIABLE gates and their order, every class's modifiable and fixed
 * attributes, the three latches (including an absent or malformed stored
 * value), value-shape rejects, duplicates, the TYPE_INVALID vs READ_ONLY split
 * for unlisted types, and first-failure-wins ordering.
 */

#include "azihsm_pkcs11_attr_policy.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
static int g_checks = 0;

#define CHECK(cond, msg)                                                                           \
    do                                                                                             \
    {                                                                                              \
        g_checks++;                                                                                \
        if (cond)                                                                                  \
        {                                                                                          \
            printf("  ok   : %s\n", (msg));                                                        \
        }                                                                                          \
        else                                                                                       \
        {                                                                                          \
            printf("  FAIL : %s\n", (msg));                                                        \
            g_fail = 1;                                                                            \
        }                                                                                          \
    } while (0)

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static CK_BBOOL g_true = CK_TRUE;
static CK_BBOOL g_false = CK_FALSE;
static CK_ULONG g_wide = 1; /* a CK_BBOOL stored or sent at the wrong width */
static CK_OBJECT_CLASS g_secret = CKO_SECRET_KEY;
static CK_OBJECT_CLASS g_data = CKO_DATA;
static CK_OBJECT_CLASS g_private = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS g_public = CKO_PUBLIC_KEY;
static CK_KEY_TYPE g_aes = CKK_AES;
static CK_ULONG g_len32 = 32;
static CK_BYTE g_secret_bytes[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
static char g_label[] = "unit";
static CK_DATE g_date = { { '2', '0', '2', '6' }, { '0', '9' }, { '2', '8' } };
static CK_BYTE g_short_date[3] = { 1, 2, 3 };

#define DATE(y, m, d)                                                                              \
    {                                                                                              \
        { (y)[0], (y)[1], (y)[2], (y)[3] }, { (m)[0], (m)[1] },                                    \
        {                                                                                          \
            (d)[0], (d)[1]                                                                         \
        }                                                                                          \
    }
static CK_DATE g_date_min = DATE("1900", "01", "01");
static CK_DATE g_date_max = DATE("9999", "12", "31");
static CK_DATE g_bad_dates[] = {
    DATE("2026", "00", "15"), DATE("2026", "13", "15"),  DATE("2026", "06", "00"),
    DATE("2026", "06", "32"), DATE("1899", "12", "31"),  DATE("20x6", "06", "15"),
    DATE("2026", " 6", "15"), DATE("2026", "06", "1\0"),
};

#define ATTR(t, v)                                                                                 \
    {                                                                                              \
        (t), (void *)&(v), sizeof(v)                                                               \
    }
#define BOOL_ATTR(t, b)                                                                            \
    {                                                                                              \
        (t), (void *)&(b), sizeof(CK_BBOOL)                                                        \
    }

/* The target object: a fixed attribute set, or a forced read result. */
typedef struct
{
    const CK_ATTRIBUTE *attrs;
    CK_ULONG count;
    CK_RV fail; /* returned by every read when non-zero */
} fake_obj;

static CK_RV fake_read(void *ctx, CK_ATTRIBUTE *a)
{
    const fake_obj *o = (const fake_obj *)ctx;
    if (o->fail != CKR_OK)
    {
        return o->fail;
    }
    for (CK_ULONG i = 0; i < o->count; i++)
    {
        const CK_ATTRIBUTE *s = &o->attrs[i];
        if (s->type != a->type)
        {
            continue;
        }
        if (s->type == CKA_VALUE)
        {
            a->ulValueLen = CK_UNAVAILABLE_INFORMATION; /* every fake key is sensitive */
            return CKR_ATTRIBUTE_SENSITIVE;
        }
        if (a->pValue == NULL)
        {
            a->ulValueLen = s->ulValueLen;
            return CKR_OK;
        }
        if (a->ulValueLen < s->ulValueLen)
        {
            a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            return CKR_BUFFER_TOO_SMALL;
        }
        memcpy(a->pValue, s->pValue, s->ulValueLen);
        a->ulValueLen = s->ulValueLen;
        return CKR_OK;
    }
    a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
    return CKR_ATTRIBUTE_TYPE_INVALID;
}

/* What C_GenerateKey stores for an AES key (a session object). */
static const CK_ATTRIBUTE AES_KEY[] = {
    ATTR(CKA_CLASS, g_secret),
    ATTR(CKA_KEY_TYPE, g_aes),
    ATTR(CKA_VALUE_LEN, g_len32),
    ATTR(CKA_LABEL, g_label),
    BOOL_ATTR(CKA_SENSITIVE, g_true),
    BOOL_ATTR(CKA_EXTRACTABLE, g_false),
    BOOL_ATTR(CKA_ENCRYPT, g_true),
    BOOL_ATTR(CKA_DECRYPT, g_true),
    BOOL_ATTR(CKA_LOCAL, g_true),
    BOOL_ATTR(CKA_ALWAYS_SENSITIVE, g_true),
    BOOL_ATTR(CKA_NEVER_EXTRACTABLE, g_true),
};

/* A public data object as pkcs11test's DataObjectTest creates it. */
static const CK_ATTRIBUTE DATA_OBJ[] = {
    ATTR(CKA_CLASS, g_data),         BOOL_ATTR(CKA_TOKEN, g_false),
    BOOL_ATTR(CKA_PRIVATE, g_false), ATTR(CKA_APPLICATION, g_label),
    ATTR(CKA_VALUE, g_secret_bytes), ATTR(CKA_LABEL, g_label),
    ATTR(CKA_ID, g_label), /* not a data-object attribute, but carried */
};

static CK_RV check_on(const CK_ATTRIBUTE *obj, CK_ULONG n, CK_BBOOL rw, CK_ATTRIBUTE a)
{
    fake_obj o = { obj, n, CKR_OK };
    return azihsm_pkcs11_setattr_check(&a, 1, rw, fake_read, &o);
}

static CK_RV on_key(CK_ATTRIBUTE a)
{
    return check_on(AES_KEY, COUNT(AES_KEY), CK_TRUE, a);
}

static CK_RV on_data(CK_ATTRIBUTE a)
{
    return check_on(DATA_OBJ, COUNT(DATA_OBJ), CK_TRUE, a);
}

static void test_arguments(void)
{
    printf("== arguments and handle ==\n");
    fake_obj o = { AES_KEY, COUNT(AES_KEY), CKR_OK };
    CK_ATTRIBUTE label = ATTR(CKA_LABEL, g_label);
    CHECK(
        azihsm_pkcs11_setattr_check(&label, 1, CK_TRUE, NULL, &o) == CKR_ARGUMENTS_BAD,
        "NULL reader -> ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_setattr_check(NULL, 1, CK_TRUE, fake_read, &o) == CKR_ARGUMENTS_BAD,
        "NULL template with count > 0 -> ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_setattr_check(NULL, 0, CK_TRUE, fake_read, &o) == CKR_OK,
        "empty template on a valid object -> OK"
    );
    CK_ATTRIBUTE many[SETATTR_MAX_TEMPLATE_ATTRS + 1];
    for (size_t i = 0; i < COUNT(many); i++)
    {
        many[i] = (CK_ATTRIBUTE)ATTR(CKA_LABEL, g_label);
    }
    CHECK(
        azihsm_pkcs11_setattr_check(many, COUNT(many), CK_TRUE, fake_read, &o) == CKR_ARGUMENTS_BAD,
        "count above the ceiling -> ARGUMENTS_BAD"
    );
    fake_obj gone = { NULL, 0, CKR_OBJECT_HANDLE_INVALID };
    CHECK(
        azihsm_pkcs11_setattr_check(&label, 1, CK_TRUE, fake_read, &gone) ==
            CKR_OBJECT_HANDLE_INVALID,
        "invisible object -> OBJECT_HANDLE_INVALID"
    );
    CHECK(
        azihsm_pkcs11_setattr_check(NULL, 0, CK_TRUE, fake_read, &gone) ==
            CKR_OBJECT_HANDLE_INVALID,
        "empty template still proves the handle"
    );
}

static void test_session_and_modifiable(void)
{
    printf("== read-only session and CKA_MODIFIABLE ==\n");
    CK_ATTRIBUTE label = ATTR(CKA_LABEL, g_label);
    const CK_ATTRIBUTE token_obj[] = { ATTR(CKA_CLASS, g_data), BOOL_ATTR(CKA_TOKEN, g_true) };
    const CK_ATTRIBUTE token_wide[] = { ATTR(CKA_CLASS, g_data), ATTR(CKA_TOKEN, g_wide) };
    const CK_ATTRIBUTE frozen[] = { ATTR(CKA_CLASS, g_data), BOOL_ATTR(CKA_MODIFIABLE, g_false) };
    const CK_ATTRIBUTE frozen_wide[] = { ATTR(CKA_CLASS, g_data), ATTR(CKA_MODIFIABLE, g_wide) };
    const CK_ATTRIBUTE open[] = { ATTR(CKA_CLASS, g_data), BOOL_ATTR(CKA_MODIFIABLE, g_true) };
    const CK_ATTRIBUTE frozen_token[] = { BOOL_ATTR(CKA_TOKEN, g_true),
                                          BOOL_ATTR(CKA_MODIFIABLE, g_false) };

    CHECK(
        check_on(token_obj, COUNT(token_obj), CK_FALSE, label) == CKR_SESSION_READ_ONLY,
        "token object in a read-only session -> SESSION_READ_ONLY"
    );
    CHECK(
        check_on(token_obj, COUNT(token_obj), CK_TRUE, label) == CKR_OK,
        "token object in a read/write session -> OK"
    );
    CHECK(
        check_on(token_wide, COUNT(token_wide), CK_FALSE, label) == CKR_SESSION_READ_ONLY,
        "malformed stored CKA_TOKEN reads as TRUE"
    );
    CHECK(
        check_on(AES_KEY, COUNT(AES_KEY), CK_FALSE, label) == CKR_OK,
        "session object (no CKA_TOKEN) in a read-only session -> OK"
    );
    CHECK(
        check_on(frozen, COUNT(frozen), CK_TRUE, label) == CKR_ACTION_PROHIBITED,
        "CKA_MODIFIABLE=FALSE -> ACTION_PROHIBITED"
    );
    CHECK(
        check_on(frozen_wide, COUNT(frozen_wide), CK_TRUE, label) == CKR_ACTION_PROHIBITED,
        "malformed stored CKA_MODIFIABLE reads as FALSE"
    );
    CHECK(check_on(open, COUNT(open), CK_TRUE, label) == CKR_OK, "CKA_MODIFIABLE=TRUE -> OK");
    CHECK(
        check_on(frozen_token, COUNT(frozen_token), CK_FALSE, label) == CKR_SESSION_READ_ONLY,
        "read-only session is checked before CKA_MODIFIABLE"
    );
    fake_obj o = { frozen, COUNT(frozen), CKR_OK };
    CHECK(
        azihsm_pkcs11_setattr_check(NULL, 0, CK_TRUE, fake_read, &o) == CKR_ACTION_PROHIBITED,
        "unmodifiable object refuses even an empty template"
    );
}

static void test_secret_key(void)
{
    printf("== secret key: modifiable ==\n");
    CHECK(on_key((CK_ATTRIBUTE)ATTR(CKA_LABEL, g_label)) == CKR_OK, "CKA_LABEL");
    CHECK(on_key((CK_ATTRIBUTE)ATTR(CKA_ID, g_label)) == CKR_OK, "CKA_ID (added)");
    CHECK(on_key((CK_ATTRIBUTE)ATTR(CKA_START_DATE, g_date)) == CKR_OK, "CKA_START_DATE");
    CHECK(
        on_key((CK_ATTRIBUTE){ CKA_END_DATE, NULL, 0 }) == CKR_OK,
        "CKA_END_DATE empty (no date)"
    );
    static const CK_ATTRIBUTE_TYPE usage[] = { CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN,  CKA_VERIFY,
                                               CKA_WRAP,    CKA_UNWRAP,  CKA_DERIVE };
    for (size_t i = 0; i < COUNT(usage); i++)
    {
        CHECK(
            (on_key((CK_ATTRIBUTE)BOOL_ATTR(usage[i], g_false)) == CKR_OK) &&
                (on_key((CK_ATTRIBUTE)BOOL_ATTR(usage[i], g_true)) == CKR_OK),
            "usage flag either way"
        );
    }
    CHECK(
        on_key((CK_ATTRIBUTE)BOOL_ATTR(CKA_SENSITIVE, g_true)) == CKR_OK,
        "CKA_SENSITIVE TRUE -> TRUE"
    );
    CHECK(
        on_key((CK_ATTRIBUTE)BOOL_ATTR(CKA_EXTRACTABLE, g_false)) == CKR_OK,
        "CKA_EXTRACTABLE FALSE -> FALSE"
    );
    CHECK(
        on_key((CK_ATTRIBUTE)BOOL_ATTR(CKA_WRAP_WITH_TRUSTED, g_true)) == CKR_OK,
        "CKA_WRAP_WITH_TRUSTED absent -> TRUE"
    );

    printf("== secret key: read-only ==\n");
    CHECK(
        on_key((CK_ATTRIBUTE)BOOL_ATTR(CKA_SENSITIVE, g_false)) == CKR_ATTRIBUTE_READ_ONLY,
        "CKA_SENSITIVE TRUE -> FALSE (Tookan A5a)"
    );
    CHECK(
        on_key((CK_ATTRIBUTE)BOOL_ATTR(CKA_EXTRACTABLE, g_true)) == CKR_ATTRIBUTE_READ_ONLY,
        "CKA_EXTRACTABLE FALSE -> TRUE (Tookan A5b)"
    );
    CHECK(
        on_key((CK_ATTRIBUTE)ATTR(CKA_VALUE, g_secret_bytes)) == CKR_ATTRIBUTE_READ_ONLY,
        "CKA_VALUE (not carried: the key lives as a masked blob)"
    );
    CHECK(on_key((CK_ATTRIBUTE)ATTR(CKA_CLASS, g_data)) == CKR_ATTRIBUTE_READ_ONLY, "CKA_CLASS");
    CHECK(
        on_key((CK_ATTRIBUTE)ATTR(CKA_KEY_TYPE, g_aes)) == CKR_ATTRIBUTE_READ_ONLY,
        "CKA_KEY_TYPE, even to its own value"
    );
    CHECK(
        on_key((CK_ATTRIBUTE)ATTR(CKA_VALUE_LEN, g_len32)) == CKR_ATTRIBUTE_READ_ONLY,
        "CKA_VALUE_LEN"
    );
    static const CK_ATTRIBUTE_TYPE fixed[] = {
        CKA_TOKEN,
        CKA_PRIVATE,
        CKA_MODIFIABLE,
        CKA_COPYABLE,
        CKA_DESTROYABLE,
        CKA_LOCAL,
        CKA_ALWAYS_SENSITIVE,
        CKA_NEVER_EXTRACTABLE,
        CKA_KEY_GEN_MECHANISM,
        CKA_CHECK_VALUE,
        CKA_ALLOWED_MECHANISMS,
        CKA_UNIQUE_ID,
    };
    for (size_t i = 0; i < COUNT(fixed); i++)
    {
        CHECK(
            on_key((CK_ATTRIBUTE)BOOL_ATTR(fixed[i], g_true)) == CKR_ATTRIBUTE_READ_ONLY,
            "fixed key/storage attribute, carried or not"
        );
    }
    CHECK(
        on_key((CK_ATTRIBUTE)BOOL_ATTR(CKA_SIGN_RECOVER, g_true)) == CKR_ATTRIBUTE_TYPE_INVALID,
        "private-key-only CKA_SIGN_RECOVER on a secret key -> TYPE_INVALID"
    );
    CHECK(
        on_key((CK_ATTRIBUTE)ATTR(CKA_APPLICATION, g_label)) == CKR_ATTRIBUTE_TYPE_INVALID,
        "data-object CKA_APPLICATION on a key -> TYPE_INVALID"
    );
    CHECK(
        on_key((CK_ATTRIBUTE)ATTR(0x7FFFF00Ful, g_label)) == CKR_ATTRIBUTE_TYPE_INVALID,
        "undefined attribute type -> TYPE_INVALID"
    );
}

static void test_latches(void)
{
    printf("== latches: absent and malformed stored values ==\n");
    const CK_ATTRIBUTE bare[] = { ATTR(CKA_CLASS, g_secret) };
    const CK_ATTRIBUTE wide[] = { ATTR(CKA_CLASS, g_secret),
                                  ATTR(CKA_SENSITIVE, g_wide),
                                  ATTR(CKA_EXTRACTABLE, g_wide),
                                  ATTR(CKA_WRAP_WITH_TRUSTED, g_wide) };
    CHECK(
        check_on(bare, 1, CK_TRUE, (CK_ATTRIBUTE)BOOL_ATTR(CKA_SENSITIVE, g_false)) == CKR_OK,
        "absent CKA_SENSITIVE reads FALSE: FALSE allowed"
    );
    CHECK(
        check_on(bare, 1, CK_TRUE, (CK_ATTRIBUTE)BOOL_ATTR(CKA_EXTRACTABLE, g_true)) == CKR_OK,
        "absent CKA_EXTRACTABLE reads TRUE: TRUE allowed"
    );
    CHECK(
        check_on(bare, 1, CK_TRUE, (CK_ATTRIBUTE)BOOL_ATTR(CKA_WRAP_WITH_TRUSTED, g_false)) ==
            CKR_OK,
        "absent CKA_WRAP_WITH_TRUSTED reads FALSE: FALSE allowed"
    );
    CHECK(
        check_on(wide, COUNT(wide), CK_TRUE, (CK_ATTRIBUTE)BOOL_ATTR(CKA_SENSITIVE, g_false)) ==
            CKR_ATTRIBUTE_READ_ONLY,
        "malformed CKA_SENSITIVE reads TRUE"
    );
    CHECK(
        check_on(wide, COUNT(wide), CK_TRUE, (CK_ATTRIBUTE)BOOL_ATTR(CKA_EXTRACTABLE, g_true)) ==
            CKR_ATTRIBUTE_READ_ONLY,
        "malformed CKA_EXTRACTABLE reads FALSE"
    );
    CHECK(
        check_on(
            wide,
            COUNT(wide),
            CK_TRUE,
            (CK_ATTRIBUTE)BOOL_ATTR(CKA_WRAP_WITH_TRUSTED, g_false)
        ) == CKR_ATTRIBUTE_READ_ONLY,
        "malformed CKA_WRAP_WITH_TRUSTED reads TRUE"
    );
}

static void test_other_classes(void)
{
    printf("== data object ==\n");
    CHECK(on_data((CK_ATTRIBUTE)ATTR(CKA_LABEL, g_label)) == CKR_OK, "CKA_LABEL");
    CHECK(
        on_data((CK_ATTRIBUTE)ATTR(CKA_CLASS, g_public)) == CKR_ATTRIBUTE_READ_ONLY,
        "CKA_CLASS (pkcs11test GetSetAttributeInvalid)"
    );
    CHECK(
        on_data((CK_ATTRIBUTE)ATTR(CKA_VALUE, g_secret_bytes)) == CKR_ATTRIBUTE_READ_ONLY,
        "CKA_VALUE"
    );
    CHECK(
        on_data((CK_ATTRIBUTE)ATTR(CKA_APPLICATION, g_label)) == CKR_ATTRIBUTE_READ_ONLY,
        "CKA_APPLICATION"
    );
    CHECK(
        on_data((CK_ATTRIBUTE)ATTR(CKA_OBJECT_ID, g_label)) == CKR_ATTRIBUTE_READ_ONLY,
        "CKA_OBJECT_ID, not carried"
    );
    CHECK(
        on_data((CK_ATTRIBUTE)ATTR(CKA_ID, g_label)) == CKR_ATTRIBUTE_READ_ONLY,
        "a carried non-data attribute -> READ_ONLY"
    );
    CHECK(
        on_data((CK_ATTRIBUTE)BOOL_ATTR(CKA_ENCRYPT, g_true)) == CKR_ATTRIBUTE_TYPE_INVALID,
        "a key attribute it does not carry -> TYPE_INVALID"
    );

    printf("== asymmetric keys and classless objects ==\n");
    const CK_ATTRIBUTE priv[] = { ATTR(CKA_CLASS, g_private) };
    const CK_ATTRIBUTE pub[] = { ATTR(CKA_CLASS, g_public) };
    const CK_ATTRIBUTE none[] = { ATTR(CKA_LABEL, g_label) };
    const CK_ATTRIBUTE bad_class[] = { ATTR(CKA_CLASS, g_true) }; /* one byte wide */
    CHECK(
        check_on(priv, 1, CK_TRUE, (CK_ATTRIBUTE)BOOL_ATTR(CKA_SIGN_RECOVER, g_true)) == CKR_OK,
        "private key: CKA_SIGN_RECOVER"
    );
    CHECK(
        check_on(priv, 1, CK_TRUE, (CK_ATTRIBUTE)ATTR(CKA_SUBJECT, g_label)) == CKR_OK,
        "private key: CKA_SUBJECT"
    );
    CHECK(
        check_on(priv, 1, CK_TRUE, (CK_ATTRIBUTE)BOOL_ATTR(CKA_ENCRYPT, g_true)) ==
            CKR_ATTRIBUTE_TYPE_INVALID,
        "private key: CKA_ENCRYPT is a public-key attribute"
    );
    CHECK(
        check_on(pub, 1, CK_TRUE, (CK_ATTRIBUTE)BOOL_ATTR(CKA_VERIFY_RECOVER, g_true)) == CKR_OK,
        "public key: CKA_VERIFY_RECOVER"
    );
    CHECK(
        check_on(pub, 1, CK_TRUE, (CK_ATTRIBUTE)BOOL_ATTR(CKA_SENSITIVE, g_true)) ==
            CKR_ATTRIBUTE_TYPE_INVALID,
        "public key: CKA_SENSITIVE does not apply"
    );
    CHECK(
        check_on(none, 1, CK_TRUE, (CK_ATTRIBUTE)ATTR(CKA_LABEL, g_label)) == CKR_OK,
        "no CKA_CLASS: CKA_LABEL still modifiable"
    );
    CHECK(
        check_on(none, 1, CK_TRUE, (CK_ATTRIBUTE)ATTR(CKA_ID, g_label)) ==
            CKR_ATTRIBUTE_TYPE_INVALID,
        "no CKA_CLASS: key attributes do not apply"
    );
    CHECK(
        check_on(bad_class, 1, CK_TRUE, (CK_ATTRIBUTE)ATTR(CKA_ID, g_label)) ==
            CKR_ATTRIBUTE_TYPE_INVALID,
        "malformed CKA_CLASS: treated as classless"
    );
}

static void test_shapes_and_order(void)
{
    printf("== value shapes, duplicates, ordering ==\n");
    CHECK(
        on_key((CK_ATTRIBUTE)ATTR(CKA_ENCRYPT, g_wide)) == CKR_ATTRIBUTE_VALUE_INVALID,
        "CK_BBOOL of the wrong width"
    );
    CHECK(
        on_key((CK_ATTRIBUTE){ CKA_ENCRYPT, &g_true, CK_UNAVAILABLE_INFORMATION }) ==
            CKR_ATTRIBUTE_VALUE_INVALID,
        "CK_BBOOL with ulValueLen left at CK_UNAVAILABLE_INFORMATION"
    );
    CHECK(
        on_key((CK_ATTRIBUTE)ATTR(CKA_SENSITIVE, g_wide)) == CKR_ATTRIBUTE_VALUE_INVALID,
        "latch value of the wrong width"
    );
    CHECK(
        on_key((CK_ATTRIBUTE){ CKA_LABEL, NULL, 4 }) == CKR_ATTRIBUTE_VALUE_INVALID,
        "NULL value with a non-zero length"
    );
    CHECK(
        on_key((CK_ATTRIBUTE)ATTR(CKA_START_DATE, g_short_date)) == CKR_ATTRIBUTE_VALUE_INVALID,
        "CK_DATE of the wrong width"
    );
    CHECK(on_key((CK_ATTRIBUTE){ CKA_LABEL, NULL, 0 }) == CKR_OK, "empty label");
    CHECK(
        (on_key((CK_ATTRIBUTE)ATTR(CKA_START_DATE, g_date_min)) == CKR_OK) &&
            (on_key((CK_ATTRIBUTE)ATTR(CKA_END_DATE, g_date_max)) == CKR_OK),
        "CK_DATE range edges 1900-01-01 and 9999-12-31"
    );
    for (size_t i = 0; i < COUNT(g_bad_dates); i++)
    {
        CHECK(
            on_key((CK_ATTRIBUTE)ATTR(CKA_END_DATE, g_bad_dates[i])) == CKR_ATTRIBUTE_VALUE_INVALID,
            "CK_DATE out of range or not all digits"
        );
    }

    fake_obj o = { AES_KEY, COUNT(AES_KEY), CKR_OK };
    CK_ATTRIBUTE dup[] = { ATTR(CKA_LABEL, g_label), ATTR(CKA_LABEL, g_label) };
    CHECK(
        azihsm_pkcs11_setattr_check(dup, COUNT(dup), CK_TRUE, fake_read, &o) ==
            CKR_TEMPLATE_INCONSISTENT,
        "repeated type -> TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE multi[] = { ATTR(CKA_LABEL, g_label),
                             ATTR(CKA_ID, g_label),
                             BOOL_ATTR(CKA_ENCRYPT, g_false),
                             BOOL_ATTR(CKA_SENSITIVE, g_true) };
    CHECK(
        azihsm_pkcs11_setattr_check(multi, COUNT(multi), CK_TRUE, fake_read, &o) == CKR_OK,
        "several modifiable attributes at once"
    );
    CK_ATTRIBUTE late_bad[] = { ATTR(CKA_LABEL, g_label),
                                ATTR(CKA_ID, g_label),
                                BOOL_ATTR(CKA_EXTRACTABLE, g_true) };
    CHECK(
        azihsm_pkcs11_setattr_check(late_bad, COUNT(late_bad), CK_TRUE, fake_read, &o) ==
            CKR_ATTRIBUTE_READ_ONLY,
        "a refused attribute after accepted ones refuses the template"
    );
    CK_ATTRIBUTE order1[] = { ATTR(CKA_ENCRYPT, g_wide), ATTR(CKA_CLASS, g_data) };
    CK_ATTRIBUTE order2[] = { ATTR(CKA_CLASS, g_data), ATTR(CKA_ENCRYPT, g_wide) };
    CHECK(
        azihsm_pkcs11_setattr_check(order1, 2, CK_TRUE, fake_read, &o) ==
            CKR_ATTRIBUTE_VALUE_INVALID,
        "first failure wins (value before read-only)"
    );
    CHECK(
        azihsm_pkcs11_setattr_check(order2, 2, CK_TRUE, fake_read, &o) == CKR_ATTRIBUTE_READ_ONLY,
        "first failure wins (read-only before value)"
    );
}

int main(void)
{
    test_arguments();
    test_session_and_modifiable();
    test_secret_key();
    test_latches();
    test_other_classes();
    test_shapes_and_order();
    printf(
        g_fail ? "\nattr_policy_test: FAILED (%d checks)\n"
               : "\nattr_policy_test: all %d checks passed\n",
        g_checks
    );
    return g_fail;
}
