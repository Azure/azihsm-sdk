// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the device-free half of the AES slice: the CKM_AES_KEY_GEN
 * template logic (src/azihsm_pkcs11_template.c) and the status translation it
 * relies on (src/azihsm_pkcs11_status.c). No device, no libcrypto, no module
 * load — the functions are linked directly:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src aes_template_test.c \
 *       ../src/azihsm_pkcs11_template.c ../src/azihsm_pkcs11_status.c \
 *       -o aes_template_test && ./aes_template_test
 *
 * Covers the complete CK_RV matrix of azihsm_pkcs11_keygen_check_template
 * (every accepted key length, every rejected attribute and the code it earns,
 * non-AES key types, wrong value sizes, NULL values, duplicates, the length
 * ceiling, first-failure-wins ordering), the append-if-absent rules of
 * azihsm_pkcs11_keygen_build_template, and the status maps including the
 * padded-decrypt remap.
 */

#include "azihsm_pkcs11_status.h"
#include "azihsm_pkcs11_template.h"

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

/* Shared attribute values (the templates below point at these). */
static CK_BBOOL g_true = CK_TRUE;
static CK_BBOOL g_false = CK_FALSE;
static CK_OBJECT_CLASS g_secret = CKO_SECRET_KEY;
static CK_KEY_TYPE g_aes = CKK_AES;
static CK_ULONG g_len16 = AES128_KEY_BYTES;
static CK_ULONG g_len24 = AES192_KEY_BYTES;
static CK_ULONG g_len32 = AES256_KEY_BYTES;
static char g_label[] = "unit";

#define ATTR(t, v)                                                                                 \
    {                                                                                              \
        (t), (void *)&(v), sizeof(v)                                                               \
    }
#define BOOL_ATTR(t, b)                                                                            \
    {                                                                                              \
        (t), (void *)&(b), sizeof(CK_BBOOL)                                                        \
    }
#define VALUE_LEN32 ATTR(CKA_VALUE_LEN, g_len32)

/* Run the check on a template and return its CK_RV; outputs are optional. */
static CK_RV check(const CK_ATTRIBUTE *tmpl, CK_ULONG count, CK_ULONG *len, CK_BBOOL *token)
{
    CK_ULONG l = 0;
    CK_BBOOL t = CK_FALSE;
    CK_RV rv = azihsm_pkcs11_keygen_check_template(tmpl, count, &l, &t);
    if (len != NULL)
    {
        *len = l;
    }
    if (token != NULL)
    {
        *token = t;
    }
    return rv;
}

/* Expect `rv` for a template consisting of CKA_VALUE_LEN=32 plus one attribute. */
static CK_RV check_with(CK_ATTRIBUTE extra)
{
    CK_ATTRIBUTE tmpl[2] = { VALUE_LEN32, { 0, NULL, 0 } };
    tmpl[1] = extra;
    return check(tmpl, 2, NULL, NULL);
}

static void test_tmpl_find(void)
{
    printf("== azihsm_pkcs11_tmpl_find ==\n");
    CK_ATTRIBUTE tmpl[] = { ATTR(CKA_LABEL, g_label), VALUE_LEN32, ATTR(CKA_LABEL, g_true) };
    CHECK(azihsm_pkcs11_tmpl_find(NULL, 3, CKA_LABEL) == NULL, "NULL template -> NULL");
    CHECK(azihsm_pkcs11_tmpl_find(tmpl, 0, CKA_LABEL) == NULL, "count 0 -> NULL");
    CHECK(azihsm_pkcs11_tmpl_find(tmpl, 3, CKA_ID) == NULL, "absent type -> NULL");
    CHECK(azihsm_pkcs11_tmpl_find(tmpl, 3, CKA_VALUE_LEN) == &tmpl[1], "finds the entry");
    CHECK(
        azihsm_pkcs11_tmpl_find(tmpl, 3, CKA_LABEL) == &tmpl[0],
        "a repeated type yields the first"
    );
    CHECK(azihsm_pkcs11_tmpl_find(tmpl, 1, CKA_VALUE_LEN) == NULL, "count bounds the search");
}

static void test_tmpl_bool(void)
{
    printf("== azihsm_pkcs11_tmpl_bool ==\n");
    CK_BBOOL out = 0x55;
    CK_BBOOL odd = 0x7F;
    CK_ULONG wide = 1;
    CK_ATTRIBUTE a_true = BOOL_ATTR(CKA_TOKEN, g_true);
    CK_ATTRIBUTE a_false = BOOL_ATTR(CKA_TOKEN, g_false);
    CK_ATTRIBUTE a_odd = BOOL_ATTR(CKA_TOKEN, odd);
    CK_ATTRIBUTE a_null = { CKA_TOKEN, NULL, sizeof(CK_BBOOL) };
    CK_ATTRIBUTE a_short = { CKA_TOKEN, &g_true, 0 };
    CK_ATTRIBUTE a_wide = ATTR(CKA_TOKEN, wide);

    CHECK(azihsm_pkcs11_tmpl_bool(NULL, &out) == CKR_ATTRIBUTE_VALUE_INVALID, "NULL attribute");
    CHECK(azihsm_pkcs11_tmpl_bool(&a_true, NULL) == CKR_ATTRIBUTE_VALUE_INVALID, "NULL out");
    CHECK(azihsm_pkcs11_tmpl_bool(&a_null, &out) == CKR_ATTRIBUTE_VALUE_INVALID, "NULL value");
    CHECK(azihsm_pkcs11_tmpl_bool(&a_short, &out) == CKR_ATTRIBUTE_VALUE_INVALID, "zero length");
    CHECK(
        azihsm_pkcs11_tmpl_bool(&a_wide, &out) == CKR_ATTRIBUTE_VALUE_INVALID,
        "CK_ULONG-sized value is not a CK_BBOOL"
    );
    CHECK(
        (azihsm_pkcs11_tmpl_bool(&a_true, &out) == CKR_OK) && (out == CK_TRUE),
        "CK_TRUE reads as CK_TRUE"
    );
    CHECK(
        (azihsm_pkcs11_tmpl_bool(&a_false, &out) == CKR_OK) && (out == CK_FALSE),
        "CK_FALSE reads as CK_FALSE"
    );
    CHECK(
        (azihsm_pkcs11_tmpl_bool(&a_odd, &out) == CKR_OK) && (out == CK_TRUE),
        "any non-zero byte normalises to CK_TRUE"
    );
}

static void test_check_arguments(void)
{
    printf("== keygen_check_template: arguments and ceiling ==\n");
    CK_ATTRIBUTE one[] = { VALUE_LEN32 };
    CK_ULONG len = 0;
    CK_BBOOL token = CK_FALSE;
    CHECK(
        azihsm_pkcs11_keygen_check_template(one, 1, NULL, &token) == CKR_ARGUMENTS_BAD,
        "NULL value_len -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_keygen_check_template(one, 1, &len, NULL) == CKR_ARGUMENTS_BAD,
        "NULL token -> CKR_ARGUMENTS_BAD"
    );
    CHECK(check(NULL, 1, NULL, NULL) == CKR_ARGUMENTS_BAD, "NULL template with count 1");
    CHECK(
        check(NULL, 0, NULL, NULL) == CKR_TEMPLATE_INCOMPLETE,
        "NULL template with count 0 is just an empty template"
    );

    /* Distinct vendor types keep the duplicate scan quiet, so the count alone
     * decides. KEYGEN_MAX_TEMPLATE_ATTRS entries pass, one more is refused. */
    CK_BYTE byte = 0;
    CK_ATTRIBUTE big[KEYGEN_MAX_TEMPLATE_ATTRS + 1];
    for (CK_ULONG i = 0; i < COUNT(big); i++)
    {
        big[i].type = CKA_VENDOR_DEFINED + i;
        big[i].pValue = &byte;
        big[i].ulValueLen = sizeof(byte);
    }
    big[0] = (CK_ATTRIBUTE)VALUE_LEN32;
    CHECK(
        (check(big, KEYGEN_MAX_TEMPLATE_ATTRS, &len, NULL) == CKR_OK) && (len == AES256_KEY_BYTES),
        "exactly KEYGEN_MAX_TEMPLATE_ATTRS distinct attributes -> CKR_OK"
    );
    CHECK(
        check(big, KEYGEN_MAX_TEMPLATE_ATTRS + 1, NULL, NULL) == CKR_ARGUMENTS_BAD,
        "KEYGEN_MAX_TEMPLATE_ATTRS + 1 -> CKR_ARGUMENTS_BAD"
    );
    len = 99;
    token = CK_TRUE;
    CHECK(
        (azihsm_pkcs11_keygen_check_template(big, KEYGEN_MAX_TEMPLATE_ATTRS + 1, &len, &token) ==
         CKR_ARGUMENTS_BAD) &&
            (len == 0) && (token == CK_FALSE),
        "outputs are reset on the ceiling verdict too"
    );

    /* Outputs are reset before any verdict. */
    len = 99;
    token = CK_TRUE;
    CK_ATTRIBUTE only_label[] = { ATTR(CKA_LABEL, g_label) };
    CHECK(
        (azihsm_pkcs11_keygen_check_template(only_label, 1, &len, &token) == CKR_TEMPLATE_INCOMPLETE
        ) && (len == 0) &&
            (token == CK_FALSE),
        "outputs are reset even when the template is rejected"
    );
}

static void test_check_accept(void)
{
    printf("== keygen_check_template: accepted templates ==\n");
    CK_ULONG len = 0;
    CK_BBOOL token = CK_TRUE;
    CK_ATTRIBUTE t16[] = { ATTR(CKA_VALUE_LEN, g_len16) };
    CK_ATTRIBUTE t24[] = { ATTR(CKA_VALUE_LEN, g_len24) };
    CK_ATTRIBUTE t32[] = { VALUE_LEN32 };
    CHECK(
        (check(t16, 1, &len, &token) == CKR_OK) && (len == AES128_KEY_BYTES) && (token == CK_FALSE),
        "CKA_VALUE_LEN 16 -> AES-128, token defaults to FALSE"
    );
    CHECK((check(t24, 1, &len, NULL) == CKR_OK) && (len == AES192_KEY_BYTES), "CKA_VALUE_LEN 24");
    CHECK((check(t32, 1, &len, NULL) == CKR_OK) && (len == AES256_KEY_BYTES), "CKA_VALUE_LEN 32");

    CK_BYTE id[] = { 1, 2, 3 };
    CK_ATTRIBUTE full[] = {
        ATTR(CKA_CLASS, g_secret),
        ATTR(CKA_KEY_TYPE, g_aes),
        VALUE_LEN32,
        BOOL_ATTR(CKA_TOKEN, g_true),
        BOOL_ATTR(CKA_SENSITIVE, g_true),
        BOOL_ATTR(CKA_EXTRACTABLE, g_false),
        BOOL_ATTR(CKA_ENCRYPT, g_true),
        BOOL_ATTR(CKA_DECRYPT, g_false),
        BOOL_ATTR(CKA_PRIVATE, g_true),
        ATTR(CKA_LABEL, g_label),
        ATTR(CKA_ID, id),
        BOOL_ATTR(CKA_WRAP, g_false),
    };
    CHECK(
        (check(full, COUNT(full), &len, &token) == CKR_OK) && (len == AES256_KEY_BYTES) &&
            (token == CK_TRUE),
        "full explicit template -> CKR_OK, token extracted"
    );

    CK_ATTRIBUTE tok_false[] = { VALUE_LEN32, BOOL_ATTR(CKA_TOKEN, g_false) };
    CHECK(
        (check(tok_false, 2, NULL, &token) == CKR_OK) && (token == CK_FALSE),
        "CKA_TOKEN=FALSE extracted"
    );

    CK_BYTE vendor_val[100] = { 0 };
    CHECK(
        check_with((CK_ATTRIBUTE)ATTR(CKA_VENDOR_DEFINED + 7, vendor_val)) == CKR_OK,
        "unknown/vendor attribute is accepted (stored verbatim)"
    );
    CK_ATTRIBUTE empty_unknown[] = { VALUE_LEN32, { CKA_APPLICATION, NULL, 0 } };
    CHECK(
        check(empty_unknown, 2, NULL, NULL) == CKR_OK,
        "NULL value with zero length is a valid empty attribute"
    );
    CHECK(check_with((CK_ATTRIBUTE)BOOL_ATTR(CKA_ENCRYPT, g_false)) == CKR_OK, "CKA_ENCRYPT=FALSE");
    CHECK(check_with((CK_ATTRIBUTE)BOOL_ATTR(CKA_DECRYPT, g_true)) == CKR_OK, "CKA_DECRYPT=TRUE");
    CHECK(
        check_with((CK_ATTRIBUTE)BOOL_ATTR(CKA_SENSITIVE, g_true)) == CKR_OK,
        "CKA_SENSITIVE=TRUE"
    );
    CHECK(
        check_with((CK_ATTRIBUTE)BOOL_ATTR(CKA_EXTRACTABLE, g_false)) == CKR_OK,
        "CKA_EXTRACTABLE=FALSE"
    );
}

/*
 * A caller that packs its whole template into one byte buffer hands us pValue
 * pointers with no particular alignment. Built with -fsanitize=undefined (see
 * the CI workflow and run_validation.sh) this is also what catches a plain
 * cast creeping back into the decoder.
 */
static void test_check_unaligned(void)
{
    printf("== keygen_check_template: unaligned attribute values ==\n");
    static unsigned char blob[64];
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_AES;
    CK_ULONG vlen = AES192_KEY_BYTES;
    CK_BBOOL tok = CK_TRUE;
    /* Starting at offset 1 puts every CK_ULONG-wide value on an odd address. */
    unsigned char *p_cls = blob + 1;
    unsigned char *p_kt = p_cls + sizeof(CK_OBJECT_CLASS);
    unsigned char *p_vlen = p_kt + sizeof(CK_KEY_TYPE);
    unsigned char *p_tok = p_vlen + sizeof(CK_ULONG);
    memcpy(p_cls, &cls, sizeof(cls));
    memcpy(p_kt, &kt, sizeof(kt));
    memcpy(p_vlen, &vlen, sizeof(vlen));
    memcpy(p_tok, &tok, sizeof(tok));

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, p_cls, sizeof(CK_OBJECT_CLASS) },
        { CKA_KEY_TYPE, p_kt, sizeof(CK_KEY_TYPE) },
        { CKA_VALUE_LEN, p_vlen, sizeof(CK_ULONG) },
        { CKA_TOKEN, p_tok, sizeof(CK_BBOOL) },
    };
    CK_ULONG len = 0;
    CK_BBOOL token = CK_FALSE;
    CHECK(
        (check(tmpl, COUNT(tmpl), &len, &token) == CKR_OK) && (len == AES192_KEY_BYTES) &&
            (token == CK_TRUE),
        "values at odd addresses decode as they would aligned"
    );

    CK_KEY_TYPE not_aes = CKK_DES3;
    memcpy(p_kt, &not_aes, sizeof(not_aes));
    CHECK(
        check(tmpl, COUNT(tmpl), NULL, NULL) == CKR_TEMPLATE_INCONSISTENT,
        "an unaligned non-AES CKA_KEY_TYPE is still rejected"
    );
}

static void test_check_reject(void)
{
    printf("== keygen_check_template: rejected templates ==\n");
    CHECK(
        check(NULL, 0, NULL, NULL) == CKR_TEMPLATE_INCOMPLETE,
        "empty -> CKR_TEMPLATE_INCOMPLETE"
    );
    CK_ATTRIBUTE no_len[] = { ATTR(CKA_CLASS, g_secret), ATTR(CKA_KEY_TYPE, g_aes) };
    CHECK(
        check(no_len, 2, NULL, NULL) == CKR_TEMPLATE_INCOMPLETE,
        "class + type without CKA_VALUE_LEN -> CKR_TEMPLATE_INCOMPLETE"
    );

    /* CKA_VALUE_LEN: every non-AES length and a wrongly sized value. */
    static const CK_ULONG bad_lens[] = { 0, 8, 15, 17, 20, 31, 33, 48, 64, 256 };
    for (size_t i = 0; i < COUNT(bad_lens); i++)
    {
        CK_ULONG l = bad_lens[i];
        CK_ATTRIBUTE t[] = { ATTR(CKA_VALUE_LEN, l) };
        char msg[80];
        snprintf(
            msg,
            sizeof(msg),
            "CKA_VALUE_LEN %lu -> CKR_ATTRIBUTE_VALUE_INVALID",
            (unsigned long)l
        );
        CHECK(check(t, 1, NULL, NULL) == CKR_ATTRIBUTE_VALUE_INVALID, msg);
    }
    CK_ATTRIBUTE short_len[] = { { CKA_VALUE_LEN, &g_len32, sizeof(CK_ULONG) - 1 } };
    CHECK(
        check(short_len, 1, NULL, NULL) == CKR_ATTRIBUTE_VALUE_INVALID,
        "CKA_VALUE_LEN with a short value -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CK_ULONG len2[2] = { AES256_KEY_BYTES, 0 };
    CK_ATTRIBUTE long_len[] = { ATTR(CKA_VALUE_LEN, len2) };
    CHECK(
        check(long_len, 1, NULL, NULL) == CKR_ATTRIBUTE_VALUE_INVALID,
        "CKA_VALUE_LEN with an over-long value -> CKR_ATTRIBUTE_VALUE_INVALID"
    );

    /* CKA_CLASS */
    CK_OBJECT_CLASS data = CKO_DATA, priv = CKO_PRIVATE_KEY, pub = CKO_PUBLIC_KEY;
    CHECK(
        check_with((CK_ATTRIBUTE)ATTR(CKA_CLASS, data)) == CKR_TEMPLATE_INCONSISTENT,
        "CKA_CLASS=CKO_DATA -> CKR_TEMPLATE_INCONSISTENT"
    );
    CHECK(
        check_with((CK_ATTRIBUTE)ATTR(CKA_CLASS, priv)) == CKR_TEMPLATE_INCONSISTENT,
        "CKA_CLASS=CKO_PRIVATE_KEY -> CKR_TEMPLATE_INCONSISTENT"
    );
    CHECK(
        check_with((CK_ATTRIBUTE)ATTR(CKA_CLASS, pub)) == CKR_TEMPLATE_INCONSISTENT,
        "CKA_CLASS=CKO_PUBLIC_KEY -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE short_class = { CKA_CLASS, &g_secret, sizeof(CK_OBJECT_CLASS) - 1 };
    CHECK(
        check_with(short_class) == CKR_ATTRIBUTE_VALUE_INVALID,
        "CKA_CLASS with a short value -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CK_OBJECT_CLASS cls2[2] = { CKO_SECRET_KEY, 0 };
    CHECK(
        check_with((CK_ATTRIBUTE)ATTR(CKA_CLASS, cls2)) == CKR_ATTRIBUTE_VALUE_INVALID,
        "CKA_CLASS with an over-long value -> CKR_ATTRIBUTE_VALUE_INVALID"
    );

    /* CKA_KEY_TYPE: the non-AES key types a caller might send to CKM_AES_KEY_GEN. */
    static const CK_KEY_TYPE other_types[] = { CKK_DES3,        CKK_DES, CKK_GENERIC_SECRET,
                                               CKK_SHA256_HMAC, CKK_RSA, CKK_EC,
                                               CKK_EC_EDWARDS };
    for (size_t i = 0; i < COUNT(other_types); i++)
    {
        CK_KEY_TYPE kt = other_types[i];
        char msg[80];
        snprintf(
            msg,
            sizeof(msg),
            "CKA_KEY_TYPE 0x%lx -> CKR_TEMPLATE_INCONSISTENT",
            (unsigned long)kt
        );
        CHECK(check_with((CK_ATTRIBUTE)ATTR(CKA_KEY_TYPE, kt)) == CKR_TEMPLATE_INCONSISTENT, msg);
    }
    CK_ATTRIBUTE short_type = { CKA_KEY_TYPE, &g_aes, sizeof(CK_KEY_TYPE) - 1 };
    CHECK(
        check_with(short_type) == CKR_ATTRIBUTE_VALUE_INVALID,
        "CKA_KEY_TYPE with a short value -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CK_KEY_TYPE kt2[2] = { CKK_AES, 0 };
    CHECK(
        check_with((CK_ATTRIBUTE)ATTR(CKA_KEY_TYPE, kt2)) == CKR_ATTRIBUTE_VALUE_INVALID,
        "CKA_KEY_TYPE with an over-long value -> CKR_ATTRIBUTE_VALUE_INVALID"
    );

    /* Sensitivity: a device key only ever exists masked. */
    CHECK(
        check_with((CK_ATTRIBUTE)BOOL_ATTR(CKA_SENSITIVE, g_false)) == CKR_TEMPLATE_INCONSISTENT,
        "CKA_SENSITIVE=FALSE -> CKR_TEMPLATE_INCONSISTENT"
    );
    CHECK(
        check_with((CK_ATTRIBUTE)BOOL_ATTR(CKA_EXTRACTABLE, g_true)) == CKR_TEMPLATE_INCONSISTENT,
        "CKA_EXTRACTABLE=TRUE -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ULONG wide_true = 1;
    static const CK_ATTRIBUTE_TYPE bool_types[] = { CKA_SENSITIVE,
                                                    CKA_EXTRACTABLE,
                                                    CKA_ENCRYPT,
                                                    CKA_DECRYPT,
                                                    CKA_TOKEN };
    for (size_t i = 0; i < COUNT(bool_types); i++)
    {
        CK_ATTRIBUTE wide = { bool_types[i], &wide_true, sizeof(wide_true) };
        CK_ATTRIBUTE nul = { bool_types[i], NULL, sizeof(CK_BBOOL) };
        char msg[80];
        snprintf(
            msg,
            sizeof(msg),
            "CKA_ 0x%lx sized as CK_ULONG -> CKR_ATTRIBUTE_VALUE_INVALID",
            (unsigned long)bool_types[i]
        );
        CHECK(check_with(wide) == CKR_ATTRIBUTE_VALUE_INVALID, msg);
        snprintf(
            msg,
            sizeof(msg),
            "CKA_ 0x%lx with NULL value -> CKR_ATTRIBUTE_VALUE_INVALID",
            (unsigned long)bool_types[i]
        );
        CHECK(check_with(nul) == CKR_ATTRIBUTE_VALUE_INVALID, msg);
    }

    /* Token-computed attributes are read-only whatever their value. */
    static const CK_ATTRIBUTE_TYPE ro_types[] = { CKA_LOCAL,
                                                  CKA_ALWAYS_SENSITIVE,
                                                  CKA_NEVER_EXTRACTABLE };
    for (size_t i = 0; i < COUNT(ro_types); i++)
    {
        char msg[80];
        snprintf(
            msg,
            sizeof(msg),
            "CKA_ 0x%lx=TRUE -> CKR_ATTRIBUTE_READ_ONLY",
            (unsigned long)ro_types[i]
        );
        CHECK(
            check_with((CK_ATTRIBUTE){ ro_types[i], &g_true, sizeof(CK_BBOOL) }) ==
                CKR_ATTRIBUTE_READ_ONLY,
            msg
        );
        snprintf(
            msg,
            sizeof(msg),
            "CKA_ 0x%lx=FALSE -> CKR_ATTRIBUTE_READ_ONLY",
            (unsigned long)ro_types[i]
        );
        CHECK(
            check_with((CK_ATTRIBUTE){ ro_types[i], &g_false, sizeof(CK_BBOOL) }) ==
                CKR_ATTRIBUTE_READ_ONLY,
            msg
        );
    }

    /* Key material cannot be supplied to a generator. */
    CK_BYTE material[AES256_KEY_BYTES] = { 0 };
    CHECK(
        check_with((CK_ATTRIBUTE)ATTR(CKA_VALUE, material)) == CKR_TEMPLATE_INCONSISTENT,
        "CKA_VALUE with material -> CKR_TEMPLATE_INCONSISTENT"
    );
    CHECK(
        check_with((CK_ATTRIBUTE){ CKA_VALUE, NULL, 0 }) == CKR_TEMPLATE_INCONSISTENT,
        "empty CKA_VALUE -> CKR_TEMPLATE_INCONSISTENT"
    );

    /* NULL value with a non-zero length, for any type. */
    CHECK(
        check_with((CK_ATTRIBUTE){ CKA_LABEL, NULL, 4 }) == CKR_ATTRIBUTE_VALUE_INVALID,
        "NULL value with length 4 -> CKR_ATTRIBUTE_VALUE_INVALID"
    );

    /* Duplicates, even with identical values. */
    CHECK(
        check_with((CK_ATTRIBUTE)VALUE_LEN32) == CKR_TEMPLATE_INCONSISTENT,
        "CKA_VALUE_LEN twice (same value) -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE dup_len[] = { VALUE_LEN32, ATTR(CKA_VALUE_LEN, g_len16) };
    CHECK(
        check(dup_len, 2, NULL, NULL) == CKR_TEMPLATE_INCONSISTENT,
        "CKA_VALUE_LEN twice (different values) -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE dup_label[] = { VALUE_LEN32, ATTR(CKA_LABEL, g_label), ATTR(CKA_LABEL, g_label) };
    CHECK(
        check(dup_label, 3, NULL, NULL) == CKR_TEMPLATE_INCONSISTENT,
        "an unknown-to-keygen type repeated -> CKR_TEMPLATE_INCONSISTENT"
    );
}

static void test_check_order(void)
{
    printf("== keygen_check_template: first failure wins ==\n");
    CK_ULONG twenty = 20;
    CK_ATTRIBUTE a[] = { ATTR(CKA_VALUE_LEN, twenty), BOOL_ATTR(CKA_LOCAL, g_true) };
    CK_ATTRIBUTE b[] = { BOOL_ATTR(CKA_LOCAL, g_true), ATTR(CKA_VALUE_LEN, twenty) };
    CHECK(
        check(a, 2, NULL, NULL) == CKR_ATTRIBUTE_VALUE_INVALID,
        "[bad VALUE_LEN, LOCAL] -> the VALUE_LEN verdict"
    );
    CHECK(
        check(b, 2, NULL, NULL) == CKR_ATTRIBUTE_READ_ONLY,
        "[LOCAL, bad VALUE_LEN] -> the LOCAL verdict"
    );
    CK_ATTRIBUTE c[] = { BOOL_ATTR(CKA_SENSITIVE, g_false), { CKA_LABEL, NULL, 4 } };
    CHECK(
        check(c, 2, NULL, NULL) == CKR_TEMPLATE_INCONSISTENT,
        "[SENSITIVE=FALSE, NULL value] -> the SENSITIVE verdict"
    );
    CK_ATTRIBUTE d[] = { { CKA_LABEL, NULL, 4 }, BOOL_ATTR(CKA_SENSITIVE, g_false) };
    CHECK(
        check(d, 2, NULL, NULL) == CKR_ATTRIBUTE_VALUE_INVALID,
        "[NULL value, SENSITIVE=FALSE] -> the NULL-value verdict"
    );
    /* The duplicate scan runs before the per-type check of the repeated entry:
     * the second value would earn CKR_ATTRIBUTE_VALUE_INVALID on its own. */
    CK_ATTRIBUTE e[] = { VALUE_LEN32, ATTR(CKA_VALUE_LEN, twenty) };
    CHECK(
        check(e, 2, NULL, NULL) == CKR_TEMPLATE_INCONSISTENT,
        "[VALUE_LEN=32, VALUE_LEN=20] -> the duplicate verdict, not the length one"
    );
    /* ...but the NULL-value guard runs before the duplicate scan. */
    CK_ATTRIBUTE f[] = { ATTR(CKA_LABEL, g_label), { CKA_LABEL, NULL, 4 } };
    CHECK(
        check(f, 2, NULL, NULL) == CKR_ATTRIBUTE_VALUE_INVALID,
        "[LABEL, LABEL with NULL value] -> the NULL-value verdict, not the duplicate one"
    );
}

/* Find `t` in a built template and compare its value. */
static int built_has(
    const CK_ATTRIBUTE *full,
    CK_ULONG n,
    CK_ATTRIBUTE_TYPE t,
    const void *v,
    CK_ULONG l
)
{
    const CK_ATTRIBUTE *a = azihsm_pkcs11_tmpl_find(full, n, t);
    return (a != NULL) && (a->pValue != NULL) && (a->ulValueLen == l) &&
           (memcmp(a->pValue, v, l) == 0);
}

static void test_build(void)
{
    printf("== keygen_build_template ==\n");
    azihsm_pkcs11_keygen_fill fill;
    memset(&fill, 0xA5, sizeof(fill)); /* every field must be written by the builder */
    CK_ATTRIBUTE full[KEYGEN_MAX_TEMPLATE_ATTRS + KEYGEN_APPENDED_ATTRS];
    CK_ULONG n = 0;

    CHECK(
        azihsm_pkcs11_keygen_build_template(NULL, 0, NULL, full, &n) == CKR_ARGUMENTS_BAD,
        "NULL fill -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_keygen_build_template(NULL, 0, &fill, NULL, &n) == CKR_ARGUMENTS_BAD,
        "NULL output array -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_keygen_build_template(NULL, 0, &fill, full, NULL) == CKR_ARGUMENTS_BAD,
        "NULL count output -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_keygen_build_template(NULL, 1, &fill, full, &n) == CKR_ARGUMENTS_BAD,
        "NULL template with count 1 -> CKR_ARGUMENTS_BAD"
    );

    /* Empty caller template: every default is appended. */
    CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
    CK_KEY_TYPE aes = CKK_AES;
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CHECK(
        (azihsm_pkcs11_keygen_build_template(NULL, 0, &fill, full, &n) == CKR_OK) &&
            (n == KEYGEN_APPENDED_ATTRS),
        "empty template -> exactly KEYGEN_APPENDED_ATTRS attributes"
    );
    CHECK(
        built_has(full, n, CKA_CLASS, &secret, sizeof(secret)),
        "default CKA_CLASS=CKO_SECRET_KEY"
    );
    CHECK(built_has(full, n, CKA_KEY_TYPE, &aes, sizeof(aes)), "default CKA_KEY_TYPE=CKK_AES");
    CHECK(built_has(full, n, CKA_SENSITIVE, &t, sizeof(t)), "default CKA_SENSITIVE=TRUE");
    CHECK(built_has(full, n, CKA_EXTRACTABLE, &f, sizeof(f)), "default CKA_EXTRACTABLE=FALSE");
    CHECK(built_has(full, n, CKA_ENCRYPT, &t, sizeof(t)), "default CKA_ENCRYPT=TRUE");
    CHECK(built_has(full, n, CKA_DECRYPT, &t, sizeof(t)), "default CKA_DECRYPT=TRUE");
    CHECK(built_has(full, n, CKA_LOCAL, &t, sizeof(t)), "CKA_LOCAL=TRUE always appended");
    CHECK(
        built_has(full, n, CKA_ALWAYS_SENSITIVE, &t, sizeof(t)),
        "CKA_ALWAYS_SENSITIVE=TRUE always"
    );
    CHECK(
        built_has(full, n, CKA_NEVER_EXTRACTABLE, &t, sizeof(t)),
        "CKA_NEVER_EXTRACTABLE=TRUE always"
    );

    /* Caller-supplied usage flags win over the defaults and are not duplicated. */
    CK_ATTRIBUTE usage[] = { VALUE_LEN32,
                             BOOL_ATTR(CKA_ENCRYPT, g_false),
                             BOOL_ATTR(CKA_DECRYPT, g_false),
                             ATTR(CKA_LABEL, g_label) };
    CHECK(
        (azihsm_pkcs11_keygen_build_template(usage, COUNT(usage), &fill, full, &n) == CKR_OK) &&
            (n == COUNT(usage) + KEYGEN_APPENDED_ATTRS - 2),
        "given ENCRYPT/DECRYPT are not appended again"
    );
    CHECK(built_has(full, n, CKA_ENCRYPT, &f, sizeof(f)), "caller's CKA_ENCRYPT=FALSE is kept");
    CHECK(built_has(full, n, CKA_DECRYPT, &f, sizeof(f)), "caller's CKA_DECRYPT=FALSE is kept");
    CHECK(
        (full[0].type == CKA_VALUE_LEN) && (full[0].pValue == &g_len32) &&
            (full[3].type == CKA_LABEL) && (full[3].pValue == g_label),
        "caller attributes are copied verbatim at the front, in order"
    );
    CHECK(built_has(full, n, CKA_CLASS, &secret, sizeof(secret)), "CKA_CLASS still appended");
    int enc_count = 0;
    for (CK_ULONG i = 0; i < n; i++)
    {
        enc_count += (full[i].type == CKA_ENCRYPT);
    }
    CHECK(enc_count == 1, "exactly one CKA_ENCRYPT in the result");

    /* All six defaults supplied: only the always-appended trio is added. */
    CK_ATTRIBUTE all6[] = { ATTR(CKA_CLASS, g_secret),
                            ATTR(CKA_KEY_TYPE, g_aes),
                            BOOL_ATTR(CKA_SENSITIVE, g_true),
                            BOOL_ATTR(CKA_EXTRACTABLE, g_false),
                            BOOL_ATTR(CKA_ENCRYPT, g_true),
                            BOOL_ATTR(CKA_DECRYPT, g_true),
                            VALUE_LEN32 };
    CHECK(
        (azihsm_pkcs11_keygen_build_template(all6, COUNT(all6), &fill, full, &n) == CKR_OK) &&
            (n == COUNT(all6) + 3),
        "all defaults given -> only LOCAL/ALWAYS_SENSITIVE/NEVER_EXTRACTABLE appended"
    );
    CHECK(
        (full[n - 3].type == CKA_LOCAL) && (full[n - 2].type == CKA_ALWAYS_SENSITIVE) &&
            (full[n - 1].type == CKA_NEVER_EXTRACTABLE),
        "the trio is appended last, in order"
    );

    /* The appended values live in `fill`. */
    const CK_ATTRIBUTE *local = azihsm_pkcs11_tmpl_find(full, n, CKA_LOCAL);
    CHECK(
        (local != NULL) && (local->pValue == &fill.btrue),
        "appended values point into the fill struct"
    );
}

static void test_status_maps(void)
{
    printf("== status maps ==\n");
    /* The padded-decrypt remap: exactly INTERNAL_ERROR (-5) with unpad. */
    CHECK(
        azihsm_pkcs11_ckr_from_cbc_fill(-5, true) == CKR_ENCRYPTED_DATA_INVALID,
        "fill: -5 with unpad -> CKR_ENCRYPTED_DATA_INVALID"
    );
    CHECK(
        azihsm_pkcs11_ckr_from_cbc_fill(-5, false) == CKR_FUNCTION_FAILED,
        "fill: -5 without unpad -> CKR_FUNCTION_FAILED (shared map default)"
    );
    CHECK(azihsm_pkcs11_ckr_from_cbc_fill(0, true) == CKR_OK, "fill: 0 -> CKR_OK");
    CHECK(
        azihsm_pkcs11_ckr_from_cbc_fill(-2, true) == CKR_KEY_HANDLE_INVALID,
        "fill: INVALID_HANDLE names the device key"
    );
    CHECK(
        azihsm_pkcs11_ckr_from_cbc_fill(-2, false) == CKR_KEY_HANDLE_INVALID,
        "fill: INVALID_HANDLE names the device key (no unpad)"
    );
    CHECK(
        azihsm_pkcs11_ckr_from_cbc_fill(-4, true) == CKR_BUFFER_TOO_SMALL,
        "fill: -4 -> BUFFER_TOO_SMALL"
    );
    CHECK(
        azihsm_pkcs11_ckr_from_cbc_fill(-1, true) == CKR_ARGUMENTS_BAD,
        "fill: -1 -> ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_ckr_from_cbc_fill(-26, true) == CKR_KEY_HANDLE_INVALID,
        "fill: MASKED_KEY_DECODE_FAILED -> KEY_HANDLE_INVALID"
    );
    CHECK(
        azihsm_pkcs11_ckr_from_cbc_fill(-8, true) == CKR_FUNCTION_FAILED,
        "fill: DDI_CMD_FAILURE is never mistaken for bad padding"
    );

    /* The shared map, plain and hinted. */
    CHECK(azihsm_pkcs11_ckr_from_azihsm(0) == CKR_OK, "0 -> CKR_OK");
    CHECK(
        azihsm_pkcs11_ckr_from_azihsm(-2) == CKR_OBJECT_HANDLE_INVALID,
        "-2 plain -> OBJECT_HANDLE_INVALID"
    );
    CHECK(
        azihsm_pkcs11_ckr_from_azihsm_hint(-2, CKR_USER_NOT_LOGGED_IN) == CKR_USER_NOT_LOGGED_IN,
        "-2 hinted -> the caller's translation"
    );
    CHECK(
        azihsm_pkcs11_ckr_from_azihsm_hint(-7, CKR_USER_NOT_LOGGED_IN) == CKR_KEY_SIZE_RANGE,
        "the hint only affects -2"
    );
    struct
    {
        int status;
        CK_RV rv;
        const char *name;
    } map[] = {
        { -1, CKR_ARGUMENTS_BAD, "-1 INVALID_ARGUMENT" },
        { -3, CKR_ARGUMENTS_BAD, "-3 INDEX_OUT_OF_RANGE" },
        { -4, CKR_BUFFER_TOO_SMALL, "-4 BUFFER_TOO_SMALL" },
        { -5, CKR_FUNCTION_FAILED, "-5 INTERNAL_ERROR (plain map)" },
        { -6, CKR_DEVICE_ERROR, "-6 RNG_ERROR" },
        { -7, CKR_KEY_SIZE_RANGE, "-7 INVALID_KEY_SIZE" },
        { -8, CKR_FUNCTION_FAILED, "-8 DDI_CMD_FAILURE" },
        { -9, CKR_ATTRIBUTE_TYPE_INVALID, "-9 PROPERTY_NOT_PRESENT" },
        { -10, CKR_TEMPLATE_INCOMPLETE, "-10 KEY_CLASS_NOT_SPECIFIED" },
        { -11, CKR_TEMPLATE_INCOMPLETE, "-11 KEY_KIND_NOT_SPECIFIED" },
        { -12, CKR_KEY_HANDLE_INVALID, "-12 INVALID_KEY" },
        { -13, CKR_MECHANISM_INVALID, "-13 UNSUPPORTED_KEY_KIND" },
        { -14, CKR_MECHANISM_INVALID, "-14 UNSUPPORTED_ALGORITHM" },
        { -15, CKR_SIGNATURE_INVALID, "-15 INVALID_SIGNATURE" },
        { -16, CKR_KEY_HANDLE_INVALID, "-16 INVALID_KEY_PROPS" },
        { -17, CKR_ATTRIBUTE_TYPE_INVALID, "-17 UNSUPPORTED_PROPERTY" },
        { -19, CKR_MECHANISM_PARAM_INVALID, "-19 INVALID_TWEAK" },
        { -20, CKR_OBJECT_HANDLE_INVALID, "-20 NOT_FOUND" },
        { -23, CKR_USER_NOT_LOGGED_IN, "-23 CREDENTIALS_NOT_ESTABLISHED" },
        { -25, CKR_USER_NOT_LOGGED_IN, "-25 PARTITION_NOT_PROVISIONED" },
        { -26, CKR_KEY_HANDLE_INVALID, "-26 MASKED_KEY_DECODE_FAILED" },
        { -27, CKR_SIGNATURE_INVALID, "-27 ECC_VERIFY_FAILED" },
        { -29, CKR_USER_NOT_LOGGED_IN, "-29 SESSION_NEEDS_RENEGOTIATION" },
        { -30, CKR_FUNCTION_FAILED, "-30 PENDING_KEY_GENERATION" },
        { -31, CKR_OBJECT_HANDLE_INVALID, "-31 KEY_NOT_FOUND" },
        { -34, CKR_PIN_LOCKED, "-34 VAULT_APP_LIMIT_REACHED" },
        { -36, CKR_DEVICE_ERROR, "-36 DEVICE_NOT_READY" },
        { -37, CKR_ACTION_PROHIBITED, "-37 CANNOT_DELETE_INTERNAL_KEYS" },
        { -38, CKR_DEVICE_ERROR, "-38 UNSUPPORTED_API_REVISION" },
        { -39, CKR_DEVICE_ERROR, "-39 DEVICE_NOT_ACCESSIBLE" },
        { -40, CKR_OPERATION_NOT_INITIALIZED, "-40 INVALID_CONTEXT_STATE" },
        /* Real statuses that deliberately have no arm stay on the fallback. */
        { -18, CKR_FUNCTION_FAILED, "-18 CERT_CHAIN_CHANGED (no arm)" },
        { -21, CKR_FUNCTION_FAILED, "-21 IO_ABORTED (no arm)" },
        { -22, CKR_FUNCTION_FAILED, "-22 IO_ABORT_IN_PROGRESS (no arm)" },
        { -24, CKR_FUNCTION_FAILED, "-24 NONCE_MISMATCH (no arm)" },
        { -33, CKR_FUNCTION_FAILED, "-33 PARTITION_ALREADY_PROVISIONED stays the fallback" },
        { -35, CKR_FUNCTION_FAILED, "-35 RETRY_EXHAUSTED (no arm)" },
        { -41, CKR_FUNCTION_FAILED, "-41 BK3_ALREADY_INITIALIZED (no arm)" },
        { -999, CKR_FUNCTION_FAILED, "unknown negative -> FUNCTION_FAILED" },
        { 7, CKR_FUNCTION_FAILED, "unknown positive -> FUNCTION_FAILED" },
    };
    for (size_t i = 0; i < COUNT(map); i++)
    {
        CHECK(azihsm_pkcs11_ckr_from_azihsm(map[i].status) == map[i].rv, map[i].name);
    }
}

int main(void)
{
    test_tmpl_find();
    test_tmpl_bool();
    test_check_arguments();
    test_check_accept();
    test_check_unaligned();
    test_check_reject();
    test_check_order();
    test_build();
    test_status_maps();
    printf(
        g_fail ? "\naes_template_test: FAILED (%d checks)\n"
               : "\naes_template_test: all %d checks passed\n",
        g_checks
    );
    return g_fail;
}
