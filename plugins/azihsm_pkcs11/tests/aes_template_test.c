// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the device-free half of the AES slice: the AES key-generation
 * template logic and cipher mechanism policy (src/azihsm_pkcs11_template.c)
 * and the status translation they rely on (src/azihsm_pkcs11_status.c). No device, no libcrypto, no
 * module load — the functions are linked directly:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src aes_template_test.c \
 *       ../src/azihsm_pkcs11_template.c ../src/azihsm_pkcs11_status.c \
 *       -o aes_template_test && ./aes_template_test
 *
 * Covers the complete CK_RV matrix of azihsm_pkcs11_keygen_check_template
 * (every accepted key length, every rejected attribute and the code it earns,
 * non-AES key types, wrong value sizes, NULL values, duplicates, the length
 * ceiling, first-failure-wins ordering), the key-family selection between
 * plain AES, GCM (by CKA_ALLOWED_MECHANISMS) and XTS, the append-if-absent
 * rules of azihsm_pkcs11_keygen_build_template, the cipher mechanism table,
 * the allowed-mechanism gate, CK_GCM_PARAMS decoding, the GCM/XTS output
 * length plan, the multi-part length rules, and the status maps including the
 * padded-decrypt remap.
 */

#include "azihsm_pkcs11_status.h"
#include "azihsm_pkcs11_template.h"

#include <stdint.h>
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

/* Run the check for `mech` and return its CK_RV; outputs are optional. */
static CK_RV check_mech(
    CK_MECHANISM_TYPE mech,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    const azihsm_pkcs11_keygen_policy **policy
)
{
    const azihsm_pkcs11_keygen_policy *pol = NULL;
    CK_ULONG l = 0;
    CK_BBOOL t = CK_FALSE;
    CK_RV rv = azihsm_pkcs11_keygen_check_template(mech, tmpl, count, &pol, &l, &t);
    if (policy != NULL)
    {
        *policy = pol;
    }
    return rv;
}

/* Run the CKM_AES_KEY_GEN check on a template; outputs are optional. */
static CK_RV check(const CK_ATTRIBUTE *tmpl, CK_ULONG count, CK_ULONG *len, CK_BBOOL *token)
{
    const azihsm_pkcs11_keygen_policy *pol = NULL;
    CK_ULONG l = 0;
    CK_BBOOL t = CK_FALSE;
    CK_RV rv = azihsm_pkcs11_keygen_check_template(CKM_AES_KEY_GEN, tmpl, count, &pol, &l, &t);
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
    const azihsm_pkcs11_keygen_policy *pol = NULL;
    CK_ULONG len = 0;
    CK_BBOOL token = CK_FALSE;
    CHECK(
        azihsm_pkcs11_keygen_check_template(CKM_AES_KEY_GEN, one, 1, &pol, NULL, &token) ==
            CKR_ARGUMENTS_BAD,
        "NULL value_len -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_keygen_check_template(CKM_AES_KEY_GEN, one, 1, &pol, &len, NULL) ==
            CKR_ARGUMENTS_BAD,
        "NULL token -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_keygen_check_template(CKM_AES_KEY_GEN, one, 1, NULL, &len, &token) ==
            CKR_ARGUMENTS_BAD,
        "NULL policy -> CKR_ARGUMENTS_BAD"
    );
    pol = (const azihsm_pkcs11_keygen_policy *)one; /* any non-NULL value */
    CHECK(
        (azihsm_pkcs11_keygen_check_template(CKM_DES_KEY_GEN, one, 1, &pol, &len, &token) ==
         CKR_MECHANISM_INVALID) &&
            (pol == NULL),
        "a non-AES key-generation mechanism -> CKR_MECHANISM_INVALID, policy cleared"
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
        (azihsm_pkcs11_keygen_check_template(
             CKM_AES_KEY_GEN,
             big,
             KEYGEN_MAX_TEMPLATE_ATTRS + 1,
             &pol,
             &len,
             &token
         ) == CKR_ARGUMENTS_BAD) &&
            (len == 0) && (token == CK_FALSE) && (pol == NULL),
        "outputs are reset on the ceiling verdict too"
    );

    /* Outputs are reset before any verdict. */
    len = 99;
    token = CK_TRUE;
    CK_ATTRIBUTE only_label[] = { ATTR(CKA_LABEL, g_label) };
    CHECK(
        (azihsm_pkcs11_keygen_check_template(CKM_AES_KEY_GEN, only_label, 1, &pol, &len, &token) ==
         CKR_TEMPLATE_INCOMPLETE) &&
            (len == 0) && (token == CK_FALSE) && (pol == NULL),
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
    CK_MECHANISM_TYPE kgm = CKM_AES_KEY_GEN;
    CHECK(
        check_with((CK_ATTRIBUTE)ATTR(CKA_KEY_GEN_MECHANISM, kgm)) == CKR_ATTRIBUTE_READ_ONLY,
        "CKA_KEY_GEN_MECHANISM -> CKR_ATTRIBUTE_READ_ONLY (the token records it)"
    );

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

/* The policy a template selects, or NULL. */
static const azihsm_pkcs11_keygen_policy *policy_for(
    CK_MECHANISM_TYPE mech,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count
)
{
    const azihsm_pkcs11_keygen_policy *pol = NULL;
    return (check_mech(mech, tmpl, count, &pol) == CKR_OK) ? pol : NULL;
}

static void test_build(void)
{
    printf("== keygen_build_template ==\n");
    CK_ATTRIBUTE plain[] = { VALUE_LEN32 };
    const azihsm_pkcs11_keygen_policy *pol = policy_for(CKM_AES_KEY_GEN, plain, 1);
    CHECK(pol != NULL, "a plain template selects a policy");
    if (pol == NULL)
    {
        return;
    }
    azihsm_pkcs11_keygen_fill fill;
    memset(&fill, 0xA5, sizeof(fill)); /* every field must be written by the builder */
    CK_ATTRIBUTE full[KEYGEN_MAX_TEMPLATE_ATTRS + KEYGEN_APPENDED_ATTRS];
    CK_ULONG n = 0;

    CHECK(
        azihsm_pkcs11_keygen_build_template(pol, NULL, 0, NULL, full, &n) == CKR_ARGUMENTS_BAD,
        "NULL fill -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_keygen_build_template(pol, NULL, 0, &fill, NULL, &n) == CKR_ARGUMENTS_BAD,
        "NULL output array -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_keygen_build_template(pol, NULL, 0, &fill, full, NULL) == CKR_ARGUMENTS_BAD,
        "NULL count output -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_keygen_build_template(pol, NULL, 1, &fill, full, &n) == CKR_ARGUMENTS_BAD,
        "NULL template with count 1 -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_keygen_build_template(NULL, NULL, 0, &fill, full, &n) == CKR_ARGUMENTS_BAD,
        "NULL policy -> CKR_ARGUMENTS_BAD"
    );
    azihsm_pkcs11_keygen_policy bad = *pol;
    bad.mech_count = 0;
    CHECK(
        azihsm_pkcs11_keygen_build_template(&bad, NULL, 0, &fill, full, &n) == CKR_ARGUMENTS_BAD,
        "policy with no mechanisms -> CKR_ARGUMENTS_BAD"
    );
    bad.mech_count = KEYGEN_MAX_KEY_MECHS + 1;
    CHECK(
        azihsm_pkcs11_keygen_build_template(&bad, NULL, 0, &fill, full, &n) == CKR_ARGUMENTS_BAD,
        "policy above KEYGEN_MAX_KEY_MECHS -> CKR_ARGUMENTS_BAD"
    );

    /* Empty caller template: every default is appended. */
    CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
    CK_KEY_TYPE aes = CKK_AES;
    CK_BBOOL t = CK_TRUE, f = CK_FALSE;
    CHECK(
        (azihsm_pkcs11_keygen_build_template(pol, NULL, 0, &fill, full, &n) == CKR_OK) &&
            (n == KEYGEN_APPENDED_ATTRS),
        "empty template -> exactly KEYGEN_APPENDED_ATTRS attributes"
    );
    CHECK(
        built_has(full, n, CKA_CLASS, &secret, sizeof(secret)),
        "default CKA_CLASS=CKO_SECRET_KEY"
    );
    CHECK(built_has(full, n, CKA_KEY_TYPE, &aes, sizeof(aes)), "default CKA_KEY_TYPE=CKK_AES");
    CK_MECHANISM_TYPE cbc_family[] = { CKM_AES_CBC, CKM_AES_CBC_PAD };
    CHECK(
        built_has(full, n, CKA_ALLOWED_MECHANISMS, cbc_family, sizeof(cbc_family)),
        "default CKA_ALLOWED_MECHANISMS = the CBC family"
    );
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
    CK_MECHANISM_TYPE aes_kg = CKM_AES_KEY_GEN;
    CHECK(
        built_has(full, n, CKA_KEY_GEN_MECHANISM, &aes_kg, sizeof(aes_kg)),
        "CKA_KEY_GEN_MECHANISM=CKM_AES_KEY_GEN always"
    );

    /* Caller-supplied usage flags win over the defaults and are not duplicated. */
    CK_ATTRIBUTE usage[] = { VALUE_LEN32,
                             BOOL_ATTR(CKA_ENCRYPT, g_false),
                             BOOL_ATTR(CKA_DECRYPT, g_false),
                             ATTR(CKA_LABEL, g_label) };
    CHECK(
        (azihsm_pkcs11_keygen_build_template(pol, usage, COUNT(usage), &fill, full, &n) == CKR_OK
        ) && (n == COUNT(usage) + KEYGEN_APPENDED_ATTRS - 2),
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

    /* All seven defaults supplied: only the always-appended four are added. */
    CK_MECHANISM_TYPE only_raw[] = { CKM_AES_CBC };
    CK_ATTRIBUTE all7[] = { ATTR(CKA_CLASS, g_secret),
                            ATTR(CKA_KEY_TYPE, g_aes),
                            ATTR(CKA_ALLOWED_MECHANISMS, only_raw),
                            BOOL_ATTR(CKA_SENSITIVE, g_true),
                            BOOL_ATTR(CKA_EXTRACTABLE, g_false),
                            BOOL_ATTR(CKA_ENCRYPT, g_true),
                            BOOL_ATTR(CKA_DECRYPT, g_true),
                            VALUE_LEN32 };
    CHECK(
        (azihsm_pkcs11_keygen_build_template(pol, all7, COUNT(all7), &fill, full, &n) == CKR_OK) &&
            (n == COUNT(all7) + 4),
        "all defaults given -> only LOCAL/ALWAYS_SENSITIVE/NEVER_EXTRACTABLE/KEY_GEN_MECHANISM "
        "appended"
    );
    CHECK(
        built_has(full, n, CKA_ALLOWED_MECHANISMS, only_raw, sizeof(only_raw)),
        "the caller's narrower CKA_ALLOWED_MECHANISMS is stored, not the family"
    );
    CHECK(
        (full[n - 4].type == CKA_LOCAL) && (full[n - 3].type == CKA_ALWAYS_SENSITIVE) &&
            (full[n - 2].type == CKA_NEVER_EXTRACTABLE) &&
            (full[n - 1].type == CKA_KEY_GEN_MECHANISM),
        "the always-appended four come last, in order"
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

static void test_families(void)
{
    printf("== key families: AES / GCM (by CKA_ALLOWED_MECHANISMS) / XTS ==\n");
    CK_ULONG len64 = AES_XTS_KEY_BYTES;
    CK_KEY_TYPE xts_type = CKK_AES_XTS;
    CK_MECHANISM_TYPE gcm[] = { CKM_AES_GCM };
    CK_MECHANISM_TYPE cbc[] = { CKM_AES_CBC };
    CK_MECHANISM_TYPE cbc_both[] = { CKM_AES_CBC_PAD, CKM_AES_CBC };
    CK_MECHANISM_TYPE xts[] = { CKM_AES_XTS };
    CK_MECHANISM_TYPE mixed[] = { CKM_AES_GCM, CKM_AES_CBC };
    CK_MECHANISM_TYPE foreign[] = { CKM_SHA256 };
    const azihsm_pkcs11_keygen_policy *pol = NULL;

    CK_ATTRIBUTE plain[] = { VALUE_LEN32 };
    CHECK(
        (check_mech(CKM_AES_KEY_GEN, plain, 1, &pol) == CKR_OK) && (pol != NULL) &&
            (pol->kind == AZIHSM_PKCS11_KIND_AES) && (pol->key_type == CKK_AES),
        "CKM_AES_KEY_GEN without a list -> the plain AES family"
    );
    CK_ATTRIBUTE t_cbc[] = { VALUE_LEN32, ATTR(CKA_ALLOWED_MECHANISMS, cbc) };
    CHECK(
        (check_mech(CKM_AES_KEY_GEN, t_cbc, 2, &pol) == CKR_OK) && (pol != NULL) &&
            (pol->kind == AZIHSM_PKCS11_KIND_AES),
        "a list inside the CBC family -> plain AES"
    );
    CK_ATTRIBUTE t_cbc2[] = { VALUE_LEN32, ATTR(CKA_ALLOWED_MECHANISMS, cbc_both) };
    CHECK(
        (check_mech(CKM_AES_KEY_GEN, t_cbc2, 2, &pol) == CKR_OK) && (pol != NULL) &&
            (pol->kind == AZIHSM_PKCS11_KIND_AES),
        "both CBC mechanisms in any order -> plain AES"
    );
    CK_ATTRIBUTE t_gcm[] = { VALUE_LEN32, ATTR(CKA_ALLOWED_MECHANISMS, gcm) };
    CHECK(
        (check_mech(CKM_AES_KEY_GEN, t_gcm, 2, &pol) == CKR_OK) && (pol != NULL) &&
            (pol->kind == AZIHSM_PKCS11_KIND_AES_GCM) && (pol->key_type == CKK_AES),
        "{CKM_AES_GCM} -> the GCM family, still CKK_AES"
    );
    CK_ATTRIBUTE t_gcm_first[] = { ATTR(CKA_ALLOWED_MECHANISMS, gcm), VALUE_LEN32 };
    CHECK(
        (check_mech(CKM_AES_KEY_GEN, t_gcm_first, 2, &pol) == CKR_OK) && (pol != NULL) &&
            (pol->kind == AZIHSM_PKCS11_KIND_AES_GCM),
        "the family is found wherever the list sits in the template"
    );
    CK_ATTRIBUTE t_gcm16[] = { ATTR(CKA_VALUE_LEN, g_len16), ATTR(CKA_ALLOWED_MECHANISMS, gcm) };
    CHECK(
        check_mech(CKM_AES_KEY_GEN, t_gcm16, 2, &pol) == CKR_ATTRIBUTE_VALUE_INVALID,
        "a 128-bit GCM key -> CKR_ATTRIBUTE_VALUE_INVALID (the device takes 256 only)"
    );
    CK_ATTRIBUTE t_mixed[] = { VALUE_LEN32, ATTR(CKA_ALLOWED_MECHANISMS, mixed) };
    CHECK(
        check_mech(CKM_AES_KEY_GEN, t_mixed, 2, &pol) == CKR_TEMPLATE_INCONSISTENT,
        "GCM mixed with CBC -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE t_xts_list[] = { VALUE_LEN32, ATTR(CKA_ALLOWED_MECHANISMS, xts) };
    CHECK(
        check_mech(CKM_AES_KEY_GEN, t_xts_list, 2, &pol) == CKR_TEMPLATE_INCONSISTENT,
        "{CKM_AES_XTS} under CKM_AES_KEY_GEN -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE t_foreign[] = { VALUE_LEN32, ATTR(CKA_ALLOWED_MECHANISMS, foreign) };
    CHECK(
        check_mech(CKM_AES_KEY_GEN, t_foreign, 2, &pol) == CKR_TEMPLATE_INCONSISTENT,
        "a mechanism no AES key serves -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE t_64[] = { ATTR(CKA_VALUE_LEN, len64) };
    CHECK(
        check_mech(CKM_AES_KEY_GEN, t_64, 1, &pol) == CKR_ATTRIBUTE_VALUE_INVALID,
        "CKA_VALUE_LEN 64 on CKM_AES_KEY_GEN -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CK_ATTRIBUTE t_xts_type[] = { VALUE_LEN32, ATTR(CKA_KEY_TYPE, xts_type) };
    CHECK(
        check_mech(CKM_AES_KEY_GEN, t_xts_type, 2, &pol) == CKR_TEMPLATE_INCONSISTENT,
        "CKK_AES_XTS on CKM_AES_KEY_GEN -> CKR_TEMPLATE_INCONSISTENT"
    );

    /* CKM_AES_XTS_KEY_GEN */
    CHECK(
        (check_mech(CKM_AES_XTS_KEY_GEN, t_64, 1, &pol) == CKR_OK) && (pol != NULL) &&
            (pol->kind == AZIHSM_PKCS11_KIND_AES_XTS) && (pol->key_type == CKK_AES_XTS),
        "CKM_AES_XTS_KEY_GEN, 64 bytes -> the XTS family, CKK_AES_XTS"
    );
    CK_ATTRIBUTE t_xts_full[] = { ATTR(CKA_VALUE_LEN, len64),
                                  ATTR(CKA_KEY_TYPE, xts_type),
                                  ATTR(CKA_ALLOWED_MECHANISMS, xts) };
    CHECK(
        check_mech(CKM_AES_XTS_KEY_GEN, t_xts_full, 3, &pol) == CKR_OK,
        "XTS with its own key type and list -> CKR_OK"
    );
    CHECK(
        check_mech(CKM_AES_XTS_KEY_GEN, plain, 1, &pol) == CKR_ATTRIBUTE_VALUE_INVALID,
        "a 32-byte XTS key -> CKR_ATTRIBUTE_VALUE_INVALID (two 256-bit halves only)"
    );
    CK_ATTRIBUTE t_xts_as_aes[] = { ATTR(CKA_VALUE_LEN, len64), ATTR(CKA_KEY_TYPE, g_aes) };
    CHECK(
        check_mech(CKM_AES_XTS_KEY_GEN, t_xts_as_aes, 2, &pol) == CKR_TEMPLATE_INCONSISTENT,
        "CKK_AES on CKM_AES_XTS_KEY_GEN -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE t_xts_gcm[] = { ATTR(CKA_VALUE_LEN, len64), ATTR(CKA_ALLOWED_MECHANISMS, gcm) };
    CHECK(
        check_mech(CKM_AES_XTS_KEY_GEN, t_xts_gcm, 2, &pol) == CKR_TEMPLATE_INCONSISTENT,
        "{CKM_AES_GCM} under CKM_AES_XTS_KEY_GEN -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE t_none[] = { ATTR(CKA_LABEL, g_label) };
    CHECK(
        check_mech(CKM_AES_XTS_KEY_GEN, t_none, 1, &pol) == CKR_TEMPLATE_INCOMPLETE,
        "XTS without CKA_VALUE_LEN -> CKR_TEMPLATE_INCOMPLETE"
    );

    /* Malformed lists, including a misaligned one (UBSan build). */
    CK_ATTRIBUTE t_empty[] = { VALUE_LEN32, { CKA_ALLOWED_MECHANISMS, gcm, 0 } };
    CHECK(
        check_mech(CKM_AES_KEY_GEN, t_empty, 2, &pol) == CKR_ATTRIBUTE_VALUE_INVALID,
        "an empty list -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CK_ATTRIBUTE t_ragged[] = { VALUE_LEN32, { CKA_ALLOWED_MECHANISMS, gcm, sizeof(gcm) - 1 } };
    CHECK(
        check_mech(CKM_AES_KEY_GEN, t_ragged, 2, &pol) == CKR_ATTRIBUTE_VALUE_INVALID,
        "a list that is not a whole number of entries -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CK_MECHANISM_TYPE many[KEYGEN_MAX_ALLOWED_MECHS + 1];
    for (CK_ULONG i = 0; i < COUNT(many); i++)
    {
        many[i] = CKM_AES_CBC;
    }
    CK_ATTRIBUTE t_many[] = { VALUE_LEN32, ATTR(CKA_ALLOWED_MECHANISMS, many) };
    CHECK(
        check_mech(CKM_AES_KEY_GEN, t_many, 2, &pol) == CKR_ATTRIBUTE_VALUE_INVALID,
        "more than KEYGEN_MAX_ALLOWED_MECHS entries -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CK_BYTE raw[sizeof(CK_MECHANISM_TYPE) + 1];
    CK_MECHANISM_TYPE g = CKM_AES_GCM;
    memcpy(raw + 1, &g, sizeof(g));
    CK_ATTRIBUTE t_unaligned[] = { VALUE_LEN32, { CKA_ALLOWED_MECHANISMS, raw + 1, sizeof(g) } };
    CHECK(
        (check_mech(CKM_AES_KEY_GEN, t_unaligned, 2, &pol) == CKR_OK) && (pol != NULL) &&
            (pol->kind == AZIHSM_PKCS11_KIND_AES_GCM),
        "a misaligned list is decoded, not dereferenced"
    );

    /* What each family stores. */
    azihsm_pkcs11_keygen_fill fill;
    CK_ATTRIBUTE full[KEYGEN_MAX_TEMPLATE_ATTRS + KEYGEN_APPENDED_ATTRS];
    CK_ULONG n = 0;
    const azihsm_pkcs11_keygen_policy *gcm_pol = policy_for(CKM_AES_KEY_GEN, t_gcm, 2);
    CHECK(
        (gcm_pol != NULL) &&
            (azihsm_pkcs11_keygen_build_template(gcm_pol, t_gcm, 2, &fill, full, &n) == CKR_OK) &&
            built_has(full, n, CKA_ALLOWED_MECHANISMS, gcm, sizeof(gcm)) &&
            built_has(full, n, CKA_KEY_TYPE, &g_aes, sizeof(g_aes)),
        "a GCM key stores {CKM_AES_GCM} and CKK_AES"
    );
    const azihsm_pkcs11_keygen_policy *xts_pol = policy_for(CKM_AES_XTS_KEY_GEN, t_64, 1);
    CHECK(
        (xts_pol != NULL) &&
            (azihsm_pkcs11_keygen_build_template(xts_pol, t_64, 1, &fill, full, &n) == CKR_OK) &&
            built_has(full, n, CKA_ALLOWED_MECHANISMS, xts, sizeof(xts)) &&
            built_has(full, n, CKA_KEY_TYPE, &xts_type, sizeof(xts_type)),
        "an XTS key stores {CKM_AES_XTS} and CKK_AES_XTS"
    );
    CK_MECHANISM_TYPE xts_kg = CKM_AES_XTS_KEY_GEN;
    CHECK(
        built_has(full, n, CKA_KEY_GEN_MECHANISM, &xts_kg, sizeof(xts_kg)),
        "an XTS key records CKM_AES_XTS_KEY_GEN as its CKA_KEY_GEN_MECHANISM"
    );
}

static void test_cipher_mechs(void)
{
    printf("== cipher mechanism table and allowed-mechanism gate ==\n");
    const azihsm_pkcs11_cipher_mech *m = azihsm_pkcs11_cipher_mech_find(CKM_AES_CBC_PAD);
    CHECK(
        (m != NULL) && (m->kind == AZIHSM_PKCS11_KIND_AES) && (m->key_type == CKK_AES),
        "CKM_AES_CBC_PAD -> AES kind, CKK_AES"
    );
    m = azihsm_pkcs11_cipher_mech_find(CKM_AES_GCM);
    CHECK(
        (m != NULL) && (m->kind == AZIHSM_PKCS11_KIND_AES_GCM) && (m->key_type == CKK_AES),
        "CKM_AES_GCM -> GCM kind, CKK_AES"
    );
    m = azihsm_pkcs11_cipher_mech_find(CKM_AES_XTS);
    CHECK(
        (m != NULL) && (m->kind == AZIHSM_PKCS11_KIND_AES_XTS) && (m->key_type == CKK_AES_XTS),
        "CKM_AES_XTS -> XTS kind, CKK_AES_XTS"
    );
    CHECK(azihsm_pkcs11_cipher_mech_find(CKM_AES_ECB) == NULL, "CKM_AES_ECB is not run");
    CHECK(azihsm_pkcs11_cipher_mech_find(CKM_AES_CTR) == NULL, "CKM_AES_CTR is not run");

    /* The store's verdict on reading CKA_ALLOWED_MECHANISMS decides first. A
     * key without the attribute (the store says CKR_ATTRIBUTE_TYPE_INVALID)
     * predates it and serves the CBC family: keys stored before keys recorded
     * the list must keep working, and only for what they could do. */
    const CK_RV absent = CKR_ATTRIBUTE_TYPE_INVALID;
    CK_MECHANISM_TYPE gcm[] = { CKM_AES_GCM };
    CHECK(azihsm_pkcs11_key_mech_permitted(absent, gcm, 0, CKM_AES_CBC), "no list: CBC allowed");
    CHECK(
        azihsm_pkcs11_key_mech_permitted(absent, gcm, 0, CKM_AES_CBC_PAD),
        "no list: CBC-PAD allowed"
    );
    CHECK(!azihsm_pkcs11_key_mech_permitted(absent, gcm, 0, CKM_AES_GCM), "no list: GCM refused");
    CHECK(!azihsm_pkcs11_key_mech_permitted(absent, gcm, 0, CKM_AES_XTS), "no list: XTS refused");
    CHECK(
        !azihsm_pkcs11_key_mech_permitted(CKR_BUFFER_TOO_SMALL, gcm, sizeof(gcm), CKM_AES_GCM),
        "a list longer than the read buffer is refused (fail closed)"
    );
    CHECK(
        !azihsm_pkcs11_key_mech_permitted(CKR_ATTRIBUTE_SENSITIVE, gcm, sizeof(gcm), CKM_AES_GCM),
        "any other store verdict is refused (fail closed)"
    );
    CHECK(
        !azihsm_pkcs11_key_mech_permitted(CKR_OK, NULL, sizeof(gcm), CKM_AES_GCM),
        "CKR_OK with no value is refused"
    );
    CHECK(
        azihsm_pkcs11_key_mech_permitted(CKR_OK, gcm, sizeof(gcm), CKM_AES_GCM),
        "{GCM}: GCM allowed"
    );
    CHECK(
        !azihsm_pkcs11_key_mech_permitted(CKR_OK, gcm, sizeof(gcm), CKM_AES_CBC),
        "{GCM}: CBC refused"
    );
    CHECK(
        !azihsm_pkcs11_key_mech_permitted(CKR_OK, gcm, 0, CKM_AES_GCM),
        "an empty list allows nothing"
    );
    CHECK(
        !azihsm_pkcs11_key_mech_permitted(CKR_OK, gcm, sizeof(gcm) - 1, CKM_AES_GCM),
        "a ragged stored list allows nothing"
    );
    CK_BYTE raw[sizeof(CK_MECHANISM_TYPE) + 1];
    CK_MECHANISM_TYPE x = CKM_AES_XTS;
    memcpy(raw + 1, &x, sizeof(x));
    CHECK(
        azihsm_pkcs11_key_mech_permitted(CKR_OK, raw + 1, sizeof(x), CKM_AES_XTS),
        "a misaligned stored list is decoded, not dereferenced"
    );

    /* The XTS tweak: 16 bytes, anything but the 128-bit maximum. */
    CK_BYTE tweak[AES_XTS_TWEAK_LEN];
    memset(tweak, 0, sizeof(tweak));
    CHECK(azihsm_pkcs11_xts_tweak_check(tweak, sizeof(tweak)) == CKR_OK, "a zero tweak -> CKR_OK");
    memset(tweak, 0xFF, sizeof(tweak));
    CHECK(
        azihsm_pkcs11_xts_tweak_check(tweak, sizeof(tweak)) == CKR_MECHANISM_PARAM_INVALID,
        "all-0xFF tweak (cannot be advanced) -> CKR_MECHANISM_PARAM_INVALID"
    );
    for (size_t i = 0; i < AES_XTS_TWEAK_LEN; i++)
    {
        memset(tweak, 0xFF, sizeof(tweak));
        tweak[i] = 0xFE;
        char msg[80];
        snprintf(msg, sizeof(msg), "tweak byte %lu = 0xFE -> CKR_OK", (unsigned long)i);
        CHECK(azihsm_pkcs11_xts_tweak_check(tweak, sizeof(tweak)) == CKR_OK, msg);
    }
    CHECK(
        azihsm_pkcs11_xts_tweak_check(tweak, sizeof(tweak) - 1) == CKR_MECHANISM_PARAM_INVALID,
        "a 15-byte tweak -> CKR_MECHANISM_PARAM_INVALID"
    );
    CHECK(
        azihsm_pkcs11_xts_tweak_check(NULL, AES_XTS_TWEAK_LEN) == CKR_MECHANISM_PARAM_INVALID,
        "a NULL tweak -> CKR_MECHANISM_PARAM_INVALID"
    );
}

static void test_gcm_params(void)
{
    printf("== CK_GCM_PARAMS decoding ==\n");
    CK_BYTE iv[AES_GCM_IV_LEN] = { 0 };
    CK_BYTE aad[5] = { 1, 2, 3, 4, 5 };
    CK_GCM_PARAMS good = { iv,  AES_GCM_IV_LEN, AES_GCM_IV_LEN * 8,
                           aad, sizeof(aad),    AES_GCM_TAG_LEN * 8 };
    CK_GCM_PARAMS out;
    CHECK(
        (azihsm_pkcs11_gcm_params_check(&good, sizeof(good), &out) == CKR_OK) && (out.pIv == iv) &&
            (out.pAAD == aad) && (out.ulAADLen == sizeof(aad)),
        "12-byte IV, AAD, 128-bit tag -> CKR_OK, decoded"
    );
    CHECK(
        azihsm_pkcs11_gcm_params_check(&good, sizeof(good), NULL) == CKR_ARGUMENTS_BAD,
        "NULL out -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        azihsm_pkcs11_gcm_params_check(NULL, sizeof(good), &out) == CKR_MECHANISM_PARAM_INVALID,
        "NULL block -> CKR_MECHANISM_PARAM_INVALID"
    );
    CHECK(
        azihsm_pkcs11_gcm_params_check(&good, sizeof(good) - 1, &out) ==
            CKR_MECHANISM_PARAM_INVALID,
        "wrong block size -> CKR_MECHANISM_PARAM_INVALID"
    );
    CK_GCM_PARAMS p = good;
    p.pAAD = NULL;
    p.ulAADLen = 0;
    CHECK(azihsm_pkcs11_gcm_params_check(&p, sizeof(p), &out) == CKR_OK, "no AAD -> CKR_OK");
    p = good;
    p.ulIvBits = 0;
    CHECK(azihsm_pkcs11_gcm_params_check(&p, sizeof(p), &out) == CKR_OK, "ulIvBits is not read");
    p = good;
    p.pIv = NULL;
    CHECK(
        azihsm_pkcs11_gcm_params_check(&p, sizeof(p), &out) == CKR_MECHANISM_PARAM_INVALID,
        "NULL IV -> CKR_MECHANISM_PARAM_INVALID"
    );
    static const CK_ULONG bad_iv_lens[] = { 0, 4, 8, 11, 13, 16 };
    for (size_t i = 0; i < COUNT(bad_iv_lens); i++)
    {
        p = good;
        p.ulIvLen = bad_iv_lens[i];
        char msg[80];
        snprintf(
            msg,
            sizeof(msg),
            "ulIvLen %lu -> CKR_MECHANISM_PARAM_INVALID",
            (unsigned long)bad_iv_lens[i]
        );
        CHECK(
            azihsm_pkcs11_gcm_params_check(&p, sizeof(p), &out) == CKR_MECHANISM_PARAM_INVALID,
            msg
        );
    }
    static const CK_ULONG bad_bits[] = { 0, 32, 64, 96, 104, 112, 120, 127, 129, 256 };
    for (size_t i = 0; i < COUNT(bad_bits); i++)
    {
        p = good;
        p.ulTagBits = bad_bits[i];
        char msg[80];
        snprintf(
            msg,
            sizeof(msg),
            "ulTagBits %lu -> CKR_MECHANISM_PARAM_INVALID",
            (unsigned long)bad_bits[i]
        );
        CHECK(
            azihsm_pkcs11_gcm_params_check(&p, sizeof(p), &out) == CKR_MECHANISM_PARAM_INVALID,
            msg
        );
    }
    p = good;
    p.pAAD = NULL;
    CHECK(
        azihsm_pkcs11_gcm_params_check(&p, sizeof(p), &out) == CKR_MECHANISM_PARAM_INVALID,
        "NULL AAD with a length -> CKR_MECHANISM_PARAM_INVALID"
    );
    if (sizeof(CK_ULONG) > sizeof(uint32_t))
    {
        p = good;
        p.ulAADLen = (CK_ULONG)UINT32_MAX + 1;
        CHECK(
            azihsm_pkcs11_gcm_params_check(&p, sizeof(p), &out) == CKR_MECHANISM_PARAM_INVALID,
            "AAD beyond 32 bits -> CKR_MECHANISM_PARAM_INVALID"
        );
    }
    /* A parameter block at an odd address (UBSan build). */
    CK_BYTE raw[sizeof(CK_GCM_PARAMS) + 1];
    memcpy(raw + 1, &good, sizeof(good));
    CHECK(
        (azihsm_pkcs11_gcm_params_check(raw + 1, sizeof(good), &out) == CKR_OK) && (out.pIv == iv),
        "a misaligned parameter block is decoded, not dereferenced"
    );
}

static void test_out_len(void)
{
    printf("== GCM / XTS output length plan ==\n");
    CK_ULONG n = 99;
    CHECK(
        azihsm_pkcs11_cipher_out_len(CKM_AES_GCM, true, 0, NULL) == CKR_ARGUMENTS_BAD,
        "NULL out_len -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        (azihsm_pkcs11_cipher_out_len(CKM_AES_GCM, true, 0, &n) == CKR_OK) &&
            (n == AES_GCM_TAG_LEN),
        "GCM encrypt of nothing -> just the tag"
    );
    CHECK(
        (azihsm_pkcs11_cipher_out_len(CKM_AES_GCM, true, 37, &n) == CKR_OK) &&
            (n == 37 + AES_GCM_TAG_LEN),
        "GCM encrypt appends the tag"
    );
    CHECK(
        azihsm_pkcs11_cipher_out_len(CKM_AES_GCM, true, (CK_ULONG)UINT32_MAX, &n) ==
            CKR_DATA_LEN_RANGE,
        "GCM encrypt whose output would pass 32 bits -> CKR_DATA_LEN_RANGE"
    );
    CHECK(
        (azihsm_pkcs11_cipher_out_len(CKM_AES_GCM, false, AES_GCM_TAG_LEN, &n) == CKR_OK) &&
            (n == 0),
        "GCM decrypt of a bare tag -> no plaintext"
    );
    CHECK(
        (azihsm_pkcs11_cipher_out_len(CKM_AES_GCM, false, 37 + AES_GCM_TAG_LEN, &n) == CKR_OK) &&
            (n == 37),
        "GCM decrypt drops the tag"
    );
    if (sizeof(CK_ULONG) > sizeof(uint32_t))
    {
        CHECK(
            azihsm_pkcs11_cipher_out_len(CKM_AES_GCM, false, (CK_ULONG)UINT32_MAX + 1, &n) ==
                CKR_ENCRYPTED_DATA_LEN_RANGE,
            "GCM decrypt beyond 32 bits -> CKR_ENCRYPTED_DATA_LEN_RANGE"
        );
    }
    n = 99;
    CHECK(
        (azihsm_pkcs11_cipher_out_len(CKM_AES_GCM, false, AES_GCM_TAG_LEN - 1, &n) ==
         CKR_ENCRYPTED_DATA_LEN_RANGE) &&
            (n == 0),
        "GCM decrypt shorter than a tag -> CKR_ENCRYPTED_DATA_LEN_RANGE, length cleared"
    );
    CHECK(
        (azihsm_pkcs11_cipher_out_len(CKM_AES_XTS, true, AES_BLOCK_LEN, &n) == CKR_OK) &&
            (n == AES_BLOCK_LEN),
        "XTS one block"
    );
    CHECK(
        (azihsm_pkcs11_cipher_out_len(CKM_AES_XTS, false, AES_XTS_MAX_DATA_LEN, &n) == CKR_OK) &&
            (n == AES_XTS_MAX_DATA_LEN),
        "XTS at the data-unit ceiling"
    );
    static const CK_ULONG bad_xts_lens[] = {
        0, 1, 15, 17, 31, AES_XTS_MAX_DATA_LEN + AES_BLOCK_LEN, AES_XTS_MAX_DATA_LEN - 1
    };
    for (size_t i = 0; i < COUNT(bad_xts_lens); i++)
    {
        char msg[80];
        snprintf(
            msg,
            sizeof(msg),
            "XTS encrypt of %lu bytes -> CKR_DATA_LEN_RANGE",
            (unsigned long)bad_xts_lens[i]
        );
        CHECK(
            azihsm_pkcs11_cipher_out_len(CKM_AES_XTS, true, bad_xts_lens[i], &n) ==
                CKR_DATA_LEN_RANGE,
            msg
        );
        snprintf(
            msg,
            sizeof(msg),
            "XTS decrypt of %lu bytes -> CKR_ENCRYPTED_DATA_LEN_RANGE",
            (unsigned long)bad_xts_lens[i]
        );
        CHECK(
            azihsm_pkcs11_cipher_out_len(CKM_AES_XTS, false, bad_xts_lens[i], &n) ==
                CKR_ENCRYPTED_DATA_LEN_RANGE,
            msg
        );
    }

    /* GCM: the padded AAD and the data travel as one 32-bit-sized buffer. */
    CHECK(azihsm_pkcs11_gcm_fits(0, 0), "GCM: no AAD, no data fits");
    CHECK(
        azihsm_pkcs11_gcm_fits(0, (CK_ULONG)UINT32_MAX),
        "GCM: no AAD and a 32-bit data length fits"
    );
    CHECK(
        azihsm_pkcs11_gcm_fits(AES_GCM_AAD_ALIGN, (CK_ULONG)UINT32_MAX - AES_GCM_AAD_ALIGN),
        "GCM: aligned AAD plus data exactly at the 32-bit limit fits"
    );
    CHECK(
        !azihsm_pkcs11_gcm_fits(1, (CK_ULONG)UINT32_MAX - 1),
        "GCM: one AAD byte pads to a full block, which then overflows 32 bits"
    );
    CHECK(
        !azihsm_pkcs11_gcm_fits(AES_GCM_AAD_ALIGN, (CK_ULONG)UINT32_MAX - AES_GCM_AAD_ALIGN + 1),
        "GCM: one byte over the 32-bit limit does not fit"
    );
    CHECK(
        azihsm_pkcs11_cipher_out_len(CKM_AES_CBC, true, 16, &n) == CKR_MECHANISM_INVALID,
        "CBC lengths come from the device -> CKR_MECHANISM_INVALID here"
    );
}

static void test_multipart(void)
{
    printf("== multi-part length rules ==\n");
    typedef struct
    {
        bool encrypt;
        bool pad;
        CK_ULONG fed_mod;
        bool fed_any;
        CK_RV rv;
        bool run;
        const char *why;
    } final_case;
    static const final_case cases[] = {
        { true, false, 0, false, CKR_OK, false, "CBC encrypt of nothing: empty, no SDK call" },
        { true, false, 0, true, CKR_OK, true, "CBC encrypt of whole blocks" },
        { true, false, 5, true, CKR_DATA_LEN_RANGE, false, "CBC encrypt of a partial block" },
        { true, true, 0, false, CKR_OK, true, "CBC-PAD encrypt of nothing: one padding block" },
        { true, true, 0, true, CKR_OK, true, "CBC-PAD encrypt of whole blocks" },
        { true, true, 7, true, CKR_OK, true, "CBC-PAD encrypt of a partial block" },
        { false, false, 0, false, CKR_OK, false, "CBC decrypt of nothing: empty, no SDK call" },
        { false, false, 0, true, CKR_OK, true, "CBC decrypt of whole blocks" },
        { false,
          false,
          3,
          true,
          CKR_ENCRYPTED_DATA_LEN_RANGE,
          false,
          "CBC decrypt, partial block" },
        { false,
          true,
          0,
          false,
          CKR_ENCRYPTED_DATA_LEN_RANGE,
          false,
          "CBC-PAD decrypt of nothing" },
        { false, true, 0, true, CKR_OK, true, "CBC-PAD decrypt of whole blocks" },
        { false,
          true,
          AES_BLOCK_LEN - 1,
          true,
          CKR_ENCRYPTED_DATA_LEN_RANGE,
          false,
          "CBC-PAD decrypt, partial block" },
    };
    for (size_t i = 0; i < COUNT(cases); i++)
    {
        const final_case *c = &cases[i];
        bool run = !c->run; /* must be overwritten on every path */
        CK_RV rv = azihsm_pkcs11_cbc_final_check(c->encrypt, c->pad, c->fed_mod, c->fed_any, &run);
        CHECK((rv == c->rv) && (run == c->run), c->why);
    }
    CHECK(
        azihsm_pkcs11_cbc_final_check(true, false, 0, true, NULL) == CKR_ARGUMENTS_BAD,
        "NULL run_final -> CKR_ARGUMENTS_BAD"
    );

    /* GCM / XTS buffering: the one-shot path's upper limits, no lower ones. */
    CHECK(azihsm_pkcs11_multipart_fits(CKM_AES_GCM, true, 0, 0), "GCM encrypt: nothing yet");
    CHECK(
        azihsm_pkcs11_multipart_fits(CKM_AES_GCM, true, 0, (CK_ULONG)UINT32_MAX - AES_GCM_TAG_LEN),
        "GCM encrypt: the most whose tagged output stays within 32 bits"
    );
    CHECK(
        !azihsm_pkcs11_multipart_fits(
            CKM_AES_GCM,
            true,
            0,
            (CK_ULONG)UINT32_MAX - AES_GCM_TAG_LEN + 1
        ),
        "GCM encrypt: one byte more does not fit"
    );
    CHECK(
        azihsm_pkcs11_multipart_fits(
            CKM_AES_GCM,
            true,
            1,
            (CK_ULONG)UINT32_MAX - AES_GCM_AAD_ALIGN
        ),
        "GCM encrypt: padded AAD plus data at the 32-bit limit"
    );
    CHECK(
        !azihsm_pkcs11_multipart_fits(
            CKM_AES_GCM,
            true,
            1,
            (CK_ULONG)UINT32_MAX - AES_GCM_AAD_ALIGN + 1
        ),
        "GCM encrypt: padded AAD plus data one byte over"
    );
    CHECK(
        azihsm_pkcs11_multipart_fits(CKM_AES_GCM, false, (CK_ULONG)UINT32_MAX, AES_GCM_TAG_LEN - 1),
        "GCM decrypt: short of a tag there is no ciphertext to measure yet"
    );
    CHECK(
        azihsm_pkcs11_multipart_fits(CKM_AES_GCM, false, 0, AES_GCM_TAG_LEN - 1),
        "GCM decrypt: short of a tag, the tag is not subtracted"
    );
    CHECK(
        azihsm_pkcs11_multipart_fits(CKM_AES_GCM, false, 0, (CK_ULONG)UINT32_MAX),
        "GCM decrypt: a 32-bit input with no AAD"
    );
    CHECK(
        !azihsm_pkcs11_multipart_fits(CKM_AES_GCM, false, AES_GCM_AAD_ALIGN, (CK_ULONG)UINT32_MAX),
        "GCM decrypt: padded AAD plus ciphertext over 32 bits"
    );
    if (sizeof(CK_ULONG) > sizeof(uint32_t))
    {
        CHECK(
            !azihsm_pkcs11_multipart_fits(CKM_AES_GCM, false, 0, (CK_ULONG)UINT32_MAX + 1),
            "GCM decrypt: input beyond 32 bits"
        );
    }
    CHECK(azihsm_pkcs11_multipart_fits(CKM_AES_XTS, true, 0, 0), "XTS: nothing yet");
    CHECK(
        azihsm_pkcs11_multipart_fits(CKM_AES_XTS, false, 0, AES_XTS_MAX_DATA_LEN),
        "XTS: the data-unit ceiling"
    );
    CHECK(
        !azihsm_pkcs11_multipart_fits(CKM_AES_XTS, true, 0, AES_XTS_MAX_DATA_LEN + 1),
        "XTS: past the data-unit ceiling"
    );
    CHECK(
        !azihsm_pkcs11_multipart_fits(CKM_AES_CBC, true, 0, AES_BLOCK_LEN),
        "CBC does not buffer here -> false"
    );
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
    test_families();
    test_cipher_mechs();
    test_gcm_params();
    test_out_len();
    test_multipart();
    test_status_maps();
    printf(
        g_fail ? "\naes_template_test: FAILED (%d checks)\n"
               : "\naes_template_test: all %d checks passed\n",
        g_checks
    );
    return g_fail;
}
