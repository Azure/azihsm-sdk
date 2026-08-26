// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Standalone unit test for the persistent object-store backend
 * (src/azihsm_pkcs11_objstore_file.c) driven directly through the azihsm_pkcs11_objstore vtable,
 * no device and no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src objstore_file_test.c \
 *       ../src/azihsm_pkcs11_objstore_file.c ../src/azihsm_pkcs11_objstore_mem.c \
 *       ../src/azihsm_pkcs11_store_io.c ../src/azihsm_pkcs11_store_record.c -o objstore_file_test
 * -lpthread
 *
 * Covers: token vs session routing, the private login gate, the v1
 * private-secret refusal, sensitive-attribute hiding, two-call sizing,
 * counter-first no-reuse of handles, destroy, and cross-process persistence
 * (a child process opens a fresh store on the same directory and reads the
 * token object the parent created, then observes the persisted counter).
 */

#include "azihsm_pkcs11_objstore.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_fail = 0;

#define CHECK(cond, msg)                                                                           \
    do                                                                                             \
    {                                                                                              \
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

#define TOKEN_FLAG (((CK_OBJECT_HANDLE)1) << (sizeof(CK_OBJECT_HANDLE) * 8 - 2))

static CK_BBOOL ck_true = CK_TRUE;
static CK_BBOOL ck_false = CK_FALSE;

/* Create a token (or session) DATA object with a label, optionally private,
 * optionally carrying a CKA_VALUE / CKA_SENSITIVE. Returns the op result. */
static CK_RV make_object(
    azihsm_pkcs11_objstore *s,
    CK_SLOT_ID slot,
    CK_BBOOL logged_in,
    CK_BBOOL token,
    CK_BBOOL priv,
    const char *label,
    const unsigned char *value,
    CK_ULONG value_len,
    CK_BBOOL sensitive,
    CK_OBJECT_HANDLE *out
)
{
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_ATTRIBUTE tmpl[6];
    CK_ULONG n = 0;
    tmpl[n++] = (CK_ATTRIBUTE){ CKA_CLASS, &cls, sizeof(cls) };
    tmpl[n++] = (CK_ATTRIBUTE){ CKA_TOKEN, token ? &ck_true : &ck_false, sizeof(CK_BBOOL) };
    tmpl[n++] = (CK_ATTRIBUTE){ CKA_PRIVATE, priv ? &ck_true : &ck_false, sizeof(CK_BBOOL) };
    tmpl[n++] = (CK_ATTRIBUTE){ CKA_LABEL, (void *)label, (CK_ULONG)strlen(label) };
    if (value != NULL)
    {
        tmpl[n++] = (CK_ATTRIBUTE){ CKA_VALUE, (void *)value, value_len };
    }
    if (sensitive)
    {
        tmpl[n++] = (CK_ATTRIBUTE){ CKA_SENSITIVE, &ck_true, sizeof(CK_BBOOL) };
    }
    return s->ops->create(s->ctx, slot, logged_in, tmpl, n, out);
}

/* Read CKA_LABEL of an object into buf; returns the op result. */
static CK_RV read_label(
    azihsm_pkcs11_objstore *s,
    CK_SLOT_ID slot,
    CK_BBOOL logged_in,
    CK_OBJECT_HANDLE h,
    char *buf,
    CK_ULONG buflen,
    CK_ULONG *outlen
)
{
    CK_ATTRIBUTE a = { CKA_LABEL, buf, buflen };
    CK_RV rv = s->ops->get_attr(s->ctx, slot, logged_in, h, &a, 1);
    *outlen = a.ulValueLen;
    return rv;
}

int main(void)
{
    char root[] = "/tmp/azihsm_pkcs11_objstore_test.XXXXXX";
    if (mkdtemp(root) == NULL)
    {
        perror("mkdtemp");
        return 1;
    }
    azihsm_pkcs11_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.store_dir, sizeof(cfg.store_dir), "%s", root);
    cfg.store_persist = true;

    azihsm_pkcs11_objstore s;
    CHECK(azihsm_pkcs11_objstore_file_create(&s, &cfg) == CKR_OK, "file store constructs");

    const CK_SLOT_ID SLOT = 0;
    char lbuf[64];
    CK_ULONG llen = 0;

    /* --- token public object: persisted, handle carries the token flag --- */
    CK_OBJECT_HANDLE tok = 0;
    CHECK(
        make_object(&s, SLOT, CK_FALSE, CK_TRUE, CK_FALSE, "tok-public", NULL, 0, CK_FALSE, &tok) ==
            CKR_OK,
        "create public token object"
    );
    CHECK((tok & TOKEN_FLAG) != 0, "token handle carries the token flag");
    CHECK(
        read_label(&s, SLOT, CK_FALSE, tok, lbuf, sizeof(lbuf), &llen) == CKR_OK && llen == 10 &&
            memcmp(lbuf, "tok-public", 10) == 0,
        "get_attr reads back the token object's label"
    );

    /* --- session object: delegated to mem, handle has no flag --- */
    CK_OBJECT_HANDLE sess = 0;
    CHECK(
        make_object(&s, SLOT, CK_FALSE, CK_FALSE, CK_FALSE, "sess-obj", NULL, 0, CK_FALSE, &sess) ==
            CKR_OK,
        "create session object"
    );
    CHECK((sess & TOKEN_FLAG) == 0, "session handle has no token flag");
    CHECK(
        read_label(&s, SLOT, CK_FALSE, sess, lbuf, sizeof(lbuf), &llen) == CKR_OK && llen == 8,
        "get_attr reads back the session object (via mem)"
    );

    /* --- private token object requires login; invisible when logged out --- */
    CK_OBJECT_HANDLE bad = 0;
    CHECK(
        make_object(&s, SLOT, CK_FALSE, CK_TRUE, CK_TRUE, "priv", NULL, 0, CK_FALSE, &bad) ==
            CKR_USER_NOT_LOGGED_IN,
        "private token create rejected when logged out"
    );
    CK_OBJECT_HANDLE priv = 0;
    CHECK(
        make_object(
            &s,
            SLOT,
            CK_TRUE,
            CK_TRUE,
            CK_TRUE,
            "priv-key-meta",
            NULL,
            0,
            CK_FALSE,
            &priv
        ) == CKR_OK,
        "private token create allowed when logged in"
    );
    CHECK(
        read_label(&s, SLOT, CK_FALSE, priv, lbuf, sizeof(lbuf), &llen) ==
            CKR_OBJECT_HANDLE_INVALID,
        "private object invisible (INVALID) when logged out"
    );
    CHECK(
        read_label(&s, SLOT, CK_TRUE, priv, lbuf, sizeof(lbuf), &llen) == CKR_OK,
        "private object visible when logged in"
    );

    /* --- v1 refusal: private object carrying a plaintext CKA_VALUE --- */
    unsigned char secret[] = { 1, 2, 3, 4 };
    CHECK(
        make_object(
            &s,
            SLOT,
            CK_TRUE,
            CK_TRUE,
            CK_TRUE,
            "priv-data",
            secret,
            sizeof(secret),
            CK_FALSE,
            &bad
        ) == CKR_TEMPLATE_INCONSISTENT,
        "private object with CKA_VALUE refused (non-device-protected secret)"
    );

    /* --- sensitive hiding on a public token object with a value --- */
    CK_OBJECT_HANDLE sens = 0;
    CHECK(
        make_object(
            &s,
            SLOT,
            CK_FALSE,
            CK_TRUE,
            CK_FALSE,
            "sens",
            secret,
            sizeof(secret),
            CK_TRUE,
            &sens
        ) == CKR_OK,
        "create public sensitive token object with a value"
    );
    CK_ATTRIBUTE vq = { CKA_VALUE, lbuf, sizeof(lbuf) };
    CHECK(
        s.ops->get_attr(s.ctx, SLOT, CK_FALSE, sens, &vq, 1) == CKR_ATTRIBUTE_SENSITIVE,
        "sensitive CKA_VALUE is hidden"
    );
    CK_ATTRIBUTE lq = { CKA_LABEL, NULL, 0 };
    CHECK(
        s.ops->get_attr(s.ctx, SLOT, CK_FALSE, sens, &lq, 1) == CKR_OK && lq.ulValueLen == 4,
        "two-call sizing on CKA_LABEL (pValue NULL -> length)"
    );

    /* --- counter-first no reuse: destroy then create gets a higher number --- */
    CK_OBJECT_HANDLE a = 0, b = 0;
    make_object(&s, SLOT, CK_FALSE, CK_TRUE, CK_FALSE, "a", NULL, 0, CK_FALSE, &a);
    CHECK(s.ops->destroy(s.ctx, SLOT, CK_FALSE, a) == CKR_OK, "destroy a token object");
    CHECK(
        read_label(&s, SLOT, CK_FALSE, a, lbuf, sizeof(lbuf), &llen) == CKR_OBJECT_HANDLE_INVALID,
        "destroyed object is gone (INVALID)"
    );
    make_object(&s, SLOT, CK_FALSE, CK_TRUE, CK_FALSE, "b", NULL, 0, CK_FALSE, &b);
    CHECK((b & ~TOKEN_FLAG) > (a & ~TOKEN_FLAG), "handle counter never reuses a number");

    CK_OBJECT_HANDLE last = b; /* highest handle so far */
    s.ops->teardown(s.ctx);

    /* --- cross-process persistence: a child opens a fresh store on the same
           directory and reads the token object created above, then confirms the
           counter persisted (new handle strictly greater than `last`). --- */
    pid_t pid = fork();
    if (pid == 0)
    {
        azihsm_pkcs11_objstore cs;
        int bad_child = 0;
        if (azihsm_pkcs11_objstore_file_create(&cs, &cfg) != CKR_OK)
        {
            _exit(10);
        }
        char cl[64];
        CK_ULONG clen = 0;
        if (read_label(&cs, SLOT, CK_FALSE, tok, cl, sizeof(cl), &clen) != CKR_OK || clen != 10 ||
            memcmp(cl, "tok-public", 10) != 0)
        {
            bad_child = 1; /* the parent's token object did not persist */
        }
        CK_OBJECT_HANDLE cnew = 0;
        if (make_object(
                &cs,
                SLOT,
                CK_FALSE,
                CK_TRUE,
                CK_FALSE,
                "child",
                NULL,
                0,
                CK_FALSE,
                &cnew
            ) != CKR_OK ||
            (cnew & ~TOKEN_FLAG) <= (last & ~TOKEN_FLAG))
        {
            bad_child = 1; /* counter did not persist across the fresh store */
        }
        cs.ops->teardown(cs.ctx);
        _exit(bad_child);
    }
    int st = 0;
    wait(&st);
    CHECK(
        WIFEXITED(st) && WEXITSTATUS(st) == 0,
        "child process reads the persisted token object and a persisted counter"
    );

    printf(g_fail ? "\nOBJSTORE_FILE FAIL\n" : "\nOBJSTORE_FILE OK\n");
    return g_fail;
}
