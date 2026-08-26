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
#include "azihsm_pkcs11_store_io.h"
#include "azihsm_pkcs11_store_record.h"

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

/* Run a full find (init -> drain -> final) and return the number of matches;
 * (CK_ULONG)-1 on an op error. */
static CK_ULONG find_count(
    azihsm_pkcs11_objstore *s,
    CK_SLOT_ID slot,
    CK_BBOOL logged_in,
    CK_ATTRIBUTE *tmpl,
    CK_ULONG n
)
{
    void *cur = NULL;
    if (s->ops->find_init(s->ctx, slot, logged_in, tmpl, n, &cur) != CKR_OK)
    {
        return (CK_ULONG)-1;
    }
    CK_ULONG total = 0;
    for (;;)
    {
        CK_OBJECT_HANDLE batch[16];
        CK_ULONG got = 0;
        if (s->ops->find(s->ctx, cur, batch, 16, &got) != CKR_OK || got == 0)
        {
            break;
        }
        total += got;
    }
    s->ops->find_final(s->ctx, cur);
    return total;
}

/* White-box check of a token object's masked-blob body: the seam has no body
 * getter yet (that arrives with the crypto ops), so read and decode the record
 * file directly and compare its body field. */
static int body_equals(
    const char *store_dir,
    CK_SLOT_ID slot,
    CK_OBJECT_HANDLE h,
    const unsigned char *exp,
    CK_ULONG exp_len
)
{
    char dir[4200];
    char name[32];
    snprintf(dir, sizeof(dir), "%s/slot-%lu", store_dir, (unsigned long)slot);
    snprintf(name, sizeof(name), "%lu.object", (unsigned long)(h & ~TOKEN_FLAG));
    unsigned char *buf = NULL;
    size_t len = 0;
    if (azihsm_pkcs11_store_read(dir, name, &buf, &len) != CKR_OK || buf == NULL)
    {
        return 0;
    }
    azihsm_pkcs11_rec_object o;
    int ok = 0;
    if (azihsm_pkcs11_record_decode(buf, len, &o) == CKR_OK)
    {
        ok = (o.body_len == exp_len) && (exp_len == 0 || memcmp(o.body, exp, exp_len) == 0);
        azihsm_pkcs11_record_free(&o);
    }
    free(buf);
    return ok;
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

    /* --- find: token + session, label filter, private gating, empty template.
           So far this slot has (visible): tok-public (token), sess-obj
           (session), priv-key-meta (token, private), sens (token). --- */
    CK_OBJECT_CLASS data_cls = CKO_DATA;
    CK_ATTRIBUTE by_class[] = { { CKA_CLASS, &data_cls, sizeof(data_cls) } };
    /* Logged out: the private object is excluded -> 3 (tok-public, sess, sens). */
    CHECK(
        find_count(&s, SLOT, CK_FALSE, by_class, 1) == 3,
        "find by class excludes the private object when logged out"
    );
    /* Logged in: the private object is included -> 4. */
    CHECK(
        find_count(&s, SLOT, CK_TRUE, by_class, 1) == 4,
        "find by class includes the private object when logged in"
    );
    /* Empty template returns all visible objects (same 3 when logged out). */
    CHECK(
        find_count(&s, SLOT, CK_FALSE, NULL, 0) == 3,
        "find with empty template returns all visible"
    );
    /* Label filter selects exactly one, and it is the on-disk token object. */
    CK_ATTRIBUTE by_label[] = { { CKA_LABEL, (void *)"tok-public", 10 } };
    void *cur = NULL;
    CK_OBJECT_HANDLE got1[4];
    CK_ULONG got1n = 0;
    s.ops->find_init(s.ctx, SLOT, CK_FALSE, by_label, 1, &cur);
    s.ops->find(s.ctx, cur, got1, 4, &got1n);
    s.ops->find_final(s.ctx, cur);
    CHECK(got1n == 1 && got1[0] == tok, "find by label returns exactly the matching token handle");
    /* A session object is found too (label filter on the session object). */
    CK_ATTRIBUTE by_slabel[] = { { CKA_LABEL, (void *)"sess-obj", 8 } };
    CHECK(find_count(&s, SLOT, CK_FALSE, by_slabel, 1) == 1, "find locates the session object");

    /* --- set_attr / set_key_body on a dedicated token object, destroyed at the
           end of this block so the persisted set stays as the later checks
           expect. --- */
    unsigned char xval[] = { 9, 8, 7 };
    CK_OBJECT_HANDLE x = 0;
    CHECK(
        make_object(
            &s,
            SLOT,
            CK_FALSE,
            CK_TRUE,
            CK_FALSE,
            "x-label",
            xval,
            sizeof(xval),
            CK_FALSE,
            &x
        ) == CKR_OK,
        "create public token object with a value"
    );

    unsigned char idbytes[] = { 0x01, 0x02 };
    CK_ATTRIBUTE chg[] = {
        { CKA_LABEL, (void *)"x-renamed", 9 },
        { CKA_ID, idbytes, sizeof(idbytes) },
    };
    CHECK(
        s.ops->set_attr(s.ctx, SLOT, CK_FALSE, x, chg, 2) == CKR_OK,
        "set_attr updates label + adds id"
    );
    CHECK(
        read_label(&s, SLOT, CK_FALSE, x, lbuf, sizeof(lbuf), &llen) == CKR_OK && llen == 9 &&
            memcmp(lbuf, "x-renamed", 9) == 0,
        "set_attr new label persisted"
    );
    CK_ATTRIBUTE idq = { CKA_ID, lbuf, sizeof(lbuf) };
    CHECK(
        s.ops->get_attr(s.ctx, SLOT, CK_FALSE, x, &idq, 1) == CKR_OK && idq.ulValueLen == 2 &&
            memcmp(lbuf, idbytes, 2) == 0,
        "set_attr added CKA_ID readable"
    );

    unsigned char body[] = { 0xAA, 0xBB, 0xCC, 0xDD };
    CHECK(
        s.ops->set_key_body(s.ctx, SLOT, CK_FALSE, x, body, sizeof(body)) == CKR_OK,
        "set_key_body attaches the masked blob"
    );
    CHECK(
        body_equals(cfg.store_dir, SLOT, x, body, sizeof(body)),
        "masked blob stored in the record body"
    );
    /* The body is a distinguished field, not an attribute: CKA_VALUE still
     * returns the object's own value, never the masked blob. */
    CK_ATTRIBUTE vq2 = { CKA_VALUE, lbuf, sizeof(lbuf) };
    CHECK(
        s.ops->get_attr(s.ctx, SLOT, CK_FALSE, x, &vq2, 1) == CKR_OK && vq2.ulValueLen == 3 &&
            memcmp(lbuf, xval, 3) == 0,
        "get_attr(CKA_VALUE) returns the value, not the masked blob"
    );
    /* A later set_attr must preserve the body (read-modify-rewrite). */
    CK_ATTRIBUTE chg2[] = { { CKA_LABEL, (void *)"x-again", 7 } };
    CHECK(s.ops->set_attr(s.ctx, SLOT, CK_FALSE, x, chg2, 1) == CKR_OK, "second set_attr ok");
    CHECK(
        body_equals(cfg.store_dir, SLOT, x, body, sizeof(body)),
        "set_attr preserved the masked blob body"
    );

    /* v1 refusal via set_attr: making an object that carries CKA_VALUE private. */
    CK_ATTRIBUTE mkpriv[] = { { CKA_PRIVATE, &ck_true, sizeof(CK_BBOOL) } };
    CHECK(
        s.ops->set_attr(s.ctx, SLOT, CK_TRUE, x, mkpriv, 1) == CKR_TEMPLATE_INCONSISTENT,
        "set_attr refuses to make a value-carrying object private"
    );
    CHECK(
        read_label(&s, SLOT, CK_FALSE, x, lbuf, sizeof(lbuf), &llen) == CKR_OK,
        "refused set_attr left the object unchanged (still public)"
    );

    CHECK(
        s.ops->destroy(s.ctx, SLOT, CK_FALSE, x) == CKR_OK,
        "cleanup: destroy the scratch object"
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
        /* A fresh find must see the persisted token objects (tok-public,
         * priv-key-meta, sens, b = 4 when logged in) and none of the parent's
         * ephemeral session objects. */
        if (find_count(&cs, SLOT, CK_TRUE, by_class, 1) != 4)
        {
            bad_child = 1;
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
