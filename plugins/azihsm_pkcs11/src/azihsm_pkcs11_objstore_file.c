// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Persistent file-backed object-store backend for the seam in azihsm_pkcs11_objstore.h.
 *
 * Token objects (CKA_TOKEN == TRUE) are written through to disk so they survive
 * a process restart and are visible to other processes sharing the store
 * directory; each object is one <handle>.object record (azihsm_pkcs11_store_record.c) in a
 * per-token directory "<store_dir>/slot-<id>/", alongside token.meta (the
 * persistent monotonic handle counter) and a .lock file. Session objects
 * (CKA_TOKEN == FALSE) are ephemeral and are delegated verbatim to an embedded
 * in-memory backend (azihsm_pkcs11_objstore_mem.c) — no need to reimplement that logic.
 *
 * A handle carries which store owns it in its top-but-one bit
 * (P11_FILE_TOKEN_FLAG): set for on-disk token objects (the low bits are the
 * counter value / filename), clear for the embedded backend's session handles
 * (small counters). Every op routes on that bit.
 *
 * Token isolation is structural: an op only ever touches the caller slot's own
 * directory, so an object created in another slot is simply not found. The
 * CKA_PRIVATE login gate and sensitive-attribute hiding are enforced here
 * exactly as the in-memory backend does, because the device authenticates the
 * partition, not individual objects.
 *
 * Like the in-memory backend this file links no libcrypto (durability rests on
 * the filesystem, not host cryptography) so the no-device smoke build compiles.
 * It does no internal thread locking — the framework holds the module lock
 * across every call — but takes the cross-process flock for each disk mutation
 * and read.
 */

#include "azihsm_pkcs11_objstore.h"
#include "azihsm_pkcs11_store_io.h"
#include "azihsm_pkcs11_store_record.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Top-but-one bit of a CK_OBJECT_HANDLE marks an on-disk token object; the
 * embedded in-memory backend's session handles are small counters that never
 * reach it. (Top-but-one rather than the top bit to steer clear of all-ones
 * error sentinels.)
 */
#define P11_FILE_TOKEN_FLAG (((CK_OBJECT_HANDLE)1) << (sizeof(CK_OBJECT_HANDLE) * 8 - 2))

/* store_dir + "/slot-" + up to 20 decimal digits + NUL. */
#define P11_FILE_TOKEN_DIR_LEN (AZIHSM_PKCS11_STORE_DIR_LEN + 32)
#define P11_FILE_OBJ_NAME_LEN 32

typedef struct
{
    char store_dir[AZIHSM_PKCS11_STORE_DIR_LEN];
    azihsm_pkcs11_objstore mem; /* embedded backend for session (CKA_TOKEN == FALSE) objects */
} file_store;

/* ---- template / record attribute helpers ------------------------------- */

static const CK_ATTRIBUTE *tmpl_find(const CK_ATTRIBUTE *tmpl, CK_ULONG count, CK_ATTRIBUTE_TYPE t)
{
    for (CK_ULONG i = 0; i < count; i++)
    {
        if (tmpl[i].type == t)
        {
            return &tmpl[i];
        }
    }
    return NULL;
}

static CK_BBOOL tmpl_bool(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ATTRIBUTE_TYPE t,
    CK_BBOOL dflt
)
{
    const CK_ATTRIBUTE *a = tmpl_find(tmpl, count, t);
    if (a == NULL || a->ulValueLen == 0 || a->pValue == NULL)
    {
        return dflt;
    }
    return ((const CK_BYTE *)a->pValue)[0] != 0 ? CK_TRUE : CK_FALSE;
}

static const azihsm_pkcs11_rec_attr *rec_find(
    const azihsm_pkcs11_rec_object *o,
    CK_ATTRIBUTE_TYPE t
)
{
    for (CK_ULONG i = 0; i < o->attr_count; i++)
    {
        if (o->attrs[i].type == t)
        {
            return &o->attrs[i];
        }
    }
    return NULL;
}

static CK_BBOOL rec_bool(const azihsm_pkcs11_rec_object *o, CK_ATTRIBUTE_TYPE t, CK_BBOOL dflt)
{
    const azihsm_pkcs11_rec_attr *a = rec_find(o, t);
    if (a == NULL || a->len == 0 || a->value == NULL)
    {
        return dflt;
    }
    return a->value[0] != 0 ? CK_TRUE : CK_FALSE;
}

/* Set (replace or append) one attribute on a decoded record. The new value is
 * staged before the object is touched, so a failed allocation leaves the record
 * unchanged rather than half-mutated (mirrors the in-memory backend). */
static CK_RV rec_set_attr(
    azihsm_pkcs11_rec_object *o,
    CK_ATTRIBUTE_TYPE type,
    const unsigned char *val,
    CK_ULONG len
)
{
    unsigned char *nv = NULL;
    if (len > 0)
    {
        nv = (unsigned char *)malloc(len);
        if (nv == NULL)
        {
            return CKR_HOST_MEMORY;
        }
        memcpy(nv, val, len);
    }
    azihsm_pkcs11_rec_attr *a = NULL;
    for (CK_ULONG i = 0; i < o->attr_count; i++)
    {
        if (o->attrs[i].type == type)
        {
            a = &o->attrs[i];
            break;
        }
    }
    if (a == NULL)
    {
        azihsm_pkcs11_rec_attr *grown = (azihsm_pkcs11_rec_attr *)
            realloc(o->attrs, (o->attr_count + 1) * sizeof(azihsm_pkcs11_rec_attr));
        if (grown == NULL)
        {
            free(nv);
            return CKR_HOST_MEMORY;
        }
        o->attrs = grown;
        a = &o->attrs[o->attr_count++];
        memset(a, 0, sizeof(*a));
        a->type = type;
    }
    if (a->value != NULL)
    {
        memset(a->value, 0, a->len);
        free(a->value);
    }
    a->value = nv;
    a->len = len;
    return CKR_OK;
}

/* ---- path helpers ------------------------------------------------------- */

static CK_RV token_dir(const file_store *st, CK_SLOT_ID slot, char *out, size_t outlen)
{
    int written = snprintf(out, outlen, "%s/slot-%lu", st->store_dir, (unsigned long)slot);
    if (written < 0 || (size_t)written >= outlen)
    {
        return CKR_FUNCTION_FAILED;
    }
    return CKR_OK;
}

static void object_name(CK_ULONG num, char *out, size_t outlen)
{
    (void)snprintf(out, outlen, "%lu.object", (unsigned long)num);
}

/* ---- disk-backed token object operations -------------------------------- */

/* Encode `o` and atomically (re)write it as <num>.object in `dir`. The encoded
 * buffer is wiped after the write since it may hold attribute bytes. */
static CK_RV rewrite_token_object(const char *dir, CK_ULONG num, const azihsm_pkcs11_rec_object *o)
{
    unsigned char *buf = NULL;
    size_t blen = 0;
    CK_RV rv = azihsm_pkcs11_record_encode(o, NULL, &blen);
    if (rv == CKR_OK)
    {
        buf = (unsigned char *)malloc(blen ? blen : 1);
        if (buf == NULL)
        {
            rv = CKR_HOST_MEMORY;
        }
    }
    if (rv == CKR_OK)
    {
        rv = azihsm_pkcs11_record_encode(o, buf, &blen);
    }
    if (rv == CKR_OK)
    {
        char name[P11_FILE_OBJ_NAME_LEN];
        object_name(num, name, sizeof(name));
        rv = azihsm_pkcs11_store_write(dir, name, buf, blen);
    }
    if (buf != NULL)
    {
        memset(buf, 0, blen);
        free(buf);
    }
    return rv;
}

static CK_RV create_token_object(
    file_store *st,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_OBJECT_HANDLE *out
)
{
    CK_BBOOL is_private = tmpl_bool(tmpl, count, CKA_PRIVATE, CK_FALSE);
    if (is_private && !user_logged_in)
    {
        return CKR_USER_NOT_LOGGED_IN;
    }
    /*
     * v1 refuses to persist a private object whose secret is not the
     * device-encrypted masked blob: a private CKA_VALUE (e.g. a CKO_DATA app
     * secret) or a plaintext CKA_PRIVATE_EXPONENT would sit in cleartext at rest
     * (the device protects only the masked key body). At-rest encryption of such
     * material is a later phase; until then, refuse rather than leak.
     */
    if (is_private && (tmpl_find(tmpl, count, CKA_VALUE) != NULL ||
                       tmpl_find(tmpl, count, CKA_PRIVATE_EXPONENT) != NULL))
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }

    char dir[P11_FILE_TOKEN_DIR_LEN];
    CK_RV rv = token_dir(st, slot, dir, sizeof(dir));
    if (rv != CKR_OK)
    {
        return rv;
    }
    rv = azihsm_pkcs11_store_dir_ensure(dir);
    if (rv != CKR_OK)
    {
        return rv;
    }

    int lock_fd = -1;
    rv = azihsm_pkcs11_store_lock(dir, &lock_fd);
    if (rv != CKR_OK)
    {
        return rv;
    }

    /* Read the persistent counter (absent -> start at 1; 0 stays invalid). */
    CK_ULONG next_handle = 1;
    CK_ULONG generation = 0;
    unsigned char *meta = NULL;
    size_t meta_len = 0;
    rv = azihsm_pkcs11_store_read(dir, "token.meta", &meta, &meta_len);
    if (rv == CKR_OK && meta != NULL)
    {
        rv = azihsm_pkcs11_meta_decode(meta, meta_len, &next_handle, &generation);
        free(meta);
    }
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_store_unlock(lock_fd);
        return rv;
    }
    CK_ULONG n = next_handle;

    /*
     * Counter-first: advance and fsync token.meta BEFORE writing the object, so
     * a crash between the two leaves handle n as an unused hole, never a reused
     * number that would overwrite a surviving object.
     */
    unsigned char metabuf[P11_META_SIZE];
    size_t mlen = sizeof(metabuf);
    rv = azihsm_pkcs11_meta_encode(n + 1, generation, metabuf, &mlen);
    if (rv == CKR_OK)
    {
        rv = azihsm_pkcs11_store_write(dir, "token.meta", metabuf, mlen);
    }
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_store_unlock(lock_fd);
        return rv;
    }

    /* Serialize the template (borrowed pointers) and write <n>.object. */
    azihsm_pkcs11_rec_attr *ra =
        (azihsm_pkcs11_rec_attr *)calloc(count ? count : 1, sizeof(azihsm_pkcs11_rec_attr));
    if (ra == NULL)
    {
        azihsm_pkcs11_store_unlock(lock_fd);
        return CKR_HOST_MEMORY;
    }
    for (CK_ULONG i = 0; i < count; i++)
    {
        ra[i].type = tmpl[i].type;
        ra[i].value = (unsigned char *)tmpl[i].pValue;
        ra[i].len = tmpl[i].ulValueLen;
    }
    azihsm_pkcs11_rec_object obj = { ra, count, NULL, 0 };

    rv = rewrite_token_object(dir, n, &obj);
    free(ra);
    azihsm_pkcs11_store_unlock(lock_fd);
    if (rv != CKR_OK)
    {
        return rv; /* counter already advanced: n is a hole, never reused */
    }
    *out = P11_FILE_TOKEN_FLAG | n;
    return CKR_OK;
}

/* Load and decode a token object under the caller's slot; applies the private
 * login gate. *found is set false (and CKR_OBJECT_HANDLE_INVALID returned) when
 * the object is absent or not visible, without leaking its existence. */
static CK_RV load_visible_token_object(
    file_store *st,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    CK_OBJECT_HANDLE h,
    azihsm_pkcs11_rec_object *out
)
{
    char dir[P11_FILE_TOKEN_DIR_LEN];
    CK_RV rv = token_dir(st, slot, dir, sizeof(dir));
    if (rv != CKR_OK)
    {
        return rv;
    }
    char name[P11_FILE_OBJ_NAME_LEN];
    object_name(h & ~P11_FILE_TOKEN_FLAG, name, sizeof(name));

    unsigned char *buf = NULL;
    size_t blen = 0;
    rv = azihsm_pkcs11_store_read(dir, name, &buf, &blen);
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (buf == NULL) /* absent */
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    rv = azihsm_pkcs11_record_decode(buf, blen, out);
    free(buf);
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (rec_bool(out, CKA_PRIVATE, CK_FALSE) && !user_logged_in)
    {
        azihsm_pkcs11_record_free(out);
        return CKR_OBJECT_HANDLE_INVALID; /* private + logged out: invisible */
    }
    return CKR_OK;
}

/* ---- vtable ops --------------------------------------------------------- */

static CK_RV file_create(
    void *ctx,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_OBJECT_HANDLE *out
)
{
    file_store *st = (file_store *)ctx;
    if (out == NULL || (count > 0 && tmpl == NULL))
    {
        return CKR_ARGUMENTS_BAD;
    }
    /* A non-zero length with a NULL value is malformed (later reads would
     * dereference it); reject up front, as the in-memory backend does. */
    for (CK_ULONG i = 0; i < count; i++)
    {
        if (tmpl[i].ulValueLen > 0 && tmpl[i].pValue == NULL)
        {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }
    if (tmpl_bool(tmpl, count, CKA_TOKEN, CK_FALSE))
    {
        return create_token_object(st, slot, user_logged_in, tmpl, count, out);
    }
    return st->mem.ops->create(st->mem.ctx, slot, user_logged_in, tmpl, count, out);
}

static CK_RV file_destroy(void *ctx, CK_SLOT_ID slot, CK_BBOOL user_logged_in, CK_OBJECT_HANDLE h)
{
    file_store *st = (file_store *)ctx;
    if ((h & P11_FILE_TOKEN_FLAG) == 0)
    {
        return st->mem.ops->destroy(st->mem.ctx, slot, user_logged_in, h);
    }

    char dir[P11_FILE_TOKEN_DIR_LEN];
    CK_RV rv = token_dir(st, slot, dir, sizeof(dir));
    if (rv != CKR_OK)
    {
        return rv;
    }
    int lock_fd = -1;
    rv = azihsm_pkcs11_store_lock(dir, &lock_fd);
    if (rv != CKR_OK)
    {
        return rv;
    }
    /* Check visibility (existence + private gate) before removing. */
    azihsm_pkcs11_rec_object o;
    rv = load_visible_token_object(st, slot, user_logged_in, h, &o);
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_store_unlock(lock_fd);
        return rv;
    }
    azihsm_pkcs11_record_free(&o);

    char name[P11_FILE_OBJ_NAME_LEN];
    object_name(h & ~P11_FILE_TOKEN_FLAG, name, sizeof(name));
    rv = azihsm_pkcs11_store_unlink(dir, name);
    azihsm_pkcs11_store_unlock(lock_fd);
    return rv;
}

static CK_RV file_get_attr(
    void *ctx,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    CK_OBJECT_HANDLE h,
    CK_ATTRIBUTE *tmpl,
    CK_ULONG count
)
{
    file_store *st = (file_store *)ctx;
    if ((h & P11_FILE_TOKEN_FLAG) == 0)
    {
        return st->mem.ops->get_attr(st->mem.ctx, slot, user_logged_in, h, tmpl, count);
    }

    char dir[P11_FILE_TOKEN_DIR_LEN];
    CK_RV rv = token_dir(st, slot, dir, sizeof(dir));
    if (rv != CKR_OK)
    {
        return rv;
    }
    int lock_fd = -1;
    rv = azihsm_pkcs11_store_lock(dir, &lock_fd);
    if (rv != CKR_OK)
    {
        return rv;
    }
    azihsm_pkcs11_rec_object o;
    rv = load_visible_token_object(st, slot, user_logged_in, h, &o);
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_store_unlock(lock_fd);
        return rv;
    }

    /* Sensitive or non-extractable secret material must not be revealed
     * (identical rule to the in-memory backend). */
    CK_BBOOL sensitive =
        rec_bool(&o, CKA_SENSITIVE, CK_FALSE) || !rec_bool(&o, CKA_EXTRACTABLE, CK_TRUE);

    CK_RV ret = CKR_OK;
    for (CK_ULONG i = 0; i < count; i++)
    {
        const azihsm_pkcs11_rec_attr *a = rec_find(&o, tmpl[i].type);
        if (a == NULL)
        {
            tmpl[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            ret = CKR_ATTRIBUTE_TYPE_INVALID;
            continue;
        }
        CK_BBOOL secret = (tmpl[i].type == CKA_VALUE || tmpl[i].type == CKA_PRIVATE_EXPONENT);
        if (sensitive && secret)
        {
            tmpl[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            ret = CKR_ATTRIBUTE_SENSITIVE;
            continue;
        }
        if (tmpl[i].pValue == NULL_PTR)
        {
            tmpl[i].ulValueLen = a->len; /* two-call: report length */
            continue;
        }
        if (tmpl[i].ulValueLen < a->len)
        {
            tmpl[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            ret = CKR_BUFFER_TOO_SMALL;
            continue;
        }
        if (a->len > 0)
        {
            memcpy(tmpl[i].pValue, a->value, a->len);
        }
        tmpl[i].ulValueLen = a->len;
    }
    azihsm_pkcs11_record_free(&o);
    azihsm_pkcs11_store_unlock(lock_fd);
    return ret;
}

static CK_RV set_attr_token(
    file_store *st,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    CK_OBJECT_HANDLE h,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count
)
{
    for (CK_ULONG i = 0; i < count; i++)
    {
        if (tmpl[i].ulValueLen > 0 && tmpl[i].pValue == NULL)
        {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }
    char dir[P11_FILE_TOKEN_DIR_LEN];
    CK_RV rv = token_dir(st, slot, dir, sizeof(dir));
    if (rv != CKR_OK)
    {
        return rv;
    }
    int lock_fd = -1;
    rv = azihsm_pkcs11_store_lock(dir, &lock_fd);
    if (rv != CKR_OK)
    {
        return rv;
    }
    azihsm_pkcs11_rec_object o;
    rv = load_visible_token_object(st, slot, user_logged_in, h, &o);
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_store_unlock(lock_fd);
        return rv;
    }
    /* Apply changes to the decoded copy only; the on-disk object is rewritten
     * once, so a mid-update failure leaves it unchanged (all-or-nothing). */
    for (CK_ULONG i = 0; i < count && rv == CKR_OK; i++)
    {
        rv = rec_set_attr(
            &o,
            tmpl[i].type,
            (const unsigned char *)tmpl[i].pValue,
            tmpl[i].ulValueLen
        );
    }
    /* The same v1 refusal as create: a private object must not end up carrying a
     * non-device-protected plaintext secret at rest. */
    if (rv == CKR_OK && rec_bool(&o, CKA_PRIVATE, CK_FALSE) &&
        (rec_find(&o, CKA_VALUE) != NULL || rec_find(&o, CKA_PRIVATE_EXPONENT) != NULL))
    {
        rv = CKR_TEMPLATE_INCONSISTENT;
    }
    if (rv == CKR_OK)
    {
        rv = rewrite_token_object(dir, h & ~P11_FILE_TOKEN_FLAG, &o);
    }
    azihsm_pkcs11_record_free(&o);
    azihsm_pkcs11_store_unlock(lock_fd);
    return rv;
}

static CK_RV file_set_attr(
    void *ctx,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    CK_OBJECT_HANDLE h,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count
)
{
    file_store *st = (file_store *)ctx;
    if ((h & P11_FILE_TOKEN_FLAG) == 0)
    {
        return st->mem.ops->set_attr(st->mem.ctx, slot, user_logged_in, h, tmpl, count);
    }
    return set_attr_token(st, slot, user_logged_in, h, tmpl, count);
}

/* ---- find (enumeration) ------------------------------------------------- */

/* A find cursor is a snapshot of matching handles built at find_init; find just
 * drains it and find_final frees it, so neither touches the store again. */
typedef struct
{
    CK_OBJECT_HANDLE *handles;
    CK_ULONG count;
    CK_ULONG cap;
    CK_ULONG pos;
} file_cursor;

static CK_RV cursor_append(file_cursor *c, CK_OBJECT_HANDLE h)
{
    if (c->count == c->cap)
    {
        CK_ULONG ncap = c->cap ? c->cap * 2 : 16;
        CK_OBJECT_HANDLE *grown = (CK_OBJECT_HANDLE *)realloc(c->handles, ncap * sizeof(*grown));
        if (grown == NULL)
        {
            return CKR_HOST_MEMORY;
        }
        c->handles = grown;
        c->cap = ncap;
    }
    c->handles[c->count++] = h;
    return CKR_OK;
}

static CK_BBOOL matches_rec(
    const azihsm_pkcs11_rec_object *o,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count
)
{
    for (CK_ULONG i = 0; i < count; i++)
    {
        const azihsm_pkcs11_rec_attr *a = rec_find(o, tmpl[i].type);
        if (a == NULL || a->len != tmpl[i].ulValueLen)
        {
            return CK_FALSE;
        }
        if (a->len > 0 && memcmp(a->value, tmpl[i].pValue, a->len) != 0)
        {
            return CK_FALSE;
        }
    }
    return CK_TRUE;
}

/* Parse "<digits>.object" into its handle number; returns 0 for any other name
 * (token.meta, .lock, temp files, ".", ".."), so the scan skips them. */
static int parse_object_name(const char *name, CK_ULONG *num)
{
    static const char suffix[] = ".object";
    size_t len = strlen(name);
    size_t slen = sizeof(suffix) - 1;
    if (len <= slen || len - slen > 20) /* 20 = max decimal digits in a u64 */
    {
        return 0;
    }
    size_t digits = len - slen;
    if (strcmp(name + digits, suffix) != 0)
    {
        return 0;
    }
    CK_ULONG v = 0;
    for (size_t i = 0; i < digits; i++)
    {
        if (name[i] < '0' || name[i] > '9')
        {
            return 0;
        }
        v = v * 10 + (CK_ULONG)(name[i] - '0');
    }
    *num = v;
    return 1;
}

/*
 * Append every visible token object in `slot` matching `tmpl` to the cursor.
 * Lock-free by design: each object write is an atomic rename and a deletion is
 * tolerated (a file that vanishes mid-scan is skipped), so a scan never reads a
 * torn record; an object added concurrently may be missed, which PKCS#11 allows.
 */
static CK_RV collect_token_matches(
    file_store *st,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    file_cursor *c
)
{
    char dir[P11_FILE_TOKEN_DIR_LEN];
    CK_RV rv = token_dir(st, slot, dir, sizeof(dir));
    if (rv != CKR_OK)
    {
        return rv;
    }
    DIR *d = opendir(dir);
    if (d == NULL)
    {
        return CKR_OK; /* no token directory yet -> no token objects */
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
    {
        CK_ULONG num = 0;
        if (!parse_object_name(e->d_name, &num))
        {
            continue;
        }
        unsigned char *buf = NULL;
        size_t blen = 0;
        if (azihsm_pkcs11_store_read(dir, e->d_name, &buf, &blen) != CKR_OK || buf == NULL)
        {
            continue; /* removed or unreadable mid-scan */
        }
        azihsm_pkcs11_rec_object o;
        int decoded = (azihsm_pkcs11_record_decode(buf, blen, &o) == CKR_OK);
        free(buf);
        if (!decoded)
        {
            continue; /* skip a corrupt record rather than fail the whole scan */
        }
        CK_BBOOL is_private = rec_bool(&o, CKA_PRIVATE, CK_FALSE);
        if ((!is_private || user_logged_in) && matches_rec(&o, tmpl, count))
        {
            rv = cursor_append(c, P11_FILE_TOKEN_FLAG | num);
        }
        azihsm_pkcs11_record_free(&o);
        if (rv != CKR_OK)
        {
            break;
        }
    }
    closedir(d);
    return rv;
}

static CK_RV file_find_init(
    void *ctx,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    void **cursor
)
{
    file_store *st = (file_store *)ctx;
    /* Reject a malformed template up front (mirrors the in-memory backend). */
    if (count > 0 && tmpl == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    for (CK_ULONG i = 0; i < count; i++)
    {
        if (tmpl[i].ulValueLen > 0 && tmpl[i].pValue == NULL)
        {
            return CKR_ARGUMENTS_BAD;
        }
    }

    file_cursor *c = (file_cursor *)calloc(1, sizeof(file_cursor));
    if (c == NULL)
    {
        return CKR_HOST_MEMORY;
    }

    /* Session matches come from the embedded backend; drain its cursor into our
     * snapshot so find/find_final never touch it again. */
    void *memcur = NULL;
    CK_RV rv = st->mem.ops->find_init(st->mem.ctx, slot, user_logged_in, tmpl, count, &memcur);
    if (rv == CKR_OK)
    {
        for (;;)
        {
            CK_OBJECT_HANDLE batch[64];
            CK_ULONG got = 0;
            rv = st->mem.ops->find(st->mem.ctx, memcur, batch, 64, &got);
            if (rv != CKR_OK || got == 0)
            {
                break;
            }
            for (CK_ULONG i = 0; i < got; i++)
            {
                rv = cursor_append(c, batch[i]);
                if (rv != CKR_OK)
                {
                    break;
                }
            }
            if (rv != CKR_OK)
            {
                break;
            }
        }
        st->mem.ops->find_final(st->mem.ctx, memcur);
    }

    /* Token matches from disk. */
    if (rv == CKR_OK)
    {
        rv = collect_token_matches(st, slot, user_logged_in, tmpl, count, c);
    }
    if (rv != CKR_OK)
    {
        free(c->handles);
        free(c);
        return rv;
    }
    *cursor = c;
    return CKR_OK;
}

static CK_RV file_find(
    void *ctx,
    void *cursor,
    CK_OBJECT_HANDLE *out,
    CK_ULONG max,
    CK_ULONG *count
)
{
    (void)ctx;
    file_cursor *c = (file_cursor *)cursor;
    CK_ULONG n = 0;
    while (c->pos < c->count && n < max)
    {
        out[n++] = c->handles[c->pos++];
    }
    *count = n;
    return CKR_OK;
}

static void file_find_final(void *ctx, void *cursor)
{
    (void)ctx;
    file_cursor *c = (file_cursor *)cursor;
    if (c != NULL)
    {
        free(c->handles);
        free(c);
    }
}

static CK_RV set_key_body_token(
    file_store *st,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    CK_OBJECT_HANDLE h,
    const CK_BYTE *blob,
    CK_ULONG len
)
{
    if (len > 0 && blob == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    char dir[P11_FILE_TOKEN_DIR_LEN];
    CK_RV rv = token_dir(st, slot, dir, sizeof(dir));
    if (rv != CKR_OK)
    {
        return rv;
    }
    int lock_fd = -1;
    rv = azihsm_pkcs11_store_lock(dir, &lock_fd);
    if (rv != CKR_OK)
    {
        return rv;
    }
    azihsm_pkcs11_rec_object o;
    rv = load_visible_token_object(st, slot, user_logged_in, h, &o);
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_store_unlock(lock_fd);
        return rv;
    }
    /* Stage the new body before touching the record, then rewrite once. */
    unsigned char *nb = NULL;
    if (len > 0)
    {
        nb = (unsigned char *)malloc(len);
        if (nb == NULL)
        {
            azihsm_pkcs11_record_free(&o);
            azihsm_pkcs11_store_unlock(lock_fd);
            return CKR_HOST_MEMORY;
        }
        memcpy(nb, blob, len);
    }
    if (o.body != NULL)
    {
        memset(o.body, 0, o.body_len);
        free(o.body);
    }
    o.body = nb;
    o.body_len = len;
    rv = rewrite_token_object(dir, h & ~P11_FILE_TOKEN_FLAG, &o);
    azihsm_pkcs11_record_free(&o);
    azihsm_pkcs11_store_unlock(lock_fd);
    return rv;
}

static CK_RV file_set_key_body(
    void *ctx,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    CK_OBJECT_HANDLE h,
    const CK_BYTE *blob,
    CK_ULONG len
)
{
    file_store *st = (file_store *)ctx;
    if ((h & P11_FILE_TOKEN_FLAG) == 0)
    {
        return st->mem.ops->set_key_body(st->mem.ctx, slot, user_logged_in, h, blob, len);
    }
    return set_key_body_token(st, slot, user_logged_in, h, blob, len);
}

static CK_RV get_key_body_token(
    file_store *st,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    CK_OBJECT_HANDLE h,
    CK_BYTE *blob,
    CK_ULONG *len
)
{
    char dir[P11_FILE_TOKEN_DIR_LEN];
    CK_RV rv = token_dir(st, slot, dir, sizeof(dir));
    if (rv != CKR_OK)
    {
        return rv;
    }
    /* Brief lock: reading the record non-atomically vs. a concurrent
     * set_key_body would be safe (writes are atomic renames) but could return a
     * stale body; the lock matches get_attr's read-under-lock discipline. */
    int lock_fd = -1;
    rv = azihsm_pkcs11_store_lock(dir, &lock_fd);
    if (rv != CKR_OK)
    {
        return rv;
    }
    azihsm_pkcs11_rec_object o;
    rv = load_visible_token_object(st, slot, user_logged_in, h, &o);
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_store_unlock(lock_fd);
        return rv;
    }
    if (blob == NULL)
    {
        *len = o.body_len;
    }
    else if (*len < o.body_len)
    {
        *len = o.body_len;
        rv = CKR_BUFFER_TOO_SMALL;
    }
    else
    {
        if (o.body_len > 0)
        {
            memcpy(blob, o.body, o.body_len);
        }
        *len = o.body_len;
    }
    azihsm_pkcs11_record_free(&o);
    azihsm_pkcs11_store_unlock(lock_fd);
    return rv;
}

static CK_RV file_get_key_body(
    void *ctx,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    CK_OBJECT_HANDLE h,
    CK_BYTE *blob,
    CK_ULONG *len
)
{
    file_store *st = (file_store *)ctx;
    if (len == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if ((h & P11_FILE_TOKEN_FLAG) == 0)
    {
        return st->mem.ops->get_key_body(st->mem.ctx, slot, user_logged_in, h, blob, len);
    }
    return get_key_body_token(st, slot, user_logged_in, h, blob, len);
}

static CK_RV file_persist(void *ctx)
{
    (void)ctx;
    /* Token operations write through synchronously (each mutation fsyncs its own
     * file and the directory), so this flush barrier has nothing outstanding. */
    return CKR_OK;
}

static void file_teardown(void *ctx)
{
    file_store *st = (file_store *)ctx;
    if (st == NULL)
    {
        return;
    }
    if (st->mem.ops != NULL && st->mem.ctx != NULL)
    {
        st->mem.ops->teardown(st->mem.ctx); /* frees session objects */
    }
    /* Token object files persist on disk; teardown frees only in-process state. */
    free(st);
}

static const azihsm_pkcs11_objstore_ops FILE_OPS = {
    .create = file_create,
    .destroy = file_destroy,
    .get_attr = file_get_attr,
    .set_attr = file_set_attr,
    .find_init = file_find_init,
    .find = file_find,
    .find_final = file_find_final,
    .set_key_body = file_set_key_body,
    .get_key_body = file_get_key_body,
    .teardown = file_teardown,
    .persist = file_persist, /* file backend flushes; contrast MEM_OPS (.persist = NULL) */
};

CK_RV azihsm_pkcs11_objstore_file_create(
    azihsm_pkcs11_objstore *out,
    const azihsm_pkcs11_config *cfg
)
{
    if (out == NULL || cfg == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    file_store *st = (file_store *)calloc(1, sizeof(file_store));
    if (st == NULL)
    {
        return CKR_HOST_MEMORY;
    }
    int written = snprintf(st->store_dir, sizeof(st->store_dir), "%s", cfg->store_dir);
    if (written < 0 || (size_t)written >= sizeof(st->store_dir))
    {
        free(st);
        return CKR_ARGUMENTS_BAD;
    }
    CK_RV rv = azihsm_pkcs11_store_dir_ensure(st->store_dir);
    if (rv != CKR_OK)
    {
        free(st);
        return rv;
    }
    rv = azihsm_pkcs11_objstore_mem_create(&st->mem);
    if (rv != CKR_OK)
    {
        free(st);
        return rv;
    }
    out->ops = &FILE_OPS;
    out->ctx = st;
    return CKR_OK;
}
