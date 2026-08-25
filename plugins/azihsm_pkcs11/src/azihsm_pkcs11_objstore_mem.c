// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * In-memory object-store backend for the seam in azihsm_pkcs11_objstore.h.
 *
 * Objects live only for the process lifetime; token objects do not yet survive a
 * restart (that is the persistent backend's job — this one implements the same
 * vtable so it can be swapped in without touching the framework layer).
 *
 * Uses libc malloc/free rather than the OpenSSL allocators the rest of the tree
 * prefers, on purpose: the object store links no libcrypto so it also compiles
 * in the no-device smoke build. It performs no internal locking — the framework
 * layer holds the module lock across every call.
 */

#include "azihsm_pkcs11_objstore.h"

#include <stdlib.h>
#include <string.h>

#define MEM_MAX_OBJECTS 1024

typedef struct
{
    CK_ATTRIBUTE_TYPE type;
    CK_BYTE *value; /* owned; NULL when len == 0 */
    CK_ULONG len;
} mem_attr;

typedef struct
{
    CK_BBOOL in_use;
    CK_OBJECT_HANDLE handle;
    CK_SLOT_ID slot;
    CK_BBOOL is_private; /* cached CKA_PRIVATE, gates find visibility */
    mem_attr *attrs;
    CK_ULONG attr_count;
    CK_BYTE *key_body; /* opaque AZIHSM masked blob; NULL for non-key objects */
    CK_ULONG key_body_len;
} mem_object;

typedef struct
{
    mem_object objects[MEM_MAX_OBJECTS];
    CK_ULONG next_handle; /* monotonic, never reused */
} mem_store;

typedef struct
{
    CK_OBJECT_HANDLE *handles;
    CK_ULONG count;
    CK_ULONG pos;
} mem_cursor;

static mem_object *lookup(mem_store *st, CK_OBJECT_HANDLE h)
{
    for (CK_ULONG i = 0; i < MEM_MAX_OBJECTS; i++)
    {
        if (st->objects[i].in_use && st->objects[i].handle == h)
        {
            return &st->objects[i];
        }
    }
    return NULL;
}

/*
 * PKCS#11 access control the device cannot enforce (it authenticates the
 * partition, not objects): an object is reachable only from its own slot
 * (token), and a private object only once the token's user is logged in.
 */
static CK_BBOOL visible(const mem_object *o, CK_SLOT_ID slot, CK_BBOOL user_logged_in)
{
    if (o->slot != slot)
    {
        return CK_FALSE;
    }
    if (o->is_private && !user_logged_in)
    {
        return CK_FALSE;
    }
    return CK_TRUE;
}

static const mem_attr *find_attr(const mem_object *o, CK_ATTRIBUTE_TYPE t)
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

static CK_BBOOL attr_bool(const mem_object *o, CK_ATTRIBUTE_TYPE t, CK_BBOOL dflt)
{
    const mem_attr *a = find_attr(o, t);
    if (a == NULL || a->len == 0 || a->value == NULL)
    {
        return dflt;
    }
    return a->value[0] != 0 ? CK_TRUE : CK_FALSE;
}

/* Release an object, zeroing attribute values and the key body first — they
 * may hold secrets. */
static void free_object(mem_object *o)
{
    for (CK_ULONG i = 0; i < o->attr_count; i++)
    {
        if (o->attrs[i].value != NULL)
        {
            memset(o->attrs[i].value, 0, o->attrs[i].len);
            free(o->attrs[i].value);
        }
    }
    free(o->attrs);
    if (o->key_body != NULL)
    {
        memset(o->key_body, 0, o->key_body_len);
        free(o->key_body);
    }
    memset(o, 0, sizeof(*o));
}

static CK_RV mem_create(
    void *ctx,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_OBJECT_HANDLE *out
)
{
    mem_store *st = (mem_store *)ctx;
    mem_object *o = NULL;
    for (CK_ULONG i = 0; i < MEM_MAX_OBJECTS; i++)
    {
        if (!st->objects[i].in_use)
        {
            o = &st->objects[i];
            break;
        }
    }
    if (o == NULL)
    {
        return CKR_DEVICE_MEMORY;
    }

    memset(o, 0, sizeof(*o));
    o->attrs = (mem_attr *)calloc(count ? count : 1, sizeof(mem_attr));
    if (o->attrs == NULL)
    {
        return CKR_HOST_MEMORY;
    }
    for (CK_ULONG i = 0; i < count; i++)
    {
        mem_attr *a = &o->attrs[i];
        a->type = tmpl[i].type;
        a->len = tmpl[i].ulValueLen;
        if (a->len > 0)
        {
            /* A non-zero length with no value is malformed: reject it rather
             * than store an attribute whose value is NULL but whose length is
             * not, which later reads (get_attr, find matching) would
             * dereference. */
            if (tmpl[i].pValue == NULL)
            {
                o->attr_count = i; /* free only what we filled */
                free_object(o);
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            a->value = (CK_BYTE *)malloc(a->len);
            if (a->value == NULL)
            {
                o->attr_count = i; /* free only what we filled */
                free_object(o);
                return CKR_HOST_MEMORY;
            }
            memcpy(a->value, tmpl[i].pValue, a->len);
        }
    }
    o->attr_count = count;
    o->in_use = CK_TRUE;
    o->handle = ++st->next_handle; /* handle 0 is CK_INVALID_HANDLE */
    o->slot = slot;
    o->is_private = attr_bool(o, CKA_PRIVATE, CK_FALSE);
    if (o->is_private && !user_logged_in)
    {
        /* A private object may only be created by a logged-in session. */
        free_object(o);
        return CKR_USER_NOT_LOGGED_IN;
    }
    *out = o->handle;
    return CKR_OK;
}

static CK_RV mem_destroy(void *ctx, CK_SLOT_ID slot, CK_BBOOL user_logged_in, CK_OBJECT_HANDLE h)
{
    mem_store *st = (mem_store *)ctx;
    mem_object *o = lookup(st, h);
    if (o == NULL || !visible(o, slot, user_logged_in))
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    free_object(o);
    return CKR_OK;
}

/* Per-attribute outcomes follow PKCS#11 §5.7.5: missing type, sensitive value,
 * two-call sizing, and too-small buffer each set ulValueLen and the return
 * value as the spec's cases prescribe. */
static CK_RV mem_get_attr(
    void *ctx,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    CK_OBJECT_HANDLE h,
    CK_ATTRIBUTE *tmpl,
    CK_ULONG count
)
{
    mem_store *st = (mem_store *)ctx;
    mem_object *o = lookup(st, h);
    if (o == NULL || !visible(o, slot, user_logged_in))
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    /* Sensitive or non-extractable secret material must not be revealed. */
    CK_BBOOL sensitive =
        attr_bool(o, CKA_SENSITIVE, CK_FALSE) || !attr_bool(o, CKA_EXTRACTABLE, CK_TRUE);

    CK_RV rv = CKR_OK;
    for (CK_ULONG i = 0; i < count; i++)
    {
        const mem_attr *a = find_attr(o, tmpl[i].type);
        if (a == NULL)
        {
            tmpl[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            rv = CKR_ATTRIBUTE_TYPE_INVALID;
            continue;
        }
        CK_BBOOL secret = (tmpl[i].type == CKA_VALUE || tmpl[i].type == CKA_PRIVATE_EXPONENT);
        if (sensitive && secret)
        {
            tmpl[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
            rv = CKR_ATTRIBUTE_SENSITIVE;
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
            rv = CKR_BUFFER_TOO_SMALL;
            continue;
        }
        if (a->len > 0)
        {
            memcpy(tmpl[i].pValue, a->value, a->len);
        }
        tmpl[i].ulValueLen = a->len;
    }
    return rv;
}

/* Not reachable yet (no C_SetAttributeValue is wired) but kept correct for
 * when it is. */
static CK_RV mem_set_attr(
    void *ctx,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    CK_OBJECT_HANDLE h,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count
)
{
    mem_store *st = (mem_store *)ctx;
    mem_object *o = lookup(st, h);
    if (o == NULL || !visible(o, slot, user_logged_in))
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    for (CK_ULONG i = 0; i < count; i++)
    {
        if (tmpl[i].ulValueLen > 0 && tmpl[i].pValue == NULL)
        {
            return CKR_ATTRIBUTE_VALUE_INVALID; /* see mem_create */
        }
        /* Stage the new value before touching the object, so a failed
         * allocation (of the value or of a grown attribute array) leaves the
         * object unchanged rather than half-mutated. */
        CK_BYTE *nv = NULL;
        if (tmpl[i].ulValueLen > 0)
        {
            nv = (CK_BYTE *)malloc(tmpl[i].ulValueLen);
            if (nv == NULL)
            {
                return CKR_HOST_MEMORY;
            }
            memcpy(nv, tmpl[i].pValue, tmpl[i].ulValueLen);
        }
        mem_attr *a = NULL;
        for (CK_ULONG j = 0; j < o->attr_count; j++)
        {
            if (o->attrs[j].type == tmpl[i].type)
            {
                a = &o->attrs[j];
                break;
            }
        }
        if (a == NULL)
        {
            mem_attr *grown = (mem_attr *)realloc(o->attrs, (o->attr_count + 1) * sizeof(mem_attr));
            if (grown == NULL)
            {
                free(nv);
                return CKR_HOST_MEMORY;
            }
            o->attrs = grown;
            a = &o->attrs[o->attr_count++];
            memset(a, 0, sizeof(*a));
            a->type = tmpl[i].type;
        }
        if (a->value != NULL)
        {
            memset(a->value, 0, a->len);
            free(a->value);
        }
        a->value = nv;
        a->len = tmpl[i].ulValueLen;
    }
    o->is_private = attr_bool(o, CKA_PRIVATE, o->is_private);
    return CKR_OK;
}

/* PKCS#11 search semantics: an object matches when every template attribute is
 * present with an exactly equal value; an empty template matches everything. */
static CK_BBOOL matches(const mem_object *o, const CK_ATTRIBUTE *tmpl, CK_ULONG count)
{
    for (CK_ULONG i = 0; i < count; i++)
    {
        const mem_attr *a = find_attr(o, tmpl[i].type);
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

static CK_RV mem_find_init(
    void *ctx,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    void **cursor
)
{
    mem_store *st = (mem_store *)ctx;

    /* Reject a malformed search template up front so matches() never reads a
     * value through a NULL pointer. */
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

    mem_cursor *cur = (mem_cursor *)calloc(1, sizeof(mem_cursor));
    if (cur == NULL)
    {
        return CKR_HOST_MEMORY;
    }
    cur->handles = (CK_OBJECT_HANDLE *)calloc(MEM_MAX_OBJECTS, sizeof(CK_OBJECT_HANDLE));
    if (cur->handles == NULL)
    {
        free(cur);
        return CKR_HOST_MEMORY;
    }
    for (CK_ULONG i = 0; i < MEM_MAX_OBJECTS; i++)
    {
        mem_object *o = &st->objects[i];
        if (!o->in_use || o->slot != slot)
        {
            continue;
        }
        if (o->is_private && !user_logged_in)
        {
            continue; /* private objects are invisible until the user logs in */
        }
        if (matches(o, tmpl, count))
        {
            cur->handles[cur->count++] = o->handle;
        }
    }
    *cursor = cur;
    return CKR_OK;
}

static CK_RV mem_find(void *ctx, void *cursor, CK_OBJECT_HANDLE *out, CK_ULONG max, CK_ULONG *count)
{
    (void)ctx;
    mem_cursor *cur = (mem_cursor *)cursor;
    CK_ULONG n = 0;
    while (cur->pos < cur->count && n < max)
    {
        out[n++] = cur->handles[cur->pos++];
    }
    *count = n;
    return CKR_OK;
}

static void mem_find_final(void *ctx, void *cursor)
{
    (void)ctx;
    mem_cursor *cur = (mem_cursor *)cursor;
    if (cur != NULL)
    {
        free(cur->handles);
        free(cur);
    }
}

static CK_RV mem_set_key_body(
    void *ctx,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    CK_OBJECT_HANDLE h,
    const CK_BYTE *blob,
    CK_ULONG len
)
{
    mem_store *st = (mem_store *)ctx;
    mem_object *o = lookup(st, h);
    if (o == NULL || !visible(o, slot, user_logged_in))
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    if (len > 0 && blob == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    CK_BYTE *copy = NULL;
    if (len > 0)
    {
        copy = (CK_BYTE *)malloc(len);
        if (copy == NULL)
        {
            return CKR_HOST_MEMORY;
        }
        memcpy(copy, blob, len);
    }
    if (o->key_body != NULL)
    {
        memset(o->key_body, 0, o->key_body_len);
        free(o->key_body);
    }
    o->key_body = copy;
    o->key_body_len = len;
    return CKR_OK;
}

static void mem_teardown(void *ctx)
{
    mem_store *st = (mem_store *)ctx;
    if (st == NULL)
    {
        return;
    }
    for (CK_ULONG i = 0; i < MEM_MAX_OBJECTS; i++)
    {
        if (st->objects[i].in_use)
        {
            free_object(&st->objects[i]);
        }
    }
    free(st);
}

static const azihsm_pkcs11_objstore_ops MEM_OPS = {
    .create = mem_create,
    .destroy = mem_destroy,
    .get_attr = mem_get_attr,
    .set_attr = mem_set_attr,
    .find_init = mem_find_init,
    .find = mem_find,
    .find_final = mem_find_final,
    .set_key_body = mem_set_key_body,
    .teardown = mem_teardown,
    .persist = NULL, /* in-memory: nothing to flush */
};

CK_RV azihsm_pkcs11_objstore_mem_create(azihsm_pkcs11_objstore *out)
{
    mem_store *st = (mem_store *)calloc(1, sizeof(mem_store));
    if (st == NULL)
    {
        return CKR_HOST_MEMORY;
    }
    out->ops = &MEM_OPS;
    out->ctx = st;
    return CKR_OK;
}
