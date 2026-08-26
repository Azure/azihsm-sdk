// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Persistent file-backed object-store backend for the seam in azihsm_pkcs11_objstore.h.
 *
 * Objects — each object's attribute template plus, for keys, the opaque AZIHSM
 * masked blob as the key body — are written through to a directory tree under
 * the configured store root, so token objects survive a process restart and are
 * visible to other processes sharing the directory (which the in-memory backend,
 * azihsm_pkcs11_objstore_mem.c, cannot do).
 *
 * Like the in-memory backend this file links no libcrypto: durability rests on
 * the filesystem (atomic temp+rename, flock), not on host cryptography, so the
 * no-device smoke build still compiles. It performs no internal thread locking —
 * the framework layer holds the module lock across every call; cross-process
 * exclusion is added with the filesystem primitives in a later phase.
 *
 * This is the skeleton: construction, teardown, and the vtable wiring are in
 * place and select-able via AZIHSM_PKCS11_PERSIST; the object operations are
 * filled in by later phases and until then report CKR_FUNCTION_NOT_SUPPORTED.
 */

#include "azihsm_pkcs11_objstore.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct
{
    char store_dir[AZIHSM_PKCS11_STORE_DIR_LEN]; /* persistent object-store root */
} file_store;

static CK_RV file_create(
    void *ctx,
    CK_SLOT_ID slot,
    CK_BBOOL user_logged_in,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_OBJECT_HANDLE *out
)
{
    (void)ctx;
    (void)slot;
    (void)user_logged_in;
    (void)tmpl;
    (void)count;
    (void)out;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV file_destroy(void *ctx, CK_SLOT_ID slot, CK_BBOOL user_logged_in, CK_OBJECT_HANDLE h)
{
    (void)ctx;
    (void)slot;
    (void)user_logged_in;
    (void)h;
    return CKR_FUNCTION_NOT_SUPPORTED;
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
    (void)ctx;
    (void)slot;
    (void)user_logged_in;
    (void)h;
    (void)tmpl;
    (void)count;
    return CKR_FUNCTION_NOT_SUPPORTED;
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
    (void)ctx;
    (void)slot;
    (void)user_logged_in;
    (void)h;
    (void)tmpl;
    (void)count;
    return CKR_FUNCTION_NOT_SUPPORTED;
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
    (void)ctx;
    (void)slot;
    (void)user_logged_in;
    (void)tmpl;
    (void)count;
    (void)cursor;
    return CKR_FUNCTION_NOT_SUPPORTED;
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
    (void)cursor;
    (void)out;
    (void)max;
    (void)count;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static void file_find_final(void *ctx, void *cursor)
{
    (void)ctx;
    (void)cursor;
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
    (void)ctx;
    (void)slot;
    (void)user_logged_in;
    (void)h;
    (void)blob;
    (void)len;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV file_persist(void *ctx)
{
    (void)ctx;
    /* Object operations write through synchronously, so this flush barrier has
     * nothing to flush yet; it is populated as the ops land. */
    return CKR_OK;
}

static void file_teardown(void *ctx)
{
    file_store *st = (file_store *)ctx;
    if (st == NULL)
    {
        return;
    }
    /* Object files persist on disk; teardown frees only in-process state. */
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
    out->ops = &FILE_OPS;
    out->ctx = st;
    return CKR_OK;
}
