// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "azihsm_pkcs11_compat.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Object-store seam.
 *
 * PKCS#11 assumes a persistent, attribute-templated, searchable object store.
 * The AZIHSM device provides none of it (it returns each key as an opaque masked
 * blob and enumerates nothing), so the object layer is emulated host-side behind
 * this vtable. The store holds each object's full attribute set plus, for keys,
 * the opaque AZIHSM masked blob as the key body; it deals in CK_RV only and never
 * calls the HSM.
 *
 * The in-memory backend (azihsm_pkcs11_objstore_mem.c) is the only implementation today. A
 * persistent backend (file/DB, plus the SDK resiliency storage) will implement
 * the same ops and set `persist`; the framework callers do not change when the
 * backend is swapped — construction picks the backend, everything else goes
 * through `ops`/`ctx`.
 */

typedef struct azihsm_pkcs11_objstore_ops azihsm_pkcs11_objstore_ops;

typedef struct
{
    const azihsm_pkcs11_objstore_ops *ops;
    void *ctx; /* backend-owned; opaque to callers */
} azihsm_pkcs11_objstore;

/*
 * Every object is bound to the slot (token) it was created in, so handle-based
 * ops carry the calling `slot` and `user_logged_in`: the device authenticates
 * the partition (token), never individual objects, so the host enforces PKCS#11
 * token isolation and private-object login-gating here. An object in another
 * slot, or a private object while not logged in, is not visible to the caller
 * and yields CKR_OBJECT_HANDLE_INVALID (rather than leaking its existence).
 */
struct azihsm_pkcs11_objstore_ops
{
    /* Create an object in `slot`; a private object requires `user_logged_in`. */
    CK_RV(*create)
    (void *ctx,
     CK_SLOT_ID slot,
     CK_BBOOL user_logged_in,
     const CK_ATTRIBUTE *tmpl,
     CK_ULONG count,
     CK_OBJECT_HANDLE *out);
    CK_RV (*destroy)(void *ctx, CK_SLOT_ID slot, CK_BBOOL user_logged_in, CK_OBJECT_HANDLE h);
    CK_RV(*get_attr)
    (void *ctx,
     CK_SLOT_ID slot,
     CK_BBOOL user_logged_in,
     CK_OBJECT_HANDLE h,
     CK_ATTRIBUTE *tmpl,
     CK_ULONG count);
    CK_RV(*set_attr)
    (void *ctx,
     CK_SLOT_ID slot,
     CK_BBOOL user_logged_in,
     CK_OBJECT_HANDLE h,
     const CK_ATTRIBUTE *tmpl,
     CK_ULONG count);

    /*
     * Materialise the matches for a template into an opaque cursor the caller
     * drains with `find` and releases with `find_final`. `slot` scopes the
     * search; private objects are excluded unless `user_logged_in`.
     */
    CK_RV(*find_init)
    (void *ctx,
     CK_SLOT_ID slot,
     CK_BBOOL user_logged_in,
     const CK_ATTRIBUTE *tmpl,
     CK_ULONG count,
     void **cursor);
    CK_RV (*find)(void *ctx, void *cursor, CK_OBJECT_HANDLE *out, CK_ULONG max, CK_ULONG *count);
    void (*find_final)(void *ctx, void *cursor);

    /*
     * Attach the opaque AZIHSM masked blob (azihsm_key_get_prop(MASKED_KEY)) as a
     * key object's body. Set by the crypto layer once a key is generated or
     * imported; unused until key operations land.
     */
    CK_RV(*set_key_body)
    (void *ctx,
     CK_SLOT_ID slot,
     CK_BBOOL user_logged_in,
     CK_OBJECT_HANDLE h,
     const CK_BYTE *blob,
     CK_ULONG len);

    void (*teardown)(void *ctx); /* free the whole store (C_Finalize) */
    CK_RV (*persist)(void *ctx); /* NULL on the in-memory backend */
};

/* Construct the in-memory backend into `out`. */
CK_RV azihsm_pkcs11_objstore_mem_create(azihsm_pkcs11_objstore *out);

#ifdef __cplusplus
}
#endif
