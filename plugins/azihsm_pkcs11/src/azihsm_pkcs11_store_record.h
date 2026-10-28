// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "azihsm_pkcs11_compat.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * On-disk record codec for the persistent object store (azihsm_pkcs11_objstore_file.c).
 *
 * An object is serialized as a fixed little-endian header ("P11O", a version, an
 * attribute count and a masked-blob length, a total length, and a zeroed
 * reserved field) followed by a flat sequence of attribute records
 * [type u32][len u32][value bytes] and then the opaque masked-blob key body.
 * The masked blob is a distinguished trailing field, not an attribute, so it is
 * never returned by C_GetAttributeValue. Decoding validates the magic, version,
 * reserved field, and every length against the buffer, so a torn or tampered
 * record is rejected rather than misread.
 *
 * Explicit little-endian + magic + version mirror the repo's persisted formats
 * (fw part_store / key_vault, key-masking aead). The token.meta counter file
 * ("P11M") shares the same header discipline.
 *
 * This codec links no libcrypto (uses libc malloc/free) so it compiles in the
 * no-device smoke build.
 */

#define P11_RECORD_VERSION 1
#define P11_META_SIZE 24

/* One attribute. `value` is borrowed by azihsm_pkcs11_record_encode (read-only) and owned
 * by a azihsm_pkcs11_record_decode result (freed by azihsm_pkcs11_record_free); NULL when len == 0.
 */
typedef struct
{
    CK_ATTRIBUTE_TYPE type;
    unsigned char *value;
    CK_ULONG len;
} azihsm_pkcs11_rec_attr;

/* A whole object: its attributes plus the opaque masked-blob key body (NULL when
 * the object is not a key). Ownership follows the attributes (see above). */
typedef struct
{
    azihsm_pkcs11_rec_attr *attrs;
    CK_ULONG attr_count;
    unsigned char *body;
    CK_ULONG body_len;
} azihsm_pkcs11_rec_object;

/*
 * Encode `obj` into the P11O record format. Two-call: with buf == NULL, sets
 * *len to the required size and returns CKR_OK; otherwise writes into buf,
 * returning CKR_BUFFER_TOO_SMALL when *len is short and otherwise setting *len
 * to the bytes written. `obj`'s buffers are read, not owned. The encoded buffer
 * may hold sensitive attribute bytes; the caller wipes it after writing.
 */
CK_RV azihsm_pkcs11_record_encode(
    const azihsm_pkcs11_rec_object *obj,
    unsigned char *buf,
    size_t *len
);

/*
 * Decode a P11O record from buf[len] into *out, validating the header and every
 * length. On success *out owns freshly-allocated buffers (free with
 * azihsm_pkcs11_record_free); on any inconsistency returns an error and *out is zeroed.
 */
CK_RV azihsm_pkcs11_record_decode(
    const unsigned char *buf,
    size_t len,
    azihsm_pkcs11_rec_object *out
);

/* Wipe and free the owned buffers of a decoded object; NULL-safe, leaves *obj
 * zeroed. */
void azihsm_pkcs11_record_free(azihsm_pkcs11_rec_object *obj);

/*
 * token.meta codec (P11M): the persistent monotonic handle counter and a
 * generation counter. Two-call like azihsm_pkcs11_record_encode; decode validates the
 * fixed P11_META_SIZE layout.
 */
CK_RV azihsm_pkcs11_meta_encode(
    CK_ULONG next_handle,
    CK_ULONG generation,
    unsigned char *buf,
    size_t *len
);
CK_RV
azihsm_pkcs11_meta_decode(
    const unsigned char *buf,
    size_t len,
    CK_ULONG *next_handle,
    CK_ULONG *generation
);

#ifdef __cplusplus
}
#endif
