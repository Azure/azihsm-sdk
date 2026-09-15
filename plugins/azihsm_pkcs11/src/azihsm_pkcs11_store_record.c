// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "azihsm_pkcs11_store_record.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * P11O object record header (little-endian):
 *   magic[4] "P11O" | u16 version | u16 reserved(0) |
 *   u32 attr_count | u32 body_len | u32 total_len
 * followed by attr_count * (u32 type | u32 value_len | value bytes) and then
 * body_len masked-blob bytes. total_len is the whole record size.
 */
static const unsigned char P11O_MAGIC[4] = { 'P', '1', '1', 'O' };
static const unsigned char P11M_MAGIC[4] = { 'P', '1', '1', 'M' };

/* Header sizes are composed from sizeof of the fields actually written, so the
 * offset arithmetic below cannot drift from the layout; the on-disk format
 * itself stays frozen (the fixed-width types pin every field). */
#define P11O_HEADER_SIZE (sizeof(P11O_MAGIC) + 2 * sizeof(uint16_t) + 3 * sizeof(uint32_t))
#define P11O_ATTR_HEADER_SIZE (2 * sizeof(uint32_t)) /* u32 type + u32 value_len */

/* The public buffer-size constant callers use must equal the composed P11M
 * field layout (magic | u16 version | u16 reserved | u64 next_handle |
 * u32 generation | u32 reserved). */
_Static_assert(
    sizeof(P11M_MAGIC) + 2 * sizeof(uint16_t) + sizeof(uint64_t) + 2 * sizeof(uint32_t) ==
        P11_META_SIZE,
    "P11_META_SIZE does not match the P11M field layout"
);

/* Explicit little-endian scalar encoding — never a native struct dump, matching
 * the repo's persisted-format convention. */
static void put_u16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
}

static void put_u32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}

static void put_u64(unsigned char *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
    {
        p[i] = (unsigned char)((v >> (8 * i)) & 0xFF);
    }
}

static uint16_t get_u16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t get_u32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get_u64(const unsigned char *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
    {
        v |= (uint64_t)p[i] << (8 * i);
    }
    return v;
}

static void free_attrs(azihsm_pkcs11_rec_attr *attrs, CK_ULONG n)
{
    if (attrs == NULL)
    {
        return;
    }
    for (CK_ULONG i = 0; i < n; i++)
    {
        if (attrs[i].value != NULL)
        {
            /* Attribute values may hold sensitive material; wipe before free
             * (plain memset, matching azihsm_pkcs11_objstore_mem.c — this module links no
             * libcrypto so OPENSSL_cleanse is unavailable). */
            memset(attrs[i].value, 0, attrs[i].len);
            free(attrs[i].value);
        }
    }
    free(attrs);
}

CK_RV azihsm_pkcs11_record_encode(
    const azihsm_pkcs11_rec_object *obj,
    unsigned char *buf,
    size_t *len
)
{
    if (obj == NULL || len == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if ((obj->attr_count > 0 && obj->attrs == NULL) || (obj->body_len > 0 && obj->body == NULL))
    {
        return CKR_ARGUMENTS_BAD;
    }

    /* Required size, accumulated so it cannot overflow the u32 length fields. */
    uint64_t need = P11O_HEADER_SIZE;
    if (obj->attr_count > 0xFFFFFFFFu || obj->body_len > 0xFFFFFFFFu)
    {
        return CKR_DATA_LEN_RANGE;
    }
    for (CK_ULONG i = 0; i < obj->attr_count; i++)
    {
        const azihsm_pkcs11_rec_attr *a = &obj->attrs[i];
        if (a->len > 0 && a->value == NULL)
        {
            return CKR_ARGUMENTS_BAD;
        }
        if (a->type > 0xFFFFFFFFu || a->len > 0xFFFFFFFFu)
        {
            return CKR_DATA_LEN_RANGE;
        }
        need += P11O_ATTR_HEADER_SIZE + (uint64_t)a->len;
    }
    need += (uint64_t)obj->body_len;
    if (need > 0xFFFFFFFFu) /* total_len is a u32 field */
    {
        return CKR_DATA_LEN_RANGE;
    }

    if (buf == NULL)
    {
        *len = (size_t)need;
        return CKR_OK;
    }
    if (*len < need)
    {
        return CKR_BUFFER_TOO_SMALL;
    }

    unsigned char *p = buf;
    memcpy(p, P11O_MAGIC, sizeof(P11O_MAGIC));
    p += sizeof(P11O_MAGIC);
    put_u16(p, P11_RECORD_VERSION);
    p += sizeof(uint16_t);
    put_u16(p, 0); /* reserved */
    p += sizeof(uint16_t);
    put_u32(p, (uint32_t)obj->attr_count);
    p += sizeof(uint32_t);
    put_u32(p, (uint32_t)obj->body_len);
    p += sizeof(uint32_t);
    put_u32(p, (uint32_t)need); /* total_len */
    p += sizeof(uint32_t);
    for (CK_ULONG i = 0; i < obj->attr_count; i++)
    {
        const azihsm_pkcs11_rec_attr *a = &obj->attrs[i];
        put_u32(p, (uint32_t)a->type);
        p += sizeof(uint32_t);
        put_u32(p, (uint32_t)a->len);
        p += sizeof(uint32_t);
        if (a->len > 0)
        {
            memcpy(p, a->value, a->len);
            p += a->len;
        }
    }
    if (obj->body_len > 0)
    {
        memcpy(p, obj->body, obj->body_len);
        p += obj->body_len;
    }
    *len = (size_t)need;
    return CKR_OK;
}

CK_RV azihsm_pkcs11_record_decode(
    const unsigned char *buf,
    size_t len,
    azihsm_pkcs11_rec_object *out
)
{
    if (buf == NULL || out == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(out, 0, sizeof(*out));
    if (len < P11O_HEADER_SIZE || memcmp(buf, P11O_MAGIC, sizeof(P11O_MAGIC)) != 0)
    {
        return CKR_FUNCTION_FAILED;
    }
    const unsigned char *hdr = buf + sizeof(P11O_MAGIC);
    uint16_t version = get_u16(hdr);
    hdr += sizeof(uint16_t);
    uint16_t reserved = get_u16(hdr);
    hdr += sizeof(uint16_t);
    uint32_t attr_count = get_u32(hdr);
    hdr += sizeof(uint32_t);
    uint32_t body_len = get_u32(hdr);
    hdr += sizeof(uint32_t);
    uint32_t total_len = get_u32(hdr);
    /* An unknown version or non-zero reserved field is a format we do not
     * understand; total_len must match exactly so trailing garbage is rejected. */
    if (version != P11_RECORD_VERSION || reserved != 0 || total_len != len)
    {
        return CKR_FUNCTION_FAILED;
    }
    /* Bound attr_count before allocating: each attribute is at least its header,
     * so it cannot exceed the remaining bytes / header size. */
    if (attr_count > (len - P11O_HEADER_SIZE) / P11O_ATTR_HEADER_SIZE)
    {
        return CKR_FUNCTION_FAILED;
    }

    azihsm_pkcs11_rec_attr *attrs = NULL;
    if (attr_count > 0)
    {
        attrs = (azihsm_pkcs11_rec_attr *)calloc(attr_count, sizeof(azihsm_pkcs11_rec_attr));
        if (attrs == NULL)
        {
            return CKR_HOST_MEMORY;
        }
    }

    size_t pos = P11O_HEADER_SIZE;
    for (uint32_t i = 0; i < attr_count; i++)
    {
        if (len - pos < P11O_ATTR_HEADER_SIZE)
        {
            free_attrs(attrs, i);
            return CKR_FUNCTION_FAILED;
        }
        uint32_t type = get_u32(buf + pos);
        pos += sizeof(uint32_t);
        uint32_t vlen = get_u32(buf + pos);
        pos += sizeof(uint32_t);
        if (len - pos < vlen)
        {
            free_attrs(attrs, i);
            return CKR_FUNCTION_FAILED;
        }
        attrs[i].type = type;
        attrs[i].len = vlen;
        if (vlen > 0)
        {
            attrs[i].value = (unsigned char *)malloc(vlen);
            if (attrs[i].value == NULL)
            {
                free_attrs(attrs, i); /* i's value not yet set; free 0..i-1 */
                return CKR_HOST_MEMORY;
            }
            memcpy(attrs[i].value, buf + pos, vlen);
            pos += vlen;
        }
    }
    /* Whatever remains must be exactly the declared body. */
    if (len - pos != body_len)
    {
        free_attrs(attrs, attr_count);
        return CKR_FUNCTION_FAILED;
    }
    unsigned char *body = NULL;
    if (body_len > 0)
    {
        body = (unsigned char *)malloc(body_len);
        if (body == NULL)
        {
            free_attrs(attrs, attr_count);
            return CKR_HOST_MEMORY;
        }
        memcpy(body, buf + pos, body_len);
    }

    out->attrs = attrs;
    out->attr_count = attr_count;
    out->body = body;
    out->body_len = body_len;
    return CKR_OK;
}

void azihsm_pkcs11_record_free(azihsm_pkcs11_rec_object *obj)
{
    if (obj == NULL)
    {
        return;
    }
    free_attrs(obj->attrs, obj->attr_count);
    if (obj->body != NULL)
    {
        memset(obj->body, 0, obj->body_len);
        free(obj->body);
    }
    memset(obj, 0, sizeof(*obj));
}

CK_RV azihsm_pkcs11_meta_encode(
    CK_ULONG next_handle,
    CK_ULONG generation,
    unsigned char *buf,
    size_t *len
)
{
    if (len == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (buf == NULL)
    {
        *len = P11_META_SIZE;
        return CKR_OK;
    }
    if (*len < P11_META_SIZE)
    {
        return CKR_BUFFER_TOO_SMALL;
    }
    unsigned char *p = buf;
    memcpy(p, P11M_MAGIC, sizeof(P11M_MAGIC));
    p += sizeof(P11M_MAGIC);
    put_u16(p, P11_RECORD_VERSION);
    p += sizeof(uint16_t);
    put_u16(p, 0); /* reserved */
    p += sizeof(uint16_t);
    put_u64(p, (uint64_t)next_handle);
    p += sizeof(uint64_t);
    put_u32(p, (uint32_t)generation);
    p += sizeof(uint32_t);
    put_u32(p, 0); /* reserved */
    *len = P11_META_SIZE;
    return CKR_OK;
}

CK_RV
azihsm_pkcs11_meta_decode(
    const unsigned char *buf,
    size_t len,
    CK_ULONG *next_handle,
    CK_ULONG *generation
)
{
    if (buf == NULL || next_handle == NULL || generation == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (len != P11_META_SIZE || memcmp(buf, P11M_MAGIC, sizeof(P11M_MAGIC)) != 0)
    {
        return CKR_FUNCTION_FAILED;
    }
    const unsigned char *p = buf + sizeof(P11M_MAGIC);
    uint16_t version = get_u16(p);
    p += sizeof(uint16_t);
    uint16_t reserved16 = get_u16(p);
    p += sizeof(uint16_t);
    uint64_t next = get_u64(p);
    p += sizeof(uint64_t);
    uint32_t generation32 = get_u32(p);
    p += sizeof(uint32_t);
    uint32_t reserved32 = get_u32(p);
    /* Validate every field before assigning the outputs. */
    if (version != P11_RECORD_VERSION || reserved16 != 0 || reserved32 != 0)
    {
        return CKR_FUNCTION_FAILED;
    }
    *next_handle = (CK_ULONG)next;
    *generation = (CK_ULONG)generation32;
    return CKR_OK;
}
