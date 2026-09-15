// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Standalone unit test for the object-record codec (src/azihsm_pkcs11_store_record.c).
 * No device, no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src \
 *       record_test.c ../src/azihsm_pkcs11_store_record.c -o record_test && ./record_test
 *
 * Covers: two-call sizing, encode/decode round-trip (attrs incl. zero-length,
 * plus a masked-blob body), the empty object, buffer-too-small, and that decode
 * rejects a bad magic / version / reserved / truncation / trailing-garbage /
 * inconsistent length rather than misreading it. Also the P11M meta codec.
 */

#include "azihsm_pkcs11_store_record.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Encode obj into a freshly malloc'd buffer via the two-call path. */
static unsigned char *encode_alloc(const azihsm_pkcs11_rec_object *obj, size_t *out_len)
{
    size_t need = 0;
    if (azihsm_pkcs11_record_encode(obj, NULL, &need) != CKR_OK)
    {
        return NULL;
    }
    unsigned char *buf = (unsigned char *)malloc(need ? need : 1);
    if (buf == NULL)
    {
        return NULL;
    }
    size_t len = need;
    if (azihsm_pkcs11_record_encode(obj, buf, &len) != CKR_OK || len != need)
    {
        free(buf);
        return NULL;
    }
    *out_len = need;
    return buf;
}

static int attrs_equal(const azihsm_pkcs11_rec_object *a, const azihsm_pkcs11_rec_object *b)
{
    if (a->attr_count != b->attr_count || a->body_len != b->body_len)
    {
        return 0;
    }
    for (CK_ULONG i = 0; i < a->attr_count; i++)
    {
        if (a->attrs[i].type != b->attrs[i].type || a->attrs[i].len != b->attrs[i].len)
        {
            return 0;
        }
        if (a->attrs[i].len > 0 &&
            memcmp(a->attrs[i].value, b->attrs[i].value, a->attrs[i].len) != 0)
        {
            return 0;
        }
    }
    if (a->body_len > 0 && memcmp(a->body, b->body, a->body_len) != 0)
    {
        return 0;
    }
    return 1;
}

int main(void)
{
    /* An object with a bool, a "ulong", a byte-string, a zero-length attr, and a
     * masked-blob body. */
    CK_BBOOL tval = CK_TRUE;
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    unsigned char label[] = "my-key-label";
    unsigned char body[300];
    for (int i = 0; i < 300; i++)
    {
        body[i] = (unsigned char)(i * 3 + 5);
    }
    azihsm_pkcs11_rec_attr in_attrs[] = {
        { CKA_CLASS, (unsigned char *)&cls, sizeof(cls) },
        { CKA_TOKEN, &tval, sizeof(tval) },
        { CKA_LABEL, label, (CK_ULONG)strlen((char *)label) },
        { CKA_ID, NULL, 0 }, /* zero-length attribute */
    };
    azihsm_pkcs11_rec_object in = { in_attrs, 4, body, sizeof(body) };

    size_t enc_len = 0;
    unsigned char *enc = encode_alloc(&in, &enc_len);
    CHECK(enc != NULL, "two-call encode");

    azihsm_pkcs11_rec_object dec;
    CHECK(azihsm_pkcs11_record_decode(enc, enc_len, &dec) == CKR_OK, "decode ok");
    CHECK(attrs_equal(&in, &dec), "round-trip identical (attrs + body)");
    CHECK(dec.attrs[3].len == 0 && dec.attrs[3].value == NULL, "zero-length attr decodes to NULL");
    azihsm_pkcs11_record_free(&dec);

    /* buffer-too-small on the fill call. */
    size_t small = enc_len - 1;
    unsigned char *tiny = (unsigned char *)malloc(small);
    CHECK(
        azihsm_pkcs11_record_encode(&in, tiny, &small) == CKR_BUFFER_TOO_SMALL,
        "encode rejects short buffer"
    );
    free(tiny);

    /* empty object (no attrs, no body). */
    azihsm_pkcs11_rec_object empty = { NULL, 0, NULL, 0 };
    size_t elen = 0;
    unsigned char *ebuf = encode_alloc(&empty, &elen);
    azihsm_pkcs11_rec_object edec;
    CHECK(
        ebuf && azihsm_pkcs11_record_decode(ebuf, elen, &edec) == CKR_OK && edec.attr_count == 0 &&
            edec.body_len == 0,
        "empty object round-trips"
    );
    azihsm_pkcs11_record_free(&edec);

    /* corruption rejections (each mutates a fresh copy). */
    unsigned char *c = (unsigned char *)malloc(enc_len);
    azihsm_pkcs11_rec_object junk;

    memcpy(c, enc, enc_len);
    c[0] = 'X'; /* magic */
    CHECK(azihsm_pkcs11_record_decode(c, enc_len, &junk) != CKR_OK, "decode rejects bad magic");

    memcpy(c, enc, enc_len);
    c[4] = 2; /* version */
    CHECK(
        azihsm_pkcs11_record_decode(c, enc_len, &junk) != CKR_OK,
        "decode rejects unknown version"
    );

    memcpy(c, enc, enc_len);
    c[6] = 1; /* reserved (offset 6..7) */
    CHECK(
        azihsm_pkcs11_record_decode(c, enc_len, &junk) != CKR_OK,
        "decode rejects non-zero reserved"
    );

    memcpy(c, enc, enc_len);
    CHECK(
        azihsm_pkcs11_record_decode(c, enc_len - 1, &junk) != CKR_OK,
        "decode rejects truncation (len mismatch)"
    );

    memcpy(c, enc, enc_len);
    c[8] = 0xFF; /* attr_count huge */
    CHECK(
        azihsm_pkcs11_record_decode(c, enc_len, &junk) != CKR_OK,
        "decode rejects oversized attr_count"
    );
    free(c);

    /* one extra trailing byte -> total_len mismatch. */
    unsigned char *ext = (unsigned char *)malloc(enc_len + 1);
    memcpy(ext, enc, enc_len);
    ext[enc_len] = 0;
    CHECK(
        azihsm_pkcs11_record_decode(ext, enc_len + 1, &junk) != CKR_OK,
        "decode rejects trailing garbage"
    );
    free(ext);
    free(ebuf);
    free(enc);

    /* meta (P11M) round-trip + rejection. */
    unsigned char mbuf[P11_META_SIZE];
    size_t mlen = sizeof(mbuf);
    CHECK(
        azihsm_pkcs11_meta_encode(0x1122334455667788ULL, 42, mbuf, &mlen) == CKR_OK &&
            mlen == P11_META_SIZE,
        "meta encode"
    );
    CK_ULONG nh = 0, gen = 0;
    CHECK(
        azihsm_pkcs11_meta_decode(mbuf, sizeof(mbuf), &nh, &gen) == CKR_OK &&
            nh == 0x1122334455667788ULL && gen == 42,
        "meta round-trips next_handle + generation"
    );
    mbuf[0] = 'Z';
    CHECK(
        azihsm_pkcs11_meta_decode(mbuf, sizeof(mbuf), &nh, &gen) != CKR_OK,
        "meta decode rejects bad magic"
    );

    printf(g_fail ? "\nRECORD FAIL\n" : "\nRECORD OK\n");
    return g_fail;
}
