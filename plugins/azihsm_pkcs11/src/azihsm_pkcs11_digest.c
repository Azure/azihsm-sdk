// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Minimal, self-contained FIPS 180-4 implementations of SHA-1, SHA-256, and
 * SHA-512 (SHA-384 is SHA-512 with a different IV, truncated), behind the
 * mechanism-keyed operation API in azihsm_pkcs11_digest.h. See the header for
 * why these are host-side. Correctness is pinned by tests/digest_kat_test.c
 * (NIST example vectors, incl. multi-block and the million-'a' message).
 */

#include "azihsm_pkcs11_digest.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* SHA-1                                                                     */
/* ========================================================================= */

typedef struct
{
    uint32_t h[5];
    uint64_t len; /* total bytes */
    uint8_t buf[64];
    size_t buflen;
} sha1_ctx;

static uint32_t rol(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static void sha1_init(sha1_ctx *c)
{
    static const uint32_t iv[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
    memcpy(c->h, iv, sizeof(iv));
    c->len = 0;
    c->buflen = 0;
}

static void sha1_block(sha1_ctx *c, const uint8_t *p)
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
    {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | ((uint32_t)p[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++)
    {
        w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], e = c->h[4];
    for (int i = 0; i < 80; i++)
    {
        uint32_t f, k;
        if (i < 20)
        {
            f = (b & cc) | ((~b) & d);
            k = 0x5a827999;
        }
        else if (i < 40)
        {
            f = b ^ cc ^ d;
            k = 0x6ed9eba1;
        }
        else if (i < 60)
        {
            f = (b & cc) | (b & d) | (cc & d);
            k = 0x8f1bbcdc;
        }
        else
        {
            f = b ^ cc ^ d;
            k = 0xca62c1d6;
        }
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d;
        d = cc;
        cc = rol(b, 30);
        b = a;
        a = t;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
}

static void sha1_update(sha1_ctx *c, const uint8_t *data, size_t n)
{
    c->len += n;
    while (n > 0)
    {
        size_t take = 64 - c->buflen;
        if (take > n)
        {
            take = n;
        }
        memcpy(c->buf + c->buflen, data, take);
        c->buflen += take;
        data += take;
        n -= take;
        if (c->buflen == 64)
        {
            sha1_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha1_final(sha1_ctx *c, uint8_t out[20])
{
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha1_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56)
    {
        sha1_update(c, &zero, 1);
    }
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++)
    {
        lenb[i] = (uint8_t)(bits >> (56 - i * 8));
    }
    sha1_update(c, lenb, 8);
    for (int i = 0; i < 5; i++)
    {
        out[i * 4] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

/* ========================================================================= */
/* SHA-256                                                                   */
/* ========================================================================= */

typedef struct
{
    uint32_t h[8];
    uint64_t len; /* total bytes */
    uint8_t buf[64];
    size_t buflen;
} sha256_ctx;

static uint32_t ror(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static void sha256_init(sha256_ctx *c)
{
    static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memcpy(c->h, iv, sizeof(iv));
    c->len = 0;
    c->buflen = 0;
}

static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2
    };
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
    {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | ((uint32_t)p[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++)
    {
        uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint32_t e = c->h[4], f = c->h[5], g = c->h[6], hh = c->h[7];
    for (int i = 0; i < 64; i++)
    {
        uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = hh + S1 + ch + k[i] + w[i];
        uint32_t S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += hh;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t n)
{
    c->len += n;
    while (n > 0)
    {
        size_t take = 64 - c->buflen;
        if (take > n)
        {
            take = n;
        }
        memcpy(c->buf + c->buflen, data, take);
        c->buflen += take;
        data += take;
        n -= take;
        if (c->buflen == 64)
        {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56)
    {
        sha256_update(c, &zero, 1);
    }
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++)
    {
        lenb[i] = (uint8_t)(bits >> (56 - i * 8));
    }
    sha256_update(c, lenb, 8);
    for (int i = 0; i < 8; i++)
    {
        out[i * 4] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

/* ========================================================================= */
/* SHA-512 (also computes SHA-384: different IV, output truncated)           */
/* ========================================================================= */

typedef struct
{
    uint64_t h[8];
    uint64_t len; /* total bytes */
    uint8_t buf[128];
    size_t buflen;
} sha512_ctx;

static uint64_t ror64(uint64_t x, int n)
{
    return (x >> n) | (x << (64 - n));
}

static void sha512_init(sha512_ctx *c)
{
    static const uint64_t iv[8] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
                                    0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                                    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };
    memcpy(c->h, iv, sizeof(iv));
    c->len = 0;
    c->buflen = 0;
}

static void sha384_init(sha512_ctx *c)
{
    static const uint64_t iv[8] = { 0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
                                    0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
                                    0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4 };
    memcpy(c->h, iv, sizeof(iv));
    c->len = 0;
    c->buflen = 0;
}

static void sha512_block(sha512_ctx *c, const uint8_t *p)
{
    static const uint64_t k[80] = {
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    };
    uint64_t w[80];
    for (int i = 0; i < 16; i++)
    {
        w[i] = ((uint64_t)p[i * 8] << 56) | ((uint64_t)p[i * 8 + 1] << 48) |
               ((uint64_t)p[i * 8 + 2] << 40) | ((uint64_t)p[i * 8 + 3] << 32) |
               ((uint64_t)p[i * 8 + 4] << 24) | ((uint64_t)p[i * 8 + 5] << 16) |
               ((uint64_t)p[i * 8 + 6] << 8) | ((uint64_t)p[i * 8 + 7]);
    }
    for (int i = 16; i < 80; i++)
    {
        uint64_t s0 = ror64(w[i - 15], 1) ^ ror64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        uint64_t s1 = ror64(w[i - 2], 19) ^ ror64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint64_t e = c->h[4], f = c->h[5], g = c->h[6], hh = c->h[7];
    for (int i = 0; i < 80; i++)
    {
        uint64_t S1 = ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t t1 = hh + S1 + ch + k[i] + w[i];
        uint64_t S0 = ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39);
        uint64_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint64_t t2 = S0 + maj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += hh;
}

static void sha512_update(sha512_ctx *c, const uint8_t *data, size_t n)
{
    c->len += n;
    while (n > 0)
    {
        size_t take = 128 - c->buflen;
        if (take > n)
        {
            take = n;
        }
        memcpy(c->buf + c->buflen, data, take);
        c->buflen += take;
        data += take;
        n -= take;
        if (c->buflen == 128)
        {
            sha512_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

static void sha512_final(sha512_ctx *c, uint8_t out[64])
{
    /* The 128-bit message length: high word carries the bits shifted out of
     * len*8, so lengths beyond 2^61 bytes would still pad correctly. */
    uint64_t bits_hi = c->len >> 61;
    uint64_t bits_lo = c->len << 3;
    uint8_t pad = 0x80;
    sha512_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 112)
    {
        sha512_update(c, &zero, 1);
    }
    uint8_t lenb[16];
    for (int i = 0; i < 8; i++)
    {
        lenb[i] = (uint8_t)(bits_hi >> (56 - i * 8));
        lenb[8 + i] = (uint8_t)(bits_lo >> (56 - i * 8));
    }
    sha512_update(c, lenb, 16);
    for (int i = 0; i < 8; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            out[i * 8 + j] = (uint8_t)(c->h[i] >> (56 - j * 8));
        }
    }
}

/* ========================================================================= */
/* Mechanism-keyed operation API                                             */
/* ========================================================================= */

struct azihsm_pkcs11_digest_op
{
    CK_MECHANISM_TYPE mech;
    CK_ULONG len; /* digest size, bytes */
    union {
        sha1_ctx s1;
        sha256_ctx s256;
        sha512_ctx s512; /* SHA-384 and SHA-512 */
    } st;
};

CK_RV azihsm_pkcs11_digest_op_new(CK_MECHANISM_TYPE mech, azihsm_pkcs11_digest_op_t **out)
{
    CK_ULONG len;
    switch (mech)
    {
    case CKM_SHA_1:
        len = 20;
        break;
    case CKM_SHA256:
        len = 32;
        break;
    case CKM_SHA384:
        len = 48;
        break;
    case CKM_SHA512:
        len = 64;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }
    azihsm_pkcs11_digest_op_t *op = malloc(sizeof(*op));
    if (op == NULL)
    {
        return CKR_HOST_MEMORY;
    }
    op->mech = mech;
    op->len = len;
    switch (mech)
    {
    case CKM_SHA_1:
        sha1_init(&op->st.s1);
        break;
    case CKM_SHA256:
        sha256_init(&op->st.s256);
        break;
    case CKM_SHA384:
        sha384_init(&op->st.s512);
        break;
    default:
        sha512_init(&op->st.s512);
        break;
    }
    *out = op;
    return CKR_OK;
}

CK_ULONG azihsm_pkcs11_digest_op_len(const azihsm_pkcs11_digest_op_t *op)
{
    return op->len;
}

void azihsm_pkcs11_digest_op_update(
    azihsm_pkcs11_digest_op_t *op,
    const CK_BYTE *data,
    CK_ULONG len
)
{
    switch (op->mech)
    {
    case CKM_SHA_1:
        sha1_update(&op->st.s1, data, len);
        break;
    case CKM_SHA256:
        sha256_update(&op->st.s256, data, len);
        break;
    default:
        sha512_update(&op->st.s512, data, len);
        break;
    }
}

void azihsm_pkcs11_digest_op_final(azihsm_pkcs11_digest_op_t *op, CK_BYTE *out)
{
    /* The cores emit their full state; SHA-384 is the SHA-512 core truncated
     * to op->len (48) bytes. */
    uint8_t full[64];
    switch (op->mech)
    {
    case CKM_SHA_1:
        sha1_final(&op->st.s1, full);
        break;
    case CKM_SHA256:
        sha256_final(&op->st.s256, full);
        break;
    default:
        sha512_final(&op->st.s512, full);
        break;
    }
    memcpy(out, full, op->len);
}

void azihsm_pkcs11_digest_op_free(azihsm_pkcs11_digest_op_t *op)
{
    free(op);
}
