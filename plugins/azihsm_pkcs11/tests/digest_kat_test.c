// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Known-answer test for the host-side digests (src/azihsm_pkcs11_digest.c).
 * No device, no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src \
 *       digest_kat_test.c ../src/azihsm_pkcs11_digest.c -o digest_kat_test && ./digest_kat_test
 *
 * Vectors are the NIST FIPS 180-4 examples per algorithm (empty message, "abc",
 * the two multi-block messages, and the million-'a' message), each digested
 * one-shot and in several chunk sizes so the block-buffering paths are
 * exercised, plus the API edges (mechanism rejection, digest lengths).
 */

#include "azihsm_pkcs11_digest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
static int g_checks = 0;

#define CHECK(cond, msg)                                                                           \
    do                                                                                             \
    {                                                                                              \
        g_checks++;                                                                                \
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

typedef struct
{
    const char *name;
    const unsigned char *msg;
    size_t msg_len;
    const char *hex[4]; /* expected digests, indexed like g_mechs[] below */
} kat_vector;

static const CK_MECHANISM_TYPE g_mechs[4] = { CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512 };
static const char *g_mech_names[4] = { "SHA-1", "SHA-256", "SHA-384", "SHA-512" };

static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len)
{
    if (strlen(hex) != out_len * 2)
    {
        return -1;
    }
    for (size_t i = 0; i < out_len; i++)
    {
        unsigned int b = 0;
        if (sscanf(hex + i * 2, "%2x", &b) != 1)
        {
            return -1;
        }
        out[i] = (unsigned char)b;
    }
    return 0;
}

/* Digest msg with the op API, feeding chunk_len bytes per update (0 = a single
 * one-shot update); compare against the expected hex digest. */
static int kat_run(CK_MECHANISM_TYPE mech, const kat_vector *v, size_t chunk_len, const char *hex)
{
    azihsm_pkcs11_digest_op_t *op = NULL;
    if (azihsm_pkcs11_digest_op_new(mech, &op) != CKR_OK)
    {
        return 0;
    }
    if (chunk_len == 0)
    {
        azihsm_pkcs11_digest_op_update(op, v->msg, v->msg_len);
    }
    else
    {
        for (size_t off = 0; off < v->msg_len; off += chunk_len)
        {
            size_t take = v->msg_len - off;
            if (take > chunk_len)
            {
                take = chunk_len;
            }
            azihsm_pkcs11_digest_op_update(op, v->msg + off, take);
        }
    }
    unsigned char got[64];
    CK_ULONG len = azihsm_pkcs11_digest_op_len(op);
    azihsm_pkcs11_digest_op_final(op, got);
    azihsm_pkcs11_digest_op_free(op);

    unsigned char want[64];
    if (len > sizeof(want) || hex_to_bytes(hex, want, len) != 0)
    {
        return 0;
    }
    return memcmp(got, want, len) == 0;
}

int main(void)
{
    static const unsigned char two448[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    static const unsigned char two896[] =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    unsigned char *million = malloc(1000000);
    if (million == NULL)
    {
        printf("  FAIL : million-'a' allocation\n");
        return 1;
    }
    memset(million, 'a', 1000000);

    const kat_vector vectors[] = {
        { "empty",
          (const unsigned char *)"",
          0,
          { "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
            "274edebfe76f65fbd51ad2f14898b95b",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" } },
        { "abc",
          (const unsigned char *)"abc",
          3,
          { "a9993e364706816aba3e25717850c26c9cd0d89d",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" } },
        { "448-bit two-block",
          two448,
          sizeof(two448) - 1,
          { "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6"
            "b0455a8520bc4e6f5fe95b1fe3c8452b",
            "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
            "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445" } },
        { "896-bit two-block",
          two896,
          sizeof(two896) - 1,
          { "a49b2446a02c645bf419f995b67091253a04a259",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
            "fcc7c71a557e2db966c3e9fa91746039",
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
            "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" } },
        { "million-'a'",
          million,
          1000000,
          { "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b"
            "07b8b3dc38ecc4ebae97ddd87f3d8985",
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
            "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b" } },
    };
    /* 0 = one-shot; the rest straddle the 64/128-byte block boundaries. */
    const size_t chunk_lens[] = { 0, 1, 7, 64, 127, 997 };

    printf("digest KAT (NIST FIPS 180-4 vectors)\n");
    char msg[128];
    for (size_t m = 0; m < 4; m++)
    {
        for (size_t vi = 0; vi < sizeof(vectors) / sizeof(vectors[0]); vi++)
        {
            const kat_vector *v = &vectors[vi];
            int ok = 1;
            for (size_t ci = 0; ci < sizeof(chunk_lens) / sizeof(chunk_lens[0]); ci++)
            {
                if (!kat_run(g_mechs[m], v, chunk_lens[ci], v->hex[m]))
                {
                    ok = 0;
                }
            }
            snprintf(msg, sizeof(msg), "%s(%s) one-shot + chunked", g_mech_names[m], v->name);
            CHECK(ok, msg);
        }
    }

    /* API edges. */
    azihsm_pkcs11_digest_op_t *op = NULL;
    CHECK(
        azihsm_pkcs11_digest_op_new(CKM_MD5, &op) == CKR_MECHANISM_INVALID && op == NULL,
        "non-digest mechanism rejected as CKR_MECHANISM_INVALID"
    );
    CHECK(
        azihsm_pkcs11_digest_op_new(CKM_AES_CBC, &op) == CKR_MECHANISM_INVALID && op == NULL,
        "cipher mechanism rejected as CKR_MECHANISM_INVALID"
    );
    const CK_ULONG want_len[4] = { 20, 32, 48, 64 };
    for (size_t m = 0; m < 4; m++)
    {
        int ok = azihsm_pkcs11_digest_op_new(g_mechs[m], &op) == CKR_OK &&
                 azihsm_pkcs11_digest_op_len(op) == want_len[m];
        azihsm_pkcs11_digest_op_free(op);
        op = NULL;
        snprintf(msg, sizeof(msg), "%s digest length is %lu", g_mech_names[m], want_len[m]);
        CHECK(ok, msg);
    }
    azihsm_pkcs11_digest_op_free(NULL); /* must be a no-op */
    CHECK(1, "freeing a NULL op is a no-op");

    free(million);
    printf(g_fail ? "\nDIGEST KAT FAIL (%d checks)\n" : "\nDIGEST KAT OK (%d checks)\n", g_checks);
    return g_fail;
}
