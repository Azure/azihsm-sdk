// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Standalone unit test for the object-store filesystem primitives
 * (src/azihsm_pkcs11_store_io.c). Builds and links directly against that source, no
 * device and no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src \
 *       store_io_test.c ../src/azihsm_pkcs11_store_io.c -o store_io_test && ./store_io_test
 *
 * Covers: directory create + owner-only verification, path-traversal rejection,
 * atomic write (0600, no leftover temp), read + two-call absence semantics,
 * idempotent unlink, oversize rejection, and cross-process exclusion via the
 * advisory lock (K children each doing M locked read-modify-writes must total
 * exactly K*M — a non-exclusive lock would lose updates).
 */

#define _DEFAULT_SOURCE

#include "azihsm_pkcs11_store_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

static mode_t file_mode(const char *dir, const char *name)
{
    char path[8192];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    struct stat st;
    if (stat(path, &st) != 0)
    {
        return 0;
    }
    return st.st_mode & 07777;
}

static int file_exists(const char *dir, const char *name)
{
    char path[8192];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    struct stat st;
    return stat(path, &st) == 0;
}

/* One child: M iterations of lock -> read counter -> +1 -> write -> unlock. */
static void child_increment(const char *dir, int iters)
{
    for (int i = 0; i < iters; i++)
    {
        int fd = -1;
        if (azihsm_pkcs11_store_lock(dir, &fd) != CKR_OK)
        {
            _exit(2);
        }
        unsigned char *buf = NULL;
        size_t len = 0;
        size_t val = 0;
        if (azihsm_pkcs11_store_read(dir, "counter", &buf, &len) != CKR_OK)
        {
            azihsm_pkcs11_store_unlock(fd);
            _exit(3);
        }
        if (buf != NULL && len == sizeof(val))
        {
            memcpy(&val, buf, sizeof(val));
        }
        free(buf);
        val++;
        /* Widen the read-modify-write window so a missing lock would race. */
        usleep(200);
        if (azihsm_pkcs11_store_write(dir, "counter", (unsigned char *)&val, sizeof(val)) != CKR_OK)
        {
            azihsm_pkcs11_store_unlock(fd);
            _exit(4);
        }
        azihsm_pkcs11_store_unlock(fd);
    }
    _exit(0);
}

int main(void)
{
    char root[] = "/tmp/azihsm_pkcs11_store_io_test.XXXXXX";
    if (mkdtemp(root) == NULL)
    {
        perror("mkdtemp");
        return 1;
    }
    char store[4096];
    snprintf(store, sizeof(store), "%s/store", root);
    printf("== store dir: %s ==\n", store);

    /* dir_ensure: create then idempotent, 0700. */
    CHECK(azihsm_pkcs11_store_dir_ensure(store) == CKR_OK, "dir_ensure creates the store dir");
    CHECK(azihsm_pkcs11_store_dir_ensure(store) == CKR_OK, "dir_ensure is idempotent when present");
    struct stat dst;
    CHECK(stat(store, &dst) == 0 && (dst.st_mode & 07777) == 0700, "store dir is 0700");

    /* path_join rejects traversal / separators, accepts a flat name. */
    char out[4608];
    CHECK(
        azihsm_pkcs11_store_path_join(out, sizeof(out), store, "obj1") == CKR_OK,
        "path_join accepts flat name"
    );
    CHECK(
        azihsm_pkcs11_store_path_join(out, sizeof(out), store, "a/b") == CKR_ARGUMENTS_BAD,
        "path_join rejects '/'"
    );
    CHECK(
        azihsm_pkcs11_store_path_join(out, sizeof(out), store, "..") == CKR_ARGUMENTS_BAD,
        "path_join rejects '..'"
    );
    CHECK(
        azihsm_pkcs11_store_path_join(out, sizeof(out), store, "../x") == CKR_ARGUMENTS_BAD,
        "path_join rejects '../x'"
    );
    CHECK(
        azihsm_pkcs11_store_path_join(out, sizeof(out), store, "") == CKR_ARGUMENTS_BAD,
        "path_join rejects empty"
    );

    /* write + read round-trip, 0600, no leftover temp. */
    unsigned char payload[100];
    for (int i = 0; i < 100; i++)
    {
        payload[i] = (unsigned char)(i * 7 + 1);
    }
    CHECK(
        azihsm_pkcs11_store_write(store, "obj1", payload, sizeof(payload)) == CKR_OK,
        "write obj1"
    );
    CHECK(file_mode(store, "obj1") == 0600, "obj1 is 0600");
    CHECK(!file_exists(store, ".obj1.tmp"), "no leftover temp after write");
    unsigned char *rd = NULL;
    size_t rdlen = 0;
    CHECK(
        azihsm_pkcs11_store_read(store, "obj1", &rd, &rdlen) == CKR_OK && rd != NULL &&
            rdlen == sizeof(payload) && memcmp(rd, payload, sizeof(payload)) == 0,
        "read obj1 round-trips"
    );
    free(rd);

    /* missing file: CKR_OK with out == NULL (absence, not error). */
    rd = (unsigned char *)1;
    rdlen = 99;
    CHECK(
        azihsm_pkcs11_store_read(store, "nope", &rd, &rdlen) == CKR_OK && rd == NULL && rdlen == 0,
        "read of missing file is absence, not error"
    );

    /* rewrite (overwrite) then unlink idempotently. */
    CHECK(
        azihsm_pkcs11_store_write(store, "obj1", payload, 10) == CKR_OK,
        "overwrite obj1 (shorter)"
    );
    CHECK(
        azihsm_pkcs11_store_read(store, "obj1", &rd, &rdlen) == CKR_OK && rdlen == 10,
        "overwrite took effect"
    );
    free(rd);
    CHECK(azihsm_pkcs11_store_unlink(store, "obj1") == CKR_OK, "unlink obj1");
    CHECK(
        azihsm_pkcs11_store_read(store, "obj1", &rd, &rdlen) == CKR_OK && rd == NULL,
        "obj1 gone after unlink"
    );
    CHECK(azihsm_pkcs11_store_unlink(store, "obj1") == CKR_OK, "unlink is idempotent");

    /* oversize write rejected. */
    size_t big = P11_STORE_MAX_FILE_SIZE + 1;
    unsigned char *bigbuf = (unsigned char *)calloc(1, big);
    CHECK(
        bigbuf != NULL &&
            azihsm_pkcs11_store_write(store, "big", bigbuf, big) == CKR_DATA_LEN_RANGE,
        "oversize write rejected"
    );
    free(bigbuf);

    /* cross-process exclusion: K children * M locked increments == K*M. */
    const int K = 4, M = 50;
    size_t zero = 0;
    CHECK(
        azihsm_pkcs11_store_write(store, "counter", (unsigned char *)&zero, sizeof(zero)) == CKR_OK,
        "counter initialized to 0"
    );
    for (int k = 0; k < K; k++)
    {
        pid_t pid = fork();
        if (pid == 0)
        {
            child_increment(store, M);
        }
    }
    int status = 0, kids_ok = 1;
    for (int k = 0; k < K; k++)
    {
        int st = 0;
        wait(&st);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
        {
            kids_ok = 0;
        }
    }
    (void)status;
    CHECK(kids_ok, "all lock children exited cleanly");
    unsigned char *cbuf = NULL;
    size_t clen = 0;
    size_t total = 0;
    if (azihsm_pkcs11_store_read(store, "counter", &cbuf, &clen) == CKR_OK && cbuf != NULL &&
        clen == sizeof(total))
    {
        memcpy(&total, cbuf, sizeof(total));
    }
    free(cbuf);
    printf("  counter total = %zu (expect %d)\n", total, K * M);
    CHECK(
        total == (size_t)(K * M),
        "cross-process lock serialized all increments (no lost updates)"
    );

    printf(g_fail ? "\nSTORE_IO FAIL\n" : "\nSTORE_IO OK\n");
    return g_fail;
}
