// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Multi-process stress test for the persistent object-store backend
 * (src/azihsm_pkcs11_objstore_file.c). No device, no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src objstore_stress_test.c \
 *       ../src/azihsm_pkcs11_objstore_file.c ../src/azihsm_pkcs11_objstore_mem.c \
 *       ../src/azihsm_pkcs11_store_io.c ../src/azihsm_pkcs11_store_record.c -o objstore_stress_test
 * -lpthread
 *
 * N worker processes each create M token objects in the same slot directory of
 * a shared store; the parent then enumerates and must see exactly N*M objects.
 * If the counter-first allocation or the cross-process flock were wrong, two
 * creates would collide on a handle number and overwrite one another, so the
 * final count would be short — this asserts none are lost and every record is
 * intact (find decodes each one).
 */

#include "azihsm_pkcs11_objstore.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define N_WORKERS 4
#define PER_WORKER 25

static CK_BBOOL ck_false = CK_FALSE;
static CK_BBOOL ck_true = CK_TRUE;

/* Create one public token DATA object with a per-worker/index unique label. */
static CK_RV create_one(azihsm_pkcs11_objstore *s, CK_SLOT_ID slot, int worker, int idx)
{
    char label[32];
    int n = snprintf(label, sizeof(label), "w%d-obj%d", worker, idx);
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_TOKEN, &ck_true, sizeof(CK_BBOOL) },
        { CKA_PRIVATE, &ck_false, sizeof(CK_BBOOL) },
        { CKA_LABEL, label, (CK_ULONG)n },
    };
    CK_OBJECT_HANDLE h = 0;
    return s->ops->create(s->ctx, slot, CK_FALSE, tmpl, 4, &h);
}

int main(void)
{
    char root[] = "/tmp/azihsm_pkcs11_objstore_stress.XXXXXX";
    if (mkdtemp(root) == NULL)
    {
        perror("mkdtemp");
        return 1;
    }
    azihsm_pkcs11_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.store_dir, sizeof(cfg.store_dir), "%s", root);
    cfg.store_persist = true;
    const CK_SLOT_ID SLOT = 0;

    /* Ensure the store (and, via the first creator, the token dir) exists before
     * forking, so all workers contend on the same directory and lock. */
    azihsm_pkcs11_objstore seed;
    if (azihsm_pkcs11_objstore_file_create(&seed, &cfg) != CKR_OK)
    {
        fprintf(stderr, "seed store create failed\n");
        return 1;
    }
    seed.ops->teardown(seed.ctx);

    for (int w = 0; w < N_WORKERS; w++)
    {
        pid_t pid = fork();
        if (pid == 0)
        {
            azihsm_pkcs11_objstore s;
            if (azihsm_pkcs11_objstore_file_create(&s, &cfg) != CKR_OK)
            {
                _exit(2);
            }
            int rc = 0;
            for (int i = 0; i < PER_WORKER; i++)
            {
                if (create_one(&s, SLOT, w, i) != CKR_OK)
                {
                    rc = 3;
                    break;
                }
            }
            s.ops->teardown(s.ctx);
            _exit(rc);
        }
    }
    int workers_ok = 1;
    for (int w = 0; w < N_WORKERS; w++)
    {
        int st = 0;
        wait(&st);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
        {
            workers_ok = 0;
        }
    }

    /* Enumerate everything the workers created. */
    azihsm_pkcs11_objstore s;
    if (azihsm_pkcs11_objstore_file_create(&s, &cfg) != CKR_OK)
    {
        fprintf(stderr, "final store create failed\n");
        return 1;
    }
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_ATTRIBUTE q[] = { { CKA_CLASS, &cls, sizeof(cls) } };
    void *cur = NULL;
    CK_ULONG total = 0;
    if (s.ops->find_init(s.ctx, SLOT, CK_FALSE, q, 1, &cur) == CKR_OK)
    {
        for (;;)
        {
            CK_OBJECT_HANDLE batch[64];
            CK_ULONG got = 0;
            if (s.ops->find(s.ctx, cur, batch, 64, &got) != CKR_OK || got == 0)
            {
                break;
            }
            total += got;
        }
        s.ops->find_final(s.ctx, cur);
    }
    s.ops->teardown(s.ctx);

    int expected = N_WORKERS * PER_WORKER;
    printf("workers_ok=%d  found=%lu  expected=%d\n", workers_ok, (unsigned long)total, expected);
    int ok = workers_ok && total == (CK_ULONG)expected;
    printf(ok ? "STRESS OK\n" : "STRESS FAIL\n");
    return ok ? 0 : 1;
}
