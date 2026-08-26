// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Module-global state, the general-purpose functions (C_Initialize / C_Finalize
 * / C_GetInfo), and small shared helpers.
 */

#include "azihsm_pkcs11_hsm.h"
#include "azihsm_pkcs11_internal.h"

#include <stdarg.h>
#include <stdlib.h>

azihsm_pkcs11_module_t g_azihsm_pkcs11 = {
    .initialized = false,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .next_session_handle = 1, /* 0 is CK_INVALID_HANDLE; handles are never reused */
};

void azihsm_pkcs11_lock(void)
{
    pthread_mutex_lock(&g_azihsm_pkcs11.lock);
}

void azihsm_pkcs11_unlock(void)
{
    pthread_mutex_unlock(&g_azihsm_pkcs11.lock);
}

void azihsm_pkcs11_log(const char *fmt, ...)
{
    static int enabled = -1;
    if (enabled < 0)
    {
        const char *e = getenv("AZIHSM_PKCS11_DEBUG");
        enabled = (e != NULL && e[0] == '1') ? 1 : 0;
    }
    if (!enabled)
    {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[azihsm-pkcs11] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

void azihsm_pkcs11_pad_str(CK_UTF8CHAR *dst, size_t dstlen, const char *src)
{
    size_t n = src ? strlen(src) : 0;
    if (n > dstlen)
    {
        n = dstlen;
    }
    if (n > 0)
    {
        memcpy(dst, src, n); /* skip when n == 0: memcpy(_, NULL, 0) with src == NULL is UB */
    }
    memset(dst + n, ' ', dstlen - n); /* PKCS#11 fixed-width fields are space-padded */
}

azihsm_pkcs11_session_t *azihsm_pkcs11_session_lookup(CK_SESSION_HANDLE h)
{
    if (h == CK_INVALID_HANDLE)
    {
        return NULL;
    }
    for (size_t i = 0; i < AZIHSM_PKCS11_MAX_SESSIONS; i++)
    {
        if (g_azihsm_pkcs11.sessions[i].in_use && g_azihsm_pkcs11.sessions[i].handle == h)
        {
            return &g_azihsm_pkcs11.sessions[i];
        }
    }
    return NULL;
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
    bool os_locking_ok = true;
    if (pInitArgs != NULL_PTR)
    {
        CK_C_INITIALIZE_ARGS_PTR args = (CK_C_INITIALIZE_ARGS_PTR)pInitArgs;
        if (args->pReserved != NULL_PTR)
        {
            return CKR_ARGUMENTS_BAD;
        }
        /* The four mutex callbacks must be all-NULL or all-set. */
        int n = (args->CreateMutex != NULL) + (args->DestroyMutex != NULL) +
                (args->LockMutex != NULL) + (args->UnlockMutex != NULL);
        if (n != 0 && n != 4)
        {
            return CKR_ARGUMENTS_BAD;
        }
        /* We always use native pthread locking, which covers the NULL and
         * CKF_OS_LOCKING_OK cases. Honouring caller-supplied mutexes with
         * CKF_OS_LOCKING_OK clear is a conformance follow-up. */
        os_locking_ok = (args->flags & CKF_OS_LOCKING_OK) != 0 || n == 0;
    }

    azihsm_pkcs11_lock();
    if (g_azihsm_pkcs11.initialized)
    {
        azihsm_pkcs11_unlock();
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    /* Commit global state only after we hold the lock and know we are the
     * initializing caller. */
    g_azihsm_pkcs11.os_locking_ok = os_locking_ok;

    memset(g_azihsm_pkcs11.slots, 0, sizeof(g_azihsm_pkcs11.slots));
    memset(g_azihsm_pkcs11.sessions, 0, sizeof(g_azihsm_pkcs11.sessions));
    g_azihsm_pkcs11.slot_count = 0;
    g_azihsm_pkcs11.next_session_handle = 1;

    /* Load module config (env-driven) before building the store: the persistent
     * file backend is opt-in via AZIHSM_PKCS11_PERSIST and needs its root dir;
     * unset keeps the in-memory backend, so the default path is unchanged. */
    azihsm_pkcs11_config cfg;
    azihsm_pkcs11_config_load(&cfg);
    CK_RV rv = cfg.store_persist ? azihsm_pkcs11_objstore_file_create(&g_azihsm_pkcs11.store, &cfg)
                                 : azihsm_pkcs11_objstore_mem_create(&g_azihsm_pkcs11.store);
    if (rv != CKR_OK)
    {
        azihsm_pkcs11_unlock();
        return rv;
    }

    int32_t n_slots = azihsm_pkcs11_hsm_enumerate_slots();
    if (n_slots < 0)
    {
        g_azihsm_pkcs11.store.ops->teardown(g_azihsm_pkcs11.store.ctx);
        g_azihsm_pkcs11.store.ctx = NULL;
        azihsm_pkcs11_unlock();
        AZIHSM_PKCS11_LOG("C_Initialize: slot enumeration failed");
        return CKR_FUNCTION_FAILED;
    }
    g_azihsm_pkcs11.slot_count = (CK_ULONG)n_slots;
    g_azihsm_pkcs11.initialized = true;
    azihsm_pkcs11_unlock();

    AZIHSM_PKCS11_LOG(
        "C_Initialize: OK (%d slot(s), os_locking=%d)",
        n_slots,
        (int)g_azihsm_pkcs11.os_locking_ok
    );
    return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
    if (pReserved != NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    azihsm_pkcs11_lock();
    if (!g_azihsm_pkcs11.initialized)
    {
        azihsm_pkcs11_unlock();
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    for (size_t i = 0; i < AZIHSM_PKCS11_MAX_SESSIONS; i++)
    {
        if (g_azihsm_pkcs11.sessions[i].in_use)
        {
            azihsm_pkcs11_session_reset_op(&g_azihsm_pkcs11.sessions[i]);
            g_azihsm_pkcs11.sessions[i].in_use = false;
        }
    }
    /* HSM login sessions are token-wide; close them per slot before closing the
     * partitions. */
    for (CK_ULONG i = 0; i < g_azihsm_pkcs11.slot_count; i++)
    {
        azihsm_pkcs11_hsm_logout(g_azihsm_pkcs11.slots[i].hsm_session);
        g_azihsm_pkcs11.slots[i].hsm_session = 0;
        g_azihsm_pkcs11.slots[i].user_logged_in = false;
        g_azihsm_pkcs11.slots[i].so_logged_in = false;
    }
    azihsm_pkcs11_hsm_close_all();
    if (g_azihsm_pkcs11.store.ctx != NULL)
    {
        /* Flush the store before tearing it down. Backends that write through
         * (or hold nothing durable) have nothing to do; persist is NULL on the
         * in-memory backend. It is a barrier, so its result does not change the
         * C_Finalize outcome. */
        if (g_azihsm_pkcs11.store.ops->persist != NULL)
        {
            (void)g_azihsm_pkcs11.store.ops->persist(g_azihsm_pkcs11.store.ctx);
        }
        g_azihsm_pkcs11.store.ops->teardown(g_azihsm_pkcs11.store.ctx);
        g_azihsm_pkcs11.store.ctx = NULL;
    }
    g_azihsm_pkcs11.initialized = false;
    azihsm_pkcs11_unlock();
    AZIHSM_PKCS11_LOG("C_Finalize: OK");
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
    if (!g_azihsm_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (pInfo == NULL_PTR)
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = AZIHSM_PKCS11_CK_MAJOR;
    pInfo->cryptokiVersion.minor = AZIHSM_PKCS11_CK_MINOR;
    azihsm_pkcs11_pad_str(
        pInfo->manufacturerID,
        sizeof(pInfo->manufacturerID),
        AZIHSM_PKCS11_MANUFACTURER
    );
    pInfo->flags = 0;
    azihsm_pkcs11_pad_str(
        pInfo->libraryDescription,
        sizeof(pInfo->libraryDescription),
        AZIHSM_PKCS11_LIBRARY_DESC
    );
    pInfo->libraryVersion.major = AZIHSM_PKCS11_LIB_MAJOR;
    pInfo->libraryVersion.minor = AZIHSM_PKCS11_LIB_MINOR;
    return CKR_OK;
}
