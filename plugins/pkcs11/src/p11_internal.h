// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "p11_compat.h"
#include "p11_objstore.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------------- */
/* Module identity                                                           */
/* ------------------------------------------------------------------------- */

#define AZIHSM_P11_MANUFACTURER "Microsoft Corporation"
#define AZIHSM_P11_LIBRARY_DESC "AZIHSM PKCS#11"
#define AZIHSM_P11_TOKEN_MODEL "AZIHSM"
#define AZIHSM_P11_SLOT_DESC "Azure Integrated HSM partition"

/* Cryptoki version reported from C_GetInfo / the 3.0 interface. */
#define AZIHSM_P11_CK_MAJOR 3
#define AZIHSM_P11_CK_MINOR 1
/* Legacy version reported through the classic CK_FUNCTION_LIST. */
#define AZIHSM_P11_CK_LEGACY_MAJOR 2
#define AZIHSM_P11_CK_LEGACY_MINOR 40
/* This module's own version. */
#define AZIHSM_P11_LIB_MAJOR 0
#define AZIHSM_P11_LIB_MINOR 1

#define AZIHSM_P11_MAX_SLOTS 16
#define AZIHSM_P11_MAX_SESSIONS 256

/* Advertised PIN length range (C_GetTokenInfo); the AZIHSM credential PIN is a
 * fixed 16-byte value. Enforced in C_Login. */
#define AZIHSM_P11_MIN_PIN_LEN 4
#define AZIHSM_P11_MAX_PIN_LEN 16

/* ------------------------------------------------------------------------- */
/* Logging (enable with env AZIHSM_PKCS11_DEBUG=1; off by default)           */
/* ------------------------------------------------------------------------- */

void azihsm_p11_log(const char *fmt, ...);
#define P11LOG(...) azihsm_p11_log(__VA_ARGS__)

/* ------------------------------------------------------------------------- */
/* Sessions                                                                  */
/* ------------------------------------------------------------------------- */

/* PKCS#11 allows at most one active operation of each kind per session. */
typedef enum
{
    P11_OP_NONE = 0,
    P11_OP_FIND,
    P11_OP_ENCRYPT,
    P11_OP_DECRYPT,
    P11_OP_DIGEST,
    P11_OP_SIGN,
    P11_OP_VERIFY,
} p11_op_type_t;

typedef struct
{
    bool in_use;
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot;
    CK_FLAGS flags; /* CKF_SERIAL_SESSION | CKF_RW_SESSION */
    CK_VOID_PTR app;
    CK_NOTIFY notify;

    p11_op_type_t op;
    void *op_ctx;      /* digest state while op == P11_OP_DIGEST */
    void *find_cursor; /* object-store cursor while op == P11_OP_FIND */
} p11_session_t;

/* ------------------------------------------------------------------------- */
/* Slots / tokens                                                            */
/* ------------------------------------------------------------------------- */

typedef struct
{
    bool present;           /* an AZIHSM partition exists for this slot */
    bool token_initialized; /* CKF_TOKEN_INITIALIZED */
    char device_path[512];  /* AZIHSM partition OS path (from part_get_info) */
    char label[64];
    char serial[24];
    uint16_t api_rev_major;
    uint16_t api_rev_minor;

    /* Login state lives on the token so it is shared across sessions. */
    bool so_logged_in;
    bool user_logged_in;

    /* AZIHSM partition handle, opened lazily at first login and reused; closed
     * at C_Finalize. 0 = not open. */
    uint32_t hsm_dev;

    /*
     * AZIHSM session handle for the token-wide login. PKCS#11 login state is
     * per-token, not per-session: this is opened by the C_Login that logs the
     * token in and closed by C_Logout, C_Finalize, or the close of the last
     * session on the slot — regardless of which session drives those calls.
     * 0 = not logged in.
     */
    uint32_t hsm_session;
} p11_slot_t;

/* ------------------------------------------------------------------------- */
/* Global module state                                                       */
/* ------------------------------------------------------------------------- */

typedef struct
{
    bool initialized;
    pthread_mutex_t lock; /* one coarse module lock; held across store calls */
    bool os_locking_ok;   /* from CK_C_INITIALIZE_ARGS */

    p11_slot_t slots[AZIHSM_P11_MAX_SLOTS];
    CK_ULONG slot_count;

    p11_session_t sessions[AZIHSM_P11_MAX_SESSIONS];
    CK_ULONG next_session_handle; /* monotonic, never reused */

    p11_objstore store; /* host object store behind the seam */
} p11_module_t;

extern p11_module_t g_p11;

void p11_lock(void);
void p11_unlock(void);

/* ------------------------------------------------------------------------- */
/* Shared helpers                                                            */
/* ------------------------------------------------------------------------- */

p11_session_t *p11_session_lookup(CK_SESSION_HANDLE h);
CK_RV p11_session_reset_op(p11_session_t *s);

/* Fill a fixed-width, space-padded CK_UTF8CHAR string field. */
void p11_pad_str(CK_UTF8CHAR *dst, size_t dstlen, const char *src);

/* The two shared function-list tables (defined in p11_dispatch.c). */
extern CK_FUNCTION_LIST azihsm_p11_function_list;         /* v2.40 view */
extern CK_FUNCTION_LIST_3_0 azihsm_p11_function_list_3_0; /* v3.x view  */
