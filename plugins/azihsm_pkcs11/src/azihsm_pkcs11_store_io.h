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
 * Filesystem primitives for the persistent object store (azihsm_pkcs11_objstore_file.c):
 * owner-only directory creation, crash-atomic whole-file writes, hardened reads,
 * and cross-process advisory locking. These mirror the provider's resiliency
 * store (plugins/ossl_prov/src/azihsm_ossl_resiliency.c) but stay in the CK_RV
 * domain and link no libcrypto, so the no-device smoke build still compiles.
 *
 * The framework holds the module lock across every store call, so these do no
 * in-process locking; azihsm_pkcs11_store_lock adds cross-PROCESS exclusion for the shared
 * directory.
 */

/* Longest single path component (a token directory or object file name). */
#define P11_STORE_MAX_NAME_LEN 256

/*
 * Largest single file read or written. Deliberately above the provider's 64 KiB
 * resiliency cap: an object record carries a full attribute template plus the
 * masked-blob key body (an RSA-4096 blob is several KiB), and cert objects can
 * be larger. Still bounded to resist a corrupt-length or disk-fill read.
 */
#define P11_STORE_MAX_FILE_SIZE (256 * 1024)

/*
 * Ensure directory `dir` exists with owner-only access: created 0700 when
 * absent; when present it must be a directory owned by the caller with no group
 * or other permission bits (rejected otherwise). The parent of `dir` must exist
 * (single-level create, as the provider's resiliency dir requires).
 */
CK_RV azihsm_pkcs11_store_dir_ensure(const char *dir);

/*
 * Join `dir` and a single flat component `name` into out[outlen] as "dir/name".
 * `name` must be a single path component: a name containing '/', equal to "..",
 * containing "../", empty, or too long is rejected (path-traversal defense).
 */
CK_RV azihsm_pkcs11_store_path_join(char *out, size_t outlen, const char *dir, const char *name);

/*
 * Atomically write `len` bytes to <dir>/<name>, mode 0600: write to a temp file,
 * fsync it, rename over the target, then fsync the directory. A crash leaves
 * either the previous content or the new content, never a partial file.
 * `data` may be NULL only when `len` is 0.
 */
CK_RV azihsm_pkcs11_store_write(
    const char *dir,
    const char *name,
    const unsigned char *data,
    size_t len
);

/*
 * Read the whole file <dir>/<name> into a freshly malloc'd buffer returned via
 * *out (caller frees) with its length in *len. A missing OR empty file is not an
 * error: *out is set NULL and *len 0 (mirrors the provider's file loader), so a
 * caller distinguishes absence by *out == NULL. A short read (torn write) is an
 * error, not a truncated buffer.
 */
CK_RV azihsm_pkcs11_store_read(const char *dir, const char *name, unsigned char **out, size_t *len);

/* Remove <dir>/<name>; a missing file is not an error (idempotent). */
CK_RV azihsm_pkcs11_store_unlink(const char *dir, const char *name);

/*
 * Acquire (blocking) the store's exclusive cross-process advisory lock via
 * flock(2) on <dir>/.lock. A fresh fd is opened per acquisition because flock
 * operates per open-file-description. On success *lock_fd holds the fd to hand
 * to azihsm_pkcs11_store_unlock.
 */
CK_RV azihsm_pkcs11_store_lock(const char *dir, int *lock_fd);

/* Release a lock taken by azihsm_pkcs11_store_lock and close its fd. No-op for fd < 0. */
void azihsm_pkcs11_store_unlock(int lock_fd);

#ifdef __cplusplus
}
#endif
