// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Resiliency callbacks for the AZIHSM OpenSSL provider.
 *
 * Implements three callback interfaces required by the AZIHSM resiliency
 * layer so that the HSM partition can transparently recover from resiliency events such as
 * live migration and firmware crash recovery:
 *
 *   1. Storage   – file-backed key-value store under a configurable
 *                  directory (read / write / clear).
 *   2. Lock      – cross-process mutual exclusion via flock(2) on a
 *                  dedicated lock file.
 *   3. POTA      – re-endorsement of the device's PID public key with
 *                  the provider's fixed POTA private key.
 */

#include "azihsm_ossl_resiliency.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "azihsm_ossl_file_io.h"
#include "azihsm_ossl_hsm.h"

/* ------------------------------------------------------------------ */
/*  Internal constants                                                 */
/* ------------------------------------------------------------------ */

// Maximum allowed key name length (defensive bound).
#define MAX_KEY_NAME_LEN 256

// Maximum data file size we are willing to read (64 KiB).
#define MAX_STORAGE_FILE_SIZE (64 * 1024)

// Absolute path buffer size: storage_dir (4096) + '/' (1) + key name (256) + '\0' (1).
#define PATH_BUF_SIZE 4354

// POTA signature: P-384 raw r||s (48 + 48).
#define POTA_SIGNATURE_SIZE 96

/* ------------------------------------------------------------------ */
/*  Resiliency context (opaque to callers)                             */
/* ------------------------------------------------------------------ */

struct azihsm_resiliency_ctx
{
    char storage_dir[4096];                    /* Base directory for storage files */
    char pota_priv_path[AZIHSM_MAX_FILE_PATH]; /* POTA private key DER file */
    char pota_pub_path[AZIHSM_MAX_FILE_PATH];  /* POTA public key DER file */
    char lock_path[PATH_BUF_SIZE];             /* Path to the lock file */
    int lock_fd;                               /* Held fd during lock (-1 when unlocked) */
    CRYPTO_RWLOCK *lock_fd_lock;               /* Protects lock_fd from concurrent access */
    struct azihsm_pota_callback_ops pota_ops;  /* POTA ops owned by ctx */
};

/* ------------------------------------------------------------------ */
/*  Helper: build a storage file path from directory + key             */
/* ------------------------------------------------------------------ */

/*
 * Constructs "<storage_dir>/<key>" in the caller-provided buffer.
 * Returns AZIHSM_STATUS_SUCCESS on success.
 * Returns AZIHSM_STATUS_INVALID_ARGUMENT if the key contains path-
 * traversal characters ('/' or "..") or is empty / too long.
 * Returns AZIHSM_STATUS_INTERNAL_ERROR if the path would be truncated.
 */
static azihsm_status build_storage_path(
    const char *storage_dir,
    const char *key,
    char *path_buf,
    size_t path_buf_size
)
{
    size_t key_len;
    int written;

    if (storage_dir == NULL || key == NULL || key[0] == '\0' || path_buf == NULL ||
        path_buf_size == 0)
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    key_len = strnlen(key, MAX_KEY_NAME_LEN + 1);
    if (key_len > MAX_KEY_NAME_LEN)
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    /* Reject path-traversal attempts: block '/' and ".." as a path component.
     * A bare ".." or a substring "../" would allow escaping storage_dir. */
    if (strchr(key, '/') != NULL || strcmp(key, "..") == 0 || strstr(key, "../") != NULL)
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    written = snprintf(path_buf, path_buf_size, "%s/%s", storage_dir, key);
    if (written < 0 || (size_t)written >= path_buf_size)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    return AZIHSM_STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Storage callbacks                                                  */
/* ------------------------------------------------------------------ */

/*
 * Read the value associated with `key` from the file system.
 *
 * Implements the two-call buffer pattern expected by the Rust adapter:
 *   - First call (value->ptr == NULL): sets value->len to the required
 *     size and returns AZIHSM_STATUS_BUFFER_TOO_SMALL.
 *   - Second call (value->ptr != NULL, value->len >= required): reads
 *     the file contents into value->ptr and updates value->len.
 *
 * Returns AZIHSM_STATUS_NOT_FOUND when the file does not exist.
 */
static azihsm_status resiliency_storage_read(
    void *ctx_ptr,
    const char *key,
    struct azihsm_buffer *value
)
{
    struct azihsm_resiliency_ctx *ctx = (struct azihsm_resiliency_ctx *)ctx_ptr;
    char path[PATH_BUF_SIZE];
    struct stat st;
    azihsm_status status;
    int fd = -1;
    size_t bytes_read;

    if (ctx == NULL || value == NULL)
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    status = build_storage_path(ctx->storage_dir, key, path, sizeof(path));
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        return status;
    }

    // Open the file without following symlinks to avoid TOCTOU on the path.
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
    {
        if (errno == ENOENT)
        {
            return AZIHSM_STATUS_NOT_FOUND;
        }
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Get file metadata from the opened descriptor.
    if (fstat(fd, &st) != 0)
    {
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Reject non-regular files (directories, FIFOs, device nodes, etc.)
    if (!S_ISREG(st.st_mode))
    {
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Reject unexpectedly large files
    if (st.st_size < 0 || (unsigned long)st.st_size > MAX_STORAGE_FILE_SIZE)
    {
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Two-call pattern: if output buffer is NULL, return required size
    if (value->ptr == NULL)
    {
        close(fd);
        value->len = (uint32_t)st.st_size;
        return AZIHSM_STATUS_BUFFER_TOO_SMALL;
    }

    // Zero-length file: nothing to read
    if (st.st_size == 0)
    {
        close(fd);
        value->len = 0;
        return AZIHSM_STATUS_SUCCESS;
    }

    // Output buffer provided but too small
    if ((uint32_t)st.st_size > value->len)
    {
        close(fd);
        value->len = (uint32_t)st.st_size;
        return AZIHSM_STATUS_BUFFER_TOO_SMALL;
    }

    // Read file contents using read() with EINTR retry, matching the write path
    bytes_read = 0;
    while (bytes_read < (size_t)st.st_size)
    {
        ssize_t n = read(fd, (char *)value->ptr + bytes_read, (size_t)st.st_size - bytes_read);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            close(fd);
            return AZIHSM_STATUS_INTERNAL_ERROR;
        }
        if (n == 0)
        {
            break; // unexpected EOF
        }
        bytes_read += (size_t)n;
    }
    close(fd);

    if (bytes_read != (size_t)st.st_size)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    value->len = (uint32_t)bytes_read;
    return AZIHSM_STATUS_SUCCESS;
}

/*
 * Write `value` to the file identified by `key`.
 *
 * Uses atomic write-to-temp + fsync + rename so that a concurrent
 * reader (or a crash mid-write) never sees a partially-written file.
 * The old value is preserved if the write fails.
 */
static azihsm_status resiliency_storage_write(
    void *ctx_ptr,
    const char *key,
    const struct azihsm_buffer *value
)
{
    struct azihsm_resiliency_ctx *ctx = (struct azihsm_resiliency_ctx *)ctx_ptr;
    char path[PATH_BUF_SIZE];
    char tmp_path[PATH_BUF_SIZE];
    azihsm_status status;
    int fd = -1;
    int written;
    size_t bytes_written;

    if (ctx == NULL || value == NULL || value->ptr == NULL)
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    if (value->len > MAX_STORAGE_FILE_SIZE)
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    status = build_storage_path(ctx->storage_dir, key, path, sizeof(path));
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        return status;
    }

    // Build temp path: "<storage_dir>/.<key>.tmp"
    written = snprintf(tmp_path, sizeof(tmp_path), "%s/.%s.tmp", ctx->storage_dir, key);
    if (written < 0 || (size_t)written >= sizeof(tmp_path))
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Open temp file for writing (owner-only, no symlink follow).
    fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    bytes_written = 0;
    while (bytes_written < value->len)
    {
        ssize_t n = write(fd, (const char *)value->ptr + bytes_written, value->len - bytes_written);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            close(fd);
            unlink(tmp_path);
            return AZIHSM_STATUS_INTERNAL_ERROR;
        }
        bytes_written += (size_t)n;
    }

    // Flush file data to disk before rename
    if (fsync(fd) != 0)
    {
        close(fd);
        unlink(tmp_path);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    close(fd);

    // Atomic rename: readers see either the old or new value, never partial
    if (rename(tmp_path, path) != 0)
    {
        unlink(tmp_path);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Fsync the directory to ensure the rename is durable across crashes
    fd = open(ctx->storage_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    if (fsync(fd) != 0)
    {
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    close(fd);

    return AZIHSM_STATUS_SUCCESS;
}

/*
 * Delete the file identified by `key`.
 *
 * Not an error if the file does not exist (idempotent).
 */
static azihsm_status resiliency_storage_clear(void *ctx_ptr, const char *key)
{
    struct azihsm_resiliency_ctx *ctx = (struct azihsm_resiliency_ctx *)ctx_ptr;
    char path[PATH_BUF_SIZE];
    azihsm_status status;

    if (ctx == NULL)
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    status = build_storage_path(ctx->storage_dir, key, path, sizeof(path));
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        return status;
    }

    if (unlink(path) != 0 && errno != ENOENT)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    return AZIHSM_STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Lock callbacks (flock-based)                                       */
/* ------------------------------------------------------------------ */

/*
 * Acquire an exclusive advisory lock (blocking).
 *
 * Opens a fresh file descriptor on the lock file and acquires an
 * exclusive flock.  A fresh fd per acquisition is required because
 * flock(2) operates per open-file-description: two threads calling
 * flock on the same fd see a single lock and the second call
 * silently succeeds.  By opening a new fd each time, each caller
 * gets its own independent lock that serializes both cross-thread
 * and cross-process.
 */
static azihsm_status resiliency_lock(void *ctx_ptr)
{
    struct azihsm_resiliency_ctx *ctx = (struct azihsm_resiliency_ctx *)ctx_ptr;
    struct stat lock_st;
    int fd;

    if (ctx == NULL)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Open a fresh fd on the lock file (create if needed, owner-only).
    fd = open(ctx->lock_path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Verify the opened path is a regular file (not a symlink, FIFO, etc.).
    if (fstat(fd, &lock_st) != 0 || !S_ISREG(lock_st.st_mode))
    {
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Acquire the cross-process exclusive lock (blocks until available).
    if (flock(fd, LOCK_EX) != 0)
    {
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Store the locked fd in the context under the in-process lock.
    if (!CRYPTO_THREAD_write_lock(ctx->lock_fd_lock))
    {
        flock(fd, LOCK_UN);
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    ctx->lock_fd = fd;
    CRYPTO_THREAD_unlock(ctx->lock_fd_lock);

    return AZIHSM_STATUS_SUCCESS;
}

/*
 * Release the advisory lock and close the file descriptor.
 */
static azihsm_status resiliency_unlock(void *ctx_ptr)
{
    struct azihsm_resiliency_ctx *ctx = (struct azihsm_resiliency_ctx *)ctx_ptr;
    int fd;

    if (ctx == NULL)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (!CRYPTO_THREAD_write_lock(ctx->lock_fd_lock))
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }
    fd = ctx->lock_fd;
    ctx->lock_fd = -1;
    CRYPTO_THREAD_unlock(ctx->lock_fd_lock);

    if (fd < 0)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    if (flock(fd, LOCK_UN) != 0)
    {
        close(fd);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    close(fd);
    return AZIHSM_STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  POTA endorsement callback                                         */
/* ------------------------------------------------------------------ */

/*
 * Re-endorse the device's PID public key with the provider's fixed
 * POTA private key.
 *
 * Called by the resiliency layer during partition restore when the
 * device may have generated a new attestation key after a resiliency event.
 *
 * Implements the two-call buffer pattern:
 *   - First call  (signature->ptr == NULL): returns required output
 *     sizes in the len fields and AZIHSM_STATUS_BUFFER_TOO_SMALL.
 *   - Second call (buffers allocated): computes the endorsement,
 *     copies signature and POTA public key DER into the output buffers.
 *
 * @param pota_pub_key_der  The caller's original endorsement verification key
 *                          (DER-encoded; passed for identification; ignored by
 *                          this provider because it always uses the same fixed
 *                          POTA key pair).
 */
static azihsm_status resiliency_pota_endorse(
    void *ctx_ptr,
    const struct azihsm_buffer *pota_pub_key_der,
    const struct azihsm_buffer *pid_pub_key_der,
    const struct azihsm_buffer *pid_cert_chain_pem,
    struct azihsm_buffer *signature,
    struct azihsm_buffer *endorsement_pub_key
)
{
    struct azihsm_resiliency_ctx *ctx = (struct azihsm_resiliency_ctx *)ctx_ptr;
    struct azihsm_buffer sig_tmp = { NULL, 0 };
    azihsm_status status;

    (void)pota_pub_key_der;   // identification only; provider uses fixed POTA key
    (void)pid_cert_chain_pem; // not needed by this provider

    if (ctx == NULL || pid_pub_key_der == NULL || signature == NULL || endorsement_pub_key == NULL)
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    // Two-call pattern: first call returns required output sizes
    if (signature->ptr == NULL || endorsement_pub_key->ptr == NULL)
    {
        struct azihsm_buffer pub_key_buf = { NULL, 0 };
        status = azihsm_file_load(ctx->pota_pub_path, &pub_key_buf);
        if (status != AZIHSM_STATUS_SUCCESS || pub_key_buf.ptr == NULL)
        {
            return (status != AZIHSM_STATUS_SUCCESS) ? status : AZIHSM_STATUS_INTERNAL_ERROR;
        }
        signature->len = POTA_SIGNATURE_SIZE;
        endorsement_pub_key->len = pub_key_buf.len;
        OPENSSL_free(pub_key_buf.ptr);
        return AZIHSM_STATUS_BUFFER_TOO_SMALL;
    }

    //
    // Second call: sign the SDK-provided PID public key (pid_pub_key_der)
    // with the fixed POTA private key and return the signature + POTA
    // public key DER. No device handle is used.
    //
    // compute_pota_endorsement() allocates sig_tmp.ptr with
    // OPENSSL_malloc.
    //

    // Load POTA private and public keys from the configured file paths
    struct azihsm_buffer priv_key_buf = { NULL, 0 };
    struct azihsm_buffer pub_key_buf = { NULL, 0 };

    status = azihsm_file_load(ctx->pota_priv_path, &priv_key_buf);
    if (status != AZIHSM_STATUS_SUCCESS || priv_key_buf.ptr == NULL)
    {
        return (status != AZIHSM_STATUS_SUCCESS) ? status : AZIHSM_STATUS_INTERNAL_ERROR;
    }

    status = azihsm_file_load(ctx->pota_pub_path, &pub_key_buf);
    if (status != AZIHSM_STATUS_SUCCESS || pub_key_buf.ptr == NULL)
    {
        OPENSSL_cleanse(priv_key_buf.ptr, priv_key_buf.len);
        OPENSSL_free(priv_key_buf.ptr);
        return (status != AZIHSM_STATUS_SUCCESS) ? status : AZIHSM_STATUS_INTERNAL_ERROR;
    }

    status = compute_pota_endorsement(pid_pub_key_der, &priv_key_buf, &sig_tmp);
    OPENSSL_cleanse(priv_key_buf.ptr, priv_key_buf.len);
    OPENSSL_free(priv_key_buf.ptr);
    if (status != AZIHSM_STATUS_SUCCESS)
    {
        OPENSSL_free(pub_key_buf.ptr);
        return status;
    }

    // Validate that caller-provided buffers are large enough
    if (signature->len < sig_tmp.len || endorsement_pub_key->len < pub_key_buf.len)
    {
        signature->len = sig_tmp.len;
        endorsement_pub_key->len = pub_key_buf.len;
        OPENSSL_cleanse(sig_tmp.ptr, sig_tmp.len);
        OPENSSL_free(sig_tmp.ptr);
        OPENSSL_free(pub_key_buf.ptr);
        return AZIHSM_STATUS_BUFFER_TOO_SMALL;
    }

    // Copy signature into caller's buffer
    memcpy(signature->ptr, sig_tmp.ptr, sig_tmp.len);
    signature->len = sig_tmp.len;
    OPENSSL_cleanse(sig_tmp.ptr, sig_tmp.len);
    OPENSSL_free(sig_tmp.ptr);

    // Copy POTA public key DER and free the loaded buffer
    memcpy(endorsement_pub_key->ptr, pub_key_buf.ptr, pub_key_buf.len);
    endorsement_pub_key->len = pub_key_buf.len;
    OPENSSL_free(pub_key_buf.ptr);

    return AZIHSM_STATUS_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Public API: context lifecycle                                     */
/* ------------------------------------------------------------------ */

azihsm_status azihsm_resiliency_create(
    const char *storage_dir,
    const char *pota_priv_path,
    const char *pota_pub_path,
    bool use_tpm_pota,
    struct azihsm_resiliency_config *out_config,
    struct azihsm_resiliency_ctx **out_ctx
)
{
    struct azihsm_resiliency_ctx *ctx = NULL;
    int written;

    if (storage_dir == NULL || out_config == NULL || out_ctx == NULL)
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    // Caller POTA source requires both key paths
    if (!use_tpm_pota && (pota_priv_path == NULL || pota_pub_path == NULL))
    {
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    // Create storage directory if it does not exist (mode 0700: owner-only access)
    if (mkdir(storage_dir, S_IRWXU) != 0)
    {
        if (errno != EEXIST)
        {
            return AZIHSM_STATUS_INTERNAL_ERROR;
        }

        // Get metadata for the existing path (lstat to reject symlinks).
        struct stat dir_st;
        if (lstat(storage_dir, &dir_st) != 0)
        {
            return AZIHSM_STATUS_INTERNAL_ERROR;
        }
        // Reject if the path is not a directory (e.g., a regular file or symlink).
        if (!S_ISDIR(dir_st.st_mode))
        {
            return AZIHSM_STATUS_INVALID_ARGUMENT;
        }
        // Reject directories not owned by the current user.
        if (dir_st.st_uid != getuid())
        {
            return AZIHSM_STATUS_INVALID_ARGUMENT;
        }
        // Reject directories with group or other permissions set.
        if ((dir_st.st_mode & (S_IRWXG | S_IRWXO)) != 0)
        {
            return AZIHSM_STATUS_INVALID_ARGUMENT;
        }
    }

    // Allocate and zero-initialize context
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
    {
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    ctx->lock_fd = -1;

    ctx->lock_fd_lock = CRYPTO_THREAD_lock_new();
    if (ctx->lock_fd_lock == NULL)
    {
        OPENSSL_free(ctx);
        return AZIHSM_STATUS_INTERNAL_ERROR;
    }

    // Copy storage directory path into context; reject if it would be truncated.
    written = snprintf(ctx->storage_dir, sizeof(ctx->storage_dir), "%s", storage_dir);
    if (written < 0 || (size_t)written >= sizeof(ctx->storage_dir))
    {
        CRYPTO_THREAD_lock_free(ctx->lock_fd_lock);
        OPENSSL_free(ctx);
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    if (pota_priv_path != NULL)
    {
        written = snprintf(ctx->pota_priv_path, sizeof(ctx->pota_priv_path), "%s", pota_priv_path);
        if (written < 0 || (size_t)written >= sizeof(ctx->pota_priv_path))
        {
            CRYPTO_THREAD_lock_free(ctx->lock_fd_lock);
            OPENSSL_free(ctx);
            return AZIHSM_STATUS_INVALID_ARGUMENT;
        }
    }
    if (pota_pub_path != NULL)
    {
        written = snprintf(ctx->pota_pub_path, sizeof(ctx->pota_pub_path), "%s", pota_pub_path);
        if (written < 0 || (size_t)written >= sizeof(ctx->pota_pub_path))
        {
            CRYPTO_THREAD_lock_free(ctx->lock_fd_lock);
            OPENSSL_free(ctx);
            return AZIHSM_STATUS_INVALID_ARGUMENT;
        }
    }

    // Build and store the lock file path
    written = snprintf(ctx->lock_path, sizeof(ctx->lock_path), "%s/.lock", storage_dir);
    if (written < 0 || (size_t)written >= sizeof(ctx->lock_path))
    {
        CRYPTO_THREAD_lock_free(ctx->lock_fd_lock);
        OPENSSL_free(ctx);
        return AZIHSM_STATUS_INVALID_ARGUMENT;
    }

    // Wire up POTA callback ops only for Caller source (not TPM)
    if (!use_tpm_pota)
    {
        ctx->pota_ops.endorse = resiliency_pota_endorse;
    }

    // Populate the output config struct
    memset(out_config, 0, sizeof(*out_config));
    out_config->ctx = ctx;
    out_config->storage_ops.read = resiliency_storage_read;
    out_config->storage_ops.write = resiliency_storage_write;
    out_config->storage_ops.clear = resiliency_storage_clear;
    out_config->lock_ops.lock = resiliency_lock;
    out_config->lock_ops.unlock = resiliency_unlock;
    out_config->pota_callback_ops = use_tpm_pota ? NULL : &ctx->pota_ops;

    *out_ctx = ctx;
    return AZIHSM_STATUS_SUCCESS;
}

void azihsm_resiliency_destroy(struct azihsm_resiliency_ctx *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    if (ctx->lock_fd >= 0)
    {
        close(ctx->lock_fd);
        ctx->lock_fd = -1;
    }

    CRYPTO_THREAD_lock_free(ctx->lock_fd_lock);

    OPENSSL_cleanse(ctx, sizeof(*ctx));
    OPENSSL_free(ctx);
}
