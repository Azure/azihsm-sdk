// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * _DEFAULT_SOURCE exposes flock(2), lstat(2), fsync(2) and the O_NOFOLLOW /
 * O_DIRECTORY / O_CLOEXEC open flags on glibc; it must precede every include.
 * The provider gets these from its CMake build, but this file also compiles in
 * the bare no-device smoke build (a plain gcc over the sources, no -lcrypto), so
 * the request is stated here.
 */
#define _DEFAULT_SOURCE

#include "azihsm_pkcs11_store_io.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/* store_dir (up to 4096) + '/' + name (up to 256) + temp affix (".<name>.tmp")
 * + NUL, with headroom. azihsm_pkcs11_store_path_join rejects anything that still would
 * not fit via the snprintf truncation check, so this is only a comfortable
 * upper bound. */
#define P11_STORE_PATH_MAX 4608

static CK_RV ckr_from_errno(int e)
{
    switch (e)
    {
    case ENOMEM:
        return CKR_HOST_MEMORY;
    case ENOSPC:
    case EDQUOT:
        return CKR_DEVICE_MEMORY; /* out of disk / quota */
    default:
        return CKR_FUNCTION_FAILED;
    }
}

CK_RV azihsm_pkcs11_store_path_join(char *out, size_t outlen, const char *dir, const char *name)
{
    if (out == NULL || dir == NULL || name == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    /* `name` must be a single flat component: no separator, no traversal. Mirror
     * the provider's build_storage_path reject set (azihsm_ossl_resiliency.c). */
    size_t nlen = strnlen(name, P11_STORE_MAX_NAME_LEN + 1);
    if (nlen == 0 || nlen > P11_STORE_MAX_NAME_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (strchr(name, '/') != NULL || strcmp(name, "..") == 0 || strstr(name, "../") != NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    int written = snprintf(out, outlen, "%s/%s", dir, name);
    if (written < 0 || (size_t)written >= outlen)
    {
        return CKR_FUNCTION_FAILED;
    }
    return CKR_OK;
}

CK_RV azihsm_pkcs11_store_dir_ensure(const char *dir)
{
    if (dir == NULL || dir[0] == '\0')
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (mkdir(dir, S_IRWXU) == 0) /* 0700: owner-only */
    {
        return CKR_OK;
    }
    if (errno != EEXIST)
    {
        return ckr_from_errno(errno);
    }
    /* Already present: require a real directory, owned by us, with no group or
     * other access (defense against a pre-planted world-writable store dir). */
    struct stat st;
    if (lstat(dir, &st) != 0)
    {
        return ckr_from_errno(errno);
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != getuid() || (st.st_mode & (S_IRWXG | S_IRWXO)) != 0)
    {
        return CKR_FUNCTION_FAILED;
    }
    return CKR_OK;
}

CK_RV azihsm_pkcs11_store_write(
    const char *dir,
    const char *name,
    const unsigned char *data,
    size_t len
)
{
    if (dir == NULL || name == NULL || (len > 0 && data == NULL))
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (len > P11_STORE_MAX_FILE_SIZE)
    {
        return CKR_DATA_LEN_RANGE;
    }

    char path[P11_STORE_PATH_MAX];
    char tmp[P11_STORE_PATH_MAX];
    CK_RV rv = azihsm_pkcs11_store_path_join(path, sizeof(path), dir, name);
    if (rv != CKR_OK)
    {
        return rv;
    }
    /* Temp name is derived from the target so it lands in the same directory
     * (rename is only atomic within one filesystem). */
    int written = snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", dir, name);
    if (written < 0 || (size_t)written >= sizeof(tmp))
    {
        return CKR_FUNCTION_FAILED;
    }

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        return ckr_from_errno(errno);
    }

    size_t off = 0;
    while (off < len)
    {
        ssize_t n = write(fd, data + off, len - off);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            int e = errno;
            close(fd);
            unlink(tmp);
            return ckr_from_errno(e);
        }
        off += (size_t)n;
    }
    /* Flush data before the rename so a crash cannot expose a renamed-but-empty
     * file. */
    if (fsync(fd) != 0)
    {
        int e = errno;
        close(fd);
        unlink(tmp);
        return ckr_from_errno(e);
    }
    if (close(fd) != 0)
    {
        int e = errno;
        unlink(tmp);
        return ckr_from_errno(e);
    }
    if (rename(tmp, path) != 0) /* atomic: readers see old or new, never partial */
    {
        int e = errno;
        unlink(tmp);
        return ckr_from_errno(e);
    }
    /* Persist the rename itself: fsync the directory. Best-effort — the data is
     * already durable; this only tightens the crash window for the name. */
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0)
    {
        (void)fsync(dfd);
        close(dfd);
    }
    return CKR_OK;
}

CK_RV azihsm_pkcs11_store_read(const char *dir, const char *name, unsigned char **out, size_t *len)
{
    if (dir == NULL || name == NULL || out == NULL || len == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    *out = NULL;
    *len = 0;

    char path[P11_STORE_PATH_MAX];
    CK_RV rv = azihsm_pkcs11_store_path_join(path, sizeof(path), dir, name);
    if (rv != CKR_OK)
    {
        return rv;
    }
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
    {
        /* Absence is a valid state, not an error (mirrors azihsm_file_load). */
        if (errno == ENOENT)
        {
            return CKR_OK;
        }
        return ckr_from_errno(errno);
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        int e = errno;
        close(fd);
        return ckr_from_errno(e);
    }
    /* Reject anything that is not a plain file, and a size we will not read. */
    if (!S_ISREG(st.st_mode) || st.st_size < 0 ||
        (unsigned long long)st.st_size > P11_STORE_MAX_FILE_SIZE)
    {
        close(fd);
        return CKR_FUNCTION_FAILED;
    }
    size_t size = (size_t)st.st_size;
    if (size == 0) /* empty file: treat as absent */
    {
        close(fd);
        return CKR_OK;
    }

    unsigned char *buf = (unsigned char *)malloc(size);
    if (buf == NULL)
    {
        close(fd);
        return CKR_HOST_MEMORY;
    }
    size_t off = 0;
    while (off < size)
    {
        ssize_t n = read(fd, buf + off, size - off);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            int e = errno;
            free(buf);
            close(fd);
            return ckr_from_errno(e);
        }
        if (n == 0)
        {
            break; /* file shrank under us — treat as a torn read below */
        }
        off += (size_t)n;
    }
    close(fd);
    if (off != size)
    {
        free(buf);
        return CKR_FUNCTION_FAILED;
    }
    *out = buf;
    *len = size;
    return CKR_OK;
}

CK_RV azihsm_pkcs11_store_unlink(const char *dir, const char *name)
{
    if (dir == NULL || name == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    char path[P11_STORE_PATH_MAX];
    CK_RV rv = azihsm_pkcs11_store_path_join(path, sizeof(path), dir, name);
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (unlink(path) != 0 && errno != ENOENT)
    {
        return ckr_from_errno(errno);
    }
    return CKR_OK;
}

CK_RV azihsm_pkcs11_store_lock(const char *dir, int *lock_fd)
{
    if (dir == NULL || lock_fd == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    *lock_fd = -1;

    char path[P11_STORE_PATH_MAX];
    CK_RV rv = azihsm_pkcs11_store_path_join(path, sizeof(path), dir, ".lock");
    if (rv != CKR_OK)
    {
        return rv;
    }
    /* Fresh fd per acquisition: flock is per open-file-description, so a shared
     * fd would let a second acquirer's lock silently succeed. */
    int fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        return ckr_from_errno(errno);
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
    {
        close(fd);
        return CKR_FUNCTION_FAILED;
    }
    if (flock(fd, LOCK_EX) != 0)
    {
        int e = errno;
        close(fd);
        return ckr_from_errno(e);
    }
    *lock_fd = fd;
    return CKR_OK;
}

void azihsm_pkcs11_store_unlock(int lock_fd)
{
    if (lock_fd < 0)
    {
        return;
    }
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
}
