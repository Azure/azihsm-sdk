// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "azihsm_pkcs11_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Staging bound for hex_decode; must cover the largest azihsm_pkcs11_config field
 * (P11_OBK_LEN). */
#define P11_HEX_DECODE_MAX 64

/* Decode exactly `bytes` bytes from a 2*bytes hex string. Returns 0 on success,
 * -1 if the string is the wrong length or contains a non-hex character. `out` is
 * written only on full success (via a local staging buffer), so a malformed
 * value leaves the caller's default in place rather than a half-decoded mix. */
static int hex_decode(const char *hex, CK_BYTE *out, size_t bytes)
{
    CK_BYTE tmp[P11_HEX_DECODE_MAX];
    /* strnlen bounds the scan to the expected length, so a string missing its
     * terminator within bytes * 2 + 1 chars is rejected rather than run past. */
    if (hex == NULL || out == NULL || bytes > sizeof(tmp) ||
        strnlen(hex, bytes * 2 + 1) != bytes * 2)
    {
        return -1;
    }
    for (size_t i = 0; i < bytes; i++)
    {
        char ch = hex[i * 2];
        char cl = hex[i * 2 + 1];
        int hi = (ch >= '0' && ch <= '9')   ? ch - '0'
                 : (ch >= 'a' && ch <= 'f') ? ch - 'a' + 10
                 : (ch >= 'A' && ch <= 'F') ? ch - 'A' + 10
                                            : -1;
        int lo = (cl >= '0' && cl <= '9')   ? cl - '0'
                 : (cl >= 'a' && cl <= 'f') ? cl - 'a' + 10
                 : (cl >= 'A' && cl <= 'F') ? cl - 'A' + 10
                                            : -1;
        if (hi < 0 || lo < 0)
        {
            return -1;
        }
        tmp[i] = (CK_BYTE)((hi << 4) | lo);
    }
    memcpy(out, tmp, bytes);
    return 0;
}

/* Return `path` advanced past a leading "file:" scheme, mirroring the provider's
 * handling of path values; returns the original pointer when the prefix is
 * absent (NULL passes through unchanged). */
static const char *strip_file_prefix(const char *path)
{
    static const char FILE_PREFIX[] = "file:";
    if ((path != NULL) && (strncmp(path, FILE_PREFIX, sizeof(FILE_PREFIX) - 1) == 0))
    {
        return path + (sizeof(FILE_PREFIX) - 1);
    }
    return path;
}

/* Reject an empty path or any ".." component so the store directory cannot be
 * pointed outside its intended location — the same rule the provider applies to
 * its resiliency storage dir. */
static bool path_is_safe(const char *path)
{
    return (path != NULL) && (path[0] != '\0') && (strstr(path, "..") == NULL);
}

/* Populate `cfg` from the environment: mock-friendly credential defaults, then
 * the env-var overrides, then the object-store settings (see the contract on
 * the declaration in azihsm_pkcs11_config.h). */
void azihsm_pkcs11_config_load(azihsm_pkcs11_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    /* Simulator defaults: any non-zero id/pin is accepted, OBK is any 48 bytes. */
    memset(cfg->id, 0x01, sizeof(cfg->id));
    memset(cfg->default_pin, 0x02, sizeof(cfg->default_pin));
    memset(cfg->obk, 0xA5, sizeof(cfg->obk));

    (void)hex_decode(getenv(AZIHSM_PKCS11_ENV_ID), cfg->id, sizeof(cfg->id));
    (void)hex_decode(getenv(AZIHSM_PKCS11_ENV_PIN), cfg->default_pin, sizeof(cfg->default_pin));

    /* Persistent object store: rooted at a dedicated default, overridable by a
     * safe AZIHSM_PKCS11_STORE_DIR; the file backend is opt-in via
     * AZIHSM_PKCS11_PERSIST (unset keeps the in-memory backend as before). */
    const char *dir = strip_file_prefix(getenv(AZIHSM_PKCS11_ENV_STORE_DIR));
    if (!path_is_safe(dir))
    {
        dir = AZIHSM_PKCS11_DEFAULT_STORE_DIR;
    }
    int written = snprintf(cfg->store_dir, sizeof(cfg->store_dir), "%s", dir);
    if (written < 0 || (size_t)written >= sizeof(cfg->store_dir))
    {
        /* An overlong override cannot be stored safely; fall back to the default
         * (which always fits) rather than a truncated path. */
        dir = AZIHSM_PKCS11_DEFAULT_STORE_DIR;
        (void)snprintf(cfg->store_dir, sizeof(cfg->store_dir), "%s", dir);
    }

    const char *persist = getenv(AZIHSM_PKCS11_ENV_PERSIST);
    cfg->store_persist =
        (persist != NULL) && ((strcmp(persist, "1") == 0) || (strcasecmp(persist, "true") == 0));
}

/* Wipe `cfg` — it carries credential and OBK bytes. The store goes through a
 * volatile pointer so the compiler cannot elide it as a dead store when the
 * config is a stack object about to leave scope; this module links no
 * libcrypto, so OPENSSL_cleanse is not available here. */
void azihsm_pkcs11_config_clear(azihsm_pkcs11_config *cfg)
{
    if (cfg == NULL)
    {
        return;
    }
    volatile unsigned char *p = (volatile unsigned char *)cfg;
    for (size_t i = 0; i < sizeof(*cfg); i++)
    {
        p[i] = 0;
    }
}
