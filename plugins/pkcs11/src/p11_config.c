// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "p11_config.h"

#include <stdlib.h>
#include <string.h>

/* Staging bound for hex_decode; must cover the largest p11_config field
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

void p11_config_load(p11_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    /* Simulator defaults: any non-zero id/pin is accepted, OBK is any 48 bytes. */
    memset(cfg->id, 0x01, sizeof(cfg->id));
    memset(cfg->default_pin, 0x02, sizeof(cfg->default_pin));
    memset(cfg->obk, 0xA5, sizeof(cfg->obk));

    (void)hex_decode(getenv(AZIHSM_P11_ENV_ID), cfg->id, sizeof(cfg->id));
    (void)hex_decode(getenv(AZIHSM_P11_ENV_PIN), cfg->default_pin, sizeof(cfg->default_pin));
}
