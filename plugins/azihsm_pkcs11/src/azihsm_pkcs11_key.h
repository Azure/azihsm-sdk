// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "azihsm_pkcs11_compat.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* AES-CBC block and IV length in bytes. The device CBC IV width is checked
 * against this in the AZIHSM_WITH_HSM build (azihsm_pkcs11_key.c). */
#define AES_BLOCK_LEN 16

/*
 * HSM key binding: the azihsm_key_* / azihsm_crypt_* half of the HSM-binding
 * layer (partition/session calls live in azihsm_pkcs11_hsm.h). Like that layer it is the
 * only place these azihsm_* families are called and the only place their
 * statuses become CK_RV; the no-device build provides stubs that return
 * CKR_FUNCTION_NOT_SUPPORTED so the entry points above stay link- and
 * validation-testable without a device.
 *
 * Keys never live on the device between uses: generation reads back the opaque
 * masked blob (the only durable form of an AZIHSM key) and frees the device
 * handle; every operation unmasks the blob into a fresh session-scoped handle
 * and releases it when the operation ends.
 */

/*
 * Generate an AES key of `bit_len` bits (128/192/256) in the device session
 * `hsm_session` and return its masked blob in a malloc'd buffer the caller
 * owns (wipe before free — it is opaque but still key-derived material). The
 * transient device handle is already freed on return.
 *
 * The device key always carries both encrypt and decrypt usage: the SDK
 * requires the pair on AES keys (api/lib HsmAesKey::validate_props), so a
 * one-directional CKA_ENCRYPT/CKA_DECRYPT policy is enforced host-side by the
 * operation-init gate, like the rest of the PKCS#11 object model.
 */
CK_RV azihsm_pkcs11_key_aes_generate(
    uint32_t hsm_session,
    uint32_t bit_len,
    CK_BYTE **out_blob,
    CK_ULONG *out_blob_len
);

/*
 * Unmask a stored AES masked blob into a live device key handle in
 * `hsm_session`. The handle is session-scoped: release it with
 * azihsm_pkcs11_key_release when the operation ends (it also dies with the session).
 */
CK_RV azihsm_pkcs11_key_aes_unmask(
    uint32_t hsm_session,
    const CK_BYTE *blob,
    CK_ULONG blob_len,
    uint32_t *out_key
);

/* Free a device key handle obtained from generate/unmask (no-op if 0). */
void azihsm_pkcs11_key_release(uint32_t key_handle);

/*
 * One-shot AES-CBC encrypt/decrypt with the 16-byte IV `iv`. Two-call sizing:
 * with out == NULL, *out_len receives the required length and the call returns
 * CKR_OK; a too-small *out_len gets the required length with
 * CKR_BUFFER_TOO_SMALL; on success *out_len is the bytes written. Every call
 * is self-contained (the IV seed is re-applied), so probing and retrying with
 * the same inputs is safe.
 */
CK_RV azihsm_pkcs11_key_aes_cbc(
    bool encrypt,
    bool pad,
    uint32_t key_handle,
    const CK_BYTE *iv,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE *out,
    CK_ULONG *out_len
);

#ifdef __cplusplus
}
#endif
