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
 * AES-GCM: the device takes a fixed 12-byte IV and produces a fixed 16-byte
 * tag; no other lengths are expressible through its params struct, so the
 * entry point rejects any other CK_GCM_PARAMS shape. Both widths are checked
 * against the device struct in the AZIHSM_WITH_HSM build.
 */
#define AES_GCM_IV_LEN 12
#define AES_GCM_TAG_LEN 16

/* The SDK pads GCM additional data to this boundary and hands the device the
 * padded AAD followed by the data as one buffer with a 32-bit length
 * (ddi/nix align_aad_in_place), so the two together must fit 32 bits. */
#define AES_GCM_AAD_ALIGN 32

/*
 * AES-XTS: a 16-byte tweak (the little-endian sector number), and one data
 * unit per one-shot call. The device caps a data unit at 8192 bytes
 * (api/lib HsmAesXtsAlgo::MAX_DUL_SIZE), which bounds a one-shot XTS message.
 */
#define AES_XTS_TWEAK_LEN 16
#define AES_XTS_MAX_DATA_LEN 8192

/*
 * The AZIHSM key kinds this module can bind. PKCS#11 has one CKK_AES (and
 * CKK_AES_XTS), while the device has three disjoint kinds with distinct
 * handles and validators, so the kind travels with every key call. Named
 * here rather than as AZIHSM_KEY_KIND_* so the entry points stay compilable
 * without azihsm.h; azihsm_pkcs11_key.c translates it in device_kind() and
 * refuses any value outside the enum.
 */
typedef enum
{
    AZIHSM_PKCS11_KIND_AES = 0, /* CKM_AES_CBC, CKM_AES_CBC_PAD */
    AZIHSM_PKCS11_KIND_AES_GCM, /* CKM_AES_GCM */
    AZIHSM_PKCS11_KIND_AES_XTS, /* CKM_AES_XTS */
} azihsm_pkcs11_key_kind_t;

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
 * Generate an AES key of `kind` and `bit_len` bits in the device session
 * `hsm_session` and return its masked blob in a malloc'd buffer the caller
 * owns (wipe before free — it is opaque but still key-derived material). The
 * transient device handle is already freed on return. The device accepts
 * 128/192/256 bits for the plain AES kind, 256 for GCM and 512 for XTS; the
 * template layer holds that policy and this call passes it through.
 *
 * The device key always carries both encrypt and decrypt usage: the SDK
 * requires the pair on AES keys (api/lib HsmAesKey::validate_props), so a
 * one-directional CKA_ENCRYPT/CKA_DECRYPT policy is enforced host-side by the
 * operation-init gate, like the rest of the PKCS#11 object model.
 */
CK_RV azihsm_pkcs11_key_aes_generate(
    uint32_t hsm_session,
    azihsm_pkcs11_key_kind_t kind,
    uint32_t bit_len,
    CK_BYTE **out_blob,
    CK_ULONG *out_blob_len
);

/*
 * Unmask a stored AES masked blob of `kind` into a live device key handle in
 * `hsm_session`. The handle is session-scoped: release it with
 * azihsm_pkcs11_key_release when the operation ends (it also dies with the session).
 * A blob unmasked under the wrong kind is refused by the device, which is the
 * fail-closed backstop behind the host-side mechanism/key-type gates.
 */
CK_RV azihsm_pkcs11_key_aes_unmask(
    uint32_t hsm_session,
    azihsm_pkcs11_key_kind_t kind,
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

/*
 * One-shot AES-GCM encrypt/decrypt with the 12-byte `iv` and optional AAD.
 * Unlike CBC the output length is deterministic, so there is no sizing pass:
 * `out` must be non-NULL with *out_len holding its capacity, and on success
 * *out_len is the bytes written (the ciphertext or plaintext only — the tag is
 * carried separately, because the device keeps it in its params struct while
 * PKCS#11 appends it to the ciphertext; the entry point does that splice).
 * `tag` is AES_GCM_TAG_LEN bytes: written on encrypt, read on decrypt.
 */
CK_RV azihsm_pkcs11_key_aes_gcm(
    bool encrypt,
    uint32_t key_handle,
    const CK_BYTE *iv,
    const CK_BYTE *aad,
    CK_ULONG aad_len,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE *tag,
    CK_BYTE *out,
    CK_ULONG *out_len
);

/*
 * One-shot AES-XTS encrypt/decrypt of a single data unit with the 16-byte
 * little-endian `tweak`. `in_len` is the data-unit length and must be a
 * non-zero multiple of AES_BLOCK_LEN not above AES_XTS_MAX_DATA_LEN (the
 * entry point enforces that as a *_LEN_RANGE first), and the tweak must not be
 * all 0xFF, which the SDK cannot advance past the data unit (the entry point
 * refuses that at init). Sizing works as for GCM: `out` is non-NULL, *out_len
 * its capacity in and the bytes written out.
 */
CK_RV azihsm_pkcs11_key_aes_xts(
    bool encrypt,
    uint32_t key_handle,
    const CK_BYTE *tweak,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE *out,
    CK_ULONG *out_len
);

#ifdef __cplusplus
}
#endif
