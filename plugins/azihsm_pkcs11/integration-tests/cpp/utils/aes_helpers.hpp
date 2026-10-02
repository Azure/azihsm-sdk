// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// Helpers for the AES tests: key generation with the usual template and the
/// two-call (probe, then fill) one-shot cipher discipline.

#include <cstring>
#include <vector>

#include "utils/module.hpp"

constexpr CK_ULONG kAesBlock = 16;

/// Generate an AES key of `bytes` with the given usage; returns the
/// C_GenerateKey result and the handle via *out.
inline CK_RV gen_aes_key(
    CK_SESSION_HANDLE s,
    CK_ULONG bytes,
    CK_BBOOL enc,
    CK_BBOOL dec,
    const char *label,
    CK_OBJECT_HANDLE *out
)
{
    CK_MECHANISM mech = { CKM_AES_KEY_GEN, nullptr, 0 };
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_AES;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_KEY_TYPE, &kt, sizeof(kt) },
        { CKA_VALUE_LEN, &bytes, sizeof(bytes) },
        { CKA_ENCRYPT, &enc, sizeof(enc) },
        { CKA_DECRYPT, &dec, sizeof(dec) },
        { CKA_LABEL, const_cast<char *>(label), static_cast<CK_ULONG>(std::strlen(label)) },
    };
    return p11()->C_GenerateKey(s, &mech, tmpl, sizeof(tmpl) / sizeof(tmpl[0]), out);
}

/// Generate an AES-GCM key: CKM_AES_KEY_GEN asking for the GCM family through
/// CKA_ALLOWED_MECHANISMS (PKCS#11 has no GCM key-generation mechanism).
inline CK_RV gen_gcm_key(CK_SESSION_HANDLE s, const char *label, CK_OBJECT_HANDLE *out)
{
    CK_MECHANISM mech = { CKM_AES_KEY_GEN, nullptr, 0 };
    CK_ULONG bytes = 32;
    CK_MECHANISM_TYPE allowed[] = { CKM_AES_GCM };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_VALUE_LEN, &bytes, sizeof(bytes) },
        { CKA_ALLOWED_MECHANISMS, allowed, sizeof(allowed) },
        { CKA_LABEL, const_cast<char *>(label), static_cast<CK_ULONG>(std::strlen(label)) },
    };
    return p11()->C_GenerateKey(s, &mech, tmpl, sizeof(tmpl) / sizeof(tmpl[0]), out);
}

/// Generate an AES-XTS key (two AES-256 subkeys) with CKM_AES_XTS_KEY_GEN.
inline CK_RV gen_xts_key(CK_SESSION_HANDLE s, const char *label, CK_OBJECT_HANDLE *out)
{
    CK_MECHANISM mech = { CKM_AES_XTS_KEY_GEN, nullptr, 0 };
    CK_ULONG bytes = 64;
    CK_KEY_TYPE kt = CKK_AES_XTS;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_KEY_TYPE, &kt, sizeof(kt) },
        { CKA_VALUE_LEN, &bytes, sizeof(bytes) },
        { CKA_LABEL, const_cast<char *>(label), static_cast<CK_ULONG>(std::strlen(label)) },
    };
    return p11()->C_GenerateKey(s, &mech, tmpl, sizeof(tmpl) / sizeof(tmpl[0]), out);
}

/// Read a key's CKA_ALLOWED_MECHANISMS (two-call sizing) into `out`.
inline CK_RV get_allowed_mechs(
    CK_SESSION_HANDLE s,
    CK_OBJECT_HANDLE obj,
    std::vector<CK_MECHANISM_TYPE> &out
)
{
    CK_ATTRIBUTE a = { CKA_ALLOWED_MECHANISMS, nullptr, 0 };
    CK_RV rv = p11()->C_GetAttributeValue(s, obj, &a, 1);
    if (rv != CKR_OK)
    {
        return rv;
    }
    out.assign(a.ulValueLen / sizeof(CK_MECHANISM_TYPE), 0);
    a.pValue = out.data();
    return p11()->C_GetAttributeValue(s, obj, &a, 1);
}

/// One-shot encrypt/decrypt with the two-call discipline: init, probe the
/// required length, then fill. `out` is sized to the bytes written.
inline CK_RV crypt_oneshot(
    CK_SESSION_HANDLE s,
    bool encrypt,
    CK_MECHANISM *mech,
    CK_OBJECT_HANDLE key,
    const std::vector<CK_BYTE> &in,
    std::vector<CK_BYTE> &out
)
{
    CK_RV rv = encrypt ? p11()->C_EncryptInit(s, mech, key) : p11()->C_DecryptInit(s, mech, key);
    if (rv != CKR_OK)
    {
        return rv;
    }
    CK_BYTE_PTR in_ptr = const_cast<CK_BYTE_PTR>(in.data());
    CK_ULONG in_len = static_cast<CK_ULONG>(in.size());
    CK_ULONG need = 0;
    rv = encrypt ? p11()->C_Encrypt(s, in_ptr, in_len, nullptr, &need)
                 : p11()->C_Decrypt(s, in_ptr, in_len, nullptr, &need);
    if (rv != CKR_OK)
    {
        return rv;
    }
    out.assign(need, 0);
    // A zero-length result still needs a real buffer: with a NULL one the fill
    // would be a second sizing probe, and the operation would never run.
    CK_BYTE none = 0;
    CK_BYTE_PTR out_ptr = (need > 0) ? out.data() : &none;
    CK_ULONG len = need;
    rv = encrypt ? p11()->C_Encrypt(s, in_ptr, in_len, out_ptr, &len)
                 : p11()->C_Decrypt(s, in_ptr, in_len, out_ptr, &len);
    out.resize((rv == CKR_OK) ? len : 0);
    return rv;
}

/// Read one attribute of `obj` into a fixed-size value.
template <typename T>
inline CK_RV get_attr(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type, T *value)
{
    CK_ATTRIBUTE a = { type, value, sizeof(T) };
    return p11()->C_GetAttributeValue(s, obj, &a, 1);
}
