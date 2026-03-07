// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef KEYGEN_HELPERS_HPP
#define KEYGEN_HELPERS_HPP

#include <cstdio>
#include <cstring>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <unistd.h>
#include <vector>

#include "ossl_helpers.hpp"
#include "provider_ctx.hpp"

// ---------------------------------------------------------------------------
// RAII guard to unlink a temp file on scope exit
// ---------------------------------------------------------------------------

struct TempFileGuard
{
    char path[64];

    explicit TempFileGuard(const char *tpl)
    {
        std::strncpy(path, tpl, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    }

    ~TempFileGuard()
    {
        ::unlink(path);
    }

    TempFileGuard(const TempFileGuard &) = delete;
    TempFileGuard &operator=(const TempFileGuard &) = delete;
};

// ---------------------------------------------------------------------------
// EC key generation helpers
// ---------------------------------------------------------------------------

/// Generate an EC session key via the azihsm provider.
inline EvpPkeyPtr generate_ec_session_key(
    OSSL_LIB_CTX *libctx,
    const char *curve,
    const char *key_usage = "digitalSignature"
)
{
    EvpPkeyCtxPtr pctx(EVP_PKEY_CTX_new_from_name(libctx, "EC", ProviderCtx::propquery()));
    if (!pctx)
    {
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(pctx.get()) <= 0)
    {
        return nullptr;
    }

    char session_val[] = "true";
    char curve_buf[16];
    std::strncpy(curve_buf, curve, sizeof(curve_buf) - 1);
    curve_buf[sizeof(curve_buf) - 1] = '\0';
    char usage_buf[32];
    std::strncpy(usage_buf, key_usage, sizeof(usage_buf) - 1);
    usage_buf[sizeof(usage_buf) - 1] = '\0';

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, curve_buf, 0),
        OSSL_PARAM_utf8_string("azihsm.session", session_val, 0),
        OSSL_PARAM_utf8_string("azihsm.key_usage", usage_buf, 0),
        OSSL_PARAM_END,
    };

    if (EVP_PKEY_CTX_set_params(pctx.get(), params) <= 0)
    {
        return nullptr;
    }

    EVP_PKEY *raw = nullptr;
    if (EVP_PKEY_generate(pctx.get(), &raw) <= 0)
    {
        return nullptr;
    }

    return EvpPkeyPtr(raw);
}

/// Generate a plain EC key via the default provider (for use as ECDH peer).
///
/// HSM-generated keys do not populate their public-key point in the keymgmt
/// data structure (pub_key_data).  When a default-provider key is passed as
/// peer via EVP_PKEY_derive_set_peer, OpenSSL performs a cross-provider import
/// which *does* populate pub_key_data, matching the pattern used by the CLI
/// integration tests (ecdh_key_exchange.sh).
inline EvpPkeyPtr generate_ec_default_key(OSSL_LIB_CTX *libctx, const char *curve)
{
    EvpPkeyCtxPtr pctx(EVP_PKEY_CTX_new_from_name(libctx, "EC", "provider=default"));
    if (!pctx)
    {
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(pctx.get()) <= 0)
    {
        return nullptr;
    }

    char curve_buf[16];
    std::strncpy(curve_buf, curve, sizeof(curve_buf) - 1);
    curve_buf[sizeof(curve_buf) - 1] = '\0';

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, curve_buf, 0),
        OSSL_PARAM_END,
    };

    if (EVP_PKEY_CTX_set_params(pctx.get(), params) <= 0)
    {
        return nullptr;
    }

    EVP_PKEY *raw = nullptr;
    if (EVP_PKEY_generate(pctx.get(), &raw) <= 0)
    {
        return nullptr;
    }

    return EvpPkeyPtr(raw);
}

// ---------------------------------------------------------------------------
// RSA key generation helper
// ---------------------------------------------------------------------------
//
// The HSM cannot generate RSA keys natively.  This helper:
// 1. Generates an RSA key with the OpenSSL default provider.
// 2. Exports the private key to DER.
// 3. Writes DER to a temporary file.
// 4. Imports into the azihsm provider with azihsm.session=true.

inline EvpPkeyPtr generate_rsa_session_key(
    OSSL_LIB_CTX *libctx,
    int bits = 2048,
    const char *key_usage = "digitalSignature"
)
{
    // 1. Generate RSA key via default provider
    EvpPkeyCtxPtr gen_ctx(EVP_PKEY_CTX_new_from_name(libctx, "RSA", "provider=default"));
    if (!gen_ctx)
    {
        return nullptr;
    }
    if (EVP_PKEY_keygen_init(gen_ctx.get()) <= 0)
    {
        return nullptr;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(gen_ctx.get(), bits) <= 0)
    {
        return nullptr;
    }

    EVP_PKEY *default_raw = nullptr;
    if (EVP_PKEY_generate(gen_ctx.get(), &default_raw) <= 0)
    {
        return nullptr;
    }
    EvpPkeyPtr default_key(default_raw);

    // 2. Export private key to DER
    int der_len = i2d_PrivateKey(default_key.get(), nullptr);
    if (der_len <= 0)
    {
        return nullptr;
    }

    std::vector<unsigned char> der_buf(static_cast<size_t>(der_len));
    unsigned char *der_ptr = der_buf.data();
    i2d_PrivateKey(default_key.get(), &der_ptr);

    // 3. Write DER to temp file (RAII guard ensures cleanup on all paths)
    char tmp_path[] = "/tmp/azihsm_test_rsa_XXXXXX";
    int fd = mkstemp(tmp_path);
    if (fd < 0)
    {
        return nullptr;
    }
    TempFileGuard guard(tmp_path);

    ssize_t written = ::write(fd, der_buf.data(), der_buf.size());
    ::close(fd);
    if (written != static_cast<ssize_t>(der_buf.size()))
    {
        return nullptr;
    }

    // 4. Import into azihsm with session=true
    EvpPkeyCtxPtr import_ctx(EVP_PKEY_CTX_new_from_name(libctx, "RSA", ProviderCtx::propquery()));
    if (!import_ctx)
    {
        return nullptr;
    }
    if (EVP_PKEY_keygen_init(import_ctx.get()) <= 0)
    {
        return nullptr;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(import_ctx.get(), bits) <= 0)
    {
        return nullptr;
    }

    char session_val[] = "true";
    char usage_buf[32];
    std::strncpy(usage_buf, key_usage, sizeof(usage_buf) - 1);
    usage_buf[sizeof(usage_buf) - 1] = '\0';

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("azihsm.session", session_val, 0),
        OSSL_PARAM_utf8_string("azihsm.key_usage", usage_buf, 0),
        OSSL_PARAM_utf8_string("azihsm.input_key", guard.path, 0),
        OSSL_PARAM_END,
    };

    if (EVP_PKEY_CTX_set_params(import_ctx.get(), params) <= 0)
    {
        return nullptr;
    }

    EVP_PKEY *hsm_raw = nullptr;
    if (EVP_PKEY_generate(import_ctx.get(), &hsm_raw) <= 0)
    {
        return nullptr;
    }

    return EvpPkeyPtr(hsm_raw);
}

#endif // KEYGEN_HELPERS_HPP
