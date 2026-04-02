// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef RESILIENCY_HELPERS_HPP
#define RESILIENCY_HELPERS_HPP

/// @file resiliency_helpers.hpp
///
/// Shared infrastructure for OSSL provider resiliency stress tests.
///
/// Provides:
///   - NativeApi: resolves partition management symbols from the already-loaded
///     libazihsm_api_native.so (via RTLD_NOLOAD)
///   - ResetHandle: RAII wrapper for a partition handle used to issue resets
///   - Resiliency test fixture with shared ProviderCtx and NativeApi
///   - Crypto roundtrip helpers (EC sign/verify, RSA sign/verify, RSA enc/dec)
///   - Tuning constants (reset interval, op counts, worker counts)

#include <atomic>
#include <chrono>
#include <cstring>
#include <dlfcn.h>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "utils/keygen_helpers.hpp"
#include "utils/ossl_helpers.hpp"
#include "utils/provider_ctx.hpp"

/* ------------------------------------------------------------------ */
/*  Native API access via dlopen/dlsym                                 */
/* ------------------------------------------------------------------ */

/*
 * The test binary links only against OpenSSL — not azihsm_api_native.
 * We dlopen the provider .so (which links the native lib) and dlsym
 * the partition functions needed for issuing resets.
 */

using hsm_handle = uint32_t;
using hsm_status = int32_t;

static constexpr hsm_status HSM_OK = 0;
static constexpr hsm_status HSM_BUF_SMALL = -4;

using fn_get_list = hsm_status (*)(hsm_handle *);
using fn_free_list = hsm_status (*)(hsm_handle);
using fn_get_count = hsm_status (*)(hsm_handle, uint32_t *);
using fn_get_path = hsm_status (*)(hsm_handle, uint32_t, void *);
using fn_open = hsm_status (*)(const void *, hsm_handle *);
using fn_close = hsm_status (*)(hsm_handle);
using fn_reset = hsm_status (*)(hsm_handle);

struct NativeApi
{
    fn_get_list get_list;
    fn_free_list free_list;
    fn_get_count get_count;
    fn_get_path get_path;
    fn_open open;
    fn_close close;
    fn_reset reset;

    /// Resolve partition management symbols from an already-loaded handle.
    explicit NativeApi(void *h)
    {
        get_list = reinterpret_cast<fn_get_list>(dlsym(h, "azihsm_part_get_list"));
        free_list = reinterpret_cast<fn_free_list>(dlsym(h, "azihsm_part_free_list"));
        get_count = reinterpret_cast<fn_get_count>(dlsym(h, "azihsm_part_get_count"));
        get_path = reinterpret_cast<fn_get_path>(dlsym(h, "azihsm_part_get_path"));
        open = reinterpret_cast<fn_open>(dlsym(h, "azihsm_part_open"));
        close = reinterpret_cast<fn_close>(dlsym(h, "azihsm_part_close"));
        reset = reinterpret_cast<fn_reset>(dlsym(h, "azihsm_part_reset"));

        if (!get_list || !free_list || !get_count || !get_path || !open || !close || !reset)
        {
            throw std::runtime_error("Failed to resolve native API symbols via dlsym");
        }
    }
};

/* ------------------------------------------------------------------ */
/*  Helper: open a partition handle for issuing resets                  */
/* ------------------------------------------------------------------ */

inline hsm_handle open_reset_handle(const NativeApi &api)
{
    hsm_handle list = 0;
    if (api.get_list(&list) != HSM_OK)
    {
        throw std::runtime_error("get_list failed");
    }

    uint32_t count = 0;
    if (api.get_count(list, &count) != HSM_OK || count == 0)
    {
        api.free_list(list);
        throw std::runtime_error("get_count failed");
    }

    /* azihsm_str layout: { uint8_t *str; uint32_t len; } */
    struct
    {
        uint8_t *str;
        uint32_t len;
    } path = { nullptr, 0 };

    if (api.get_path(list, 0, &path) != HSM_BUF_SMALL)
    {
        api.free_list(list);
        throw std::runtime_error("get_path size query failed");
    }

    std::vector<uint8_t> buf(path.len, 0);
    path.str = buf.data();
    auto err = api.get_path(list, 0, &path);
    api.free_list(list);
    if (err != HSM_OK)
    {
        throw std::runtime_error("get_path failed");
    }

    hsm_handle part = 0;
    if (api.open(&path, &part) != HSM_OK)
    {
        throw std::runtime_error("part_open failed");
    }
    return part;
}

/* RAII wrapper for partition handle */
struct ResetHandle
{
    hsm_handle h;
    const NativeApi &api;

    explicit ResetHandle(const NativeApi &a) : h(open_reset_handle(a)), api(a)
    {
    }
    ~ResetHandle()
    {
        if (h)
            api.close(h);
    }
    ResetHandle(const ResetHandle &) = delete;
    ResetHandle &operator=(const ResetHandle &) = delete;
};

/* ------------------------------------------------------------------ */
/*  Crypto roundtrip helpers                                           */
/* ------------------------------------------------------------------ */

/// ECDSA sign + verify round-trip via OpenSSL EVP.
inline bool ec_sign_verify_roundtrip(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey)
{
    const std::string msg_str = "NSSR resiliency test: ECDSA round-trip";
    const auto *msg = reinterpret_cast<const unsigned char *>(msg_str.data());
    const size_t msg_len = msg_str.size();

    EvpMdCtxPtr sctx(EVP_MD_CTX_new());
    if (!sctx)
        return false;
    if (EVP_DigestSignInit_ex(
            sctx.get(),
            nullptr,
            "SHA384",
            libctx,
            ProviderCtx::propquery(),
            pkey,
            nullptr
        ) != 1)
        return false;

    size_t sig_len = 0;
    if (EVP_DigestSign(sctx.get(), nullptr, &sig_len, msg, msg_len) != 1)
        return false;

    std::vector<unsigned char> sig(sig_len);
    if (EVP_DigestSign(sctx.get(), sig.data(), &sig_len, msg, msg_len) != 1)
        return false;
    sig.resize(sig_len);

    EvpMdCtxPtr vctx(EVP_MD_CTX_new());
    if (!vctx)
        return false;
    if (EVP_DigestVerifyInit_ex(
            vctx.get(),
            nullptr,
            "SHA384",
            libctx,
            ProviderCtx::propquery(),
            pkey,
            nullptr
        ) != 1)
        return false;

    return EVP_DigestVerify(vctx.get(), sig.data(), sig.size(), msg, msg_len) == 1;
}

/// RSA PKCS#1 sign + verify round-trip via OpenSSL EVP.
inline bool rsa_sign_verify_roundtrip(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey)
{
    const std::string msg_str = "NSSR resiliency test: RSA PKCS#1 round-trip";
    const auto *msg = reinterpret_cast<const unsigned char *>(msg_str.data());
    const size_t msg_len = msg_str.size();

    EvpMdCtxPtr sctx(EVP_MD_CTX_new());
    if (!sctx)
        return false;
    if (EVP_DigestSignInit_ex(
            sctx.get(),
            nullptr,
            "SHA256",
            libctx,
            ProviderCtx::propquery(),
            pkey,
            nullptr
        ) != 1)
        return false;

    size_t sig_len = 0;
    if (EVP_DigestSign(sctx.get(), nullptr, &sig_len, msg, msg_len) != 1)
        return false;

    std::vector<unsigned char> sig(sig_len);
    if (EVP_DigestSign(sctx.get(), sig.data(), &sig_len, msg, msg_len) != 1)
        return false;
    sig.resize(sig_len);

    EvpMdCtxPtr vctx(EVP_MD_CTX_new());
    if (!vctx)
        return false;
    if (EVP_DigestVerifyInit_ex(
            vctx.get(),
            nullptr,
            "SHA256",
            libctx,
            ProviderCtx::propquery(),
            pkey,
            nullptr
        ) != 1)
        return false;

    return EVP_DigestVerify(vctx.get(), sig.data(), sig.size(), msg, msg_len) == 1;
}

/// RSA-OAEP encrypt + decrypt round-trip via OpenSSL EVP.
inline bool rsa_encrypt_decrypt_roundtrip(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey)
{
    const std::string plaintext = "NSSR resiliency: RSA-OAEP payload";
    const auto *pt = reinterpret_cast<const unsigned char *>(plaintext.data());
    const size_t pt_len = plaintext.size();

    EvpPkeyCtxPtr ectx(EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ProviderCtx::propquery()));
    if (!ectx || EVP_PKEY_encrypt_init(ectx.get()) != 1)
        return false;

    char oaep[] = "oaep";
    OSSL_PARAM ep[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, oaep, 0),
        OSSL_PARAM_END,
    };
    if (EVP_PKEY_CTX_set_params(ectx.get(), ep) != 1)
        return false;

    size_t ct_len = 0;
    if (EVP_PKEY_encrypt(ectx.get(), nullptr, &ct_len, pt, pt_len) != 1)
        return false;

    std::vector<unsigned char> ct(ct_len);
    if (EVP_PKEY_encrypt(ectx.get(), ct.data(), &ct_len, pt, pt_len) != 1)
        return false;
    ct.resize(ct_len);

    EvpPkeyCtxPtr dctx(EVP_PKEY_CTX_new_from_pkey(libctx, pkey, ProviderCtx::propquery()));
    if (!dctx || EVP_PKEY_decrypt_init(dctx.get()) != 1)
        return false;

    char oaep2[] = "oaep";
    OSSL_PARAM dp[] = {
        OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, oaep2, 0),
        OSSL_PARAM_END,
    };
    if (EVP_PKEY_CTX_set_params(dctx.get(), dp) != 1)
        return false;

    size_t dec_len = 0;
    if (EVP_PKEY_decrypt(dctx.get(), nullptr, &dec_len, ct.data(), ct.size()) != 1)
        return false;

    std::vector<unsigned char> dec(dec_len);
    if (EVP_PKEY_decrypt(dctx.get(), dec.data(), &dec_len, ct.data(), ct.size()) != 1)
        return false;

    return dec_len == pt_len && std::memcmp(dec.data(), pt, pt_len) == 0;
}

/// SHA digest round-trip via OpenSSL EVP (streaming).
inline bool digest_roundtrip(OSSL_LIB_CTX *libctx, const char *algo)
{
    const std::string input = "NSSR resiliency test: digest round-trip";

    EvpMdPtr md(EVP_MD_fetch(libctx, algo, ProviderCtx::propquery()));
    if (!md)
        return false;

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx)
        return false;

    if (EVP_DigestInit_ex2(ctx.get(), md.get(), nullptr) != 1)
        return false;
    if (EVP_DigestUpdate(ctx.get(), input.data(), input.size()) != 1)
        return false;

    unsigned int out_len = 0;
    std::vector<unsigned char> result(static_cast<size_t>(EVP_MD_get_size(md.get())));
    if (EVP_DigestFinal_ex(ctx.get(), result.data(), &out_len) != 1)
        return false;

    return out_len > 0;
}

/* ------------------------------------------------------------------ */
/*  Test fixture                                                       */
/* ------------------------------------------------------------------ */

/// Base fixture for resiliency tests.  Constructs ProviderCtx first
/// (which loads the provider and initializes the mock device), then
/// resolves the native API symbols via dlopen in SetUp().
class resiliency_base : public ::testing::Test
{
  protected:
    ProviderCtx prov_;
    NativeApi *native_ = nullptr;
    void *native_handle_ = nullptr;

    void SetUp() override
    {
        // The provider .so is already loaded by prov_ via OpenSSL.
        // Its dependency libazihsm_api_native.so is therefore also
        // already in the process.  We open it with RTLD_NOLOAD to
        // get a handle without re-loading or re-initializing it.
        void *h = dlopen("libazihsm_api_native.so", RTLD_NOW | RTLD_NOLOAD);
        ASSERT_NE(h, nullptr) << "dlopen(RTLD_NOLOAD) failed: " << dlerror()
                              << " — is the provider loaded?";

        native_handle_ = h;
        native_ = new NativeApi(h);
    }

    void TearDown() override
    {
        delete native_;
        native_ = nullptr;
        if (native_handle_ != nullptr)
        {
            dlclose(native_handle_);
            native_handle_ = nullptr;
        }
    }

    OSSL_LIB_CTX *libctx()
    {
        return prov_.libctx();
    }
    NativeApi &api()
    {
        return *native_;
    }
};

/* ------------------------------------------------------------------ */
/*  Tuning constants                                                   */
/* ------------------------------------------------------------------ */

// Aligned with the Rust resiliency stress tests (api/tests/src/resiliency/stress/tests.rs).
static constexpr auto RESET_INTERVAL = std::chrono::milliseconds(1000);
static constexpr auto WORKER_SLEEP = std::chrono::milliseconds(10);
static constexpr uint32_t STRESS_OPS = 500;
static constexpr uint32_t MULTI_OPS_PER_WORKER = 500;
static constexpr uint32_t NUM_WORKERS = 8;

#endif // RESILIENCY_HELPERS_HPP
