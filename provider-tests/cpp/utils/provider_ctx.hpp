// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef PROVIDER_CTX_HPP
#define PROVIDER_CTX_HPP

#include <cstdlib>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <stdexcept>
#include <string>

/// RAII wrapper that creates an OpenSSL library context, loads the default
/// provider and the azihsm provider, and tears everything down on destruction.
///
/// The provider search path is taken from the `PROVIDER_PATH` environment
/// variable (defaults to `target/debug` if unset).
class ProviderCtx
{
  public:
    ProviderCtx()
    {
        const char *env = std::getenv("PROVIDER_PATH");
        provider_path_ = (env != nullptr && env[0] != '\0') ? env : "target/debug";

        libctx_ = OSSL_LIB_CTX_new();
        if (libctx_ == nullptr)
        {
            throw std::runtime_error("OSSL_LIB_CTX_new() failed");
        }

        if (OSSL_PROVIDER_set_default_search_path(libctx_, provider_path_.c_str()) != 1)
        {
            OSSL_LIB_CTX_free(libctx_);
            throw std::runtime_error("OSSL_PROVIDER_set_default_search_path() failed");
        }

        deflt_ = OSSL_PROVIDER_load(libctx_, "default");
        if (deflt_ == nullptr)
        {
            OSSL_LIB_CTX_free(libctx_);
            throw std::runtime_error("Failed to load default provider");
        }

        azihsm_ = OSSL_PROVIDER_load(libctx_, "azihsm_provider");
        if (azihsm_ == nullptr)
        {
            OSSL_PROVIDER_unload(deflt_);
            OSSL_LIB_CTX_free(libctx_);
            throw std::runtime_error(
                "Failed to load azihsm_provider from " + provider_path_
            );
        }
    }

    ~ProviderCtx() noexcept
    {
        if (azihsm_ != nullptr)
        {
            OSSL_PROVIDER_unload(azihsm_);
        }
        if (deflt_ != nullptr)
        {
            OSSL_PROVIDER_unload(deflt_);
        }
        if (libctx_ != nullptr)
        {
            OSSL_LIB_CTX_free(libctx_);
        }
    }

    // Non-copyable
    ProviderCtx(const ProviderCtx &) = delete;
    ProviderCtx &operator=(const ProviderCtx &) = delete;

    // Movable
    ProviderCtx(ProviderCtx &&other) noexcept
        : libctx_(other.libctx_), deflt_(other.deflt_), azihsm_(other.azihsm_),
          provider_path_(std::move(other.provider_path_))
    {
        other.libctx_ = nullptr;
        other.deflt_ = nullptr;
        other.azihsm_ = nullptr;
    }

    ProviderCtx &operator=(ProviderCtx &&other) noexcept
    {
        if (this != &other)
        {
            if (azihsm_ != nullptr)
                OSSL_PROVIDER_unload(azihsm_);
            if (deflt_ != nullptr)
                OSSL_PROVIDER_unload(deflt_);
            if (libctx_ != nullptr)
                OSSL_LIB_CTX_free(libctx_);

            libctx_ = other.libctx_;
            deflt_ = other.deflt_;
            azihsm_ = other.azihsm_;
            provider_path_ = std::move(other.provider_path_);

            other.libctx_ = nullptr;
            other.deflt_ = nullptr;
            other.azihsm_ = nullptr;
        }
        return *this;
    }

    /// The OpenSSL library context with both providers loaded.
    OSSL_LIB_CTX *libctx() const noexcept
    {
        return libctx_;
    }

    /// The loaded azihsm provider handle.
    OSSL_PROVIDER *azihsm() const noexcept
    {
        return azihsm_;
    }

    /// Property query string that directs OpenSSL to prefer the azihsm provider.
    static constexpr const char *propquery()
    {
        return "?provider=azihsm";
    }

  private:
    OSSL_LIB_CTX *libctx_ = nullptr;
    OSSL_PROVIDER *deflt_ = nullptr;
    OSSL_PROVIDER *azihsm_ = nullptr;
    std::string provider_path_;
};

#endif // PROVIDER_CTX_HPP
