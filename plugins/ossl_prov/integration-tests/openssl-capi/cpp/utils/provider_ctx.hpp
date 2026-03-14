// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef PROVIDER_CTX_HPP
#define PROVIDER_CTX_HPP

#include <cstdlib>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <stdexcept>
#include <string>

/// RAII wrapper that creates an OpenSSL library context and loads provider
/// configuration from `OPENSSL_CONF`.
///
/// The generated `openssl.cnf` (produced by the Rust test runner) auto-
/// activates the default and azihsm providers with absolute paths to both
/// the provider module and key material files.
class ProviderCtx
{
  public:
    ProviderCtx()
    {
        libctx_ = OSSL_LIB_CTX_new();
        if (libctx_ == nullptr)
        {
            throw std::runtime_error("OSSL_LIB_CTX_new() failed");
        }

        // We use AZIHSM_OPENSSL_CONF (not OPENSSL_CONF) to pass the config
        // path.  OPENSSL_CONF is processed automatically by OpenSSL for the
        // *default* library context during auto-init.  If we set OPENSSL_CONF,
        // the provider would be loaded twice (once into the default context,
        // once into ours), and the mock HSM device handle cannot be opened
        // concurrently — the second load deadlocks.
        const char *conf = std::getenv("AZIHSM_OPENSSL_CONF");
        if (conf == nullptr)
        {
            OSSL_LIB_CTX_free(libctx_);
            throw std::runtime_error(
                "AZIHSM_OPENSSL_CONF environment variable is not set"
            );
        }

        if (OSSL_LIB_CTX_load_config(libctx_, conf) != 1)
        {
            OSSL_LIB_CTX_free(libctx_);
            throw std::runtime_error(
                std::string("OSSL_LIB_CTX_load_config() failed for: ") + conf
            );
        }

        // Verify providers were activated by the config.
        if (!OSSL_PROVIDER_available(libctx_, "default"))
        {
            OSSL_LIB_CTX_free(libctx_);
            throw std::runtime_error(
                "default provider not available after config load"
            );
        }

        if (!OSSL_PROVIDER_available(libctx_, "azihsm"))
        {
            OSSL_LIB_CTX_free(libctx_);
            throw std::runtime_error(
                "azihsm provider not available after config load"
            );
        }
    }

    ~ProviderCtx() noexcept
    {
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
        : libctx_(other.libctx_)
    {
        other.libctx_ = nullptr;
    }

    ProviderCtx &operator=(ProviderCtx &&other) noexcept
    {
        if (this != &other)
        {
            if (libctx_ != nullptr)
                OSSL_LIB_CTX_free(libctx_);

            libctx_ = other.libctx_;
            other.libctx_ = nullptr;
        }
        return *this;
    }

    /// The OpenSSL library context with both providers loaded.
    OSSL_LIB_CTX *libctx() const noexcept
    {
        return libctx_;
    }

    /// Property query string that directs OpenSSL to prefer the azihsm provider.
    static constexpr const char *propquery()
    {
        return "?provider=azihsm";
    }

  private:
    OSSL_LIB_CTX *libctx_ = nullptr;
};

#endif // PROVIDER_CTX_HPP
