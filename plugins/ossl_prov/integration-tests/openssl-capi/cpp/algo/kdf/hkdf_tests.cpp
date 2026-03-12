// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file hkdf_tests.cpp
///
/// HKDF (HMAC-based Key Derivation Function) tests via the OpenSSL EVP KDF
/// API.  The azihsm provider's HKDF implementation takes a masked key blob as
/// IKM (input keying material), which is obtained from an ECDH derivation.
/// The derived output is also a masked key blob.

#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "utils/keygen_helpers.hpp"
#include "utils/ossl_helpers.hpp"
#include "utils/provider_ctx.hpp"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class hkdf : public ::testing::Test
{
  protected:
    ProviderCtx prov_;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Derive an AES-256 key from an ECDH shared secret via HKDF.
TEST_F(hkdf, derive_aes256)
{
    std::string ecdh_file = derive_masked_key_file(prov_.libctx());
    ASSERT_FALSE(ecdh_file.empty()) << "ECDH derivation failed";
    TempFileGuard ecdh_guard(ecdh_file.c_str());

    char output_path[] = "/tmp/azihsm_test_hkdf_out_XXXXXX";
    int fd = mkstemp(output_path);
    ASSERT_GE(fd, 0);
    ::close(fd);
    ::unlink(output_path);
    TempFileGuard out_guard(output_path);

    EvpKdfPtr kdf(EVP_KDF_fetch(prov_.libctx(), "HKDF", ProviderCtx::propquery()));
    ASSERT_NE(kdf, nullptr);

    EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(kctx, nullptr);

    char digest[] = "SHA256";
    char derived_type[] = "aes";
    uint32_t derived_bits = 256;

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_utf8_string("azihsm.ikm_file",
                               const_cast<char *>(ecdh_file.c_str()), 0),
        OSSL_PARAM_utf8_string("output_file", output_path, 0),
        OSSL_PARAM_utf8_string("derived_key_type", derived_type, 0),
        OSSL_PARAM_uint32("derived_key_bits", &derived_bits),
        OSSL_PARAM_END,
    };

    unsigned char dummy[4096];
    ASSERT_EQ(EVP_KDF_derive(kctx.get(), dummy, sizeof(dummy), params), 1)
        << "HKDF derive failed";

    struct stat st = {};
    ASSERT_EQ(::stat(output_path, &st), 0) << "Output file not created";
    EXPECT_GT(st.st_size, 0) << "Derived key file should be non-empty";
}

/// Derive with explicit salt and info parameters.
TEST_F(hkdf, derive_with_salt_and_info)
{
    std::string ecdh_file = derive_masked_key_file(prov_.libctx());
    ASSERT_FALSE(ecdh_file.empty());
    TempFileGuard ecdh_guard(ecdh_file.c_str());

    char output_path[] = "/tmp/azihsm_test_hkdf_si_XXXXXX";
    int fd = mkstemp(output_path);
    ASSERT_GE(fd, 0);
    ::close(fd);
    ::unlink(output_path);
    TempFileGuard out_guard(output_path);

    EvpKdfPtr kdf(EVP_KDF_fetch(prov_.libctx(), "HKDF", ProviderCtx::propquery()));
    ASSERT_NE(kdf, nullptr);
    EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf.get()));
    ASSERT_NE(kctx, nullptr);

    char digest[] = "SHA256";
    char derived_type[] = "aes";
    uint32_t derived_bits = 256;
    unsigned char salt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c};
    unsigned char info[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                            0xf8, 0xf9};

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_utf8_string("azihsm.ikm_file",
                               const_cast<char *>(ecdh_file.c_str()), 0),
        OSSL_PARAM_utf8_string("output_file", output_path, 0),
        OSSL_PARAM_utf8_string("derived_key_type", derived_type, 0),
        OSSL_PARAM_uint32("derived_key_bits", &derived_bits),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof(salt)),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, info, sizeof(info)),
        OSSL_PARAM_END,
    };

    unsigned char dummy[4096];
    ASSERT_EQ(EVP_KDF_derive(kctx.get(), dummy, sizeof(dummy), params), 1)
        << "HKDF derive with salt/info failed";

    struct stat st = {};
    ASSERT_EQ(::stat(output_path, &st), 0);
    EXPECT_GT(st.st_size, 0);
}

/// Different salt values produce different derived keys.
TEST_F(hkdf, different_salt_different_output)
{
    std::string ecdh_file = derive_masked_key_file(prov_.libctx());
    ASSERT_FALSE(ecdh_file.empty());
    TempFileGuard ecdh_guard(ecdh_file.c_str());

    auto derive_to_file = [&](unsigned char *salt, size_t salt_len,
                              const char *path) -> bool
    {
        EvpKdfPtr kdf(EVP_KDF_fetch(prov_.libctx(), "HKDF", ProviderCtx::propquery()));
        if (!kdf) return false;
        EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf.get()));
        if (!kctx) return false;

        char digest[] = "SHA256";
        char derived_type[] = "aes";
        uint32_t derived_bits = 256;

        OSSL_PARAM params[] = {
            OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
            OSSL_PARAM_utf8_string("azihsm.ikm_file",
                                   const_cast<char *>(ecdh_file.c_str()), 0),
            OSSL_PARAM_utf8_string("output_file", const_cast<char *>(path), 0),
            OSSL_PARAM_utf8_string("derived_key_type", derived_type, 0),
            OSSL_PARAM_uint32("derived_key_bits", &derived_bits),
            OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len),
            OSSL_PARAM_END,
        };

        unsigned char dummy[4096];
        return EVP_KDF_derive(kctx.get(), dummy, sizeof(dummy), params) == 1;
    };

    char path_a[] = "/tmp/azihsm_test_hkdf_a_XXXXXX";
    char path_b[] = "/tmp/azihsm_test_hkdf_b_XXXXXX";
    int fd_a = mkstemp(path_a);
    ASSERT_GE(fd_a, 0);
    ::close(fd_a);
    ::unlink(path_a);
    int fd_b = mkstemp(path_b);
    ASSERT_GE(fd_b, 0);
    ::close(fd_b);
    ::unlink(path_b);
    TempFileGuard guard_a(path_a);
    TempFileGuard guard_b(path_b);

    unsigned char salt_a[] = {0x01, 0x02, 0x03, 0x04};
    unsigned char salt_b[] = {0x05, 0x06, 0x07, 0x08};

    ASSERT_TRUE(derive_to_file(salt_a, sizeof(salt_a), path_a));
    ASSERT_TRUE(derive_to_file(salt_b, sizeof(salt_b), path_b));

    // Read both files and compare
    auto read_file = [](const char *path) -> std::vector<unsigned char>
    {
        FILE *f = std::fopen(path, "rb");
        if (!f) return {};
        std::fseek(f, 0, SEEK_END);
        long sz = std::ftell(f);
        std::fseek(f, 0, SEEK_SET);
        std::vector<unsigned char> buf(static_cast<size_t>(sz));
        std::fread(buf.data(), 1, buf.size(), f);
        std::fclose(f);
        return buf;
    };

    auto data_a = read_file(path_a);
    auto data_b = read_file(path_b);
    ASSERT_FALSE(data_a.empty());
    ASSERT_FALSE(data_b.empty());
    EXPECT_NE(data_a, data_b) << "Different salts should produce different derived keys";
}
