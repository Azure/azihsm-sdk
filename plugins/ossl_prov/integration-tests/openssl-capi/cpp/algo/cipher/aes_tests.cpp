// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file aes_tests.cpp
///
/// AES cipher tests (CBC / GCM / XTS) via the OpenSSL 3.5 EVP_SKEY API.  Keys
/// are created with EVP_SKEY_generate() against the "AES" SKEYMGMT and bound to
/// a cipher with EVP_CipherInit_SKEY(); no raw key material crosses the API.
/// `openssl enc` cannot drive GCM/XTS (opt_cipher() rejects AEAD + XTS), so
/// those round-trips are only expressible at the C-API level.
///
/// Tests are suffixed `_RequiresOpenssl35` (the harness reports them ignored on
/// OpenSSL 3.0) and guarded by `#if OPENSSL_VERSION_NUMBER >= 0x30500000L` so the
/// file still compiles against pre-3.5 headers.

#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <string>
#include <vector>

#include "utils/ossl_helpers.hpp"
#include "utils/provider_ctx.hpp"

class aes_skey : public ::testing::Test
{
  protected:
    ProviderCtx prov_;
};

#if OPENSSL_VERSION_NUMBER >= 0x30500000L

namespace
{

struct EvpSkeyDeleter
{
    void operator()(EVP_SKEY *p) const
    {
        EVP_SKEY_free(p);
    }
};
using EvpSkeyPtr = std::unique_ptr<EVP_SKEY, EvpSkeyDeleter>;

/// Generate an opaque, HSM-backed AES key.
///
/// @param key_bytes  raw key length in bytes (16/24/32 for AES, 32 for GCM,
///                   64 for the XTS key pair).
/// @param kind       azihsm.key_kind selector ("AES-GCM" / "AES-XTS"); pass
///                   nullptr for a plain AES (CBC-capable) key.
EvpSkeyPtr generate_skey(OSSL_LIB_CTX *libctx, size_t key_bytes, const char *kind)
{
    size_t klen = key_bytes;
    OSSL_PARAM params[3];
    int n = 0;
    params[n++] = OSSL_PARAM_construct_size_t(OSSL_SKEY_PARAM_KEY_LENGTH, &klen);
    if (kind != nullptr)
    {
        params[n++] =
            OSSL_PARAM_construct_utf8_string("azihsm.key_kind", const_cast<char *>(kind), 0);
    }
    params[n++] = OSSL_PARAM_construct_end();

    return EvpSkeyPtr(EVP_SKEY_generate(libctx, "AES", ProviderCtx::propquery(), params));
}

EvpCipherPtr fetch_cipher(OSSL_LIB_CTX *libctx, const char *name)
{
    return EvpCipherPtr(EVP_CIPHER_fetch(libctx, name, ProviderCtx::propquery()));
}

} // namespace

// ---------------------------------------------------------------------------
// AES-CBC
// ---------------------------------------------------------------------------

/// Encrypt-then-decrypt round-trip for AES-256-CBC with PKCS#7 padding using an
/// opaque HSM key, asserting the recovered plaintext matches.
TEST_F(aes_skey, cbc_roundtrip_RequiresOpenssl35)
{
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 32, nullptr);
    ASSERT_NE(skey, nullptr) << "EVP_SKEY_generate(AES) failed";

    EvpCipherPtr cipher = fetch_cipher(prov_.libctx(), "AES-256-CBC");
    ASSERT_NE(cipher, nullptr) << "EVP_CIPHER_fetch(AES-256-CBC) failed";

    unsigned char iv[16];
    for (int i = 0; i < 16; ++i)
        iv[i] = static_cast<unsigned char>(i);

    // Not a multiple of the 16-byte block size, so the final-block padding path
    // is exercised.
    const std::string msg = "The quick brown fox jumps over the lazy dog!!";
    std::vector<unsigned char> pt(msg.begin(), msg.end());

    // Encrypt
    EvpCipherCtxPtr ectx(EVP_CIPHER_CTX_new());
    ASSERT_NE(ectx, nullptr);
    ASSERT_EQ(
        EVP_CipherInit_SKEY(ectx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 1, nullptr),
        1
    ) << "encrypt skey-init failed";

    std::vector<unsigned char> ct(pt.size() + 32);
    int outl = 0;
    int total = 0;
    ASSERT_EQ(
        EVP_CipherUpdate(ectx.get(), ct.data(), &outl, pt.data(), static_cast<int>(pt.size())),
        1
    );
    total = outl;
    ASSERT_EQ(EVP_CipherFinal_ex(ectx.get(), ct.data() + total, &outl), 1);
    total += outl;
    ct.resize(static_cast<size_t>(total));
    // CBC + PKCS#7 padding always rounds up to the next full block.
    EXPECT_EQ(ct.size() % 16, 0u);
    EXPECT_GT(ct.size(), pt.size());

    // Decrypt
    EvpCipherCtxPtr dctx(EVP_CIPHER_CTX_new());
    ASSERT_NE(dctx, nullptr);
    ASSERT_EQ(
        EVP_CipherInit_SKEY(dctx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 0, nullptr),
        1
    ) << "decrypt skey-init failed";

    std::vector<unsigned char> dec(ct.size() + 32);
    int doutl = 0;
    int dtotal = 0;
    ASSERT_EQ(
        EVP_CipherUpdate(dctx.get(), dec.data(), &doutl, ct.data(), static_cast<int>(ct.size())),
        1
    );
    dtotal = doutl;
    ASSERT_EQ(EVP_CipherFinal_ex(dctx.get(), dec.data() + dtotal, &doutl), 1);
    dtotal += doutl;
    dec.resize(static_cast<size_t>(dtotal));

    EXPECT_EQ(dec, pt);
}

// ---------------------------------------------------------------------------
// AES-GCM (AEAD tag + AAD)
// ---------------------------------------------------------------------------

/// AES-256-GCM round-trip with AAD: encrypt produces a tag, decrypt verifies it.
///
/// The azihsm HSM performs GCM as a one-shot operation, so the AEAD tag must be
/// set (for decrypt) before the ciphertext is fed via EVP_CipherUpdate.
TEST_F(aes_skey, gcm_roundtrip_with_aad_RequiresOpenssl35)
{
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 32, "AES-GCM");
    ASSERT_NE(skey, nullptr) << "EVP_SKEY_generate(AES-GCM) failed";

    EvpCipherPtr cipher = fetch_cipher(prov_.libctx(), "AES-256-GCM");
    ASSERT_NE(cipher, nullptr) << "EVP_CIPHER_fetch(AES-256-GCM) failed";

    unsigned char iv[12];
    for (int i = 0; i < 12; ++i)
        iv[i] = static_cast<unsigned char>(0xA0 + i);

    const std::string msg = "Sphinx of black quartz, judge my vow.";
    std::vector<unsigned char> pt(msg.begin(), msg.end());
    const std::string aad_s = "header-v1";
    std::vector<unsigned char> aad(aad_s.begin(), aad_s.end());

    // Encrypt
    EvpCipherCtxPtr ectx(EVP_CIPHER_CTX_new());
    ASSERT_NE(ectx, nullptr);
    ASSERT_EQ(
        EVP_CipherInit_SKEY(ectx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 1, nullptr),
        1
    );

    int outl = 0;
    // AAD is fed with a NULL output buffer.
    ASSERT_EQ(
        EVP_CipherUpdate(ectx.get(), nullptr, &outl, aad.data(), static_cast<int>(aad.size())),
        1
    );

    std::vector<unsigned char> ct(pt.size() + 16);
    int total = 0;
    ASSERT_EQ(
        EVP_CipherUpdate(ectx.get(), ct.data(), &outl, pt.data(), static_cast<int>(pt.size())),
        1
    );
    total = outl;
    ASSERT_EQ(EVP_CipherFinal_ex(ectx.get(), ct.data() + total, &outl), 1);
    total += outl;
    ct.resize(static_cast<size_t>(total));
    EXPECT_EQ(ct.size(), pt.size()); // GCM ciphertext length == plaintext length

    unsigned char tag[16] = { 0 };
    OSSL_PARAM get_tag[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_construct_end(),
    };
    ASSERT_EQ(EVP_CIPHER_CTX_get_params(ectx.get(), get_tag), 1) << "failed to read GCM tag";

    // Decrypt with the correct tag -> succeeds and recovers the plaintext.
    EvpCipherCtxPtr dctx(EVP_CIPHER_CTX_new());
    ASSERT_NE(dctx, nullptr);
    ASSERT_EQ(
        EVP_CipherInit_SKEY(dctx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 0, nullptr),
        1
    );

    ASSERT_EQ(
        EVP_CipherUpdate(dctx.get(), nullptr, &outl, aad.data(), static_cast<int>(aad.size())),
        1
    );

    OSSL_PARAM set_tag[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_construct_end(),
    };
    ASSERT_EQ(EVP_CIPHER_CTX_set_params(dctx.get(), set_tag), 1) << "failed to set GCM tag";

    std::vector<unsigned char> dec(ct.size() + 16);
    int dtotal = 0;
    ASSERT_EQ(
        EVP_CipherUpdate(dctx.get(), dec.data(), &outl, ct.data(), static_cast<int>(ct.size())),
        1
    ) << "GCM decrypt/verify failed for valid tag";
    dtotal = outl;
    int fret = EVP_CipherFinal_ex(dctx.get(), dec.data() + dtotal, &outl);
    dtotal += (fret == 1 ? outl : 0);
    dec.resize(static_cast<size_t>(dtotal));

    EXPECT_EQ(fret, 1);
    EXPECT_EQ(dec, pt);
}

/// A corrupted AEAD tag must cause GCM decryption to fail (authentication).
TEST_F(aes_skey, gcm_bad_tag_rejected_RequiresOpenssl35)
{
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 32, "AES-GCM");
    ASSERT_NE(skey, nullptr);
    EvpCipherPtr cipher = fetch_cipher(prov_.libctx(), "AES-256-GCM");
    ASSERT_NE(cipher, nullptr);

    unsigned char iv[12] = { 0 };
    const std::string msg = "authenticate me";
    std::vector<unsigned char> pt(msg.begin(), msg.end());

    EvpCipherCtxPtr ectx(EVP_CIPHER_CTX_new());
    ASSERT_EQ(
        EVP_CipherInit_SKEY(ectx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 1, nullptr),
        1
    );
    std::vector<unsigned char> ct(pt.size() + 16);
    int outl = 0;
    int total = 0;
    ASSERT_EQ(
        EVP_CipherUpdate(ectx.get(), ct.data(), &outl, pt.data(), static_cast<int>(pt.size())),
        1
    );
    total = outl;
    ASSERT_EQ(EVP_CipherFinal_ex(ectx.get(), ct.data() + total, &outl), 1);
    total += outl;
    ct.resize(static_cast<size_t>(total));

    unsigned char tag[16] = { 0 };
    OSSL_PARAM get_tag[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_construct_end(),
    };
    ASSERT_EQ(EVP_CIPHER_CTX_get_params(ectx.get(), get_tag), 1);

    tag[0] ^= 0xFF; // corrupt the tag

    EvpCipherCtxPtr dctx(EVP_CIPHER_CTX_new());
    ASSERT_EQ(
        EVP_CipherInit_SKEY(dctx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 0, nullptr),
        1
    );
    OSSL_PARAM set_tag[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag)),
        OSSL_PARAM_construct_end(),
    };
    ASSERT_EQ(EVP_CIPHER_CTX_set_params(dctx.get(), set_tag), 1);

    std::vector<unsigned char> dec(ct.size() + 16);
    int dtotal = 0;
    int upd =
        EVP_CipherUpdate(dctx.get(), dec.data(), &outl, ct.data(), static_cast<int>(ct.size()));
    dtotal = (upd == 1 ? outl : 0);
    int fin = EVP_CipherFinal_ex(dctx.get(), dec.data() + dtotal, &outl);

    // Authentication failure may surface at the (one-shot) update or at final;
    // either way the overall decryption must NOT succeed.
    EXPECT_FALSE(upd == 1 && fin == 1) << "GCM accepted a corrupted tag";
}

// ---------------------------------------------------------------------------
// AES-XTS (double-length key)
// ---------------------------------------------------------------------------

/// AES-256-XTS round-trip over a single data unit using an opaque key pair.
TEST_F(aes_skey, xts_roundtrip_RequiresOpenssl35)
{
    // XTS key is a pair of AES-256 halves: 64 bytes total (512 bits).
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 64, "AES-XTS");
    ASSERT_NE(skey, nullptr) << "EVP_SKEY_generate(AES-XTS) failed";

    EvpCipherPtr cipher = fetch_cipher(prov_.libctx(), "AES-256-XTS");
    ASSERT_NE(cipher, nullptr) << "EVP_CIPHER_fetch(AES-256-XTS) failed";

    // 16-byte tweak / data-unit number.
    unsigned char iv[16];
    for (int i = 0; i < 16; ++i)
        iv[i] = static_cast<unsigned char>(i + 1);

    // XTS requires at least one full block (16 bytes) in a data unit.
    std::vector<unsigned char> pt(64);
    for (size_t i = 0; i < pt.size(); ++i)
        pt[i] = static_cast<unsigned char>(i * 7 + 3);

    EvpCipherCtxPtr ectx(EVP_CIPHER_CTX_new());
    ASSERT_EQ(
        EVP_CipherInit_SKEY(ectx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 1, nullptr),
        1
    );
    std::vector<unsigned char> ct(pt.size() + 16);
    int outl = 0;
    int total = 0;
    ASSERT_EQ(
        EVP_CipherUpdate(ectx.get(), ct.data(), &outl, pt.data(), static_cast<int>(pt.size())),
        1
    );
    total = outl;
    ASSERT_EQ(EVP_CipherFinal_ex(ectx.get(), ct.data() + total, &outl), 1);
    total += outl;
    ct.resize(static_cast<size_t>(total));
    EXPECT_EQ(ct.size(), pt.size()); // XTS ciphertext length == plaintext length
    EXPECT_NE(ct, pt);

    EvpCipherCtxPtr dctx(EVP_CIPHER_CTX_new());
    ASSERT_EQ(
        EVP_CipherInit_SKEY(dctx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 0, nullptr),
        1
    );
    std::vector<unsigned char> dec(ct.size() + 16);
    int dtotal = 0;
    ASSERT_EQ(
        EVP_CipherUpdate(dctx.get(), dec.data(), &outl, ct.data(), static_cast<int>(ct.size())),
        1
    );
    dtotal = outl;
    ASSERT_EQ(EVP_CipherFinal_ex(dctx.get(), dec.data() + dtotal, &outl), 1);
    dtotal += outl;
    dec.resize(static_cast<size_t>(dtotal));

    EXPECT_EQ(dec, pt);
}

// ---------------------------------------------------------------------------
// Opacity guarantee
// ---------------------------------------------------------------------------

/// The HSM-backed key must never expose raw key material:
/// EVP_SKEY_get0_raw_key() must fail.
TEST_F(aes_skey, opaque_key_not_exportable_RequiresOpenssl35)
{
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 32, nullptr);
    ASSERT_NE(skey, nullptr);

    const unsigned char *raw = nullptr;
    size_t raw_len = 0;
    EXPECT_EQ(EVP_SKEY_get0_raw_key(skey.get(), &raw, &raw_len), 0)
        << "opaque HSM key must not export raw bytes";
}

#endif // OPENSSL_VERSION_NUMBER >= 0x30500000L
