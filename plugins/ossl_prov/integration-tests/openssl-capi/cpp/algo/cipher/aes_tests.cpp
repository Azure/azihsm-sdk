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

/// OSSL_CIPHER_PARAM_UPDATED_IV must report the post-update CBC chaining IV (the
/// last ciphertext block), not the original init IV, so a caller can resume the
/// chain.
TEST_F(aes_skey, cbc_updated_iv_tracks_chaining_RequiresOpenssl35)
{
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 32, nullptr);
    ASSERT_NE(skey, nullptr);
    EvpCipherPtr cipher = fetch_cipher(prov_.libctx(), "AES-256-CBC");
    ASSERT_NE(cipher, nullptr);

    unsigned char iv[16];
    for (int i = 0; i < 16; ++i)
        iv[i] = static_cast<unsigned char>(i);

    EvpCipherCtxPtr ectx(EVP_CIPHER_CTX_new());
    ASSERT_EQ(
        EVP_CipherInit_SKEY(ectx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 1, nullptr),
        1
    );

    // Two full blocks: the update emits 32 bytes and chains the IV forward.
    std::vector<unsigned char> pt(32, 0x5A);
    std::vector<unsigned char> ct(pt.size() + 16);
    int outl = 0;
    ASSERT_EQ(
        EVP_CipherUpdate(ectx.get(), ct.data(), &outl, pt.data(), static_cast<int>(pt.size())),
        1
    );
    ASSERT_EQ(outl, 32);

    unsigned char updated[16] = { 0 };
    OSSL_PARAM get_iv[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, updated, sizeof(updated)),
        OSSL_PARAM_construct_end(),
    };
    ASSERT_EQ(EVP_CIPHER_CTX_get_params(ectx.get(), get_iv), 1);

    // The chained IV is the last ciphertext block produced so far, and has moved
    // on from the original init IV.
    EXPECT_EQ(std::memcmp(updated, ct.data() + 16, 16), 0)
        << "UPDATED_IV must equal the last ciphertext block";
    EXPECT_NE(std::memcmp(updated, iv, 16), 0) << "UPDATED_IV must not be the init IV";
}

/// The CBC *decrypt* streaming path must also advance UPDATED_IV (the FFI writes
/// the chaining IV back on each update); it must not keep reporting the init IV.
TEST_F(aes_skey, cbc_decrypt_updated_iv_tracks_chaining_RequiresOpenssl35)
{
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 32, nullptr);
    ASSERT_NE(skey, nullptr);
    EvpCipherPtr cipher = fetch_cipher(prov_.libctx(), "AES-256-CBC");
    ASSERT_NE(cipher, nullptr);

    unsigned char iv[16];
    for (int i = 0; i < 16; ++i)
        iv[i] = static_cast<unsigned char>(i);

    // Produce two ciphertext blocks.
    std::vector<unsigned char> pt(32, 0x5A);
    EvpCipherCtxPtr ectx(EVP_CIPHER_CTX_new());
    ASSERT_EQ(
        EVP_CipherInit_SKEY(ectx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 1, nullptr),
        1
    );
    std::vector<unsigned char> ct(pt.size() + 16);
    int outl = 0;
    ASSERT_EQ(
        EVP_CipherUpdate(ectx.get(), ct.data(), &outl, pt.data(), static_cast<int>(pt.size())),
        1
    );
    ASSERT_EQ(outl, 32);

    // Decrypt: feed the ciphertext, then read UPDATED_IV.
    EvpCipherCtxPtr dctx(EVP_CIPHER_CTX_new());
    ASSERT_EQ(
        EVP_CipherInit_SKEY(dctx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 0, nullptr),
        1
    );
    std::vector<unsigned char> dec(ct.size() + 16);
    ASSERT_EQ(EVP_CipherUpdate(dctx.get(), dec.data(), &outl, ct.data(), 32), 1);

    unsigned char updated[16] = { 0 };
    OSSL_PARAM get_iv[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, updated, sizeof(updated)),
        OSSL_PARAM_construct_end(),
    };
    ASSERT_EQ(EVP_CIPHER_CTX_get_params(dctx.get(), get_iv), 1);
    EXPECT_NE(std::memcmp(updated, iv, 16), 0)
        << "decrypt UPDATED_IV must advance from the init IV";
}

/// A key whose length is known must match the cipher variant: an AES-256 key
/// must not bind to AES-128-CBC, but must bind to AES-256-CBC.
TEST_F(aes_skey, init_rejects_key_length_mismatch_RequiresOpenssl35)
{
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 32, nullptr); // AES-256, key_bytes=32
    ASSERT_NE(skey, nullptr);

    unsigned char iv[16] = { 0 };

    EvpCipherPtr c128 = fetch_cipher(prov_.libctx(), "AES-128-CBC");
    ASSERT_NE(c128, nullptr);
    EvpCipherCtxPtr bad(EVP_CIPHER_CTX_new());
    EXPECT_NE(EVP_CipherInit_SKEY(bad.get(), c128.get(), skey.get(), iv, sizeof(iv), 1, nullptr), 1)
        << "binding a 32-byte key to AES-128-CBC must fail";

    EvpCipherPtr c256 = fetch_cipher(prov_.libctx(), "AES-256-CBC");
    ASSERT_NE(c256, nullptr);
    EvpCipherCtxPtr ok(EVP_CIPHER_CTX_new());
    EXPECT_EQ(EVP_CipherInit_SKEY(ok.get(), c256.get(), skey.get(), iv, sizeof(iv), 1, nullptr), 1)
        << "the matching AES-256-CBC binding must succeed";
}

/// A cipher context cannot be cloned faithfully once data processing has begun
/// (CBC carries chaining state), so EVP_CIPHER_CTX_copy() must fail mid-stream
/// rather than produce a half-copied context; copying a fresh context is fine.
TEST_F(aes_skey, dupctx_after_update_rejected_RequiresOpenssl35)
{
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 32, nullptr);
    ASSERT_NE(skey, nullptr);
    EvpCipherPtr cipher = fetch_cipher(prov_.libctx(), "AES-256-CBC");
    ASSERT_NE(cipher, nullptr);

    unsigned char iv[16] = { 0 };
    EvpCipherCtxPtr ectx(EVP_CIPHER_CTX_new());
    ASSERT_EQ(
        EVP_CipherInit_SKEY(ectx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 1, nullptr),
        1
    );

    // A copy before any data has been fed is allowed.
    EvpCipherCtxPtr fresh(EVP_CIPHER_CTX_new());
    EXPECT_EQ(EVP_CIPHER_CTX_copy(fresh.get(), ectx.get()), 1)
        << "copying a freshly-initialised context should succeed";

    // Feed a block; the chaining state now makes a faithful copy impossible.
    std::vector<unsigned char> pt(16, 0x11);
    std::vector<unsigned char> ct(pt.size() + 16);
    int outl = 0;
    ASSERT_EQ(
        EVP_CipherUpdate(ectx.get(), ct.data(), &outl, pt.data(), static_cast<int>(pt.size())),
        1
    );

    EvpCipherCtxPtr mid(EVP_CIPHER_CTX_new());
    EXPECT_NE(EVP_CIPHER_CTX_copy(mid.get(), ectx.get()), 1)
        << "copying a mid-stream context must fail";
}

/// Reusing an EVP_CIPHER_CTX via a second EVP_CipherInit_SKEY must fully reset
/// per-operation state (CBC chaining IV, buffered sub-block): the re-initialised
/// context must produce the same ciphertext as a fresh one.
TEST_F(aes_skey, cbc_reinit_resets_state_RequiresOpenssl35)
{
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 32, nullptr);
    ASSERT_NE(skey, nullptr);
    EvpCipherPtr cipher = fetch_cipher(prov_.libctx(), "AES-256-CBC");
    ASSERT_NE(cipher, nullptr);

    unsigned char iv1[16];
    unsigned char iv2[16];
    for (int i = 0; i < 16; ++i)
    {
        iv1[i] = static_cast<unsigned char>(i);
        iv2[i] = static_cast<unsigned char>(0xF0 + i);
    }
    const std::string msg = "reuse the same context!!";
    std::vector<unsigned char> pt(msg.begin(), msg.end());

    auto encrypt = [&](EVP_CIPHER_CTX *c, const unsigned char *iv) {
        EXPECT_EQ(EVP_CipherInit_SKEY(c, cipher.get(), skey.get(), iv, 16, 1, nullptr), 1);
        std::vector<unsigned char> ct(pt.size() + 16);
        int outl = 0;
        int total = 0;
        EXPECT_EQ(EVP_CipherUpdate(c, ct.data(), &outl, pt.data(), static_cast<int>(pt.size())), 1);
        total = outl;
        EXPECT_EQ(EVP_CipherFinal_ex(c, ct.data() + total, &outl), 1);
        total += outl;
        ct.resize(static_cast<size_t>(total));
        return ct;
    };

    // First operation with iv1, then RE-INIT the same context with iv2.
    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    encrypt(ctx.get(), iv1);
    std::vector<unsigned char> reused = encrypt(ctx.get(), iv2);

    // A fresh context with iv2 must produce identical ciphertext.
    EvpCipherCtxPtr fresh(EVP_CIPHER_CTX_new());
    std::vector<unsigned char> clean = encrypt(fresh.get(), iv2);

    EXPECT_EQ(reused, clean) << "re-init must reset CBC state to match a fresh context";
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

/// AES-GCM must never encrypt under an unset (NULL) nonce.  This provider has no
/// post-init IV parameter, so a NULL IV is unrecoverable: init must fail closed
/// rather than silently use an all-zero nonce (a catastrophic reuse hazard).
TEST_F(aes_skey, gcm_missing_iv_rejected_RequiresOpenssl35)
{
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 32, "AES-GCM");
    ASSERT_NE(skey, nullptr);
    EvpCipherPtr cipher = fetch_cipher(prov_.libctx(), "AES-256-GCM");
    ASSERT_NE(cipher, nullptr);

    EvpCipherCtxPtr ectx(EVP_CIPHER_CTX_new());
    ASSERT_NE(ectx, nullptr);
    EXPECT_NE(EVP_CipherInit_SKEY(ectx.get(), cipher.get(), skey.get(), nullptr, 0, 1, nullptr), 1)
        << "GCM encrypt-init with a NULL IV must fail, not default to a zero nonce";
}

/// AES-GCM decrypt verifies the tag inside the single HSM operation, so feeding
/// ciphertext before the tag is set must fail clearly instead of decrypting
/// against an unset (zero) tag.
TEST_F(aes_skey, gcm_decrypt_without_tag_rejected_RequiresOpenssl35)
{
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 32, "AES-GCM");
    ASSERT_NE(skey, nullptr);
    EvpCipherPtr cipher = fetch_cipher(prov_.libctx(), "AES-256-GCM");
    ASSERT_NE(cipher, nullptr);

    unsigned char iv[12];
    for (int i = 0; i < 12; ++i)
        iv[i] = static_cast<unsigned char>(i);
    const std::string msg = "tag before data";
    std::vector<unsigned char> pt(msg.begin(), msg.end());

    // Encrypt to obtain valid ciphertext (the tag is intentionally discarded).
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

    // Decrypt WITHOUT setting the tag: the ciphertext update must fail.
    EvpCipherCtxPtr dctx(EVP_CIPHER_CTX_new());
    ASSERT_EQ(
        EVP_CipherInit_SKEY(dctx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 0, nullptr),
        1
    );
    std::vector<unsigned char> dec(ct.size() + 16);
    EXPECT_NE(
        EVP_CipherUpdate(dctx.get(), dec.data(), &outl, ct.data(), static_cast<int>(ct.size())),
        1
    ) << "GCM decrypt without a tag must fail, not run against a zero tag";
}

/// A truncated GCM tag read (a leading prefix of the full 16-byte tag) must be
/// honoured rather than rejected.
TEST_F(aes_skey, gcm_tag_truncation_supported_RequiresOpenssl35)
{
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 32, "AES-GCM");
    ASSERT_NE(skey, nullptr);
    EvpCipherPtr cipher = fetch_cipher(prov_.libctx(), "AES-256-GCM");
    ASSERT_NE(cipher, nullptr);

    unsigned char iv[12] = { 0 };
    const std::string msg = "truncate my tag";
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

    unsigned char full[16] = { 0 };
    OSSL_PARAM get_full[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, full, sizeof(full)),
        OSSL_PARAM_construct_end(),
    };
    ASSERT_EQ(EVP_CIPHER_CTX_get_params(ectx.get(), get_full), 1);

    unsigned char trunc[12] = { 0 };
    OSSL_PARAM get_trunc[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, trunc, sizeof(trunc)),
        OSSL_PARAM_construct_end(),
    };
    ASSERT_EQ(EVP_CIPHER_CTX_get_params(ectx.get(), get_trunc), 1)
        << "a 12-byte (truncated) GCM tag read must be accepted";
    EXPECT_EQ(std::memcmp(full, trunc, sizeof(trunc)), 0)
        << "truncated tag must be the leading prefix of the full tag";
}

/// GCM AAD supplied after the (one-shot) data update must be rejected: it could
/// not have been folded into the authentication tag.
TEST_F(aes_skey, gcm_aad_after_data_rejected_RequiresOpenssl35)
{
    EvpSkeyPtr skey = generate_skey(prov_.libctx(), 32, "AES-GCM");
    ASSERT_NE(skey, nullptr);
    EvpCipherPtr cipher = fetch_cipher(prov_.libctx(), "AES-256-GCM");
    ASSERT_NE(cipher, nullptr);

    unsigned char iv[12] = { 0 };
    const std::string msg = "data first";
    std::vector<unsigned char> pt(msg.begin(), msg.end());

    EvpCipherCtxPtr ectx(EVP_CIPHER_CTX_new());
    ASSERT_EQ(
        EVP_CipherInit_SKEY(ectx.get(), cipher.get(), skey.get(), iv, sizeof(iv), 1, nullptr),
        1
    );
    std::vector<unsigned char> ct(pt.size() + 16);
    int outl = 0;
    ASSERT_EQ(
        EVP_CipherUpdate(ectx.get(), ct.data(), &outl, pt.data(), static_cast<int>(pt.size())),
        1
    );

    // Feeding AAD (out == NULL) after the data one-shot must fail.
    const unsigned char aad[4] = { 1, 2, 3, 4 };
    EXPECT_NE(EVP_CipherUpdate(ectx.get(), nullptr, &outl, aad, sizeof(aad)), 1)
        << "AAD after the GCM data one-shot must be rejected";
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

/// Key generation must reject lengths the HSM cannot honour, with a clear early
/// failure, while a supported length still succeeds.
TEST_F(aes_skey, generate_rejects_unsupported_key_length_RequiresOpenssl35)
{
    // AES-GCM is 256-bit only.
    EXPECT_EQ(generate_skey(prov_.libctx(), 16, "AES-GCM"), nullptr)
        << "AES-GCM with a 16-byte key must be rejected";
    // Plain AES accepts only 16/24/32 bytes.
    EXPECT_EQ(generate_skey(prov_.libctx(), 20, nullptr), nullptr)
        << "AES with a 20-byte key must be rejected";
    // A supported length still generates.
    EXPECT_NE(generate_skey(prov_.libctx(), 32, nullptr), nullptr) << "AES-256 must still generate";
}

#endif // OPENSSL_VERSION_NUMBER >= 0x30500000L
