// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file gcm_tests.cpp
///
/// One-shot C_Encrypt / C_Decrypt with CKM_AES_GCM through the module ABI:
/// round trips with and without AAD, the PKCS#11 ciphertext layout (the tag
/// appended), authentication failures, the CK_GCM_PARAMS shapes the device
/// cannot run, the key-family gate between GCM and CBC keys, and the sizing
/// and lifetime rules shared with CBC. Every case starts from a fresh GCM key.

#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"

namespace
{

constexpr CK_ULONG kGcmIv = 12;
constexpr CK_ULONG kGcmTag = 16;

} // namespace

class aes_gcm : public UserSession
{
  protected:
    void SetUp() override
    {
        UserSession::SetUp();
        if (HasFatalFailure())
        {
            return;
        }
        ASSERT_CKR_OK(gen_gcm_key(s_, "gcm-fixture", &key_));
        std::memset(iv_, 0x3C, sizeof(iv_));
        const char aad[] = "header-bytes";
        aad_.assign(aad, aad + sizeof(aad) - 1);
        plain_.resize(37); // deliberately not a block multiple
        for (size_t i = 0; i < plain_.size(); i++)
        {
            plain_[i] = static_cast<CK_BYTE>(0x40 + i);
        }
        set_params(aad_.data(), static_cast<CK_ULONG>(aad_.size()));
    }

    /// Point params_ at iv_ and the given AAD with a 128-bit tag.
    void set_params(CK_BYTE_PTR aad, CK_ULONG aad_len)
    {
        params_ = {};
        params_.pIv = iv_;
        params_.ulIvLen = kGcmIv;
        params_.ulIvBits = kGcmIv * 8;
        params_.pAAD = aad;
        params_.ulAADLen = aad_len;
        params_.ulTagBits = kGcmTag * 8;
        mech_ = { CKM_AES_GCM, &params_, sizeof(params_) };
    }

    /// Encrypt plain_ into `ct` (plaintext length + tag). ASSERTs on failure.
    void encrypt_plain(std::vector<CK_BYTE> &ct)
    {
        ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, plain_, ct));
        ASSERT_EQ(plain_.size() + kGcmTag, ct.size());
    }

    /// Decrypt `ct` under mech_ and expect it to be refused with no output.
    /// Every backend reports a failed tag check today as the generic
    /// device-command failure, which the module cannot tell apart from a device
    /// fault, so it is CKR_FUNCTION_FAILED rather than CKR_ENCRYPTED_DATA_INVALID
    /// (see azihsm_pkcs11_status.c). The assertion pins that, so it flags the
    /// day the SDK starts reporting the tag check on its own. ASSERTs on
    /// failure, so call it as ASSERT_NO_FATAL_FAILURE(expect_refused(ct)).
    void expect_refused(std::vector<CK_BYTE> ct)
    {
        ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &mech_, key_));
        std::vector<CK_BYTE> out(ct.size(), 0xEE);
        CK_ULONG len = static_cast<CK_ULONG>(out.size());
        EXPECT_CKR(
            CKR_FUNCTION_FAILED,
            p11()->C_Decrypt(s_, ct.data(), static_cast<CK_ULONG>(ct.size()), out.data(), &len)
        );
        EXPECT_EQ(0u, len);
        // Whatever the device produced before refusing must not be handed back
        // behind a zero length, and nothing beyond the plaintext span is touched.
        size_t pt_len = ct.size() - kGcmTag;
        for (size_t i = 0; i < pt_len; i++)
        {
            ASSERT_EQ(0, out[i]) << "byte " << i << " of the output buffer was not wiped";
        }
        for (size_t i = pt_len; i < out.size(); i++)
        {
            EXPECT_EQ(0xEE, out[i]) << "bytes beyond the plaintext span are untouched";
        }
        EXPECT_CKR(
            CKR_OPERATION_NOT_INITIALIZED,
            p11()->C_Decrypt(s_, ct.data(), static_cast<CK_ULONG>(ct.size()), out.data(), &len)
        ) << "the failure terminated the operation";
    }

    CK_OBJECT_HANDLE key_ = 0;
    CK_BYTE iv_[kGcmIv];
    std::vector<CK_BYTE> aad_;
    std::vector<CK_BYTE> plain_;
    CK_GCM_PARAMS params_{};
    CK_MECHANISM mech_{};
};

// ---------------------------------------------------------------------------
// Round trips, layout and sizing
// ---------------------------------------------------------------------------

TEST_F(aes_gcm, roundtrip_with_aad_and_two_call_sizing)
{
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, key_));
    CK_ULONG need = 0;
    ASSERT_CKR_OK(p11()->C_Encrypt(s_, plain_.data(), 37, nullptr, &need));
    EXPECT_EQ(37u + kGcmTag, need) << "the tag is appended to the ciphertext";

    std::vector<CK_BYTE> ct(64, 0);
    CK_ULONG small = 37; // room for the ciphertext but not the tag
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_Encrypt(s_, plain_.data(), 37, ct.data(), &small));
    EXPECT_EQ(need, small);

    CK_ULONG len = static_cast<CK_ULONG>(ct.size()); // larger than needed is fine
    ASSERT_CKR_OK(p11()->C_Encrypt(s_, plain_.data(), 37, ct.data(), &len))
        << "the probe and the too-small call kept the operation alive";
    EXPECT_EQ(need, len);
    ct.resize(len);
    EXPECT_NE(0, std::memcmp(ct.data(), plain_.data(), plain_.size()));

    std::vector<CK_BYTE> back;
    ASSERT_CKR_OK(crypt_oneshot(s_, false, &mech_, key_, ct, back));
    EXPECT_EQ(plain_, back);
}

TEST_F(aes_gcm, roundtrip_without_aad)
{
    set_params(nullptr, 0);
    std::vector<CK_BYTE> ct, back;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain(ct));
    ASSERT_CKR_OK(crypt_oneshot(s_, false, &mech_, key_, ct, back));
    EXPECT_EQ(plain_, back);
}

TEST_F(aes_gcm, empty_plaintext_yields_just_the_tag)
{
    std::vector<CK_BYTE> empty, ct, back;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, empty, ct));
    EXPECT_EQ(kGcmTag, ct.size());
    ASSERT_CKR_OK(crypt_oneshot(s_, false, &mech_, key_, ct, back));
    EXPECT_TRUE(back.empty());
    // The decrypt really ran and checked the tag: the operation is over, not
    // still waiting for a fill.
    CK_BYTE none = 0;
    CK_ULONG len = 0;
    EXPECT_CKR(
        CKR_OPERATION_NOT_INITIALIZED,
        p11()->C_Decrypt(s_, ct.data(), kGcmTag, &none, &len)
    );
}

TEST_F(aes_gcm, same_inputs_give_the_same_ciphertext_and_tag)
{
    // The IV is re-applied from the operation's own copy on every call.
    std::vector<CK_BYTE> a, b;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain(a));
    ASSERT_NO_FATAL_FAILURE(encrypt_plain(b));
    EXPECT_EQ(a, b);
}

TEST_F(aes_gcm, the_aad_is_authenticated_not_encrypted)
{
    // Changing only the AAD leaves the ciphertext alone and changes the tag.
    std::vector<CK_BYTE> with_aad, other_aad;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain(with_aad));
    std::vector<CK_BYTE> aad2 = aad_;
    aad2[0] ^= 0x01;
    set_params(aad2.data(), static_cast<CK_ULONG>(aad2.size()));
    ASSERT_NO_FATAL_FAILURE(encrypt_plain(other_aad));
    EXPECT_EQ(0, std::memcmp(with_aad.data(), other_aad.data(), plain_.size()));
    EXPECT_NE(
        0,
        std::memcmp(with_aad.data() + plain_.size(), other_aad.data() + plain_.size(), kGcmTag)
    );
}

TEST_F(aes_gcm, parameters_are_copied_at_init)
{
    // The caller may reuse or free its CK_GCM_PARAMS, IV and AAD as soon as
    // C_EncryptInit returns.
    std::vector<CK_BYTE> ref, ct;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain(ref));

    std::vector<CK_BYTE> aad_copy = aad_;
    CK_BYTE iv_copy[kGcmIv];
    std::memcpy(iv_copy, iv_, sizeof(iv_copy));
    CK_GCM_PARAMS p = params_;
    p.pIv = iv_copy;
    p.pAAD = aad_copy.data();
    CK_MECHANISM m = { CKM_AES_GCM, &p, sizeof(p) };
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &m, key_));
    std::memset(iv_copy, 0, sizeof(iv_copy));
    std::memset(aad_copy.data(), 0, aad_copy.size());
    std::memset(&p, 0, sizeof(p));

    CK_ULONG len = static_cast<CK_ULONG>(plain_.size() + kGcmTag);
    ct.assign(len, 0);
    ASSERT_CKR_OK(
        p11()->C_Encrypt(s_, plain_.data(), static_cast<CK_ULONG>(plain_.size()), ct.data(), &len)
    );
    ct.resize(len);
    EXPECT_EQ(ref, ct);
}

TEST_F(aes_gcm, in_place_encrypt_and_decrypt)
{
    std::vector<CK_BYTE> ref;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain(ref));

    // One buffer holds the plaintext and receives ciphertext plus tag.
    std::vector<CK_BYTE> buf(plain_.size() + kGcmTag, 0);
    std::memcpy(buf.data(), plain_.data(), plain_.size());
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, key_));
    CK_ULONG len = static_cast<CK_ULONG>(buf.size());
    ASSERT_CKR_OK(
        p11()->C_Encrypt(s_, buf.data(), static_cast<CK_ULONG>(plain_.size()), buf.data(), &len)
    );
    EXPECT_EQ(ref, buf);

    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &mech_, key_));
    len = static_cast<CK_ULONG>(buf.size());
    ASSERT_CKR_OK(
        p11()->C_Decrypt(s_, buf.data(), static_cast<CK_ULONG>(buf.size()), buf.data(), &len)
    );
    ASSERT_EQ(plain_.size(), len);
    EXPECT_EQ(0, std::memcmp(buf.data(), plain_.data(), plain_.size()));
}

// ---------------------------------------------------------------------------
// Authentication failures
// ---------------------------------------------------------------------------

TEST_F(aes_gcm, tampered_ciphertext_is_refused)
{
    std::vector<CK_BYTE> ct;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain(ct));
    ct[3] ^= 0x80;
    ASSERT_NO_FATAL_FAILURE(expect_refused(ct));
}

TEST_F(aes_gcm, a_tampered_tag_on_an_empty_message_is_refused)
{
    std::vector<CK_BYTE> empty, ct;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, empty, ct));
    ASSERT_EQ(kGcmTag, ct.size());
    ct[0] ^= 0x01;
    ASSERT_NO_FATAL_FAILURE(expect_refused(ct));
}

TEST_F(aes_gcm, tampered_tag_is_refused)
{
    std::vector<CK_BYTE> ct;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain(ct));
    ct.back() ^= 0x01;
    ASSERT_NO_FATAL_FAILURE(expect_refused(ct));
}

TEST_F(aes_gcm, wrong_aad_or_iv_is_refused)
{
    std::vector<CK_BYTE> ct;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain(ct));
    std::vector<CK_BYTE> aad2 = aad_;
    aad2.back() ^= 0x01;
    set_params(aad2.data(), static_cast<CK_ULONG>(aad2.size()));
    ASSERT_NO_FATAL_FAILURE(expect_refused(ct));

    set_params(aad_.data(), static_cast<CK_ULONG>(aad_.size()));
    iv_[0] ^= 0x01;
    ASSERT_NO_FATAL_FAILURE(expect_refused(ct));
}

TEST_F(aes_gcm, bad_arguments_terminate_the_operation)
{
    CK_BYTE out[64];
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, key_));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_Encrypt(s_, plain_.data(), 37, out, nullptr));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Encrypt(s_, plain_.data(), 37, out, &len));

    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &mech_, key_));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_Decrypt(s_, nullptr, 32, out, &len));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Decrypt(s_, out, 32, out, &len));
}

TEST_F(aes_gcm, ciphertext_shorter_than_a_tag_is_a_length_error)
{
    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &mech_, key_));
    CK_BYTE short_ct[kGcmTag - 1] = { 0 };
    CK_BYTE out[kGcmTag];
    CK_ULONG len = sizeof(out);
    EXPECT_CKR(
        CKR_ENCRYPTED_DATA_LEN_RANGE,
        p11()->C_Decrypt(s_, short_ct, sizeof(short_ct), out, &len)
    );
    EXPECT_CKR(
        CKR_OPERATION_NOT_INITIALIZED,
        p11()->C_Decrypt(s_, short_ct, sizeof(short_ct), out, &len)
    );
}

// ---------------------------------------------------------------------------
// Parameters the device cannot run
// ---------------------------------------------------------------------------

TEST_F(aes_gcm, rejects_every_parameter_shape_but_12_byte_iv_and_128_bit_tag)
{
    CK_BYTE long_iv[16] = { 0 };
    CK_GCM_PARAMS p = params_;
    CK_MECHANISM m = { CKM_AES_GCM, &p, sizeof(p) };

    p.pIv = long_iv;
    p.ulIvLen = sizeof(long_iv);
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_EncryptInit(s_, &m, key_)) << "16-byte IV";
    p = params_;
    p.pIv = nullptr;
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_EncryptInit(s_, &m, key_)) << "NULL IV";
    p = params_;
    for (CK_ULONG bits : { 0ul, 32ul, 96ul, 120ul, 256ul })
    {
        p.ulTagBits = bits;
        EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_DecryptInit(s_, &m, key_))
            << "tag bits " << bits;
    }
    p = params_;
    p.pAAD = nullptr; // with ulAADLen still non-zero
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_EncryptInit(s_, &m, key_)) << "NULL AAD";

    CK_MECHANISM wrong_size = { CKM_AES_GCM, &params_, sizeof(params_) - 1 };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_EncryptInit(s_, &wrong_size, key_));
    CK_MECHANISM raw_iv = { CKM_AES_GCM, iv_, sizeof(iv_) };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_EncryptInit(s_, &raw_iv, key_))
        << "a bare IV is not a CK_GCM_PARAMS";
    CK_MECHANISM none = { CKM_AES_GCM, nullptr, 0 };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_DecryptInit(s_, &none, key_));

    // None of the refusals left an operation behind.
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, key_));
}

TEST_F(aes_gcm, iv_bits_is_not_read)
{
    // v3.0 says to give the IV length in ulIvLen; ulIvBits is filled
    // inconsistently by callers and does not decide anything here.
    std::vector<CK_BYTE> ref, ct;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain(ref));
    params_.ulIvBits = 0;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain(ct));
    EXPECT_EQ(ref, ct);
}

// ---------------------------------------------------------------------------
// Key families
// ---------------------------------------------------------------------------

TEST_F(aes_gcm, a_cbc_key_cannot_run_gcm_and_a_gcm_key_cannot_run_cbc)
{
    CK_OBJECT_HANDLE cbc_key = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "gcm-vs-cbc", &cbc_key));
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_EncryptInit(s_, &mech_, cbc_key));

    CK_BYTE cbc_iv[kAesBlock] = { 0 };
    CK_MECHANISM cbc = { CKM_AES_CBC_PAD, cbc_iv, sizeof(cbc_iv) };
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_EncryptInit(s_, &cbc, key_));
}

TEST_F(aes_gcm, direction_policy_still_applies)
{
    CK_MECHANISM_TYPE allowed[] = { CKM_AES_GCM };
    CK_ULONG bytes = 32;
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_VALUE_LEN, &bytes, sizeof(bytes) },
        { CKA_ALLOWED_MECHANISMS, allowed, sizeof(allowed) },
        { CKA_DECRYPT, &no, sizeof(no) },
    };
    CK_MECHANISM kg = { CKM_AES_KEY_GEN, nullptr, 0 };
    CK_OBJECT_HANDLE enc_only = 0;
    ASSERT_CKR_OK(p11()->C_GenerateKey(s_, &kg, tmpl, 3, &enc_only));
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, enc_only));
    abandon_operations(s_);
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_DecryptInit(s_, &mech_, enc_only));
}
