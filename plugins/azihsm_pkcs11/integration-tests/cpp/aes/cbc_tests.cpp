// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file cbc_tests.cpp
///
/// One-shot C_Encrypt / C_Decrypt with CKM_AES_CBC and CKM_AES_CBC_PAD through
/// the module ABI: round trips, the two-call sizing discipline, the
/// operation-lifetime rules (what keeps an operation alive and what terminates
/// it), init precedence, usage enforcement, and that a logout tears active
/// cipher state down. Every case starts from a fresh AES-256 key.

#include <algorithm>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"

class aes_cbc : public UserSession
{
  protected:
    void SetUp() override
    {
        UserSession::SetUp();
        if (HasFatalFailure())
        {
            return;
        }
        ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "cbc-fixture", &key_));
        std::memset(iv_, 0xA5, sizeof(iv_));
        pad_ = { CKM_AES_CBC_PAD, iv_, sizeof(iv_) };
        raw_ = { CKM_AES_CBC, iv_, sizeof(iv_) };
        plain_.resize(40);
        for (size_t i = 0; i < plain_.size(); i++)
        {
            plain_[i] = static_cast<CK_BYTE>(i);
        }
    }

    /// Encrypt `plain_` with CBC-PAD into `ct` (48 bytes). ASSERTs on failure,
    /// so call it as ASSERT_NO_FATAL_FAILURE(encrypt_plain_pad(ct)).
    void encrypt_plain_pad(std::vector<CK_BYTE> &ct)
    {
        ASSERT_CKR_OK(crypt_oneshot(s_, true, &pad_, key_, plain_, ct));
        ASSERT_EQ(48u, ct.size());
    }

    CK_OBJECT_HANDLE key_ = 0;
    CK_BYTE iv_[kAesBlock];
    CK_MECHANISM pad_{};
    CK_MECHANISM raw_{};
    std::vector<CK_BYTE> plain_;
};

// ---------------------------------------------------------------------------
// Round trips and sizing
// ---------------------------------------------------------------------------

TEST_F(aes_cbc, cbc_pad_roundtrip_with_two_call_sizing)
{
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &pad_, key_));
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_EncryptInit(s_, &pad_, key_));

    CK_ULONG need = 0;
    ASSERT_CKR_OK(p11()->C_Encrypt(s_, plain_.data(), 40, nullptr, &need));
    EXPECT_EQ(48u, need) << "40 bytes -> 3 padded blocks";

    CK_BYTE ct[64];
    CK_ULONG small = 16;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_Encrypt(s_, plain_.data(), 40, ct, &small));
    EXPECT_EQ(48u, small) << "the required length is reported";

    CK_ULONG len = sizeof(ct);
    ASSERT_CKR_OK(p11()->C_Encrypt(s_, plain_.data(), 40, ct, &len))
        << "the probe and the too-small call kept the operation alive";
    EXPECT_EQ(48u, len);
    EXPECT_NE(0, std::memcmp(ct, plain_.data(), 16));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Encrypt(s_, plain_.data(), 40, ct, &len))
        << "completion terminated the operation";

    std::vector<CK_BYTE> back;
    ASSERT_CKR_OK(crypt_oneshot(s_, false, &pad_, key_, std::vector<CK_BYTE>(ct, ct + len), back));
    EXPECT_EQ(plain_, back);
}

TEST_F(aes_cbc, cbc_pad_adds_a_full_block_for_aligned_input)
{
    std::vector<CK_BYTE> two_blocks(plain_.begin(), plain_.begin() + 32);
    std::vector<CK_BYTE> ct, back;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &pad_, key_, two_blocks, ct));
    EXPECT_EQ(48u, ct.size());
    ASSERT_CKR_OK(crypt_oneshot(s_, false, &pad_, key_, ct, back));
    EXPECT_EQ(two_blocks, back);
}

TEST_F(aes_cbc, raw_cbc_roundtrip)
{
    std::vector<CK_BYTE> two_blocks(plain_.begin(), plain_.begin() + 32);
    std::vector<CK_BYTE> ct, back;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &raw_, key_, two_blocks, ct));
    EXPECT_EQ(32u, ct.size());
    ASSERT_CKR_OK(crypt_oneshot(s_, false, &raw_, key_, ct, back));
    EXPECT_EQ(two_blocks, back);
}

TEST_F(aes_cbc, same_input_same_iv_gives_same_ciphertext)
{
    // The IV seed is re-applied on every call, so probing and retrying never
    // drift the chain.
    std::vector<CK_BYTE> a, b;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &pad_, key_, plain_, a));
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &pad_, key_, plain_, b));
    EXPECT_EQ(a, b);
}

// ---------------------------------------------------------------------------
// Failures that terminate the operation
// ---------------------------------------------------------------------------

TEST_F(aes_cbc, bad_padding_is_invalid_ciphertext_and_wipes_the_output)
{
    // Build ciphertexts whose LAST plaintext block cannot be valid PKCS#7 by
    // raw-CBC-encrypting 48 bytes with a chosen tail, then decrypt them as
    // CBC-PAD. Deterministic — flipping random ciphertext bytes instead yields
    // valid padding about 0.4% of the time.
    struct
    {
        std::vector<CK_BYTE> tail;
        const char *why;
    } cases[] = {
        { { 0x00 }, "pad byte 0 (valid range is 1..16)" },
        { { 0x11 }, "pad byte 17 (longer than a block)" },
        { { 0x01, 0x02 }, "pad byte 2 but the byte before it is not 2" },
    };
    for (const auto &c : cases)
    {
        std::vector<CK_BYTE> bad_plain(48, 0x42);
        std::copy(c.tail.begin(), c.tail.end(), bad_plain.end() - c.tail.size());
        std::vector<CK_BYTE> ct;
        ASSERT_CKR_OK(crypt_oneshot(s_, true, &raw_, key_, bad_plain, ct)) << c.why;
        ASSERT_EQ(48u, ct.size());

        CK_BYTE out[64];
        std::memset(out, 0xEE, sizeof(out));
        CK_ULONG len = sizeof(out);
        ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &pad_, key_));
        EXPECT_CKR(CKR_ENCRYPTED_DATA_INVALID, p11()->C_Decrypt(s_, ct.data(), 48, out, &len))
            << c.why;
        EXPECT_EQ(0u, len);
        // The device wrote the raw blocks before the padding was rejected; the
        // module must not hand them back behind a zero length.
        for (size_t i = 0; i < 48; i++)
        {
            ASSERT_EQ(0, out[i]) << "byte " << i << " of the output buffer was not wiped";
        }
        EXPECT_EQ(0xEE, out[48]) << "bytes beyond the required length are untouched";
        CK_ULONG need = 0;
        EXPECT_CKR(
            CKR_OPERATION_NOT_INITIALIZED,
            p11()->C_Decrypt(s_, ct.data(), 48, nullptr, &need)
        ) << "the padding error terminated the operation";
    }
}

TEST_F(aes_cbc, corrupt_ciphertext_never_yields_the_plaintext)
{
    // Random corruption may or may not survive the padding check; either way
    // the original plaintext must not come back and the operation must end.
    std::vector<CK_BYTE> ct;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain_pad(ct));
    ct.back() ^= 0xFF;
    ct.front() ^= 0xFF;
    std::vector<CK_BYTE> back;
    CK_RV rv = crypt_oneshot(s_, false, &pad_, key_, ct, back);
    EXPECT_TRUE((rv == CKR_ENCRYPTED_DATA_INVALID) || (rv == CKR_OK)) << Ckr{ rv };
    EXPECT_NE(plain_, back);
    CK_ULONG need = 0;
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Decrypt(s_, ct.data(), 48, nullptr, &need));
}

TEST_F(aes_cbc, raw_cbc_rejects_a_partial_block_and_terminates)
{
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &raw_, key_));
    CK_ULONG need = 0;
    EXPECT_CKR(CKR_DATA_LEN_RANGE, p11()->C_Encrypt(s_, plain_.data(), 30, nullptr, &need));
    EXPECT_CKR(
        CKR_OPERATION_NOT_INITIALIZED,
        p11()->C_Encrypt(s_, plain_.data(), 32, nullptr, &need)
    );
}

TEST_F(aes_cbc, decrypt_rejects_a_partial_block_and_terminates)
{
    std::vector<CK_BYTE> ct;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain_pad(ct));
    CK_ULONG need = 0;
    for (CK_MECHANISM *m : { &pad_, &raw_ })
    {
        ASSERT_CKR_OK(p11()->C_DecryptInit(s_, m, key_));
        EXPECT_CKR(
            CKR_ENCRYPTED_DATA_LEN_RANGE,
            p11()->C_Decrypt(s_, ct.data(), 20, nullptr, &need)
        );
        EXPECT_CKR(
            CKR_OPERATION_NOT_INITIALIZED,
            p11()->C_Decrypt(s_, ct.data(), 48, nullptr, &need)
        );
    }
    // CBC-PAD ciphertext is never empty either.
    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &pad_, key_));
    EXPECT_CKR(CKR_ENCRYPTED_DATA_LEN_RANGE, p11()->C_Decrypt(s_, ct.data(), 0, nullptr, &need));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Decrypt(s_, ct.data(), 48, nullptr, &need));
}

TEST_F(aes_cbc, bad_arguments_terminate_the_operation)
{
    CK_ULONG need = 0;
    CK_BYTE out[64];

    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &pad_, key_));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_Encrypt(s_, plain_.data(), 40, nullptr, nullptr));
    EXPECT_CKR(
        CKR_OPERATION_NOT_INITIALIZED,
        p11()->C_Encrypt(s_, plain_.data(), 40, nullptr, &need)
    );

    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &pad_, key_));
    need = sizeof(out);
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_Encrypt(s_, nullptr, 16, out, &need));
    EXPECT_CKR(
        CKR_OPERATION_NOT_INITIALIZED,
        p11()->C_Encrypt(s_, plain_.data(), 40, nullptr, &need)
    );

    std::vector<CK_BYTE> ct;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain_pad(ct));
    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &pad_, key_));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_Decrypt(s_, ct.data(), 48, nullptr, nullptr));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Decrypt(s_, ct.data(), 48, nullptr, &need));
}

TEST_F(aes_cbc, wrong_session_does_not_touch_the_operation)
{
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &pad_, key_));
    CK_ULONG need = 0;
    EXPECT_CKR(
        CKR_SESSION_HANDLE_INVALID,
        p11()->C_Encrypt(kInvalidSession, plain_.data(), 40, nullptr, &need)
    );
    EXPECT_CKR_OK(p11()->C_Encrypt(s_, plain_.data(), 40, nullptr, &need))
        << "the operation on the real session is still alive";
    EXPECT_EQ(48u, need);
}

TEST_F(aes_cbc, data_call_without_init_is_not_initialized)
{
    CK_ULONG need = 0;
    EXPECT_CKR(
        CKR_OPERATION_NOT_INITIALIZED,
        p11()->C_Encrypt(s_, plain_.data(), 16, nullptr, &need)
    );
    EXPECT_CKR(
        CKR_OPERATION_NOT_INITIALIZED,
        p11()->C_Decrypt(s_, plain_.data(), 16, nullptr, &need)
    );
    // A decrypt data call does not satisfy an encrypt operation, and vice versa.
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &raw_, key_));
    EXPECT_CKR(
        CKR_OPERATION_NOT_INITIALIZED,
        p11()->C_Decrypt(s_, plain_.data(), 16, nullptr, &need)
    );
    EXPECT_CKR_OK(p11()->C_Encrypt(s_, plain_.data(), 16, nullptr, &need))
        << "the mismatched call left the encrypt operation alone";
}

// ---------------------------------------------------------------------------
// Init precedence and validation
// ---------------------------------------------------------------------------

TEST_F(aes_cbc, init_reports_the_session_handle_first)
{
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, p11()->C_EncryptInit(kInvalidSession, &pad_, key_));
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, p11()->C_EncryptInit(kInvalidSession, nullptr, key_));
    EXPECT_CKR(
        CKR_SESSION_HANDLE_INVALID,
        p11()->C_DecryptInit(kInvalidSession, nullptr, kInvalidObject)
    );
}

TEST_F(aes_cbc, init_reports_arguments_then_operation_state_then_mechanism)
{
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_EncryptInit(s_, nullptr, key_));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_DecryptInit(s_, nullptr, key_));

    CK_MECHANISM gcm = { CKM_AES_GCM, iv_, sizeof(iv_) };
    EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_EncryptInit(s_, &gcm, key_));
    EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_DecryptInit(s_, &gcm, key_));

    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &pad_, key_));
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_EncryptInit(s_, &gcm, key_))
        << "an active operation is reported before the mechanism is judged";
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_DecryptInit(s_, &pad_, key_));
}

TEST_F(aes_cbc, init_validates_the_iv)
{
    CK_MECHANISM short_iv = { CKM_AES_CBC_PAD, iv_, 12 };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_EncryptInit(s_, &short_iv, key_));
    CK_MECHANISM no_iv = { CKM_AES_CBC, nullptr, 0 };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_DecryptInit(s_, &no_iv, key_));
    CK_MECHANISM long_iv = { CKM_AES_CBC, plain_.data(), 32 };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_EncryptInit(s_, &long_iv, key_));
}

TEST_F(aes_cbc, init_validates_the_key_handle)
{
    EXPECT_CKR(CKR_KEY_HANDLE_INVALID, p11()->C_EncryptInit(s_, &pad_, kInvalidObject));
    EXPECT_CKR(CKR_KEY_HANDLE_INVALID, p11()->C_DecryptInit(s_, &pad_, kInvalidObject));

    // A data object is a valid object handle but backs no key.
    CK_BYTE payload[4] = { 1, 2, 3, 4 };
    CK_ATTRIBUTE data_tmpl[] = { { CKA_VALUE, payload, sizeof(payload) } };
    CK_OBJECT_HANDLE data_obj = 0;
    ASSERT_CKR_OK(p11()->C_CreateObject(s_, data_tmpl, 1, &data_obj));
    EXPECT_CKR(CKR_KEY_HANDLE_INVALID, p11()->C_EncryptInit(s_, &pad_, data_obj));
    EXPECT_CKR(CKR_KEY_HANDLE_INVALID, p11()->C_DecryptInit(s_, &raw_, data_obj));
}

TEST_F(aes_cbc, init_requires_login)
{
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    EXPECT_CKR(CKR_USER_NOT_LOGGED_IN, p11()->C_EncryptInit(s_, &pad_, key_));
    EXPECT_CKR(CKR_USER_NOT_LOGGED_IN, p11()->C_DecryptInit(s_, &pad_, key_));
    // Still: a malformed request is reported before the login state.
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_EncryptInit(s_, nullptr, key_));
    CK_MECHANISM gcm = { CKM_AES_GCM, iv_, sizeof(iv_) };
    EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_EncryptInit(s_, &gcm, key_));
}

// ---------------------------------------------------------------------------
// Usage policy, wrong key, teardown
// ---------------------------------------------------------------------------

TEST_F(aes_cbc, usage_flags_are_enforced_at_init)
{
    CK_OBJECT_HANDLE dec_only = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 16, CK_FALSE, CK_TRUE, "dec-only", &dec_only));
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_EncryptInit(s_, &pad_, dec_only));
    // Raw CBC decrypts any aligned input (to garbage), so this exercises the
    // permitted direction without tripping over padding.
    std::vector<CK_BYTE> junk(16, 0x11), out;
    EXPECT_CKR_OK(crypt_oneshot(s_, false, &raw_, dec_only, junk, out));
    EXPECT_EQ(16u, out.size());

    CK_OBJECT_HANDLE enc_only = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 24, CK_TRUE, CK_FALSE, "enc-only", &enc_only));
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_DecryptInit(s_, &raw_, enc_only));
    EXPECT_CKR_OK(crypt_oneshot(s_, true, &raw_, enc_only, junk, out));
    EXPECT_EQ(16u, out.size());
}

TEST_F(aes_cbc, wrong_key_never_recovers_the_plaintext)
{
    std::vector<CK_BYTE> ct;
    ASSERT_NO_FATAL_FAILURE(encrypt_plain_pad(ct));
    CK_OBJECT_HANDLE other = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "other", &other));
    std::vector<CK_BYTE> back;
    CK_RV rv = crypt_oneshot(s_, false, &pad_, other, ct, back);
    EXPECT_FALSE((rv == CKR_OK) && (back == plain_));
}

TEST_F(aes_cbc, logout_tears_down_the_active_operation)
{
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &pad_, key_));
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    CK_ULONG need = 0;
    EXPECT_CKR(
        CKR_OPERATION_NOT_INITIALIZED,
        p11()->C_Encrypt(s_, plain_.data(), 16, nullptr, &need)
    );
    EXPECT_CKR(CKR_USER_NOT_LOGGED_IN, p11()->C_EncryptInit(s_, &pad_, key_));
}

TEST_F(aes_cbc, closing_a_session_with_an_active_operation_is_clean)
{
    CK_SESSION_HANDLE other = 0;
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &other)
    );
    ASSERT_CKR_OK(p11()->C_EncryptInit(other, &pad_, key_));
    EXPECT_CKR_OK(p11()->C_CloseSession(other));
    CK_ULONG need = 0;
    EXPECT_CKR(
        CKR_SESSION_HANDLE_INVALID,
        p11()->C_Encrypt(other, plain_.data(), 16, nullptr, &need)
    );
    // The fixture session and its login are unaffected by the other close.
    std::vector<CK_BYTE> ct;
    EXPECT_CKR_OK(crypt_oneshot(s_, true, &pad_, key_, plain_, ct));
}
