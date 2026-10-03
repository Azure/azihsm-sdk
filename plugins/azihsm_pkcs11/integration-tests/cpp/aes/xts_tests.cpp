// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file xts_tests.cpp
///
/// One-shot C_Encrypt / C_Decrypt with CKM_AES_XTS through the module ABI:
/// round trips across the supported data-unit lengths, the length policy (one
/// data unit per call, a non-zero multiple of the block up to 8 KiB), the
/// tweak's effect, parameter validation, the key-type gate between XTS and
/// plain AES keys, and in-place operation. Every case starts from a fresh XTS
/// key.

#include <algorithm>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"

namespace
{

constexpr CK_ULONG kXtsTweak = 16;
constexpr CK_ULONG kXtsMaxData = 8192;

} // namespace

class aes_xts : public UserSession
{
  protected:
    void SetUp() override
    {
        UserSession::SetUp();
        if (HasFatalFailure())
        {
            return;
        }
        ASSERT_CKR_OK(gen_xts_key(s_, "xts-fixture", &key_));
        // A sector number differing from its neighbours in the low bytes: the
        // simulator only honours the low 64 bits of the tweak.
        std::memset(tweak_, 0, sizeof(tweak_));
        tweak_[0] = 0x2A;
        mech_ = { CKM_AES_XTS, tweak_, sizeof(tweak_) };
    }

    CK_OBJECT_HANDLE key_ = 0;
    CK_BYTE tweak_[kXtsTweak];
    CK_MECHANISM mech_{};
};

// ---------------------------------------------------------------------------
// Round trips and sizing
// ---------------------------------------------------------------------------

TEST_F(aes_xts, roundtrip_across_data_unit_lengths)
{
    for (CK_ULONG n : { 16ul, 32ul, 512ul, 4096ul, kXtsMaxData })
    {
        std::vector<CK_BYTE> plain = pattern(n), ct, back;
        ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, plain, ct)) << n << " bytes";
        ASSERT_EQ(n, ct.size()) << "XTS output is as long as its input";
        EXPECT_NE(plain, ct);
        ASSERT_CKR_OK(crypt_oneshot(s_, false, &mech_, key_, ct, back)) << n << " bytes";
        EXPECT_EQ(plain, back) << n << " bytes";
    }
}

TEST_F(aes_xts, two_call_sizing_keeps_the_operation_alive)
{
    std::vector<CK_BYTE> plain = pattern(64);
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, key_));
    CK_ULONG need = 0;
    ASSERT_CKR_OK(p11()->C_Encrypt(s_, plain.data(), 64, nullptr, &need));
    EXPECT_EQ(64u, need);
    CK_BYTE ct[128];
    CK_ULONG small = 32;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_Encrypt(s_, plain.data(), 64, ct, &small));
    EXPECT_EQ(64u, small);
    CK_ULONG len = sizeof(ct);
    ASSERT_CKR_OK(p11()->C_Encrypt(s_, plain.data(), 64, ct, &len));
    EXPECT_EQ(64u, len);
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Encrypt(s_, plain.data(), 64, ct, &len));
}

TEST_F(aes_xts, the_tweak_changes_the_ciphertext)
{
    std::vector<CK_BYTE> plain = pattern(32), a, b;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, plain, a));
    tweak_[0] ^= 0x01; // the next sector
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, plain, b));
    EXPECT_NE(a, b);

    // And decrypting under the wrong tweak does not give the plaintext back.
    std::vector<CK_BYTE> back;
    ASSERT_CKR_OK(crypt_oneshot(s_, false, &mech_, key_, a, back));
    EXPECT_NE(plain, back);
}

TEST_F(aes_xts, the_whole_message_is_one_data_unit)
{
    // Every block of an XTS data unit is keyed off that unit's tweak, and the
    // next unit uses the next tweak. So were a message split into smaller
    // units, its second block (or half) would equal that block encrypted on
    // its own under tweak + 1. It must not.
    std::vector<CK_BYTE> plain = pattern(32), whole, first, second;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, plain, whole));
    std::vector<CK_BYTE> p0(plain.begin(), plain.begin() + kAesBlock);
    std::vector<CK_BYTE> p1(plain.begin() + kAesBlock, plain.end());
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, p0, first));
    EXPECT_TRUE(std::equal(first.begin(), first.end(), whole.begin()))
        << "the first block depends only on the data unit's tweak";
    tweak_[0]++; // the next sector number (little-endian; 0x2A carries nothing)
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, p1, second));
    EXPECT_FALSE(std::equal(second.begin(), second.end(), whole.begin() + kAesBlock))
        << "a data unit per block would make these equal";

    // The same at sector size: a 1 KiB message against its second 512 bytes.
    tweak_[0]--;
    std::vector<CK_BYTE> big = pattern(1024), big_ct, half_ct;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, big, big_ct));
    std::vector<CK_BYTE> half(big.begin() + 512, big.end());
    tweak_[0]++;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, half, half_ct));
    EXPECT_FALSE(std::equal(half_ct.begin(), half_ct.end(), big_ct.begin() + 512))
        << "a 512-byte data unit would make these equal";
}

TEST_F(aes_xts, same_inputs_give_the_same_ciphertext)
{
    std::vector<CK_BYTE> plain = pattern(48), a, b;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, plain, a));
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, plain, b));
    EXPECT_EQ(a, b);
}

TEST_F(aes_xts, in_place_matches_the_out_of_place_result)
{
    std::vector<CK_BYTE> plain = pattern(96), ref;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, plain, ref));

    std::vector<CK_BYTE> buf = plain;
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, key_));
    CK_ULONG len = static_cast<CK_ULONG>(buf.size());
    ASSERT_CKR_OK(p11()->C_Encrypt(s_, buf.data(), len, buf.data(), &len));
    EXPECT_EQ(ref, buf);

    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &mech_, key_));
    len = static_cast<CK_ULONG>(buf.size());
    ASSERT_CKR_OK(p11()->C_Decrypt(s_, buf.data(), len, buf.data(), &len));
    EXPECT_EQ(plain, buf);
}

// ---------------------------------------------------------------------------
// Length policy
// ---------------------------------------------------------------------------

TEST_F(aes_xts, lengths_outside_one_data_unit_are_range_errors)
{
    std::vector<CK_BYTE> big = pattern(kXtsMaxData + kAesBlock);
    CK_BYTE out[kXtsMaxData + kAesBlock];
    for (CK_ULONG n : { 0ul, 15ul, 17ul, 100ul, kXtsMaxData + kAesBlock })
    {
        CK_ULONG len = sizeof(out);
        ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, key_));
        EXPECT_CKR(CKR_DATA_LEN_RANGE, p11()->C_Encrypt(s_, big.data(), n, out, &len))
            << n << " bytes";
        EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Encrypt(s_, big.data(), n, out, &len))
            << "the range error terminated the operation";

        len = sizeof(out);
        ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &mech_, key_));
        EXPECT_CKR(CKR_ENCRYPTED_DATA_LEN_RANGE, p11()->C_Decrypt(s_, big.data(), n, out, &len))
            << n << " bytes";
        EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Decrypt(s_, big.data(), n, out, &len))
            << "the range error terminated the operation";
    }
}

// ---------------------------------------------------------------------------
// Parameters and key types
// ---------------------------------------------------------------------------

TEST_F(aes_xts, init_validates_the_tweak)
{
    CK_MECHANISM short_tweak = { CKM_AES_XTS, tweak_, 8 };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_EncryptInit(s_, &short_tweak, key_));
    CK_MECHANISM no_tweak = { CKM_AES_XTS, nullptr, 0 };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_DecryptInit(s_, &no_tweak, key_));
    CK_BYTE longer[32] = { 0 };
    CK_MECHANISM long_tweak = { CKM_AES_XTS, longer, sizeof(longer) };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_EncryptInit(s_, &long_tweak, key_));

    // The device must advance the tweak past the data unit, which the 128-bit
    // maximum cannot do; it is refused up front rather than mid-operation.
    CK_BYTE max[kXtsTweak];
    std::memset(max, 0xFF, sizeof(max));
    CK_MECHANISM max_tweak = { CKM_AES_XTS, max, sizeof(max) };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_EncryptInit(s_, &max_tweak, key_));
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_DecryptInit(s_, &max_tweak, key_));
    max[0] = 0xFE; // one below the maximum (little-endian): the largest usable tweak
    std::vector<CK_BYTE> plain = pattern(16), ct, back;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &max_tweak, key_, plain, ct));
    ASSERT_CKR_OK(crypt_oneshot(s_, false, &max_tweak, key_, ct, back));
    EXPECT_EQ(plain, back);
}

TEST_F(aes_xts, bad_arguments_terminate_the_operation)
{
    std::vector<CK_BYTE> plain = pattern(32);
    CK_BYTE out[32];
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, key_));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_Encrypt(s_, plain.data(), 32, out, nullptr));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Encrypt(s_, plain.data(), 32, out, &len));

    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &mech_, key_));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_Decrypt(s_, nullptr, 32, out, &len));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Decrypt(s_, plain.data(), 32, out, &len));
}

TEST_F(aes_xts, xts_and_plain_aes_keys_do_not_mix)
{
    // XTS keys are CKK_AES_XTS, so the key-type gate separates them from the
    // CBC and GCM keys, which are both CKK_AES.
    CK_BYTE iv[kAesBlock] = { 0 };
    CK_MECHANISM cbc = { CKM_AES_CBC, iv, sizeof(iv) };
    EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT, p11()->C_EncryptInit(s_, &cbc, key_));

    CK_OBJECT_HANDLE aes_key = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "xts-vs-aes", &aes_key));
    EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT, p11()->C_EncryptInit(s_, &mech_, aes_key));

    CK_OBJECT_HANDLE gcm_key = 0;
    ASSERT_CKR_OK(gen_gcm_key(s_, "xts-vs-gcm", &gcm_key));
    EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT, p11()->C_DecryptInit(s_, &mech_, gcm_key));
}

TEST_F(aes_xts, logout_tears_an_active_operation_down)
{
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, key_));
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    std::vector<CK_BYTE> plain = pattern(16);
    CK_BYTE out[16];
    CK_ULONG len = sizeof(out);
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Encrypt(s_, plain.data(), 16, out, &len));
}
