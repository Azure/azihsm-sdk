// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file multipart_tests.cpp
///
/// Multi-part C_EncryptUpdate / C_EncryptFinal and C_DecryptUpdate /
/// C_DecryptFinal with CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_GCM and
/// CKM_AES_XTS through the module ABI: agreement with the one-shot calls over
/// many part sizes, sizing probes and too-small buffers, the length rules at
/// the final call, the mode rule between one-shot and multi-part calls, and
/// what each mechanism releases when. CBC runs through the SDK's stream
/// context; GCM and XTS buffer until the final call (azihsm_pkcs11_crypt.c
/// says why). Every case starts from a fresh key.

#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"

namespace
{

constexpr CK_ULONG kGcmIv = 12;
constexpr CK_ULONG kGcmTag = 16;
constexpr CK_ULONG kXtsTweak = 16;
constexpr CK_ULONG kXtsMaxData = 8192;

/// Part sizes every agreement check runs through; 0 = the whole input at once.
const size_t kChunks[] = { 0, 1, 7, 15, 16, 17, 33 };

CK_RV update(
    CK_SESSION_HANDLE s,
    bool encrypt,
    const CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE_PTR out,
    CK_ULONG_PTR out_len
)
{
    CK_BYTE_PTR p = const_cast<CK_BYTE_PTR>(in);
    return encrypt ? p11()->C_EncryptUpdate(s, p, in_len, out, out_len)
                   : p11()->C_DecryptUpdate(s, p, in_len, out, out_len);
}

CK_RV final_call(CK_SESSION_HANDLE s, bool encrypt, CK_BYTE_PTR out, CK_ULONG_PTR out_len)
{
    return encrypt ? p11()->C_EncryptFinal(s, out, out_len)
                   : p11()->C_DecryptFinal(s, out, out_len);
}

/// Expect the session's operation of this direction to be gone.
void expect_terminated(CK_SESSION_HANDLE s, bool encrypt)
{
    CK_BYTE out[kAesBlock];
    CK_ULONG len = sizeof(out);
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, final_call(s, encrypt, out, &len))
        << "the operation was terminated";
}

} // namespace

/// Shared by the three fixtures: the agreement check against the one-shot
/// calls, given a mechanism and a key.
class multipart_base : public UserSession
{
  protected:
    /// Multi-part encryption of `pt` agrees with the one-shot ciphertext for
    /// every part size, and multi-part decryption of that ciphertext recovers
    /// `pt`.
    void check_agreement(CK_MECHANISM *mech, const std::vector<CK_BYTE> &pt)
    {
        std::vector<CK_BYTE> one;
        ASSERT_CKR_OK(crypt_oneshot(s_, true, mech, key_, pt, one));
        for (size_t chunk : kChunks)
        {
            SCOPED_TRACE(testing::Message() << "length " << pt.size() << ", part size " << chunk);
            std::vector<CK_BYTE> ct, back;
            ASSERT_CKR_OK(crypt_multipart(s_, true, mech, key_, pt, chunk, ct));
            EXPECT_EQ(one, ct);
            ASSERT_CKR_OK(crypt_multipart(s_, false, mech, key_, one, chunk, back));
            EXPECT_EQ(pt, back);
        }
    }

    CK_OBJECT_HANDLE key_ = 0;
};

// ===========================================================================
// AES-CBC / AES-CBC-PAD
// ===========================================================================

class aes_multipart_cbc : public multipart_base
{
  protected:
    void SetUp() override
    {
        UserSession::SetUp();
        if (HasFatalFailure())
        {
            return;
        }
        ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "multipart-cbc", &key_));
        std::memset(iv_, 0x5C, sizeof(iv_));
        raw_ = { CKM_AES_CBC, iv_, sizeof(iv_) };
        pad_ = { CKM_AES_CBC_PAD, iv_, sizeof(iv_) };
    }

    CK_BYTE iv_[kAesBlock];
    CK_MECHANISM raw_{};
    CK_MECHANISM pad_{};
};

TEST_F(aes_multipart_cbc, unpadded_parts_agree_with_one_shot)
{
    for (size_t n : { 0ul, kAesBlock, 3 * kAesBlock, 10 * kAesBlock })
    {
        ASSERT_NO_FATAL_FAILURE(check_agreement(&raw_, pattern(n)));
    }
}

TEST_F(aes_multipart_cbc, padded_parts_agree_with_one_shot)
{
    for (size_t n :
         { 0ul, 1ul, kAesBlock - 1, kAesBlock, kAesBlock + 1, 3 * kAesBlock - 1, 10 * kAesBlock })
    {
        ASSERT_NO_FATAL_FAILURE(check_agreement(&pad_, pattern(n)));
    }
}

TEST_F(aes_multipart_cbc, output_trails_the_input_by_one_block)
{
    // The SDK stream holds back the last full block even without padding.
    // PKCS#11 allows that, but pkcs11test's EncryptDecryptParts expects one
    // block out per one-block part, so it stays off the conformance list. This
    // pins the SDK behaviour: it fails the day the SDK stops holding back, and
    // then that pkcs11test case can join the list.
    const CK_ULONG released[] = { 0, kAesBlock, kAesBlock };
    constexpr size_t kBlocks = sizeof(released) / sizeof(released[0]);
    std::vector<CK_BYTE> pt = pattern(kBlocks * kAesBlock);
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &raw_, key_));
    CK_BYTE out[(kBlocks + 1) * kAesBlock];
    for (size_t b = 0; b < kBlocks; b++)
    {
        CK_ULONG len = sizeof(out);
        ASSERT_CKR_OK(update(s_, true, pt.data() + (b * kAesBlock), kAesBlock, out, &len));
        EXPECT_EQ(released[b], len) << "block " << b;
    }
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_EncryptFinal(s_, out, &len));
    EXPECT_EQ(kAesBlock, len) << "the final call releases the held-back block";
}

TEST_F(aes_multipart_cbc, update_probe_consumes_nothing)
{
    // The SDK's own sizing call would run the update when no output is due, so
    // the module answers the probe itself; the data must go in exactly once.
    std::vector<CK_BYTE> pt = pattern(kAesBlock);
    std::vector<CK_BYTE> one;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &raw_, key_, pt, one));

    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &raw_, key_));
    CK_ULONG need = 0;
    ASSERT_CKR_OK(update(s_, true, pt.data(), kAesBlock, nullptr, &need));
    CK_BYTE out[4 * kAesBlock];
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(update(s_, true, pt.data(), kAesBlock, out, &len));
    EXPECT_LE(len, need) << "the probe reports an upper bound";
    CK_ULONG last = sizeof(out) - len;
    ASSERT_CKR_OK(p11()->C_EncryptFinal(s_, out + len, &last));
    EXPECT_EQ(one, std::vector<CK_BYTE>(out, out + len + last));
}

TEST_F(aes_multipart_cbc, too_small_update_buffer_keeps_the_operation)
{
    std::vector<CK_BYTE> pt = pattern(2 * kAesBlock);
    std::vector<CK_BYTE> one;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &raw_, key_, pt, one));

    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &raw_, key_));
    std::vector<CK_BYTE> ct;
    CK_BYTE out[4 * kAesBlock];
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(update(s_, true, pt.data(), kAesBlock, out, &len));
    ct.insert(ct.end(), out, out + len);

    CK_BYTE tiny = 0;
    len = 0;
    EXPECT_CKR(
        CKR_BUFFER_TOO_SMALL,
        update(s_, true, pt.data() + kAesBlock, kAesBlock, &tiny, &len)
    );
    EXPECT_EQ(kAesBlock, len) << "the required length";
    len = sizeof(out);
    ASSERT_CKR_OK(update(s_, true, pt.data() + kAesBlock, kAesBlock, out, &len))
        << "the retry of the same part";
    ct.insert(ct.end(), out, out + len);
    len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_EncryptFinal(s_, out, &len));
    ct.insert(ct.end(), out, out + len);
    EXPECT_EQ(one, ct);
}

TEST_F(aes_multipart_cbc, final_right_after_init)
{
    CK_BYTE out[2 * kAesBlock];
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &raw_, key_));
    ASSERT_CKR_OK(p11()->C_EncryptFinal(s_, out, &len));
    EXPECT_EQ(0u, len) << "the empty message is a whole number of blocks";

    len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &raw_, key_));
    ASSERT_CKR_OK(p11()->C_DecryptFinal(s_, out, &len));
    EXPECT_EQ(0u, len);

    std::vector<CK_BYTE> one;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &pad_, key_, {}, one));
    len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &pad_, key_));
    ASSERT_CKR_OK(p11()->C_EncryptFinal(s_, out, &len));
    EXPECT_EQ(one, std::vector<CK_BYTE>(out, out + len)) << "one padding block";

    len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &pad_, key_));
    EXPECT_CKR(CKR_ENCRYPTED_DATA_LEN_RANGE, p11()->C_DecryptFinal(s_, out, &len))
        << "a padded ciphertext has at least one block";
    expect_terminated(s_, false);
}

TEST_F(aes_multipart_cbc, final_enforces_whole_blocks)
{
    struct Case
    {
        bool pad;
        bool encrypt;
        CK_ULONG fed;
        CK_RV expected;
    };
    static const Case kCases[] = {
        { false, true, 5, CKR_DATA_LEN_RANGE },
        { false, true, kAesBlock + 1, CKR_DATA_LEN_RANGE },
        { false, false, 5, CKR_ENCRYPTED_DATA_LEN_RANGE },
        { true, false, kAesBlock - 1, CKR_ENCRYPTED_DATA_LEN_RANGE },
        { true, false, kAesBlock + 1, CKR_ENCRYPTED_DATA_LEN_RANGE },
    };
    for (const Case &c : kCases)
    {
        SCOPED_TRACE(
            testing::Message() << (c.pad ? "CBC-PAD " : "CBC ")
                               << (c.encrypt ? "encrypt" : "decrypt") << " of " << c.fed << " bytes"
        );
        CK_MECHANISM *mech = c.pad ? &pad_ : &raw_;
        ASSERT_CKR_OK(
            c.encrypt ? p11()->C_EncryptInit(s_, mech, key_) : p11()->C_DecryptInit(s_, mech, key_)
        );
        std::vector<CK_BYTE> in = pattern(c.fed);
        CK_BYTE out[4 * kAesBlock];
        CK_ULONG len = sizeof(out);
        ASSERT_CKR_OK(update(s_, c.encrypt, in.data(), c.fed, out, &len))
            << "a partial block may still be completed by a later part";
        len = sizeof(out);
        EXPECT_CKR(c.expected, final_call(s_, c.encrypt, out, &len));
        expect_terminated(s_, c.encrypt);
    }
}

TEST_F(aes_multipart_cbc, padded_decrypt_final_fits_an_exact_buffer)
{
    // The SDK asks for two blocks of room for this final call although it
    // returns less than one; the module finishes into its own buffer, so the
    // caller's buffer only has to hold the real result, and a too-small one
    // can retry.
    constexpr CK_ULONG kLen = kAesBlock + 4;
    std::vector<CK_BYTE> pt = pattern(kLen);
    std::vector<CK_BYTE> ct;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &pad_, key_, pt, ct));

    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &pad_, key_));
    CK_BYTE out[2 * kAesBlock];
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(update(s_, false, ct.data(), static_cast<CK_ULONG>(ct.size()), out, &len));
    EXPECT_EQ(kAesBlock, len);
    CK_ULONG need = 0;
    ASSERT_CKR_OK(p11()->C_DecryptFinal(s_, nullptr, &need));
    EXPECT_GE(need, kLen - kAesBlock) << "an upper bound before the final call has run";

    CK_BYTE small = 0;
    len = 1;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_DecryptFinal(s_, &small, &len));
    EXPECT_EQ(kLen - kAesBlock, len) << "exact once the final call has run";

    CK_BYTE exact[kLen - kAesBlock];
    len = sizeof(exact);
    ASSERT_CKR_OK(p11()->C_DecryptFinal(s_, exact, &len));
    ASSERT_EQ(kLen - kAesBlock, len);
    EXPECT_EQ(0, std::memcmp(exact, pt.data() + kAesBlock, len));
    expect_terminated(s_, false);
}

TEST_F(aes_multipart_cbc, bad_padding_is_encrypted_data_invalid)
{
    // 20 bytes pad with twelve 0x0C bytes. Flipping the last byte of the first
    // ciphertext block by 0x0C turns the final padding byte into 0x00, which
    // no valid padding has.
    constexpr CK_ULONG kLen = kAesBlock + 4;
    constexpr CK_BYTE kPadByte = 2 * kAesBlock - kLen;
    std::vector<CK_BYTE> ct;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &pad_, key_, pattern(kLen), ct));
    ct[kAesBlock - 1] ^= kPadByte;

    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &pad_, key_));
    CK_BYTE out[2 * kAesBlock];
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(update(s_, false, ct.data(), static_cast<CK_ULONG>(ct.size()), out, &len));
    std::memset(out, 0xEE, sizeof(out));
    len = sizeof(out);
    EXPECT_CKR(CKR_ENCRYPTED_DATA_INVALID, p11()->C_DecryptFinal(s_, out, &len));
    EXPECT_EQ(0u, len);
    for (size_t i = 0; i < sizeof(out); i++)
    {
        ASSERT_EQ(0xEE, out[i]) << "byte " << i << ": nothing of the refused block is handed out";
    }
    expect_terminated(s_, false);
}

TEST_F(aes_multipart_cbc, in_place_parts_agree_with_one_shot)
{
    // Each part is encrypted over the buffer it came from, with the output
    // written where the output so far ends: the output never runs ahead of
    // the input, so no unread input is overwritten, but one call's output and
    // input ranges overlap.
    std::vector<CK_BYTE> pt = pattern(3 * kAesBlock);
    std::vector<CK_BYTE> one;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &raw_, key_, pt, one));

    std::vector<CK_BYTE> buf = pt;
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &raw_, key_));
    CK_ULONG written = 0;
    CK_ULONG off = 0;
    for (CK_ULONG n : { 5ul, 27ul, kAesBlock })
    {
        CK_ULONG len = off + n - written;
        ASSERT_CKR_OK(update(s_, true, buf.data() + off, n, buf.data() + written, &len));
        written += len;
        off += n;
    }
    CK_ULONG len = static_cast<CK_ULONG>(buf.size()) - written;
    ASSERT_CKR_OK(p11()->C_EncryptFinal(s_, buf.data() + written, &len));
    EXPECT_EQ(buf.size(), written + len);
    EXPECT_EQ(one, buf);
}

TEST_F(aes_multipart_cbc, one_shot_after_update_is_operation_active)
{
    std::vector<CK_BYTE> pt = pattern(kAesBlock);
    CK_BYTE out[4 * kAesBlock];
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &raw_, key_));
    ASSERT_CKR_OK(update(s_, true, pt.data(), kAesBlock, out, &len));
    len = sizeof(out);
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_Encrypt(s_, pt.data(), kAesBlock, out, &len));
    expect_terminated(s_, true);
}

TEST_F(aes_multipart_cbc, multi_part_after_one_shot_probe_is_operation_active)
{
    std::vector<CK_BYTE> pt = pattern(kAesBlock);
    CK_BYTE out[4 * kAesBlock];
    CK_ULONG need = 0;
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &raw_, key_));
    ASSERT_CKR_OK(p11()->C_Encrypt(s_, pt.data(), kAesBlock, nullptr, &need));
    CK_ULONG len = sizeof(out);
    EXPECT_CKR(CKR_OPERATION_ACTIVE, update(s_, true, pt.data(), kAesBlock, out, &len));
    expect_terminated(s_, true);

    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &raw_, key_));
    ASSERT_CKR_OK(p11()->C_Decrypt(s_, pt.data(), kAesBlock, nullptr, &need));
    len = sizeof(out);
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_DecryptFinal(s_, out, &len));
    expect_terminated(s_, false);
}

TEST_F(aes_multipart_cbc, bad_arguments_terminate_the_operation)
{
    std::vector<CK_BYTE> pt = pattern(kAesBlock);
    CK_BYTE out[4 * kAesBlock];
    CK_ULONG len = sizeof(out);

    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &raw_, key_));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, update(s_, true, pt.data(), kAesBlock, out, nullptr));
    expect_terminated(s_, true);

    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &raw_, key_));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, update(s_, true, nullptr, kAesBlock, out, &len));
    expect_terminated(s_, true);

    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &raw_, key_));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_DecryptFinal(s_, out, nullptr));
    expect_terminated(s_, false);
}

TEST_F(aes_multipart_cbc, calls_need_an_operation_of_their_direction)
{
    std::vector<CK_BYTE> pt = pattern(kAesBlock);
    CK_BYTE out[4 * kAesBlock];
    CK_ULONG len = sizeof(out);
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, update(s_, true, pt.data(), kAesBlock, out, &len));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_EncryptFinal(s_, out, nullptr))
        << "with no operation even a NULL length is not judged";

    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &raw_, key_));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, update(s_, false, pt.data(), kAesBlock, out, &len));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_DecryptFinal(s_, out, &len));
    len = sizeof(out);
    EXPECT_CKR_OK(p11()->C_EncryptFinal(s_, out, &len)) << "the encrypt operation is untouched";
}

TEST_F(aes_multipart_cbc, an_invalid_session_leaves_the_operation_alone)
{
    std::vector<CK_BYTE> pt = pattern(kAesBlock);
    CK_BYTE out[4 * kAesBlock];
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &raw_, key_));
    EXPECT_CKR(
        CKR_SESSION_HANDLE_INVALID,
        p11()->C_EncryptUpdate(kInvalidSession, pt.data(), kAesBlock, out, &len)
    );
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, p11()->C_EncryptFinal(kInvalidSession, out, &len));
    len = sizeof(out);
    EXPECT_CKR_OK(update(s_, true, pt.data(), kAesBlock, out, &len));
    len = sizeof(out);
    EXPECT_CKR_OK(p11()->C_EncryptFinal(s_, out, &len));
}

TEST_F(aes_multipart_cbc, update_after_the_final_call_ran_is_operation_active)
{
    // Once a final call with a buffer has finished the stream, only its retry
    // may follow.
    std::vector<CK_BYTE> ct;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &pad_, key_, pattern(kAesBlock + 4), ct));
    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &pad_, key_));
    CK_BYTE out[2 * kAesBlock];
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(update(s_, false, ct.data(), static_cast<CK_ULONG>(ct.size()), out, &len));
    CK_BYTE small = 0;
    len = 1;
    ASSERT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_DecryptFinal(s_, &small, &len));
    len = sizeof(out);
    EXPECT_CKR(CKR_OPERATION_ACTIVE, update(s_, false, ct.data(), kAesBlock, out, &len));
    expect_terminated(s_, false);
}

// ===========================================================================
// AES-GCM
// ===========================================================================

class aes_multipart_gcm : public multipart_base
{
  protected:
    void SetUp() override
    {
        UserSession::SetUp();
        if (HasFatalFailure())
        {
            return;
        }
        ASSERT_CKR_OK(gen_gcm_key(s_, "multipart-gcm", &key_));
        std::memset(iv_, 0x6D, sizeof(iv_));
        const char aad[] = "multi-part header";
        aad_.assign(aad, aad + sizeof(aad) - 1);
        params_ = {};
        params_.pIv = iv_;
        params_.ulIvLen = kGcmIv;
        params_.ulIvBits = kGcmIv * 8;
        params_.pAAD = aad_.data();
        params_.ulAADLen = static_cast<CK_ULONG>(aad_.size());
        params_.ulTagBits = kGcmTag * 8;
        mech_ = { CKM_AES_GCM, &params_, sizeof(params_) };
    }

    CK_BYTE iv_[kGcmIv];
    std::vector<CK_BYTE> aad_;
    CK_GCM_PARAMS params_{};
    CK_MECHANISM mech_{};
};

TEST_F(aes_multipart_gcm, parts_agree_with_one_shot)
{
    for (size_t n : { 0ul, 1ul, kAesBlock, 37ul, 200ul })
    {
        ASSERT_NO_FATAL_FAILURE(check_agreement(&mech_, pattern(n)));
    }
}

TEST_F(aes_multipart_gcm, updates_release_nothing_until_the_final_call)
{
    constexpr CK_ULONG kLen = 37;
    std::vector<CK_BYTE> pt = pattern(kLen);
    std::vector<CK_BYTE> ct(kLen + kGcmTag);
    CK_ULONG len = static_cast<CK_ULONG>(ct.size());
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, key_));
    ASSERT_CKR_OK(update(s_, true, pt.data(), kLen, ct.data(), &len));
    EXPECT_EQ(0u, len);
    len = static_cast<CK_ULONG>(ct.size());
    ASSERT_CKR_OK(p11()->C_EncryptFinal(s_, ct.data(), &len));
    EXPECT_EQ(kLen + kGcmTag, len) << "ciphertext and the appended tag";

    // A GCM decrypt must not release plaintext before its tag is checked.
    std::vector<CK_BYTE> back(kLen);
    len = kLen;
    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &mech_, key_));
    ASSERT_CKR_OK(update(s_, false, ct.data(), static_cast<CK_ULONG>(ct.size()), back.data(), &len)
    );
    EXPECT_EQ(0u, len);
    len = kLen;
    ASSERT_CKR_OK(p11()->C_DecryptFinal(s_, back.data(), &len));
    EXPECT_EQ(kLen, len);
    EXPECT_EQ(pt, back);
}

TEST_F(aes_multipart_gcm, tampered_tag_fails_at_the_final_call)
{
    // As in the one-shot case the failed tag check arrives as the generic
    // device-command failure (see gcm_tests.cpp, expect_refused).
    constexpr CK_ULONG kLen = 37;
    std::vector<CK_BYTE> ct;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, pattern(kLen), ct));
    ct.back() ^= 0x01;
    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &mech_, key_));
    std::vector<CK_BYTE> out(ct.size(), 0xEE);
    CK_ULONG len = static_cast<CK_ULONG>(out.size());
    ASSERT_CKR_OK(update(s_, false, ct.data(), static_cast<CK_ULONG>(ct.size()), out.data(), &len));
    len = static_cast<CK_ULONG>(out.size());
    EXPECT_CKR(CKR_FUNCTION_FAILED, p11()->C_DecryptFinal(s_, out.data(), &len));
    EXPECT_EQ(0u, len);
    for (size_t i = 0; i < kLen; i++)
    {
        ASSERT_EQ(0, out[i]) << "byte " << i << " of the output buffer was not wiped";
    }
    expect_terminated(s_, false);
}

TEST_F(aes_multipart_gcm, ciphertext_shorter_than_the_tag_is_len_range)
{
    std::vector<CK_BYTE> in = pattern(kGcmTag - 1);
    CK_BYTE out[kGcmTag];
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &mech_, key_));
    ASSERT_CKR_OK(update(s_, false, in.data(), static_cast<CK_ULONG>(in.size()), out, &len));
    len = sizeof(out);
    EXPECT_CKR(CKR_ENCRYPTED_DATA_LEN_RANGE, p11()->C_DecryptFinal(s_, out, &len));
    expect_terminated(s_, false);
}

TEST_F(aes_multipart_gcm, final_probe_and_too_small_buffer_keep_the_operation)
{
    constexpr CK_ULONG kLen = 37;
    std::vector<CK_BYTE> pt = pattern(kLen);
    std::vector<CK_BYTE> one;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, pt, one));

    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, key_));
    CK_BYTE none = 0;
    CK_ULONG len = 0;
    ASSERT_CKR_OK(update(s_, true, pt.data(), kLen, &none, &len));
    CK_ULONG need = 0;
    ASSERT_CKR_OK(p11()->C_EncryptFinal(s_, nullptr, &need));
    EXPECT_EQ(kLen + kGcmTag, need);
    std::vector<CK_BYTE> ct(need);
    len = need - 1;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_EncryptFinal(s_, ct.data(), &len));
    EXPECT_EQ(need, len);
    ASSERT_CKR_OK(p11()->C_EncryptFinal(s_, ct.data(), &len));
    EXPECT_EQ(one, ct);
}

// ===========================================================================
// AES-XTS
// ===========================================================================

class aes_multipart_xts : public multipart_base
{
  protected:
    void SetUp() override
    {
        UserSession::SetUp();
        if (HasFatalFailure())
        {
            return;
        }
        ASSERT_CKR_OK(gen_xts_key(s_, "multipart-xts", &key_));
        std::memset(tweak_, 0, sizeof(tweak_));
        tweak_[0] = 0x3B;
        mech_ = { CKM_AES_XTS, tweak_, sizeof(tweak_) };
    }

    CK_BYTE tweak_[kXtsTweak];
    CK_MECHANISM mech_{};
};

TEST_F(aes_multipart_xts, parts_agree_with_one_shot)
{
    for (size_t n : { kAesBlock, 2 * kAesBlock, 512ul, kXtsMaxData })
    {
        ASSERT_NO_FATAL_FAILURE(check_agreement(&mech_, pattern(n)));
    }
}

TEST_F(aes_multipart_xts, an_update_past_the_data_unit_cap_fails_at_once)
{
    // The whole operation is one data unit, so the cap applies to the sum of
    // the parts; the part that crosses it is refused rather than buffered.
    std::vector<CK_BYTE> in = pattern(kXtsMaxData);
    CK_BYTE out[kAesBlock];
    for (bool encrypt : { true, false })
    {
        SCOPED_TRACE(encrypt ? "encrypt" : "decrypt");
        ASSERT_CKR_OK(
            encrypt ? p11()->C_EncryptInit(s_, &mech_, key_)
                    : p11()->C_DecryptInit(s_, &mech_, key_)
        );
        CK_ULONG len = sizeof(out);
        ASSERT_CKR_OK(update(s_, encrypt, in.data(), kXtsMaxData, out, &len));
        EXPECT_EQ(0u, len) << "nothing comes out before the final call";
        len = sizeof(out);
        EXPECT_CKR(
            encrypt ? CKR_DATA_LEN_RANGE : CKR_ENCRYPTED_DATA_LEN_RANGE,
            update(s_, encrypt, in.data(), kAesBlock, out, &len)
        );
        expect_terminated(s_, encrypt);
    }
}

TEST_F(aes_multipart_xts, final_needs_one_whole_data_unit)
{
    CK_BYTE out[2 * kAesBlock];
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, key_));
    EXPECT_CKR(CKR_DATA_LEN_RANGE, p11()->C_EncryptFinal(s_, out, &len)) << "no data";
    expect_terminated(s_, true);

    std::vector<CK_BYTE> in = pattern(kAesBlock + 1);
    len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &mech_, key_));
    ASSERT_CKR_OK(update(s_, true, in.data(), static_cast<CK_ULONG>(in.size()), out, &len));
    len = sizeof(out);
    EXPECT_CKR(CKR_DATA_LEN_RANGE, p11()->C_EncryptFinal(s_, out, &len)) << "not whole blocks";
    expect_terminated(s_, true);
}
