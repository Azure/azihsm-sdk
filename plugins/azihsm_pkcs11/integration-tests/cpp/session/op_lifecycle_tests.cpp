// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file op_lifecycle_tests.cpp
///
/// The operation-lifetime rules on the digest entry points (they work in a
/// public session, so they are the cheapest place to pin the module-wide
/// state machine): a bad session handle before anything else, an operation
/// must exist before arguments are judged, every data-call failure terminates
/// the operation, and a one-shot and a multi-part operation cannot be mixed.

#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "utils/module.hpp"

namespace
{

CK_MECHANISM g_sha256 = { CKM_SHA256, nullptr, 0 };
const CK_BYTE g_abc[] = { 'a', 'b', 'c' };
const CK_BYTE g_abc_sha256[32] = { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                                   0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
                                   0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };

} // namespace

class op_lifecycle : public PublicSession
{
  protected:
    CK_BYTE_PTR abc()
    {
        return const_cast<CK_BYTE_PTR>(g_abc);
    }
};

TEST_F(op_lifecycle, one_shot_and_multi_part_digests_agree_with_the_known_answer)
{
    CK_BYTE one[32], multi[32];
    CK_ULONG len = sizeof(one);
    ASSERT_CKR_OK(p11()->C_DigestInit(s_, &g_sha256));
    ASSERT_CKR_OK(p11()->C_Digest(s_, abc(), 3, one, &len));
    EXPECT_EQ(32u, len);

    len = sizeof(multi);
    ASSERT_CKR_OK(p11()->C_DigestInit(s_, &g_sha256));
    ASSERT_CKR_OK(p11()->C_DigestUpdate(s_, abc(), 1));
    ASSERT_CKR_OK(p11()->C_DigestUpdate(s_, abc() + 1, 2));
    ASSERT_CKR_OK(p11()->C_DigestFinal(s_, multi, &len));
    EXPECT_EQ(32u, len);

    EXPECT_EQ(0, std::memcmp(one, g_abc_sha256, 32));
    EXPECT_EQ(0, std::memcmp(multi, g_abc_sha256, 32));
}

TEST_F(op_lifecycle, init_reports_the_session_handle_first)
{
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, p11()->C_DigestInit(kInvalidSession, &g_sha256));
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, p11()->C_DigestInit(kInvalidSession, nullptr));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_DigestInit(s_, nullptr));
}

TEST_F(op_lifecycle, data_calls_need_an_operation_before_arguments_are_judged)
{
    // With no operation there is nothing to terminate, so even a NULL length
    // pointer is answered with CKR_OPERATION_NOT_INITIALIZED.
    CK_BYTE buf[64];
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Digest(s_, abc(), 3, buf, nullptr));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_DigestFinal(s_, buf, nullptr));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_DigestUpdate(s_, nullptr, 5));
    // But a bad handle still wins over everything.
    EXPECT_CKR(
        CKR_SESSION_HANDLE_INVALID,
        p11()->C_Digest(kInvalidSession, abc(), 3, buf, nullptr)
    );
}

TEST_F(op_lifecycle, bad_arguments_terminate_the_digest_operation)
{
    CK_BYTE buf[64];
    CK_ULONG len = sizeof(buf);

    ASSERT_CKR_OK(p11()->C_DigestInit(s_, &g_sha256));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_Digest(s_, abc(), 3, buf, nullptr));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Digest(s_, abc(), 3, buf, &len));

    ASSERT_CKR_OK(p11()->C_DigestInit(s_, &g_sha256));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_Digest(s_, nullptr, 3, buf, &len));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Digest(s_, abc(), 3, buf, &len));

    ASSERT_CKR_OK(p11()->C_DigestInit(s_, &g_sha256));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_DigestFinal(s_, buf, nullptr));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_DigestFinal(s_, buf, &len));

    ASSERT_CKR_OK(p11()->C_DigestInit(s_, &g_sha256));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_DigestUpdate(s_, nullptr, 5));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_DigestFinal(s_, buf, &len));
}

TEST_F(op_lifecycle, sizing_probe_and_too_small_buffer_keep_the_operation)
{
    CK_BYTE buf[64];
    CK_ULONG len = 0;
    ASSERT_CKR_OK(p11()->C_DigestInit(s_, &g_sha256));
    EXPECT_CKR_OK(p11()->C_Digest(s_, abc(), 3, nullptr, &len));
    EXPECT_EQ(32u, len);
    len = 4;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_Digest(s_, abc(), 3, buf, &len));
    EXPECT_EQ(32u, len);
    len = sizeof(buf);
    EXPECT_CKR_OK(p11()->C_Digest(s_, abc(), 3, buf, &len));
    EXPECT_EQ(0, std::memcmp(buf, g_abc_sha256, 32)) << "the data was absorbed exactly once";
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Digest(s_, abc(), 3, buf, &len));
}

TEST_F(op_lifecycle, one_shot_after_update_is_operation_active_and_terminates)
{
    CK_BYTE buf[64];
    CK_ULONG len = 0;
    ASSERT_CKR_OK(p11()->C_DigestInit(s_, &g_sha256));
    ASSERT_CKR_OK(p11()->C_DigestUpdate(s_, abc(), 1));
    EXPECT_CKR_OK(p11()->C_DigestFinal(s_, nullptr, &len)) << "a final sizing probe is fine";
    EXPECT_EQ(32u, len);
    len = sizeof(buf);
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_Digest(s_, abc() + 1, 2, buf, &len));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_DigestFinal(s_, buf, &len));
}

TEST_F(op_lifecycle, multi_part_after_one_shot_probe_is_operation_active_and_terminates)
{
    CK_BYTE buf[64];
    CK_ULONG len = 0;
    ASSERT_CKR_OK(p11()->C_DigestInit(s_, &g_sha256));
    EXPECT_CKR_OK(p11()->C_Digest(s_, abc(), 3, nullptr, &len));
    len = sizeof(buf);
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_DigestFinal(s_, buf, &len));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Digest(s_, abc(), 3, buf, &len));

    ASSERT_CKR_OK(p11()->C_DigestInit(s_, &g_sha256));
    EXPECT_CKR_OK(p11()->C_Digest(s_, abc(), 3, nullptr, &len));
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_DigestUpdate(s_, abc(), 3));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_DigestFinal(s_, buf, &len));
}

TEST_F(op_lifecycle, final_right_after_init_is_the_zero_part_case)
{
    // SHA-256 of the empty message.
    static const CK_BYTE empty_sha256[32] = { 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                                              0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                                              0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                                              0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };
    CK_BYTE buf[64];
    CK_ULONG len = sizeof(buf);
    ASSERT_CKR_OK(p11()->C_DigestInit(s_, &g_sha256));
    EXPECT_CKR_OK(p11()->C_DigestFinal(s_, buf, &len));
    EXPECT_EQ(32u, len);
    EXPECT_EQ(0, std::memcmp(buf, empty_sha256, 32));
}

TEST_F(op_lifecycle, a_second_init_is_operation_active)
{
    ASSERT_CKR_OK(p11()->C_DigestInit(s_, &g_sha256));
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_DigestInit(s_, &g_sha256));
    CK_MECHANISM md5 = { CKM_MD5, nullptr, 0 };
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_DigestInit(s_, &md5))
        << "the active operation is reported before the mechanism is judged";
}

TEST_F(op_lifecycle, unsupported_digest_mechanism_is_invalid)
{
    CK_MECHANISM md5 = { CKM_MD5, nullptr, 0 };
    EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_DigestInit(s_, &md5));
    CK_BYTE param = 0;
    CK_MECHANISM with_param = { CKM_SHA256, &param, 1 };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_DigestInit(s_, &with_param));
}
