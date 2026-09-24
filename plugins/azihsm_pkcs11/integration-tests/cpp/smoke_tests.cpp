// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file smoke_tests.cpp
///
/// The module loads, identifies itself, exposes a token on slot 0 and
/// advertises the AES mechanisms this slice implements. If the .so is missing
/// or its init fails, ModuleEnvironment already throws before any of these.

#include <gtest/gtest.h>
#include <vector>

#include "utils/module.hpp"

class smoke : public PublicSession
{
};

TEST_F(smoke, module_reports_cryptoki_3_1)
{
    CK_INFO info{};
    ASSERT_CKR_OK(p11()->C_GetInfo(&info));
    EXPECT_EQ(3, info.cryptokiVersion.major);
    EXPECT_EQ(1, info.cryptokiVersion.minor);
}

TEST_F(smoke, slot_zero_has_a_login_required_token)
{
    CK_ULONG count = 0;
    ASSERT_CKR_OK(p11()->C_GetSlotList(CK_TRUE, nullptr, &count));
    ASSERT_GE(count, 1u);

    CK_TOKEN_INFO tinfo{};
    ASSERT_CKR_OK(p11()->C_GetTokenInfo(kSlot, &tinfo));
    EXPECT_NE(0u, tinfo.flags & CKF_LOGIN_REQUIRED)
        << "every key-backed call needs the device session behind C_Login";
}

TEST_F(smoke, aes_mechanisms_are_advertised)
{
    CK_ULONG count = 0;
    ASSERT_CKR_OK(p11()->C_GetMechanismList(kSlot, nullptr, &count));
    std::vector<CK_MECHANISM_TYPE> mechs(count);
    ASSERT_CKR_OK(p11()->C_GetMechanismList(kSlot, mechs.data(), &count));

    auto has = [&](CK_MECHANISM_TYPE m) {
        for (CK_MECHANISM_TYPE x : mechs)
        {
            if (x == m)
            {
                return true;
            }
        }
        return false;
    };
    EXPECT_TRUE(has(CKM_AES_KEY_GEN));
    EXPECT_TRUE(has(CKM_AES_CBC));
    EXPECT_TRUE(has(CKM_AES_CBC_PAD));

    CK_MECHANISM_INFO minfo{};
    ASSERT_CKR_OK(p11()->C_GetMechanismInfo(kSlot, CKM_AES_KEY_GEN, &minfo));
    EXPECT_NE(0u, minfo.flags & CKF_GENERATE);
    ASSERT_CKR_OK(p11()->C_GetMechanismInfo(kSlot, CKM_AES_CBC_PAD, &minfo));
    EXPECT_NE(0u, minfo.flags & CKF_ENCRYPT);
    EXPECT_NE(0u, minfo.flags & CKF_DECRYPT);
}

TEST_F(smoke, unimplemented_entry_point_reports_not_supported)
{
    CK_UTF8CHAR pin[] = "1234";
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_SetPIN(s_, pin, 4, pin, 4));
}

TEST_F(smoke, session_info_reflects_open_public_session)
{
    CK_SESSION_INFO sinfo{};
    ASSERT_CKR_OK(p11()->C_GetSessionInfo(s_, &sinfo));
    EXPECT_EQ(kSlot, sinfo.slotID);
    EXPECT_EQ(static_cast<CK_STATE>(CKS_RW_PUBLIC_SESSION), sinfo.state);
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, p11()->C_GetSessionInfo(kInvalidSession, &sinfo));
}
