// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// The module under test and the session fixtures every test builds on.
///
/// The module is dlopen'd and C_Initialize'd once per process by
/// ModuleEnvironment (registered in main.cpp); each test then opens its own
/// session on slot 0 through PublicSession (logged out — public objects and
/// digests work here) or UserSession (logged in as CKU_USER — every
/// key-backed call needs the device session behind the login). After every
/// test the fixture abandons any operation the test left active, destroys the
/// session objects it created, logs out and closes the session, so no state
/// leaks between cases and a single-process run stays idempotent.

#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <gtest/gtest.h>
#include <ostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "azihsm_pkcs11_compat.h"

#ifndef AZIHSM_PKCS11_DEFAULT_MODULE
#define AZIHSM_PKCS11_DEFAULT_MODULE ""
#endif

/// A CK_RV that prints as hex in assertion failures (gtest formats the
/// compared values itself, so a stream manipulator on the message would not
/// reach them and would leak into whatever the caller streams afterwards).
struct Ckr
{
    CK_RV v;
};
inline bool operator==(Ckr a, Ckr b)
{
    return a.v == b.v;
}
inline std::ostream &operator<<(std::ostream &os, Ckr c)
{
    return os << "0x" << std::hex << c.v << std::dec;
}

#define EXPECT_CKR(expected, actual) EXPECT_EQ(Ckr{ (CK_RV)(expected) }, Ckr{ (CK_RV)(actual) })
#define ASSERT_CKR(expected, actual) ASSERT_EQ(Ckr{ (CK_RV)(expected) }, Ckr{ (CK_RV)(actual) })
#define EXPECT_CKR_OK(actual) EXPECT_CKR(CKR_OK, actual)
#define ASSERT_CKR_OK(actual) ASSERT_CKR(CKR_OK, actual)

/// The slot every test uses (the first AZIHSM partition).
constexpr CK_SLOT_ID kSlot = 0;
/// A session handle no module ever hands out.
constexpr CK_SESSION_HANDLE kInvalidSession = 0xDEADBEEF;
/// An object handle no module ever hands out.
constexpr CK_OBJECT_HANDLE kInvalidObject = 0xDEADBEEF;

class Pkcs11Module
{
  public:
    static Pkcs11Module &instance()
    {
        static Pkcs11Module m;
        return m;
    }

    /// AZIHSM_PKCS11_MODULE, or the cargo build output baked in at configure time.
    static const char *module_path()
    {
        const char *p = std::getenv("AZIHSM_PKCS11_MODULE");
        return ((p != nullptr) && (*p != '\0')) ? p : AZIHSM_PKCS11_DEFAULT_MODULE;
    }

    /// AZIHSM_PKCS11_TEST_PIN, or the simulator default.
    static std::string pin()
    {
        const char *p = std::getenv("AZIHSM_PKCS11_TEST_PIN");
        return ((p != nullptr) && (*p != '\0')) ? std::string(p) : std::string("1234");
    }

    void load()
    {
        const char *path = module_path();
        dl_ = dlopen(path, RTLD_NOW);
        if (dl_ == nullptr)
        {
            throw std::runtime_error(std::string("dlopen(") + path + "): " + dlerror());
        }
        using get_list_fn = CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR);
        auto get_list = reinterpret_cast<get_list_fn>(dlsym(dl_, "C_GetFunctionList"));
        if (get_list == nullptr)
        {
            throw std::runtime_error("C_GetFunctionList not exported by the module");
        }
        CK_RV rv = get_list(&fns_);
        if ((rv != CKR_OK) || (fns_ == nullptr))
        {
            throw std::runtime_error("C_GetFunctionList failed");
        }
        rv = fns_->C_Initialize(nullptr);
        if (rv != CKR_OK)
        {
            throw std::runtime_error("C_Initialize failed with rv=" + std::to_string(rv));
        }
    }

    void unload() noexcept
    {
        if (fns_ != nullptr)
        {
            (void)fns_->C_Finalize(nullptr);
            fns_ = nullptr;
        }
        if (dl_ != nullptr)
        {
            dlclose(dl_);
            dl_ = nullptr;
        }
    }

    CK_FUNCTION_LIST_PTR fns() const
    {
        return fns_;
    }

  private:
    void *dl_ = nullptr;
    CK_FUNCTION_LIST_PTR fns_ = nullptr;
};

/// The module's function list (valid once ModuleEnvironment has run).
inline CK_FUNCTION_LIST_PTR p11()
{
    return Pkcs11Module::instance().fns();
}

class ModuleEnvironment : public ::testing::Environment
{
  public:
    void SetUp() override
    {
        Pkcs11Module::instance().load();
    }
    void TearDown() override
    {
        Pkcs11Module::instance().unload();
    }
};

/// Terminate whatever operation `s` has active. A data call with bad
/// arguments terminates a cipher or digest operation (spec rule, see
/// azihsm_pkcs11_crypt.c), and C_FindObjectsFinal ends a search; each call is
/// a harmless CKR_OPERATION_NOT_INITIALIZED when nothing is active.
inline void abandon_operations(CK_SESSION_HANDLE s)
{
    (void)p11()->C_Encrypt(s, nullptr, 0, nullptr, nullptr);
    (void)p11()->C_Decrypt(s, nullptr, 0, nullptr, nullptr);
    (void)p11()->C_Digest(s, nullptr, 0, nullptr, nullptr);
    (void)p11()->C_FindObjectsFinal(s);
}

/// Destroy every session object visible from `s` (anything not CKA_TOKEN=TRUE),
/// leaving token objects alone. The module destroys a session's own objects
/// when it closes; this is belt and braces for anything a test created on a
/// session it never closed, so a long single-process run stays idempotent.
inline void destroy_session_objects(CK_SESSION_HANDLE s)
{
    if (p11()->C_FindObjectsInit(s, nullptr, 0) != CKR_OK)
    {
        return;
    }
    std::vector<CK_OBJECT_HANDLE> all;
    CK_OBJECT_HANDLE batch[64];
    CK_ULONG n = 0;
    while ((p11()->C_FindObjects(s, batch, 64, &n) == CKR_OK) && (n > 0))
    {
        all.insert(all.end(), batch, batch + n);
    }
    (void)p11()->C_FindObjectsFinal(s);
    for (CK_OBJECT_HANDLE h : all)
    {
        CK_BBOOL token = CK_FALSE;
        CK_ATTRIBUTE a = { CKA_TOKEN, &token, sizeof(token) };
        bool is_token = (p11()->C_GetAttributeValue(s, h, &a, 1) == CKR_OK) && (token == CK_TRUE);
        if (!is_token)
        {
            (void)p11()->C_DestroyObject(s, h);
        }
    }
}

/// A read/write session on slot 0, logged OUT.
class PublicSession : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ASSERT_NE(p11(), nullptr) << "module not loaded";
        ASSERT_CKR_OK(
            p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &s_)
        );
    }
    void TearDown() override
    {
        if (s_ != 0)
        {
            abandon_operations(s_);
            destroy_session_objects(s_);
            (void)p11()->C_CloseSession(s_);
            s_ = 0;
        }
    }

    CK_SESSION_HANDLE s_ = 0;
};

/// A read/write session on slot 0, logged in as CKU_USER (token-wide login);
/// logs out again after the test.
class UserSession : public PublicSession
{
  protected:
    void SetUp() override
    {
        PublicSession::SetUp();
        if (HasFatalFailure())
        {
            return;
        }
        std::string pin = Pkcs11Module::pin();
        ASSERT_CKR_OK(p11()->C_Login(
            s_,
            CKU_USER,
            reinterpret_cast<CK_UTF8CHAR_PTR>(pin.data()),
            static_cast<CK_ULONG>(pin.size())
        ));
    }
    void TearDown() override
    {
        if (s_ != 0)
        {
            /* Private session objects are only visible while logged in. */
            abandon_operations(s_);
            destroy_session_objects(s_);
            (void)p11()->C_Logout(s_); /* may already be logged out by the test */
        }
        PublicSession::TearDown();
    }
};
