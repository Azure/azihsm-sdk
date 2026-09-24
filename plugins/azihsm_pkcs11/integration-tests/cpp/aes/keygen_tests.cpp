// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file keygen_tests.cpp
///
/// C_GenerateKey with CKM_AES_KEY_GEN through the module ABI: the login gate,
/// argument/mechanism/session precedence, the template verdicts as seen by a
/// caller (the full CK_RV matrix of the normaliser is unit-tested in
/// tests/aes_template_test.c; here a representative row per verdict proves the
/// wiring), and the attributes a generated key carries.

#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "azihsm_pkcs11_template.h"
#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"

namespace
{

CK_BBOOL g_true = CK_TRUE;
CK_BBOOL g_false = CK_FALSE;
CK_ULONG g_len32 = 32;
CK_MECHANISM g_keygen = { CKM_AES_KEY_GEN, nullptr, 0 };

/// C_GenerateKey with CKA_VALUE_LEN=32 plus one extra attribute.
CK_RV keygen_with(CK_SESSION_HANDLE s, CK_ATTRIBUTE extra, CK_OBJECT_HANDLE *out)
{
    CK_ATTRIBUTE tmpl[] = { { CKA_VALUE_LEN, &g_len32, sizeof(g_len32) }, extra };
    return p11()->C_GenerateKey(s, &g_keygen, tmpl, 2, out);
}

} // namespace

// ---------------------------------------------------------------------------
// Logged out
// ---------------------------------------------------------------------------

class aes_keygen_public : public PublicSession
{
};

TEST_F(aes_keygen_public, requires_login)
{
    CK_OBJECT_HANDLE key = 0;
    EXPECT_CKR(CKR_USER_NOT_LOGGED_IN, gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "nologin", &key));
}

TEST_F(aes_keygen_public, malformed_request_is_reported_before_login_state)
{
    // A logged-out caller learns about its bad request, not about its login.
    CK_OBJECT_HANDLE key = 0;
    CK_ATTRIBUTE tmpl[] = { { CKA_VALUE_LEN, &g_len32, sizeof(g_len32) } };
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_GenerateKey(s_, &g_keygen, nullptr, 1, &key));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_GenerateKey(s_, &g_keygen, tmpl, 1, nullptr));
    CK_MECHANISM des = { CKM_DES_KEY_GEN, nullptr, 0 };
    EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_GenerateKey(s_, &des, tmpl, 1, &key));
}

// ---------------------------------------------------------------------------
// Logged in
// ---------------------------------------------------------------------------

class aes_keygen : public UserSession
{
};

TEST_F(aes_keygen, session_handle_is_checked_before_mechanism_and_arguments)
{
    CK_OBJECT_HANDLE key = 0;
    CK_MECHANISM des = { CKM_DES_KEY_GEN, nullptr, 0 };
    CK_ATTRIBUTE tmpl[] = { { CKA_VALUE_LEN, &g_len32, sizeof(g_len32) } };
    EXPECT_CKR(
        CKR_SESSION_HANDLE_INVALID,
        p11()->C_GenerateKey(kInvalidSession, &des, tmpl, 1, &key)
    );
    EXPECT_CKR(
        CKR_SESSION_HANDLE_INVALID,
        p11()->C_GenerateKey(kInvalidSession, nullptr, nullptr, 3, nullptr)
    );
}

TEST_F(aes_keygen, arguments_are_checked_before_mechanism)
{
    CK_OBJECT_HANDLE key = 0;
    CK_MECHANISM des = { CKM_DES_KEY_GEN, nullptr, 0 };
    CK_ATTRIBUTE tmpl[] = { { CKA_VALUE_LEN, &g_len32, sizeof(g_len32) } };
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_GenerateKey(s_, &des, nullptr, 3, &key));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_GenerateKey(s_, &des, tmpl, 1, nullptr));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_GenerateKey(s_, nullptr, tmpl, 1, &key));
}

TEST_F(aes_keygen, rejects_mechanism_parameter)
{
    CK_OBJECT_HANDLE key = 0;
    CK_BYTE param = 0;
    CK_MECHANISM with_param = { CKM_AES_KEY_GEN, &param, 1 };
    CK_ATTRIBUTE tmpl[] = { { CKA_VALUE_LEN, &g_len32, sizeof(g_len32) } };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_GenerateKey(s_, &with_param, tmpl, 1, &key));
}

TEST_F(aes_keygen, rejects_other_keygen_mechanisms)
{
    CK_OBJECT_HANDLE key = 0;
    CK_ATTRIBUTE tmpl[] = { { CKA_VALUE_LEN, &g_len32, sizeof(g_len32) } };
    CK_MECHANISM xts = { CKM_AES_XTS_KEY_GEN, nullptr, 0 };
    EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_GenerateKey(s_, &xts, tmpl, 1, &key));
    CK_MECHANISM generic = { CKM_GENERIC_SECRET_KEY_GEN, nullptr, 0 };
    EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_GenerateKey(s_, &generic, tmpl, 1, &key));
}

TEST_F(aes_keygen, template_without_value_len_is_incomplete)
{
    CK_OBJECT_HANDLE key = 0;
    EXPECT_CKR(CKR_TEMPLATE_INCOMPLETE, p11()->C_GenerateKey(s_, &g_keygen, nullptr, 0, &key));
    CK_ATTRIBUTE label_only[] = { { CKA_LABEL, const_cast<char *>("x"), 1 } };
    EXPECT_CKR(CKR_TEMPLATE_INCOMPLETE, p11()->C_GenerateKey(s_, &g_keygen, label_only, 1, &key));
}

TEST_F(aes_keygen, rejects_unsupported_key_length)
{
    CK_OBJECT_HANDLE key = 0;
    for (CK_ULONG bad : { 0ul, 8ul, 20ul, 33ul, 64ul })
    {
        CK_ATTRIBUTE tmpl[] = { { CKA_VALUE_LEN, &bad, sizeof(bad) } };
        EXPECT_CKR(CKR_ATTRIBUTE_VALUE_INVALID, p11()->C_GenerateKey(s_, &g_keygen, tmpl, 1, &key))
            << "CKA_VALUE_LEN " << bad;
    }
}

TEST_F(aes_keygen, rejects_extractable_and_non_sensitive)
{
    // Device keys only ever exist masked, so a readable key cannot be produced.
    CK_OBJECT_HANDLE key = 0;
    EXPECT_CKR(
        CKR_TEMPLATE_INCONSISTENT,
        keygen_with(s_, { CKA_EXTRACTABLE, &g_true, sizeof(g_true) }, &key)
    );
    EXPECT_CKR(
        CKR_TEMPLATE_INCONSISTENT,
        keygen_with(s_, { CKA_SENSITIVE, &g_false, sizeof(g_false) }, &key)
    );
}

TEST_F(aes_keygen, token_computed_attributes_are_read_only)
{
    CK_OBJECT_HANDLE key = 0;
    for (CK_ATTRIBUTE_TYPE t : { CKA_LOCAL, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE })
    {
        EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, keygen_with(s_, { t, &g_true, sizeof(g_true) }, &key))
            << "attribute 0x" << std::hex << t;
    }
}

TEST_F(aes_keygen, rejects_wrong_class_and_non_aes_key_types)
{
    CK_OBJECT_HANDLE key = 0;
    CK_OBJECT_CLASS data = CKO_DATA;
    EXPECT_CKR(
        CKR_TEMPLATE_INCONSISTENT,
        keygen_with(s_, { CKA_CLASS, &data, sizeof(data) }, &key)
    );
    for (CK_KEY_TYPE kt : { CKK_DES3, CKK_GENERIC_SECRET, CKK_RSA })
    {
        EXPECT_CKR(
            CKR_TEMPLATE_INCONSISTENT,
            keygen_with(s_, { CKA_KEY_TYPE, &kt, sizeof(kt) }, &key)
        ) << "key type 0x"
          << std::hex << kt;
    }
}

TEST_F(aes_keygen, rejects_supplied_key_material_and_duplicates)
{
    CK_OBJECT_HANDLE key = 0;
    CK_BYTE material[32] = { 0 };
    EXPECT_CKR(
        CKR_TEMPLATE_INCONSISTENT,
        keygen_with(s_, { CKA_VALUE, material, sizeof(material) }, &key)
    );
    CK_ULONG other = 16;
    EXPECT_CKR(
        CKR_TEMPLATE_INCONSISTENT,
        keygen_with(s_, { CKA_VALUE_LEN, &other, sizeof(other) }, &key)
    );
    EXPECT_CKR(CKR_ATTRIBUTE_VALUE_INVALID, keygen_with(s_, { CKA_LABEL, nullptr, 4 }, &key))
        << "NULL value with a length";
}

TEST_F(aes_keygen, rejects_oversized_template)
{
    // One over the ceiling, made of distinct vendor attributes so nothing
    // else in the template is wrong.
    CK_BYTE byte = 0;
    std::vector<CK_ATTRIBUTE> tmpl(KEYGEN_MAX_TEMPLATE_ATTRS + 1);
    for (size_t i = 0; i < tmpl.size(); i++)
    {
        tmpl[i] = { CKA_VENDOR_DEFINED + static_cast<CK_ATTRIBUTE_TYPE>(i), &byte, sizeof(byte) };
    }
    tmpl[0] = { CKA_VALUE_LEN, &g_len32, sizeof(g_len32) };
    CK_OBJECT_HANDLE key = 0;
    EXPECT_CKR(
        CKR_ARGUMENTS_BAD,
        p11()->C_GenerateKey(s_, &g_keygen, tmpl.data(), static_cast<CK_ULONG>(tmpl.size()), &key)
    );
    // Exactly the ceiling is fine.
    EXPECT_CKR_OK(p11()->C_GenerateKey(s_, &g_keygen, tmpl.data(), KEYGEN_MAX_TEMPLATE_ATTRS, &key)
    );
}

TEST_F(aes_keygen, token_object_needs_a_read_write_session)
{
    // The login is token-wide, so a fresh read-only session is logged in too.
    CK_SESSION_HANDLE ro = 0;
    ASSERT_CKR_OK(p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &ro));
    CK_OBJECT_HANDLE key = 0;
    EXPECT_CKR(
        CKR_SESSION_READ_ONLY,
        keygen_with(ro, { CKA_TOKEN, &g_true, sizeof(g_true) }, &key)
    );
    EXPECT_CKR_OK(keygen_with(ro, { CKA_TOKEN, &g_false, sizeof(g_false) }, &key))
        << "a session object is fine on a read-only session";
    EXPECT_CKR_OK(p11()->C_CloseSession(ro));
}

TEST_F(aes_keygen, generates_all_three_key_sizes)
{
    for (CK_ULONG bytes : { 16ul, 24ul, 32ul })
    {
        CK_OBJECT_HANDLE key = 0;
        ASSERT_CKR_OK(gen_aes_key(s_, bytes, CK_TRUE, CK_TRUE, "sized", &key)) << bytes << " bytes";
        EXPECT_NE(CK_INVALID_HANDLE, key);
        CK_ULONG vlen = 0;
        ASSERT_CKR_OK(get_attr(s_, key, CKA_VALUE_LEN, &vlen));
        EXPECT_EQ(bytes, vlen);
    }
}

TEST_F(aes_keygen, generated_key_carries_the_token_decided_attributes)
{
    CK_OBJECT_HANDLE key = 0;
    CK_ATTRIBUTE minimal[] = { { CKA_VALUE_LEN, &g_len32, sizeof(g_len32) } };
    ASSERT_CKR_OK(p11()->C_GenerateKey(s_, &g_keygen, minimal, 1, &key));

    CK_OBJECT_CLASS cls = 0;
    CK_KEY_TYPE kt = 0;
    ASSERT_CKR_OK(get_attr(s_, key, CKA_CLASS, &cls));
    ASSERT_CKR_OK(get_attr(s_, key, CKA_KEY_TYPE, &kt));
    EXPECT_EQ(static_cast<CK_OBJECT_CLASS>(CKO_SECRET_KEY), cls);
    EXPECT_EQ(static_cast<CK_KEY_TYPE>(CKK_AES), kt);

    struct
    {
        CK_ATTRIBUTE_TYPE type;
        CK_BBOOL expected;
        const char *name;
    } bools[] = {
        { CKA_SENSITIVE, CK_TRUE, "CKA_SENSITIVE" },
        { CKA_EXTRACTABLE, CK_FALSE, "CKA_EXTRACTABLE" },
        { CKA_LOCAL, CK_TRUE, "CKA_LOCAL" },
        { CKA_ALWAYS_SENSITIVE, CK_TRUE, "CKA_ALWAYS_SENSITIVE" },
        { CKA_NEVER_EXTRACTABLE, CK_TRUE, "CKA_NEVER_EXTRACTABLE" },
        { CKA_ENCRYPT, CK_TRUE, "CKA_ENCRYPT (default)" },
        { CKA_DECRYPT, CK_TRUE, "CKA_DECRYPT (default)" },
    };
    for (const auto &b : bools)
    {
        CK_BBOOL v = 0x55;
        ASSERT_CKR_OK(get_attr(s_, key, b.type, &v)) << b.name;
        EXPECT_EQ(b.expected, v) << b.name;
    }
}

TEST_F(aes_keygen, caller_usage_flags_are_stored_verbatim)
{
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 16, CK_TRUE, CK_FALSE, "enc-only", &key));
    CK_BBOOL enc = 0x55, dec = 0x55;
    ASSERT_CKR_OK(get_attr(s_, key, CKA_ENCRYPT, &enc));
    ASSERT_CKR_OK(get_attr(s_, key, CKA_DECRYPT, &dec));
    EXPECT_EQ(CK_TRUE, enc);
    EXPECT_EQ(CK_FALSE, dec);
}

TEST_F(aes_keygen, key_material_is_never_readable)
{
    // A generated key has no CKA_VALUE host-side (only the masked blob), so
    // the store reports the attribute as absent; either way nothing leaks.
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "secret", &key));
    CK_BYTE raw[64];
    std::memset(raw, 0xEE, sizeof(raw));
    CK_ATTRIBUTE value = { CKA_VALUE, raw, sizeof(raw) };
    EXPECT_CKR(CKR_ATTRIBUTE_TYPE_INVALID, p11()->C_GetAttributeValue(s_, key, &value, 1));
    EXPECT_EQ(CK_UNAVAILABLE_INFORMATION, value.ulValueLen);
    EXPECT_EQ(0xEE, raw[0]) << "the buffer must not have been written";
}

TEST_F(aes_keygen, generated_key_is_findable_by_class_type_and_label)
{
    char label[] = "findme-unique-label";
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, label, &key));

    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = CKK_AES;
    CK_ATTRIBUTE find_tmpl[] = { { CKA_CLASS, &cls, sizeof(cls) },
                                 { CKA_KEY_TYPE, &kt, sizeof(kt) },
                                 { CKA_LABEL, label, sizeof(label) - 1 } };
    ASSERT_CKR_OK(p11()->C_FindObjectsInit(s_, find_tmpl, 3));
    // Drain the search in small batches so the assertion holds however many
    // other keys the store carries.
    std::vector<CK_OBJECT_HANDLE> found;
    CK_OBJECT_HANDLE batch[4];
    CK_ULONG n = 0;
    do
    {
        ASSERT_CKR_OK(p11()->C_FindObjects(s_, batch, 4, &n));
        found.insert(found.end(), batch, batch + n);
    } while (n > 0);
    EXPECT_CKR_OK(p11()->C_FindObjectsFinal(s_));
    ASSERT_EQ(1u, found.size()) << "exactly the generated key matches its unique label";
    EXPECT_EQ(key, found[0]);
}

// ---------------------------------------------------------------------------
// Session-object lifetime (the C_CloseSession rule: a session object is
// destroyed when the session that created it closes; a token object outlives it)
// ---------------------------------------------------------------------------

TEST_F(aes_keygen, session_object_dies_with_its_session)
{
    CK_SESSION_HANDLE other = 0;
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &other)
    );
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(gen_aes_key(other, 32, CK_TRUE, CK_TRUE, "ephemeral", &key));
    CK_ULONG vlen = 0;
    ASSERT_CKR_OK(get_attr(s_, key, CKA_VALUE_LEN, &vlen)) << "visible from a sibling session";
    ASSERT_CKR_OK(p11()->C_CloseSession(other));
    EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID, get_attr(s_, key, CKA_VALUE_LEN, &vlen));
    CK_BYTE iv[kAesBlock] = { 0 };
    CK_MECHANISM cbc = { CKM_AES_CBC, iv, sizeof(iv) };
    EXPECT_CKR(CKR_KEY_HANDLE_INVALID, p11()->C_EncryptInit(s_, &cbc, key));
}

TEST_F(aes_keygen, data_object_dies_with_its_session_too)
{
    CK_SESSION_HANDLE other = 0;
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &other)
    );
    CK_BYTE payload[4] = { 1, 2, 3, 4 };
    CK_ATTRIBUTE tmpl[] = { { CKA_VALUE, payload, sizeof(payload) } };
    CK_OBJECT_HANDLE obj = 0;
    ASSERT_CKR_OK(p11()->C_CreateObject(other, tmpl, 1, &obj));
    ASSERT_CKR_OK(p11()->C_CloseSession(other));
    CK_BYTE back[4];
    CK_ATTRIBUTE read = { CKA_VALUE, back, sizeof(back) };
    EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID, p11()->C_GetAttributeValue(s_, obj, &read, 1));
}

TEST_F(aes_keygen, token_object_survives_its_session)
{
    CK_SESSION_HANDLE other = 0;
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &other)
    );
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(keygen_with(other, { CKA_TOKEN, &g_true, sizeof(g_true) }, &key));
    ASSERT_CKR_OK(p11()->C_CloseSession(other));
    CK_ULONG vlen = 0;
    EXPECT_CKR_OK(get_attr(s_, key, CKA_VALUE_LEN, &vlen));
    EXPECT_EQ(32u, vlen);
    // Leave the token store as we found it.
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, key));
}

TEST_F(aes_keygen, destroying_from_a_sibling_then_closing_the_owner_is_clean)
{
    CK_SESSION_HANDLE other = 0;
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &other)
    );
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(gen_aes_key(other, 32, CK_TRUE, CK_TRUE, "shared", &key));
    ASSERT_CKR_OK(p11()->C_DestroyObject(s_, key)) << "any session of the token may destroy it";

    // This session's own key predates the close, so it is the thing the
    // owner's teardown could damage. (That the owner also forgot the
    // already-destroyed handle is not observable through the ABI: handles are
    // never reused, so a missing disown would only be an ignored error.)
    CK_OBJECT_HANDLE mine = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 16, CK_TRUE, CK_TRUE, "mine", &mine));
    EXPECT_CKR_OK(p11()->C_CloseSession(other));
    CK_ULONG vlen = 0;
    EXPECT_CKR_OK(get_attr(s_, mine, CKA_VALUE_LEN, &vlen));
    CK_BYTE iv[kAesBlock] = { 0 };
    CK_MECHANISM cbc = { CKM_AES_CBC, iv, sizeof(iv) };
    EXPECT_CKR_OK(p11()->C_EncryptInit(s_, &cbc, mine)) << "and is still usable";
}

TEST_F(aes_keygen, close_all_sessions_destroys_session_objects)
{
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "doomed-by-close-all", &key));
    ASSERT_CKR_OK(p11()->C_CloseAllSessions(kSlot));
    s_ = 0; /* gone; the fixture has nothing left to tear down */
    // A fresh session sees neither the object nor the login.
    CK_SESSION_HANDLE fresh = 0;
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &fresh)
    );
    CK_SESSION_INFO info{};
    ASSERT_CKR_OK(p11()->C_GetSessionInfo(fresh, &info));
    EXPECT_EQ(static_cast<CK_STATE>(CKS_RW_PUBLIC_SESSION), info.state) << "the login went too";
    // The key is public (gen_aes_key sets no CKA_PRIVATE), so this verdict is
    // "destroyed", not "hidden by the login gate".
    CK_ULONG vlen = 0;
    EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID, get_attr(fresh, key, CKA_VALUE_LEN, &vlen));
    EXPECT_CKR_OK(p11()->C_CloseSession(fresh));
}

TEST_F(aes_keygen, create_object_validates_cka_token)
{
    // The framework settles CKA_TOKEN before the store sees the template: a
    // wrongly sized value is invalid rather than silently a session object
    // (the backends read the raw bytes more loosely).
    CK_BYTE payload[4] = { 1, 2, 3, 4 };
    CK_ULONG wide_true = 1;
    CK_ATTRIBUTE bad[] = { { CKA_VALUE, payload, sizeof(payload) },
                           { CKA_TOKEN, &wide_true, sizeof(wide_true) } };
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    EXPECT_CKR(CKR_ATTRIBUTE_VALUE_INVALID, p11()->C_CreateObject(s_, bad, 2, &obj));
    EXPECT_EQ(CK_INVALID_HANDLE, obj) << "nothing was created";
}

TEST_F(aes_keygen, create_object_refuses_a_token_object_on_a_read_only_session)
{
    CK_SESSION_HANDLE ro = 0;
    ASSERT_CKR_OK(p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &ro));
    CK_BYTE payload[4] = { 1, 2, 3, 4 };
    CK_ATTRIBUTE tmpl[] = { { CKA_VALUE, payload, sizeof(payload) },
                            { CKA_TOKEN, &g_true, sizeof(g_true) } };
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    EXPECT_CKR(CKR_SESSION_READ_ONLY, p11()->C_CreateObject(ro, tmpl, 2, &obj));
    // A session object is fine there, as in C_GenerateKey.
    CK_ATTRIBUTE session_tmpl[] = { { CKA_VALUE, payload, sizeof(payload) },
                                    { CKA_TOKEN, &g_false, sizeof(g_false) } };
    EXPECT_CKR_OK(p11()->C_CreateObject(ro, session_tmpl, 2, &obj));
    EXPECT_CKR_OK(p11()->C_CloseSession(ro));
}

TEST_F(aes_keygen, destroyed_key_is_gone)
{
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "doomed", &key));
    ASSERT_CKR_OK(p11()->C_DestroyObject(s_, key));
    CK_ULONG vlen = 0;
    EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID, get_attr(s_, key, CKA_VALUE_LEN, &vlen));
    CK_BYTE iv[kAesBlock] = { 0 };
    CK_MECHANISM cbc = { CKM_AES_CBC, iv, sizeof(iv) };
    EXPECT_CKR(CKR_KEY_HANDLE_INVALID, p11()->C_EncryptInit(s_, &cbc, key));
}
