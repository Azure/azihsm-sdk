// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file attr_tests.cpp
///
/// C_SetAttributeValue and C_GetObjectSize through the module ABI: argument
/// and handle precedence, the read-only-session and CKA_MODIFIABLE gates, the
/// all-or-nothing template rule, and on a generated AES key the latches that
/// keep it sensitive and unextractable plus a usage flag that really changes
/// what C_EncryptInit allows. The full verdict matrix of the policy is
/// unit-tested in tests/attr_policy_test.c; here a representative row per
/// verdict proves the wiring.

#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"

namespace
{

CK_BBOOL g_false = CK_FALSE;
CK_OBJECT_CLASS g_data = CKO_DATA;
CK_OBJECT_CLASS g_public_key = CKO_PUBLIC_KEY;
CK_BYTE g_value[] = { 0xDE, 0xAD, 0xBE, 0xEF };

/// A public data object; `token` and `modifiable` as asked.
CK_RV make_data(
    CK_SESSION_HANDLE s,
    const char *label,
    CK_BBOOL token,
    CK_BBOOL modifiable,
    CK_OBJECT_HANDLE *out
)
{
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &g_data, sizeof(g_data) },
        { CKA_TOKEN, &token, sizeof(token) },
        { CKA_PRIVATE, &g_false, sizeof(g_false) },
        { CKA_MODIFIABLE, &modifiable, sizeof(modifiable) },
        { CKA_VALUE, g_value, sizeof(g_value) },
        { CKA_LABEL, const_cast<char *>(label), static_cast<CK_ULONG>(std::strlen(label)) },
    };
    return p11()->C_CreateObject(s, tmpl, sizeof(tmpl) / sizeof(tmpl[0]), out);
}

std::string read_label(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h)
{
    char buf[64] = {};
    CK_ATTRIBUTE a = { CKA_LABEL, buf, sizeof(buf) };
    if (p11()->C_GetAttributeValue(s, h, &a, 1) != CKR_OK)
    {
        return "<unreadable>";
    }
    return std::string(buf, a.ulValueLen);
}

CK_RV set_label(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, const char *label)
{
    CK_ATTRIBUTE a = { CKA_LABEL,
                       const_cast<char *>(label),
                       static_cast<CK_ULONG>(std::strlen(label)) };
    return p11()->C_SetAttributeValue(s, h, &a, 1);
}

CK_RV set_bool(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE t, CK_BBOOL v)
{
    CK_ATTRIBUTE a = { t, &v, sizeof(v) };
    return p11()->C_SetAttributeValue(s, h, &a, 1);
}

} // namespace

// ---------------------------------------------------------------------------
// Data objects, logged out
// ---------------------------------------------------------------------------

class object_attrs : public PublicSession
{
};

TEST_F(object_attrs, set_label_reads_back)
{
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(make_data(s_, "old", CK_FALSE, CK_TRUE, &h));
    EXPECT_CKR_OK(set_label(s_, h, "renamed"));
    EXPECT_EQ("renamed", read_label(s_, h));
}

TEST_F(object_attrs, set_argument_and_handle_errors)
{
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(make_data(s_, "args", CK_FALSE, CK_TRUE, &h));
    CK_ATTRIBUTE a = { CKA_LABEL, const_cast<char *>("x"), 1 };
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, p11()->C_SetAttributeValue(kInvalidSession, h, &a, 1));
    EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID, p11()->C_SetAttributeValue(s_, kInvalidObject, &a, 1));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_SetAttributeValue(s_, h, nullptr, 1));
    EXPECT_CKR_OK(p11()->C_SetAttributeValue(s_, h, nullptr, 0));
    EXPECT_CKR(
        CKR_OBJECT_HANDLE_INVALID,
        p11()->C_SetAttributeValue(s_, kInvalidObject, nullptr, 0)
    );
}

TEST_F(object_attrs, fixed_attributes_are_read_only)
{
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(make_data(s_, "fixed", CK_FALSE, CK_TRUE, &h));
    CK_ATTRIBUTE cls = { CKA_CLASS, &g_public_key, sizeof(g_public_key) };
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, p11()->C_SetAttributeValue(s_, h, &cls, 1));
    CK_ATTRIBUTE value = { CKA_VALUE, g_value, sizeof(g_value) };
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, p11()->C_SetAttributeValue(s_, h, &value, 1));
    // CKA_TOKEN / CKA_PRIVATE change only through C_CopyObject.
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, set_bool(s_, h, CKA_TOKEN, CK_TRUE));
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, set_bool(s_, h, CKA_PRIVATE, CK_TRUE));
    // A key attribute a data object does not carry.
    EXPECT_CKR(CKR_ATTRIBUTE_TYPE_INVALID, set_bool(s_, h, CKA_ENCRYPT, CK_TRUE));
}

TEST_F(object_attrs, refused_template_changes_nothing)
{
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(make_data(s_, "before", CK_FALSE, CK_TRUE, &h));
    CK_ATTRIBUTE tmpl[] = {
        { CKA_LABEL, const_cast<char *>("after"), 5 },
        { CKA_CLASS, &g_public_key, sizeof(g_public_key) },
    };
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, p11()->C_SetAttributeValue(s_, h, tmpl, 2));
    EXPECT_EQ("before", read_label(s_, h));

    CK_ATTRIBUTE dup[] = {
        { CKA_LABEL, const_cast<char *>("one"), 3 },
        { CKA_LABEL, const_cast<char *>("two"), 3 },
    };
    EXPECT_CKR(CKR_TEMPLATE_INCONSISTENT, p11()->C_SetAttributeValue(s_, h, dup, 2));
    EXPECT_EQ("before", read_label(s_, h));
}

TEST_F(object_attrs, unmodifiable_object_is_prohibited)
{
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(make_data(s_, "frozen", CK_FALSE, CK_FALSE, &h));
    EXPECT_CKR(CKR_ACTION_PROHIBITED, set_label(s_, h, "thawed"));
    EXPECT_EQ("frozen", read_label(s_, h));
}

TEST_F(object_attrs, token_object_needs_read_write_session)
{
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(make_data(s_, "tok", CK_TRUE, CK_TRUE, &h));
    CK_SESSION_HANDLE ro = 0;
    ASSERT_CKR_OK(p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &ro));
    EXPECT_CKR(CKR_SESSION_READ_ONLY, set_label(ro, h, "from-ro"));
    EXPECT_CKR_OK(set_label(s_, h, "from-rw"));
    EXPECT_EQ("from-rw", read_label(ro, h));

    // A session object stays modifiable from a read-only session.
    CK_OBJECT_HANDLE sess = 0;
    ASSERT_CKR_OK(make_data(ro, "sess", CK_FALSE, CK_TRUE, &sess));
    EXPECT_CKR_OK(set_label(ro, sess, "sess-renamed"));

    EXPECT_CKR_OK(p11()->C_CloseSession(ro));
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, h));
}

TEST_F(object_attrs, find_sees_the_new_label)
{
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(make_data(s_, "findme-old", CK_FALSE, CK_TRUE, &h));
    ASSERT_CKR_OK(set_label(s_, h, "findme-new"));
    CK_ATTRIBUTE by_label = { CKA_LABEL, const_cast<char *>("findme-new"), 10 };
    ASSERT_CKR_OK(p11()->C_FindObjectsInit(s_, &by_label, 1));
    CK_OBJECT_HANDLE found[4] = {};
    CK_ULONG n = 0;
    EXPECT_CKR_OK(p11()->C_FindObjects(s_, found, 4, &n));
    EXPECT_CKR_OK(p11()->C_FindObjectsFinal(s_));
    ASSERT_EQ(1u, n);
    EXPECT_EQ(h, found[0]);
}

TEST_F(object_attrs, object_size_arguments_and_growth)
{
    CK_OBJECT_HANDLE h = 0;
    ASSERT_CKR_OK(make_data(s_, "abc", CK_FALSE, CK_TRUE, &h));
    CK_ULONG size = 0;
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, p11()->C_GetObjectSize(kInvalidSession, h, &size));
    EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID, p11()->C_GetObjectSize(s_, kInvalidObject, &size));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_GetObjectSize(s_, h, nullptr));

    ASSERT_CKR_OK(p11()->C_GetObjectSize(s_, h, &size));
    EXPECT_GE(size, sizeof(g_value) + 3);
    ASSERT_CKR_OK(set_label(s_, h, "abcdefgh"));
    CK_ULONG grown = 0;
    ASSERT_CKR_OK(p11()->C_GetObjectSize(s_, h, &grown));
    EXPECT_EQ(size + 5, grown);
}

// ---------------------------------------------------------------------------
// Generated AES keys, logged in
// ---------------------------------------------------------------------------

class object_attrs_key : public UserSession
{
};

TEST_F(object_attrs_key, protection_latches_hold)
{
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "latch", &key));
    // Tookan A5a / A5b: no way back to a readable or extractable key.
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, set_bool(s_, key, CKA_SENSITIVE, CK_FALSE));
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, set_bool(s_, key, CKA_EXTRACTABLE, CK_TRUE));
    // Re-asserting the protected state is allowed.
    EXPECT_CKR_OK(set_bool(s_, key, CKA_SENSITIVE, CK_TRUE));
    EXPECT_CKR_OK(set_bool(s_, key, CKA_EXTRACTABLE, CK_FALSE));
    CK_BBOOL sensitive = CK_FALSE;
    CK_BBOOL extractable = CK_TRUE;
    EXPECT_CKR_OK(get_attr(s_, key, CKA_SENSITIVE, &sensitive));
    EXPECT_CKR_OK(get_attr(s_, key, CKA_EXTRACTABLE, &extractable));
    EXPECT_EQ(CK_TRUE, sensitive);
    EXPECT_EQ(CK_FALSE, extractable);

    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, set_bool(s_, key, CKA_LOCAL, CK_FALSE));
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, set_bool(s_, key, CKA_ALWAYS_SENSITIVE, CK_FALSE));
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, set_bool(s_, key, CKA_NEVER_EXTRACTABLE, CK_FALSE));
    CK_ULONG len16 = 16;
    CK_ATTRIBUTE vlen = { CKA_VALUE_LEN, &len16, sizeof(len16) };
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, p11()->C_SetAttributeValue(s_, key, &vlen, 1));
    CK_ATTRIBUTE value = { CKA_VALUE, g_value, sizeof(g_value) };
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, p11()->C_SetAttributeValue(s_, key, &value, 1));
}

TEST_F(object_attrs_key, usage_flag_gates_encrypt_init)
{
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "usage", &key));
    CK_BYTE iv[kAesBlock] = {};
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    std::vector<CK_BYTE> pt(20, 0x42), ct, back;

    ASSERT_CKR_OK(set_bool(s_, key, CKA_ENCRYPT, CK_FALSE));
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_EncryptInit(s_, &mech, key));

    ASSERT_CKR_OK(set_bool(s_, key, CKA_ENCRYPT, CK_TRUE));
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech, key, pt, ct));
    // The masked body survived the attribute rewrite: the key still decrypts.
    ASSERT_CKR_OK(crypt_oneshot(s_, false, &mech, key, ct, back));
    EXPECT_EQ(pt, back);
}

TEST_F(object_attrs_key, key_metadata_is_modifiable)
{
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 16, CK_TRUE, CK_TRUE, "meta", &key));
    CK_BYTE id[] = { 0x01, 0x02, 0x03 };
    CK_DATE start = { { '2', '0', '2', '6' }, { '0', '9' }, { '2', '8' } };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_LABEL, const_cast<char *>("meta-2"), 6 },
        { CKA_ID, id, sizeof(id) },
        { CKA_START_DATE, &start, sizeof(start) },
    };
    ASSERT_CKR_OK(p11()->C_SetAttributeValue(s_, key, tmpl, 3));
    EXPECT_EQ("meta-2", read_label(s_, key));
    CK_BYTE got[8] = {};
    CK_ATTRIBUTE q = { CKA_ID, got, sizeof(got) };
    ASSERT_CKR_OK(p11()->C_GetAttributeValue(s_, key, &q, 1));
    ASSERT_EQ(sizeof(id), q.ulValueLen);
    EXPECT_EQ(0, std::memcmp(id, got, sizeof(id)));

    CK_DATE bad_month = { { '2', '0', '2', '6' }, { '1', '3' }, { '0', '1' } };
    CK_ATTRIBUTE bad_date = { CKA_END_DATE, &bad_month, sizeof(bad_month) };
    EXPECT_CKR(CKR_ATTRIBUTE_VALUE_INVALID, p11()->C_SetAttributeValue(s_, key, &bad_date, 1));

    CK_BBOOL bad_width[2] = { CK_TRUE, CK_TRUE };
    CK_ATTRIBUTE wide = { CKA_DECRYPT, bad_width, sizeof(bad_width) };
    EXPECT_CKR(CKR_ATTRIBUTE_VALUE_INVALID, p11()->C_SetAttributeValue(s_, key, &wide, 1));
}

TEST_F(object_attrs_key, key_size_counts_the_masked_body)
{
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "sz", &key));
    CK_ULONG size = 0;
    ASSERT_CKR_OK(p11()->C_GetObjectSize(s_, key, &size));
    // What C_GenerateKey stores besides the masked blob: class, key type and
    // value length, seven CK_BBOOL usage/protection flags, and the label.
    constexpr CK_ULONG kAttrBytes = sizeof(CK_OBJECT_CLASS) + sizeof(CK_KEY_TYPE) +
                                    sizeof(CK_ULONG) + 7 * sizeof(CK_BBOOL) + (sizeof("sz") - 1);
    EXPECT_GT(size, kAttrBytes);
}
