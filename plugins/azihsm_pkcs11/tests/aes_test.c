// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Functional test for C_GenerateKey (CKM_AES_KEY_GEN) and the one-shot
 * AES-CBC / AES-CBC-PAD C_Encrypt / C_Decrypt paths, driven through the real
 * module ABI: it dlopens the built module (path in argv[1]) and talks to the
 * device behind it, so it needs the mock- or hardware-backed build:
 *
 *   cargo build -p azihsm_pkcs11 --features mock
 *   gcc -I ../include/pkcs11-v3.1 -I ../src aes_test.c -o aes_test -ldl
 *   ./aes_test ../../../target/debug/azihsm_pkcs11.so
 *
 * Covers: keygen template validation (the normaliser's accept/reject table),
 * generated-key attributes and search, encrypt/decrypt round trips for
 * CBC-PAD and raw CBC, the two-call output sizing discipline (probe keeps the
 * operation, too-small keeps it, completion ends it), the operation state
 * machine, usage enforcement, and that logout tears active cipher state down.
 */

#include "azihsm_pkcs11_compat.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;

#define CHECK(cond, msg)                                                                           \
    do                                                                                             \
    {                                                                                              \
        if (cond)                                                                                  \
        {                                                                                          \
            printf("  ok   : %s\n", (msg));                                                        \
        }                                                                                          \
        else                                                                                       \
        {                                                                                          \
            printf("  FAIL : %s\n", (msg));                                                        \
            g_fail = 1;                                                                            \
        }                                                                                          \
    } while (0)

static CK_FUNCTION_LIST_PTR p11;

static CK_BBOOL ck_true = CK_TRUE;
static CK_BBOOL ck_false = CK_FALSE;
static CK_OBJECT_CLASS secret_class = CKO_SECRET_KEY;
static CK_KEY_TYPE aes_type = CKK_AES;

/* Generate an AES key of `bytes` with the given usage; returns the C_GenerateKey
 * result and the handle via *out. */
static CK_RV gen_key(
    CK_SESSION_HANDLE s,
    CK_ULONG bytes,
    CK_BBOOL enc,
    CK_BBOOL dec,
    const char *label,
    CK_OBJECT_HANDLE *out
)
{
    CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &secret_class, sizeof(secret_class) },
        { CKA_KEY_TYPE, &aes_type, sizeof(aes_type) },
        { CKA_VALUE_LEN, &bytes, sizeof(bytes) },
        { CKA_ENCRYPT, &enc, sizeof(enc) },
        { CKA_DECRYPT, &dec, sizeof(dec) },
        { CKA_LABEL, (void *)label, (CK_ULONG)strlen(label) },
    };
    return p11->C_GenerateKey(s, &mech, tmpl, sizeof(tmpl) / sizeof(tmpl[0]), out);
}

/* One-shot encrypt/decrypt with the two-call discipline (probe, then fill).
 * *len must hold the capacity of `out` on entry; it returns the bytes written. */
static CK_RV crypt_oneshot(
    CK_SESSION_HANDLE s,
    int encrypt,
    CK_MECHANISM *mech,
    CK_OBJECT_HANDLE key,
    CK_BYTE *in,
    CK_ULONG in_len,
    CK_BYTE *out,
    CK_ULONG *len
)
{
    CK_RV rv = encrypt ? p11->C_EncryptInit(s, mech, key) : p11->C_DecryptInit(s, mech, key);
    if (rv != CKR_OK)
    {
        return rv;
    }
    CK_ULONG need = 0;
    rv = encrypt ? p11->C_Encrypt(s, in, in_len, NULL, &need)
                 : p11->C_Decrypt(s, in, in_len, NULL, &need);
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (need > *len)
    {
        return CKR_BUFFER_TOO_SMALL;
    }
    *len = need;
    return encrypt ? p11->C_Encrypt(s, in, in_len, out, len)
                   : p11->C_Decrypt(s, in, in_len, out, len);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: %s <module.so>\n", argv[0]);
        return 2;
    }
    void *dl = dlopen(argv[1], RTLD_NOW);
    if (dl == NULL)
    {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 2;
    }
    CK_RV(*get_list)
    (CK_FUNCTION_LIST_PTR_PTR) = (CK_RV(*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(dl, "C_GetFunctionList");
    if (get_list == NULL || get_list(&p11) != CKR_OK)
    {
        fprintf(stderr, "C_GetFunctionList failed\n");
        return 2;
    }

    CHECK(p11->C_Initialize(NULL) == CKR_OK, "C_Initialize");
    CK_SESSION_HANDLE s = 0;
    CHECK(
        p11->C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &s) == CKR_OK,
        "C_OpenSession"
    );

    printf("== before login ==\n");
    CK_OBJECT_HANDLE key = 0;
    CHECK(
        gen_key(s, 32, CK_TRUE, CK_TRUE, "aes-test", &key) == CKR_USER_NOT_LOGGED_IN,
        "C_GenerateKey before C_Login -> CKR_USER_NOT_LOGGED_IN"
    );

    const char *pin = getenv("AZIHSM_PKCS11_TEST_PIN");
    if (pin == NULL)
    {
        pin = "1234";
    }
    CHECK(
        p11->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin)) == CKR_OK,
        "C_Login(USER)"
    );

    printf("== keygen template validation ==\n");
    {
        CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL, 0 };
        CK_ULONG bytes = 32;
        CK_BYTE param = 0;
        CK_MECHANISM bad_param_mech = { CKM_AES_KEY_GEN, &param, 1 };
        CK_ATTRIBUTE ok_tmpl[] = { { CKA_VALUE_LEN, &bytes, sizeof(bytes) } };
        CHECK(
            p11->C_GenerateKey(s, &bad_param_mech, ok_tmpl, 1, &key) == CKR_MECHANISM_PARAM_INVALID,
            "keygen with a mechanism parameter -> CKR_MECHANISM_PARAM_INVALID"
        );
        CK_MECHANISM wrong_mech = { CKM_AES_XTS_KEY_GEN, NULL, 0 };
        CHECK(
            p11->C_GenerateKey(s, &wrong_mech, ok_tmpl, 1, &key) == CKR_MECHANISM_INVALID,
            "CKM_AES_XTS_KEY_GEN (not in this slice) -> CKR_MECHANISM_INVALID"
        );
        CHECK(
            p11->C_GenerateKey(s, &mech, NULL, 0, &key) == CKR_TEMPLATE_INCOMPLETE,
            "keygen without CKA_VALUE_LEN -> CKR_TEMPLATE_INCOMPLETE"
        );
        CK_ULONG bad_bytes = 20;
        CK_ATTRIBUTE bad_len[] = { { CKA_VALUE_LEN, &bad_bytes, sizeof(bad_bytes) } };
        CHECK(
            p11->C_GenerateKey(s, &mech, bad_len, 1, &key) == CKR_ATTRIBUTE_VALUE_INVALID,
            "CKA_VALUE_LEN 20 -> CKR_ATTRIBUTE_VALUE_INVALID"
        );
        CK_ATTRIBUTE extractable[] = { { CKA_VALUE_LEN, &bytes, sizeof(bytes) },
                                       { CKA_EXTRACTABLE, &ck_true, sizeof(ck_true) } };
        CHECK(
            p11->C_GenerateKey(s, &mech, extractable, 2, &key) == CKR_TEMPLATE_INCONSISTENT,
            "CKA_EXTRACTABLE=TRUE -> CKR_TEMPLATE_INCONSISTENT"
        );
        CK_ATTRIBUTE nonsensitive[] = { { CKA_VALUE_LEN, &bytes, sizeof(bytes) },
                                        { CKA_SENSITIVE, &ck_false, sizeof(ck_false) } };
        CHECK(
            p11->C_GenerateKey(s, &mech, nonsensitive, 2, &key) == CKR_TEMPLATE_INCONSISTENT,
            "CKA_SENSITIVE=FALSE -> CKR_TEMPLATE_INCONSISTENT"
        );
        CK_ATTRIBUTE local[] = { { CKA_VALUE_LEN, &bytes, sizeof(bytes) },
                                 { CKA_LOCAL, &ck_true, sizeof(ck_true) } };
        CHECK(
            p11->C_GenerateKey(s, &mech, local, 2, &key) == CKR_ATTRIBUTE_READ_ONLY,
            "CKA_LOCAL in the template -> CKR_ATTRIBUTE_READ_ONLY"
        );
        CK_OBJECT_CLASS data_class = CKO_DATA;
        CK_ATTRIBUTE wrong_class[] = { { CKA_VALUE_LEN, &bytes, sizeof(bytes) },
                                       { CKA_CLASS, &data_class, sizeof(data_class) } };
        CHECK(
            p11->C_GenerateKey(s, &mech, wrong_class, 2, &key) == CKR_TEMPLATE_INCONSISTENT,
            "CKA_CLASS=CKO_DATA -> CKR_TEMPLATE_INCONSISTENT"
        );
        CK_ULONG other_bytes = 16;
        CK_ATTRIBUTE dup[] = { { CKA_VALUE_LEN, &bytes, sizeof(bytes) },
                               { CKA_VALUE_LEN, &other_bytes, sizeof(other_bytes) } };
        CHECK(
            p11->C_GenerateKey(s, &mech, dup, 2, &key) == CKR_TEMPLATE_INCONSISTENT,
            "duplicate CKA_VALUE_LEN -> CKR_TEMPLATE_INCONSISTENT"
        );
    }

    printf("== generate + inspect + find ==\n");
    CHECK(gen_key(s, 32, CK_TRUE, CK_TRUE, "aes-test", &key) == CKR_OK, "generate AES-256");
    CHECK(key != CK_INVALID_HANDLE, "handle is valid");
    {
        CK_OBJECT_CLASS cls = 0;
        CK_KEY_TYPE kt = 0;
        CK_ULONG vlen = 0;
        CK_BBOOL local = CK_FALSE;
        CK_BBOOL sens = CK_FALSE;
        CK_ATTRIBUTE attrs[] = {
            { CKA_CLASS, &cls, sizeof(cls) },       { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { CKA_VALUE_LEN, &vlen, sizeof(vlen) }, { CKA_LOCAL, &local, sizeof(local) },
            { CKA_SENSITIVE, &sens, sizeof(sens) },
        };
        CHECK(p11->C_GetAttributeValue(s, key, attrs, 5) == CKR_OK, "read generated attributes");
        CHECK(
            cls == CKO_SECRET_KEY && kt == CKK_AES && vlen == 32,
            "class/type/value-len are as generated"
        );
        CHECK(local == CK_TRUE && sens == CK_TRUE, "CKA_LOCAL and CKA_SENSITIVE default to TRUE");
        /* A generated key never has a CKA_VALUE host-side (only the masked
         * blob exists), so the store reports the attribute as absent rather
         * than sensitive; either way the material is unreadable. */
        CK_BYTE raw[64];
        CK_ATTRIBUTE value = { CKA_VALUE, raw, sizeof(raw) };
        CHECK(
            p11->C_GetAttributeValue(s, key, &value, 1) == CKR_ATTRIBUTE_TYPE_INVALID &&
                value.ulValueLen == CK_UNAVAILABLE_INFORMATION,
            "CKA_VALUE readback reveals nothing"
        );
    }
    {
        CK_ATTRIBUTE find_tmpl[] = { { CKA_CLASS, &secret_class, sizeof(secret_class) },
                                     { CKA_KEY_TYPE, &aes_type, sizeof(aes_type) } };
        CK_OBJECT_HANDLE found[8];
        CK_ULONG n = 0;
        CHECK(p11->C_FindObjectsInit(s, find_tmpl, 2) == CKR_OK, "C_FindObjectsInit");
        CHECK(
            p11->C_FindObjects(s, found, sizeof(found) / sizeof(found[0]), &n) == CKR_OK && n >= 1,
            "C_FindObjects finds keys"
        );
        int seen = 0;
        for (CK_ULONG i = 0; i < n; i++)
        {
            seen |= (found[i] == key);
        }
        CHECK(seen, "the generated key is among the matches");
        CHECK(p11->C_FindObjectsFinal(s) == CKR_OK, "C_FindObjectsFinal");
    }

    CK_BYTE iv[16];
    memset(iv, 0xA5, sizeof(iv));
    CK_MECHANISM cbc_pad = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    CK_MECHANISM cbc = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_BYTE plain[40];
    for (size_t i = 0; i < sizeof(plain); i++)
    {
        plain[i] = (CK_BYTE)i;
    }

    printf("== CBC-PAD round trip + sizing discipline ==\n");
    CK_BYTE cipher[64];
    CK_ULONG cipher_len = 0;
    {
        CHECK(p11->C_EncryptInit(s, &cbc_pad, key) == CKR_OK, "C_EncryptInit(CBC_PAD)");
        CHECK(
            p11->C_EncryptInit(s, &cbc_pad, key) == CKR_OPERATION_ACTIVE,
            "second C_EncryptInit -> CKR_OPERATION_ACTIVE"
        );
        CK_ULONG need = 0;
        CHECK(
            p11->C_Encrypt(s, plain, sizeof(plain), NULL, &need) == CKR_OK && need == 48,
            "sizing probe reports 48 (40 bytes -> 3 padded blocks)"
        );
        CK_ULONG small = 16;
        CHECK(
            p11->C_Encrypt(s, plain, sizeof(plain), cipher, &small) == CKR_BUFFER_TOO_SMALL &&
                small == 48,
            "too-small buffer -> CKR_BUFFER_TOO_SMALL with the required length"
        );
        cipher_len = sizeof(cipher);
        CHECK(
            p11->C_Encrypt(s, plain, sizeof(plain), cipher, &cipher_len) == CKR_OK &&
                cipher_len == 48,
            "encrypt succeeds after the probe/too-small calls (op stayed alive)"
        );
        CHECK(memcmp(cipher, plain, 16) != 0, "ciphertext differs from plaintext");
        CHECK(
            p11->C_Encrypt(s, plain, sizeof(plain), cipher, &cipher_len) ==
                CKR_OPERATION_NOT_INITIALIZED,
            "one-shot completion terminated the operation"
        );
    }
    {
        CK_BYTE back[64];
        CK_ULONG back_len = sizeof(back);
        CHECK(
            crypt_oneshot(s, 0, &cbc_pad, key, cipher, cipher_len, back, &back_len) == CKR_OK,
            "C_Decrypt(CBC_PAD)"
        );
        CHECK(
            back_len == sizeof(plain) && memcmp(back, plain, sizeof(plain)) == 0,
            "decrypt returns the original plaintext (padding stripped)"
        );
    }

    printf("== CBC-PAD block-aligned input gains a full padding block ==\n");
    {
        /* A 32-byte (2-block) input must produce 48 bytes: PKCS#7 always adds a
         * full padding block when the input is already block-aligned. */
        CK_BYTE ct[64];
        CK_ULONG ct_len = sizeof(ct);
        CHECK(
            crypt_oneshot(s, 1, &cbc_pad, key, plain, 32, ct, &ct_len) == CKR_OK && ct_len == 48,
            "CBC-PAD encrypt of 32 bytes -> 48"
        );
        CK_BYTE back[64];
        CK_ULONG back_len = sizeof(back);
        CHECK(
            crypt_oneshot(s, 0, &cbc_pad, key, ct, ct_len, back, &back_len) == CKR_OK &&
                back_len == 32 && memcmp(back, plain, 32) == 0,
            "CBC-PAD decrypt strips the padding block back to 32"
        );
    }

    printf("== CBC-PAD decrypt of corrupt padding ==\n");
    {
        CK_BYTE ct[64];
        CK_ULONG ct_len = sizeof(ct);
        CHECK(
            crypt_oneshot(s, 1, &cbc_pad, key, plain, sizeof(plain), ct, &ct_len) == CKR_OK,
            "encrypt a message to corrupt"
        );
        ct[ct_len - 1] ^= 0xFF; /* wreck the final (padding) block */
        ct[0] ^= 0xFF;
        CK_BYTE back[64];
        CK_ULONG back_len = sizeof(back);
        CHECK(p11->C_DecryptInit(s, &cbc_pad, key) == CKR_OK, "C_DecryptInit for bad padding");
        CHECK(
            p11->C_Decrypt(s, ct, ct_len, back, &back_len) == CKR_ENCRYPTED_DATA_INVALID,
            "bad PKCS#7 padding -> CKR_ENCRYPTED_DATA_INVALID"
        );
        CK_ULONG need = 0;
        CHECK(
            p11->C_Decrypt(s, ct, ct_len, NULL, &need) == CKR_OPERATION_NOT_INITIALIZED,
            "the padding error terminated the operation"
        );
    }

    printf("== raw CBC round trip + length policy ==\n");
    {
        CK_BYTE out[32];
        CK_ULONG out_len = sizeof(out);
        CHECK(
            crypt_oneshot(s, 1, &cbc, key, plain, 32, out, &out_len) == CKR_OK && out_len == 32,
            "raw CBC encrypt of 32 bytes"
        );
        CK_BYTE back[32];
        CK_ULONG back_len = sizeof(back);
        CHECK(
            crypt_oneshot(s, 0, &cbc, key, out, 32, back, &back_len) == CKR_OK && back_len == 32 &&
                memcmp(back, plain, 32) == 0,
            "raw CBC decrypt round trip"
        );
        CHECK(p11->C_EncryptInit(s, &cbc, key) == CKR_OK, "C_EncryptInit(CBC) for length test");
        CK_ULONG need = 0;
        CHECK(
            p11->C_Encrypt(s, plain, 30, NULL, &need) == CKR_DATA_LEN_RANGE,
            "raw CBC with 30 bytes -> CKR_DATA_LEN_RANGE"
        );
        CHECK(
            p11->C_Encrypt(s, plain, 32, NULL, &need) == CKR_OPERATION_NOT_INITIALIZED,
            "the length error terminated the operation"
        );
        CHECK(p11->C_DecryptInit(s, &cbc_pad, key) == CKR_OK, "C_DecryptInit for length test");
        CHECK(
            p11->C_Decrypt(s, cipher, 20, NULL, &need) == CKR_ENCRYPTED_DATA_LEN_RANGE,
            "decrypt of a 20-byte ciphertext -> CKR_ENCRYPTED_DATA_LEN_RANGE"
        );
    }

    printf("== state machine + argument validation ==\n");
    {
        CK_ULONG need = 0;
        CHECK(
            p11->C_Encrypt(s, plain, 16, NULL, &need) == CKR_OPERATION_NOT_INITIALIZED,
            "C_Encrypt without init -> CKR_OPERATION_NOT_INITIALIZED"
        );
        CK_MECHANISM short_iv = { CKM_AES_CBC_PAD, iv, 12 };
        CHECK(
            p11->C_EncryptInit(s, &short_iv, key) == CKR_MECHANISM_PARAM_INVALID,
            "12-byte IV -> CKR_MECHANISM_PARAM_INVALID"
        );
        CK_MECHANISM gcm = { CKM_AES_GCM, iv, sizeof(iv) };
        CHECK(
            p11->C_EncryptInit(s, &gcm, key) == CKR_MECHANISM_INVALID,
            "CKM_AES_GCM (not in this slice) -> CKR_MECHANISM_INVALID"
        );
        CHECK(
            p11->C_EncryptInit(s, &cbc_pad, 0xDEAD) == CKR_KEY_HANDLE_INVALID,
            "bogus key handle -> CKR_KEY_HANDLE_INVALID"
        );
        CK_BYTE payload[4] = { 1, 2, 3, 4 };
        CK_ATTRIBUTE data_tmpl[] = { { CKA_VALUE, payload, sizeof(payload) } };
        CK_OBJECT_HANDLE data_obj = 0;
        CHECK(p11->C_CreateObject(s, data_tmpl, 1, &data_obj) == CKR_OK, "create a data object");
        CHECK(
            p11->C_EncryptInit(s, &cbc_pad, data_obj) == CKR_KEY_HANDLE_INVALID,
            "data object as key -> CKR_KEY_HANDLE_INVALID"
        );
    }

    printf("== usage enforcement ==\n");
    {
        CK_OBJECT_HANDLE dec_only = 0;
        CHECK(
            gen_key(s, 16, CK_FALSE, CK_TRUE, "aes-dec-only", &dec_only) == CKR_OK,
            "generate a decrypt-only AES-128 key"
        );
        CHECK(
            p11->C_EncryptInit(s, &cbc_pad, dec_only) == CKR_KEY_FUNCTION_NOT_PERMITTED,
            "C_EncryptInit on it -> CKR_KEY_FUNCTION_NOT_PERMITTED"
        );
        /* Raw CBC: any block-aligned ciphertext decrypts (to garbage), so this
         * exercises the permitted direction without tripping over padding. */
        CHECK(p11->C_DecryptInit(s, &cbc, dec_only) == CKR_OK, "C_DecryptInit on it is fine");
        CK_ULONG need = 0;
        CK_BYTE junk[16];
        memset(junk, 0x11, sizeof(junk));
        CHECK(
            p11->C_Decrypt(s, junk, sizeof(junk), NULL, &need) == CKR_OK && need == 16,
            "sizing probe on the decrypt-only key"
        );
        CK_BYTE out[32];
        need = sizeof(out);
        CHECK(
            p11->C_Decrypt(s, junk, sizeof(junk), out, &need) == CKR_OK && need == 16,
            "raw CBC decrypt with the decrypt-only key"
        );

        /* Mirror case: an encrypt-only key must refuse C_DecryptInit. Uses a
         * 192-bit key so the size path is covered too. */
        CK_OBJECT_HANDLE enc_only = 0;
        CHECK(
            gen_key(s, 24, CK_TRUE, CK_FALSE, "aes-enc-only", &enc_only) == CKR_OK,
            "generate an encrypt-only AES-192 key"
        );
        CHECK(
            p11->C_DecryptInit(s, &cbc, enc_only) == CKR_KEY_FUNCTION_NOT_PERMITTED,
            "C_DecryptInit on it -> CKR_KEY_FUNCTION_NOT_PERMITTED"
        );
        CHECK(p11->C_EncryptInit(s, &cbc, enc_only) == CKR_OK, "C_EncryptInit on it is fine");
        need = 0;
        CHECK(
            p11->C_Encrypt(s, plain, 16, NULL, &need) == CKR_OK && need == 16,
            "sizing probe on the encrypt-only key"
        );
        CK_BYTE eout[32];
        CK_ULONG eout_len = sizeof(eout);
        CHECK(
            p11->C_Encrypt(s, plain, 16, eout, &eout_len) == CKR_OK && eout_len == 16,
            "raw CBC encrypt with the encrypt-only key"
        );
    }

    printf("== wrong-key decrypt ==\n");
    {
        CK_OBJECT_HANDLE other = 0;
        CHECK(gen_key(s, 32, CK_TRUE, CK_TRUE, "aes-other", &other) == CKR_OK, "second key");
        CK_BYTE back[64];
        CK_ULONG back_len = sizeof(back);
        CK_RV rv = crypt_oneshot(s, 0, &cbc_pad, other, cipher, cipher_len, back, &back_len);
        CHECK(
            !(rv == CKR_OK && back_len == sizeof(plain) && memcmp(back, plain, sizeof(plain)) == 0),
            "decrypting with the wrong key never yields the plaintext"
        );
    }

    printf("== logout tears cipher state down ==\n");
    {
        CHECK(p11->C_EncryptInit(s, &cbc_pad, key) == CKR_OK, "init an op, then log out");
        CHECK(p11->C_Logout(s) == CKR_OK, "C_Logout");
        CK_ULONG need = 0;
        CHECK(
            p11->C_Encrypt(s, plain, 16, NULL, &need) == CKR_OPERATION_NOT_INITIALIZED,
            "the operation did not survive C_Logout"
        );
        CHECK(
            p11->C_EncryptInit(s, &cbc_pad, key) == CKR_USER_NOT_LOGGED_IN,
            "C_EncryptInit while logged out -> CKR_USER_NOT_LOGGED_IN"
        );
    }

    CHECK(p11->C_CloseSession(s) == CKR_OK, "C_CloseSession");
    CHECK(p11->C_Finalize(NULL) == CKR_OK, "C_Finalize");

    printf(g_fail ? "\naes_test: FAILED\n" : "\naes_test: all checks passed\n");
    return g_fail;
}
