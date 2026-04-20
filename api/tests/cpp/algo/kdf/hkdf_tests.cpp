// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "algo/aes/helpers.hpp"
#include "handle/part_list_handle.hpp"
#include "utils/auto_key.hpp"
#include "utils/shared_secret.hpp"
#include "utils/kdf_derive.hpp"

static const std::vector<azihsm_algo_id> &supported_hkdf_hash_algos()
{
    static const std::vector<azihsm_algo_id> algos = {
        AZIHSM_ALGO_ID_HMAC_SHA1,
        AZIHSM_ALGO_ID_HMAC_SHA256,
        AZIHSM_ALGO_ID_HMAC_SHA384,
        AZIHSM_ALGO_ID_HMAC_SHA512,
    };
    return algos;
}

static const uint32_t AES_KEY_SIZES[] = { 128, 192, 256 };

// Derives matching ECDH shared secrets for two parties on the given curve.
// Both output handles are managed by auto_key for RAII cleanup.
static void derive_ecdh_shared_secrets(
    azihsm_handle session,
    azihsm_ecc_curve curve,
    auto_key &shared_secret_a,
    auto_key &shared_secret_b
)
{
    EcdhKeyPairSet keys;
    ASSERT_EQ(keys.generate(session, curve), AZIHSM_STATUS_SUCCESS);

    ASSERT_EQ(
        derive_shared_secret_via_ecdh(
            session,
            keys.priv_key_a.get(),
            keys.pub_key_b.get(),
            curve,
            shared_secret_a.handle
        ),
        AZIHSM_STATUS_SUCCESS
    );

    ASSERT_EQ(
        derive_shared_secret_via_ecdh(
            session,
            keys.priv_key_b.get(),
            keys.pub_key_a.get(),
            curve,
            shared_secret_b.handle
        ),
        AZIHSM_STATUS_SUCCESS
    );
}

// Derives an AES key from a shared secret using HKDF, then validates kind and bits.
static void derive_aes_key_from_shared_secret(
    azihsm_handle session,
    azihsm_algo *hkdf_algo,
    azihsm_handle shared_secret,
    uint32_t bits,
    auto_key &out_key
)
{
    azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
    azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES;
    uint8_t can_encrypt = 1;
    uint8_t can_decrypt = 1;

    std::vector<azihsm_key_prop> props;
    props.push_back({ .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) }
    );
    props.push_back({ .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) });
    props.push_back({ .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) });
    props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) }
    );
    props.push_back(
        { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &can_decrypt, .len = sizeof(can_decrypt) }
    );

    azihsm_key_prop_list prop_list = { .props = props.data(),
                                       .count = static_cast<uint32_t>(props.size()) };

    auto err = azihsm_key_derive(session, hkdf_algo, shared_secret, &prop_list, &out_key.handle);
    ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

    // Validate kind
    azihsm_key_kind actual_kind{};
    azihsm_key_prop kind_prop = { .id = AZIHSM_KEY_PROP_ID_KIND,
                                  .val = &actual_kind,
                                  .len = sizeof(actual_kind) };
    ASSERT_EQ(azihsm_key_get_prop(out_key.get(), &kind_prop), AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(actual_kind, AZIHSM_KEY_KIND_AES);

    // Validate bit length
    uint32_t actual_bits = 0;
    azihsm_key_prop bits_prop = { .id = AZIHSM_KEY_PROP_ID_BIT_LEN,
                                  .val = &actual_bits,
                                  .len = sizeof(actual_bits) };
    ASSERT_EQ(azihsm_key_get_prop(out_key.get(), &bits_prop), AZIHSM_STATUS_SUCCESS);
    ASSERT_EQ(actual_bits, bits);
}

// Verifies AES-CBC-PAD encrypt/decrypt roundtrip: encrypt with enc_key, decrypt with dec_key,
// check plaintext matches.
static void assert_aes_cbc_roundtrip(
    azihsm_handle enc_key,
    azihsm_handle dec_key,
    const uint8_t *plaintext,
    size_t plaintext_len
)
{
    // Build AES-CBC-PAD algo with a random-ish IV (using zeros here for simplicity).
    azihsm_algo_aes_cbc_params cbc_params{};
    std::memset(cbc_params.iv, 0, sizeof(cbc_params.iv));
    // Put a distinguishing byte so the IV isn't all-zero (mirrors Rust's test_iv behavior).
    cbc_params.iv[0] = 0xAB;

    azihsm_algo enc_algo = { .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
                             .params = &cbc_params,
                             .len = sizeof(cbc_params) };

    // Encrypt
    std::vector<uint8_t> ciphertext;
    ASSERT_EQ(
        single_shot_crypt(
            CryptOperation::Encrypt,
            enc_key,
            &enc_algo,
            plaintext,
            plaintext_len,
            ciphertext
        ),
        AZIHSM_STATUS_SUCCESS
    );

    // Reset IV for decryption
    azihsm_algo_aes_cbc_params dec_cbc_params{};
    std::memset(dec_cbc_params.iv, 0, sizeof(dec_cbc_params.iv));
    dec_cbc_params.iv[0] = 0xAB;

    azihsm_algo dec_algo = { .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
                             .params = &dec_cbc_params,
                             .len = sizeof(dec_cbc_params) };

    // Decrypt
    std::vector<uint8_t> decrypted;
    ASSERT_EQ(
        single_shot_crypt(
            CryptOperation::Decrypt,
            dec_key,
            &dec_algo,
            ciphertext.data(),
            ciphertext.size(),
            decrypted
        ),
        AZIHSM_STATUS_SUCCESS
    );

    ASSERT_EQ(decrypted.size(), plaintext_len);
    if (plaintext_len > 0)
    {
        ASSERT_EQ(std::memcmp(decrypted.data(), plaintext, plaintext_len), 0)
            << "AES-CBC roundtrip mismatch";
    }
}

// Builds an azihsm_algo for HKDF with the given HMAC algo ID and optional salt/info.
static void build_hkdf_algo(
    azihsm_algo_hkdf_params &hkdf_params,
    azihsm_algo &hkdf_algo,
    azihsm_algo_id hmac_algo_id,
    azihsm_buffer *salt,
    azihsm_buffer *info
)
{
    hkdf_params.hmac_algo_id = hmac_algo_id;
    hkdf_params.salt = salt;
    hkdf_params.info = info;

    hkdf_algo.id = AZIHSM_ALGO_ID_HKDF_DERIVE;
    hkdf_algo.params = &hkdf_params;
    hkdf_algo.len = sizeof(hkdf_params);
}

// Runs the full HKDF matrix test for a given curve:
//   1. Iterates hash algorithms × AES key sizes with no salt/info.
//   2. Tests salt+info derivation with SHA-256/AES-256.
//   3. Tests mismatched info between parties (negative).
static void run_hkdf_matrix_for_curve(azihsm_handle session, azihsm_ecc_curve curve)
{
    auto_key shared_secret_a;
    auto_key shared_secret_b;
    derive_ecdh_shared_secrets(session, curve, shared_secret_a, shared_secret_b);

    // Part 1: hash algo × AES key size matrix, no salt/info
    for (const auto &hash : supported_hkdf_hash_algos())
    {
        for (uint32_t bits : AES_KEY_SIZES)
        {
            SCOPED_TRACE(
                std::string("hash=") + get_hmac_algo_name(hash) + " aes_bits=" + std::to_string(bits)
            );

            azihsm_algo_hkdf_params hkdf_params{};
            azihsm_algo hkdf_algo{};
            build_hkdf_algo(hkdf_params, hkdf_algo, hash, nullptr, nullptr);

            auto_key derived_key_a;
            derive_aes_key_from_shared_secret(
                session,
                &hkdf_algo,
                shared_secret_a.get(),
                bits,
                derived_key_a
            );

            auto_key derived_key_b;
            derive_aes_key_from_shared_secret(
                session,
                &hkdf_algo,
                shared_secret_b.get(),
                bits,
                derived_key_b
            );

            std::string pt_str = std::string("HKDF hash=") + get_hmac_algo_name(hash)
                                 + " aes_bits=" + std::to_string(bits);
            assert_aes_cbc_roundtrip(
                derived_key_a.get(),
                derived_key_b.get(),
                reinterpret_cast<const uint8_t *>(pt_str.data()),
                pt_str.size()
            );
        }
    }

    // Part 2: salt + info should also work
    {
        const char *salt_str = "hkdf-salt";
        const char *info_str = "hkdf-info";
        azihsm_buffer salt_buf = { .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(salt_str)),
                                   .len = static_cast<uint32_t>(std::strlen(salt_str)) };
        azihsm_buffer info_buf = { .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(info_str)),
                                   .len = static_cast<uint32_t>(std::strlen(info_str)) };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, AZIHSM_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key derived_key_a;
        derive_aes_key_from_shared_secret(
            session,
            &hkdf_algo,
            shared_secret_a.get(),
            256,
            derived_key_a
        );

        auto_key derived_key_b;
        derive_aes_key_from_shared_secret(
            session,
            &hkdf_algo,
            shared_secret_b.get(),
            256,
            derived_key_b
        );

        const char *rt_msg = "HKDF with salt+info derived key roundtrip";
        assert_aes_cbc_roundtrip(
            derived_key_a.get(),
            derived_key_b.get(),
            reinterpret_cast<const uint8_t *>(rt_msg),
            std::strlen(rt_msg)
        );
    }

    // Part 3: different info between parties ⇒ keys should not match
    {
        const char *salt_str = "hkdf-salt";
        const char *info_a_str = "hkdf-info-a";
        const char *info_b_str = "hkdf-info-b";

        azihsm_buffer salt_buf = { .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(salt_str)),
                                   .len = static_cast<uint32_t>(std::strlen(salt_str)) };
        azihsm_buffer info_a_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(info_a_str)),
            .len = static_cast<uint32_t>(std::strlen(info_a_str))
        };
        azihsm_buffer info_b_buf = {
            .ptr = reinterpret_cast<uint8_t *>(const_cast<char *>(info_b_str)),
            .len = static_cast<uint32_t>(std::strlen(info_b_str))
        };

        azihsm_algo_hkdf_params hkdf_params_a{};
        azihsm_algo hkdf_algo_a{};
        build_hkdf_algo(
            hkdf_params_a,
            hkdf_algo_a,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_a_buf
        );

        azihsm_algo_hkdf_params hkdf_params_b{};
        azihsm_algo hkdf_algo_b{};
        build_hkdf_algo(
            hkdf_params_b,
            hkdf_algo_b,
            AZIHSM_ALGO_ID_HMAC_SHA256,
            &salt_buf,
            &info_b_buf
        );

        auto_key derived_key_a;
        derive_aes_key_from_shared_secret(
            session,
            &hkdf_algo_a,
            shared_secret_a.get(),
            256,
            derived_key_a
        );

        auto_key derived_key_b;
        derive_aes_key_from_shared_secret(
            session,
            &hkdf_algo_b,
            shared_secret_b.get(),
            256,
            derived_key_b
        );

        // Encrypt with key_a, attempt decrypt with key_b; if decryption succeeds the plaintext
        // must differ.
        uint8_t iv[16] = { 0 };
        azihsm_algo_aes_cbc_params enc_params{};
        std::memcpy(enc_params.iv, iv, sizeof(iv));
        azihsm_algo enc_algo = { .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
                                 .params = &enc_params,
                                 .len = sizeof(enc_params) };

        const char *mismatch_msg = "HKDF salt/info mismatch should fail";
        std::vector<uint8_t> ciphertext;
        ASSERT_EQ(
            single_shot_crypt(
                CryptOperation::Encrypt,
                derived_key_a.get(),
                &enc_algo,
                reinterpret_cast<const uint8_t *>(mismatch_msg),
                std::strlen(mismatch_msg),
                ciphertext
            ),
            AZIHSM_STATUS_SUCCESS
        );

        azihsm_algo_aes_cbc_params dec_params{};
        std::memcpy(dec_params.iv, iv, sizeof(iv));
        azihsm_algo dec_algo = { .id = AZIHSM_ALGO_ID_AES_CBC_PAD,
                                 .params = &dec_params,
                                 .len = sizeof(dec_params) };

        std::vector<uint8_t> decrypted;
        auto dec_err = single_shot_crypt(
            CryptOperation::Decrypt,
            derived_key_b.get(),
            &dec_algo,
            ciphertext.data(),
            ciphertext.size(),
            decrypted
        );

        if (dec_err == AZIHSM_STATUS_SUCCESS)
        {
            // If decryption succeeded despite key mismatch, the plaintext must differ.
            size_t msg_len = std::strlen(mismatch_msg);
            bool content_matches = (decrypted.size() == msg_len)
                                   && (std::memcmp(decrypted.data(), mismatch_msg, msg_len) == 0);
            ASSERT_FALSE(content_matches) << "Mismatched info should not produce matching plaintext";
        }
    }
}

// ============================================================
// Test fixture
// ============================================================

class azihsm_hkdf : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};
};

// ============================================================
// Test cases
// ============================================================

TEST_F(azihsm_hkdf, hkdf_matrix_p256)
{
    part_list_.for_each_session(
        [](azihsm_handle session) { run_hkdf_matrix_for_curve(session, AZIHSM_ECC_CURVE_P256); }
    );
}

TEST_F(azihsm_hkdf, hkdf_matrix_p384)
{
    part_list_.for_each_session(
        [](azihsm_handle session) { run_hkdf_matrix_for_curve(session, AZIHSM_ECC_CURVE_P384); }
    );
}

TEST_F(azihsm_hkdf, hkdf_matrix_p521)
{
    part_list_.for_each_session(
        [](azihsm_handle session) { run_hkdf_matrix_for_curve(session, AZIHSM_ECC_CURVE_P521); }
    );
}

TEST_F(azihsm_hkdf, hkdf_derive_aes_gcm_key_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, AZIHSM_ALGO_ID_HMAC_SHA256, nullptr, nullptr);

        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES_GCM;
        uint32_t bits = 256;
        uint8_t can_encrypt = 1;
        uint8_t can_decrypt = 1;

        std::vector<azihsm_key_prop> props;
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &can_decrypt, .len = sizeof(can_decrypt) }
        );

        azihsm_key_prop_list prop_list = { .props = props.data(),
                                           .count = static_cast<uint32_t>(props.size()) };

        // AesGcm is not in GenericSecretKey::check_key_kind, so validate_props
        // (called inside HsmKeyManager::derive_key) rejects it with InvalidKeyProps.
        azihsm_handle derived_handle = 0;
        auto err =
            azihsm_key_derive(session, &hkdf_algo, secret_a.get(), &prop_list, &derived_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(derived_handle, 0u);
    });
}

TEST_F(azihsm_hkdf, hkdf_derive_unsupported_key_kind_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, AZIHSM_ALGO_ID_HMAC_SHA256, nullptr, nullptr);

        // SharedSecret passes GenericSecretKey::validate_props but is not a valid
        // HKDF output key type in the DDI TryFrom<&HsmKeyProps> for DdiKeyType
        // (api/lib/src/ddi/hkdf.rs:101-117), which returns InvalidArgument.
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_SHARED_SECRET;
        uint32_t bits = 256;
        uint8_t can_derive = 1;

        std::vector<azihsm_key_prop> props;
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_DERIVE, .val = &can_derive, .len = sizeof(can_derive) }
        );

        azihsm_key_prop_list prop_list = { .props = props.data(),
                                           .count = static_cast<uint32_t>(props.size()) };

        azihsm_handle derived_handle = 0;
        auto err =
            azihsm_key_derive(session, &hkdf_algo, secret_a.get(), &prop_list, &derived_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(derived_handle, 0u);
    });
}

TEST_F(azihsm_hkdf, hkdf_derive_invalid_hmac_algo_id_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        // Use an algo ID that is not a valid HMAC algorithm to trigger the default branch
        // of the match on hmac_algo_id at kdf.rs:121
        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, AZIHSM_ALGO_ID_SHA256, nullptr, nullptr);

        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES;
        uint32_t bits = 256;
        uint8_t can_encrypt = 1;
        uint8_t can_decrypt = 1;

        std::vector<azihsm_key_prop> props;
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &can_decrypt, .len = sizeof(can_decrypt) }
        );

        azihsm_key_prop_list prop_list = { .props = props.data(),
                                           .count = static_cast<uint32_t>(props.size()) };

        azihsm_handle derived_handle = 0;
        auto err =
            azihsm_key_derive(session, &hkdf_algo, secret_a.get(), &prop_list, &derived_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_ARGUMENT);
        ASSERT_EQ(derived_handle, 0u);
    });
}

TEST_F(azihsm_hkdf, hkdf_derive_zero_bit_len_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, AZIHSM_ALGO_ID_HMAC_SHA256, nullptr, nullptr);

        // Use bits=0 to cause HsmGenericSecretKey::validate_props (called inside
        // HsmKeyManager::derive_key at kdf.rs:154) to fail.
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES;
        uint32_t bits = 0;
        uint8_t can_encrypt = 1;
        uint8_t can_decrypt = 1;

        std::vector<azihsm_key_prop> props;
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) }
        );
        props.push_back(
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &can_decrypt, .len = sizeof(can_decrypt) }
        );

        azihsm_key_prop_list prop_list = { .props = props.data(),
                                           .count = static_cast<uint32_t>(props.size()) };

        azihsm_handle derived_handle = 0;
        auto err =
            azihsm_key_derive(session, &hkdf_algo, secret_a.get(), &prop_list, &derived_handle);
        ASSERT_EQ(err, AZIHSM_STATUS_INVALID_KEY_PROPS);
        ASSERT_EQ(derived_handle, 0u);
    });
}

TEST_F(azihsm_hkdf, hkdf_empty_salt_info_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        auto_key secret_a;
        auto_key secret_b;
        derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

        // Empty (zero-length) salt and info buffers.
        azihsm_buffer salt_buf = { .ptr = nullptr, .len = 0 };
        azihsm_buffer info_buf = { .ptr = nullptr, .len = 0 };

        azihsm_algo_hkdf_params hkdf_params{};
        azihsm_algo hkdf_algo{};
        build_hkdf_algo(hkdf_params, hkdf_algo, AZIHSM_ALGO_ID_HMAC_SHA256, &salt_buf, &info_buf);

        auto_key key_a;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_a.get(), 256, key_a);

        auto_key key_b;
        derive_aes_key_from_shared_secret(session, &hkdf_algo, secret_b.get(), 256, key_b);

        const char *msg = "empty salt info";
        assert_aes_cbc_roundtrip(
            key_a.get(),
            key_b.get(),
            reinterpret_cast<const uint8_t *>(msg),
            std::strlen(msg)
        );
    });
}
