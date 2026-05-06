// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <cstring>
#include <string>

#include "kdf_derive.hpp"
#include "rng.hpp"

const uint32_t AES_KEY_SIZES[] = { 128, 192, 256 };

const char *get_hmac_algo_name(azihsm_algo_id hmac_algo_id)
{
    switch (hmac_algo_id)
    {
    case AZIHSM_ALGO_ID_HMAC_SHA1:
        return "SHA1";
    case AZIHSM_ALGO_ID_HMAC_SHA256:
        return "SHA256";
    case AZIHSM_ALGO_ID_HMAC_SHA384:
        return "SHA384";
    case AZIHSM_ALGO_ID_HMAC_SHA512:
        return "SHA512";
    default:
        return "unknown";
    }
}

// Builds an azihsm_algo for HKDF with the given HMAC algo ID and optional salt/info.
void build_hkdf_algo(
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

// Derives matching ECDH shared secrets for two parties on the given curve.
// Both output handles are managed by auto_key for RAII cleanup.
void derive_ecdh_shared_secrets(
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
void derive_aes_key_from_shared_secret(
    azihsm_handle session,
    azihsm_algo *hkdf_algo,
    azihsm_handle shared_secret,
    uint32_t bits,
    auto_key &out_key
)
{
    key_props props = {};
    props.key_class = AZIHSM_KEY_CLASS_SECRET;
    props.key_kind = AZIHSM_KEY_KIND_AES;
    props.key_size_bits = bits;
    props.encrypt = 1;
    props.decrypt = 1;

    std::vector<azihsm_key_prop> props_vec;
    azihsm_key_prop_list prop_list = build_key_prop_list(props, props_vec);

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
void assert_aes_cbc_roundtrip(
    azihsm_handle enc_key,
    azihsm_handle dec_key,
    const uint8_t *plaintext,
    size_t plaintext_len
)
{
    // Build AES-CBC-PAD algo with a random IV.
    azihsm_algo_aes_cbc_params cbc_params{};
    auto iv = test_iv(sizeof(cbc_params.iv));
    std::memcpy(cbc_params.iv, iv.data(), sizeof(cbc_params.iv));

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

    // Reuse the same IV for decryption
    azihsm_algo_aes_cbc_params dec_cbc_params{};
    std::memcpy(dec_cbc_params.iv, iv.data(), sizeof(dec_cbc_params.iv));

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

// Runs the full HKDF matrix test for a given curve:
//   1. Iterates hash algorithms × AES key sizes with no salt/info.
//   2. Tests salt+info derivation with SHA-256/AES-256.
//   3. Tests mismatched info between parties (negative).
void run_hkdf_matrix_for_curve(azihsm_handle session, azihsm_ecc_curve curve)
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
                std::string("hash=") + get_hmac_algo_name(hash) +
                " aes_bits=" + std::to_string(bits)
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

            std::string pt_str = std::string("HKDF hash=") + get_hmac_algo_name(hash) +
                                 " aes_bits=" + std::to_string(bits);
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
        azihsm_algo_aes_cbc_params enc_params{};
        auto iv = test_iv(sizeof(enc_params.iv));
        std::memcpy(enc_params.iv, iv.data(), iv.size());
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

        // reuse the same IV for decryption
        azihsm_algo_aes_cbc_params dec_params{};
        std::memcpy(dec_params.iv, iv.data(), iv.size());
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
            bool content_matches = (decrypted.size() == msg_len) &&
                                   (std::memcmp(decrypted.data(), mismatch_msg, msg_len) == 0);
            ASSERT_FALSE(content_matches)
                << "Mismatched info should not produce matching plaintext";
        }
    }
}

void hkdf_derive_fails_common(
    azihsm_handle session,
    azihsm_algo_id hmac_algo_id,
    key_props &props,
    azihsm_status expected_status
)
{
    auto_key secret_a;
    auto_key secret_b;
    derive_ecdh_shared_secrets(session, AZIHSM_ECC_CURVE_P256, secret_a, secret_b);

    azihsm_algo_hkdf_params hkdf_params{};
    azihsm_algo hkdf_algo{};
    build_hkdf_algo(hkdf_params, hkdf_algo, hmac_algo_id, nullptr, nullptr);

    std::vector<azihsm_key_prop> prop_vec;

    azihsm_key_prop_list prop_list = build_key_prop_list(props, prop_vec);

    azihsm_handle derived_handle = 0;
    auto err = azihsm_key_derive(session, &hkdf_algo, secret_a.get(), &prop_list, &derived_handle);
    ASSERT_EQ(err, expected_status);
    ASSERT_EQ(derived_handle, 0u);
}
