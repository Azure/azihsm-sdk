// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <array>
#include <azihsm_api.h>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "handle/key_handle.hpp"
#include "handle/part_handle.hpp"
#include "handle/part_list_handle.hpp"
#include "handle/session_handle.hpp"
#include "helpers.hpp"
#include "utils/aes_keygen.hpp"
#include "utils/auto_key.hpp"
#include "utils/rsa_keygen.hpp"

class azihsm_aes_keygen : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Helper function to compare AES XTS key properties
    static void compare_aes_xts_key_properties(
        azihsm_handle original_key,
        azihsm_handle unmasked_key,
        uint32_t expected_bits
    )
    {
        compare_key_properties(original_key, unmasked_key);

        // Validate key kind
        azihsm_key_kind original_kind;
        azihsm_key_prop prop{};
        prop.id = AZIHSM_KEY_PROP_ID_KIND;
        prop.len = sizeof(azihsm_key_kind);

        prop.val = &original_kind;
        azihsm_status err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_kind, AZIHSM_KEY_KIND_AES_XTS);

        // Validate key bit length
        uint32_t original_bits;
        prop.id = AZIHSM_KEY_PROP_ID_BIT_LEN;
        prop.len = sizeof(uint32_t);

        prop.val = &original_bits;
        err = azihsm_key_get_prop(original_key, &prop);
        EXPECT_EQ(err, AZIHSM_STATUS_SUCCESS);
        EXPECT_EQ(original_bits, expected_bits);
    }

    // Helper: compute tweak + units as little-endian u128 addition
    std::array<uint8_t, 16> tweak_after_units(const uint8_t tweak[16], size_t units)
    {
        // Add units to tweak interpreted as a little-endian 128-bit integer
        uint64_t lo = 0;
        uint64_t hi = 0;
        std::memcpy(&lo, tweak, 8);
        std::memcpy(&hi, tweak + 8, 8);

        uint64_t new_lo = lo + static_cast<uint64_t>(units);
        uint64_t carry = (new_lo < lo) ? 1 : 0;
        uint64_t new_hi = hi + carry;

        std::array<uint8_t, 16> out;
        std::memcpy(out.data(), &new_lo, 8);
        std::memcpy(out.data() + 8, &new_hi, 8);
        return out;
    }
};

// ================================
// AES Key Tests
// ================================

/// Test AES key generation for key sizes of 128
TEST_F(azihsm_aes_keygen, session_aes_128_key_generation)
{
    part_list_.for_each_session([](azihsm_handle session) {
        session_aes_key_generation_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            128
        );
    });
}

/// Test AES key generation for key sizes of 192
TEST_F(azihsm_aes_keygen, session_aes_192_key_generation)
{
    part_list_.for_each_session([](azihsm_handle session) {
        session_aes_key_generation_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            192
        );
    });
}

/// Test AES key generation for key sizes of 256
TEST_F(azihsm_aes_keygen, session_aes_256_key_generation)
{
    part_list_.for_each_session([](azihsm_handle session) {
        session_aes_key_generation_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256
        );
    });
}

/// Test AES key unwrapping for key sizes of 128
TEST_F(azihsm_aes_keygen, aes_128_key_unwrap)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_unwrap_common(session, AZIHSM_KEY_KIND_AES, 128);
    });
}

/// Test AES key unwrapping for key sizes of 192
TEST_F(azihsm_aes_keygen, aes_192_key_unwrap)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_unwrap_common(session, AZIHSM_KEY_KIND_AES, 192);
    });
}

/// Test AES key unwrapping for key sizes of 256
TEST_F(azihsm_aes_keygen, aes_256_key_unwrap)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_unwrap_common(session, AZIHSM_KEY_KIND_AES, 256);
    });
}

/// Test AES key unmasking for key sizes of 128
TEST_F(azihsm_aes_keygen, aes_128_key_unmask)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_unmask_common(session, AZIHSM_ALGO_ID_AES_KEY_GEN, AZIHSM_KEY_KIND_AES, 128);
    });
}

/// Test AES key unmasking for key sizes of 192
TEST_F(azihsm_aes_keygen, aes_192_key_unmask)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_unmask_common(session, AZIHSM_ALGO_ID_AES_KEY_GEN, AZIHSM_KEY_KIND_AES, 192);
    });
}

/// Test AES key unmasking for key sizes of 256
TEST_F(azihsm_aes_keygen, aes_256_key_unmask)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_unmask_common(session, AZIHSM_ALGO_ID_AES_KEY_GEN, AZIHSM_KEY_KIND_AES, 256);
    });
}

/// verifies AES key unwrap fails when wrapped blob is corrupted
TEST_F(azihsm_aes_keygen, aes_key_unwrap_corrupted_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_unwrap_corrupted_fails_common(session, AZIHSM_KEY_KIND_AES, 256);
    });
}

/// verifies AES key unmask fails when unmasking with corrupted masked blob
TEST_F(azihsm_aes_keygen, aes_unmask_corrupted_blob_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unmask_corrupted_blob_fails_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256
        );
    });
}

/// verifies AES key unwrap fails when unwrapping with wrong algorithm type
TEST_F(azihsm_aes_keygen, aes_unwrap_wrong_algo_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Use wrong algo ID: AES_CBC is an encryption algo, not a key-unwrap algo
        aes_unwrap_wrong_algo_fails_common(
            session,
            AZIHSM_KEY_KIND_AES,
            256,
            AZIHSM_ALGO_ID_AES_CBC
        );
    });
}

/// verifies AES key unmasking produces a usable key that can encrypt and decrypt,
/// and that the unmasked key is independent of the original key by deleting the
/// original key before using the unmasked key
TEST_F(azihsm_aes_keygen, aes_unmasked_key_independent_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unmasked_key_independent_handle_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256
        );
    });
}

/// verifies AES key unwrap fails when the wrapped blob is truncated
TEST_F(azihsm_aes_keygen, aes_unwrap_truncated_blob_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unwrap_truncated_blob_fails_common(session, AZIHSM_KEY_KIND_AES, 256);
    });
}

/// verifies AES key generation fails when sign flag is set
TEST_F(azihsm_aes_keygen, aes_key_gen_with_sign_flag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256,
            { AZIHSM_KEY_PROP_ID_ENCRYPT, AZIHSM_KEY_PROP_ID_DECRYPT, AZIHSM_KEY_PROP_ID_SIGN }
        );
    });
}

/// verifies AES key generation fails when verify flag is set
TEST_F(azihsm_aes_keygen, aes_key_gen_with_verify_flag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256,
            { AZIHSM_KEY_PROP_ID_ENCRYPT, AZIHSM_KEY_PROP_ID_DECRYPT, AZIHSM_KEY_PROP_ID_VERIFY }
        );
    });
}

/// verifies AES key generation fails when wrap flag is set
TEST_F(azihsm_aes_keygen, aes_key_gen_with_wrap_flag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256,
            { AZIHSM_KEY_PROP_ID_ENCRYPT, AZIHSM_KEY_PROP_ID_DECRYPT, AZIHSM_KEY_PROP_ID_WRAP }
        );
    });
}

/// verifies AES key generation fails when unwrap flag is set
TEST_F(azihsm_aes_keygen, aes_key_gen_with_unwrap_flag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256,
            { AZIHSM_KEY_PROP_ID_ENCRYPT, AZIHSM_KEY_PROP_ID_DECRYPT, AZIHSM_KEY_PROP_ID_UNWRAP }
        );
    });
}

/// verifies AES key generation fails when derive flag is set
TEST_F(azihsm_aes_keygen, aes_key_gen_with_derive_flag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256,
            { AZIHSM_KEY_PROP_ID_ENCRYPT, AZIHSM_KEY_PROP_ID_DECRYPT, AZIHSM_KEY_PROP_ID_DERIVE }
        );
    });
}

/// verifies AES key generation fails when multiple unsupported capabilities are set
/// in properties
TEST_F(azihsm_aes_keygen, aes_key_gen_multiple_invalid_flags_fail)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256,
            { AZIHSM_KEY_PROP_ID_ENCRYPT,
              AZIHSM_KEY_PROP_ID_DECRYPT,
              AZIHSM_KEY_PROP_ID_SIGN,
              AZIHSM_KEY_PROP_ID_WRAP,
              AZIHSM_KEY_PROP_ID_DERIVE }
        );
    });
}

/// verifies AES key generation rejects keys with only unsupported capabilities
TEST_F(azihsm_aes_keygen, aes_key_gen_only_invalid_capabilities)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256,
            { AZIHSM_KEY_PROP_ID_SIGN,
              AZIHSM_KEY_PROP_ID_VERIFY,
              AZIHSM_KEY_PROP_ID_WRAP,
              AZIHSM_KEY_PROP_ID_UNWRAP,
              AZIHSM_KEY_PROP_ID_DERIVE }
        );
    });
}

/// verifies invalid flags are rejected even if encrypt/decrypt permissions are missing
TEST_F(azihsm_aes_keygen, aes_key_gen_invalid_flags_without_crypto_permissions)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256,
            { AZIHSM_KEY_PROP_ID_SIGN, AZIHSM_KEY_PROP_ID_WRAP }
        );
    });
}

/// verifies AES key generation rejects combinations of unsupported capability flags
TEST_F(azihsm_aes_keygen, aes_key_gen_multiple_invalid_capabilities)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_multiple_invalid_capabilities_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256
        );
    });
}

/// verifies AES key generation fails when decrypt permission is missing
TEST_F(azihsm_aes_keygen, aes_key_gen_no_decrypt_flag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256,
            { AZIHSM_KEY_PROP_ID_ENCRYPT }
        );
    });
}

/// verifies AES key generation fails when encrypt permission is missing
TEST_F(azihsm_aes_keygen, aes_key_gen_no_encrypt_flag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256,
            { AZIHSM_KEY_PROP_ID_DECRYPT }
        );
    });
}

/// verifies AES key unwrap fails when properties specify wrong bit length (128) for a 256-bit key
TEST_F(azihsm_aes_keygen, aes_unwrap_bits_mismatch_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unwrap_bits_mismatch_fails_common(session, AZIHSM_KEY_KIND_AES, 256, 128);
    });
}

/// verifies AES unmask fails when unmasking an AES masked blob with the wrong key kind (AES-GCM)
TEST_F(azihsm_aes_keygen, aes_unmask_wrong_kind_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unmask_wrong_kind_fails_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256,
            AZIHSM_KEY_KIND_AES_GCM
        );
    });
}

/// verifies AES-CBC encryption and decryption roundtrip using an unwrapped key
TEST_F(azihsm_aes_keygen, aes_unwrapped_key_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unwrapped_key_roundtrip_common(session, AZIHSM_KEY_KIND_AES, 256);
    });
}

/// verifies AES key generation rejects invalid key sizes and returns appropriate error
TEST_F(azihsm_aes_keygen, aes_key_generation_invalid_sizes_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // AES is only supported for 128, 192, and 256 bits.
        for (uint32_t bits : { 0u, 1u, 127u, 129u, 191u, 193u, 255u, 257u, 384u, 512u, 1024u })
        {
            aes_key_gen_invalid_props_fail_common(
                session,
                AZIHSM_ALGO_ID_AES_KEY_GEN,
                AZIHSM_KEY_KIND_AES,
                bits,
                { AZIHSM_KEY_PROP_ID_ENCRYPT, AZIHSM_KEY_PROP_ID_DECRYPT }
            );
        }
    });
}

/// verifies AES key generation with non-session persistence creates a non-session key
/// and succeeds with correct AZIHSM_KEY_PROP_ID_SESSION property
TEST_F(azihsm_aes_keygen, aes_key_gen_persistent)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_persistent_common(
            session,
            AZIHSM_ALGO_ID_AES_KEY_GEN,
            AZIHSM_KEY_KIND_AES,
            256
        );
    });
}

// ================================
// AES XTS Tests
// ================================

/// verifies AES-XTS 512-bit key generation succeeds with correct properties and capabilities
TEST_F(azihsm_aes_keygen, session_aes_xts_512_key_generation)
{
    part_list_.for_each_session([](azihsm_handle session) {
        session_aes_key_generation_common(
            session,
            AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
            AZIHSM_KEY_KIND_AES_XTS,
            512
        );
    });
}

/// verifies AES-XTS key generation rejects invalid key sizes and returns appropriate error
TEST_F(azihsm_aes_keygen, aes_xts_key_generation_invalid_sizes_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // AES-XTS is only supported for 64-byte keys (512 bits).
        for (uint32_t bits : { 0u, 1u, 128u, 192u, 256u, 384u, 511u, 513u, 1024u })
        {
            aes_key_gen_invalid_props_fail_common(
                session,
                AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
                AZIHSM_KEY_KIND_AES_XTS,
                bits,
                { AZIHSM_KEY_PROP_ID_ENCRYPT, AZIHSM_KEY_PROP_ID_DECRYPT }
            );
        }
    });
}

/// Test AES-XTS key unwrapping
TEST_F(azihsm_aes_keygen, aes_xts_key_unwrap)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_unwrap_common(session, AZIHSM_KEY_KIND_AES_XTS, 512);
    });
}

/// Test AES-XTS key unwrapping, and validate the unwrapped key can be used for encryption
/// and decryption with correct tweak handling. Also validates that the unwrapped key has
/// expected properties and capabilities, and is not local to the session.
TEST_F(azihsm_aes_keygen, aes_xts_key_unwrap_tweak_handling_roundtrip)
{
    part_list_.for_each_session([this](azihsm_handle session) {
        // Step 1: Generate RSA unwrapping key pair
        auto_key wrapping_priv_key;
        auto_key wrapping_pub_key;
        auto err = generate_rsa_unwrapping_keypair(
            session,
            wrapping_priv_key.get_ptr(),
            wrapping_pub_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(wrapping_priv_key.get(), 0);
        ASSERT_NE(wrapping_pub_key.get(), 0);

        // AES-XTS uses two AES-256 keys (total bits=512).
        constexpr size_t key_bytes = 32;
        std::vector<uint8_t> key1_plain(key_bytes, 0x11);
        std::vector<uint8_t> key2_plain(key_bytes, 0x22);
        auto wrapped_blob = build_xts_wrapped_blob(wrapping_pub_key, key1_plain, key2_plain);
        ASSERT_FALSE(wrapped_blob.empty());

        // Step 2: Unwrap the XTS wrapped blob
        azihsm_algo_rsa_pkcs_oaep_params oaep_params = build_oaep_sha256_params();

        azihsm_algo_rsa_aes_key_wrap_params unwrap_params =
            build_rsa_aes_key_unwrap_params(oaep_params, AZIHSM_KEY_KIND_AES_XTS, 256);

        azihsm_algo unwrap_algo = build_rsa_aes_key_unwrap_algo(unwrap_params);

        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES_XTS;
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t bits = 512;
        bool can_encrypt = true;
        bool can_decrypt = true;

        std::vector<azihsm_key_prop> unwrap_props_vec;
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) });
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) });
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) }
        );
        unwrap_props_vec.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) }
        );

        azihsm_key_prop_list unwrap_prop_list{ unwrap_props_vec.data(),
                                               static_cast<uint32_t>(unwrap_props_vec.size()) };

        azihsm_buffer wrapped_blob_buf{ wrapped_blob.data(),
                                        static_cast<uint32_t>(wrapped_blob.size()) };

        auto_key xts_key;
        err = azihsm_key_unwrap(
            &unwrap_algo,
            wrapping_priv_key,
            &wrapped_blob_buf,
            &unwrap_prop_list,
            xts_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(xts_key, 0);

        // Step 3: Verify unwrapped key properties
        verify_key_property(xts_key, AZIHSM_KEY_PROP_ID_CLASS, AZIHSM_KEY_CLASS_SECRET);
        verify_key_property(xts_key, AZIHSM_KEY_PROP_ID_KIND, AZIHSM_KEY_KIND_AES_XTS);
        verify_key_property(xts_key, AZIHSM_KEY_PROP_ID_BIT_LEN, static_cast<uint32_t>(512));
        verify_key_property(xts_key, AZIHSM_KEY_PROP_ID_ENCRYPT, true);
        verify_key_property(xts_key, AZIHSM_KEY_PROP_ID_DECRYPT, true);
        verify_key_property(xts_key, AZIHSM_KEY_PROP_ID_LOCAL, false);

        // Step 4: Encrypt/decrypt roundtrip with tweak handling
        constexpr size_t dul = 64;
        std::vector<uint8_t> plaintext(128, 0x11);
        ASSERT_EQ(plaintext.size(), dul * 2);

        uint8_t tweak[16] = { 0 };

        // One-shot encrypt of 2 data units.
        azihsm_algo_aes_xts_params enc_xts_params{};
        std::memcpy(enc_xts_params.sector_num, tweak, 16);
        enc_xts_params.data_unit_length = static_cast<uint32_t>(dul);

        azihsm_algo enc_algo{};
        enc_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        enc_algo.params = &enc_xts_params;
        enc_algo.len = sizeof(enc_xts_params);

        std::vector<uint8_t> ciphertext_full;
        err = single_shot_crypt(
            CryptOperation::Encrypt,
            xts_key,
            &enc_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext_full
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(ciphertext_full.size(), plaintext.size());
        ASSERT_NE(ciphertext_full, plaintext) << "Ciphertext should differ from plaintext";

        // Verify tweak was incremented by 2 data units after encrypt
        std::array<uint8_t, 16> expected_tweak_after_2 = tweak_after_units(tweak, 2);
        ASSERT_EQ(std::memcmp(enc_xts_params.sector_num, expected_tweak_after_2.data(), 16), 0)
            << "Encrypt should increment tweak per data unit";

        // Encrypt per-data-unit with tweak and tweak+1; output should match one-shot.
        const uint8_t *pt0 = plaintext.data();
        const uint8_t *pt1 = plaintext.data() + dul;

        azihsm_algo_aes_xts_params xts_params0{};
        std::memcpy(xts_params0.sector_num, tweak, 16);
        xts_params0.data_unit_length = static_cast<uint32_t>(dul);
        azihsm_algo algo0{};
        algo0.id = AZIHSM_ALGO_ID_AES_XTS;
        algo0.params = &xts_params0;
        algo0.len = sizeof(xts_params0);

        std::vector<uint8_t> ct0;
        err = single_shot_crypt(CryptOperation::Encrypt, xts_key, &algo0, pt0, dul, ct0);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::array<uint8_t, 16> tweak1 = tweak_after_units(tweak, 1);
        azihsm_algo_aes_xts_params xts_params1{};
        std::memcpy(xts_params1.sector_num, tweak1.data(), 16);
        xts_params1.data_unit_length = static_cast<uint32_t>(dul);
        azihsm_algo algo1{};
        algo1.id = AZIHSM_ALGO_ID_AES_XTS;
        algo1.params = &xts_params1;
        algo1.len = sizeof(xts_params1);

        std::vector<uint8_t> ct1;
        err = single_shot_crypt(CryptOperation::Encrypt, xts_key, &algo1, pt1, dul, ct1);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        std::vector<uint8_t> ciphertext_split;
        ciphertext_split.reserve(ciphertext_full.size());
        ciphertext_split.insert(ciphertext_split.end(), ct0.begin(), ct0.end());
        ciphertext_split.insert(ciphertext_split.end(), ct1.begin(), ct1.end());
        ASSERT_EQ(ciphertext_split, ciphertext_full) << "Tweak increment mismatch";

        // One-shot decrypt should restore plaintext and increment tweak similarly.
        azihsm_algo_aes_xts_params dec_xts_params{};
        std::memcpy(dec_xts_params.sector_num, tweak, 16);
        dec_xts_params.data_unit_length = static_cast<uint32_t>(dul);

        azihsm_algo dec_algo{};
        dec_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        dec_algo.params = &dec_xts_params;
        dec_algo.len = sizeof(dec_xts_params);

        std::vector<uint8_t> decrypted;
        err = single_shot_crypt(
            CryptOperation::Decrypt,
            xts_key,
            &dec_algo,
            ciphertext_full.data(),
            ciphertext_full.size(),
            decrypted
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(decrypted, plaintext) << "Roundtrip plaintext mismatch";
        ASSERT_EQ(std::memcmp(dec_xts_params.sector_num, expected_tweak_after_2.data(), 16), 0)
            << "Decrypt should increment tweak per data unit";

        // Clean up
        err = azihsm_key_delete(wrapping_priv_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        wrapping_priv_key.release();

        err = azihsm_key_delete(wrapping_pub_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        wrapping_pub_key.release();

        err = azihsm_key_delete(xts_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        xts_key.release();
    });
}

/// Test AES-XTS key unmasking
TEST_F(azihsm_aes_keygen, aes_xts_key_unmask)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Step 1: Generate AES-XTS-512 key
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_XTS_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES_XTS;
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t bits = 512;
        bool is_session = true;
        bool can_encrypt = true;
        bool can_decrypt = true;

        std::vector<azihsm_key_prop> props_vec;
        props_vec.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
        props_vec.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) });
        props_vec.push_back({ AZIHSM_KEY_PROP_ID_BIT_LEN, &bits, sizeof(bits) });
        props_vec.push_back({ AZIHSM_KEY_PROP_ID_SESSION, &is_session, sizeof(is_session) });
        props_vec.push_back({ AZIHSM_KEY_PROP_ID_ENCRYPT, &can_encrypt, sizeof(can_encrypt) });
        props_vec.push_back({ AZIHSM_KEY_PROP_ID_DECRYPT, &can_decrypt, sizeof(can_decrypt) });

        azihsm_key_prop_list prop_list{ props_vec.data(), static_cast<uint32_t>(props_vec.size()) };

        auto_key original_key;
        azihsm_status err =
            azihsm_key_gen(session, &keygen_algo, &prop_list, original_key.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(original_key, 0);

        // Step 2: Encrypt with the original generated key
        constexpr size_t dul = 64;
        std::vector<uint8_t> plaintext(128, 0x33);
        uint8_t tweak[16] = { 0 };

        azihsm_algo_aes_xts_params enc_xts_params{};
        std::memcpy(enc_xts_params.sector_num, tweak, 16);
        enc_xts_params.data_unit_length = static_cast<uint32_t>(dul);

        azihsm_algo enc_algo{};
        enc_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        enc_algo.params = &enc_xts_params;
        enc_algo.len = sizeof(enc_xts_params);

        std::vector<uint8_t> ciphertext;
        err = single_shot_crypt(
            CryptOperation::Encrypt,
            original_key,
            &enc_algo,
            plaintext.data(),
            plaintext.size(),
            ciphertext
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Step 3: Get masked key via property
        uint8_t *masked_key_ptr = nullptr;
        uint32_t masked_key_len = 0;

        azihsm_key_prop masked_prop{};
        masked_prop.id = AZIHSM_KEY_PROP_ID_MASKED_KEY;
        masked_prop.val = masked_key_ptr;
        masked_prop.len = masked_key_len;

        err = azihsm_key_get_prop(original_key, &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(masked_prop.len, 0);

        std::vector<uint8_t> masked_key_data(masked_prop.len);
        masked_prop.val = masked_key_data.data();

        err = azihsm_key_get_prop(original_key, &masked_prop);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);

        // Step 4: Unmask the masked key
        azihsm_buffer masked_key_buf{};
        masked_key_buf.ptr = masked_key_data.data();
        masked_key_buf.len = static_cast<uint32_t>(masked_key_data.size());

        auto_key unmasked_key;
        err = azihsm_key_unmask(
            session,
            AZIHSM_KEY_KIND_AES_XTS,
            &masked_key_buf,
            unmasked_key.get_ptr()
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(unmasked_key, 0);

        // Step 5: Compare key properties
        compare_aes_xts_key_properties(original_key, unmasked_key, 512);

        // Step 6: Prove the unmasked key is a different key ID by deleting the
        // original key before using the unmasked key.
        err = azihsm_key_delete(original_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        original_key.release();

        // Step 7: Decrypt with the unmasked key
        azihsm_algo_aes_xts_params dec_xts_params{};
        std::memcpy(dec_xts_params.sector_num, tweak, 16);
        dec_xts_params.data_unit_length = static_cast<uint32_t>(dul);

        azihsm_algo dec_algo{};
        dec_algo.id = AZIHSM_ALGO_ID_AES_XTS;
        dec_algo.params = &dec_xts_params;
        dec_algo.len = sizeof(dec_xts_params);

        std::vector<uint8_t> decrypted;
        err = single_shot_crypt(
            CryptOperation::Decrypt,
            unmasked_key,
            &dec_algo,
            ciphertext.data(),
            ciphertext.size(),
            decrypted
        );
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_EQ(decrypted, plaintext) << "XTS roundtrip mismatch";

        // Clean up
        err = azihsm_key_delete(unmasked_key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        unmasked_key.release();
    });
}

/// verifies AES-XTS key unwrap fails when the wrapped blob is corrupted
TEST_F(azihsm_aes_keygen, aes_xts_key_unwrap_corrupted_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_unwrap_corrupted_fails_common(session, AZIHSM_KEY_KIND_AES_XTS, 512);
    });
}

/// verifies AES-XTS key unwrap fails when unwrapping with wrong algorithm type
TEST_F(azihsm_aes_keygen, aes_xts_unwrap_wrong_algo_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Use wrong algo ID: AES_XTS is an encryption algo, not a key-unwrap algo
        aes_unwrap_wrong_algo_fails_common(
            session,
            AZIHSM_KEY_KIND_AES_XTS,
            512,
            AZIHSM_ALGO_ID_AES_XTS
        );
    });
}

/// verifies AES-XTS key unmasking produces a usable key that can encrypt and decrypt,
/// and that the unmasked key is independent of the original key by deleting the
/// original key before using the unmasked key
TEST_F(azihsm_aes_keygen, aes_xts_unmasked_key_independent_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unmasked_key_independent_handle_common(
            session,
            AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
            AZIHSM_KEY_KIND_AES_XTS,
            512
        );
    });
}

/// verifies AES-XTS key generation fails when decrypt permission is missing
TEST_F(azihsm_aes_keygen, aes_xts_key_gen_no_decrypt_flag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
            AZIHSM_KEY_KIND_AES_XTS,
            512,
            { AZIHSM_KEY_PROP_ID_ENCRYPT }
        );
    });
}

/// verifies AES-XTS key unmask fails when unmasking with corrupted masked blob
TEST_F(azihsm_aes_keygen, aes_xts_unmask_corrupted_blob_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unmask_corrupted_blob_fails_common(
            session,
            AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
            AZIHSM_KEY_KIND_AES_XTS,
            512
        );
    });
}

/// verifies AES-XTS key generation fails when encrypt permission is missing
TEST_F(azihsm_aes_keygen, aes_xts_key_gen_no_encrypt_flag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
            AZIHSM_KEY_KIND_AES_XTS,
            512,
            { AZIHSM_KEY_PROP_ID_DECRYPT }
        );
    });
}

/// verifies AES-XTS key unwrap fails when properties specify wrong bit length (256) for a 512-bit
/// key
TEST_F(azihsm_aes_keygen, aes_xts_unwrap_bits_mismatch_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unwrap_bits_mismatch_fails_common(session, AZIHSM_KEY_KIND_AES_XTS, 512, 256);
    });
}

/// verifies AES-XTS key unmask fails when using the wrong key kind
TEST_F(azihsm_aes_keygen, aes_xts_unmask_wrong_kind_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unmask_wrong_kind_fails_common(
            session,
            AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
            AZIHSM_KEY_KIND_AES_XTS,
            512,
            AZIHSM_KEY_KIND_AES
        );
    });
}

/// verifies AES-XTS key unwrap fails when the wrapped blob is truncated
TEST_F(azihsm_aes_keygen, aes_xts_unwrap_truncated_blob_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unwrap_truncated_blob_fails_common(session, AZIHSM_KEY_KIND_AES_XTS, 512);
    });
}

/// verifies AES-XTS key generation rejects combinations of unsupported capability flags
TEST_F(azihsm_aes_keygen, aes_xts_key_gen_multiple_invalid_capabilities)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_multiple_invalid_capabilities_common(
            session,
            AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
            AZIHSM_KEY_KIND_AES_XTS,
            512
        );
    });
}

/// verifies AES-XTS encryption and decryption roundtrip using an unwrapped key
TEST_F(azihsm_aes_keygen, aes_xts_unwrapped_key_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unwrapped_key_roundtrip_common(session, AZIHSM_KEY_KIND_AES_XTS, 512);
    });
}

/// verifies AES-XTS key generation with non-session persistence creates a non-session key
/// and succeeds with correct AZIHSM_KEY_PROP_ID_SESSION property
TEST_F(azihsm_aes_keygen, aes_xts_key_gen_persistent)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_persistent_common(
            session,
            AZIHSM_ALGO_ID_AES_XTS_KEY_GEN,
            AZIHSM_KEY_KIND_AES_XTS,
            512
        );
    });
}

// ================================
// AES GCM Tests
// ================================

/// Test AES-GCM key generation, and validate the generated key has expected properties
/// and capabilities.
TEST_F(azihsm_aes_keygen, session_aes_gcm_256_key_generation)
{
    part_list_.for_each_session([](azihsm_handle session) {
        session_aes_key_generation_common(
            session,
            AZIHSM_ALGO_ID_AES_GCM_KEY_GEN,
            AZIHSM_KEY_KIND_AES_GCM,
            256
        );
    });
}

/// Test AES-GCM key unmasking for a 256-bit key
TEST_F(azihsm_aes_keygen, aes_gcm_256_key_unmask)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_unmask_common(
            session,
            AZIHSM_ALGO_ID_AES_GCM_KEY_GEN,
            AZIHSM_KEY_KIND_AES_GCM,
            256
        );
    });
}

/// verifies AES-GCM key can be unwrapped using RSA-AES wrapping
TEST_F(azihsm_aes_keygen, aes_gcm_256_key_unwrap)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_unwrap_common(session, AZIHSM_KEY_KIND_AES_GCM, 256);
    });
}

// Purpose: Validate the complete lifecycle of an AES-GCM-256 key by:
// 1. Wrapping a locally generated AES-GCM key using RSA-AES key wrap
// 2. Unwrapping it into the HSM
// 3. Using the unwrapped key for authenticated encryption
// 4. Decrypting the ciphertext and verifying it matches the original plaintext
// This ensures the key material is correctly transported and functional for cryptographic
// operations.
TEST_F(azihsm_aes_keygen, aes_gcm_unwrapped_key_roundtrip)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unwrapped_key_roundtrip_common(session, AZIHSM_KEY_KIND_AES_GCM, 256);
    });
}

/// verifies AES-GCM key generation rejects invalid key sizes and returns appropriate error
TEST_F(azihsm_aes_keygen, aes_gcm_key_generation_invalid_sizes_rejected)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // AES-GCM is only supported for 256 bits.
        for (uint32_t bits : { 0u, 1u, 128u, 192u, 255u, 257u, 384u, 512u, 1024u })
        {
            aes_key_gen_invalid_props_fail_common(
                session,
                AZIHSM_ALGO_ID_AES_GCM_KEY_GEN,
                AZIHSM_KEY_KIND_AES_GCM,
                bits,
                { AZIHSM_KEY_PROP_ID_ENCRYPT, AZIHSM_KEY_PROP_ID_DECRYPT }
            );
        }
    });
}

/// verifies AES-GCM key generation fails when encrypt flag is not set
TEST_F(azihsm_aes_keygen, aes_gcm_key_gen_no_encrypt_flag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_GCM_KEY_GEN,
            AZIHSM_KEY_KIND_AES_GCM,
            256,
            { AZIHSM_KEY_PROP_ID_DECRYPT }
        );
    });
}

/// verifies AES-GCM key generation fails when decrypt flag is not set
TEST_F(azihsm_aes_keygen, aes_gcm_key_gen_no_decrypt_flag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_invalid_props_fail_common(
            session,
            AZIHSM_ALGO_ID_AES_GCM_KEY_GEN,
            AZIHSM_KEY_KIND_AES_GCM,
            256,
            { AZIHSM_KEY_PROP_ID_ENCRYPT }
        );
    });
}

/// verifies AES-GCM key generation with non-session persistence creates a non-session key
/// and succeeds with correct AZIHSM_KEY_PROP_ID_SESSION property
TEST_F(azihsm_aes_keygen, aes_gcm_key_gen_persistent)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_persistent_common(
            session,
            AZIHSM_ALGO_ID_AES_GCM_KEY_GEN,
            AZIHSM_KEY_KIND_AES_GCM,
            256
        );
    });
}

/// verifies AES-GCM key unwrap fails when unwrapping with wrong algorithm type
TEST_F(azihsm_aes_keygen, aes_gcm_unwrap_wrong_algo_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Use wrong algo ID: AES_GCM is an encryption algo, not a key-unwrap algo
        aes_unwrap_wrong_algo_fails_common(
            session,
            AZIHSM_KEY_KIND_AES_GCM,
            256,
            AZIHSM_ALGO_ID_AES_GCM
        );
    });
}

/// verifies AES-GCM key unmasking produces a usable key that can encrypt and decrypt,
/// and that the unmasked key is independent of the original key by deleting the
/// original key before using the unmasked key
TEST_F(azihsm_aes_keygen, aes_gcm_unmasked_key_independent_handle)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unmasked_key_independent_handle_common(
            session,
            AZIHSM_ALGO_ID_AES_GCM_KEY_GEN,
            AZIHSM_KEY_KIND_AES_GCM,
            256
        );
    });
}

/// verifies AES-GCM decryption fails when decrypting with a corrupted authentication tag
/// note: AES-GCM-specific test since tag is part of AES-GCM params
TEST_F(azihsm_aes_keygen, aes_gcm_wrong_tag_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Generate AES-GCM-256 key
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_GCM_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES_GCM;
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t bits = 256;
        bool is_session = true;
        bool can_encrypt = true;
        bool can_decrypt = true;

        std::vector<azihsm_key_prop> props_vec = {
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) },
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) },
            { .id = AZIHSM_KEY_PROP_ID_SESSION, .val = &is_session, .len = sizeof(is_session) },
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) },
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &can_decrypt, .len = sizeof(can_decrypt) }
        };

        azihsm_key_prop_list prop_list{ .props = props_vec.data(),
                                        .count = static_cast<uint32_t>(props_vec.size()) };

        auto_key key;
        azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, key.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(key, 0);

        // Encrypt
        uint8_t iv[12] = { 1 };
        azihsm_algo_aes_gcm_params gcm_params{};
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        azihsm_algo crypt_algo{};
        crypt_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        crypt_algo.params = &gcm_params;
        crypt_algo.len = sizeof(gcm_params);

        std::vector<uint8_t> plaintext = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };
        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        azihsm_buffer output{ nullptr, 0 };

        err = azihsm_crypt_encrypt(&crypt_algo, key, &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(output.len, 0);

        std::vector<uint8_t> ciphertext(output.len);
        output.ptr = ciphertext.data();
        err = azihsm_crypt_encrypt(&crypt_algo, key, &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ciphertext.resize(output.len);

        // Save and corrupt the tag
        uint8_t saved_tag[16];
        std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));
        saved_tag[0] ^= 0xFF;

        // Attempt decryption with corrupted tag
        std::memcpy(gcm_params.iv, iv, sizeof(iv));
        std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

        azihsm_buffer cipher_buf{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        azihsm_buffer plain_buf{ nullptr, 0 };

        // Size query always succeeds
        err = azihsm_crypt_decrypt(&crypt_algo, key, &cipher_buf, &plain_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(plain_buf.len, 0);

        // Actual decrypt should fail due to wrong tag
        std::vector<uint8_t> decrypted(plain_buf.len);
        plain_buf.ptr = decrypted.data();
        err = azihsm_crypt_decrypt(&crypt_algo, key, &cipher_buf, &plain_buf);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);

        // Clean up
        err = azihsm_key_delete(key);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        key.release();
    });
}

/// verifies AES-GCM key unmask fails when using the wrong key kind
TEST_F(azihsm_aes_keygen, aes_gcm_unmask_wrong_kind_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unmask_wrong_kind_fails_common(
            session,
            AZIHSM_ALGO_ID_AES_GCM_KEY_GEN,
            AZIHSM_KEY_KIND_AES_GCM,
            256,
            AZIHSM_KEY_KIND_AES_XTS
        );
    });
}

/// verifies AES-GCM key unwrap fails when properties specify wrong bit length (128) for a 256-bit
/// key
TEST_F(azihsm_aes_keygen, aes_gcm_unwrap_bits_mismatch_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unwrap_bits_mismatch_fails_common(session, AZIHSM_KEY_KIND_AES_GCM, 256, 128);
    });
}

/// verifies AES-GCM decryption fails when decrypting with a different key than was used to encrypt
/// note: AES-GCM-specific test since AES-CBC & AES-XTS can still decrypt with wrong key
TEST_F(azihsm_aes_keygen, aes_gcm_wrong_key_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        // Generate two keys
        azihsm_algo keygen_algo{};
        keygen_algo.id = AZIHSM_ALGO_ID_AES_GCM_KEY_GEN;
        keygen_algo.params = nullptr;
        keygen_algo.len = 0;

        azihsm_key_kind key_kind = AZIHSM_KEY_KIND_AES_GCM;
        azihsm_key_class key_class = AZIHSM_KEY_CLASS_SECRET;
        uint32_t bits = 256;
        bool is_session = true;
        bool can_encrypt = true;
        bool can_decrypt = true;

        std::vector<azihsm_key_prop> props_vec = {
            { .id = AZIHSM_KEY_PROP_ID_KIND, .val = &key_kind, .len = sizeof(key_kind) },
            { .id = AZIHSM_KEY_PROP_ID_CLASS, .val = &key_class, .len = sizeof(key_class) },
            { .id = AZIHSM_KEY_PROP_ID_BIT_LEN, .val = &bits, .len = sizeof(bits) },
            { .id = AZIHSM_KEY_PROP_ID_SESSION, .val = &is_session, .len = sizeof(is_session) },
            { .id = AZIHSM_KEY_PROP_ID_ENCRYPT, .val = &can_encrypt, .len = sizeof(can_encrypt) },
            { .id = AZIHSM_KEY_PROP_ID_DECRYPT, .val = &can_decrypt, .len = sizeof(can_decrypt) }
        };

        azihsm_key_prop_list prop_list{ .props = props_vec.data(),
                                        .count = static_cast<uint32_t>(props_vec.size()) };

        auto_key key1;
        azihsm_status err = azihsm_key_gen(session, &keygen_algo, &prop_list, key1.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(key1, 0);

        auto_key key2;
        err = azihsm_key_gen(session, &keygen_algo, &prop_list, key2.get_ptr());
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ASSERT_NE(key2, 0);

        std::vector<uint8_t> plaintext;
        std::vector<uint8_t> iv;
        azihsm_algo_aes_gcm_params gcm_params{};
        azihsm_algo enc_algo{};

        iv = std::vector<uint8_t>(12, 1);
        std::memcpy(gcm_params.iv, iv.data(), iv.size());
        std::memset(gcm_params.tag, 0, sizeof(gcm_params.tag));
        gcm_params.aad = nullptr;

        enc_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        enc_algo.params = &gcm_params;
        enc_algo.len = sizeof(gcm_params);

        plaintext = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd' };

        azihsm_buffer input{ plaintext.data(), static_cast<uint32_t>(plaintext.size()) };
        azihsm_buffer output{ nullptr, 0 };

        // Encrypt with key1
        err = azihsm_crypt_encrypt(&enc_algo, key1, &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(output.len, 0);

        std::vector<uint8_t> ciphertext(output.len);
        output.ptr = ciphertext.data();
        err = azihsm_crypt_encrypt(&enc_algo, key1, &input, &output);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        ciphertext.resize(output.len);

        azihsm_algo dec_algo{};

        // Save the tag from encryption
        uint8_t saved_tag[16];
        std::memcpy(saved_tag, gcm_params.tag, sizeof(saved_tag));

        // Attempt decryption with key2 (wrong key)
        std::memcpy(gcm_params.iv, iv.data(), iv.size());
        std::memcpy(gcm_params.tag, saved_tag, sizeof(saved_tag));

        dec_algo.id = AZIHSM_ALGO_ID_AES_GCM;
        dec_algo.params = &gcm_params;
        dec_algo.len = sizeof(gcm_params);

        azihsm_buffer cipher_buf{ ciphertext.data(), static_cast<uint32_t>(ciphertext.size()) };
        azihsm_buffer plain_buf{ nullptr, 0 };

        // Size query always succeeds
        err = azihsm_crypt_decrypt(&dec_algo, key2, &cipher_buf, &plain_buf);
        ASSERT_EQ(err, AZIHSM_STATUS_BUFFER_TOO_SMALL);
        ASSERT_GT(plain_buf.len, 0);

        // Actual decrypt should fail due to wrong key
        std::vector<uint8_t> decrypted(plain_buf.len);
        plain_buf.ptr = decrypted.data();
        err = azihsm_crypt_decrypt(&dec_algo, key2, &cipher_buf, &plain_buf);
        ASSERT_NE(err, AZIHSM_STATUS_SUCCESS);

        // Clean up
        err = azihsm_key_delete(key1);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        key1.release();

        err = azihsm_key_delete(key2);
        ASSERT_EQ(err, AZIHSM_STATUS_SUCCESS);
        key2.release();
    });
}

/// verifies AES-GCM key unwrap fails when wrapped blob is corrupted
TEST_F(azihsm_aes_keygen, aes_gcm_key_unwrap_corrupted_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_unwrap_corrupted_fails_common(session, AZIHSM_KEY_KIND_AES_GCM, 256);
    });
}

/// verifies AES-GCM key unmask fails when unmasking with corrupted masked blob
TEST_F(azihsm_aes_keygen, aes_gcm_unmask_corrupted_blob_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unmask_corrupted_blob_fails_common(
            session,
            AZIHSM_ALGO_ID_AES_GCM_KEY_GEN,
            AZIHSM_KEY_KIND_AES_GCM,
            256
        );
    });
}

/// verifies AES-GCM key unwrap fails when the wrapped blob is truncated
TEST_F(azihsm_aes_keygen, aes_gcm_unwrap_truncated_blob_fails)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_unwrap_truncated_blob_fails_common(session, AZIHSM_KEY_KIND_AES_GCM, 256);
    });
}

/// verifies AES-GCM key generation rejects combinations of unsupported capability flags
TEST_F(azihsm_aes_keygen, aes_gcm_key_gen_multiple_invalid_capabilities)
{
    part_list_.for_each_session([](azihsm_handle session) {
        aes_key_gen_multiple_invalid_capabilities_common(
            session,
            AZIHSM_ALGO_ID_AES_GCM_KEY_GEN,
            AZIHSM_KEY_KIND_AES_GCM,
            256
        );
    });
}
