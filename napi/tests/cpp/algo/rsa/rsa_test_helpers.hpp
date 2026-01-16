// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include <azihsm_api.h>
#include <gtest/gtest.h>
#include <vector>

// Helper to build RSA private key property list
inline std::vector<azihsm_key_prop> build_rsa_priv_key_props(uint32_t modulus_bits, uint32_t &priv_key_class,
                                                             uint32_t &priv_key_kind, uint32_t &rsa_modulus_bits,
                                                             uint8_t &priv_is_session, uint8_t &priv_can_unwrap)
{
    priv_key_class = 3; // AZIHSM_KEY_CLASS_PRIVATE
    priv_key_kind = 1;  // AZIHSM_KEY_KIND_RSA
    rsa_modulus_bits = modulus_bits;
    priv_is_session = 1;
    priv_can_unwrap = 1;

    return {
        {AZIHSM_KEY_PROP_ID_CLASS, &priv_key_class, sizeof(priv_key_class)},
        {AZIHSM_KEY_PROP_ID_KIND, &priv_key_kind, sizeof(priv_key_kind)},
        {AZIHSM_KEY_PROP_ID_BIT_LEN, &rsa_modulus_bits, sizeof(rsa_modulus_bits)},
        {AZIHSM_KEY_PROP_ID_SESSION, &priv_is_session, sizeof(priv_is_session)},
        {AZIHSM_KEY_PROP_ID_UNWRAP, &priv_can_unwrap, sizeof(priv_can_unwrap)},
    };
}

// Helper to build RSA public key property list
inline std::vector<azihsm_key_prop> build_rsa_pub_key_props(uint32_t modulus_bits, uint32_t &pub_key_class,
                                                            uint32_t &pub_key_kind, uint32_t &rsa_modulus_bits,
                                                            uint8_t &pub_is_session, uint8_t &pub_can_wrap)
{
    pub_key_class = 2; // AZIHSM_KEY_CLASS_PUBLIC
    pub_key_kind = 1;  // AZIHSM_KEY_KIND_RSA
    rsa_modulus_bits = modulus_bits;
    pub_is_session = 1;
    pub_can_wrap = 1;

    return {
        {AZIHSM_KEY_PROP_ID_CLASS, &pub_key_class, sizeof(pub_key_class)},
        {AZIHSM_KEY_PROP_ID_KIND, &pub_key_kind, sizeof(pub_key_kind)},
        {AZIHSM_KEY_PROP_ID_BIT_LEN, &rsa_modulus_bits, sizeof(rsa_modulus_bits)},
        {AZIHSM_KEY_PROP_ID_SESSION, &pub_is_session, sizeof(pub_is_session)},
        {AZIHSM_KEY_PROP_ID_WRAP, &pub_can_wrap, sizeof(pub_can_wrap)},
    };
}

// Helper function to generate RSA key pair for testing
static void generate_rsa_keypair(azihsm_handle session, uint32_t modulus_bits, azihsm_handle &priv_key_handle,
                                 azihsm_handle &pub_key_handle)
{
    azihsm_algo keygen_algo{};
    keygen_algo.id = AZIHSM_ALGO_ID_RSA_KEY_UNWRAPPING_KEY_PAIR_GEN;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    // Private key properties
    uint32_t priv_key_class, priv_key_kind, priv_rsa_modulus_bits;
    uint8_t priv_is_session, priv_can_sign;
    auto priv_props = build_rsa_priv_key_props(modulus_bits, priv_key_class, priv_key_kind, priv_rsa_modulus_bits,
                                               priv_is_session, priv_can_sign);
    azihsm_key_prop_list priv_prop_list{priv_props.data(), static_cast<uint32_t>(priv_props.size())};

    // Public key properties
    uint32_t pub_key_class, pub_key_kind, pub_rsa_modulus_bits;
    uint8_t pub_is_session, pub_can_verify;
    auto pub_props = build_rsa_pub_key_props(modulus_bits, pub_key_class, pub_key_kind, pub_rsa_modulus_bits,
                                             pub_is_session, pub_can_verify);
    azihsm_key_prop_list pub_prop_list{pub_props.data(), static_cast<uint32_t>(pub_props.size())};

    auto err =
        azihsm_key_gen_pair(session, &keygen_algo, &priv_prop_list, &pub_prop_list, &priv_key_handle, &pub_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(priv_key_handle, 0);
    ASSERT_NE(pub_key_handle, 0);
}