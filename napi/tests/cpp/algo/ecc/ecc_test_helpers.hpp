// Copyright (C) Microsoft Corporation. All rights reserved.

#pragma once

#include <azihsm_api.h>
#include <gtest/gtest.h>

// Helper to build ECC private key property list
inline void build_ecc_priv_key_props(uint32_t curve, uint32_t &priv_key_class, uint32_t &priv_key_kind,
                                     uint32_t &ecc_curve, uint8_t &priv_is_session, uint8_t &priv_can_sign,
                                     azihsm_key_prop *props)
{
    priv_key_class = 3; // AZIHSM_KEY_CLASS_PRIVATE
    priv_key_kind = 2;  // AZIHSM_KEY_KIND_EC
    ecc_curve = curve;
    priv_is_session = 1;
    priv_can_sign = 1;

    props[0] = {AZIHSM_KEY_PROP_ID_CLASS, &priv_key_class, sizeof(priv_key_class)};
    props[1] = {AZIHSM_KEY_PROP_ID_KIND, &priv_key_kind, sizeof(priv_key_kind)};
    props[2] = {AZIHSM_KEY_PROP_ID_EC_CURVE, &ecc_curve, sizeof(ecc_curve)};
    props[3] = {AZIHSM_KEY_PROP_ID_SESSION, &priv_is_session, sizeof(priv_is_session)};
    props[4] = {AZIHSM_KEY_PROP_ID_SIGN, &priv_can_sign, sizeof(priv_can_sign)};
}

// Helper to build ECC public key property list
inline void build_ecc_pub_key_props(uint32_t curve, uint32_t &pub_key_class, uint32_t &pub_key_kind,
                                    uint32_t &ecc_curve, uint8_t &pub_is_session, uint8_t &pub_can_verify,
                                    azihsm_key_prop *props)
{
    pub_key_class = 2; // AZIHSM_KEY_CLASS_PUBLIC
    pub_key_kind = 2;  // AZIHSM_KEY_KIND_EC
    ecc_curve = curve;
    pub_is_session = 1;
    pub_can_verify = 1;

    props[0] = {AZIHSM_KEY_PROP_ID_CLASS, &pub_key_class, sizeof(pub_key_class)};
    props[1] = {AZIHSM_KEY_PROP_ID_KIND, &pub_key_kind, sizeof(pub_key_kind)};
    props[2] = {AZIHSM_KEY_PROP_ID_EC_CURVE, &ecc_curve, sizeof(ecc_curve)};
    props[3] = {AZIHSM_KEY_PROP_ID_SESSION, &pub_is_session, sizeof(pub_is_session)};
    props[4] = {AZIHSM_KEY_PROP_ID_VERIFY, &pub_can_verify, sizeof(pub_can_verify)};
}

// Helper function to generate ECC key pair for testing
static void generate_ecc_keypair(azihsm_handle session, uint32_t curve, azihsm_handle &priv_key_handle,
                                 azihsm_handle &pub_key_handle)
{
    azihsm_algo keygen_algo{};
    keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    // Private key properties
    uint32_t priv_key_class, priv_key_kind, priv_ecc_curve;
    uint8_t priv_is_session, priv_can_sign;
    azihsm_key_prop priv_props[5];

    build_ecc_priv_key_props(curve, priv_key_class, priv_key_kind, priv_ecc_curve, priv_is_session, priv_can_sign,
                             priv_props);
    azihsm_key_prop_list priv_prop_list{priv_props, 5};

    // Public key properties
    uint32_t pub_key_class, pub_key_kind, pub_ecc_curve;
    uint8_t pub_is_session, pub_can_verify;
    azihsm_key_prop pub_props[5];

    build_ecc_pub_key_props(curve, pub_key_class, pub_key_kind, pub_ecc_curve, pub_is_session, pub_can_verify,
                            pub_props);
    azihsm_key_prop_list pub_prop_list{pub_props, 5};

    auto err =
        azihsm_key_gen_pair(session, &keygen_algo, &priv_prop_list, &pub_prop_list, &priv_key_handle, &pub_key_handle);
    ASSERT_EQ(err, AZIHSM_ERROR_SUCCESS);
    ASSERT_NE(priv_key_handle, 0);
    ASSERT_NE(pub_key_handle, 0);
}