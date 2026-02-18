// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <azihsm_api.h>
#include <gtest/gtest.h>
#include <vector>

// Dummy private key properties for negative tests
struct DummyEccPrivKeyProps
{
    uint32_t key_class = AZIHSM_KEY_CLASS_PRIVATE;
    uint32_t key_kind = AZIHSM_KEY_KIND_ECC;
    uint32_t ecc_curve = AZIHSM_ECC_CURVE_P256;
    uint8_t is_session = 1;
    uint8_t can_sign = 1;

    std::vector<azihsm_key_prop> props;

    DummyEccPrivKeyProps()
    {
        props.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) });
        props.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
        props.push_back({ AZIHSM_KEY_PROP_ID_EC_CURVE, &ecc_curve, sizeof(ecc_curve) });
        props.push_back({ AZIHSM_KEY_PROP_ID_SESSION, &is_session, sizeof(is_session) });
        props.push_back({ AZIHSM_KEY_PROP_ID_SIGN, &can_sign, sizeof(can_sign) });
    }

    azihsm_key_prop_list get_prop_list()
    {
        return { props.data(), static_cast<uint32_t>(props.size()) };
    }
};

// Dummy public key properties for negative tests
struct DummyEccPubKeyProps
{
    uint32_t key_class = AZIHSM_KEY_CLASS_PUBLIC;
    uint32_t key_kind = AZIHSM_KEY_KIND_ECC;
    uint32_t ecc_curve = AZIHSM_ECC_CURVE_P256;
    uint8_t is_session = 1;
    uint8_t can_verify = 1;

    std::vector<azihsm_key_prop> props;

    DummyEccPubKeyProps()
    {
        props.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &key_class, sizeof(key_class) });
        props.push_back({ AZIHSM_KEY_PROP_ID_KIND, &key_kind, sizeof(key_kind) });
        props.push_back({ AZIHSM_KEY_PROP_ID_EC_CURVE, &ecc_curve, sizeof(ecc_curve) });
        props.push_back({ AZIHSM_KEY_PROP_ID_SESSION, &is_session, sizeof(is_session) });
        props.push_back({ AZIHSM_KEY_PROP_ID_VERIFY, &can_verify, sizeof(can_verify) });
    }

    azihsm_key_prop_list get_prop_list()
    {
        return { props.data(), static_cast<uint32_t>(props.size()) };
    }
};

// Helper function to generate ECC key pair for testing
static azihsm_status generate_ecc_keypair(
    azihsm_handle session,
    azihsm_ecc_curve curve,
    bool session_key,
    azihsm_handle *priv_key_handle,
    azihsm_handle *pub_key_handle
)
{
    azihsm_algo keygen_algo{};
    keygen_algo.id = AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN;
    keygen_algo.params = nullptr;
    keygen_algo.len = 0;

    // Private key properties
    uint32_t priv_key_class = AZIHSM_KEY_CLASS_PRIVATE;
    uint32_t priv_key_kind = AZIHSM_KEY_KIND_ECC;
    uint32_t priv_ecc_curve = curve;
    uint8_t session_key_flag = session_key ? 1 : 0;
    uint8_t priv_can_sign = 1;

    std::vector<azihsm_key_prop> priv_props;
    priv_props.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &priv_key_class, sizeof(priv_key_class) });
    priv_props.push_back({ AZIHSM_KEY_PROP_ID_KIND, &priv_key_kind, sizeof(priv_key_kind) });
    priv_props.push_back({ AZIHSM_KEY_PROP_ID_EC_CURVE, &priv_ecc_curve, sizeof(priv_ecc_curve) });
    priv_props.push_back(
        { AZIHSM_KEY_PROP_ID_SESSION, &session_key_flag, sizeof(session_key_flag) }
    );
    priv_props.push_back({ AZIHSM_KEY_PROP_ID_SIGN, &priv_can_sign, sizeof(priv_can_sign) });

    azihsm_key_prop_list priv_prop_list{ priv_props.data(),
                                         static_cast<uint32_t>(priv_props.size()) };

    // Public key properties
    uint32_t pub_key_class = AZIHSM_KEY_CLASS_PUBLIC;
    uint32_t pub_key_kind = AZIHSM_KEY_KIND_ECC;
    uint32_t pub_ecc_curve = curve;
    uint8_t pub_can_verify = 1;

    std::vector<azihsm_key_prop> pub_props;
    pub_props.push_back({ AZIHSM_KEY_PROP_ID_CLASS, &pub_key_class, sizeof(pub_key_class) });
    pub_props.push_back({ AZIHSM_KEY_PROP_ID_KIND, &pub_key_kind, sizeof(pub_key_kind) });
    pub_props.push_back({ AZIHSM_KEY_PROP_ID_EC_CURVE, &pub_ecc_curve, sizeof(pub_ecc_curve) });
    pub_props.push_back(
        { AZIHSM_KEY_PROP_ID_SESSION, &session_key_flag, sizeof(session_key_flag) }
    );
    pub_props.push_back({ AZIHSM_KEY_PROP_ID_VERIFY, &pub_can_verify, sizeof(pub_can_verify) });

    azihsm_key_prop_list pub_prop_list{ pub_props.data(), static_cast<uint32_t>(pub_props.size()) };

    return azihsm_key_gen_pair(
        session,
        &keygen_algo,
        &priv_prop_list,
        &pub_prop_list,
        priv_key_handle,
        pub_key_handle
    );
}