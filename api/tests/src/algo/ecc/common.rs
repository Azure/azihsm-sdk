// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

/// Generates an ECC key pair with signing (private) and verification (public) capabilities
pub(crate) fn generate_ecc_key_pair(
    session: &HsmSession,
    curve: HsmEccCurve,
) -> (HsmEccPrivateKey, HsmEccPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build public key props");

    let mut algo = HsmEccKeyGenAlgo::default();

    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
        .expect("Failed to generate ECC key pair")
}
