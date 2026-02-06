// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub(crate) fn sig_der_to_raw(curve: EccCurve, sig_der: &[u8]) -> Vec<u8> {
    let sig =
        DerEccSignature::from_der(curve, sig_der).expect("Failed to parse DER ECDSA signature");
    let mut raw = vec![0u8; curve.point_size() * 2];
    raw[..curve.point_size()].copy_from_slice(sig.r());
    raw[curve.point_size()..].copy_from_slice(sig.s());
    raw
}

pub(crate) fn expected_sig_len_from_curve_bits(curve_bits: usize) -> usize {
    match curve_bits {
        256 => EccCurve::P256.point_size() * 2,
        384 => EccCurve::P384.point_size() * 2,
        521 => EccCurve::P521.point_size() * 2,
        other => panic!("Unsupported curve_bits: {other}"),
    }
}

pub(crate) fn export_key_bytes<K: ExportableKey>(key: &K) -> Vec<u8> {
    let len = key
        .to_bytes(None)
        .expect("Failed to query key bytes length");
    let mut bytes = vec![0u8; len];
    key.to_bytes(Some(&mut bytes))
        .expect("Failed to export key bytes");
    bytes
}

pub(crate) fn export_secret(secret: &GenericSecretKey) -> Vec<u8> {
    let len = secret
        .to_bytes(None)
        .expect("Failed to query shared secret length");
    let mut bytes = vec![0u8; len];
    secret
        .to_bytes(Some(&mut bytes))
        .expect("Failed to export shared secret");
    bytes
}
