// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for ECC public-key validation primitives used by ECDH point
//! validation: [`EccCurve::coordinate_in_range`] (field-element range check)
//! and [`EccPublicKey::is_on_curve`] (on-curve check).

use super::*;

const ALL_CURVES: [EccCurve; 3] = [EccCurve::P256, EccCurve::P384, EccCurve::P521];

/// Returns `p - 1` (big-endian) for the curve field prime `p`.
fn prime_minus_one(curve: EccCurve) -> Vec<u8> {
    let mut p = curve.prime().to_vec();
    for byte in p.iter_mut().rev() {
        if *byte == 0 {
            *byte = 0xff;
        } else {
            *byte -= 1;
            break;
        }
    }
    p
}

/// Returns a coordinate equal to `1` (big-endian) for the curve.
fn coordinate_one(curve: EccCurve) -> Vec<u8> {
    let mut one = vec![0u8; curve.point_size()];
    *one.last_mut().unwrap() = 1;
    one
}

#[test]
fn coordinate_in_range_accepts_valid_field_elements() {
    for curve in ALL_CURVES {
        let (gx, gy) = generator(curve);
        assert!(curve.coordinate_in_range(&gx), "Gx must be in range");
        assert!(curve.coordinate_in_range(&gy), "Gy must be in range");
        // Inclusive bounds: 1 and p - 1.
        assert!(curve.coordinate_in_range(&coordinate_one(curve)));
        assert!(curve.coordinate_in_range(&prime_minus_one(curve)));
    }
}

#[test]
fn coordinate_in_range_rejects_zero_and_prime_and_above() {
    for curve in ALL_CURVES {
        let ps = curve.point_size();
        // 0 is below the lower bound.
        assert!(!curve.coordinate_in_range(&vec![0u8; ps]));
        // p itself and any value >= p are rejected.
        assert!(!curve.coordinate_in_range(curve.prime()));
        assert!(!curve.coordinate_in_range(&vec![0xffu8; ps]));
    }
}

#[test]
fn coordinate_in_range_rejects_wrong_length() {
    for curve in ALL_CURVES {
        let ps = curve.point_size();
        assert!(!curve.coordinate_in_range(&vec![1u8; ps + 1]));
        assert!(!curve.coordinate_in_range(&vec![1u8; ps - 1]));
    }
}

#[test]
fn is_on_curve_accepts_generator_and_its_negation() {
    for curve in ALL_CURVES {
        let (gx, gy) = generator(curve);
        assert!(
            EccPublicKey::is_on_curve(curve, &gx, &gy).unwrap(),
            "generator must be on curve"
        );
        // -G = (Gx, p - Gy) is also a valid curve point.
        let neg_gy = negate_y_modp(curve, &gy);
        assert!(
            EccPublicKey::is_on_curve(curve, &gx, &neg_gy).unwrap(),
            "-G must be on curve"
        );
    }
}

#[test]
fn is_on_curve_rejects_off_curve_point() {
    for curve in ALL_CURVES {
        let (gx, gy) = generator(curve);
        // Flip the least-significant bit of Gy. The only valid y-values for a
        // given x are Gy and p - Gy, so Gy ^ 1 is off the curve while staying a
        // valid in-range field element.
        let mut bad_y = gy.clone();
        *bad_y.last_mut().unwrap() ^= 0x01;
        assert!(
            curve.coordinate_in_range(&bad_y),
            "tampered y must still be a valid field element"
        );
        assert!(
            !EccPublicKey::is_on_curve(curve, &gx, &bad_y).unwrap(),
            "tampered point must not be on curve"
        );
    }
}
