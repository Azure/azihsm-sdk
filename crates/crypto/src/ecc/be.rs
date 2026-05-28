// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Big-endian byte-string arithmetic helpers used by FIPS 186-5
//! Appendix A.2.1 key-pair derivation.
//!
//! The helpers operate on arbitrary-length big-endian byte slices without
//! relying on a platform big-integer backend. They are intentionally minimal:
//! a schoolbook bit-by-bit modular reduction and a single-byte increment.
//!
//! These routines are **not constant-time** with respect to the data being
//! reduced. They are intended for use during deterministic ECC key derivation
//! where the OKM is produced by an approved KDF and one-shot keygen latency
//! is not on a side-channel-observable hot path. A constant-time replacement
//! can be dropped in later without changing the public API of
//! [`super::EccPrivateKey::from_okm_a2_1`].

/// Maximum modulus length supported by [`be_reduce`], in bytes.
///
/// Set to 66 bytes to cover NIST P-521's curve order.
pub(super) const MAX_MOD_LEN: usize = 66;

/// Reduces a big-endian non-negative integer `c` modulo `m`.
///
/// `c` may be any length (including longer than `m`). `m` must be non-empty,
/// non-zero, and at most [`MAX_MOD_LEN`] bytes. The returned array is
/// big-endian; only the first `m.len()` bytes are meaningful (callers slice
/// to `m.len()`).
///
/// Implementation: bit-by-bit shift-and-subtract long division. Variable
/// time over `c`.
///
/// # Panics
///
/// Panics if `m` is empty, longer than [`MAX_MOD_LEN`], or all-zero. These
/// preconditions are invariants of the only caller
/// ([`super::EccPrivateKey::from_okm_a2_1`]) and depend only on public
/// curve parameters, never on secret input.
pub(super) fn be_reduce(c: &[u8], m: &[u8]) -> [u8; MAX_MOD_LEN] {
    assert!(!m.is_empty(), "be_reduce: modulus must be non-empty");
    assert!(m.len() <= MAX_MOD_LEN, "be_reduce: modulus too large");
    assert!(
        m.iter().any(|&b| b != 0),
        "be_reduce: modulus must be non-zero"
    );

    let m_len = m.len();
    let mut rem = [0u8; MAX_MOD_LEN];

    for &byte in c {
        for bit_idx in (0..8).rev() {
            // rem <<= 1, shifting in the next bit of c.
            let mut carry = ((byte >> bit_idx) & 1) as u16;
            for i in (0..m_len).rev() {
                let v = (rem[i] as u16) * 2 + carry;
                rem[i] = (v & 0xff) as u8;
                carry = v >> 8;
            }

            // if rem >= m { rem -= m }
            if rem[..m_len] >= *m {
                let mut borrow = 0i16;
                for i in (0..m_len).rev() {
                    let v = rem[i] as i16 - m[i] as i16 - borrow;
                    if v < 0 {
                        rem[i] = (v + 256) as u8;
                        borrow = 1;
                    } else {
                        rem[i] = v as u8;
                        borrow = 0;
                    }
                }
            }
        }
    }

    rem
}

/// Adds 1 to `buf` interpreted as a big-endian integer, in place.
///
/// # Panics
///
/// Panics on overflow. Callers must guarantee the result fits, which is the
/// case for [`super::EccPrivateKey::from_okm_a2_1`] because the input is
/// `c mod (n - 1)` with `c mod (n - 1) <= n - 2`, so `+1 <= n - 1` and
/// cannot overflow `n.len()` bytes.
pub(super) fn be_inc(buf: &mut [u8]) {
    for i in (0..buf.len()).rev() {
        let (v, carry) = buf[i].overflowing_add(1);
        buf[i] = v;
        if !carry {
            return;
        }
    }
    panic!("be_inc: overflow");
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::*;
    use super::*;

    fn reduce_eq(c_hex: &str, m_hex: &str, expected_hex: &str) {
        let c = hex::decode(c_hex).unwrap();
        let m = hex::decode(m_hex).unwrap();
        let expected = hex::decode(expected_hex).unwrap();
        let out = be_reduce(&c, &m);
        assert_eq!(&out[..m.len()], expected.as_slice(), "c={c_hex} m={m_hex}");
    }

    #[test]
    fn be_reduce_small_cases() {
        // 100 mod 7 = 2
        reduce_eq("64", "07", "02");
        // 0 mod n = 0
        reduce_eq("00", "11", "00");
        // n mod n = 0
        reduce_eq("11", "11", "00");
        // (n - 1) mod n = n - 1
        reduce_eq("10", "11", "10");
        // multi-byte: 0x1234 mod 0x100 = 0x34
        reduce_eq("1234", "0100", "0034");
        // c shorter than m: 0x05 mod 0x1000 = 0x0005
        reduce_eq("05", "1000", "0005");
    }

    #[test]
    fn be_reduce_p256_order_boundary() {
        // c == n - 1 ⇒ c mod (n - 1) == 0
        let n_minus_one = {
            let mut v = EccCurve::P256.order().to_vec();
            *v.last_mut().unwrap() -= 1;
            v
        };
        let out = be_reduce(&n_minus_one, &n_minus_one);
        assert_eq!(&out[..n_minus_one.len()], vec![0u8; n_minus_one.len()]);

        // c == n - 2 ⇒ c mod (n - 1) == n - 2
        let mut n_minus_two = n_minus_one.clone();
        *n_minus_two.last_mut().unwrap() -= 1;
        let out = be_reduce(&n_minus_two, &n_minus_one);
        assert_eq!(&out[..n_minus_two.len()], n_minus_two.as_slice());
    }

    #[test]
    fn be_inc_basic() {
        let mut buf = [0u8; 4];
        be_inc(&mut buf);
        assert_eq!(buf, [0, 0, 0, 1]);

        let mut buf = [0, 0, 0, 0xff];
        be_inc(&mut buf);
        assert_eq!(buf, [0, 0, 1, 0]);

        let mut buf = [0, 0xff, 0xff, 0xff];
        be_inc(&mut buf);
        assert_eq!(buf, [1, 0, 0, 0]);
    }

    #[test]
    #[should_panic(expected = "be_inc: overflow")]
    fn be_inc_overflow_panics() {
        let mut buf = [0xffu8; 4];
        be_inc(&mut buf);
    }
}
