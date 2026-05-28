// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::*;

/// Trait that reports the encoded length of an object in AZIHSM Binary
/// Object Representation (MBOR).
pub trait MborLen {
    /// Accumulates the encoded length of the object in MBOR.
    fn mbor_len(&self, acc: &mut MborLenAccumulator);
}

macro_rules! mbor_len_uint {
    ($($ty:ty),*) => {
        $(
            impl MborLen for $ty {
                fn mbor_len(&self, acc: &mut MborLenAccumulator) {
                    acc.incr(1 + core::mem::size_of::<$ty>())
                }
            }
        )*
    };
}

mbor_len_uint!(u8, u16, u32, u64);

impl MborLen for bool {
    fn mbor_len(&self, acc: &mut MborLenAccumulator) {
        acc.incr(1) // Marker byte encodes value
    }
}

impl MborLen for MborMap {
    fn mbor_len(&self, acc: &mut MborLenAccumulator) {
        acc.incr(1) // Marker + field count in one byte
    }
}

impl MborLen for MborByteSlice<'_> {
    fn mbor_len(&self, acc: &mut MborLenAccumulator) {
        acc.incr(1); // Marker
        acc.incr(2); // Length (u16)
        acc.incr(self.0.len()); // Data
    }
}

impl MborLen for MborPaddedByteSlice<'_> {
    fn mbor_len(&self, acc: &mut MborLenAccumulator) {
        acc.incr(1); // Marker
        acc.incr(2); // Length (u16)
        acc.incr(self.1 as usize); // Padding
        acc.incr(self.0.len()); // Data
    }
}

/// Accumulator for computing the total encoded size of an MBOR payload
/// without writing any bytes.
#[derive(Default)]
pub struct MborLenAccumulator {
    len: usize,
}

impl MborLenAccumulator {
    /// Add `n` bytes to the accumulated length.
    pub fn incr(&mut self, n: usize) {
        self.len += n;
    }

    /// Total accumulated length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if no bytes have been accumulated.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len_u8() {
        let mut acc = MborLenAccumulator::default();
        0u8.mbor_len(&mut acc);
        assert_eq!(acc.len(), 2); // marker + 1 byte
    }

    #[test]
    fn len_u16() {
        let mut acc = MborLenAccumulator::default();
        0u16.mbor_len(&mut acc);
        assert_eq!(acc.len(), 3); // marker + 2 bytes
    }

    #[test]
    fn len_u32() {
        let mut acc = MborLenAccumulator::default();
        0u32.mbor_len(&mut acc);
        assert_eq!(acc.len(), 5); // marker + 4 bytes
    }

    #[test]
    fn len_u64() {
        let mut acc = MborLenAccumulator::default();
        0u64.mbor_len(&mut acc);
        assert_eq!(acc.len(), 9); // marker + 8 bytes
    }

    #[test]
    fn len_bool() {
        let mut acc = MborLenAccumulator::default();
        true.mbor_len(&mut acc);
        assert_eq!(acc.len(), 1);
    }

    #[test]
    fn len_map() {
        let mut acc = MborLenAccumulator::default();
        MborMap(3).mbor_len(&mut acc);
        assert_eq!(acc.len(), 1);
    }

    #[test]
    fn len_byte_slice() {
        let data = [0u8; 10];
        let mut acc = MborLenAccumulator::default();
        MborByteSlice(&data).mbor_len(&mut acc);
        assert_eq!(acc.len(), 1 + 2 + 10);
    }

    #[test]
    fn len_padded_byte_slice() {
        let data = [0u8; 10];
        let mut acc = MborLenAccumulator::default();
        MborPaddedByteSlice(&data, 1).mbor_len(&mut acc);
        assert_eq!(acc.len(), 1 + 2 + 1 + 10);
    }

    #[test]
    fn len_accumulator_default_empty() {
        let acc = MborLenAccumulator::default();
        assert!(acc.is_empty());
        assert_eq!(acc.len(), 0);
    }
}
