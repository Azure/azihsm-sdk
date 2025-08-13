// Copyright (c) Microsoft Corporation. All rights reserved.

use crate::*;

/// Trait that reports the encoded length of an object in
/// Manticore Binary Object Representation (MBOR).
pub trait MborLen {
    /// Returns the encoded length of the object in MBOR.
    ///
    /// # Arguments
    ///
    /// * `acc` - Accumulator
    fn mbor_len(&self, acc: &mut MborLenAccumulator);
}

macro_rules! mbor_len_uint {
    ($($ty:ty),*) => {
        $(
            /// Implement `MborLen` for `$ty`.
            impl MborLen for $ty {
                /// Returns the encoded length of the object in MBOR.
                fn mbor_len(&self, acc: &mut MborLenAccumulator) {
                    acc.incr(1 + core::mem::size_of::<$ty>())
                }
            }
        )*
    };
}

mbor_len_uint!(u8, u16, u32, u64);

/// Implement `MborLen` for `bool`.
impl MborLen for bool {
    fn mbor_len(&self, acc: &mut MborLenAccumulator) {
        acc.incr(1) // Marker + data
    }
}

/// Implement `MborLen` for `MborMap`.
impl MborLen for MborMap {
    fn mbor_len(&self, acc: &mut MborLenAccumulator) {
        acc.incr(1) // Marker and field count
    }
}

/// Implement `MborLen` for `MborByteSlice`.
impl MborLen for MborByteSlice<'_> {
    fn mbor_len(&self, acc: &mut MborLenAccumulator) {
        acc.incr(1); // Marker
        acc.incr(2); // Length
        acc.incr(self.0.len()); // Data
    }
}

/// Implement `MborLen` for `MborPaddedByteArray`.
impl<const N: usize> MborLen for MborPaddedByteArray<'_, N> {
    fn mbor_len(&self, acc: &mut MborLenAccumulator) {
        acc.incr(1); // Marker
        acc.incr(2); // Length
        acc.incr(self.1 as usize); // Pad
        acc.incr(self.0.len()); // Data
    }
}

#[derive(Default)]
pub struct MborLenAccumulator {
    len: usize,
}

impl MborLenAccumulator {
    pub fn incr(&mut self, n: usize) {
        self.len += n
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
