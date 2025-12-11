// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(not(feature = "fuzzing"), no_std)]

extern crate alloc;

mod decode;
mod encode;
mod len;

pub use decode::MborDecode;
pub use decode::MborDecodeError;
pub use decode::MborDecoder;
pub use encode::MborEncode;
pub use encode::MborEncodeError;
pub use encode::MborEncoder;
pub use len::MborLen;
pub use len::MborLenAccumulator;

pub type MborId = u8;

/// MBOR map.
pub struct MborMap(pub u8);

/// MBOR slice.
pub struct MborByteSlice<'a>(pub &'a [u8]);

/// Errors used for the `MborByteArray` object.
#[derive(Debug)]
pub enum MborByteArrayError {
    InvalidLen,
}

/// MBOR variable length array of max `N` length.
#[cfg(feature = "array")]
#[derive(Debug, Clone, Copy)]
pub struct MborByteArray<const N: usize> {
    data: [u8; N],
    len: usize,
}

/// A custom `Arbitrary` trait implementation that creates an `MborByteArray`
/// while also checking for errors during creation.
#[cfg(feature = "array")]
#[cfg(feature = "fuzzing")]
impl<'a, const N: usize> arbitrary::Arbitrary<'a> for MborByteArray<N> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let data = <[u8; N]>::arbitrary(u)?;
        let len = usize::arbitrary(u)?;
        if let Ok(result) = MborByteArray::new(data, len) {
            return Ok(result);
        }
        Err(arbitrary::Error::IncorrectFormat)
    }
}

#[cfg(feature = "array")]
impl<const N: usize> MborByteArray<N> {
    pub fn new(data: [u8; N], len: usize) -> Result<Self, MborByteArrayError> {
        // The value in the length field (`len`) must not be larger than the
        // maximum number of bytes available in the internal buffer. If that's
        // the case, then the length field is invalid, and this will create
        // trouble later; refuse to create a new `MborByteArray` and return an
        // error.
        if len > N {
            return Err(MborByteArrayError::InvalidLen);
        }
        Ok(Self { data, len })
    }

    /// Creates a new `MborByteArray` from a slice. The slice must not exceed
    /// the maximum allowed length `N`. If it does, an error is returned.
    pub fn from_slice(slice: &[u8]) -> Result<Self, MborByteArrayError> {
        // The length of the slice must not exceed the maximum allowed length
        if slice.len() > N {
            return Err(MborByteArrayError::InvalidLen);
        }

        let mut data = [0u8; N];
        data[..slice.len()].copy_from_slice(slice);
        Ok(Self {
            data,
            len: slice.len(),
        })
    }

    /// Returns a reference to the internal data array.
    pub fn data(&self) -> &[u8; N] {
        &self.data
    }

    /// Returns a mutable reference to the internal data array.
    pub fn data_mut(&mut self) -> &mut [u8; N] {
        &mut self.data
    }

    /// Returns ownership to the internal data array.
    pub fn data_take(&self) -> [u8; N] {
        self.data
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn maxlen(&self) -> usize {
        N
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

#[cfg(feature = "array")]
impl<const N: usize> PartialEq for MborByteArray<N> {
    fn eq(&self, other: &Self) -> bool {
        self.data[..self.len] == other.data[..other.len]
    }
}

#[cfg(feature = "array")]
impl<const N: usize> Eq for MborByteArray<N> {}

/// MBOR variable length array of max `N` length.
#[derive(Debug, Clone)]
#[cfg(not(feature = "array"))]
pub struct MborByteArray<const N: usize> {
    data: alloc::rc::Rc<core::cell::RefCell<(*const u8, usize)>>,
}

#[cfg(not(feature = "array"))]
impl<const N: usize> MborByteArray<N> {
    pub fn new(addr: *const u8) -> Result<Self, MborByteArrayError> {
        Ok(Self {
            data: alloc::rc::Rc::new(core::cell::RefCell::new((addr, N))),
        })
    }

    pub fn new_with_len(addr: *const u8, len: usize) -> Result<Self, MborByteArrayError> {
        // The requested length must not exceed `N` (the maximum allowed length)
        if len > N {
            return Err(MborByteArrayError::InvalidLen);
        }

        Ok(Self {
            data: alloc::rc::Rc::new(core::cell::RefCell::new((addr, len))),
        })
    }

    pub fn ptr(&self) -> *const u8 {
        self.data.borrow().0
    }

    pub fn len(&self) -> usize {
        self.data.borrow().1
    }

    pub fn maxlen(&self) -> usize {
        N
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn set_ptr(&self, ptr: *const u8) {
        self.data.borrow_mut().0 = ptr
    }

    pub fn set_len(&self, len: usize) {
        self.data.borrow_mut().1 = len
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.data.borrow().0, self.data.borrow().1) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(self.data.borrow().0 as *mut u8, self.data.borrow().1)
        }
    }
}

#[cfg(not(feature = "array"))]
impl<const N: usize> PartialEq for MborByteArray<N> {
    fn eq(&self, other: &Self) -> bool {
        let this =
            unsafe { core::slice::from_raw_parts(self.data.borrow().0, self.data.borrow().1) };
        let that =
            unsafe { core::slice::from_raw_parts(other.data.borrow().0, other.data.borrow().1) };
        this == that && self.data.borrow().1 == other.data.borrow().1
    }
}

#[cfg(not(feature = "array"))]
impl<const N: usize> Eq for MborByteArray<N> {}

/// MBOR Padded Array.
pub struct MborPaddedByteArray<'a, const N: usize>(pub &'a MborByteArray<N>, pub u8);

#[inline(always)]
pub fn pad4(len: u32) -> u32 {
    ((len + 0x3) & !0x3) - len
}

pub const MAP_MARKER: u8 = 0xA0;
pub const MAP_FIELD_COUNT_MASK: u8 = 0b000_11111;

pub const BOOL_MARKER: u8 = 0x14;
pub const BYTES_MARKER: u8 = 0x80;

pub const BYTES_PAD_MASK: u8 = 0b0000_0011;

pub const UINT_MARKER: u8 = 0x18;
pub const U8_MASK: u8 = 0x00;
pub const U16_MASK: u8 = 0x01;
pub const U32_MASK: u8 = 0x02;
pub const U64_MASK: u8 = 0x03;

pub const U8_MARKER: u8 = UINT_MARKER | U8_MASK;
pub const U16_MARKER: u8 = UINT_MARKER | U16_MASK;
pub const U32_MARKER: u8 = UINT_MARKER | U32_MASK;
pub const U64_MARKER: u8 = UINT_MARKER | U64_MASK;
