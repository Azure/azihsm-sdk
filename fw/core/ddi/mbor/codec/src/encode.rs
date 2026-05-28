// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::*;

/// Error type for MBOR encoding.
#[derive(Debug)]
pub enum MborEncodeError {
    BufferOverflow,
    InvalidLen,
    InvalidParameter,
}

impl From<MborEncodeError> for azihsm_fw_hsm_pal_traits::HsmError {
    #[inline]
    fn from(_: MborEncodeError) -> Self {
        Self::DdiEncodeFailed
    }
}

/// Trait that encodes an object in AZIHSM Binary Object Representation
/// (MBOR).
pub trait MborEncode {
    /// Encodes the object into the given encoder.
    fn mbor_encode(&self, encoder: &mut MborEncoder<'_>) -> Result<(), MborEncodeError>;
}

impl MborEncode for MborMap {
    fn mbor_encode(&self, encoder: &mut MborEncoder<'_>) -> Result<(), MborEncodeError> {
        encoder.encode(&[MAP_MARKER | (MAP_FIELD_COUNT_MASK & self.0)])
    }
}

impl MborEncode for u8 {
    fn mbor_encode(&self, encoder: &mut MborEncoder<'_>) -> Result<(), MborEncodeError> {
        encoder.encode(&[U8_MARKER, *self])
    }
}

impl MborEncode for u16 {
    fn mbor_encode(&self, encoder: &mut MborEncoder<'_>) -> Result<(), MborEncodeError> {
        let be = self.to_be_bytes();
        encoder.encode(&[U16_MARKER, be[0], be[1]])
    }
}

impl MborEncode for u32 {
    fn mbor_encode(&self, encoder: &mut MborEncoder<'_>) -> Result<(), MborEncodeError> {
        let be = self.to_be_bytes();
        encoder.encode(&[U32_MARKER, be[0], be[1], be[2], be[3]])
    }
}

impl MborEncode for u64 {
    fn mbor_encode(&self, encoder: &mut MborEncoder<'_>) -> Result<(), MborEncodeError> {
        let be = self.to_be_bytes();
        encoder.encode(&[
            U64_MARKER, be[0], be[1], be[2], be[3], be[4], be[5], be[6], be[7],
        ])
    }
}

impl MborEncode for bool {
    fn mbor_encode(&self, encoder: &mut MborEncoder<'_>) -> Result<(), MborEncodeError> {
        encoder.encode(&[BOOL_MARKER + u8::from(*self)])
    }
}

impl MborEncode for MborByteSlice<'_> {
    fn mbor_encode(&self, encoder: &mut MborEncoder<'_>) -> Result<(), MborEncodeError> {
        let len_be = (self.0.len() as u16).to_be_bytes();
        encoder.encode(&[BYTES_MARKER, len_be[0], len_be[1]])?;
        encoder.encode(self.0)
    }
}

impl MborEncode for MborPaddedByteSlice<'_> {
    fn mbor_encode(&self, encoder: &mut MborEncoder<'_>) -> Result<(), MborEncodeError> {
        let pad = BYTES_PAD_MASK & self.1;
        let len_be = (self.0.len() as u16).to_be_bytes();

        // Fuse marker + length + padding into one write (3–6 bytes).
        let hdr = [BYTES_MARKER | pad, len_be[0], len_be[1], 0, 0, 0];
        encoder.encode(&hdr[..3 + pad as usize])?;

        // Data
        encoder.encode(self.0)
    }
}

/// Encoder for AZIHSM Binary Object Representation (MBOR).
///
/// Operates in one of two modes:
/// - **Checked** (`new`): every `encode()` call validates buffer capacity.
/// - **Trusted** (`new_trusted`): bounds checks are `debug_assert!` only,
///   producing zero branches in release builds. The caller must have
///   pre-computed the total encoded length via [`MborLenAccumulator`] and
///   verified it fits before constructing a trusted encoder.
///
/// When the `trusted-encode` crate feature is enabled, **all** encoders use
/// `debug_assert!`-only bounds checks regardless of constructor, eliminating
/// the runtime branch entirely.
pub struct MborEncoder<'a> {
    buffer: &'a mut [u8],
    pos: usize,
    #[cfg(not(feature = "trusted-encode"))]
    trusted: bool,
}

impl<'a> MborEncoder<'a> {
    /// Create a checked encoder. Every `encode()` call validates that the
    /// write fits in the remaining buffer.
    ///
    /// When the `trusted-encode` feature is enabled, this behaves identically
    /// to [`new_trusted`](Self::new_trusted).
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            pos: 0,
            #[cfg(not(feature = "trusted-encode"))]
            trusted: false,
        }
    }

    /// Create a trusted encoder. Bounds checks are `debug_assert!` only.
    ///
    /// # Safety contract
    ///
    /// The caller **must** have pre-computed the total encoded size via
    /// [`MborLenAccumulator`] and confirmed that it does not exceed
    /// `buffer.len()` before calling this constructor.
    pub fn new_trusted(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            pos: 0,
            #[cfg(not(feature = "trusted-encode"))]
            trusted: true,
        }
    }

    /// Current write position (bytes written so far).
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Remaining capacity in the output buffer.
    pub fn remaining(&self) -> usize {
        self.buffer.len() - self.pos
    }

    /// Write `value` into the output buffer and advance `pos`.
    #[inline(always)]
    pub fn encode(&mut self, value: &[u8]) -> Result<(), MborEncodeError> {
        #[cfg(not(feature = "trusted-encode"))]
        {
            if self.trusted {
                debug_assert!(
                    value.len() + self.pos <= self.buffer.len(),
                    "trusted encode overflow: pos={} len={} cap={}",
                    self.pos,
                    value.len(),
                    self.buffer.len(),
                );
            } else if value.len() + self.pos > self.buffer.len() {
                return Err(MborEncodeError::BufferOverflow);
            }
        }
        #[cfg(feature = "trusted-encode")]
        debug_assert!(
            value.len() + self.pos <= self.buffer.len(),
            "trusted encode overflow: pos={} len={} cap={}",
            self.pos,
            value.len(),
            self.buffer.len(),
        );
        // SAFETY: bounds are guaranteed by the check above (checked mode) or
        // by the caller's upfront length calculation (trusted mode).
        #[allow(unsafe_code)]
        unsafe {
            core::ptr::copy_nonoverlapping(
                value.as_ptr(),
                self.buffer.as_mut_ptr().add(self.pos),
                value.len(),
            );
        }
        self.pos += value.len();
        Ok(())
    }

    /// Write the MBOR byte-array framing and return a mutable slice into the
    /// output buffer where the caller (or a hardware DMA engine) can write
    /// data directly.
    ///
    /// The returned slice starts at a **4-byte-aligned** offset within the
    /// output buffer and has exactly `data_len` bytes.
    ///
    /// Layout written: `[BYTES_MARKER | pad] [len_hi] [len_lo] [0..pad] [-- data_len --]`
    pub fn encode_reserve(
        &mut self,
        data_len: usize,
        pad: u8,
    ) -> Result<&'a mut [u8], MborEncodeError> {
        let pad = BYTES_PAD_MASK & pad;
        let total = 1 + 2 + pad as usize + data_len; // marker + len + pad + data

        #[cfg(not(feature = "trusted-encode"))]
        {
            if self.trusted {
                debug_assert!(
                    total + self.pos <= self.buffer.len(),
                    "trusted encode_reserve overflow",
                );
            } else if total + self.pos > self.buffer.len() {
                return Err(MborEncodeError::BufferOverflow);
            }
        }
        #[cfg(feature = "trusted-encode")]
        debug_assert!(
            total + self.pos <= self.buffer.len(),
            "trusted encode_reserve overflow",
        );

        // Marker with padding bits
        self.buffer[self.pos] = BYTES_MARKER | pad;
        self.pos += 1;

        // 2-byte big-endian length
        let len_be = (data_len as u16).to_be_bytes();
        self.buffer[self.pos] = len_be[0];
        self.buffer[self.pos + 1] = len_be[1];
        self.pos += 2;

        // Padding zero bytes
        for _ in 0..pad {
            self.buffer[self.pos] = 0;
            self.pos += 1;
        }

        // Return mutable slice for the data region.
        let data_start = self.pos;
        self.pos += data_len;

        // SAFETY: we verified above that `self.pos <= self.buffer.len()`.
        // We need to reborrow from the raw pointer to decouple the returned
        // slice lifetime from `&mut self`.
        #[allow(unsafe_code)]
        let slice = unsafe {
            core::slice::from_raw_parts_mut(self.buffer.as_mut_ptr().add(data_start), data_len)
        };

        Ok(slice)
    }

    /// Like [`encode_reserve`](Self::encode_reserve), but returns the byte
    /// range of the reserved data region inside the encoder's buffer
    /// instead of a mutable slice into it.
    ///
    /// Used by the `reserve()` codegen to record per-field offsets in a
    /// layout struct without producing a borrow that would alias the
    /// encoder. Combined with a later `from_layout(buf, &layout)` call,
    /// this lets a caller fill the reserved regions across an `await`
    /// without keeping the encoder alive.
    pub fn reserve_offset(
        &mut self,
        data_len: usize,
        pad: u8,
    ) -> Result<core::ops::Range<usize>, MborEncodeError> {
        let pad = BYTES_PAD_MASK & pad;
        let total = 1 + 2 + pad as usize + data_len;

        #[cfg(not(feature = "trusted-encode"))]
        {
            if self.trusted {
                debug_assert!(
                    total + self.pos <= self.buffer.len(),
                    "trusted reserve_offset overflow",
                );
            } else if total + self.pos > self.buffer.len() {
                return Err(MborEncodeError::BufferOverflow);
            }
        }
        #[cfg(feature = "trusted-encode")]
        debug_assert!(
            total + self.pos <= self.buffer.len(),
            "trusted reserve_offset overflow",
        );

        self.buffer[self.pos] = BYTES_MARKER | pad;
        self.pos += 1;

        let len_be = (data_len as u16).to_be_bytes();
        self.buffer[self.pos] = len_be[0];
        self.buffer[self.pos + 1] = len_be[1];
        self.pos += 2;

        for _ in 0..pad {
            self.buffer[self.pos] = 0;
            self.pos += 1;
        }

        let start = self.pos;
        self.pos += data_len;
        Ok(start..start + data_len)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    extern crate std;

    use std::vec;
    use std::vec::Vec;

    use super::*;

    #[test]
    fn encode_bool() {
        let mut buf = vec![0u8; 1];
        let mut enc = MborEncoder::new(&mut buf);
        true.mbor_encode(&mut enc).unwrap();
        assert_eq!(buf, vec![0x15]);

        let mut buf = vec![0u8; 1];
        let mut enc = MborEncoder::new(&mut buf);
        false.mbor_encode(&mut enc).unwrap();
        assert_eq!(buf, vec![0x14]);
    }

    #[test]
    fn encode_u8() {
        let mut buf = vec![0u8; 2];
        let mut enc = MborEncoder::new(&mut buf);
        42u8.mbor_encode(&mut enc).unwrap();
        assert_eq!(buf, vec![U8_MARKER, 42]);
    }

    #[test]
    fn encode_u16() {
        let mut buf = vec![0u8; 3];
        let mut enc = MborEncoder::new(&mut buf);
        0x1234u16.mbor_encode(&mut enc).unwrap();
        assert_eq!(buf, vec![U16_MARKER, 0x12, 0x34]);
    }

    #[test]
    fn encode_u32() {
        let mut buf = vec![0u8; 5];
        let mut enc = MborEncoder::new(&mut buf);
        0xDEADBEEFu32.mbor_encode(&mut enc).unwrap();
        assert_eq!(buf, vec![U32_MARKER, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn encode_u64() {
        let mut buf = vec![0u8; 9];
        let mut enc = MborEncoder::new(&mut buf);
        1u64.mbor_encode(&mut enc).unwrap();
        assert_eq!(buf, vec![U64_MARKER, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn encode_map() {
        let mut buf = vec![0u8; 1];
        let mut enc = MborEncoder::new(&mut buf);
        MborMap(3).mbor_encode(&mut enc).unwrap();
        assert_eq!(buf, vec![MAP_MARKER | 3]);
    }

    #[test]
    fn encode_byte_slice() {
        let data = [1u8, 2, 3];
        let mut buf = vec![0u8; 6]; // 1 marker + 2 len + 3 data
        let mut enc = MborEncoder::new(&mut buf);
        MborByteSlice(&data).mbor_encode(&mut enc).unwrap();
        assert_eq!(buf, vec![BYTES_MARKER, 0, 3, 1, 2, 3]);
    }

    #[test]
    fn encode_padded_byte_slice() {
        let data = [0xAAu8; 10];
        let mut buf = vec![0u8; 14]; // 1 marker + 2 len + 1 pad + 10 data
        let mut enc = MborEncoder::new(&mut buf);
        MborPaddedByteSlice(&data, 1).mbor_encode(&mut enc).unwrap();
        assert_eq!(enc.position(), 14);
        assert_eq!(buf[0], BYTES_MARKER | 1);
        assert_eq!(&buf[1..3], &[0, 10]); // length
        assert_eq!(buf[3], 0); // pad byte
        assert_eq!(&buf[4..14], &[0xAA; 10]);
    }

    #[test]
    #[cfg(not(feature = "trusted-encode"))]
    fn encode_buffer_overflow() {
        let mut buf = vec![0u8; 1];
        let mut enc = MborEncoder::new(&mut buf);
        let result = 0u32.mbor_encode(&mut enc);
        assert!(result.is_err());
    }

    #[test]
    fn encode_trusted() {
        let mut buf = vec![0u8; 2];
        let mut enc = MborEncoder::new_trusted(&mut buf);
        42u8.mbor_encode(&mut enc).unwrap();
        assert_eq!(buf, vec![U8_MARKER, 42]);
    }

    #[test]
    fn encode_reserve_returns_mutable_slice() {
        let mut buf = vec![0u8; 16];
        let mut enc = MborEncoder::new(&mut buf);
        let slice = enc.encode_reserve(4, 1).unwrap();
        assert_eq!(slice.len(), 4);
        slice.copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(enc.position(), 8); // 1 marker + 2 len + 1 pad + 4 data
        assert_eq!(buf[0], BYTES_MARKER | 1);
        assert_eq!(&buf[1..3], &[0, 4]);
        assert_eq!(buf[3], 0); // pad
        assert_eq!(&buf[4..8], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    fn _encode_to_vec<T: MborEncode>(value: &T) -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        let pos = {
            let mut enc = MborEncoder::new(&mut buf);
            value.mbor_encode(&mut enc).unwrap();
            enc.position()
        };
        buf.truncate(pos);
        buf
    }

    #[test]
    fn encode_multiple_fields() {
        let mut buf = vec![0u8; 32];
        let mut enc = MborEncoder::new(&mut buf);
        MborMap(2).mbor_encode(&mut enc).unwrap();
        0u8.mbor_encode(&mut enc).unwrap();
        42u16.mbor_encode(&mut enc).unwrap();
        1u8.mbor_encode(&mut enc).unwrap();
        true.mbor_encode(&mut enc).unwrap();
        let pos = enc.position();
        // Map(2) + id(0) + u16(42) + id(1) + bool(true)
        // = 1 + 2 + 3 + 2 + 1 = 9
        assert_eq!(pos, 9);
    }
}
