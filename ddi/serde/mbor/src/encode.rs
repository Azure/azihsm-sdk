// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::*;

/// Error type for MBOR encoding.
#[derive(Debug)]
pub enum MborEncodeError {
    BufferOverflow,
    DerDecodeFailed,
    InvalidLen,
    InvalidParameter,
}

impl From<MborByteArrayError> for MborEncodeError {
    fn from(err: MborByteArrayError) -> MborEncodeError {
        match err {
            MborByteArrayError::InvalidLen => MborEncodeError::InvalidLen,
        }
    }
}

/// Trait that encodes an object in Manticore Binary Object Representation (MBOR).
pub trait MborEncode {
    /// Encodes the object in MBOR.
    ///
    /// # Arguments
    ///
    /// * `encoder` - Encoder to use.
    fn mbor_encode(&self, encoder: &mut MborEncoder) -> Result<(), MborEncodeError>;
}

impl MborEncode for MborMap {
    fn mbor_encode(&self, encoder: &mut MborEncoder) -> Result<(), MborEncodeError> {
        encoder.encode(&[MAP_MARKER | (MAP_FIELD_COUNT_MASK & self.0)])
    }
}

impl MborEncode for u8 {
    fn mbor_encode(&self, encoder: &mut MborEncoder) -> Result<(), MborEncodeError> {
        // Encode marker
        encoder.encode(&[U8_MARKER])?;

        // Encode data
        encoder.encode(&[*self])
    }
}

impl MborEncode for u16 {
    fn mbor_encode(&self, encoder: &mut MborEncoder) -> Result<(), MborEncodeError> {
        // Encode marker
        encoder.encode(&[U16_MARKER])?;

        // Encode data
        encoder.encode(&self.to_be_bytes())
    }
}

impl MborEncode for u32 {
    fn mbor_encode(&self, encoder: &mut MborEncoder) -> Result<(), MborEncodeError> {
        // Encode marker
        encoder.encode(&[U32_MARKER])?;

        // Encode data
        encoder.encode(&self.to_be_bytes())
    }
}

impl MborEncode for u64 {
    fn mbor_encode(&self, encoder: &mut MborEncoder) -> Result<(), MborEncodeError> {
        // Encode marker
        encoder.encode(&[U64_MARKER])?;

        // Encode data
        encoder.encode(&self.to_be_bytes())
    }
}

impl MborEncode for bool {
    fn mbor_encode(&self, encoder: &mut MborEncoder) -> Result<(), MborEncodeError> {
        encoder.encode(&[BOOL_MARKER + u8::from(*self)])
    }
}

impl MborEncode for MborByteSlice<'_> {
    fn mbor_encode(&self, encoder: &mut MborEncoder) -> Result<(), MborEncodeError> {
        // Encode marker
        encoder.encode(&[BYTES_MARKER])?;

        // Encode length
        encoder.encode(&(self.0.len() as u16).to_be_bytes())?;

        // Encode data
        encoder.encode(self.0)
    }
}

#[cfg(feature = "array")]
impl<const N: usize> MborEncode for MborPaddedByteArray<'_, N> {
    fn mbor_encode(&self, encoder: &mut MborEncoder) -> Result<(), MborEncodeError> {
        if self.0.len > N {
            Err(MborEncodeError::BufferOverflow)?
        }
        let pad = BYTES_PAD_MASK & self.1;

        // Encode marker and padding
        encoder.encode(&[BYTES_MARKER | pad])?;

        // Encode length
        encoder.encode(&(self.0.len as u16).to_be_bytes())?;

        // Encode padding
        for _ in 0..pad {
            encoder.encode(&[0])?;
        }

        #[cfg(test)]
        assert_eq!(encoder.position() % 4, 0);

        // Encode data
        encoder.encode(&self.0.data[..self.0.len])
    }
}

#[cfg(not(feature = "array"))]
impl<const N: usize> MborEncode for MborPaddedByteArray<'_, N> {
    fn mbor_encode(&self, encoder: &mut MborEncoder) -> Result<(), MborEncodeError> {
        if self.0.len() > N {
            Err(MborEncodeError::BufferOverflow)?
        }
        let pad = BYTES_PAD_MASK & self.1;

        // Encode marker and padding
        encoder.encode(&[BYTES_MARKER | pad])?;

        // Encode length
        encoder.encode(&(self.0.len() as u16).to_be_bytes())?;

        // Encode padding
        for _ in 0..pad {
            encoder.encode(&[0])?;
        }

        #[cfg(test)]
        assert_eq!(encoder.position() % 4, 0);

        // Encode data
        let data_ptr = self.0.ptr();
        self.0.set_ptr(encoder.addr());
        if data_ptr.is_null() {
            encoder.skip(self.0.len())
        } else {
            let data = unsafe { core::slice::from_raw_parts(data_ptr, self.0.len()) };
            encoder.encode(data)
        }
    }
}

/// Encoder for Manticore Binary Object Representation (MBOR).
pub struct MborEncoder<'a> {
    buffer: &'a mut [u8],
    pos: usize,
    #[cfg(feature = "pre_encode")]
    pre_encode: bool,
}

impl MborEncoder<'_> {
    pub fn new(
        buffer: &mut [u8],
        #[cfg(feature = "pre_encode")] pre_encode: bool,
    ) -> MborEncoder<'_> {
        MborEncoder {
            buffer,
            pos: 0,
            #[cfg(feature = "pre_encode")]
            pre_encode,
        }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buffer.len() - self.position()
    }

    #[cfg(feature = "pre_encode")]
    pub fn pre_encode(&self) -> bool {
        self.pre_encode
    }

    #[cfg(not(feature = "array"))]
    fn addr(&self) -> *const u8 {
        unsafe { self.buffer.as_ptr().add(self.pos) }
    }

    #[cfg(not(feature = "array"))]
    fn skip(&mut self, len: usize) -> Result<(), MborEncodeError> {
        if len + self.pos > self.buffer.len() {
            Err(MborEncodeError::BufferOverflow)?
        }
        self.pos += len;
        Ok(())
    }

    #[inline(always)]
    fn encode(&mut self, value: &[u8]) -> Result<(), MborEncodeError> {
        if value.len() + self.pos > self.buffer.len() {
            Err(MborEncodeError::BufferOverflow)?
        }
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
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;
    #[cfg(not(feature = "array"))]
    use core::ptr::null;

    use super::*;

    #[test]
    fn test_mbor_bool() {
        let mut buf = vec![0u8; 1];
        #[cfg(feature = "pre_encode")]
        let mut encoder = MborEncoder::new(&mut buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let mut encoder = MborEncoder::new(&mut buf);
        true.mbor_encode(&mut encoder).unwrap();
        assert_eq!(encoder.position(), 1);
        assert_eq!(buf, vec![0x15]);

        #[cfg(feature = "post_decode")]
        let mut decoder = MborDecoder::new(&buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = MborDecoder::new(&buf);
        let decoded = bool::mbor_decode(&mut decoder).unwrap();
        assert!(decoded);

        let mut buf = vec![0u8; 1];
        #[cfg(feature = "pre_encode")]
        let mut encoder = MborEncoder::new(&mut buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let mut encoder = MborEncoder::new(&mut buf);
        false.mbor_encode(&mut encoder).unwrap();
        assert_eq!(encoder.position(), 1);
        assert_eq!(buf, vec![0x14]);

        #[cfg(feature = "post_decode")]
        let mut decoder = MborDecoder::new(&buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = MborDecoder::new(&buf);
        let decoded = bool::mbor_decode(&mut decoder).unwrap();
        assert!(!decoded);
    }

    #[test]
    fn test_mbor_array_null() {
        #[cfg(feature = "array")]
        let data = { MborByteArray::new([0; 10], 10).expect("Failed to initialize MborByteArray") };
        #[cfg(not(feature = "array"))]
        let data =
            { MborByteArray::<10>::new(null()).expect("Failed to initialize MborByteArray") };
        let arr = MborPaddedByteArray(&data, 1);
        let mut acc = MborLenAccumulator::default();
        arr.mbor_len(&mut acc);
        let mut buf = vec![0u8; acc.len()];
        #[cfg(feature = "pre_encode")]
        let mut encoder = MborEncoder::new(&mut buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let mut encoder = MborEncoder::new(&mut buf);
        arr.mbor_encode(&mut encoder).unwrap();
        assert_eq!(encoder.position(), buf.len());
        assert_eq!(
            buf,
            [0x81, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]
        );

        #[cfg(feature = "post_decode")]
        let mut decoder = MborDecoder::new(&buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = MborDecoder::new(&buf);
        let decoded = MborByteArray::mbor_decode(&mut decoder).unwrap();
        assert!(arr.0 == &decoded);
    }

    #[test]
    fn test_mbor_array_not_null() {
        #[cfg(feature = "array")]
        let data =
            { MborByteArray::new([0x3; 10], 10).expect("Failed to initialize MborByteArray") };
        #[cfg(not(feature = "array"))]
        let data_src = [0x3u8; 10];
        #[cfg(not(feature = "array"))]
        let data = {
            MborByteArray::<10>::new_with_len(data_src.as_ptr(), data_src.len())
                .expect("Failed to initialize MborByteArray")
        };
        let arr = MborPaddedByteArray(&data, 1);
        let mut acc = MborLenAccumulator::default();
        arr.mbor_len(&mut acc);
        let mut buf = vec![0u8; acc.len()];
        #[cfg(feature = "pre_encode")]
        let mut encoder = MborEncoder::new(&mut buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let mut encoder = MborEncoder::new(&mut buf);
        arr.mbor_encode(&mut encoder).unwrap();
        assert_eq!(encoder.position(), buf.len());
        assert_eq!(
            buf,
            [0x81, 0x0, 0xa, 0x0, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3]
        );

        #[cfg(feature = "post_decode")]
        let mut decoder = MborDecoder::new(&buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = MborDecoder::new(&buf);
        let decoded = MborByteArray::mbor_decode(&mut decoder).unwrap();
        assert!(arr.0 == &decoded);
    }

    #[test]
    fn test_mbor_u8() {
        let data = 12u8;

        let mut buf = vec![0u8; 2];
        #[cfg(feature = "pre_encode")]
        let mut encoder = MborEncoder::new(&mut buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let mut encoder = MborEncoder::new(&mut buf);
        data.mbor_encode(&mut encoder).unwrap();
        let mut acc = MborLenAccumulator::default();
        data.mbor_len(&mut acc);
        assert_eq!(acc.len(), 2);
        assert_eq!(encoder.position(), 2);
        assert_eq!(buf, vec![U8_MARKER, 12]);

        #[cfg(feature = "post_decode")]
        let mut decoder = MborDecoder::new(&buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = MborDecoder::new(&buf);
        let decoded = u8::mbor_decode(&mut decoder).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_mbor_u16() {
        let data = 1234u16;

        let mut buf = vec![0u8; 3];
        #[cfg(feature = "pre_encode")]
        let mut encoder = MborEncoder::new(&mut buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let mut encoder = MborEncoder::new(&mut buf);
        data.mbor_encode(&mut encoder).unwrap();
        let mut acc = MborLenAccumulator::default();
        data.mbor_len(&mut acc);
        assert_eq!(acc.len(), 3);
        assert_eq!(encoder.position(), 3);
        assert_eq!(buf, vec![U16_MARKER, 0x04, 0xD2]);

        #[cfg(feature = "post_decode")]
        let mut decoder = MborDecoder::new(&buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = MborDecoder::new(&buf);
        let decoded = u16::mbor_decode(&mut decoder).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_mbor_u32() {
        let data = 123456789u32;

        let mut buf = vec![0u8; 5];
        #[cfg(feature = "pre_encode")]
        let mut encoder = MborEncoder::new(&mut buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let mut encoder = MborEncoder::new(&mut buf);
        data.mbor_encode(&mut encoder).unwrap();
        let mut acc = MborLenAccumulator::default();
        data.mbor_len(&mut acc);
        assert_eq!(acc.len(), 5);
        assert_eq!(encoder.position(), 5);
        assert_eq!(buf, vec![U32_MARKER, 0x07, 0x5B, 0xCD, 0x15]);

        #[cfg(feature = "post_decode")]
        let mut decoder = MborDecoder::new(&buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = MborDecoder::new(&buf);
        let decoded = u32::mbor_decode(&mut decoder).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_mbor_u64() {
        let data = 1234567890123456789u64;

        let mut buf = vec![0u8; 9];
        #[cfg(feature = "pre_encode")]
        let mut encoder = MborEncoder::new(&mut buf, true);
        #[cfg(not(feature = "pre_encode"))]
        let mut encoder = MborEncoder::new(&mut buf);
        data.mbor_encode(&mut encoder).unwrap();
        let mut acc = MborLenAccumulator::default();
        data.mbor_len(&mut acc);
        assert_eq!(acc.len(), 9);
        assert_eq!(encoder.position(), 9);
        assert_eq!(
            buf,
            vec![U64_MARKER, 0x11, 0x22, 0x10, 0xF4, 0x7D, 0xE9, 0x81, 0x15]
        );

        #[cfg(feature = "post_decode")]
        let mut decoder = MborDecoder::new(&buf, true);
        #[cfg(not(feature = "post_decode"))]
        let mut decoder = MborDecoder::new(&buf);
        let decoded = u64::mbor_decode(&mut decoder).unwrap();
        assert_eq!(decoded, data);
    }
}
