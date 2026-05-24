// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_hsm_pal_traits::DmaBuf;

use crate::*;

/// Error type for MBOR decoding.
#[derive(Debug)]
pub enum MborDecodeError {
    BufferUnderFlow,
    ExpectedMap,
    ExpectedU8,
    ExpectedU16,
    ExpectedU32,
    ExpectedBool,
    DecodeU8,
    DecodeU16,
    DecodeU32,
    DecodeU64,
    DecodeU8N,
    InvalidId,
    InvalidLen,
    InvalidPadding,
    InvalidParameter,
}

impl From<MborDecodeError> for azihsm_fw_hsm_pal_traits::HsmError {
    #[inline]
    fn from(_: MborDecodeError) -> Self {
        Self::DdiDecodeFailed
    }
}

/// Trait that decodes an object in AZIHSM Binary Object Representation
/// (MBOR).
pub trait MborDecode<'b>: Sized {
    /// Decodes the object from the given decoder.
    fn mbor_decode(decoder: &mut MborDecoder<'b>) -> Result<Self, MborDecodeError>;
}

impl MborDecode<'_> for MborMap {
    fn mbor_decode(decoder: &mut MborDecoder<'_>) -> Result<Self, MborDecodeError> {
        let byte = decoder.byte()?;
        if byte & MAP_MARKER != MAP_MARKER {
            return Err(MborDecodeError::ExpectedMap);
        }
        Ok(Self(byte & MAP_FIELD_COUNT_MASK))
    }
}

impl MborDecode<'_> for u8 {
    fn mbor_decode(decoder: &mut MborDecoder<'_>) -> Result<Self, MborDecodeError> {
        let bytes = decoder.bytes(2)?;
        // Skipping the first byte check (marker) for performance reasons.
        Ok(bytes[1])
    }
}

impl MborDecode<'_> for u16 {
    fn mbor_decode(decoder: &mut MborDecoder<'_>) -> Result<Self, MborDecodeError> {
        let bytes: &[u8] = decoder.bytes(3)?;
        // Skipping the first byte check (marker) for performance reasons.
        Ok(u16::from_be_bytes(
            bytes[1..].try_into().or(Err(MborDecodeError::DecodeU16))?,
        ))
    }
}

impl MborDecode<'_> for u32 {
    fn mbor_decode(decoder: &mut MborDecoder<'_>) -> Result<Self, MborDecodeError> {
        let bytes: &[u8] = decoder.bytes(5)?;
        // Skipping the first byte check (marker) for performance reasons.
        Ok(u32::from_be_bytes(
            bytes[1..].try_into().or(Err(MborDecodeError::DecodeU32))?,
        ))
    }
}

impl MborDecode<'_> for u64 {
    fn mbor_decode(decoder: &mut MborDecoder<'_>) -> Result<Self, MborDecodeError> {
        let bytes: &[u8] = decoder.bytes(9)?;
        // Skipping the first byte check (marker) for performance reasons.
        Ok(u64::from_be_bytes(
            bytes[1..].try_into().or(Err(MborDecodeError::DecodeU64))?,
        ))
    }
}

impl MborDecode<'_> for bool {
    fn mbor_decode(decoder: &mut MborDecoder<'_>) -> Result<Self, MborDecodeError> {
        let byte = decoder.byte()? & !BOOL_MARKER;
        match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(MborDecodeError::ExpectedBool),
        }
    }
}

impl<const N: usize> MborDecode<'_> for [u8; N] {
    fn mbor_decode(decoder: &mut MborDecoder<'_>) -> Result<Self, MborDecodeError> {
        let marker = decoder.byte()?;
        if marker & BYTES_MARKER != BYTES_MARKER {
            return Err(MborDecodeError::ExpectedU8);
        }

        let pad = marker & BYTES_PAD_MASK;
        if pad != 0 {
            return Err(MborDecodeError::InvalidPadding);
        }

        let len_bytes: &[u8] = decoder.bytes(core::mem::size_of::<u16>())?;
        let len = u16::from_be_bytes(len_bytes.try_into().or(Err(MborDecodeError::DecodeU16))?);

        if len != N as u16 {
            return Err(MborDecodeError::InvalidLen);
        }

        let data: &[u8] = decoder.bytes(len as usize)?;

        data.try_into().or(Err(MborDecodeError::DecodeU8N))
    }
}

/// Decoder for AZIHSM Binary Object Representation (MBOR).
///
/// Borrows the input buffer and returns sub-slices on decode, enabling
/// zero-copy access to byte array fields.
pub struct MborDecoder<'a> {
    buffer: &'a DmaBuf,
    pos: usize,
}

impl<'a> MborDecoder<'a> {
    /// Create a new decoder over `buf`.
    pub fn new(buf: &'a DmaBuf) -> Self {
        Self {
            buffer: buf,
            pos: 0,
        }
    }

    /// Current read position (bytes consumed so far).
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Peek at the next MBOR-encoded `u8` value without consuming it.
    /// Returns `None` if there are fewer than 2 bytes remaining.
    pub fn peek_u8(&mut self) -> Option<u8> {
        if let Ok(bytes) = self.bytes(2) {
            // Skipping the first byte check (marker) for performance reasons.
            self.pos -= 2;
            Some(bytes[1])
        } else {
            None
        }
    }

    /// Peek at the next raw byte without consuming it.
    /// Returns `None` if the buffer is exhausted.
    pub fn peek_byte(&mut self) -> Option<u8> {
        if let Ok(byte) = self.byte() {
            self.pos -= 1;
            Some(byte)
        } else {
            None
        }
    }

    /// Decode a variable-length byte field and return a borrowed sub-slice
    /// of the input buffer (zero-copy). Accepts and skips padding.
    ///
    /// Returns `(padding, data_slice)`.
    pub fn decode_byte_slice(&mut self) -> Result<(u8, &'a DmaBuf), MborDecodeError> {
        let marker = self.byte()?;
        if marker & BYTES_MARKER != BYTES_MARKER {
            return Err(MborDecodeError::ExpectedU8);
        }

        let pad = marker & BYTES_PAD_MASK;

        let len_bytes: &[u8] = self.bytes(core::mem::size_of::<u16>())?;
        let len = u16::from_be_bytes(len_bytes.try_into().or(Err(MborDecodeError::DecodeU16))?);

        // Skip padding bytes
        self.skip(pad as usize)?;

        // Return borrowed slice — zero-copy
        let data = self.bytes(len as usize)?;
        Ok((pad, data))
    }

    /// Decode a fixed-length byte field with no padding (zero-copy).
    ///
    /// Rejects any padding in the marker and verifies the length matches
    /// `expected_len` exactly. This mirrors the old `[u8; N]` decode
    /// behavior.
    pub fn decode_byte_slice_exact(
        &mut self,
        expected_len: usize,
    ) -> Result<&'a DmaBuf, MborDecodeError> {
        let marker = self.byte()?;
        if marker & BYTES_MARKER != BYTES_MARKER {
            return Err(MborDecodeError::ExpectedU8);
        }

        let pad = marker & BYTES_PAD_MASK;
        if pad != 0 {
            return Err(MborDecodeError::InvalidPadding);
        }

        let len_bytes: &[u8] = self.bytes(core::mem::size_of::<u16>())?;
        let len = u16::from_be_bytes(len_bytes.try_into().or(Err(MborDecodeError::DecodeU16))?);

        if len as usize != expected_len {
            return Err(MborDecodeError::InvalidLen);
        }

        self.bytes(len as usize)
    }

    // ── Private helpers ────────────────────────────────────────────

    pub(crate) fn byte(&mut self) -> Result<u8, MborDecodeError> {
        const LEN: usize = core::mem::size_of::<u8>();
        Ok(self.bytes(LEN)?[0])
    }

    #[inline(always)]
    pub(crate) fn bytes(&mut self, len: usize) -> Result<&'a DmaBuf, MborDecodeError> {
        if len + self.pos > self.buffer.len() {
            return Err(MborDecodeError::BufferUnderFlow);
        }
        let bytes = &self.buffer[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    pub(crate) fn skip(&mut self, len: usize) -> Result<(), MborDecodeError> {
        if len + self.pos > self.buffer.len() {
            return Err(MborDecodeError::BufferUnderFlow);
        }
        self.pos += len;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, unsafe_code)]
mod tests {
    extern crate std;

    use core::ops::Deref;

    use super::*;

    /// In tests, local arrays aren't DMA memory, but we need `&DmaBuf`
    /// to construct a decoder. This is safe in tests — no real DMA hw.
    fn dma(buf: &[u8]) -> &DmaBuf {
        // SAFETY: In tests, no real DMA hardware is involved. The
        // `DmaBuf::from_raw` transmute is safe because the data is only
        // read by the decoder, not submitted to a DMA engine.
        unsafe { DmaBuf::from_raw(buf) }
    }

    #[test]
    fn decode_bool() {
        let buf = [0x15]; // true
        let mut dec = MborDecoder::new(dma(&buf));
        assert!(bool::mbor_decode(&mut dec).unwrap());

        let buf = [0x14]; // false
        let mut dec = MborDecoder::new(dma(&buf));
        assert!(!bool::mbor_decode(&mut dec).unwrap());
    }

    #[test]
    fn decode_u8() {
        let buf = [U8_MARKER, 42];
        let mut dec = MborDecoder::new(dma(&buf));
        assert_eq!(u8::mbor_decode(&mut dec).unwrap(), 42);
    }

    #[test]
    fn decode_u16() {
        let buf = [U16_MARKER, 0x12, 0x34];
        let mut dec = MborDecoder::new(dma(&buf));
        assert_eq!(u16::mbor_decode(&mut dec).unwrap(), 0x1234);
    }

    #[test]
    fn decode_u32() {
        let buf = [U32_MARKER, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut dec = MborDecoder::new(dma(&buf));
        assert_eq!(u32::mbor_decode(&mut dec).unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn decode_u64() {
        let buf = [U64_MARKER, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut dec = MborDecoder::new(dma(&buf));
        assert_eq!(u64::mbor_decode(&mut dec).unwrap(), 1);
    }

    #[test]
    fn decode_map() {
        let buf = [MAP_MARKER | 5];
        let mut dec = MborDecoder::new(dma(&buf));
        let m = MborMap::mbor_decode(&mut dec).unwrap();
        assert_eq!(m.0, 5);
    }

    #[test]
    fn decode_fixed_array() {
        let buf = [BYTES_MARKER, 0, 3, 0xAA, 0xBB, 0xCC];
        let mut dec = MborDecoder::new(dma(&buf));
        let arr: [u8; 3] = MborDecode::mbor_decode(&mut dec).unwrap();
        assert_eq!(arr, [0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn decode_byte_slice_zero_copy() {
        let buf = [BYTES_MARKER, 0, 4, 1, 2, 3, 4];
        let mut dec = MborDecoder::new(dma(&buf));
        let (pad, slice) = dec.decode_byte_slice().unwrap();
        assert_eq!(pad, 0);
        assert_eq!(slice.deref(), &[1, 2, 3, 4]);
        assert_eq!(slice.as_ptr(), buf[3..].as_ptr());
    }

    #[test]
    fn decode_byte_slice_with_padding() {
        // marker=0x81 (pad=1), len=3, pad_byte=0, data=[0xAA, 0xBB, 0xCC]
        let buf = [BYTES_MARKER | 1, 0, 3, 0, 0xAA, 0xBB, 0xCC];
        let mut dec = MborDecoder::new(dma(&buf));
        let (pad, slice) = dec.decode_byte_slice().unwrap();
        assert_eq!(pad, 1);
        assert_eq!(slice.deref(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn decode_buffer_underflow() {
        let buf = [U32_MARKER, 0xDE]; // too short for u32
        let mut dec = MborDecoder::new(dma(&buf));
        assert!(u32::mbor_decode(&mut dec).is_err());
    }

    #[test]
    fn peek_u8_does_not_consume() {
        let buf = [U8_MARKER, 99];
        let mut dec = MborDecoder::new(dma(&buf));
        assert_eq!(dec.peek_u8(), Some(99));
        assert_eq!(dec.position(), 0);
        assert_eq!(u8::mbor_decode(&mut dec).unwrap(), 99);
    }

    #[test]
    fn peek_byte_does_not_consume() {
        let buf = [MAP_MARKER | 2];
        let mut dec = MborDecoder::new(dma(&buf));
        assert_eq!(dec.peek_byte(), Some(MAP_MARKER | 2));
        assert_eq!(dec.position(), 0);
    }

    // ── decode_byte_slice_exact tests ──────────────────────────────

    #[test]
    fn decode_byte_slice_exact_ok() {
        // No padding, len=4, data=[1,2,3,4]
        let buf = [BYTES_MARKER, 0, 4, 1, 2, 3, 4];
        let mut dec = MborDecoder::new(dma(&buf));
        let slice = dec.decode_byte_slice_exact(4).unwrap();
        assert_eq!(slice.deref(), &[1, 2, 3, 4]);
        assert_eq!(slice.as_ptr(), buf[3..].as_ptr());
    }

    #[test]
    fn decode_byte_slice_exact_wrong_len() {
        // Data is 4 bytes but we expect 3
        let buf = [BYTES_MARKER, 0, 4, 1, 2, 3, 4];
        let mut dec = MborDecoder::new(dma(&buf));
        assert!(dec.decode_byte_slice_exact(3).is_err());
    }

    #[test]
    fn decode_byte_slice_exact_rejects_padding() {
        // marker=0x81 (pad=1) — exact decode rejects padding
        let buf = [BYTES_MARKER | 1, 0, 3, 0, 0xAA, 0xBB, 0xCC];
        let mut dec = MborDecoder::new(dma(&buf));
        assert!(dec.decode_byte_slice_exact(3).is_err());
    }

    // ── Round-trip tests: encode then decode ───────────────────────

    #[test]
    fn roundtrip_byte_slice_no_padding() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut buf = [0u8; 16];
        let mut enc = crate::MborEncoder::new(&mut buf);
        crate::MborByteSlice(&data).mbor_encode(&mut enc).unwrap();
        let pos = enc.position();

        let mut dec = MborDecoder::new(dma(&buf[..pos]));
        let slice = dec.decode_byte_slice_exact(4).unwrap();
        assert_eq!(slice.deref(), &data);
    }

    #[test]
    fn roundtrip_byte_slice_with_padding() {
        let data = [0xAA; 10];
        let mut buf = [0u8; 32];
        let mut enc = crate::MborEncoder::new(&mut buf);
        crate::MborPaddedByteSlice(&data, 1)
            .mbor_encode(&mut enc)
            .unwrap();
        let pos = enc.position();

        let mut dec = MborDecoder::new(dma(&buf[..pos]));
        let (pad, slice) = dec.decode_byte_slice().unwrap();
        assert_eq!(pad, 1);
        assert_eq!(slice.deref(), &data);
    }

    #[test]
    fn padded_encode_rejected_by_exact_decode() {
        let data = [0xBB; 8];
        let mut buf = [0u8; 32];
        let mut enc = crate::MborEncoder::new(&mut buf);
        crate::MborPaddedByteSlice(&data, 2)
            .mbor_encode(&mut enc)
            .unwrap();
        let pos = enc.position();

        let mut dec = MborDecoder::new(dma(&buf[..pos]));
        assert!(dec.decode_byte_slice_exact(8).is_err());
    }

    #[test]
    fn unpadded_encode_accepted_by_variable_decode() {
        let data = [0xCC; 6];
        let mut buf = [0u8; 16];
        let mut enc = crate::MborEncoder::new(&mut buf);
        crate::MborByteSlice(&data).mbor_encode(&mut enc).unwrap();
        let pos = enc.position();

        let mut dec = MborDecoder::new(dma(&buf[..pos]));
        let (pad, slice) = dec.decode_byte_slice().unwrap();
        assert_eq!(pad, 0);
        assert_eq!(slice.deref(), &data);
    }
}
