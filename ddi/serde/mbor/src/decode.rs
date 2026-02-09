// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
    InvalidKeyType,
    InvalidKeyData,
    InvalidParameter,
}

impl From<MborByteArrayError> for MborDecodeError {
    fn from(err: MborByteArrayError) -> MborDecodeError {
        match err {
            MborByteArrayError::InvalidLen => MborDecodeError::InvalidLen,
        }
    }
}

/// Trait that decodes an object in Manticore Binary Object Representation (MBOR).
pub trait MborDecode<'b>: Sized {
    /// Decodes the object in MBOR.
    ///
    /// # Arguments
    ///
    /// * `decoder` - Decoder to use.
    ///
    /// # Returns
    ///
    ///
    fn mbor_decode(decoder: &mut MborDecoder<'b>) -> Result<Self, MborDecodeError>;
}

impl MborDecode<'_> for MborMap {
    fn mbor_decode(decoder: &mut MborDecoder) -> Result<Self, MborDecodeError> {
        let byte = decoder.byte()?;
        if byte & MAP_MARKER != MAP_MARKER {
            Err(MborDecodeError::ExpectedMap)?
        }

        Ok(Self(byte & MAP_FIELD_COUNT_MASK))
    }
}

impl MborDecode<'_> for u8 {
    fn mbor_decode(decoder: &mut MborDecoder) -> Result<Self, MborDecodeError> {
        let bytes = decoder.bytes(2)?;
        // Skipping the first byte check (marker) for performance reasons.
        Ok(bytes[1])
    }
}

impl MborDecode<'_> for u16 {
    fn mbor_decode(decoder: &mut MborDecoder) -> Result<Self, MborDecodeError> {
        let bytes = decoder.bytes(3)?;
        // Skipping the first byte check (marker) for performance reasons.
        Ok(u16::from_be_bytes(
            bytes[1..].try_into().or(Err(MborDecodeError::DecodeU16))?,
        ))
    }
}

impl MborDecode<'_> for u32 {
    fn mbor_decode(decoder: &mut MborDecoder) -> Result<Self, MborDecodeError> {
        let bytes = decoder.bytes(5)?;
        // Skipping the first byte check (marker) for performance reasons.
        Ok(u32::from_be_bytes(
            bytes[1..].try_into().or(Err(MborDecodeError::DecodeU32))?,
        ))
    }
}

impl MborDecode<'_> for u64 {
    fn mbor_decode(decoder: &mut MborDecoder) -> Result<Self, MborDecodeError> {
        let bytes = decoder.bytes(9)?;
        // Skipping the first byte check (marker) for performance reasons.
        Ok(u64::from_be_bytes(
            bytes[1..].try_into().or(Err(MborDecodeError::DecodeU64))?,
        ))
    }
}

impl MborDecode<'_> for bool {
    fn mbor_decode(decoder: &mut MborDecoder) -> Result<Self, MborDecodeError> {
        let byte = decoder.byte()? & !BOOL_MARKER;
        match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(MborDecodeError::ExpectedBool),
        }
    }
}

impl<const N: usize> MborDecode<'_> for [u8; N] {
    fn mbor_decode(decoder: &mut MborDecoder) -> Result<Self, MborDecodeError> {
        let marker = decoder.byte()?;
        if marker & BYTES_MARKER != BYTES_MARKER {
            Err(MborDecodeError::ExpectedU8)?
        }

        let pad = marker & BYTES_PAD_MASK;
        if pad != 0 {
            Err(MborDecodeError::InvalidPadding)?
        }

        let len = u16::from_be_bytes(
            decoder
                .bytes(core::mem::size_of::<u16>())?
                .try_into()
                .or(Err(MborDecodeError::DecodeU16))?,
        );

        if len != N as u16 {
            Err(MborDecodeError::InvalidLen)?
        }

        let data = decoder.bytes(len as usize)?;

        data.try_into().or(Err(MborDecodeError::DecodeU8N))
    }
}

#[cfg(feature = "array")]
impl<const N: usize> MborDecode<'_> for MborByteArray<N> {
    fn mbor_decode(decoder: &mut MborDecoder) -> Result<Self, MborDecodeError> {
        let marker = decoder.byte()?;
        if marker & BYTES_MARKER != BYTES_MARKER {
            Err(MborDecodeError::ExpectedU8)?
        }

        let len = u16::from_be_bytes(
            decoder
                .bytes(core::mem::size_of::<u16>())?
                .try_into()
                .or(Err(MborDecodeError::DecodeU16))?,
        );

        if len > N as u16 {
            Err(MborDecodeError::BufferUnderFlow)?
        }

        let pad = marker & BYTES_PAD_MASK;
        decoder.skip(pad as usize)?;

        let data = decoder.bytes(len as usize)?;

        let mut bytes = [0; N];
        bytes[..len as usize].copy_from_slice(data);

        Ok(Self::new(bytes, len as usize)?)
    }
}

#[cfg(not(feature = "array"))]
impl<const N: usize> MborDecode<'_> for MborByteArray<N> {
    fn mbor_decode(decoder: &mut MborDecoder) -> Result<Self, MborDecodeError> {
        let marker = decoder.byte()?;
        if marker & BYTES_MARKER != BYTES_MARKER {
            Err(MborDecodeError::ExpectedU8)?
        }

        let len = u16::from_be_bytes(
            decoder
                .bytes(core::mem::size_of::<u16>())?
                .try_into()
                .or(Err(MborDecodeError::DecodeU16))?,
        );

        if len > N as u16 {
            Err(MborDecodeError::BufferUnderFlow)?
        }

        let pad = marker & BYTES_PAD_MASK;
        decoder.skip(pad as usize)?;

        let arr = Self::new_with_len(decoder.addr(), len as usize)?;
        decoder.skip(len as usize)?;

        Ok(arr)
    }
}

/// Decoder for MBOR.
pub struct MborDecoder<'a> {
    buffer: &'a [u8],
    pos: usize,
    #[cfg(feature = "post_decode")]
    post_decode: bool,
}

impl<'a> MborDecoder<'a> {
    pub fn new(buf: &'a [u8], #[cfg(feature = "post_decode")] post_decode: bool) -> Self {
        Self {
            buffer: buf,
            pos: 0,
            #[cfg(feature = "post_decode")]
            post_decode,
        }
    }

    #[cfg(feature = "post_decode")]
    pub fn post_decode(&self) -> bool {
        self.post_decode
    }

    fn byte(&mut self) -> Result<u8, MborDecodeError> {
        const LEN: usize = core::mem::size_of::<u8>();
        Ok(self.bytes(LEN)?[0])
    }

    #[inline(always)]
    fn bytes(&mut self, len: usize) -> Result<&'a [u8], MborDecodeError> {
        if len + self.pos > self.buffer.len() {
            Err(MborDecodeError::BufferUnderFlow)?
        }

        let bytes = &self.buffer[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    fn skip(&mut self, len: usize) -> Result<(), MborDecodeError> {
        if len + self.pos > self.buffer.len() {
            Err(MborDecodeError::BufferUnderFlow)?
        }

        self.pos += len;
        Ok(())
    }

    #[cfg(not(feature = "array"))]
    fn addr(&self) -> *const u8 {
        unsafe { self.buffer.as_ptr().add(self.pos) }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn peek_u8(&mut self) -> Option<u8> {
        if let Ok(bytes) = self.bytes(2) {
            // Skipping the first byte check (marker) for performance reasons.
            self.pos -= 2;
            Some(bytes[1])
        } else {
            None
        }
    }

    pub fn peek_byte(&mut self) -> Option<u8> {
        if let Ok(byte) = self.byte() {
            self.pos -= 1;
            Some(byte)
        } else {
            None
        }
    }
}
