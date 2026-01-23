// Copyright (C) Microsoft Corporation. All rights reserved.

use std::mem::ManuallyDrop;

/// Character (single-byte for non-Windows)
#[cfg(not(target_os = "windows"))]
pub type AzihsmChar = u8;

/// Wide character (UTF-16 for Windows)
#[cfg(target_os = "windows")]
pub type AzihsmWideChar = u16;

/// String
#[repr(C)]
pub struct AzihsmStr {
    /// Pointer to the string
    #[cfg(not(target_os = "windows"))]
    pub str: *mut AzihsmChar,

    /// Pointer to the string
    #[cfg(target_os = "windows")]
    pub str: *mut AzihsmWideChar,

    /// Length of the string (including null terminator)
    pub len: u32,
}

impl Drop for AzihsmStr {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if !self.str.is_null() {
            // Recreate the Vec from the raw pointer and drop it
            //
            // Safety: `self.str` is not null
            let _ = unsafe { Vec::from_raw_parts(self.str, self.len as usize, self.len as usize) };
        }
    }
}

impl AzihsmStr {
    pub(crate) fn from_string(s: &str) -> Self {
        let mut str = Vec::with_capacity(s.len() + 1);
        str.extend(
            #[cfg(target_os = "windows")]
            s.encode_utf16()
                .map(|c| c as AzihsmWideChar)
                .chain(std::iter::once(0 as AzihsmWideChar)),
            #[cfg(not(target_os = "windows"))]
            s.bytes()
                .map(|b| b as AzihsmChar)
                .chain(std::iter::once(0 as AzihsmChar)),
        );

        debug_assert_eq!(str.len(), str.capacity());

        let mut str = ManuallyDrop::new(str);

        AzihsmStr {
            str: str.as_mut_ptr(),
            len: str.len() as u32,
        }
    }

    #[allow(clippy::inherent_to_string)]
    pub(crate) fn to_string(&self) -> String {
        // Safety: `self.str` is not null
        #[allow(unsafe_code)]
        unsafe {
            #[cfg(target_os = "windows")]
            let str = String::from_utf16_lossy(std::slice::from_raw_parts(
                self.str as *const u16,
                self.len as usize - 1,
            ));
            #[cfg(not(target_os = "windows"))]
            let str = String::from_utf8_lossy(std::slice::from_raw_parts(
                self.str as *const u8,
                self.len as usize - 1,
            ))
            .into_owned();
            str
        }
    }

    pub(crate) fn is_null(&self) -> bool {
        self.str.is_null() || self.len <= 1
    }

    /// Returns the raw byte representation of the string.
    ///
    /// On Windows, this returns the UTF-16 encoded string as bytes (2 bytes per character).
    /// On non-Windows platforms, this returns the UTF-8 encoded string as bytes.
    ///
    /// The returned slice includes the null terminator.
    ///
    /// # Returns
    ///
    /// A byte slice containing the platform-specific string encoding:
    /// - Windows: UTF-16LE byte representation (cast from `u16` to `u8`)
    /// - Non-Windows: UTF-8 byte representation
    ///
    /// Returns an empty slice if the string pointer is null or the length is 0.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        // Guard against null pointer or invalid length to prevent UB
        if self.str.is_null() || self.len == 0 {
            return &[];
        }

        // Safety: We've checked that `self.str` is not null and `self.len > 0`
        #[allow(unsafe_code)]
        unsafe {
            #[cfg(target_os = "windows")]
            {
                std::slice::from_raw_parts(
                    self.str as *const u8,
                    self.len as usize * std::mem::size_of::<AzihsmWideChar>(),
                )
            }
            #[cfg(not(target_os = "windows"))]
            {
                std::slice::from_raw_parts(self.str as *const AzihsmChar, self.len as usize)
            }
        }
    }
}
