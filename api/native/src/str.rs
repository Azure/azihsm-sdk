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
        str.shrink_to_fit();
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_len_including_nul(s: &str) -> usize {
        #[cfg(target_os = "windows")]
        {
            s.encode_utf16().count() + 1
        }
        #[cfg(not(target_os = "windows"))]
        {
            s.len() + 1
        }
    }

    fn assert_trailing_nul(az: &AzihsmStr) {
        assert!(!az.str.is_null());
        assert!(az.len > 0);

        // Safety:
        #[allow(unsafe_code)]
        unsafe {
            #[cfg(target_os = "windows")]
            {
                let slice =
                    std::slice::from_raw_parts(az.str as *const AzihsmWideChar, az.len as usize);
                assert_eq!(slice[az.len as usize - 1], 0);
            }

            #[cfg(not(target_os = "windows"))]
            {
                let slice =
                    std::slice::from_raw_parts(az.str as *const AzihsmChar, az.len as usize);
                assert_eq!(slice[az.len as usize - 1], 0);
            }
        }
    }

    #[test]
    fn from_string_len_includes_nul_ascii() {
        let s = "hello";
        let az = AzihsmStr::from_string(s);

        assert_eq!(az.len as usize, expected_len_including_nul(s));
        assert_trailing_nul(&az);
        assert_eq!(az.to_string(), s);
        assert!(!az.is_null());
    }

    #[test]
    fn from_string_len_includes_nul_non_ascii() {
        // Exercises multi-byte UTF-8 and UTF-16 surrogate behavior.
        let s = "Hello 世界 😀 é";
        let az = AzihsmStr::from_string(s);

        assert_eq!(az.len as usize, expected_len_including_nul(s));
        assert_trailing_nul(&az);
        assert_eq!(az.to_string(), s);
        assert!(!az.is_null());
    }

    #[test]
    fn from_string_empty_is_null_semantics() {
        let az = AzihsmStr::from_string("");
        assert_eq!(az.len, 1);
        assert_trailing_nul(&az);
        assert_eq!(az.to_string(), "");
        assert!(az.is_null());
    }

    #[test]
    fn from_string_preserves_interior_nul_roundtrip() {
        let s = "a\0b";
        let az = AzihsmStr::from_string(s);

        assert_eq!(az.len as usize, expected_len_including_nul(s));
        assert_trailing_nul(&az);
        assert_eq!(az.to_string(), s);
    }

    #[test]
    fn drop_many_strings_smoke() {
        // This won't "prove" no UB, but it’s a solid regression smoke test.
        for _ in 0..10_000 {
            let _ = AzihsmStr::from_string("Hello 世界 😀 é");
        }
    }
}
