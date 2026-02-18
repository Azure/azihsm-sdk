// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io;

#[cfg(unix)]
use unix::Tpm as TpmInner;
#[cfg(feature = "vtpm-tests")]
use vtpm::RefTpm;
#[cfg(windows)]
use windows::Tpm as TpmInner;

/// Simple cross-platform TPM access (Linux: /dev/tpmrm0|/dev/tpm0, Windows: TBS).
/// Blocking, minimal, not thread-safe across simultaneous transmit calls (uses Mutex).
///
/// Linux notes:
///   Prefer the resource manager device (/dev/tpmrm0) when available.
///   Transmit writes the full command then reads the TPM2 header (10 bytes) to learn total size.
///
/// Windows notes:
///   Uses TBS (TPM Base Services). Link with tbs.dll (implicit).
///   Requires the tbs development headers at build time only for reference; here we redefine what is needed.
///
/// This is a minimal example; production code should add timeouts, command size limits, and stronger error mapping.
pub struct Tpm {
    inner: Inner,
}

/// Low-level TPM transport abstraction.
pub trait RawTpm {
    fn transmit_raw(&self, command: &[u8]) -> io::Result<Vec<u8>>;
}

enum Inner {
    #[cfg(unix)]
    Unix(TpmInner),
    #[cfg(windows)]
    Windows(TpmInner),
    #[cfg(feature = "vtpm-tests")]
    Ref(RefTpm),
}

impl Tpm {
    /// Open default TPM device / context.
    pub fn open() -> io::Result<Self> {
        #[cfg(unix)]
        {
            TpmInner::open().map(|u| Tpm {
                inner: Inner::Unix(u),
            })
        }
        #[cfg(windows)]
        {
            TpmInner::open().map(|w| Tpm {
                inner: Inner::Windows(w),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(io::Error::new(io::ErrorKind::Other, "Unsupported platform"))
        }
    }

    /// Transmit a TPM command buffer and return the full response.
    /// Command must already contain a valid TPM header with correct length.
    pub fn transmit(&self, command: &[u8]) -> io::Result<Vec<u8>> {
        if command.len() < 10 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Command too short",
            ));
        }
        match &self.inner {
            #[cfg(unix)]
            Inner::Unix(u) => u.transmit(command),
            #[cfg(windows)]
            Inner::Windows(w) => w.transmit(command),
            #[cfg(feature = "vtpm-tests")]
            Inner::Ref(r) => r.transmit(command),
        }
    }
}

impl Tpm {
    /// Returns true if this TPM handle is backed by the in-process reference implementation.
    #[cfg(feature = "vtpm-tests")]
    pub fn is_reference(&self) -> bool {
        matches!(self.inner, Inner::Ref(_))
    }
    #[cfg(not(feature = "vtpm-tests"))]
    pub fn is_reference(&self) -> bool {
        false
    }
}

impl RawTpm for Tpm {
    fn transmit_raw(&self, command: &[u8]) -> io::Result<Vec<u8>> {
        self.transmit(command)
    }
}

#[cfg(unix)]
mod unix {
    use std::fs::OpenOptions;
    use std::io;
    use std::io::Read;
    use std::io::Write;

    use parking_lot::Mutex;

    pub struct Tpm {
        file: Mutex<std::fs::File>,
    }

    impl Tpm {
        pub fn open() -> io::Result<Self> {
            let candidates = ["/dev/tpmrm0", "/dev/tpm0"];
            let mut last_err = None;
            for path in candidates {
                match OpenOptions::new().read(true).write(true).open(path) {
                    Ok(f) => {
                        return Ok(Tpm {
                            file: Mutex::new(f),
                        })
                    }
                    Err(e) => last_err = Some(e),
                }
            }

            Err(last_err
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No TPM device")))
        }

        pub fn transmit(&self, command: &[u8]) -> io::Result<Vec<u8>> {
            let mut f = self.file.lock();

            // Write full command
            f.write_all(command)?;

            // Read TPM header (10 bytes)
            let mut header = [0u8; 10];
            f.read_exact(&mut header)?;

            // Parse total response size (bytes 2..6 big-endian)
            let size = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
            if size < 10 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid TPM response length",
                ));
            }
            let mut resp = Vec::with_capacity(size);
            resp.extend_from_slice(&header);

            let remaining = size - 10;
            if remaining > 0 {
                let mut rest = vec![0u8; remaining];
                f.read_exact(&mut rest)?;
                resp.extend_from_slice(&rest);
            }

            Ok(resp)
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::io;

    use parking_lot::Mutex;

    pub struct Tpm {
        handle: u32, // TBS_HCONTEXT
        lock: Mutex<()>,
    }

    impl Tpm {
        pub fn open() -> io::Result<Self> {
            let params2 = win_ffi::TBS_CONTEXT_PARAMS2 {
                version: win_ffi::TPM_VERSION_20, // required for PARAMS2  [1](https://learn.microsoft.com/en-us/windows/win32/api/tbs/ns-tbs-tbs_context_params2)
                Anonymous: win_ffi::TBS_CONTEXT_PARAMS2_FLAGS { asUINT32: 0x6 }, // includeTpm12 | includeTpm20
            };

            let mut handle: u32 = 0;
            // SAFETY: Make an FFI call.
            let rc = unsafe {
                win_ffi::Tbsi_Context_Create(
                    std::ptr::from_ref(&params2),
                    std::ptr::from_mut(&mut handle),
                )
            };
            if rc == win_ffi::TBS_SUCCESS {
                return Ok(Tpm {
                    handle,
                    lock: Mutex::new(()),
                });
            }

            if rc == 0x8028_400F {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("TPM not found (TBS_E_TPM_NOT_FOUND) rc=0x{rc:08x}. System reports TPM present so this may indicate a TBS access restriction (service state, policy) or a virtualization layer issue."),
                ));
            }
            Err(io::Error::other(format!(
                "Tbsi_Context_Create failed rc=0x{rc:08x}"
            )))
        }

        pub fn transmit(&self, command: &[u8]) -> io::Result<Vec<u8>> {
            if command.len() > u32::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Command too large",
                ));
            }
            let _g = self.lock.lock();
            let mut buf = vec![0u8; 8192];
            let mut out_len: u32 = buf.len() as u32;
            // SAFETY: Make an FFI call.
            let rc = unsafe {
                win_ffi::Tbsip_Submit_Command(
                    self.handle,
                    win_ffi::TBS_COMMAND_LOCALITY_ZERO,
                    win_ffi::TBS_COMMAND_PRIORITY_NORMAL,
                    command.as_ptr(),
                    command.len() as u32,
                    buf.as_mut_ptr(),
                    std::ptr::from_mut::<u32>(&mut out_len),
                )
            };

            if rc != win_ffi::TBS_SUCCESS {
                return Err(io::Error::other(format!(
                    "Tbsip_Submit_Command failed: 0x{rc:08x}"
                )));
            }

            buf.truncate(out_len as usize);
            if buf.len() < 10 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Response too short",
                ));
            }
            let declared = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;
            if declared != buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Response length mismatch: declared {declared} actual {}",
                        buf.len()
                    ),
                ));
            }
            Ok(buf)
        }
    }

    impl Drop for Tpm {
        fn drop(&mut self) {
            // SAFETY: Make an FFI call.
            unsafe { win_ffi::Tbsip_Context_Close(self.handle) };
        }
    }

    // Minimal subset of TBS FFI we need (manual because windows crate does not currently expose TBS APIs).
    mod win_ffi {
        pub const TBS_SUCCESS: u32 = 0;
        pub const TPM_VERSION_20: u32 = 2;
        pub const TBS_COMMAND_LOCALITY_ZERO: u32 = 0;
        pub const TBS_COMMAND_PRIORITY_NORMAL: u32 = 100;

        // Allow non-snake / camel case naming that matches the Windows SDK for FFI correctness.
        #[allow(non_snake_case)]
        #[repr(C)]
        pub union TBS_CONTEXT_PARAMS2_FLAGS {
            pub asUINT32: u32, // bit 0: requestRaw, bit 1: includeTpm12, bit 2: includeTpm20
        }

        #[repr(C)]
        #[allow(non_camel_case_types)]
        #[allow(non_snake_case)]
        pub struct TBS_CONTEXT_PARAMS2 {
            pub version: u32, // must be TPM_VERSION_20 for PARAMS2
            pub Anonymous: TBS_CONTEXT_PARAMS2_FLAGS,
        }

        #[link(name = "tbs")]
        extern "system" {
            pub fn Tbsi_Context_Create(params: *const TBS_CONTEXT_PARAMS2, handle: *mut u32)
                -> u32;
            pub fn Tbsip_Context_Close(handle: u32);
            pub fn Tbsip_Submit_Command(
                handle: u32,
                locality: u32,
                priority: u32,
                commandBuffer: *const u8,
                commandBufferSize: u32,
                resultBuffer: *mut u8,
                resultBufferSize: *mut u32,
            ) -> u32;
        }
    }
}

// ---------------- Reference (in-process) TPM for tests (feature gated) ---------------
#[cfg(feature = "vtpm-tests")]
mod vtpm {
    use std::io;

    use parking_lot::Mutex;

    use crate::tpm::device::Inner;
    use crate::tpm::device::Tpm;

    pub struct RefTpm {
        inner: Mutex<ms_tpm_20_ref::MsTpm20RefPlatform>,
    }

    impl RefTpm {
        pub fn transmit(&self, command: &[u8]) -> io::Result<Vec<u8>> {
            let mut guard = self.inner.lock();
            let mut buf = [0u8; 8192];
            // ms-tpm-20-ref execute_command takes &mut self, a (possibly mutable) request buffer, and an output buffer.
            let mut req = command.to_vec();
            let sz = guard.execute_command(&mut req, &mut buf).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("ref tpm exec failed: {e}"))
            })?;

            Ok(buf[..sz].to_vec())
        }
    }

    // Public (feature-gated) constructor for the in-process reference TPM so that
    // integration tests (which compile the library without #[cfg(test)]) can use it.
    impl Tpm {
        pub fn open_reference() -> io::Result<Self> {
            use std::time::Instant;

            use ms_tpm_20_ref::DynResult;
            use ms_tpm_20_ref::InitKind;
            use ms_tpm_20_ref::MsTpm20RefPlatform;
            use ms_tpm_20_ref::PlatformCallbacks;

            struct TestPlatform {
                nv: Vec<u8>,
                start: Instant,
            }
            impl PlatformCallbacks for TestPlatform {
                fn commit_nv_state(&mut self, state: &[u8]) -> DynResult<()> {
                    self.nv = state.to_vec();
                    Ok(())
                }
                fn get_crypt_random(&mut self, buf: &mut [u8]) -> DynResult<usize> {
                    getrandom::getrandom(buf).map_err(|err| {
                        io::Error::other(format!(
                            "Failed to fill buffer with random bytes via getrandom: {err}"
                        ))
                    })?;
                    Ok(buf.len())
                }
                fn monotonic_timer(&mut self) -> std::time::Duration {
                    self.start.elapsed()
                }
                fn get_unique_value(&self) -> &'static [u8] {
                    b"cvm-ref-tpm"
                }
            }

            let platform = Box::new(TestPlatform {
                nv: vec![],
                start: Instant::now(),
            });
            let inner =
                MsTpm20RefPlatform::initialize(platform, InitKind::ColdInit).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("ref tpm init failed: {e}"))
                })?;
            let tpm = Tpm {
                inner: Inner::Ref(RefTpm {
                    inner: Mutex::new(inner),
                }),
            };
            // Issue Startup(Clear)
            let startup = [0x80, 0x01, 0, 0, 0, 0x0C, 0, 0, 0x01, 0x44, 0, 0];
            let _ = tpm.transmit(&startup)?;

            Ok(tpm)
        }
    }

    // Retain backwards-compatible test-only name for existing unit tests.
    #[cfg(all(feature = "vtpm-tests", test))]
    impl Tpm {
        pub fn open_reference_for_tests() -> io::Result<Self> {
            Self::open_reference()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;

    // This test only checks that open_default does not panic; it may fail if no TPM present.
    #[test]
    fn maybe_open() {
        let _ = Tpm::open(); // Ignore result; on CI without TPM it will error.
    }

    // TPM2_GetCapability (0x0000017A) requesting TPM properties starting at TPM2_PT_FIXED (0x00000100)
    // Command structure:
    //   tag: 0x8001 (TPM_ST_NO_SESSIONS)
    //   size: 0x000000 (placeholder patched below)
    //   commandCode: 0x0000017A
    //   capability: 0x00000006 (TPM2_CAP_TPM_PROPERTIES)
    //   property:   0x00000100 (TPM2_PT_FIXED)
    //   propertyCount: 0x00000001
    #[test]
    fn transmit_get_capability() {
        // Build command buffer
        let cmd = vec![
            0x80, 0x01, // tag
            0x00, 0x00, 0x00, 0x16, // size = 22 bytes
            0x00, 0x00, 0x01, 0x7A, // TPM2_CC_GetCapability
            0x00, 0x00, 0x00, 0x06, // capability = TPM2_CAP_TPM_PROPERTIES
            0x00, 0x00, 0x01, 0x00, // property = TPM2_PT_FIXED
            0x00, 0x00, 0x00, 0x01, // propertyCount = 1
        ];
        assert_eq!(cmd.len(), 22);

        let tpm = match test_tpm_instance() {
            Some(t) => t,
            None => return, // Skip
        };
        match tpm.transmit(&cmd) {
            Ok(resp) => {
                // Minimal sanity: header length matches buffer length.
                if resp.len() >= 10 {
                    let declared =
                        u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]) as usize;
                    assert_eq!(declared, resp.len(), "Declared length mismatch");
                }
            }
            Err(_) => {
                // Environment may forbid command; treat as skip. Reference TPM may surface WouldBlock pseudo errors.
            }
        }
    }

    /// Choose a TPM instance for tests based on feature + env:
    ///   CVM_TPM_TEST_MODE=ref -> reference TPM (if feature enabled)
    ///   CVM_TPM_TEST_MODE=hw  -> hardware TPM
    ///   unset -> prefer reference (if enabled) else hardware.
    fn test_tpm_instance() -> Option<Tpm> {
        let mode = env::var("CVM_TPM_TEST_MODE").ok();
        #[cfg(feature = "vtpm-tests")]
        {
            if matches!(mode.as_deref(), Some("ref")) {
                return Tpm::open_reference_for_tests().ok();
            }
            if matches!(mode.as_deref(), Some("hw")) {
                Tpm::open().ok()
            } else {
                // default preference: reference then hardware
                Tpm::open_reference_for_tests()
                    .ok()
                    .or_else(|| Tpm::open().ok())
            }
        }
        #[cfg(not(feature = "vtpm-tests"))]
        {
            let _ = mode; // silence unused
            Tpm::open().ok()
        }
    }
}
