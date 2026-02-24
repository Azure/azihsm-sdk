// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI Implementation - MCR Windows Device - Device Module

#![allow(unsafe_code)]
#![allow(unused_assignments)]

use std::fs::File;
use std::fs::OpenOptions;
use std::mem;
use std::os::windows::prelude::*;
use std::path::Path;
use std::ptr;
use std::sync::Arc;

use azihsm_ddi_interface::*;
use azihsm_ddi_mbor::MborDecode;
use azihsm_ddi_mbor::MborDecoder;
use azihsm_ddi_mbor::MborEncoder;
use azihsm_ddi_types::DdiAesOp;
use azihsm_ddi_types::DdiDecoder;
use azihsm_ddi_types::DdiDeviceKind;
use azihsm_ddi_types::DdiOpReq;
use azihsm_ddi_types::DdiRespHdr;
use azihsm_ddi_types::DdiStatus;
use azihsm_ddi_types::MborError;
use azihsm_ddi_types::SessionControlKind;
use bitfield_struct::bitfield;
use parking_lot::RwLock;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::DWORD;
use winapi::shared::winerror::ERROR_IO_PENDING;
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::ioapiset::GetOverlappedResult;
use winapi::um::minwinbase::OVERLAPPED;
use winapi::um::winbase::FILE_FLAG_OVERLAPPED;
use winapi::um::winioctl::CTL_CODE;
use winapi::um::winioctl::FILE_READ_ACCESS;
use winapi::um::winioctl::FILE_WRITE_ACCESS;
use winapi::um::winioctl::METHOD_BUFFERED;
use winapi::um::winnt::HANDLE;

use crate::io_event::IoEvent;

const MCR_CP_CMD_SESSION_GENERIC: u16 = 0x0;

#[derive(Default)]
#[repr(C)]
pub struct McrIoctlHeader {
    ioctl_data_size: u32,
    app_cmd_id: u32,
    timeout: u32,
    flags: u32,
}

#[repr(C)]
pub struct McrIoctlUserBuffer {
    src_buf: *const u8,
    src_length: u32,
    dst_buf: *mut u8,
    dst_length: u32,
}

impl Default for McrIoctlUserBuffer {
    fn default() -> Self {
        Self {
            src_buf: std::ptr::null(),
            src_length: 0,
            dst_buf: std::ptr::null_mut(),
            dst_length: 0,
        }
    }
}

///McrCpGenericIoctlErrorKind
/// Enumeration values for ioctl error status
#[derive(PartialEq)]
enum McrCpGenericIoctlErrorKind {
    /// Device or driver has no memory to
    /// satisfy the request
    NoMemory = 1,
    /// Application has provided an invalid
    /// cmdset.
    InvalidCmdset = 2,

    /// Input buffers provided in the command
    /// are more than 8k.
    InputBufferLargerThan8K = 3,

    /// Output buffers provided in the command are
    /// more than 8k
    OutputBufferLargerThan8K = 4,

    /// Input buffer is invalid
    ///
    InvalidInputBuffer = 5,

    // Accessing some or all of the input buffer
    // resulted in an error
    InputBufferAccessError = 6,

    /// Output buffer is invalid
    InvalidOutputBuffer = 7,

    // accessing some or all of the output buffer
    // resulted in an error
    OutputBufferAccessError = 8,

    /// Process issuing the ioctl does
    /// not own the file handle
    InvalidFDOwner = 9,

    /// An error was encountered submitting
    /// the request to the Manticore device.
    DeviceSubmissionError = 10,

    /// The limit on the number of sessions allowed
    /// on a file handle has been reached.
    SessionLimitReached = 11,

    /// Application was trying to submit an operation
    /// that requires a session but no session has been
    /// opened on the file handle.
    NoExistingSession = 12,

    /// Driver has received an opcode that is not defined
    InvalidOpcode = 13,

    /// Session id in the device does not match the value
    /// provided in the request
    SessionIdDoesNotMatch = 14,

    /// IO abort is in progress by Driver
    DriverAbortInProgress = 0x04000001,

    /// Driver aborted the IO request
    DriverAbortedIo = 0x04000002,
}

impl TryFrom<u32> for McrCpGenericIoctlErrorKind {
    type Error = u32;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            x if x == McrCpGenericIoctlErrorKind::NoMemory as u32 => {
                Ok(McrCpGenericIoctlErrorKind::NoMemory)
            }
            x if x == McrCpGenericIoctlErrorKind::InvalidCmdset as u32 => {
                Ok(McrCpGenericIoctlErrorKind::InvalidCmdset)
            }
            x if x == McrCpGenericIoctlErrorKind::InputBufferLargerThan8K as u32 => {
                Ok(McrCpGenericIoctlErrorKind::InputBufferLargerThan8K)
            }
            x if x == McrCpGenericIoctlErrorKind::OutputBufferLargerThan8K as u32 => {
                Ok(McrCpGenericIoctlErrorKind::OutputBufferLargerThan8K)
            }
            x if x == McrCpGenericIoctlErrorKind::InvalidInputBuffer as u32 => {
                Ok(McrCpGenericIoctlErrorKind::InvalidInputBuffer)
            }
            x if x == McrCpGenericIoctlErrorKind::InputBufferAccessError as u32 => {
                Ok(McrCpGenericIoctlErrorKind::InputBufferAccessError)
            }
            x if x == McrCpGenericIoctlErrorKind::InvalidOutputBuffer as u32 => {
                Ok(McrCpGenericIoctlErrorKind::InvalidOutputBuffer)
            }
            x if x == McrCpGenericIoctlErrorKind::OutputBufferAccessError as u32 => {
                Ok(McrCpGenericIoctlErrorKind::OutputBufferAccessError)
            }
            x if x == McrCpGenericIoctlErrorKind::InvalidFDOwner as u32 => {
                Ok(McrCpGenericIoctlErrorKind::InvalidFDOwner)
            }
            x if x == McrCpGenericIoctlErrorKind::DeviceSubmissionError as u32 => {
                Ok(McrCpGenericIoctlErrorKind::DeviceSubmissionError)
            }
            x if x == McrCpGenericIoctlErrorKind::SessionLimitReached as u32 => {
                Ok(McrCpGenericIoctlErrorKind::SessionLimitReached)
            }
            x if x == McrCpGenericIoctlErrorKind::NoExistingSession as u32 => {
                Ok(McrCpGenericIoctlErrorKind::NoExistingSession)
            }
            x if x == McrCpGenericIoctlErrorKind::InvalidOpcode as u32 => {
                Ok(McrCpGenericIoctlErrorKind::InvalidOpcode)
            }
            x if x == McrCpGenericIoctlErrorKind::SessionIdDoesNotMatch as u32 => {
                Ok(McrCpGenericIoctlErrorKind::SessionIdDoesNotMatch)
            }
            x if x == McrCpGenericIoctlErrorKind::DriverAbortInProgress as u32 => {
                Ok(McrCpGenericIoctlErrorKind::DriverAbortInProgress)
            }
            x if x == McrCpGenericIoctlErrorKind::DriverAbortedIo as u32 => {
                Ok(McrCpGenericIoctlErrorKind::DriverAbortedIo)
            }
            _ => Err(value)?,
        }
    }
}

#[bitfield(u8)]
struct SessionControlFlags {
    /// kind defines the type of
    /// opcode
    #[bits(2)]
    pub kind: u8,

    /// When set to true, this indicates
    /// that the session id in the SQE is
    /// defined.
    #[bits(1)]
    pub session_id_is_valid: bool,

    /**
    reserved
    */
    #[bits(5)]
    pub _rsvd1: u8,
}

#[derive(Default)]
#[repr(C)]
pub struct McrCpGenericIoctlIndata {
    ioctl_hdr: McrIoctlHeader,
    context: u64,
    opc: u16,
    cmdset: u16,
    user_buffers: McrIoctlUserBuffer,
    session_control: SessionControlFlags,
    rsvd1: [u8; 3],
    session_id: u16,
    rsvd2: [u8; 14],
    rsvd3: [u32; 32],
    hot_patch_reserved: [usize; 16],
}

#[derive(Default)]
#[repr(C)]
pub struct McrCpGenericIoctlOutData {
    pub ioctl_hdr: McrIoctlHeader,
    pub ctxt: u64,
    pub status: u32,
    pub byte_count: u32,
    pub ioctl_status: u32,
    pub rsvd: [u32; 32],
    hot_patch_reserved: [usize; 16],
}

///McrFpIoctlErrorKind
/// Enumeration values for ioctl error status
/// in fast path
#[derive(PartialEq)]
pub enum McrFpIoctlErrorKind {
    /// Device or driver has no memory to
    /// satisfy the request
    NoMemory = 100,

    /// Application has provided an invalid
    /// input buffer
    InvalidInputBuffer = 101,

    /// Unable to access input buffer
    InputBufferAccessError = 102,

    /// INvalid destination buffer
    InvalidOutputBuffer = 103,

    /// error accessing destination buffer
    OutputBufferAccessError = 104,

    /// Process issuing the ioctl does
    /// not own the file handle
    InvalidFDOwner = 105,

    /// Unable to submit command to device
    DeviceSubmissionError = 106,

    /// Session id does not match
    /// Session id provided for the operation
    /// does not match the session id registered
    /// with the file handle
    InvalidSessionId = 107,

    /// Short app id does not match
    /// Short app id provided for the operation
    /// does not match the short app id registered
    /// for the file handle
    InvalidShortAppId = 108,

    /// There is no session id registered on the
    /// handle
    NoValidSessionId = 109,

    ///There is a valid session id but there is no
    /// short app id
    NoValidShortAppId = 110,

    /// Device has no FP queues
    NoFPQueuesCreated = 111,

    /// Ioctl has invalid cypher type
    InvalidCypherType = 112,

    /// Ioctl has invalid frame type
    InvalidFrameType = 113,

    ///Ioctl has invalid opcode
    InvalidOpcode = 114,

    ///Input buffer is above maximum length
    /// allowed for DMA
    InputBufferLengthAboveMax = 115,

    ///Output buffer is above maximum length
    /// allowed for DMA
    OutputBufferLengthAboveMax = 116,

    ///Aes Gcm ioctl validation failed
    AesGcmIoctlValidationFailed = 117,

    ///Aes Xts ioctl validation failed
    AesXtsIoctlValidationFailed = 118,
}

impl TryFrom<u32> for McrFpIoctlErrorKind {
    type Error = u32;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            x if x == McrFpIoctlErrorKind::NoMemory as u32 => Ok(McrFpIoctlErrorKind::NoMemory),
            x if x == McrFpIoctlErrorKind::InvalidInputBuffer as u32 => {
                Ok(McrFpIoctlErrorKind::InvalidInputBuffer)
            }
            x if x == McrFpIoctlErrorKind::InputBufferAccessError as u32 => {
                Ok(McrFpIoctlErrorKind::InputBufferAccessError)
            }
            x if x == McrFpIoctlErrorKind::InvalidOutputBuffer as u32 => {
                Ok(McrFpIoctlErrorKind::InvalidOutputBuffer)
            }
            x if x == McrFpIoctlErrorKind::InvalidInputBuffer as u32 => {
                Ok(McrFpIoctlErrorKind::InvalidInputBuffer)
            }
            x if x == McrFpIoctlErrorKind::InputBufferAccessError as u32 => {
                Ok(McrFpIoctlErrorKind::InputBufferAccessError)
            }
            x if x == McrFpIoctlErrorKind::InvalidOutputBuffer as u32 => {
                Ok(McrFpIoctlErrorKind::InvalidOutputBuffer)
            }
            x if x == McrFpIoctlErrorKind::OutputBufferAccessError as u32 => {
                Ok(McrFpIoctlErrorKind::OutputBufferAccessError)
            }
            x if x == McrFpIoctlErrorKind::InvalidFDOwner as u32 => {
                Ok(McrFpIoctlErrorKind::InvalidFDOwner)
            }
            x if x == McrFpIoctlErrorKind::DeviceSubmissionError as u32 => {
                Ok(McrFpIoctlErrorKind::DeviceSubmissionError)
            }
            x if x == McrFpIoctlErrorKind::InvalidSessionId as u32 => {
                Ok(McrFpIoctlErrorKind::InvalidSessionId)
            }
            x if x == McrFpIoctlErrorKind::InvalidShortAppId as u32 => {
                Ok(McrFpIoctlErrorKind::InvalidShortAppId)
            }
            x if x == McrFpIoctlErrorKind::InvalidOpcode as u32 => {
                Ok(McrFpIoctlErrorKind::InvalidOpcode)
            }
            x if x == McrFpIoctlErrorKind::NoValidSessionId as u32 => {
                Ok(McrFpIoctlErrorKind::NoValidSessionId)
            }
            x if x == McrFpIoctlErrorKind::NoValidShortAppId as u32 => {
                Ok(McrFpIoctlErrorKind::NoValidShortAppId)
            }
            x if x == McrFpIoctlErrorKind::NoFPQueuesCreated as u32 => {
                Ok(McrFpIoctlErrorKind::NoFPQueuesCreated)
            }
            x if x == McrFpIoctlErrorKind::InvalidCypherType as u32 => {
                Ok(McrFpIoctlErrorKind::InvalidCypherType)
            }
            x if x == McrFpIoctlErrorKind::InvalidFrameType as u32 => {
                Ok(McrFpIoctlErrorKind::InvalidFrameType)
            }
            x if x == McrFpIoctlErrorKind::InvalidOpcode as u32 => {
                Ok(McrFpIoctlErrorKind::InvalidOpcode)
            }
            x if x == McrFpIoctlErrorKind::AesGcmIoctlValidationFailed as u32 => {
                Ok(McrFpIoctlErrorKind::AesGcmIoctlValidationFailed)
            }
            x if x == McrFpIoctlErrorKind::AesXtsIoctlValidationFailed as u32 => {
                Ok(McrFpIoctlErrorKind::AesXtsIoctlValidationFailed)
            }
            x if x == McrFpIoctlErrorKind::InputBufferLengthAboveMax as u32 => {
                Ok(McrFpIoctlErrorKind::InputBufferLengthAboveMax)
            }
            x if x == McrFpIoctlErrorKind::OutputBufferLengthAboveMax as u32 => {
                Ok(McrFpIoctlErrorKind::OutputBufferLengthAboveMax)
            }
            _ => Err(value)?,
        }
    }
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct FpGcmParams {
    kid: u32,
    tag: [u8; 16],
    init_vec: [u8; 12],
    aad_data_len: u32,
    aligned_aad_data_len: u32,
    enable_gcm_work_around: u8,
    rsvd: [u8; 3],
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct FpXtsParams {
    data_unit_len: u16,
    rsvd: u16,
    key_id1: u32,
    key_id2: u32,
    tweak: [u8; 16],
}

///FpXtsDul
/// Encodings for
/// Xts data unit length
enum FpXtsDul {
    ///Dul == length of
    /// source buffer
    XtsDulFull = 0,

    ///Dul == 512bytes
    XtsDul512 = 1,

    ///Dul == 4096 bytes
    XtsDul4k = 2,

    ///Dul == 8192 bytes
    XtsDul8k = 3,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union XtsOrGcmParams {
    gcm: FpGcmParams,
    xts: FpXtsParams,
}

#[repr(C)]
pub struct McrFpIoctlIndata {
    pub ioctl_hdr: McrIoctlHeader,
    pub context: u64,
    pub opc: u8,
    pub cypher: u8,
    pub rsvd1: u16,
    pub user_buffers: McrIoctlUserBuffer,
    pub frame_type: u8,
    pub session_id: u16,
    pub short_app_id: u8,
    pub xts_or_gcm: XtsOrGcmParams,
    pub rsvd2: [u32; 30],
    pub hot_patch_reserved: [usize; 16],
}

impl Default for McrFpIoctlIndata {
    fn default() -> Self {
        McrFpIoctlIndata {
            xts_or_gcm: XtsOrGcmParams {
                gcm: FpGcmParams::default(),
            },
            ioctl_hdr: McrIoctlHeader::default(),
            context: 0,
            opc: 0,
            cypher: 0,
            rsvd1: 0u16,
            user_buffers: McrIoctlUserBuffer::default(),
            frame_type: 0,
            session_id: 0,
            short_app_id: 0,
            rsvd2: [0; 30],
            hot_patch_reserved: [0usize; 16],
        }
    }
}

#[derive(Default)]
#[repr(C)]
pub struct McrFpIoctlOutData {
    /// ioctl_hdr
    pub ioctl_hdr: McrIoctlHeader,

    /// Command context
    pub ctxt: u64,

    /// Result from device
    pub result: u32,

    /// Output of AES GCM or XTS
    /// operations
    pub cmd_spec_data: [u8; 16],

    /// # of bytes copied by device
    /// to output buffer
    pub byte_count: u32,
    /// extended_status
    /// If result indicates failure,
    /// this will contain more
    /// information about the failure
    pub extended_status: u32,
    pub fips_approved: bool,
    pub reserved: [u8; 3],
    pub iv_from_device: [u8; 12],
    pub rsvd: [u32; 26],
    pub hot_patch_reserved: [usize; 16],
}

#[allow(unused)]
// constants for fp ioctl operations
pub const MCR_FP_IOCTL_CODE_XTS: u32 = 0x100;
pub const MCR_FP_IOCTL_CODE_GCM: u32 = 0x101;
pub const MCR_FP_IOCTL_FRAME_TYPE_AES: u8 = 1;
pub const MCR_FP_IOCTL_AES_CYPHER_GCM: u8 = 0;
#[allow(unused)]
pub const MCR_FP_IOCTL_AES_CYPHER_XTS: u8 = 1;
pub const MCR_FP_IOCTL_OP_TYPE_ENCRYPT: u8 = 0;
pub const MCR_FP_IOCTL_OP_TYPE_DECRYPT: u8 = 1;

// Constants for reset device operations:

#[allow(unused)]
#[derive(PartialEq)]
pub enum AbortType {
    Reserved = 0, // Reserved for driver use, driver will fail the IOCTL if this value is used.
    AppLevelTwoNssr = 1, // Perform a Level-Two abort but use SubSystem Reset
    AppLevelTwoCtrlReset = 2, // Perform a Disable/Enable Of Controller
}

#[derive(Default)]
#[repr(C)]
pub struct ResetDeviceInData {
    pub ioctl_hdr: McrIoctlHeader,
    pub ctxt: u64,
    pub abort_type: u32,
}

#[derive(Default)]
#[repr(C)]
pub struct ResetDeviceOutData {
    pub ioctl_hdr: McrIoctlHeader,
    pub ctxt: u64,
    pub abort_status: u32,
}

pub const MCR_IOCTL_RESET_DEVICE: u32 = 0x402;

/// DDI Implementation - MCR Windows Device
#[derive(Debug, Clone)]
pub struct DdiWinDev {
    // File handle
    file: Arc<RwLock<File>>,
    // Device kind
    device_kind: Option<DdiDeviceKind>,
}

impl DdiWinDev {
    pub(crate) fn open(path: &str) -> DdiResult<Self> {
        tracing::debug!("{:?} {}", path, "Opening DdiWinDev");

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OVERLAPPED)
            .open(Path::new(path))
            .map_err(DdiError::IoError)?;

        Ok(Self {
            file: Arc::new(RwLock::new(file)),
            device_kind: None,
        })
    }

    /// Returns the device kind (Virtual or Physical).
    ///
    /// # Returns
    ///
    /// The device kind that was determined when the device was opened.
    pub fn device_kind(&self) -> Option<DdiDeviceKind> {
        self.device_kind
    }

    fn map_ioctl_status(&self, ioctl_status: u32) -> Result<u32, DdiError> {
        match McrCpGenericIoctlErrorKind::try_from(ioctl_status) {
            Ok(McrCpGenericIoctlErrorKind::SessionLimitReached) => {
                return Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionLimitReached,
                ));
            }

            Ok(McrCpGenericIoctlErrorKind::NoExistingSession) => {
                return Err(DdiError::DdiStatus(DdiStatus::FileHandleNoExistingSession));
            }

            Ok(McrCpGenericIoctlErrorKind::SessionIdDoesNotMatch) => {
                return Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionIdDoesNotMatch,
                ));
            }

            Ok(McrCpGenericIoctlErrorKind::DeviceSubmissionError) => {
                return Err(DdiError::DeviceNotReady);
            }

            Ok(McrCpGenericIoctlErrorKind::DriverAbortInProgress) => {
                return Err(DdiError::DriverError(DriverError::IoAbortInProgress));
            }

            Ok(McrCpGenericIoctlErrorKind::DriverAbortedIo) => {
                return Err(DdiError::DriverError(DriverError::IoAborted));
            }
            _ => {}
        }

        match McrFpIoctlErrorKind::try_from(ioctl_status) {
            Ok(McrFpIoctlErrorKind::InvalidSessionId) => {
                return Err(DdiError::DdiStatus(
                    DdiStatus::FileHandleSessionIdDoesNotMatch,
                ));
            }

            Ok(McrFpIoctlErrorKind::InvalidShortAppId) => {
                return Err(DdiError::DdiStatus(DdiStatus::InvalidShortAppId));
            }

            Ok(McrFpIoctlErrorKind::NoValidSessionId) => {
                return Err(DdiError::DdiStatus(DdiStatus::FileHandleNoExistingSession));
            }

            Ok(McrFpIoctlErrorKind::NoValidShortAppId) => {
                return Err(DdiError::DdiStatus(DdiStatus::NoShortAppIdCreated));
            }

            Ok(McrFpIoctlErrorKind::AesXtsIoctlValidationFailed) => {
                return Err(DdiError::InvalidParameter);
            }

            Ok(McrFpIoctlErrorKind::AesGcmIoctlValidationFailed) => {
                return Err(DdiError::InvalidParameter);
            }
            _ => {}
        }

        Ok(ioctl_status)
    }
}

/// Align AAD in place according to the following rules:
/// The AAD needs to be aligned in such a way that the
/// AAD data comes in the middle of alignment.
/// This means that a AAD size of 11 bytes will be aligned like this:
///
/// Before[Size:11]: [AB, AB, AB, AB, AB, AB, AB, AB, AB, AB, AB]
/// Buffer size after resize to  32
/// After: [00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, | 16 bytes of zeros
///         AB, AB, AB, AB, AB, AB, AB, AB, AB, AB, AB, | 11 bytes of AAD data    
///         00, 00, 00, 00, 00] | 5 bytes of zeros to pad to 32B multiple
///
/// - If len % 32 == 0: do nothing
/// - Else if len % 32 <= 16: prepend 16 zeros, then pad with zeros to a 32B multiple
/// - Else: just pad with zeros to a 32B multiple
///
/// This mutates `buf` directly.
///
pub fn align_aad_in_place(buf: &mut Vec<u8>) {
    const AAD_ALIGN: usize = 32;
    let len = buf.len();
    let rem = len & (AAD_ALIGN - 1);

    if rem == 0 {
        return; // already aligned
    }

    // If original remainder <= 16, insert a 16-byte zero prefix.
    if rem <= 16 {
        buf.splice(0..0, std::iter::repeat_n(0u8, 16).take(16));
    }

    // Now pad with zeros to the next AAD_ALIGN-byte boundary based on the NEW length.
    let target = buf.len().div_ceil(AAD_ALIGN) * AAD_ALIGN;
    buf.resize(target, 0);
}

impl DdiDev for DdiWinDev {
    /// Set Device Kind, to determine encode/decode behavior
    ///
    /// # Arguments
    /// * `type`        - Type of device
    ///
    /// # Error
    /// * `DdiError` - Error encountered?
    fn set_device_kind(&mut self, kind: DdiDeviceKind) {
        self.device_kind = Some(kind);
    }

    /// Execute Operation
    ///
    /// # Arguments
    /// * `req`         - Operation Request
    /// * `cookie`      - Cookie
    ///
    /// # Returns
    /// * `OpReq::Resp` - Operation response
    ///
    /// # Error
    /// * `DdiError` - Error encountered while executing the command
    fn exec_op<T: DdiOpReq>(
        &self,
        req: &T,
        _cookie: &mut Option<DdiCookie>,
    ) -> DdiResult<T::OpResp> {
        const REQ_BUF_LEN: usize = 8192;

        let (pre_encode, post_decode) = match self.device_kind {
            Some(DdiDeviceKind::Physical) => (true, true),
            _ => (false, false),
        };

        let mut req_buf = [0u8; REQ_BUF_LEN];
        let mut encoder = MborEncoder::new(&mut req_buf, pre_encode);

        req.mbor_encode(&mut encoder)
            .map_err(|_| DdiError::MborError(MborError::EncodeError))?;

        let req_buf_len = encoder.position();
        let req_buf = &req_buf[..req_buf_len];

        tracing::debug!(opcode = ?req.get_opcode(), "Request Buffer (in hex): {:02x?}", req_buf);

        let mut resp_buf = Box::<[u8; 8192]>::new([0u8; 8192]);

        let mut ioctl_in_buffer = McrCpGenericIoctlIndata::default();
        let ioctl_out_buffer = McrCpGenericIoctlOutData::default();

        ioctl_in_buffer.ioctl_hdr.ioctl_data_size =
            mem::size_of::<McrCpGenericIoctlIndata>() as u32;
        ioctl_in_buffer.ioctl_hdr.app_cmd_id = 0xCD1DDEAD;
        ioctl_in_buffer.ioctl_hdr.timeout = 100; // in ms
        ioctl_in_buffer.ioctl_hdr.flags = 0;

        ioctl_in_buffer.context = 0;
        ioctl_in_buffer.opc = 0; /* not applicable */
        ioctl_in_buffer.cmdset = MCR_CP_CMD_SESSION_GENERIC;

        ioctl_in_buffer.user_buffers.src_length = req_buf.len() as u32;
        ioctl_in_buffer.user_buffers.src_buf = req_buf.as_ptr();
        ioctl_in_buffer.user_buffers.dst_length = resp_buf.len() as u32;
        ioctl_in_buffer.user_buffers.dst_buf = resp_buf.as_mut_ptr();

        /*
         * Retrieve the opcode and session id from the
         * DdiReq header and map them to ioctl compatible
         * values
         */
        let session_control_kind: SessionControlKind = req.get_opcode().into();
        if (session_control_kind == SessionControlKind::NoSession
            || session_control_kind == SessionControlKind::Open)
            && req.get_session_id().is_some()
        {
            return Err(DdiError::DdiStatus(DdiStatus::InvalidArg));
        }
        ioctl_in_buffer
            .session_control
            .set_kind(session_control_kind.into());

        if let Some(x) = req.get_session_id() {
            ioctl_in_buffer.session_id = x;
            ioctl_in_buffer
                .session_control
                .set_session_id_is_valid(true);
        }

        let ioctl_code: DWORD = CTL_CODE(
            0x3F,
            0x201,
            METHOD_BUFFERED,
            FILE_READ_ACCESS | FILE_WRITE_ACCESS,
        );

        // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
        // debugging as well as code reviews.
        let mut overlapped: OVERLAPPED = unsafe { mem::zeroed() };
        let mut bytes_returned: DWORD = 0;
        let in_ptr = ptr::addr_of!(ioctl_in_buffer);
        let out_ptr = ptr::addr_of!(ioctl_out_buffer);
        let overlapped_ptr: *mut OVERLAPPED = &mut overlapped;

        let event = IoEvent::new()?;
        overlapped.hEvent = event.handle();

        // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
        // debugging as well as code reviews.
        let _ioctl_ret = unsafe {
            DeviceIoControl(
                self.file.read().as_raw_handle() as HANDLE,
                ioctl_code,
                in_ptr as *mut c_void,
                mem::size_of::<McrCpGenericIoctlIndata>() as DWORD,
                out_ptr as *mut c_void,
                mem::size_of::<McrCpGenericIoctlOutData>() as DWORD,
                ptr::null_mut(),
                overlapped_ptr,
            )
        };

        let last_error = std::io::Error::last_os_error();
        if last_error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            tracing::warn!(?last_error, "DeviceIoControl returned error after exec_op");
            Err(DdiError::IoError(last_error))?;
        }

        // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
        // debugging as well as code reviews.
        let result = unsafe {
            GetOverlappedResult(
                self.file.read().as_raw_handle() as HANDLE,
                overlapped_ptr,
                &mut bytes_returned,
                1,
            )
        };

        /*
         *  There are 2 ways to deal with this ioctl
         *  If the ioctl has failed, return the Winerror
         *  If the ioctl has succeeded, the extended ioctl status
         *  will further indicate success or failure
         */

        if result == 0 {
            //
            // This is the WinApi Failure. The Driver will not copy any data in this case
            // So we cannot map the error status here.
            //

            let last_error = std::io::Error::last_os_error();
            tracing::warn!(
                ?last_error,
                "GetOverlappedResult returned error after exec_op"
            );
            Err(DdiError::IoError(last_error))?;
        }

        self.map_ioctl_status(ioctl_out_buffer.ioctl_status)?;

        if ioctl_out_buffer.ioctl_status != 0 {
            Err(DdiError::WinError(ioctl_out_buffer.ioctl_status))?;
        }

        if ioctl_out_buffer.status != 0 {
            Err(DdiError::DdiError(ioctl_out_buffer.status))?
        }

        let resp_len = ioctl_out_buffer.byte_count as usize;
        tracing::debug!(opcode = ?req.get_opcode(), "Response Buffer (in hex): {:02x?}", &resp_buf[..resp_len]);

        let mut decoder = DdiDecoder::new(&resp_buf[..resp_len], post_decode);

        let hdr = decoder
            .decode_hdr::<DdiRespHdr>()
            .map_err(|_| DdiError::MborError(MborError::DecodeError))?;

        if hdr.status != DdiStatus::Success {
            return Err(DdiError::DdiStatus(hdr.status));
        }

        let mut decoder = MborDecoder::new(&resp_buf[..resp_len], post_decode);
        let resp = <T::OpResp>::mbor_decode(&mut decoder)
            .map_err(|_| DdiError::MborError(MborError::DecodeError))?;
        Ok(resp)
    }

    /// Execute AES GCM operation (encryption/decryption) with slice-based buffers
    ///
    /// This is a slice-based variant that allows the caller to provide pre-allocated
    /// buffers, avoiding the extra allocation and copy overhead of the Vec-based API.
    ///
    /// # Arguments
    /// * `mode`        - Encryption or decryption
    /// * `gcm_params`  - Parameters for the operation (key ID, IV, tag, session info)
    /// * `src_buf`     - Source buffer slice to encrypt or decrypt
    /// * `dst_buf`     - Destination buffer slice to write encrypted or decrypted data
    /// * `tag`         - Output parameter for encryption tag or input tag for decryption
    /// * `iv`          - Output parameter for IV returned from device
    /// * `fips_approved` - Output parameter set to indicate if operation was FIPS approved
    ///
    /// # Returns
    /// * `usize` - Number of bytes written to the destination buffer
    ///
    /// # Error
    /// * `DdiError` - Error that occurred during operation
    ///
    /// # Notes
    /// - The destination buffer must be at least as large as the source buffer
    /// - For decryption, the tag must be provided in `gcm_params`
    /// - AAD data is automatically aligned to 32-byte boundaries as required by the driver
    fn exec_op_fp_gcm_slice(
        &self,
        mode: DdiAesOp,
        gcm_params: DdiAesGcmParams,
        src_buf: &[u8],
        dst_buf: &mut [u8],
        tag: &mut Option<[u8; 16]>,
        iv: &mut Option<[u8; 12]>,
        fips_approved: &mut bool,
    ) -> Result<usize, DdiError> {
        // Note: src_buf_len == 0 is valid for GCM (AAD-only authentication)
        let src_buf_len = src_buf.len();

        // If this is a decryption operation, the tag must be provided
        if mode == DdiAesOp::Decrypt && gcm_params.tag.is_none() {
            Err(DdiError::DdiStatus(DdiStatus::NoTagProvided))?;
        }

        // Validate destination buffer size
        // For zero-length input, dst_buf can be empty
        if src_buf_len > 0 && dst_buf.len() < src_buf_len {
            tracing::error!(
                "Destination buffer size ({}) is less than source buffer size ({})",
                dst_buf.len(),
                src_buf_len
            );
            return Err(DdiError::InvalidParameter);
        }

        let mut ioctl_in_buffer = McrFpIoctlIndata::default();
        let ioctl_out_buffer = McrFpIoctlOutData::default();

        ioctl_in_buffer.ioctl_hdr.ioctl_data_size = mem::size_of::<McrFpIoctlIndata>() as u32;
        ioctl_in_buffer.ioctl_hdr.app_cmd_id = 0xCD1DDEAE;
        ioctl_in_buffer.ioctl_hdr.timeout = 100; // in ms
        ioctl_in_buffer.ioctl_hdr.flags = 0;

        ioctl_in_buffer.context = 0;

        // Extract the aad
        let aad = gcm_params.aad.unwrap_or_default();
        let aad_len = aad.len();

        // Fill in the actual aad length without padding
        ioctl_in_buffer.xts_or_gcm.gcm.aad_data_len = aad_len as u32;

        // If the aad is not aligned to 32 bytes, pad it with zeros
        // The driver expects the aad to be aligned to 32 bytes
        let mut final_aad = aad;
        align_aad_in_place(&mut final_aad);

        ioctl_in_buffer.xts_or_gcm.gcm.aligned_aad_data_len = final_aad.len() as u32;
        ioctl_in_buffer.xts_or_gcm.gcm.enable_gcm_work_around = 1;

        // Create a new buffer that concatenates aad and the source data
        let mut new_src_buf: Vec<u8> = Vec::new();
        new_src_buf.extend(&final_aad);
        new_src_buf.extend(src_buf);

        // Create temporary destination buffer that includes space for AAD
        let mut temp_dest_buf: Vec<u8> = vec![0; new_src_buf.len()];

        if mode == DdiAesOp::Encrypt {
            ioctl_in_buffer.opc = MCR_FP_IOCTL_OP_TYPE_ENCRYPT;
        } else {
            ioctl_in_buffer.opc = MCR_FP_IOCTL_OP_TYPE_DECRYPT;
            // If this is a decryption operation, we've already handled the case
            // where a tag is not provided above, so it's safe to unwrap here.
            // Even still, we use `ok_or_else` to log and return an error if
            // this unwrap were to produce an unexpected `None`.
            ioctl_in_buffer.xts_or_gcm.gcm.tag = gcm_params.tag.ok_or_else(|| {
                tracing::error!(
                    "Failed to unwrap tag for decryption operation despite prior validation"
                );
                DdiError::DdiStatus(DdiStatus::InternalError)
            })?;
        }

        ioctl_in_buffer.cypher = MCR_FP_IOCTL_AES_CYPHER_GCM;
        let ioctl_code = CTL_CODE(
            0x3F,
            MCR_FP_IOCTL_CODE_GCM,
            METHOD_BUFFERED,
            FILE_READ_ACCESS | FILE_WRITE_ACCESS,
        );

        ioctl_in_buffer.xts_or_gcm.gcm.kid = gcm_params.key_id;
        ioctl_in_buffer.xts_or_gcm.gcm.init_vec = gcm_params.iv;

        ioctl_in_buffer.frame_type = MCR_FP_IOCTL_FRAME_TYPE_AES;
        ioctl_in_buffer.session_id = gcm_params.session_id;
        ioctl_in_buffer.short_app_id = gcm_params.short_app_id;

        // Initialize the source and destination buffers
        // Note if aad is present, source buffer is different
        // than the cleartext
        // destination buffer length is always the same as the
        // cleartext buffer length
        ioctl_in_buffer.user_buffers.src_length = new_src_buf.len() as u32;
        ioctl_in_buffer.user_buffers.src_buf = new_src_buf.as_ptr();
        ioctl_in_buffer.user_buffers.dst_length = temp_dest_buf.len() as u32;
        ioctl_in_buffer.user_buffers.dst_buf = temp_dest_buf.as_mut_ptr();

        // SAFETY: WINAPI call requires unsafe call
        let mut overlapped: OVERLAPPED = unsafe { mem::zeroed() };
        let mut bytes_returned: DWORD = 0;
        let in_ptr = ptr::addr_of!(ioctl_in_buffer);
        let out_ptr = ptr::addr_of!(ioctl_out_buffer);
        let overlapped_ptr: *mut OVERLAPPED = &mut overlapped;

        let event = IoEvent::new()?;
        overlapped.hEvent = event.handle();

        // Safety: This is unsafe because of the call to system routine DeviceIoControl
        let _ioctl_ret = unsafe {
            DeviceIoControl(
                self.file.read().as_raw_handle() as HANDLE,
                ioctl_code,
                in_ptr as *mut c_void,
                mem::size_of::<McrFpIoctlIndata>() as DWORD,
                out_ptr as *mut c_void,
                mem::size_of::<McrFpIoctlOutData>() as DWORD,
                ptr::null_mut(),
                overlapped_ptr,
            )
        };

        let last_error = std::io::Error::last_os_error();
        if last_error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            tracing::warn!(
                ?last_error,
                "DeviceIoControl returned error after exec_op_fp_gcm_slice"
            );
            Err(DdiError::IoError(last_error))?;
        }

        // SAFETY: WINAPI call requires unsafe call
        let result = unsafe {
            GetOverlappedResult(
                self.file.read().as_raw_handle() as HANDLE,
                overlapped_ptr,
                &mut bytes_returned,
                1,
            )
        };

        /* There are 2 ways to deal with this ioctl
         *  If the ioctl has failed, return the Winerror
         *  If the ioctl has succeeded, the extended ioctl status
         *  will further indicate success or failure
         */

        if result == 0 {
            let last_error = std::io::Error::last_os_error();
            tracing::warn!(
                ?last_error,
                "GetOverlappedResult returned error after exec_op_fp_gcm_slice"
            );
            Err(DdiError::IoError(last_error))?;
        }

        self.map_ioctl_status(ioctl_out_buffer.extended_status)?;

        if ioctl_out_buffer.result != 0 {
            Err(DdiError::FpError(ioctl_out_buffer.result))?
        }

        if ioctl_out_buffer.extended_status != 0 {
            Err(DdiError::FpCmdSpecificError(
                ioctl_out_buffer.extended_status,
            ))?
        }

        // Copy the actual data (excluding AAD) to the destination buffer
        let aad_offset = final_aad.len();
        let data_len = temp_dest_buf.len().saturating_sub(aad_offset);

        // Only copy if there's actual data (not just AAD)
        if data_len > 0 {
            if data_len > dst_buf.len() {
                if mode == DdiAesOp::Encrypt {
                    tracing::error!(
                        "AES GCM Encrypt: Device output length ({}) is greater than destination buffer size ({})",
                        data_len,
                        dst_buf.len()
                    );
                    Err(DdiError::DdiStatus(DdiStatus::AesEncryptFailed))?;
                } else {
                    tracing::error!(
                        "AES GCM Decrypt: Device output length ({}) is greater than destination buffer size ({})",
                        data_len,
                        dst_buf.len()
                    );
                    Err(DdiError::DdiStatus(DdiStatus::AesDecryptFailed))?;
                }
            }
            dst_buf[..data_len].copy_from_slice(&temp_dest_buf[aad_offset..]);
        }

        // Set output parameters from device response
        *tag = Some(ioctl_out_buffer.cmd_spec_data);
        *iv = Some(ioctl_out_buffer.iv_from_device);
        *fips_approved = ioctl_out_buffer.fips_approved;

        Ok(data_len)
    }

    /// exec_op_fp_gcm
    /// Windows implementation of
    /// fast path AES GCM encryption
    /// decryption functionality
    /// mode -> Encryption or decryption
    /// gcm_params -> Parameters for operation
    /// session id and short_app_id are application
    /// specific
    /// src_buf
    ///   For encryption, this is the cleartext buffer
    ///   For decryption, this is the encrypted content
    fn exec_op_fp_gcm(
        &self,
        mode: DdiAesOp,
        gcm_params: DdiAesGcmParams,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesGcmResult, DdiError> {
        let src_buf_len = src_buf.len();
        let mut dest_buf: Vec<u8> = vec![0; src_buf_len];
        let mut fips_approved = false;
        let mut tag = None;
        let mut iv = None;

        let total_size = self.exec_op_fp_gcm_slice(
            mode,
            gcm_params,
            &src_buf,
            &mut dest_buf,
            &mut tag,
            &mut iv,
            &mut fips_approved,
        )?;

        if total_size < src_buf_len {
            dest_buf.truncate(total_size);
        }

        Ok(DdiAesGcmResult {
            data: dest_buf,
            tag,
            iv,
            fips_approved,
        })
    }

    /// Execute AES XTS operation (encryption/decryption) with slice-based buffers
    ///
    /// This is a slice-based variant that allows the caller to provide pre-allocated
    /// buffers, avoiding the extra allocation and copy overhead of the Vec-based API.
    ///
    /// # Arguments
    /// * `mode`        - Encryption or decryption
    /// * `xts_params`  - Parameters for the operation (data unit length, keys, tweak, session info)
    /// * `src_buf`     - Source buffer slice to encrypt or decrypt
    /// * `dst_buf`     - Destination buffer slice to write encrypted or decrypted data
    /// * `fips_approved` - Output parameter set to indicate if operation was FIPS approved
    ///
    /// # Returns
    /// * `usize` - Number of bytes written to the destination buffer
    ///
    /// # Error
    /// * `DdiError` - Error that occurred during operation
    ///
    /// # Notes
    /// - The destination buffer must be at least as large as the source buffer
    /// - The return value indicates how many bytes were actually written
    fn exec_op_fp_xts_slice(
        &self,
        mode: DdiAesOp,
        xts_params: DdiAesXtsParams,
        src_buf: &[u8],
        dst_buf: &mut [u8],
        fips_approved: &mut bool,
    ) -> Result<usize, DdiError> {
        let src_buf_len = src_buf.len();

        // Validate input parameters
        if src_buf_len == 0 {
            return Err(DdiError::InvalidParameter);
        }

        // Validate destination buffer size
        if dst_buf.len() < src_buf_len {
            tracing::error!(
                "Destination buffer size ({}) is less than source buffer size ({})",
                dst_buf.len(),
                src_buf_len
            );
            return Err(DdiError::InvalidParameter);
        }

        let mut ioctl_in_buffer = McrFpIoctlIndata::default();
        let ioctl_out_buffer = McrFpIoctlOutData::default();

        let xts_dul = xts_params.data_unit_len;
        // map the caller provided data unit length to ioctl encoding
        // If not valid size, return error
        if xts_dul == src_buf_len {
            ioctl_in_buffer.xts_or_gcm.xts.data_unit_len = FpXtsDul::XtsDulFull as u16;
        } else {
            match xts_dul {
                512 => ioctl_in_buffer.xts_or_gcm.xts.data_unit_len = FpXtsDul::XtsDul512 as u16,
                4096 => ioctl_in_buffer.xts_or_gcm.xts.data_unit_len = FpXtsDul::XtsDul4k as u16,
                8192 => ioctl_in_buffer.xts_or_gcm.xts.data_unit_len = FpXtsDul::XtsDul8k as u16,
                _ => {
                    tracing::error!(
                        "FP AES XTS: Data unit length ({}) is not valid. Src buffer size: {}",
                        xts_params.data_unit_len,
                        src_buf_len
                    );
                    Err(DdiError::InvalidParameter)?;
                }
            }
        }

        ioctl_in_buffer.ioctl_hdr.ioctl_data_size = mem::size_of::<McrFpIoctlIndata>() as u32;
        ioctl_in_buffer.ioctl_hdr.app_cmd_id = 0xCD1DDEAE;
        ioctl_in_buffer.ioctl_hdr.timeout = 100; // in ms
        ioctl_in_buffer.ioctl_hdr.flags = 0;

        ioctl_in_buffer.context = 0;

        if mode == DdiAesOp::Encrypt {
            ioctl_in_buffer.opc = MCR_FP_IOCTL_OP_TYPE_ENCRYPT;
        } else {
            ioctl_in_buffer.opc = MCR_FP_IOCTL_OP_TYPE_DECRYPT;
        }

        ioctl_in_buffer.cypher = MCR_FP_IOCTL_AES_CYPHER_XTS; /* xts */
        let ioctl_code = CTL_CODE(
            0x3F,
            MCR_FP_IOCTL_CODE_XTS,
            METHOD_BUFFERED,
            FILE_READ_ACCESS | FILE_WRITE_ACCESS,
        );

        ioctl_in_buffer.xts_or_gcm.xts.key_id1 = xts_params.key_id1;
        ioctl_in_buffer.xts_or_gcm.xts.key_id2 = xts_params.key_id2;

        ioctl_in_buffer.xts_or_gcm.xts.tweak = xts_params.tweak;

        ioctl_in_buffer.frame_type = MCR_FP_IOCTL_FRAME_TYPE_AES; /* aes frame type */
        ioctl_in_buffer.session_id = xts_params.session_id;
        ioctl_in_buffer.short_app_id = xts_params.short_app_id;

        // Initialize the source and destination buffers
        ioctl_in_buffer.user_buffers.src_length = src_buf_len as u32;
        ioctl_in_buffer.user_buffers.src_buf = src_buf.as_ptr();
        ioctl_in_buffer.user_buffers.dst_length = src_buf_len as u32;
        ioctl_in_buffer.user_buffers.dst_buf = dst_buf.as_mut_ptr();

        // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
        // debugging as well as code reviews.
        let mut overlapped: OVERLAPPED = unsafe { mem::zeroed() };
        let mut bytes_returned: DWORD = 0;
        let in_ptr = ptr::addr_of!(ioctl_in_buffer);
        let out_ptr = ptr::addr_of!(ioctl_out_buffer);
        let overlapped_ptr: *mut OVERLAPPED = &mut overlapped;

        let event = IoEvent::new()?;
        overlapped.hEvent = event.handle();

        // Safety: This is unsafe because of the call to
        // system routine DeviceIoControl
        let _ioctl_ret = unsafe {
            DeviceIoControl(
                self.file.read().as_raw_handle() as HANDLE,
                ioctl_code,
                in_ptr as *mut c_void,
                mem::size_of::<McrFpIoctlIndata>() as DWORD,
                out_ptr as *mut c_void,
                mem::size_of::<McrFpIoctlOutData>() as DWORD,
                ptr::null_mut(),
                overlapped_ptr,
            )
        };

        let last_error = std::io::Error::last_os_error();
        if last_error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            tracing::warn!(
                ?last_error,
                "DeviceIoControl returned error after exec_op_fp_xts_slice"
            );
            Err(DdiError::IoError(last_error))?;
        }

        // SAFETY: WINAPI call requires unsafe call. The pointers to the buffers are valid and have been checked via
        // debugging as well as code reviews.
        let result = unsafe {
            GetOverlappedResult(
                self.file.read().as_raw_handle() as HANDLE,
                overlapped_ptr,
                &mut bytes_returned,
                1,
            )
        };

        if result == 0 {
            let last_error = std::io::Error::last_os_error();
            tracing::warn!(
                ?last_error,
                "GetOverlappedResult returned error after exec_op_fp_xts_slice"
            );
            Err(DdiError::IoError(last_error))?;
        }

        self.map_ioctl_status(ioctl_out_buffer.extended_status)?;

        if ioctl_out_buffer.result != 0 {
            Err(DdiError::FpError(ioctl_out_buffer.result))?
        }

        if ioctl_out_buffer.extended_status != 0 {
            Err(DdiError::FpCmdSpecificError(
                ioctl_out_buffer.extended_status,
            ))?
        }

        let total_size = ioctl_out_buffer.byte_count as usize;

        if total_size > dst_buf.len() {
            if mode == DdiAesOp::Encrypt {
                tracing::error!(
                    "AES XTS Encrypt: Device output length ({}) is greater than destination buffer size ({})",
                    total_size,
                    dst_buf.len()
                );
                Err(DdiError::DdiStatus(DdiStatus::AesEncryptFailed))?;
            } else {
                tracing::error!(
                    "AES XTS Decrypt: Device output length ({}) is greater than destination buffer size ({})",
                    total_size,
                    dst_buf.len()
                );
                Err(DdiError::DdiStatus(DdiStatus::AesDecryptFailed))?;
            }
        }

        *fips_approved = ioctl_out_buffer.fips_approved;

        Ok(total_size)
    }

    /// Execute AES Xts Operation on fast path
    ///
    /// # Arguments
    /// * `mode`        - Encryption or decryption
    /// * `xts_params`  - Parameters for the operation
    /// * `src_buf`     - User buffer for encryption or decryption
    ///
    /// # Returns
    /// * `DdiAesXtsParams` - On success
    ///
    /// # Error
    /// * `DdiError` - Error that occurred during operation
    fn exec_op_fp_xts(
        &self,
        mode: DdiAesOp,
        xts_params: DdiAesXtsParams,
        src_buf: Vec<u8>,
    ) -> Result<DdiAesXtsResult, DdiError> {
        let src_buf_len = src_buf.len();
        let mut dest_buf: Vec<u8> = vec![0; src_buf_len];
        let mut fips_approved = false;

        let total_size = self.exec_op_fp_xts_slice(
            mode,
            xts_params,
            &src_buf,
            &mut dest_buf,
            &mut fips_approved,
        )?;

        if total_size < src_buf_len {
            dest_buf.truncate(total_size);
        }

        Ok(DdiAesXtsResult {
            data: dest_buf,
            fips_approved,
        })
    }

    /// Execute NVMe subsystem reset to help emulate Live Migration
    ///
    /// # Returns
    /// * `Ok(())` - Successfully sent NSSR Reset Device command
    /// * `Err(DdiError)` - Error occurred while executing the command
    fn simulate_nssr_after_lm(&self) -> Result<(), DdiError> {
        let ioctl_in_buffer = ResetDeviceInData {
            ioctl_hdr: McrIoctlHeader {
                ioctl_data_size: mem::size_of::<ResetDeviceInData>() as u32,
                app_cmd_id: 0xCD1DDEAE,
                timeout: 100, // in ms
                flags: 0,
            },
            abort_type: AbortType::AppLevelTwoNssr as u32,
            ..Default::default()
        };

        let ioctl_out_buffer = ResetDeviceOutData::default();

        // SAFETY: WINAPI call requires unsafe call.
        let mut overlapped: OVERLAPPED = unsafe { mem::zeroed() };
        let mut bytes_returned: DWORD = 0;
        let in_ptr = ptr::addr_of!(ioctl_in_buffer);
        let out_ptr = ptr::addr_of!(ioctl_out_buffer);
        let overlapped_ptr: *mut OVERLAPPED = &mut overlapped;

        let event = IoEvent::new()?;
        overlapped.hEvent = event.handle();

        let ioctl_code = CTL_CODE(
            0x3F,
            MCR_IOCTL_RESET_DEVICE,
            METHOD_BUFFERED,
            FILE_READ_ACCESS | FILE_WRITE_ACCESS,
        );

        // SAFETY: WINAPI call requires unsafe call.
        let _ioctl_ret = unsafe {
            DeviceIoControl(
                self.file.read().as_raw_handle() as HANDLE,
                ioctl_code,
                in_ptr as *mut c_void,
                mem::size_of::<ResetDeviceInData>() as DWORD,
                out_ptr as *mut c_void,
                mem::size_of::<ResetDeviceOutData>() as DWORD,
                ptr::null_mut(),
                overlapped_ptr,
            )
        };

        let last_error = std::io::Error::last_os_error();
        if last_error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            tracing::warn!(
                ?last_error,
                "DeviceIoControl returned error after simulate_nssr_after_lm"
            );
            Err(DdiError::IoError(last_error))?;
        }

        // SAFETY: WINAPI call requires unsafe call.
        let result = unsafe {
            GetOverlappedResult(
                self.file.read().as_raw_handle() as HANDLE,
                overlapped_ptr,
                &mut bytes_returned,
                1,
            )
        };

        /* There are 2 ways to deal with this ioctl
         *  If the ioctl has failed, return the Winerror
         *  If the ioctl has succeeded, the extended ioctl status
         *  will further indicate success or failure
         */

        if result == 0 {
            let last_error = std::io::Error::last_os_error();
            tracing::warn!(
                ?last_error,
                "GetOverlappedResult returned error after simulate_nssr_after_lm"
            );
            Err(DdiError::IoError(last_error))?;
        }

        if ioctl_out_buffer.abort_status != 0 {
            Err(DdiError::ResetDeviceError(ioctl_out_buffer.abort_status))?
        }

        Ok(())
    }
}
