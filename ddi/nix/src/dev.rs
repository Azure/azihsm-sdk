// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI Implementation - MCR Mock Device - Device Module

#![allow(unsafe_code)]

use std::fs::File;
use std::fs::OpenOptions;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::path::Path;
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
use nix::ioctl_readwrite;
use parking_lot::RwLock;

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

    /// Session id in request does not match id in context
    SessionIdMismatch = 14,

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
            x if x == McrCpGenericIoctlErrorKind::SessionIdMismatch as u32 => {
                Ok(McrCpGenericIoctlErrorKind::SessionIdMismatch)
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

/// Definitions for structures and ioctl codes for the
/// ioctl implemented by the Linux driver for session validation
///

#[derive(Default)]
#[repr(C)]
pub struct McrIoctlHeader {
    ioctl_data_size: u32,
    app_cmd_id: u32,
    timeout: u32,
    rsvd: u32,
}

#[repr(u16)]
pub enum McrCpCmdSet {
    Generic = 0,
}

#[bitfield(u8)]
struct SessionControlFlags {
    /// opcode carried in the sqe
    /// specifies whether the opcode
    /// is of type open, close, in or
    /// none
    #[bits(2)]
    pub kind: u8,

    /// valid_session_id
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

#[repr(C)]
pub struct McrCpGenericIoctlIndata {
    context: u64,
    rsvd1: u16,
    command_set: McrCpCmdSet,
    rsvd2: u8,
    src_length: u32,
    src_buf: *const u8, // ptr
    dst_length: u32,
    dst_buf: *mut u8, // ptr
    session_control_flags: SessionControlFlags,
    rsvd4: u8,
    session_id: u16,
    rsvd5: [u8; 16],
}

impl Default for McrCpGenericIoctlIndata {
    fn default() -> Self {
        Self {
            context: 0,
            rsvd1: 0,
            command_set: McrCpCmdSet::Generic,
            rsvd2: 0,
            src_length: 0,
            src_buf: std::ptr::null(),
            dst_length: 0,
            dst_buf: std::ptr::null_mut(),
            session_control_flags: SessionControlFlags {
                ..Default::default()
            },
            rsvd4: 0,
            session_id: 0,
            rsvd5: [0; 16],
        }
    }
}

/// McrCpGenericIoctlOutdata
/// Output buffer returned by device
/// for HSM generic commands
#[derive(Default)]
#[repr(C)]
pub struct McrCpGenericIoctlOutdata {
    /// context echoed back to the output
    /// buffer from input buffer
    context: u64,

    /// device specific status
    /// 0 is success
    /// This status is when the command
    /// has reached the device but there is
    /// a failure seen on the device.
    status: u32,

    /// Number of bytes transferred by the device
    /// to the user buffers. Device and command
    /// specific
    byte_count: u32,

    /// Information about ioctl in case ioctl has
    /// failed. See McrCpGenericIoctlErrorKind
    /// This field is defined only if ioctl has
    /// failed.
    ioctl_status: u32,
}

#[derive(Default)]
#[repr(C)]
pub struct McrCpGenericCmd {
    hdr: McrIoctlHeader,
    in_data: McrCpGenericIoctlIndata,
    out_data: McrCpGenericIoctlOutdata,
}

const MCR_HSM_IOC_MAGIC: u8 = b'B'; // Defined in mcr-linux-mod's /mcr_hsm_dev_ioctl.h
const MCR_HSM_IOC_SEQ: u8 = 0x03;
ioctl_readwrite!(
    mcr_ctrl_cmd_generic_ioctl,
    MCR_HSM_IOC_MAGIC,
    MCR_HSM_IOC_SEQ,
    McrCpGenericCmd
);

// Fast path ioctl definitions and structures

///McrFpIoctlErrorKind
/// Enumeration values for ioctl error status
/// in fast path
#[derive(PartialEq)]
enum McrFpIoctlErrorKind {
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

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct FpGcmParams {
    kid: u32,
    tag: [u8; 16],
    iv: [u8; 12],
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

#[repr(C)]
#[derive(Copy, Clone)]
union XtsOrGcmParams {
    gcm: FpGcmParams,
    xts: FpXtsParams,
}

#[repr(C)]
pub struct McrFpIoctlIndata {
    context: u64,
    opc: u8,
    cypher: u8,
    rsvd1: u16,
    user_buffers: McrIoctlUserBuffer,
    frame_type: u8,
    session_id: u16,
    short_app_id: u8,
    xts_or_gcm: XtsOrGcmParams,
    rsvd2: [u32; 30],
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

impl Default for McrFpIoctlIndata {
    fn default() -> Self {
        McrFpIoctlIndata {
            xts_or_gcm: XtsOrGcmParams {
                gcm: FpGcmParams::default(),
            },
            context: 0,
            opc: 0,
            cypher: 0,
            rsvd1: 0u16,
            user_buffers: McrIoctlUserBuffer::default(),
            frame_type: 0,
            session_id: 0,
            short_app_id: 0,
            rsvd2: [0; 30],
        }
    }
}

//struct McrFpIoctlOutData
//Output buffer returned by driver
//to indicate status of an operation
//ctxt :- User provided context in input buffer
//status :- Device status
//cmd_spec_data :- Data returned by device
//ioctl_status :- If ioctl fails, contains status
#[derive(Default)]
#[repr(C)]
pub struct McrFpIoctlOutData {
    ctxt: u64,
    device_status: u32,
    cmd_spec_data: [u8; 16],
    byte_count: u32,
    ioctl_status: u32,
    pub fips_approved: bool,
    pub reserved: [u8; 3],
    pub iv_from_device: [u8; 12],
    rsvd: [u32; 26],
}

#[derive(Default)]
#[repr(C)]
pub struct McrFpCmd {
    hdr: McrIoctlHeader,
    in_data: McrFpIoctlIndata,
    out_data: McrFpIoctlOutData,
}

#[allow(unused)]
const MCR_FP_IOC_XTS: u8 = 0x0B;
const MCR_FP_IOC_GCM: u8 = 0x0C;

/*
* Define ioctl codes for xts and gcm
*/
ioctl_readwrite!(
    mcr_fp_ioctl_cmd_xts,
    MCR_HSM_IOC_MAGIC,
    MCR_FP_IOC_XTS,
    McrFpCmd
);

ioctl_readwrite!(
    mcr_fp_ioctl_cmd_gcm,
    MCR_HSM_IOC_MAGIC,
    MCR_FP_IOC_GCM,
    McrFpCmd
);

#[allow(unused)]
#[derive(PartialEq)]
pub enum AbortType {
    Reserved = 0, // Reserved for driver use, driver will fail the IOCTL if this value is used.
    AppLevelTwoNssr = 1, // Perform a Level-Two abort but use SubSystem Reset
    AppLevelTwoCtrlReset = 2, // Perform a Disable/Enable Of Controller
}

#[derive(Default)]
#[repr(C)]
struct ResetDeviceIoctlInData {
    abort_type: u32,
    rsvd: [u32; 20],
}

#[derive(Default)]
#[repr(C)]
struct ResetDeviceIoctlOutData {
    abort_sts: u32,
    rsvd: [u32; 20],
}

#[derive(Default)]
#[repr(C)]
struct ResetDeviceData {
    pub hdr: McrIoctlHeader,
    pub ctxt: u64,
    pub rst_in_data: ResetDeviceIoctlInData,
    pub rst_out_data: ResetDeviceIoctlOutData,
    rsvd: [u32; 20],
}

pub const MCR_IOCTL_RESET_DEVICE: u32 = 0x6;

ioctl_readwrite!(
    mcr_reset_device,
    MCR_HSM_IOC_MAGIC,
    MCR_IOCTL_RESET_DEVICE as u8,
    ResetDeviceData
);

// constants for fp ioctl operations
const MCR_FP_IOCTL_FRAME_TYPE_AES: u8 = 1;
const MCR_FP_IOCTL_AES_CYPHER_GCM: u8 = 0;
#[allow(unused)]
const MCR_FP_IOCTL_AES_CYPHER_XTS: u8 = 1;
const MCR_FP_IOCTL_OP_TYPE_ENCRYPT: u8 = 0;
const MCR_FP_IOCTL_OP_TYPE_DECRYPT: u8 = 1;

/// DDI Implementation - MCR Linux Device
#[derive(Debug, Clone)]
pub struct DdiNixDev {
    // File handle
    file: Arc<RwLock<File>>,
    // Device kind
    device_kind: Option<DdiDeviceKind>,
}

impl DdiNixDev {
    pub(crate) fn open(path: &str) -> DdiResult<Self> {
        tracing::debug!("{:?} {}", path, "Opening DdiNixDev");

        let file = OpenOptions::new()
            .read(true)
            .write(true)
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

            Ok(McrCpGenericIoctlErrorKind::SessionIdMismatch) => {
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

impl DdiDev for DdiNixDev {
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

        let mut cmd = McrCpGenericCmd::default();

        // extract the opcode (required) and session id
        // which is optional(depending on the opcode) from the
        // DdiOpReq structure.
        // If opcode kind is no session and session id is provided
        // error the command out
        let session_control_kind: SessionControlKind = req.get_opcode().into();
        if (session_control_kind == SessionControlKind::NoSession
            || session_control_kind == SessionControlKind::Open)
            && req.get_session_id().is_some()
        {
            return Err(DdiError::DdiStatus(DdiStatus::InvalidArg));
        }
        cmd.in_data
            .session_control_flags
            .set_kind(session_control_kind.into());

        if let Some(x) = req.get_session_id() {
            cmd.in_data.session_id = x;
            cmd.in_data
                .session_control_flags
                .set_session_id_is_valid(true);
        }

        cmd.hdr.ioctl_data_size = mem::size_of::<McrCpGenericCmd>() as u32;
        cmd.hdr.app_cmd_id = 0xCD1DDEAD;
        cmd.hdr.timeout = 100; // in ms

        cmd.in_data.command_set = McrCpCmdSet::Generic;

        cmd.in_data.src_length = req_buf.len() as u32;
        cmd.in_data.src_buf = req_buf.as_ptr();
        cmd.in_data.dst_length = resp_buf.len() as u32;
        cmd.in_data.dst_buf = resp_buf.as_mut_ptr();

        // SAFETY: IOCTL call requires unsafe call. The pointers to the buffers are valid and have been checked via
        // debugging as well as code reviews.
        let resp = unsafe { mcr_ctrl_cmd_generic_ioctl(self.file.read().as_raw_fd(), &mut cmd) };

        if resp.is_err() {
            self.map_ioctl_status(cmd.out_data.ioctl_status)?;
            resp.map_err(DdiError::NixError)?;
        }

        if cmd.out_data.status != 0 {
            Err(DdiError::DdiError(cmd.out_data.status))?
        }

        let resp_len = cmd.out_data.byte_count as usize;
        tracing::debug!(opcode = ?req.get_opcode(), "Response Buffer (in hex): {:02x?}", &resp_buf[..resp_len]);

        let mut decoder = DdiDecoder::new(&resp_buf[..resp_len], true);

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
        let src_buf_len = src_buf.len();
        // Note: src_buf_len == 0 is valid for GCM (AAD-only authentication)

        // If this is a decryption operation, the tag must be provided. Return
        // early with an error if the caller did not provide a tag.
        if mode == DdiAesOp::Decrypt && gcm_params.tag.is_none() {
            Err(DdiError::DdiStatus(DdiStatus::NoTagProvided))?;
        }

        let mut cmd = McrFpCmd::default();

        cmd.hdr.ioctl_data_size = mem::size_of::<McrFpCmd>() as u32;
        cmd.hdr.app_cmd_id = 0xCD1DDEAD;
        cmd.hdr.timeout = 100; // in ms

        // Extract the aad
        let aad = gcm_params.aad.unwrap_or_default();
        let aad_len = aad.len();
        // Fill in the actual aad length without padding
        cmd.in_data.xts_or_gcm.gcm.aad_data_len = aad_len as u32;

        // If the aad is not aligned to 32 bytes, pad it with zeros
        // The driver expects the aad to be aligned to 32 bytes
        let mut final_aad = aad;
        align_aad_in_place(&mut final_aad);

        cmd.in_data.xts_or_gcm.gcm.aligned_aad_data_len = final_aad.len() as u32;
        cmd.in_data.xts_or_gcm.gcm.enable_gcm_work_around = 1;

        // Create a new buffer that concatenates aad and the cleartext
        let mut new_src_buf: Vec<u8> = Vec::new();
        new_src_buf.extend(&final_aad);
        new_src_buf.extend(src_buf);

        // Validate destination buffer size
        // For zero-length input, dst_buf can be empty
        if src_buf_len > 0 && dst_buf.len() < src_buf_len {
            tracing::error!(
                "Destination buffer size ({}) is less than source buffer size ({})",
                dst_buf.len(),
                src_buf_len
            );
            Err(DdiError::InvalidParameter)?;
        }

        // Create temporary destination buffer that includes space for AAD
        // For zero-length data, the driver accepts dst_length = 0 and returns tag in output structure
        let mut temp_dest_buf: Vec<u8> = vec![0; new_src_buf.len()];

        cmd.in_data.user_buffers.src_length = new_src_buf.len() as u32;
        cmd.in_data.user_buffers.src_buf = new_src_buf.as_ptr();
        cmd.in_data.user_buffers.dst_length = temp_dest_buf.len() as u32;
        cmd.in_data.user_buffers.dst_buf = temp_dest_buf.as_mut_ptr();
        cmd.in_data.context = 0;

        if mode == DdiAesOp::Encrypt {
            cmd.in_data.opc = MCR_FP_IOCTL_OP_TYPE_ENCRYPT;
        } else {
            cmd.in_data.opc = MCR_FP_IOCTL_OP_TYPE_DECRYPT;
            // If this is a decryption operation, we've already handled the case
            // where a tag is not provided above, so it's safe to unwrap here.
            // Even still, we use `ok_or_else` to log and return an error if
            // this unwrap were to produce an unexpected `None`.
            cmd.in_data.xts_or_gcm.gcm.tag = gcm_params.tag.ok_or_else(|| {
                tracing::error!(
                    "Failed to unwrap tag for decryption operation despite prior validation"
                );
                DdiError::DdiStatus(DdiStatus::InternalError)
            })?;
        }

        cmd.in_data.cypher = MCR_FP_IOCTL_AES_CYPHER_GCM; /* gcm */

        cmd.in_data.frame_type = MCR_FP_IOCTL_FRAME_TYPE_AES; /* aes frame type */
        cmd.in_data.session_id = gcm_params.session_id;
        cmd.in_data.short_app_id = gcm_params.short_app_id;

        // fill up the fields in the ioctl buffer from the parameters
        cmd.in_data.xts_or_gcm.gcm.kid = gcm_params.key_id;
        cmd.in_data.xts_or_gcm.gcm.iv = gcm_params.iv;

        // SAFETY: IOCTL call requires unsafe call. The pointers to the buffers are valid and have been checked via
        // debugging as well as code reviews.
        let resp = unsafe { mcr_fp_ioctl_cmd_gcm(self.file.read().as_raw_fd(), &mut cmd) };
        if resp.is_err() {
            self.map_ioctl_status(cmd.out_data.ioctl_status)?;
            resp.map_err(DdiError::NixError)?;
        }

        if cmd.out_data.device_status != 0 {
            Err(DdiError::FpError(cmd.out_data.device_status))?
        }

        if cmd.out_data.ioctl_status != 0 {
            Err(DdiError::FpCmdSpecificError(cmd.out_data.ioctl_status))?
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
        *tag = Some(cmd.out_data.cmd_spec_data);
        *iv = Some(cmd.out_data.iv_from_device);
        *fips_approved = cmd.out_data.fips_approved;

        Ok(data_len)
    }

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

        let mut cmd = McrFpCmd::default();

        cmd.hdr.ioctl_data_size = mem::size_of::<McrFpCmd>() as u32;
        cmd.hdr.app_cmd_id = 0xCD1DDEAD;
        cmd.hdr.timeout = 100; // in ms

        let xts_dul = xts_params.data_unit_len;
        // map the caller provided data unit length to ioctl encoding
        // If not valid size, return error
        if xts_dul == src_buf_len {
            cmd.in_data.xts_or_gcm.xts.data_unit_len = FpXtsDul::XtsDulFull as u16;
        } else {
            match xts_dul {
                512 => cmd.in_data.xts_or_gcm.xts.data_unit_len = FpXtsDul::XtsDul512 as u16,
                4096 => cmd.in_data.xts_or_gcm.xts.data_unit_len = FpXtsDul::XtsDul4k as u16,
                8192 => cmd.in_data.xts_or_gcm.xts.data_unit_len = FpXtsDul::XtsDul8k as u16,
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

        cmd.in_data.user_buffers.src_length = src_buf_len as u32;
        cmd.in_data.user_buffers.src_buf = src_buf.as_ptr();
        cmd.in_data.user_buffers.dst_length = src_buf_len as u32;
        cmd.in_data.user_buffers.dst_buf = dst_buf.as_mut_ptr();
        cmd.in_data.context = 0;

        if mode == DdiAesOp::Encrypt {
            cmd.in_data.opc = MCR_FP_IOCTL_OP_TYPE_ENCRYPT;
        } else {
            cmd.in_data.opc = MCR_FP_IOCTL_OP_TYPE_DECRYPT;
        }

        cmd.in_data.cypher = MCR_FP_IOCTL_AES_CYPHER_XTS;

        cmd.in_data.frame_type = MCR_FP_IOCTL_FRAME_TYPE_AES; /* aes frame type */
        cmd.in_data.session_id = xts_params.session_id;
        cmd.in_data.short_app_id = xts_params.short_app_id;

        cmd.in_data.xts_or_gcm.xts.key_id1 = xts_params.key_id1;
        cmd.in_data.xts_or_gcm.xts.key_id2 = xts_params.key_id2;

        cmd.in_data.xts_or_gcm.xts.tweak = xts_params.tweak;

        // SAFETY: IOCTL call requires unsafe call. The pointers to the buffers are valid and have been checked via
        // debugging as well as code reviews.
        let resp = unsafe { mcr_fp_ioctl_cmd_xts(self.file.read().as_raw_fd(), &mut cmd) };

        if resp.is_err() {
            self.map_ioctl_status(cmd.out_data.ioctl_status)?;
            resp.map_err(DdiError::NixError)?;
        }

        if cmd.out_data.device_status != 0 {
            Err(DdiError::FpError(cmd.out_data.device_status))?
        }

        if cmd.out_data.ioctl_status != 0 {
            Err(DdiError::FpCmdSpecificError(cmd.out_data.ioctl_status))?
        }

        let total_size = cmd.out_data.byte_count as usize;

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

        *fips_approved = cmd.out_data.fips_approved;

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
        let mut cmd = ResetDeviceData::default();

        cmd.hdr.ioctl_data_size = mem::size_of::<ResetDeviceData>() as u32;
        cmd.hdr.app_cmd_id = 0xCD1DDEAD;
        cmd.hdr.timeout = 100; // in ms

        cmd.rst_in_data = ResetDeviceIoctlInData {
            abort_type: AbortType::AppLevelTwoNssr as u32,
            ..Default::default()
        };

        // SAFETY: IOCTL call requires unsafe call.
        let resp = unsafe { mcr_reset_device(self.file.read().as_raw_fd(), &mut cmd) };

        if resp.is_err() {
            resp.map_err(DdiError::NixError)?;
        }

        if cmd.rst_out_data.abort_sts != 0 {
            Err(DdiError::ResetDeviceError(cmd.rst_out_data.abort_sts))?
        }

        Ok(())
    }
}
