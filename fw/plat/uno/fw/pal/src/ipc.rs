// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IPC wire format shared between HSM, Admin and FP cores.
//!
//! The 64-byte slot modelled here matches the `ipc_message_t` regfile
//! byte-for-byte. Each slot is carried over the INTC doorbell-based
//! IPC driver ([`azihsm_fw_uno_drivers_ipc`]).
//!
//! # Layout
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │  IpcMessageHeader (32 bits)                 │
//! │  ┌─────┬────┬─────┬──────┬─────┬────┬────┐ │
//! │  │op:7 │R:1 │tag:8│sts:4 │sub:2│cmp:2│len:8│
//! │  └─────┴────┴─────┴──────┴─────┴────┴────┘ │
//! ├─────────────────────────────────────────────┤
//! │  Payload (60 bytes)                         │
//! └─────────────────────────────────────────────┘
//! ```

use bitfield_struct::bitfield;
use open_enum::open_enum;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Component-level result alias.
pub type IpcResult<T> = Result<T, u32>;

/// Component identifier for this crate (matches V1 `mcr-error`).
const COMPONENT_IPC_MESSAGE: u32 = 0x09;

// ---------------------------------------------------------------------------
// Raw IPC message slot
// ---------------------------------------------------------------------------

/// Number of `u32` words in a single IPC slot (16 × 4 = 64 bytes).
pub const IPC_MESSAGE_LENGTH: usize = 16;

/// Number of payload bytes available after the 32-bit header.
pub const IPC_MESSAGE_PAYLOAD_LEN: usize = IPC_MESSAGE_LENGTH * 4 - 4;

/// Length of the IPC header in bytes.
pub const IPC_HEADER_LEN_IN_BYTES: usize = 4;

/// Raw IPC message slot. Matches the `ipc_message_t` regfile (16 × u32).
#[repr(C)]
#[derive(Clone, Copy, Debug, IntoBytes, Immutable, FromBytes)]
pub struct IpcMessage {
    /// Fixed-length IPC message data.
    pub data: [u32; IPC_MESSAGE_LENGTH],
}

const _: () = assert!(core::mem::size_of::<IpcMessage>() == IPC_MESSAGE_LENGTH * 4);

// ---------------------------------------------------------------------------
// IO controller / channel identifiers
// ---------------------------------------------------------------------------

/// IO Controller Identifier.
#[repr(u8)]
#[open_enum]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable, FromBytes)]
pub enum IoControllerId {
    /// Core 0.
    Core0 = 0,

    /// Core 1.
    Core1 = 1,
}

/// IO Channel Identifier (five channels, 0..4).
#[repr(u8)]
#[open_enum]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable, FromBytes)]
pub enum IoChannelId {
    /// Channel 0.
    Channel0 = 0,

    /// Channel 1.
    Channel1 = 1,

    /// Channel 2.
    Channel2 = 2,

    /// Channel 3.
    Channel3 = 3,

    /// Channel 4.
    Channel4 = 4,
}

impl From<IoChannelId> for usize {
    fn from(value: IoChannelId) -> Self {
        value.0 as usize
    }
}

impl From<IoChannelId> for u32 {
    fn from(value: IoChannelId) -> Self {
        value.0 as u32
    }
}

// ---------------------------------------------------------------------------
// Boot state (cross-core rendezvous values)
// ---------------------------------------------------------------------------

/// Various states of an IO processing core. The `Run` variant (3) is the
/// rendezvous value written into the `BOOT_STATUS` GSRAM slot at the end
/// of the boot handshake.
#[repr(u32)]
#[open_enum]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoProcessorBootState {
    /// IO processor boot start phase.
    Start = 1,

    /// IO processor boot phase completed.
    Done = 2,

    /// IO processor is in run state.
    Run = 3,
}

// ---------------------------------------------------------------------------
// IPC message opcodes
// ---------------------------------------------------------------------------

/// IPC message opcode. Matches V1's `IpcMessageOpCode` discriminants on
/// the wire; only the variants currently used by the V2 boot handshake
/// have dedicated body types, but the rest are listed so opcode parsing
/// remains stable across the whole protocol.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum IpcMessageOpCode {
    /// IO core state change (NormalBoot / Start / iDFU phases).
    #[default]
    StateChange = 0x0,

    /// Create / delete submission queue.
    CreateDeleteSq = 0x3,

    /// PCIe function enable / disable.
    PfnEnableDisable = 0x5,

    /// Send CDMA IO.
    CdmaIo = 0x6,

    /// AES key update.
    AesKeyUpdate = 0x7,

    /// FP error log.
    FpErrLog = 0x9,

    /// Set resource.
    SetResource = 0x7f,
}

impl TryFrom<u8> for IpcMessageOpCode {
    type Error = u32;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x00 => Self::StateChange,
            0x03 => Self::CreateDeleteSq,
            0x05 => Self::PfnEnableDisable,
            0x06 => Self::CdmaIo,
            0x07 => Self::AesKeyUpdate,
            0x09 => Self::FpErrLog,
            0x7F => Self::SetResource,
            _ => return Err(IpcMessageErr::InvalidOpcodeConversion.into()),
        })
    }
}

// ---------------------------------------------------------------------------
// IPC header
// ---------------------------------------------------------------------------

/// IPC message header (first 32-bit word of every IPC slot).
#[bitfield(u32)]
#[derive(IntoBytes, Immutable, FromBytes, PartialEq, Eq)]
pub struct IpcMessageHeader {
    /// Message operation. Decoded into [`IpcMessageOpCode`] by the consumer.
    #[bits(7)]
    pub msg_op: u32,

    /// Request (`false`) or response (`true`).
    pub response: bool,

    /// Software tag used to track request / response pairs.
    #[bits(8)]
    pub tag: u32,

    /// Per-message status; values are defined by [`IpcMessageStatusCode`].
    #[bits(4)]
    pub status: u32,

    /// Bit map recording which cores the message was submitted to.
    #[bits(2)]
    pub submit_map: u32,

    /// Bit map recording which cores have completed the message.
    #[bits(2)]
    pub complete_map: u32,

    /// Length of the message body in bytes.
    #[bits(8)]
    pub length: u32,
}

// ---------------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------------

/// IPC message status code (encoded in [`IpcMessageHeader::status`]).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcMessageStatusCode {
    /// Success.
    Success = 0,

    /// Opcode not supported by the receiver.
    MessageNotSupported = 1,

    /// Invalid field in the message body.
    InvalidField = 2,

    /// Target function not enabled.
    FunctionNotEnabled = 3,

    /// Operation timed out.
    OperationTimeout = 4,

    /// Operation failed.
    OperationFailed = 5,

    /// Operation still pending.
    Pending = 6,

    /// Unknown / catch-all status.
    UnknownStatus = 0xF,
}

impl From<IpcMessageStatusCode> for u32 {
    fn from(value: IpcMessageStatusCode) -> Self {
        value as Self
    }
}

impl From<u32> for IpcMessageStatusCode {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::Success,
            1 => Self::MessageNotSupported,
            2 => Self::InvalidField,
            3 => Self::FunctionNotEnabled,
            4 => Self::OperationTimeout,
            5 => Self::OperationFailed,
            6 => Self::Pending,
            _ => Self::UnknownStatus,
        }
    }
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// IPC message error code. Encoded as the low 16 bits of an [`IpcResult`]
/// error; the high 16 bits carry [`COMPONENT_IPC_MESSAGE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum IpcMessageErr {
    /// Invalid IO state value.
    InvalidIoStateValue = 1,

    /// Invalid IO channel identifier.
    InvalidChannelId = 2,

    /// Invalid IO controller identifier.
    InvalidControllerId = 3,

    /// Raw IPC slot could not be decoded into the requested type.
    InvalidInputMessageForDecode = 11,

    /// Header bytes could not be decoded.
    InvalidMessageHeaderDecode = 12,

    /// Opcode did not match the expected message type.
    InvalidOpcodeConversion = 13,

    /// Target partition id is out of range.
    InvalidPartitionId = 14,
}

impl From<IpcMessageErr> for u32 {
    fn from(value: IpcMessageErr) -> Self {
        (COMPONENT_IPC_MESSAGE << 16) | (value as u32)
    }
}

// ---------------------------------------------------------------------------
// IpcMessageType trait + encoder / decoder
// ---------------------------------------------------------------------------

/// Interface implemented by each typed IPC message body.
pub trait IpcMessageType {
    /// IPC message opcode advertised in the header.
    const OP: IpcMessageOpCode;

    /// IPC message body length in bytes (excluding the 4-byte header).
    const LEN: usize;

    /// Validate the decoded body. Returns `Err` on invalid field values.
    fn validate(&self) -> IpcResult<()>;
}

/// IPC message encoder trait. Implemented by typed message bodies that
/// can be serialised back to a raw [`IpcMessage`] slot.
pub trait IpcMessageEncoderTrait {
    /// Encode this typed message into a raw IPC slot.
    fn encode(self) -> IpcMessage;
}

/// Helper encoder used by the typed message bodies.
pub struct IpcMessageEncoder;

impl IpcMessageEncoder {
    /// Encode a typed message into a raw [`IpcMessage`] slot.
    pub fn encode<T: IpcMessageType + IntoBytes + Immutable>(message: T) -> IpcMessage {
        let mut ipc_message = IpcMessage {
            data: [0; IPC_MESSAGE_LENGTH],
        };
        ipc_message
            .as_mut_bytes()
            .copy_from_slice(message.as_bytes());
        ipc_message
    }
}

/// Helper decoder used to recover typed message bodies from raw IPC slots.
pub struct IpcMessageDecoder;

impl IpcMessageDecoder {
    /// Decode a raw IPC slot into the requested typed message.
    ///
    /// Fails when the header opcode does not match `T::OP`, when the
    /// byte layout cannot be reinterpreted as `T`, or when
    /// `T::validate` rejects the body.
    pub fn decode<T: IpcMessageType + IntoBytes + Immutable + FromBytes>(
        ipc_message: IpcMessage,
    ) -> IpcResult<T> {
        let header = Self::decode_header(&ipc_message)?;
        if header.msg_op() != T::OP as u32 {
            return Err(IpcMessageErr::InvalidOpcodeConversion.into());
        }
        let message = T::read_from_bytes(ipc_message.as_bytes())
            .map_err(|_| u32::from(IpcMessageErr::InvalidInputMessageForDecode))?;
        message.validate()?;
        Ok(message)
    }

    /// Decode just the 32-bit header from a raw IPC slot.
    pub fn decode_header(ipc_message: &IpcMessage) -> IpcResult<IpcMessageHeader> {
        IpcMessageHeader::read_from_bytes(ipc_message.data[0].as_bytes())
            .map_err(|_| u32::from(IpcMessageErr::InvalidMessageHeaderDecode))
    }
}

// ---------------------------------------------------------------------------
// IpcMessageIoStateChange (opcode 0x0)
// ---------------------------------------------------------------------------

/// IO core state value carried by [`IpcMessageIoStateChange`].
#[repr(u8)]
#[open_enum]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable, FromBytes)]
pub enum IoProcessorState {
    /// Normal boot from a POR.
    NormalBoot = 3,

    /// Move IO cores to the start state to begin IO operations.
    Start = 6,

    /// iDFU `WAIT_PREPARE_RELEASE` state.
    PrepareRelease = 10,

    /// iDFU `WAIT_RELEASE` state.
    Release = 11,
}

/// IO state change IPC message body (opcode `StateChange`, 0x0).
#[repr(C)]
#[derive(Debug, IntoBytes, Immutable, FromBytes)]
pub struct IpcMessageIoStateChange {
    /// IPC header fields.
    pub header: IpcMessageHeader,

    /// IO processor state field.
    pub state: IoProcessorState,

    /// Reserved padding so the body fills the 60-byte payload area.
    pub _rsvd: [u8; IPC_MESSAGE_PAYLOAD_LEN - IpcMessageIoStateChange::LEN],
}

const _: () =
    assert!(core::mem::size_of::<IpcMessageIoStateChange>() == core::mem::size_of::<IpcMessage>());

impl Default for IpcMessageIoStateChange {
    fn default() -> Self {
        Self {
            header: IpcMessageHeader::new()
                .with_msg_op(IpcMessageOpCode::StateChange as u32)
                .with_length(Self::LEN as u32),
            state: IoProcessorState::NormalBoot,
            _rsvd: [0; IPC_MESSAGE_PAYLOAD_LEN - Self::LEN],
        }
    }
}

impl IpcMessageType for IpcMessageIoStateChange {
    const OP: IpcMessageOpCode = IpcMessageOpCode::StateChange;
    const LEN: usize = core::mem::size_of::<IoProcessorState>();

    fn validate(&self) -> IpcResult<()> {
        if !matches!(
            self.state,
            IoProcessorState::NormalBoot
                | IoProcessorState::Start
                | IoProcessorState::PrepareRelease
                | IoProcessorState::Release
        ) {
            return Err(IpcMessageErr::InvalidIoStateValue.into());
        }
        Ok(())
    }
}

impl IpcMessageEncoderTrait for IpcMessageIoStateChange {
    fn encode(self) -> IpcMessage {
        IpcMessageEncoder::encode(self)
    }
}

// ---------------------------------------------------------------------------
// Boot handshake helpers
// ---------------------------------------------------------------------------

/// Decode a raw IPC message buffer into an [`IoProcessorState`].
///
/// Returns `None` if the opcode doesn't match `StateChange` or the state
/// is unrecognized.
pub fn decode_state_change(buf: &[u32; IPC_MESSAGE_LENGTH]) -> Option<IoProcessorState> {
    let msg = IpcMessage { data: *buf };
    let decoded = IpcMessageIoStateChange::read_from_bytes(msg.as_bytes()).ok()?;

    let header = decoded.header;
    if header.msg_op() != IpcMessageOpCode::StateChange as u32 {
        return None;
    }

    match decoded.state {
        IoProcessorState::NormalBoot | IoProcessorState::Start => Some(decoded.state),
        _ => None,
    }
}

/// Encode an ACK reply for a state change message.
///
/// Copies the original header, sets the response bit and success status,
/// and echoes the state back.
pub fn encode_state_change_ack(
    original_buf: &[u32; IPC_MESSAGE_LENGTH],
    state: IoProcessorState,
) -> [u32; IPC_MESSAGE_LENGTH] {
    let original_header = IpcMessageHeader::read_from_bytes(original_buf[0].as_bytes())
        .unwrap_or(IpcMessageHeader::new());

    let ack_header = original_header
        .with_response(true)
        .with_status(IpcMessageStatusCode::Success as u32);

    let reply = IpcMessageIoStateChange {
        header: ack_header,
        state,
        _rsvd: [0; IPC_MESSAGE_PAYLOAD_LEN - core::mem::size_of::<IoProcessorState>()],
    };

    let mut out = [0u32; IPC_MESSAGE_LENGTH];
    out.as_mut_bytes().copy_from_slice(reply.as_bytes());
    out
}
// ---------------------------------------------------------------------------
// IpcMessageSetResource (opcode 0x7f)
// ---------------------------------------------------------------------------

/// `SetResource` payload: assigns key-vault tables to a partition.
///
/// Mirrors the reference firmware's `SetResInfo`. The 128-bit `mask`
/// (little-endian) selects which of the 65 global key-vault tables the
/// target partition (`pfn`) owns; a zero mask frees the partition.
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, Immutable, FromBytes)]
pub struct SetResInfo {
    /// 128-bit table-ownership mask (little-endian byte order).
    pub mask: [u8; 16],

    /// Target partition (PCIe function) the mask applies to. The
    /// reference firmware encodes this as a 1-byte `PcieFunction`, not a
    /// `u16` -- a wider field shifts `vm_launch_guid` and corrupts `pfn`.
    pub pfn: u8,

    /// VM launch GUID (unused by the emulator; retained for wire
    /// compatibility with the reference firmware).
    pub vm_launch_guid: [u8; 16],
}

impl SetResInfo {
    /// Decodes the resource mask into a `u128` (little-endian).
    #[inline]
    pub fn mask_u128(&self) -> u128 {
        u128::from_le_bytes(self.mask)
    }
}

/// `SetResource` IPC message body (opcode `SetResource`, 0x7f).
#[repr(C)]
#[derive(Debug, IntoBytes, Immutable, FromBytes)]
pub struct IpcMessageSetResource {
    /// IPC header fields.
    pub header: IpcMessageHeader,

    /// Resource assignment payload.
    pub info: SetResInfo,

    /// Reserved padding so the body fills the 60-byte payload area.
    pub _rsvd: [u8; IPC_MESSAGE_PAYLOAD_LEN - IpcMessageSetResource::LEN],
}

const _: () =
    assert!(core::mem::size_of::<IpcMessageSetResource>() == core::mem::size_of::<IpcMessage>());

// Lock the wire layout: 16-byte mask + 1-byte pfn + 16-byte guid, no padding.
const _: () = assert!(core::mem::size_of::<SetResInfo>() == 33);

impl IpcMessageType for IpcMessageSetResource {
    const OP: IpcMessageOpCode = IpcMessageOpCode::SetResource;
    const LEN: usize = core::mem::size_of::<SetResInfo>();

    fn validate(&self) -> IpcResult<()> {
        if usize::from(self.info.pfn) >= crate::part::NUM_PARTITIONS {
            return Err(IpcMessageErr::InvalidPartitionId.into());
        }
        Ok(())
    }
}

/// Decode a raw IPC buffer into an [`IpcMessageSetResource`].
///
/// Returns `None` if the opcode does not match or the body fails to
/// decode/validate.
pub fn decode_set_resource(buf: &[u32; IPC_MESSAGE_LENGTH]) -> Option<IpcMessageSetResource> {
    let msg = IpcMessage { data: *buf };
    IpcMessageDecoder::decode::<IpcMessageSetResource>(msg).ok()
}

/// Encode an ACK reply for a `SetResource` message.
///
/// Copies the original header, sets the response bit, writes `status`,
/// and reports the resulting owned-table count in the first payload byte.
pub fn encode_set_resource_ack(
    original_buf: &[u32; IPC_MESSAGE_LENGTH],
    status: IpcMessageStatusCode,
    res_count: u8,
) -> [u32; IPC_MESSAGE_LENGTH] {
    let original_header = IpcMessageHeader::read_from_bytes(original_buf[0].as_bytes())
        .unwrap_or(IpcMessageHeader::new());

    let ack_header = original_header
        .with_response(true)
        .with_status(status as u32);

    let mut out = *original_buf;
    out[0] = ack_header.into_bits();
    // Report the owned-table count in the first payload byte.
    out[1] = res_count as u32;
    out
}
// ---------------------------------------------------------------------------
// IpcMessagePfnEnableDisable (opcode 0x5)
// ---------------------------------------------------------------------------

/// Partition (PCIe function) enable / disable action.
#[repr(u8)]
#[open_enum]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable, FromBytes)]
pub enum PfnEnableDisableAction {
    /// Disable the partition (`Enabled` → `Disabled`).
    Disable = 0,

    /// Enable the partition (`Allocated` | `Disabled` → `Enabled`).
    Enable = 1,

    /// Reset / migrate the partition.
    Migrate = 2,
}

/// `PfnEnableDisable` payload: targets one partition and an action.
///
/// Mirrors the reference firmware's `PfnEnableDisableInfo`.
#[repr(C)]
#[derive(Debug, Clone, Copy, IntoBytes, Immutable, FromBytes)]
pub struct PfnEnableDisableInfo {
    /// Target partition (PCIe function); 1-byte `PcieFunction` on the wire.
    pub pfn: u8,

    /// Action to perform (`Disable` / `Enable` / `Migrate`).
    pub action: u8,
}

/// `PfnEnableDisable` IPC message body (opcode `PfnEnableDisable`, 0x5).
#[repr(C)]
#[derive(Debug, IntoBytes, Immutable, FromBytes)]
pub struct IpcMessagePfnEnableDisable {
    /// IPC header fields.
    pub header: IpcMessageHeader,

    /// Enable / disable payload.
    pub info: PfnEnableDisableInfo,

    /// Reserved padding so the body fills the 60-byte payload area.
    pub _rsvd: [u8; IPC_MESSAGE_PAYLOAD_LEN - IpcMessagePfnEnableDisable::LEN],
}

const _: () = assert!(
    core::mem::size_of::<IpcMessagePfnEnableDisable>() == core::mem::size_of::<IpcMessage>()
);

impl IpcMessageType for IpcMessagePfnEnableDisable {
    const OP: IpcMessageOpCode = IpcMessageOpCode::PfnEnableDisable;
    const LEN: usize = core::mem::size_of::<PfnEnableDisableInfo>();

    fn validate(&self) -> IpcResult<()> {
        if usize::from(self.info.pfn) >= crate::part::NUM_PARTITIONS {
            return Err(IpcMessageErr::InvalidPartitionId.into());
        }
        Ok(())
    }
}

/// Decode a raw IPC buffer into an [`IpcMessagePfnEnableDisable`].
///
/// Returns `None` if the opcode does not match or the body fails to
/// decode/validate.
pub fn decode_pfn_enable_disable(
    buf: &[u32; IPC_MESSAGE_LENGTH],
) -> Option<IpcMessagePfnEnableDisable> {
    let msg = IpcMessage { data: *buf };
    IpcMessageDecoder::decode::<IpcMessagePfnEnableDisable>(msg).ok()
}

/// Encode an ACK reply for a `PfnEnableDisable` message.
///
/// Copies the original header, sets the response bit and `status`.
pub fn encode_pfn_enable_disable_ack(
    original_buf: &[u32; IPC_MESSAGE_LENGTH],
    status: IpcMessageStatusCode,
) -> [u32; IPC_MESSAGE_LENGTH] {
    let original_header = IpcMessageHeader::read_from_bytes(original_buf[0].as_bytes())
        .unwrap_or(IpcMessageHeader::new());

    let ack_header = original_header
        .with_response(true)
        .with_status(status as u32);

    let mut out = *original_buf;
    out[0] = ack_header.into_bits();
    out
}
