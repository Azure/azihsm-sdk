// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public PKA type definitions.

/// ECC curve selector.
///
/// Selects the hardware curve profile for ECC commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpkaEccCurve {
    /// NIST P-256.
    P256,

    /// NIST P-384.
    P384,

    /// NIST P-521.
    P521,
}

/// RSA key size selector.
///
/// Legacy size-only selector retained for compatibility. Prefer
/// [`UpkaRsaKeyType`] for new code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpkaRsaSize {
    /// RSA-2048.
    Rsa2k,

    /// RSA-3072.
    Rsa3k,

    /// RSA-4096.
    Rsa4k,
}

/// RSA key type selector (combines modulus size and CRT format).
///
/// This type prevents invalid combinations by coupling key width and
/// private-key format in one enum value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpkaRsaKeyType {
    /// RSA-2048 standard format.
    Rsa2048,

    /// RSA-2048 CRT format.
    Rsa2048Crt,

    /// RSA-3072 standard format.
    Rsa3072,

    /// RSA-3072 CRT format.
    Rsa3072Crt,

    /// RSA-4096 standard format.
    Rsa4096,

    /// RSA-4096 CRT format.
    Rsa4096Crt,
}

/// Monotonic identifier assigned to each submitted command request.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(u16);

impl RequestId {
    /// Create a request identifier from a raw value.
    ///
    /// # Parameters
    ///
    /// - `raw`: Raw request identifier value.
    ///
    /// # Returns
    ///
    /// - `RequestId` wrapper around `raw`.
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Return the raw request identifier value.
    ///
    /// # Returns
    ///
    /// - Raw `u16` request identifier.
    pub const fn raw(self) -> u16 {
        self.0
    }
}

/// Logical UPKA engine identifier.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EngineId(u8);

impl EngineId {
    /// Create an engine identifier from a raw engine index.
    ///
    /// # Parameters
    ///
    /// - `raw`: Raw engine index.
    ///
    /// # Returns
    ///
    /// - `EngineId` wrapper around `raw`.
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Return the raw engine index.
    ///
    /// # Returns
    ///
    /// - Raw `u8` engine index.
    pub const fn raw(self) -> u8 {
        self.0
    }
}

/// Queue slot identifier in the pre-staging ring.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueueSlotId(u8);

impl QueueSlotId {
    /// Create a queue slot identifier from a raw slot index.
    ///
    /// # Parameters
    ///
    /// - `raw`: Raw queue slot index.
    ///
    /// # Returns
    ///
    /// - `QueueSlotId` wrapper around `raw`.
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Return the raw queue slot index.
    ///
    /// # Returns
    ///
    /// - Raw `u8` queue slot index.
    pub const fn raw(self) -> u8 {
        self.0
    }
}

/// Wipe behavior requested after command completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WipePolicy {
    /// Do not wipe the engine state after command completion.
    NoWipe,

    /// Wipe only when the command itself succeeds.
    WipeOnSuccess,

    /// Always attempt a wipe after command completion.
    WipeAlways,
}

/// Opaque command completion status reported by hardware.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CommandStatus(u8);

impl CommandStatus {
    /// Create a command status from a raw status byte.
    ///
    /// # Parameters
    ///
    /// - `raw`: Hardware status byte captured at completion.
    ///
    /// # Returns
    ///
    /// - `CommandStatus` wrapper around `raw`.
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// Return the raw hardware status byte.
    ///
    /// # Returns
    ///
    /// - Raw `u8` completion status.
    pub const fn raw(self) -> u8 {
        self.0
    }
}

/// Normalized request payload submitted through the scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandRequest {
    /// Unique request identifier.
    pub id: RequestId,

    /// Hardware opcode for the operation.
    pub opcode: u32,

    /// Result pointer written by hardware.
    pub result_ptr: u32,

    /// First opcode argument.
    pub arg1: u32,

    /// Second opcode argument.
    pub arg2: u32,

    /// Third opcode argument.
    pub arg3: u32,

    /// Wipe policy applied after command completion.
    pub wipe_policy: WipePolicy,
}

/// Final command outcome returned by the orchestration layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandOutcome {
    /// Queue slot used by this command.
    pub queue_slot: QueueSlotId,

    /// Final command completion status.
    pub status: CommandStatus,
}

/// Explicit lifecycle state of a queue slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueSlotState {
    /// Slot is free and available for a new request.
    Free,

    /// Slot contains a queued request not yet assigned to an engine.
    Pending {
        /// Request associated with this slot.
        req: RequestId,

        /// Whether descriptor data was already staged.
        pre_staged: bool,
    },

    /// Slot has been assigned to an engine and is waiting for completion.
    Assigned {
        /// Request associated with this slot.
        req: RequestId,

        /// Engine assigned to execute this request.
        engine: EngineId,

        /// Whether descriptor data was already staged.
        pre_staged: bool,
    },

    /// Slot is processing completion bookkeeping.
    Completing {
        /// Request associated with this slot.
        req: RequestId,

        /// Engine currently completing the request.
        engine: EngineId,
    },
}

/// Explicit lifecycle state of one hardware engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    /// Engine is idle and available for assignment.
    Idle,

    /// Engine is running a command.
    Running {
        /// Request currently executing on this engine.
        req: RequestId,
    },

    /// Engine is running a wipe command.
    Wiping {
        /// Request whose post-command wipe is running.
        req: RequestId,
    },
}
