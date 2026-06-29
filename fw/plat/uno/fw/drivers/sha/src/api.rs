// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::future::poll_fn;
use core::task::Poll;

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_single_cell::SingleCell;
use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_drivers_nvic::Nvic;
use azihsm_fw_uno_error::HsmResult;
use azihsm_fw_uno_pac::Interrupt;
use azihsm_fw_uno_reg_soc::io_gsram::regs::IoGsramRegs;
use azihsm_fw_uno_reg_soc::io_gsram::ShaCmdEntry;
use azihsm_fw_uno_reg_soc::io_gsram::*;
use azihsm_fw_uno_reg_soc::sha::regs::ShaRegs;
use azihsm_fw_uno_reg_soc::sha::SHA_BASE;
use bitfield_struct::bitfield;
use embassy_sync::waitqueue::WakerRegistration;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;

use crate::ShaError;

/// SHA peripheral MMIO registers.
const SHA: StaticRef<ShaRegs> = unsafe { StaticRef::new(SHA_BASE as *const ShaRegs) };

/// DTCM overlay for SHA command descriptors.
const SHA_Q: StaticRef<IoGsramRegs> =
    unsafe { StaticRef::new(IO_GSRAM_BASE as *const IoGsramRegs) };

/// Status flag mask (read-side decode): COMPLETE, ERROR_*, DIGEST_MATCH.
const STATUS_FLAGS_MASK: u32 = 0x5E;

#[bitfield(u32)]
struct ShaCmdCode {
    /// Load initial digest from memory.
    #[bits(1)]
    load_digest: bool,

    #[bits(3)]
    _rsvd0: u8,

    /// Write full working variable size instead of NIST digest.
    #[bits(1)]
    dont_truncate: bool,

    #[bits(3)]
    _rsvd1: u8,

    /// Enable automatic SHA padding.
    #[bits(1)]
    auto_pad: bool,

    /// Read message addressing mode (must be 0 = INCR).
    #[bits(2)]
    read_message_mode: u8,

    #[bits(5)]
    _rsvd2: u8,

    /// SHA algorithm selector.
    #[bits(4)]
    sha_mode: u8,

    /// Byte-swap digest output.
    #[bits(1)]
    digest_byte_swap: bool,

    /// Compare computed digest against reference.
    #[bits(1)]
    check_digest: bool,

    /// Pass-through message write mode.
    #[bits(2)]
    pass_message_mode: u8,

    #[bits(4)]
    _rsvd3: u8,

    /// Command tag, must be 0x3.
    #[bits(4)]
    tag: u8,
}

/// SHA algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ShaMode {
    /// SHA-1, 20-byte digest, 64-byte block size.
    Sha1 = 1,

    /// SHA-224, 28-byte digest, 64-byte block size.
    Sha224 = 2,

    /// SHA-256, 32-byte digest, 64-byte block size.
    Sha256 = 3,

    /// SHA-384, 48-byte digest, 128-byte block size.
    Sha384 = 4,

    /// SHA-512, 64-byte digest, 128-byte block size.
    Sha512 = 5,

    /// SHA-512/224, 28-byte digest, 128-byte block size.
    Sha512_224 = 6,

    /// SHA-512/256, 32-byte digest, 128-byte block size.
    Sha512_256 = 7,
}

impl From<azihsm_fw_hsm_pal_traits::HsmHashAlgo> for ShaMode {
    fn from(algo: azihsm_fw_hsm_pal_traits::HsmHashAlgo) -> Self {
        use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
        match algo {
            HsmHashAlgo::Sha1 => Self::Sha1,
            HsmHashAlgo::Sha256 => Self::Sha256,
            HsmHashAlgo::Sha384 => Self::Sha384,
            HsmHashAlgo::Sha512 => Self::Sha512,
        }
    }
}

/// High-level SHA request submitted to [`ShaDriver::digest`].
#[derive(Debug)]
pub struct ShaRequest<'a> {
    /// SHA algorithm.
    pub mode: ShaMode,

    /// Message to hash.
    pub message: &'a DmaBuf,

    /// Output digest buffer. Also used as initial state input when
    /// `load_digest` is true and `initial_digest` is `None` — the
    /// hardware reads the current contents before overwriting.
    pub digest: &'a mut DmaBuf,

    /// Enable automatic padding. When true, `byte_count` is used for the
    /// length field embedded in the padded message.
    pub auto_pad: bool,

    /// Total message length in bytes used by automatic padding.
    pub byte_count: u32,

    /// Load initial hash state instead of FIPS constants. When true,
    /// the state is read from `initial_digest` if provided, or from
    /// `digest` itself (zero-copy in-place reload).
    pub load_digest: bool,

    /// Separate initial digest buffer. When `None` and `load_digest`
    /// is true, the current contents of `digest` are used.
    pub initial_digest: Option<&'a DmaBuf>,

    /// Write the full working-variable state instead of the NIST digest size.
    pub dont_truncate: bool,

    /// Byte-swap the output digest.
    pub digest_byte_swap: bool,

    /// Compare the computed digest against `ref_digest`.
    pub check_digest: bool,

    /// Reference digest used when `check_digest` is enabled.
    pub ref_digest: Option<&'a DmaBuf>,
}

impl<'a> ShaRequest<'a> {
    /// Create a request with the required fields; all options default off.
    pub fn new(mode: ShaMode, message: &'a DmaBuf, digest: &'a mut DmaBuf) -> Self {
        Self {
            mode,
            message,
            digest,
            auto_pad: false,
            byte_count: 0,
            load_digest: false,
            initial_digest: None,
            dont_truncate: false,
            digest_byte_swap: false,
            check_digest: false,
            ref_digest: None,
        }
    }

    /// Enable auto-padding with the given total byte count.
    pub fn with_auto_pad(mut self, byte_count: u32) -> Self {
        self.auto_pad = true;
        self.byte_count = byte_count;
        self
    }

    /// Load initial state from `digest` buffer before processing.
    pub fn with_load_digest(mut self) -> Self {
        self.load_digest = true;
        self
    }

    /// Output full working-variable state (for multi-step chaining).
    pub fn with_full_state(mut self) -> Self {
        self.dont_truncate = true;
        self
    }

    /// Byte-swap the output digest (little-endian output).
    pub fn with_byte_swap(mut self) -> Self {
        self.digest_byte_swap = true;
        self
    }

    /// Compare the computed digest against the provided reference digest.
    pub fn with_check_digest(mut self, ref_digest: &'a DmaBuf) -> Self {
        self.check_digest = true;
        self.ref_digest = Some(ref_digest);
        self
    }

    /// Load initial state from a separate buffer instead of `digest`.
    ///
    /// When combined with [`with_load_digest`](Self::with_load_digest),
    /// the hardware reads initial state from `initial` rather than
    /// `digest`. This allows the digest output to target a different
    /// buffer than the state input — enabling zero-copy finalization.
    pub fn with_initial_digest(mut self, initial: &'a DmaBuf) -> Self {
        self.load_digest = true;
        self.initial_digest = Some(initial);
        self
    }
}

struct WaiterSlot {
    /// Waker registration for async notification when this slot completes
    /// or becomes the active exclusive slot.
    waker: WakerRegistration,

    /// Completion status flags from the STATUS register, set by
    /// [`ShaDriver::wake`]. Zero means not yet completed.
    status: u8,

    /// True for [`ShaDriver::with_exclusive`] slots — prevents
    /// [`ShaDriver::wake`] from submitting a command for this slot.
    exclusive: bool,
}

struct ShaState<const DEPTH: usize> {
    /// Per-slot waiter state (waker, status, exclusive flag).
    slots: [WaiterSlot; DEPTH],

    /// Index of the oldest unconsumed slot.
    head: u8,

    /// Index of the slot currently in hardware / next to submit.
    active: u8,

    /// Index of the next slot to allocate.
    tail: u8,
}

/// Async SHA driver.
///
/// Serializes concurrent callers — only one SHA command is in flight at a time.
/// Additional callers are queued and served in FIFO order.
///
/// # Type Parameters
///
/// - `DEPTH`: Maximum number of concurrent waiters. Must be a power of 2,
///   at most 128.
pub struct ShaDriver<const DEPTH: usize> {
    state: SingleCell<ShaState<DEPTH>>,
}

impl<const DEPTH: usize> core::fmt::Debug for ShaDriver<DEPTH> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShaDriver").field("DEPTH", &DEPTH).finish()
    }
}

impl<const DEPTH: usize> ShaDriver<DEPTH> {
    const MASK: u8 = (DEPTH - 1) as u8;

    const _ASSERT_DEPTH_NONZERO: () = assert!(DEPTH > 0, "DEPTH must be > 0");
    const _ASSERT_DEPTH_POW2: () = assert!(DEPTH.is_power_of_two(), "DEPTH must be power of 2");
    const _ASSERT_DEPTH_MAX: () = assert!(DEPTH <= 128, "DEPTH must be <= 128 (u8 indices)");
    const _ASSERT_DEPTH_FIT: () = assert!(
        DEPTH <= SHA_CMD_COUNT as usize,
        "DEPTH exceeds SHA_CMD capacity"
    );

    /// Initialize the SHA peripheral and return a driver instance.
    ///
    /// Clears any stale status flags. NVIC interrupt enabling is the
    /// responsibility of the caller.
    ///
    /// # Panics
    ///
    /// Compile-time assertion if `DEPTH` is 0, not a power of 2, or exceeds 128.
    pub fn new() -> Self {
        #[allow(clippy::let_unit_value)]
        let _ = (
            Self::_ASSERT_DEPTH_NONZERO,
            Self::_ASSERT_DEPTH_POW2,
            Self::_ASSERT_DEPTH_MAX,
            Self::_ASSERT_DEPTH_FIT,
        );

        Self {
            state: SingleCell::new(ShaState {
                slots: core::array::from_fn(|_| WaiterSlot {
                    waker: WakerRegistration::new(),
                    status: 0,
                    exclusive: false,
                }),
                head: 0,
                active: 0,
                tail: 0,
            }),
        }
    }

    /// Submit a SHA digest request and await completion.
    ///
    /// Concurrent callers are queued (up to `DEPTH`) and served in FIFO order.
    /// Returns [`ShaError::QUEUE_FULL`] if all slots are occupied.
    pub async fn digest<'a>(&'a self, req: ShaRequest<'a>) -> HsmResult<()> {
        let status = self.digest_status(req).await?;
        map_status(status)
    }

    /// Submit a SHA request with digest comparison enabled and return whether it matched.
    pub async fn digest_verify<'a>(&'a self, req: ShaRequest<'a>) -> HsmResult<bool> {
        // `digest_verify()` must always execute the hardware compare path. If we
        // forwarded a request with `check_digest == false`, the operation would
        // complete without performing any comparison and could be misreported as
        // a simple mismatch.
        let mut req = req;
        req.check_digest = true;

        let status = self.digest_status(req).await?;
        map_verify_status(status)
    }

    fn digest_status<'a>(
        &'a self,
        req: ShaRequest<'a>,
    ) -> impl core::future::Future<Output = HsmResult<u8>> + 'a {
        let mut slot_idx: Option<u8> = None;

        poll_fn(move |cx| {
            self.state.with(|s| {
                if slot_idx.is_none() {
                    if let Err(e) = validate(&req) {
                        return Poll::Ready(Err(e));
                    }
                    let Ok(mode) = mode_field(req.mode) else {
                        return Poll::Ready(Err(ShaError::INVALID_MODE));
                    };
                    if s.tail.wrapping_sub(s.head) as usize >= DEPTH {
                        return Poll::Ready(Err(ShaError::QUEUE_FULL));
                    }

                    let idx = (s.tail & Self::MASK) as usize;
                    let was_empty = s.active == s.tail;
                    slot_idx = Some(s.tail);
                    s.tail = s.tail.wrapping_add(1);

                    write_cmd(idx, &req, mode);

                    if was_empty {
                        submit_cmd(idx);
                    }
                }

                let idx = (slot_idx.unwrap() & Self::MASK) as usize;
                let slot = &mut s.slots[idx];

                if slot.status != 0 {
                    let status = slot.status;
                    slot.status = 0;

                    while s.head != s.active && s.slots[(s.head & Self::MASK) as usize].status == 0
                    {
                        s.head = s.head.wrapping_add(1);
                    }

                    return Poll::Ready(Ok(status));
                }

                slot.waker.register(cx.waker());
                Poll::Pending
            })
        })
    }

    /// Wake the driver on SHA completion.
    ///
    /// Call from the `SHA_DONE` IRQ handler (interrupt mode) or the main
    /// poll loop (polling mode).
    pub fn wake(&self) {
        let status = SHA.status.get();
        let flags = status & STATUS_FLAGS_MASK;
        if flags == 0 {
            return;
        }

        // STATUS (SHA_BASE + 0x4) is read-only (RO32): the COMPLETE/ERROR bits
        // auto-clear when the next command doorbell sets BUSY. Writing it
        // bus-faults the engine and hard-faults the CPU, so only clear the
        // NVIC pending bit here.
        Nvic::unpend(Interrupt::SHA_DONE);

        self.state.with(|s| {
            if s.active != s.tail {
                let idx = (s.active & Self::MASK) as usize;
                let slot = &mut s.slots[idx];
                slot.status = flags as u8;
                slot.waker.wake();

                s.active = s.active.wrapping_add(1);
                if s.active != s.tail {
                    let next = (s.active & Self::MASK) as usize;
                    if !s.slots[next].exclusive {
                        submit_cmd(next);
                    } else {
                        // Exclusive slot — wake it so it can start its
                        // synchronous work. Don't submit a command.
                        s.slots[next].waker.wake();
                    }
                }
            }
        });
    }

    /// Acquire exclusive synchronous access to the SHA engine.
    ///
    /// Allocates a waiter slot and waits (async) for it to become the active
    /// slot — meaning all prior callers have completed and the hardware is
    /// available. Then runs `f` synchronously with a [`ShaExclusive`] handle
    /// that exposes busy-polled [`digest`](ShaExclusive::digest) and
    /// [`digest_verify`](ShaExclusive::digest_verify) methods. The slot is
    /// released when the closure returns, waking the next queued caller.
    ///
    /// Multiple tasks may call `with_exclusive` concurrently — they queue
    /// behind each other and behind regular [`digest`](Self::digest) calls
    /// through the same FIFO slot queue.
    ///
    /// This is designed for multi-invocation patterns (MGF1, HKDF, PBKDF2)
    /// where the overhead of poll/wake per SHA call is undesirable. One
    /// async boundary to acquire hardware, N synchronous hashes, one wake
    /// on release.
    ///
    /// # Cancellation safety
    ///
    /// The slot is allocated on the first poll and must be consumed. Dropping
    /// the future after slot allocation but before completion will leave a
    /// dead slot that blocks the queue. Callers must not cancel this future
    /// after the first poll.
    pub async fn with_exclusive<F, R>(&self, f: F) -> HsmResult<R>
    where
        F: FnOnce(&ShaExclusive<'_, DEPTH>) -> HsmResult<R>,
    {
        let mut slot_idx: Option<u8> = None;

        // Wait for our slot to become the active one.
        poll_fn(|cx| {
            self.state.with(|s| {
                if slot_idx.is_none() {
                    if s.tail.wrapping_sub(s.head) as usize >= DEPTH {
                        return Poll::Ready(Err(ShaError::QUEUE_FULL));
                    }
                    let idx = (s.tail & Self::MASK) as usize;
                    s.slots[idx].exclusive = true;
                    slot_idx = Some(s.tail);
                    s.tail = s.tail.wrapping_add(1);
                }

                // Our slot is active when active has reached it — all prior
                // commands have completed and the hardware is free.
                if s.active == slot_idx.unwrap() {
                    Poll::Ready(Ok(()))
                } else {
                    let idx = (slot_idx.unwrap() & Self::MASK) as usize;
                    s.slots[idx].waker.register(cx.waker());
                    Poll::Pending
                }
            })
        })
        .await?;

        let result = f(&ShaExclusive {
            driver: self,
            slot_idx: (slot_idx.unwrap() & Self::MASK) as usize,
        });

        // Release our slot: clear exclusive flag, advance head and active
        // past it, then submit/wake the next queued slot if present.
        self.state.with(|s| {
            let my = slot_idx.unwrap();
            let idx = (my & Self::MASK) as usize;
            s.slots[idx].exclusive = false;
            s.active = my.wrapping_add(1);
            s.head = my.wrapping_add(1);
            if s.active != s.tail {
                let next = (s.active & Self::MASK) as usize;
                if !s.slots[next].exclusive {
                    submit_cmd(next);
                } else {
                    s.slots[next].waker.wake();
                }
            }
        });

        result
    }
}

/// Exclusive synchronous handle to the SHA engine.
///
/// Provides busy-polled [`digest`](Self::digest) and
/// [`digest_verify`](Self::digest_verify) methods that submit a command
/// and spin on the hardware status register instead of yielding to the
/// async executor.
///
/// Cannot be constructed directly — only obtained through
/// [`ShaDriver::with_exclusive`].
#[derive(Debug)]
pub struct ShaExclusive<'a, const DEPTH: usize> {
    /// Ties the lifetime to the owning [`ShaDriver`]. Not read at runtime —
    /// hardware access goes through module-level statics.
    #[allow(dead_code)]
    driver: &'a ShaDriver<DEPTH>,

    /// The ring-buffer slot index (`raw_tail & MASK`) reserved for this
    /// exclusive session. Passed to `submit_and_spin` so it writes and submits
    /// the command descriptor into the correct slot instead of hard-coding 0.
    slot_idx: usize,
}

impl<const DEPTH: usize> ShaExclusive<'_, DEPTH> {
    /// Submit a SHA request and busy-poll until completion.
    ///
    /// Identical to [`ShaDriver::digest`] but runs synchronously, spinning
    /// on the hardware status register instead of yielding to the executor.
    pub fn digest(&self, req: ShaRequest<'_>) -> HsmResult<()> {
        let status = self.submit_and_spin(&req)?;
        map_status(status)
    }

    /// Submit a SHA request with digest comparison and busy-poll until
    /// completion.
    ///
    /// Synchronous variant of [`ShaDriver::digest_verify`].
    pub fn digest_verify(&self, req: ShaRequest<'_>) -> HsmResult<bool> {
        let status = self.submit_and_spin(&req)?;
        map_verify_status(status)
    }

    /// Write the command descriptor, submit to hardware, and spin until the
    /// status register indicates completion. Clears NVIC pending after
    /// consuming the status to prevent stale pending bits from triggering
    /// a spurious [`ShaDriver::wake`] call when normal polling resumes.
    fn submit_and_spin(&self, req: &ShaRequest<'_>) -> HsmResult<u8> {
        // `self.driver` ensures this method can only be called via a valid
        // ShaExclusive handle — the field itself is not read at runtime.
        //
        // Use the descriptor slot reserved for this exclusive session rather
        // than hard-coding slot 0. The normal async path may continue to
        // enqueue descriptors into the shared ring while exclusivity is held,
        // so reusing slot 0 here can clobber an in-flight async command (or
        // be clobbered by one when the ring wraps).
        validate(req)?;
        let mode = mode_field(req.mode)?;
        let cmd_idx = self.slot_idx & (DEPTH - 1);
        write_cmd(cmd_idx, req, mode);
        submit_cmd(cmd_idx);

        loop {
            let status = SHA.status.get();
            let flags = status & STATUS_FLAGS_MASK;
            if flags != 0 {
                // STATUS is read-only; do not write it (bus-faults). It
                // auto-clears on the next command doorbell.
                Nvic::unpend(Interrupt::SHA_DONE);
                return Ok(flags as u8);
            }
        }
    }
}

fn submit_cmd(slot: usize) {
    let desc_addr = IO_GSRAM_BASE + SHA_CMD_OFFSET + (slot as u32) * SHA_CMD_STRIDE;
    SHA.command.set(desc_addr);
}

/// Write a SHA command descriptor to the DTCM slot at `idx`.
///
/// The caller must have validated the request and obtained the `mode` byte
/// via [`mode_field`] before calling this function. The actual hardware
/// submission happens separately via [`submit_cmd`].
fn write_cmd(idx: usize, req: &ShaRequest<'_>, mode: u8) {
    let cmd = ShaCmdCode::new()
        .with_tag(0x3)
        .with_sha_mode(mode)
        .with_auto_pad(req.auto_pad)
        .with_load_digest(req.load_digest)
        .with_dont_truncate(req.dont_truncate)
        .with_digest_byte_swap(req.digest_byte_swap)
        .with_check_digest(req.check_digest);
    let initial_digest_addr = if req.load_digest {
        req.initial_digest
            .map_or(req.digest.as_ptr() as u32, |d| d.as_ptr() as u32)
    } else {
        0
    };
    let ref_digest_addr = req.ref_digest.map_or(0, |d| d.as_ptr() as u32);
    // Plain pointer writes — SHA_CMD is in DTCM, not MMIO.
    // The COMMAND register write (submit_cmd) is the barrier.
    let entry_ptr = (&SHA_Q.sha_cmd[idx]) as *const ShaCmdEntry as *mut u32;
    unsafe {
        entry_ptr.add(0).write(cmd.into());
        entry_ptr.add(1).write(req.digest.as_ptr() as u32);
        entry_ptr.add(2).write(req.byte_count);
        entry_ptr.add(3).write(req.message.len() as u32);
        entry_ptr.add(4).write(req.message.as_ptr() as u32);
        entry_ptr.add(5).write(initial_digest_addr);
        entry_ptr.add(6).write(0);
        entry_ptr.add(7).write(ref_digest_addr);
    }
}

fn mode_field(mode: ShaMode) -> HsmResult<u8> {
    let mode = mode as u8;
    if (1..=7).contains(&mode) {
        Ok(mode)
    } else {
        Err(ShaError::INVALID_MODE)
    }
}

fn digest_size(mode: ShaMode) -> usize {
    match mode {
        ShaMode::Sha1 => 20,
        ShaMode::Sha224 => 28,
        ShaMode::Sha256 => 32,
        ShaMode::Sha384 => 48,
        ShaMode::Sha512 => 64,
        ShaMode::Sha512_224 => 28,
        ShaMode::Sha512_256 => 32,
    }
}

fn working_var_size(mode: ShaMode) -> usize {
    match mode {
        ShaMode::Sha1 => 20,
        ShaMode::Sha224 | ShaMode::Sha256 => 32,
        ShaMode::Sha384 | ShaMode::Sha512 | ShaMode::Sha512_224 | ShaMode::Sha512_256 => 64,
    }
}

fn block_len(mode: ShaMode) -> usize {
    match mode {
        ShaMode::Sha1 | ShaMode::Sha224 | ShaMode::Sha256 => 64,
        ShaMode::Sha384 | ShaMode::Sha512 | ShaMode::Sha512_224 | ShaMode::Sha512_256 => 128,
    }
}

fn output_size(req: &ShaRequest<'_>) -> usize {
    if req.dont_truncate {
        working_var_size(req.mode)
    } else {
        digest_size(req.mode)
    }
}

fn validate(req: &ShaRequest<'_>) -> HsmResult<()> {
    let _ = mode_field(req.mode)?;

    if req.auto_pad {
        if req.byte_count < req.message.len() as u32 {
            return Err(ShaError::INVALID_MSG_LEN);
        }
    } else if !req.message.len().is_multiple_of(block_len(req.mode)) {
        return Err(ShaError::INVALID_MSG_LEN);
    }
    if req.digest.len() < output_size(req) {
        return Err(ShaError::CMD_ERROR);
    }
    if req.load_digest {
        match req.initial_digest {
            Some(initial_digest) if initial_digest.len() >= working_var_size(req.mode) => {}
            None if req.digest.len() >= working_var_size(req.mode) => {}
            _ => return Err(ShaError::CMD_ERROR),
        }
    }
    if req.check_digest {
        match req.ref_digest {
            Some(ref_digest) if ref_digest.len() >= digest_size(req.mode) => {}
            _ => return Err(ShaError::CMD_ERROR),
        }
    }

    Ok(())
}

fn map_status(status: u8) -> HsmResult<()> {
    if status & (1 << 1) != 0 {
        return Ok(());
    }
    if status & (1 << 2) != 0 {
        return Err(ShaError::CMD_ERROR);
    }
    if status & (1 << 3) != 0 {
        return Err(ShaError::BUS_ERROR);
    }
    if status & (1 << 4) != 0 {
        return Err(ShaError::FAULT_ERROR);
    }
    Err(ShaError::FAULT_ERROR)
}

fn map_verify_status(status: u8) -> HsmResult<bool> {
    map_status(status)?;
    Ok(status & (1 << 6) != 0)
}
