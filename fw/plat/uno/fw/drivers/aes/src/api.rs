// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::future::poll_fn;
use core::task::Poll;

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_single_cell::SingleCell;
use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_drivers_nvic::Nvic;
use azihsm_fw_uno_error::HsmResult;
use azihsm_fw_uno_pac::interrupt::Interrupt;
use azihsm_fw_uno_reg_soc::aes::regs::AesRegs;
use azihsm_fw_uno_reg_soc::aes::AES_BASE;
use azihsm_fw_uno_reg_soc::io_gsram::regs::IoGsramRegs;
use azihsm_fw_uno_reg_soc::io_gsram::*;
use bitfield_struct::bitfield;
use embassy_sync::waitqueue::WakerRegistration;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;

use crate::AesError;

/// AES peripheral MMIO registers.
const AES: StaticRef<AesRegs> = unsafe { StaticRef::new(AES_BASE as *const AesRegs) };

/// DTCM overlay for AES command descriptors.
const AES_Q: StaticRef<IoGsramRegs> =
    unsafe { StaticRef::new(IO_GSRAM_BASE as *const IoGsramRegs) };

/// Status flag mask (read-side decode): COMPLETE, ERROR_CMD, ERROR_BUS, ERROR_FAULT.
const STATUS_FLAGS_MASK: u32 = 0x1E;

/// AES block size in bytes.
pub const AES_BLOCK_SIZE: usize = 16;

/// AES IV size in bytes.
pub const AES_IV_SIZE: usize = 16;

// ── Command code bit layout (must match the AES peripheral spec) ──

#[bitfield(u32)]
struct AesCmdCode {
    /// Key length: 1=128-bit, 2=192-bit, 3=256-bit.
    #[bits(2)]
    key_len: u8,

    #[bits(10)]
    _rsvd0: u16,

    /// Write updated IV back (CBC only).
    #[bits(1)]
    update_iv: bool,

    #[bits(3)]
    _rsvd1: u8,

    /// Encrypt (1) or decrypt (0).
    #[bits(1)]
    encrypt: bool,

    #[bits(7)]
    _rsvd2: u8,

    /// Cipher mode (1=ECB, 2=CBC, 3=CTR).
    #[bits(4)]
    mode: u8,

    /// Command tag, must be 0x2.
    #[bits(4)]
    tag: u8,
}

/// AES cipher mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AesMode {
    /// Electronic Codebook — no IV.
    Ecb = 1,
    /// Cipher Block Chaining — requires a 16-byte IV.
    Cbc = 2,
    /// Counter mode — requires a 16-byte counter block IV.
    Ctr = 3,
}

/// AES operation direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesOp {
    Decrypt,
    Encrypt,
}

fn key_len_field(key_len: usize) -> Result<u8, azihsm_fw_uno_error::HsmError> {
    match key_len {
        16 => Ok(1),
        24 => Ok(2),
        32 => Ok(3),
        _ => Err(AesError::INVALID_KEY_LEN),
    }
}

/// High-level AES request submitted to [`AesDriver::encrypt_decrypt`].
#[derive(Debug)]
pub struct AesRequest<'a> {
    pub mode: AesMode,
    pub op: AesOp,
    /// AES key bytes. Length must be 16, 24, or 32.
    pub key: &'a DmaBuf,
    /// IV for CBC/CTR (exactly 16 bytes). May be `None` for ECB.
    /// If `update_iv` is true, the IV is written back with the final
    /// chaining block.
    pub iv: Option<&'a mut DmaBuf>,
    /// When true (CBC only), the hardware writes the updated IV back.
    pub update_iv: bool,
    /// Plaintext or ciphertext input. ECB/CBC lengths must be a non-zero
    /// multiple of 16; CTR lengths may be any non-zero byte count.
    pub message: &'a DmaBuf,
    /// Output buffer. Must be at least as large as `message`.
    pub result: &'a mut DmaBuf,
}

struct WaiterSlot {
    /// Waker registration for async notification when this slot completes
    /// or becomes the active exclusive slot.
    waker: WakerRegistration,

    /// Completion status flags from the STATUS register, set by
    /// [`AesDriver::wake`]. Zero means not yet completed.
    status: u8,

    /// True for [`AesDriver::with_exclusive`] slots — prevents
    /// [`AesDriver::wake`] from submitting a command for this slot.
    exclusive: bool,
}

struct AesState<const DEPTH: usize> {
    slots: [WaiterSlot; DEPTH],
    /// Index of the oldest unconsumed slot (callers advance on consume).
    head: u8,
    /// Index of the slot currently in hardware / next to submit.
    active: u8,
    /// Index of the next slot to allocate.
    tail: u8,
}

/// Async AES driver.
///
/// Serializes concurrent callers — only one AES command is in flight
/// at a time. Additional callers are queued and served in FIFO order.
///
/// # Type Parameters
///
/// - `DEPTH`: Maximum number of concurrent waiters. Must be a power of 2,
///   at most 128.
pub struct AesDriver<const DEPTH: usize> {
    #[allow(dead_code)] // reserved for future interrupt-driven mode
    interrupt: bool,
    state: SingleCell<AesState<DEPTH>>,
}

impl<const DEPTH: usize> core::fmt::Debug for AesDriver<DEPTH> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AesDriver").field("DEPTH", &DEPTH).finish()
    }
}

impl<const DEPTH: usize> AesDriver<DEPTH> {
    const MASK: u8 = (DEPTH - 1) as u8;

    const _ASSERT_DEPTH_NONZERO: () = assert!(DEPTH > 0, "DEPTH must be > 0");
    const _ASSERT_DEPTH_POW2: () = assert!(DEPTH.is_power_of_two(), "DEPTH must be power of 2");
    const _ASSERT_DEPTH_MAX: () = assert!(DEPTH <= 128, "DEPTH must be <= 128 (u8 indices)");
    const _ASSERT_DEPTH_FIT: () = assert!(
        DEPTH <= AES_CMD_COUNT as usize,
        "DEPTH exceeds AES_CMD capacity"
    );

    /// Initialize the AES peripheral and return a driver instance.
    ///
    /// # Parameters
    ///
    /// - `interrupt`: If true, enables interrupt-driven mode (IRQ5).
    ///   If false, use polling via [`wake`](Self::wake).
    ///
    /// # Panics
    ///
    /// Compile-time assertion if `DEPTH` is 0, not a power of 2, or exceeds 128.
    pub fn new(interrupt: bool) -> Self {
        #[allow(clippy::let_unit_value)]
        let _ = (
            Self::_ASSERT_DEPTH_NONZERO,
            Self::_ASSERT_DEPTH_POW2,
            Self::_ASSERT_DEPTH_MAX,
            Self::_ASSERT_DEPTH_FIT,
        );
        let _ = interrupt; // reserved for future interrupt-driven mode

        Self {
            interrupt,
            state: SingleCell::new(AesState {
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

    /// Submit an AES operation and await completion.
    ///
    /// Concurrent callers are queued (up to `DEPTH`) and served in FIFO
    /// order. Returns [`AesError::QUEUE_FULL`] if all slots are occupied.
    pub fn encrypt_decrypt<'a>(
        &'a self,
        req: AesRequest<'a>,
    ) -> impl core::future::Future<Output = HsmResult<()>> + 'a {
        let mut slot_idx: Option<u8> = None;

        poll_fn(move |cx| {
            self.state.with(|s| {
                // First poll: validate, claim a slot, build descriptor, enqueue.
                if slot_idx.is_none() {
                    if let Err(e) = validate(&req) {
                        return Poll::Ready(Err(e));
                    }
                    let Ok(key_len) = key_len_field(req.key.len()) else {
                        return Poll::Ready(Err(AesError::INVALID_KEY_LEN));
                    };
                    if s.tail.wrapping_sub(s.head) as usize >= DEPTH {
                        return Poll::Ready(Err(AesError::QUEUE_FULL));
                    }

                    let idx = (s.tail & Self::MASK) as usize;
                    let was_empty = s.active == s.tail;
                    slot_idx = Some(s.tail);
                    s.tail = s.tail.wrapping_add(1);

                    // Write the command descriptor into DTCM.
                    let cmd_code = AesCmdCode::new()
                        .with_tag(0x2)
                        .with_mode(req.mode as u8)
                        .with_encrypt(req.op == AesOp::Encrypt)
                        .with_update_iv(req.update_iv)
                        .with_key_len(key_len);
                    let iv_addr = match req.iv.as_deref() {
                        Some(iv) => iv.as_ptr() as u32,
                        None => 0,
                    };
                    let entry = &AES_Q.aes_cmd[idx];
                    entry.cmd_code.set(cmd_code.into());
                    entry.result.set(req.result.as_ptr() as u32);
                    entry.byte_count.set(req.message.len() as u32);
                    entry.message.set(req.message.as_ptr() as u32);
                    entry.key.set(req.key.as_ptr() as u32);
                    entry.iv.set(iv_addr);

                    // If we're the only entry, submit to hardware immediately.
                    if was_empty {
                        submit_cmd(idx);
                    }
                }

                let idx = (slot_idx.unwrap() & Self::MASK) as usize;
                let slot = &mut s.slots[idx];

                // Check if our command completed.
                if slot.status != 0 {
                    let status = slot.status;
                    slot.status = 0;

                    // Advance head past consecutive consumed slots.
                    while s.head != s.active && s.slots[(s.head & Self::MASK) as usize].status == 0
                    {
                        s.head = s.head.wrapping_add(1);
                    }

                    return Poll::Ready(map_status(status));
                }

                // Register waker for completion notification.
                slot.waker.register(cx.waker());
                Poll::Pending
            })
        })
    }

    /// Wake the driver on AES completion.
    ///
    /// Call from the `AES_DONE` IRQ handler (interrupt mode) or the
    /// main poll loop (polling mode).
    pub fn wake(&self) {
        let status = AES.status.get();
        let flags = status & STATUS_FLAGS_MASK;
        if flags == 0 {
            // No flag set — spurious wake.
            return;
        }

        // STATUS (AES_BASE + 0x4) is read-only (RO32): the flag bits auto-clear
        // when the next command doorbell sets BUSY. Writing it bus-faults the
        // engine and hard-faults the CPU, so only clear the NVIC pending bit.
        Nvic::unpend(Interrupt::AES_DONE);

        self.state.with(|s| {
            // The active slot is at `active`.
            if s.active != s.tail {
                let idx = (s.active & Self::MASK) as usize;
                let slot = &mut s.slots[idx];
                slot.status = flags as u8;
                slot.waker.wake();

                // Advance past the completed slot and submit the next
                // command immediately so there is no idle gap.
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
    /// Acquire exclusive synchronous access to the AES engine.
    ///
    /// Allocates a waiter slot and waits (async) for it to become the active
    /// slot — meaning all prior callers have completed and the hardware is
    /// available. Then runs `f` synchronously with an [`AesExclusive`] handle
    /// that exposes a busy-polled [`encrypt_decrypt`](AesExclusive::encrypt_decrypt)
    /// method. The slot is released when the closure returns, waking the next
    /// queued caller.
    ///
    /// Multiple tasks may call `with_exclusive` concurrently — they queue
    /// behind each other and behind regular [`encrypt_decrypt`](Self::encrypt_decrypt)
    /// calls through the same FIFO slot queue.
    ///
    /// This is designed for multi-invocation patterns (AES-KW, AES-KWP)
    /// where the overhead of poll/wake per AES-ECB call is undesirable. One
    /// async boundary to acquire hardware, N synchronous encryptions, one wake
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
        F: FnOnce(&AesExclusive<'_, DEPTH>) -> HsmResult<R>,
    {
        let mut slot_idx: Option<u8> = None;

        // Wait for our slot to become the active one.
        poll_fn(|cx| {
            self.state.with(|s| {
                if slot_idx.is_none() {
                    if s.tail.wrapping_sub(s.head) as usize >= DEPTH {
                        return Poll::Ready(Err(AesError::QUEUE_FULL));
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

        let result = f(&AesExclusive {
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

/// Exclusive synchronous handle to the AES engine.
///
/// Provides a busy-polled [`encrypt_decrypt`](Self::encrypt_decrypt) method
/// that submits a command and spins on the hardware status register instead
/// of yielding to the async executor.
///
/// Cannot be constructed directly — only obtained through
/// [`AesDriver::with_exclusive`].
#[derive(Debug)]
pub struct AesExclusive<'a, const DEPTH: usize> {
    /// Ties the lifetime to the owning [`AesDriver`]. Not read at runtime —
    /// hardware access goes through module-level statics.
    #[allow(dead_code)]
    driver: &'a AesDriver<DEPTH>,

    /// The ring-buffer slot index (`raw_tail & MASK`) reserved for this
    /// exclusive session. Passed to `submit_and_spin` so it writes the
    /// command descriptor into the correct slot.
    slot_idx: usize,
}

impl<const DEPTH: usize> AesExclusive<'_, DEPTH> {
    /// Submit an AES request and busy-poll until completion.
    ///
    /// Identical to [`AesDriver::encrypt_decrypt`] but runs synchronously,
    /// spinning on the hardware status register instead of yielding to
    /// the executor.
    pub fn encrypt_decrypt(&self, req: &AesRequest<'_>) -> HsmResult<()> {
        let status = self.submit_and_spin(req)?;
        map_status(status)
    }

    /// Write the command descriptor, submit to hardware, and spin until the
    /// status register indicates completion. Clears NVIC pending after
    /// consuming the status to prevent stale pending bits from triggering
    /// a spurious [`AesDriver::wake`] call when normal polling resumes.
    fn submit_and_spin(&self, req: &AesRequest<'_>) -> HsmResult<u8> {
        validate(req)?;
        let key_len = key_len_field(req.key.len())?;
        let idx = self.slot_idx & (DEPTH - 1);

        let cmd_code = AesCmdCode::new()
            .with_tag(0x2)
            .with_mode(req.mode as u8)
            .with_encrypt(req.op == AesOp::Encrypt)
            .with_update_iv(req.update_iv)
            .with_key_len(key_len);
        let iv_addr = match req.iv.as_deref() {
            Some(iv) => iv.as_ptr() as u32,
            None => 0,
        };
        let entry = &AES_Q.aes_cmd[idx];
        entry.cmd_code.set(cmd_code.into());
        entry.result.set(req.result.as_ptr() as u32);
        entry.byte_count.set(req.message.len() as u32);
        entry.message.set(req.message.as_ptr() as u32);
        entry.key.set(req.key.as_ptr() as u32);
        entry.iv.set(iv_addr);

        submit_cmd(idx);

        loop {
            let status = AES.status.get();
            let flags = status & STATUS_FLAGS_MASK;
            if flags != 0 {
                // STATUS is read-only; do not write it (bus-faults). It
                // auto-clears on the next command doorbell.
                Nvic::unpend(Interrupt::AES_DONE);
                return Ok(flags as u8);
            }
        }
    }
}

fn submit_cmd(slot: usize) {
    let desc_addr = IO_GSRAM_BASE + AES_CMD_OFFSET + (slot as u32) * AES_CMD_STRIDE;
    AES.command.set(desc_addr);
}

fn validate(req: &AesRequest<'_>) -> HsmResult<()> {
    match req.key.len() {
        16 | 24 | 32 => {}
        _ => return Err(AesError::INVALID_KEY_LEN),
    }
    if req.message.is_empty() {
        return Err(AesError::INVALID_MSG_LEN);
    }
    if req.mode != AesMode::Ctr && !req.message.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(AesError::INVALID_MSG_LEN);
    }
    if req.result.len() < req.message.len() {
        return Err(AesError::RESULT_BUF_TOO_SMALL);
    }
    if matches!(req.mode, AesMode::Cbc | AesMode::Ctr) {
        match req.iv.as_deref() {
            Some(iv) if iv.len() == AES_IV_SIZE => {}
            _ => return Err(AesError::INVALID_IV),
        }
    }
    Ok(())
}

fn map_status(status: u8) -> HsmResult<()> {
    // Bit positions must match the RDL: COMPLETE=1, ERROR_CMD=2,
    // ERROR_BUS=3, ERROR_FAULT=4.
    if status & (1 << 1) != 0 {
        return Ok(());
    }
    if status & (1 << 2) != 0 {
        return Err(AesError::CMD_ERROR);
    }
    if status & (1 << 3) != 0 {
        return Err(AesError::BUS_ERROR);
    }
    if status & (1 << 4) != 0 {
        return Err(AesError::FAULT_ERROR);
    }
    Err(AesError::FAULT_ERROR)
}
