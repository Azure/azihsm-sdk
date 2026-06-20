// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IPC driver implementation.
//!
#![allow(unsafe_code)]

use core::future::poll_fn;
use core::task::Poll;

use azihsm_fw_single_cell::SingleCell;
use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_reg_soc::intc::regs::IntcRegs;
use azihsm_fw_uno_reg_soc::intc::INTC_BASE;
use embassy_sync::waitqueue::WakerRegistration;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;

/// IPC message length in DWORDs (16 × 4 = 64 bytes).
pub const IPC_MSG_DWORDS: usize = 16;

/// Maximum number of concurrent send slots across all send pairs.
const MAX_SEND_SLOTS: usize = 8;

/// Pair direction and type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcPairKind {
    /// We receive requests, single waiter.
    RecvMessage,

    /// We send requests, multiple senders serialized.
    SendMessage,

    /// We receive events, single waiter.
    RecvEvent,

    /// We send events, sync fire-and-forget.
    SendEvent,
}

/// Configuration for one IPC descriptor pair.
#[derive(Debug, Clone, Copy)]
pub struct IpcPairConfig {
    /// Pair direction and type.
    pub kind: IpcPairKind,

    /// Descriptor ID for inbound (we get interrupted when remote writes here).
    pub inbound_desc: u8,

    /// Descriptor ID for outbound (we write here to ring the remote).
    pub outbound_desc: u8,

    /// TX ring base address in shared memory (message pairs only).
    pub tx_ring_base: u32,

    /// TX producer index address in shared memory (message pairs only).
    pub tx_pi: u32,

    /// TX consumer index address in shared memory (message pairs only).
    pub tx_ci: u32,

    /// RX ring base address in shared memory (message pairs only).
    pub rx_ring_base: u32,

    /// RX producer index address in shared memory (message pairs only).
    pub rx_pi: u32,

    /// RX consumer index address in shared memory (message pairs only).
    pub rx_ci: u32,

    /// Ring depth in entries (message pairs only, must be > 1).
    pub depth: u16,

    /// Entry size in DWORDs (message pairs only).
    pub msg_len: u16,
}

/// Configuration for the IPC driver.
#[derive(Debug)]
pub struct IpcConfig<'a> {
    /// Block index for this CPU .
    pub int_block: u8,

    /// Pair configurations, indexed by pair ID.
    pub pairs: &'a [IpcPairConfig],
}

/// Internal state for one pair.
struct PairState {
    /// Pair kind.
    kind: IpcPairKind,

    /// Inbound descriptor ID.
    inbound_desc: u8,

    /// Outbound descriptor ID.
    outbound_desc: u8,

    /// Waker for recv or in-flight send response.
    waker: WakerRegistration,

    /// TX ring pointer (message pairs only).
    tx_ring: *mut u32,

    /// RX ring pointer (message pairs only).
    rx_ring: *const u32,

    /// TX producer index pointer in shared memory (message pairs only).
    tx_pi: *mut u32,

    /// TX consumer index pointer in shared memory (message pairs only).
    /// Read by the remote side; unused by the local driver.
    #[allow(dead_code)]
    tx_ci: *const u32,

    /// RX producer index pointer in shared memory (message pairs only).
    rx_pi: *const u32,

    /// RX consumer index pointer in shared memory (message pairs only).
    rx_ci: *mut u32,

    /// Ring depth (message pairs only).
    depth: u16,

    /// Entry size in DWORDs (message pairs only).
    msg_len: u16,

    /// Currently in-flight send slot (send pairs only).
    in_flight: Option<u8>,

    /// Software flag set by wake() when a descriptor fires.
    /// For RecvEvent: holds the descriptor value read by wake().
    /// Consumed by recv_event().
    event_pending: Option<u32>,
}

/// Send slot for serializing multiple senders on a send pair.
struct SendSlot {
    /// Waker for this sender.
    waker: WakerRegistration,

    /// True when the response has arrived for this slot.
    completed: bool,

    /// Which send pair this slot belongs to.
    pair_index: u8,
}

/// Mutable driver state protected by [`SingleCell`].
struct DriverState<const MAX_PAIRS: usize> {
    /// Per-pair state.
    pairs: [PairState; MAX_PAIRS],

    /// Send slot pool shared across all send pairs.
    send_slots: [SendSlot; MAX_SEND_SLOTS],

    /// Free slot bitmask (bit N = slot N is free).
    slot_free: u32,
}

/// IPC driver managing all descriptor pairs on one block.
///
/// `MAX_PAIRS` is the number of configured pairs (const generic).
pub struct IpcDriver<const MAX_PAIRS: usize> {
    /// Block index.
    int_block: u8,

    /// Number of configured pairs (may be < MAX_PAIRS).
    num_pairs: u8,

    /// INTC register access.
    regs: StaticRef<IntcRegs>,

    /// Descriptor-to-pair lookup (descriptor ID → pair index, 0xFF = unmapped).
    desc_to_pair: [u8; 32],

    /// Mutable state.
    state: SingleCell<DriverState<MAX_PAIRS>>,
}

impl<const MAX_PAIRS: usize> core::fmt::Debug for IpcDriver<MAX_PAIRS> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IpcDriver")
            .field("int_block", &self.int_block)
            .field("num_pairs", &self.num_pairs)
            .finish_non_exhaustive()
    }
}

// SAFETY: IpcDriver is only used from a single-core cooperative executor.
// Raw pointers in PairState point to stable shared memory (SRAM/DTCM).
unsafe impl<const MAX_PAIRS: usize> Sync for IpcDriver<MAX_PAIRS> {}

impl PairState {
    /// # Safety
    ///
    /// Caller must ensure `tx_ring` is valid and `pi` is within ring bounds.
    unsafe fn copy_to_tx(&self, pi: u16, src: &[u32]) {
        let entry_offset = pi as usize * self.msg_len as usize;
        let words = src.len().min(self.msg_len as usize);
        for (i, item) in src.iter().enumerate().take(words) {
            unsafe { self.tx_ring.add(entry_offset + i).write_volatile(*item) };
        }
    }

    /// # Safety
    ///
    /// Caller must ensure `rx_ring` is valid and `ci` is within ring bounds.
    unsafe fn copy_from_rx(&self, ci: u16, dst: &mut [u32]) {
        let entry_offset = ci as usize * self.msg_len as usize;
        let words = dst.len().min(self.msg_len as usize);
        for (i, item) in dst.iter_mut().enumerate().take(words) {
            *item = unsafe { self.rx_ring.add(entry_offset + i).read_volatile() };
        }
    }

    const EMPTY: Self = Self {
        kind: IpcPairKind::RecvEvent,
        inbound_desc: 0,
        outbound_desc: 0,
        waker: WakerRegistration::new(),
        tx_ring: core::ptr::null_mut(),
        rx_ring: core::ptr::null(),
        tx_pi: core::ptr::null_mut(),
        tx_ci: core::ptr::null(),
        rx_pi: core::ptr::null(),
        rx_ci: core::ptr::null_mut(),
        depth: 0,
        msg_len: 0,
        in_flight: None,
        event_pending: None,
    };
}

impl SendSlot {
    const EMPTY: Self = Self {
        waker: WakerRegistration::new(),
        completed: false,
        pair_index: 0xFF,
    };
}

impl<const MAX_PAIRS: usize> IpcDriver<MAX_PAIRS> {
    /// Initialize the IPC driver.
    ///
    /// Clears all pending bits on this block, builds the
    /// descriptor-to-pair lookup table, and copies pair configs
    /// into internal state.
    pub fn new(config: IpcConfig<'_>) -> Self {
        assert!(config.pairs.len() <= MAX_PAIRS);

        let regs = unsafe { StaticRef::new(INTC_BASE as *const IntcRegs) };

        let mut desc_to_pair = [0xFFu8; 32];
        let mut pairs = [PairState::EMPTY; MAX_PAIRS];

        for (i, pc) in config.pairs.iter().enumerate() {
            desc_to_pair[pc.inbound_desc as usize] = i as u8;

            pairs[i] = PairState {
                kind: pc.kind,
                inbound_desc: pc.inbound_desc,
                outbound_desc: pc.outbound_desc,
                waker: WakerRegistration::new(),
                tx_ring: pc.tx_ring_base as *mut u32,
                rx_ring: pc.rx_ring_base as *const u32,
                tx_pi: pc.tx_pi as *mut u32,
                tx_ci: pc.tx_ci as *const u32,
                rx_pi: pc.rx_pi as *const u32,
                rx_ci: pc.rx_ci as *mut u32,
                depth: pc.depth,
                msg_len: pc.msg_len,
                in_flight: None,
                event_pending: None,
            };
        }

        Self {
            int_block: config.int_block,
            num_pairs: config.pairs.len() as u8,
            regs,
            desc_to_pair,
            state: SingleCell::new(DriverState {
                pairs,
                send_slots: [SendSlot::EMPTY; MAX_SEND_SLOTS],
                slot_free: (1u32 << MAX_SEND_SLOTS) - 1,
            }),
        }
    }

    /// Clear pending interrupts. Must be called after clocks are available.
    pub fn init(&self) {
        let pend_clr = &self.regs.pend_clr[self.int_block as usize];
        pend_clr.set(0xFFFF_FFFF);
    }

    /// Enable interrupts for a pair's inbound descriptor.
    pub fn enable(&self, pair: u8) {
        self.state.with(|s| {
            let p = &s.pairs[pair as usize];
            let enable_set = &self.regs.enable_set[self.int_block as usize];
            enable_set.set(1u32 << p.inbound_desc);
        });
    }

    /// Disable interrupts for a pair's inbound descriptor.
    pub fn disable(&self, pair: u8) {
        self.state.with(|s| {
            let p = &s.pairs[pair as usize];
            let enable_clr = &self.regs.enable_clr[self.int_block as usize];
            enable_clr.set(1u32 << p.inbound_desc);
        });
    }

    /// Wake all pairs with pending descriptors.
    ///
    /// Reads PEND_SET, iterates set bits, and wakes the appropriate
    /// pair's waker. For send pairs, wakes the in-flight slot's waker.
    /// Clears processed pending bits.
    pub fn wake(&self, irq: u16) {
        self.state.with(|s| {
            let pend_set = &self.regs.pend_set[self.int_block as usize];
            let pend = pend_set.get();
            if pend == 0 {
                azihsm_fw_uno_drivers_nvic::Nvic::unpend_raw(irq);
                return;
            }

            let mut bits = pend;
            while bits != 0 {
                let n = bits.trailing_zeros() as u8;
                bits &= !(1u32 << n);

                let pair_idx = self.desc_to_pair[n as usize];
                if pair_idx == 0xFF || pair_idx >= self.num_pairs {
                    continue;
                }

                let pair = &mut s.pairs[pair_idx as usize];
                match pair.kind {
                    IpcPairKind::RecvMessage => {
                        pair.waker.wake();
                    }
                    IpcPairKind::RecvEvent => {
                        pair.event_pending = Some(self.regs.desc[n as usize].get());
                        pair.waker.wake();
                    }
                    IpcPairKind::SendMessage => {
                        if let Some(slot_idx) = pair.in_flight {
                            s.send_slots[slot_idx as usize].completed = true;
                            s.send_slots[slot_idx as usize].waker.wake();
                        }
                    }
                    IpcPairKind::SendEvent => {}
                }
            }

            let pend_clr = &self.regs.pend_clr[self.int_block as usize];
            pend_clr.set(pend);
            azihsm_fw_uno_drivers_nvic::Nvic::unpend_raw(irq);
        });
    }

    // ── Message recv pair ───────────────────────────────────────

    /// Receive a message from a recv pair (async, single waiter).
    ///
    /// Awaits the inbound descriptor's pending bit, then copies the
    /// message from the RX ring into `buf` and advances CI.
    pub fn recv<'a>(
        &'a self,
        pair: u8,
        buf: &'a mut [u32],
    ) -> impl core::future::Future<Output = u32> + 'a {
        poll_fn(move |cx| {
            self.state.with(|s| {
                let p = &mut s.pairs[pair as usize];

                let pi = unsafe { p.rx_pi.read_volatile() } as u16;
                let ci = unsafe { p.rx_ci.read_volatile() } as u16;

                if pi == ci {
                    p.waker.register(cx.waker());
                    return Poll::Pending;
                }

                // Copy message from RX ring and advance CI
                unsafe { p.copy_from_rx(ci, buf) };
                let new_ci = (ci + 1) % p.depth;
                unsafe { p.rx_ci.write_volatile(new_ci as u32) };

                Poll::Ready(0)
            })
        })
    }

    /// Send a response on a recv pair (sync, never blocks).
    ///
    /// Copies `msg` into the TX ring, advances PI, and rings the
    /// outbound descriptor.
    pub fn reply(&self, pair: u8, msg: &[u32]) {
        self.state.with(|s| {
            let p = &mut s.pairs[pair as usize];

            let pi = unsafe { p.tx_pi.read_volatile() } as u16;

            // Copy message into TX ring and advance PI
            unsafe { p.copy_to_tx(pi, msg) };
            let new_pi = (pi + 1) % p.depth;
            unsafe { p.tx_pi.write_volatile(new_pi as u32) };

            // Ring outbound descriptor
            cortex_m::asm::dmb();
            self.regs.desc[p.outbound_desc as usize].set(new_pi as u32);
        });
    }

    // ── Message send pair ───────────────────────────────────────

    /// Send a request on a send pair and await the response (async).
    ///
    /// Multiple callers are serialized via the slot pool. Only the
    /// in-flight sender holds a slot — queued senders wait on the
    /// pair waker without consuming a slot. This ensures no slot is
    /// leaked if a future is dropped while waiting in the queue.
    pub fn send<'a>(
        &'a self,
        pair: u8,
        msg: &'a [u32],
        resp: &'a mut [u32],
    ) -> impl core::future::Future<Output = ()> + 'a {
        let mut slot_id: Option<u8> = None;
        let mut sent = false;

        poll_fn(move |cx| {
            self.state.with(|s| {
                let p = &mut s.pairs[pair as usize];

                // Phase 1: wait for our turn (no slot allocated yet)
                if !sent {
                    if p.in_flight.is_some() {
                        p.waker.register(cx.waker());
                        return Poll::Pending;
                    }

                    // Allocate a slot now that we're in-flight
                    if slot_id.is_none() {
                        if s.slot_free == 0 {
                            p.waker.register(cx.waker());
                            return Poll::Pending;
                        }
                        let sid = s.slot_free.trailing_zeros() as u8;
                        s.slot_free &= !(1u32 << sid);
                        s.send_slots[sid as usize].pair_index = pair;
                        s.send_slots[sid as usize].completed = false;
                        slot_id = Some(sid);
                    }

                    let sid = slot_id.unwrap();
                    p.in_flight = Some(sid);

                    // Send the message
                    let pi = unsafe { p.tx_pi.read_volatile() } as u16;
                    unsafe { p.copy_to_tx(pi, msg) };
                    let new_pi = (pi + 1) % p.depth;
                    unsafe { p.tx_pi.write_volatile(new_pi as u32) };

                    cortex_m::asm::dmb();
                    self.regs.desc[p.outbound_desc as usize].set(new_pi as u32);

                    sent = true;
                }

                // Phase 2: wait for response
                let sid = slot_id.unwrap();
                let slot = &mut s.send_slots[sid as usize];
                if !slot.completed {
                    slot.waker.register(cx.waker());
                    return Poll::Pending;
                }

                // Response arrived — read from RX ring
                let pi = unsafe { p.rx_pi.read_volatile() } as u16;
                let ci = unsafe { p.rx_ci.read_volatile() } as u16;

                if pi != ci {
                    unsafe { p.copy_from_rx(ci, resp) };
                    let new_ci = (ci + 1) % p.depth;
                    unsafe { p.rx_ci.write_volatile(new_ci as u32) };
                }

                // Clear pending
                let pend_clr = &self.regs.pend_clr[self.int_block as usize];
                pend_clr.set(1u32 << p.inbound_desc);

                // Release slot
                slot.completed = false;
                slot.pair_index = 0xFF;
                s.slot_free |= 1u32 << sid;
                p.in_flight = None;

                // Wake next queued sender for this pair
                p.waker.wake();

                Poll::Ready(())
            })
        })
    }

    // ── Event recv pair ─────────────────────────────────────────

    /// Receive an event value (async, single waiter).
    ///
    /// Awaits the `event_pending` value set by `wake()`. The HW
    /// pending bit and descriptor value were already read and cleared
    /// in `wake()`, so this never touches HW registers.
    pub fn recv_event<'a>(&'a self, pair: u8) -> impl core::future::Future<Output = u32> + 'a {
        poll_fn(move |cx| {
            self.state.with(|s| {
                let p = &mut s.pairs[pair as usize];
                match p.event_pending.take() {
                    Some(value) => Poll::Ready(value),
                    None => {
                        p.waker.register(cx.waker());
                        Poll::Pending
                    }
                }
            })
        })
    }

    /// Acknowledge an event on a recv event pair (sync).
    ///
    /// Writes `value` to the outbound descriptor, signaling the
    /// remote CPU that we handled the event.
    pub fn ack_event(&self, pair: u8, value: u32) {
        self.send_event(pair, value);
    }

    // ── Event send pair ─────────────────────────────────────────

    /// Send an event value (sync, fire-and-forget).
    ///
    /// Writes `value` to the outbound descriptor register, triggering
    /// a pending interrupt on all blocks that have it enabled.
    pub fn send_event(&self, pair: u8, value: u32) {
        self.state.with(|s| {
            let p = &s.pairs[pair as usize];
            self.regs.desc[p.outbound_desc as usize].set(value);
        });
    }
}
