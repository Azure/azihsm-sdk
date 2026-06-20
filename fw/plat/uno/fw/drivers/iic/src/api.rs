// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::future::poll_fn;
use core::task::Poll;

use azihsm_fw_single_cell::SingleCell;
use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_reg_soc::iic::regs::IicRegs;
use azihsm_fw_uno_reg_soc::iic::IIC_BASE;
use azihsm_fw_uno_reg_soc::iic::*;
use azihsm_fw_uno_trace::tracing::*;
use embassy_sync::waitqueue::WakerRegistration;
use tock_registers::interfaces::ReadWriteable;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;

use crate::ChannelConfig;
use crate::IcqEntry;
use crate::IoMetaEntry;
use crate::IoMetaQueue;
use crate::IsqEntry;

/// Mutable driver state — ring indices and async waker.
struct ChannelState {
    /// ICQ consumer index — FW advances after reading completions.
    icq_head: u16,

    /// Waker for async recv — woken by IRQ or polling.
    waker: WakerRegistration,
}

/// Async IIC (Inbound IO Controller) driver.
///
/// One instance per (controller, channel) pair. The controller is
/// resolved to an MMIO base address at init. The channel index selects
/// the ISQ and ICQ register arrays.
///
/// # Type Parameters
///
/// - `DEPTH`: Queue depth (number of entries). Must be power of 2.
pub struct IicDriver<const DEPTH: usize> {
    /// Physical channel index within the controller.
    channel: u8,

    /// IO_SQ buffer pool base address.
    buf_pool_base: u32,

    /// Size of each receive buffer in bytes.
    buf_size: u32,

    /// ISQ ring memory (typed overlay at config.isq_base).
    isq_ring: *mut IsqEntry,

    /// ICQ ring memory (typed overlay at config.icq_base).
    icq_ring: *const IcqEntry,

    /// ICQ tail shadow address (FW reads this instead of MMIO register).
    icq_tail_shadow: *const u32,

    /// IO_META sidecar array — recv() writes metadata here.
    io_meta: *mut IoMetaEntry,

    /// Driver state protected by single-threaded access.
    state: SingleCell<ChannelState>,

    /// Controller MMIO registers.
    regs: StaticRef<IicRegs>,

    /// Saved channel configuration, consumed by [`init`](Self::init).
    config: ChannelConfig,
}

// SAFETY: Single-core Cortex-M with cooperative scheduling.
unsafe impl<const DEPTH: usize> Send for IicDriver<DEPTH> {}
unsafe impl<const DEPTH: usize> Sync for IicDriver<DEPTH> {}

impl<const DEPTH: usize> core::fmt::Debug for IicDriver<DEPTH> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IicDriver")
            .field("DEPTH", &DEPTH)
            .field("channel", &self.channel)
            .finish()
    }
}

impl<const DEPTH: usize> IicDriver<DEPTH> {
    const MASK: u16 = (DEPTH - 1) as u16;

    const _ASSERT_POW2: () = assert!(DEPTH.is_power_of_two(), "DEPTH must be power of 2");
    const _ASSERT_MAX: () = assert!(DEPTH <= 0x8000, "DEPTH exceeds 16-bit index range");
    const _ASSERT_MIN: () = assert!(DEPTH >= 32, "DEPTH must be at least 32");

    /// Encoded depth for hardware registers: 0h=32, 1h=64, ..., Bh=65536.
    const ENCODED_DEPTH: u32 = DEPTH.trailing_zeros() - 5;

    /// Construct the driver for a specific controller and channel without touching MMIO.
    ///
    /// Only stores configuration and initializes software state. Hardware
    /// registers and DTCM shadow words are programmed by [`init`](Self::init);
    /// the channel is then activated by [`enable`](Self::enable).
    ///
    /// Splitting construction from MMIO programming lets firmware build the
    /// driver instance early while deferring shared-register writes until after
    /// the boot handshake has completed.
    ///
    /// # Panics
    ///
    /// Compile-time panic if `DEPTH` is not a power of 2 or exceeds 32768.
    pub fn new(config: ChannelConfig) -> Self {
        #[allow(clippy::let_unit_value)]
        {
            let _ = Self::_ASSERT_POW2;
            let _ = Self::_ASSERT_MAX;
            let _ = Self::_ASSERT_MIN;
        }

        let regs = unsafe { StaticRef::new(IIC_BASE as *const IicRegs) };
        let isq_ring = config.isq_base as *mut IsqEntry;

        Self {
            channel: config.channel,
            buf_pool_base: config.io_pool_base,
            buf_size: config.io_size,
            isq_ring,
            icq_ring: config.icq_base as *const IcqEntry,
            icq_tail_shadow: config.icq_tail_shadow as *const u32,
            io_meta: config.io_meta_base as *mut IoMetaEntry,
            state: SingleCell::new(ChannelState {
                icq_head: 0,
                waker: WakerRegistration::new(),
            }),
            regs,
            config,
        }
    }

    /// Program ICQ/ISQ channel registers, pre-fill the ISQ, and enable.
    ///
    /// Must only be called after any boot handshake completes. Calling this
    /// earlier can race the controller-side owner of shared common and IRQ
    /// registers.
    pub fn init(&self) {
        let config = self.config;
        let regs = self.regs;
        let ch = config.channel as usize;

        // Detect if channel was already programmed by another core
        let icq_ctrl = regs.icq_ch[ch].ctrl.get();
        let isq_ctrl = regs.isq_ch[ch].ctrl.get();
        if icq_ctrl & 0x1 != 0 || isq_ctrl & 0x1 != 0 {
            warn!(
                "iic",
                "ch={} ALREADY ENABLED before init! icq_ctrl={:#x} isq_ctrl={:#x}",
                config.channel,
                icq_ctrl,
                isq_ctrl
            );
        }

        // ── Step 1: Pre-fill ISQ with buffer addresses ──────────────
        for i in 0..DEPTH {
            let buf_addr = config.io_pool_base + (i as u32) * config.io_size;
            let entry = unsafe { &mut *self.isq_ring.add(i) };
            entry.addr_lo = buf_addr;
            entry.addr_hi = 0;
        }

        // ── Step 2: Reset RX queue shadow PI ───────────────────────
        unsafe { (config.icq_tail_shadow as *mut u32).write_volatile(0) };

        // ── Step 3: Program ICQ channel ────────────────────────────
        let icq = &regs.icq_ch[ch];
        icq.base_lo.set(config.icq_base);
        icq.base_hi.set(0);
        icq.tail_shadow_lo.set(config.icq_tail_shadow);
        icq.tail_shadow_hi.set(0);
        icq.tail.write(ICQ_CHANNEL_TAIL::TAIL.val(0));
        icq.head.write(ICQ_CHANNEL_HEAD::HEAD.val(0));
        // Step 3.7: Enable interrupt before configuration_control
        if config.interrupt {
            let val = regs.irq_enable.read(IRQ_ENABLE::IRQ_EN) | (1 << config.channel);
            regs.irq_enable.write(IRQ_ENABLE::IRQ_EN.val(val));
        }
        icq.ctrl.modify(
            ICQ_CHANNEL_CTRL::DEPTH.val(Self::ENCODED_DEPTH)
                + ICQ_CHANNEL_CTRL::IFC_SLCT.val(0)
                + ICQ_CHANNEL_CTRL::SHADOW_EN::SET,
        );

        // ── Step 4: Program ISQ (DFL) channel ──────────────────────
        let isq = &regs.isq_ch[ch];
        isq.ifc_slct.write(
            ISQ_CHANNEL_IFC_SLCT::BUF_IFC_SLCT.val(0) + ISQ_CHANNEL_IFC_SLCT::LIST_IFC_SLCT.val(0),
        );
        isq.base_lo.set(config.isq_base);
        isq.base_hi.set(0);
        isq.status.write(ISQ_CHANNEL_STATUS::EMPTY::SET);
        isq.tail
            .write(ISQ_CHANNEL_TAIL::TAIL.val((DEPTH as u32) - 1));
        isq.head.write(ISQ_CHANNEL_HEAD::HEAD.val(0));
        isq.ctrl.modify(
            ISQ_CHANNEL_CTRL::DEPTH.val(Self::ENCODED_DEPTH)
                + ISQ_CHANNEL_CTRL::BUF_LEN.val(config.io_size >> 4),
        );

        // ── Step 5: Enable ─────────────────────────────────────────
        regs.icq_ch[ch].ctrl.modify(ICQ_CHANNEL_CTRL::EN::SET);
        regs.isq_ch[ch].ctrl.modify(ISQ_CHANNEL_CTRL::EN::SET);
    }

    /// Disable the channel — deactivates ISQ and ICQ hardware.
    pub fn disable(&self) {
        let ch = self.channel as usize;
        self.regs.isq_ch[ch]
            .ctrl
            .modify(ISQ_CHANNEL_CTRL::EN::CLEAR);
        self.regs.icq_ch[ch]
            .ctrl
            .modify(ICQ_CHANNEL_CTRL::EN::CLEAR);

        let mask = !(1u32 << self.channel);
        let current = self.regs.irq_enable.read(IRQ_ENABLE::IRQ_EN);
        self.regs
            .irq_enable
            .write(IRQ_ENABLE::IRQ_EN.val(current & mask));
    }

    /// Free an IO slot: return the buffer to the ISQ for hardware reuse
    /// and grant a credit back to the source queue.
    ///
    /// Both DFL refill and IQ credit release happen together when an IO
    /// is fully processed.
    pub fn free_io(&self, index: u16, queue_id: u16) {
        // Return buffer to DFL (read PI from HW each time)
        let buf_addr = self.buf_addr(index);
        let pi = self.regs.isq_ch[self.channel as usize]
            .tail
            .read(ISQ_CHANNEL_TAIL::TAIL) as u16;
        let new_pi = (pi + 1) & Self::MASK;
        let entry = unsafe { &mut *self.isq_ring.add(new_pi as usize) };
        entry.addr_lo = buf_addr;
        entry.addr_hi = 0;

        // Ensure descriptor write is visible to HW before doorbell
        cortex_m::asm::dmb();

        self.regs.isq_ch[self.channel as usize]
            .tail
            .write(ISQ_CHANNEL_TAIL::TAIL.val(new_pi.into()));

        // Grant one credit back to the source queue
        let iq = &self.regs.iq[queue_id as usize];
        let current = iq.credit.read(IQ_QUEUE_CREDIT::CREDIT);
        iq.credit.write(IQ_QUEUE_CREDIT::CREDIT.val(current + 1));
    }

    /// Receive an inbound IO request asynchronously (zero-copy).
    ///
    /// Waits until an ICQ entry is available, copies metadata into the
    /// IO_META sidecar, and returns the IO_SQ slot index. Failed
    /// entries (status != 0) are silently recycled.
    ///
    /// When done, call [`free_io`](Self::free_io) to return the slot
    /// and grant credit back.
    pub fn recv(&self) -> impl core::future::Future<Output = u16> + '_ {
        poll_fn(move |cx| {
            self.state.with(|s| {
                // Read tail from shadow (DTCM)
                let tail = unsafe { self.icq_tail_shadow.read_volatile() } as u16;
                if s.icq_head == tail {
                    s.waker.register(cx.waker());
                    return Poll::Pending;
                }

                let icq_slot = (s.icq_head & Self::MASK) as usize;
                let entry = unsafe { &*self.icq_ring.add(icq_slot) };

                let success = entry.status.success();
                let index = self.buf_index(entry.buffer_addr());

                s.icq_head = (s.icq_head + 1) & Self::MASK;
                self.regs.icq_ch[self.channel as usize]
                    .head
                    .write(ICQ_CHANNEL_HEAD::HEAD.val(s.icq_head.into()));

                // Skip failed entries — recycle buffer, return credit, and keep polling
                if !success {
                    let _cause = self.regs.interrupt_cause.get();
                    let queue_id = entry.info.queue_id() as u16;
                    warn!(
                        "iic",
                        "recv FAILED ch={} slot={} addr={:#x} axi_id={} qid={} cause={:#010x}",
                        self.channel,
                        index,
                        entry.buffer_addr(),
                        entry.info.axi_id(),
                        queue_id,
                        _cause
                    );
                    self.free_io(index, queue_id);
                    s.waker.register(cx.waker());
                    return Poll::Pending;
                }

                // Persist metadata into IO_META sidecar
                let meta = unsafe { &mut *self.io_meta.add(index as usize) };
                meta.controller_id = entry.info.axi_id();
                meta.queue = IoMetaQueue::new()
                    .with_queue_id(entry.info.queue_id() as u16)
                    .with_queue_index(entry.info.queue_index());

                Poll::Ready(index)
            })
        })
    }

    /// Wake the driver if the ICQ has pending entries.
    pub fn wake(&self, irq: u16) {
        self.state.with(|s| {
            // Clear NVIC pending bit for this interrupt
            azihsm_fw_uno_drivers_nvic::Nvic::unpend_raw(irq);

            let tail = unsafe { self.icq_tail_shadow.read_volatile() } as u16;
            let _hw_tail = self.regs.icq_ch[self.channel as usize].tail.get() as u16;
            //             debug!(
            //                 "iic",
            //                 "wake ch={} head={} shadow_tail={} hw_tail={} shadow_ptr={:#x}",
            //                 self.channel,
            //                 s.icq_head,
            //                 tail,
            //                 hw_tail,
            //                 self.icq_tail_shadow as u32
            //             );
            if s.icq_head != tail {
                s.waker.wake();
            }
        });
    }

    #[inline]
    fn buf_addr(&self, index: u16) -> u32 {
        self.buf_pool_base + (index as u32) * self.buf_size
    }

    #[inline]
    fn buf_index(&self, addr: u32) -> u16 {
        ((addr - self.buf_pool_base) / self.buf_size) as u16
    }
}
