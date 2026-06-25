// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::future::poll_fn;
use core::task::Poll;

use azihsm_fw_single_cell::SingleCell;
use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_error::HsmResult;
use azihsm_fw_uno_reg_soc::gdma::regs::GdmaRegs;
use azihsm_fw_uno_reg_soc::gdma::CQ_CHANNEL_HEAD;
use azihsm_fw_uno_reg_soc::gdma::CQ_CTRL;
use azihsm_fw_uno_reg_soc::gdma::GDMA_BASE;
use azihsm_fw_uno_reg_soc::gdma::IRQ_ENABLE;
use azihsm_fw_uno_reg_soc::gdma::SQ_CHANNEL_HEAD;
use azihsm_fw_uno_reg_soc::gdma::SQ_CHANNEL_TAIL;
use azihsm_fw_uno_reg_soc::gdma::SQ_CTRL;
use azihsm_fw_uno_reg_soc::io_gsram::GdmaCqEntry;
use azihsm_fw_uno_reg_soc::io_gsram::GdmaSqEntry;
use azihsm_fw_uno_reg_soc::io_gsram::GDMA_CQ_COUNT;
use azihsm_fw_uno_reg_soc::io_gsram::GDMA_CQ_STATUS;
use azihsm_fw_uno_reg_soc::io_gsram::GDMA_SQ_COUNT;
use embassy_sync::waitqueue::WakerRegistration;
use tock_registers::interfaces::ReadWriteable;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;

use crate::ChannelConfig;
use crate::GdmaBuf;
use crate::GdmaError;
use crate::MemInterface;

struct TagSlot {
    waker: WakerRegistration,
    completed: bool,
    status: u8,
}

struct GdmaState<const DEPTH: usize> {
    cq_head: u16,
    sq_tail: u16,
    /// Cached SQ head index. Updated lazily when the queue looks full.
    sq_head_cached: u16,
    tag_free: u32,
    tags: [TagSlot; DEPTH],
}

/// Async GDMA (General DMA Controller) driver.
///
/// One instance manages a single hardware channel. Queue ring addresses and
/// shadow pointers are supplied by [`ChannelConfig`], while the MMIO base comes
/// from the generated [`GDMA_BASE`] constant.
///
/// # Type Parameters
///
/// - `DEPTH`: Queue depth and max concurrent tags. Must be a power of 2, at
///   most 32.
pub struct GdmaDriver<const DEPTH: usize> {
    /// Physical channel index.
    channel: u8,

    /// Cached channel configuration used by [`init`](Self::init).
    config: ChannelConfig,

    /// Controller MMIO registers.
    regs: StaticRef<GdmaRegs>,

    /// SQ ring in DTCM (typed overlay).
    sq_ring: *mut GdmaSqEntry,

    /// CQ ring in DTCM (typed overlay).
    cq_ring: *const GdmaCqEntry,

    /// CQ tail shadow address (firmware reads this instead of MMIO).
    cq_tail_shadow: *const u32,

    /// SQ head shadow address used for the lazy full-queue check.
    sq_head_shadow: *const u32,

    /// Mutable state protected by single-threaded access.
    state: SingleCell<GdmaState<DEPTH>>,
}

// SAFETY: GdmaDriver is only used on single-core Cortex-M firmware with
// cooperative scheduling. The raw pointers reference MMIO or DTCM memory with
// a single owner in practice; Send/Sync are needed for Embassy's static tasks.
unsafe impl<const DEPTH: usize> Send for GdmaDriver<DEPTH> {}
unsafe impl<const DEPTH: usize> Sync for GdmaDriver<DEPTH> {}

impl<const DEPTH: usize> core::fmt::Debug for GdmaDriver<DEPTH> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GdmaDriver")
            .field("DEPTH", &DEPTH)
            .field("channel", &self.channel)
            .finish()
    }
}

impl<const DEPTH: usize> GdmaDriver<DEPTH> {
    const MASK: u16 = (DEPTH - 1) as u16;

    const _ASSERT_DEPTH_POW2: () = assert!(DEPTH.is_power_of_two(), "DEPTH must be power of 2");
    const _ASSERT_DEPTH_MAX: () = assert!(DEPTH <= 32, "DEPTH must be <= 32 (u32 tag bitmap)");
    const _ASSERT_SQ_FIT: () =
        assert!(DEPTH <= GDMA_SQ_COUNT as usize, "DEPTH exceeds SQ capacity");
    const _ASSERT_CQ_FIT: () =
        assert!(DEPTH <= GDMA_CQ_COUNT as usize, "DEPTH exceeds CQ capacity");

    const _ASSERT_SQ_ENTRY_SIZE: () = assert!(
        core::mem::size_of::<GdmaSqEntry>() == 16 * 4,
        "GdmaSqEntry must be 64 bytes"
    );
    const _ASSERT_SQ_ENTRY_ALIGN: () = assert!(
        core::mem::align_of::<GdmaSqEntry>() == core::mem::align_of::<u32>(),
        "GdmaSqEntry must be u32-aligned"
    );

    /// Construct the driver for a specific channel without touching MMIO.
    ///
    /// Only stores configuration and initializes software state. Hardware
    /// registers and DTCM shadow words are programmed by [`init`](Self::init);
    /// the channel is then activated by [`enable`](Self::enable).
    ///
    /// Splitting construction from MMIO programming lets the firmware build
    /// the driver instance early while deferring any shared-register writes
    /// until after the boot handshake has completed.
    ///
    /// # Panics
    ///
    /// Compile-time panic if `DEPTH` is not a power of 2, exceeds 32, or is
    /// larger than the GDMA queue storage allocated in DTCM.
    pub fn new(config: ChannelConfig) -> Self {
        #[allow(clippy::let_unit_value)]
        {
            let _ = Self::_ASSERT_DEPTH_POW2;
            let _ = Self::_ASSERT_DEPTH_MAX;
            let _ = Self::_ASSERT_SQ_FIT;
            let _ = Self::_ASSERT_CQ_FIT;
            let _ = Self::_ASSERT_SQ_ENTRY_SIZE;
            let _ = Self::_ASSERT_SQ_ENTRY_ALIGN;
        }

        let regs = unsafe { StaticRef::new(GDMA_BASE as *const GdmaRegs) };

        let tags = core::array::from_fn(|_| TagSlot {
            waker: WakerRegistration::new(),
            completed: false,
            status: 0,
        });

        let tag_free = if DEPTH >= 32 {
            u32::MAX
        } else {
            (1u32 << DEPTH) - 1
        };

        Self {
            channel: config.channel,
            config,
            regs,
            sq_ring: config.sq_base as *mut GdmaSqEntry,
            cq_ring: config.cq_base as *const GdmaCqEntry,
            cq_tail_shadow: config.cq_tail_shadow as *const u32,
            sq_head_shadow: config.sq_head_shadow as *const u32,
            state: SingleCell::new(GdmaState {
                cq_head: 0,
                sq_tail: 0,
                sq_head_cached: 0,
                tag_free,
                tags,
            }),
        }
    }

    /// Program the channelized SQ and CQ registers, clear DTCM shadows,
    /// and enable.
    ///
    /// Must only be called after any boot handshake completes.
    pub fn init(&self) {
        let ch = self.config.channel as usize;

        let sq = &self.regs.sq[ch];
        sq.base_lo.set(self.config.sq_base);
        sq.base_hi.set(0);
        sq.head_shadow.set(self.config.sq_head_shadow);
        sq.tail.write(SQ_CHANNEL_TAIL::TAIL.val(0));
        self.regs.sq_ctrl[ch].write(SQ_CTRL::DEPTH.val(DEPTH as u32));

        let cq = &self.regs.cq[ch];
        cq.base_lo.set(self.config.cq_base);
        cq.base_hi.set(0);
        cq.tail_shadow.set(self.config.cq_tail_shadow);
        cq.head.write(CQ_CHANNEL_HEAD::HEAD.val(0));
        self.regs.cq_ctrl[ch].write(CQ_CTRL::DEPTH.val(DEPTH as u32));

        unsafe { (self.config.cq_tail_shadow as *mut u32).write_volatile(0) };
        unsafe { (self.config.sq_head_shadow as *mut u32).write_volatile(0) };

        // Enable
        self.regs.cq_ctrl[ch].modify(CQ_CTRL::EN::SET + CQ_CTRL::TAIL_SHADOW_EN::SET);
        self.regs.sq_ctrl[ch].modify(SQ_CTRL::EN::SET + SQ_CTRL::HEAD_SHADOW_EN::SET);

        if self.config.interrupt {
            let val = self.regs.irq_enable.read(IRQ_ENABLE::IRQ_EN) | (1u32 << self.config.channel);
            self.regs.irq_enable.write(IRQ_ENABLE::IRQ_EN.val(val));
        }
    }

    /// Allocate a tag, write an SQ entry, and ring the doorbell.
    fn submit(
        &self,
        src_addr: GdmaBuf,
        src_ifc: MemInterface,
        src_len: u32,
        dst_addr: GdmaBuf,
        dst_ifc: MemInterface,
        dst_len: u32,
    ) -> HsmResult<u16> {
        if src_len == 0 || dst_len == 0 {
            return Err(GdmaError::ZERO_LENGTH);
        }
        if src_ifc.is_invalid_host() || dst_ifc.is_invalid_host() {
            return Err(GdmaError::INVALID_HOST_IFC);
        }

        self.state.with(|s| {
            if s.tag_free == 0 {
                return Err(GdmaError::NO_FREE_TAGS);
            }
            let tag = s.tag_free.trailing_zeros() as u16;
            s.tag_free &= !(1u32 << tag);

            let next_tail = (s.sq_tail + 1) & Self::MASK;
            if next_tail == s.sq_head_cached {
                s.sq_head_cached = unsafe { self.sq_head_shadow.read_volatile() } as u16;
                if next_tail == s.sq_head_cached {
                    s.sq_head_cached = self.regs.sq[self.channel as usize]
                        .head
                        .read(SQ_CHANNEL_HEAD::HEAD) as u16;
                    if next_tail == s.sq_head_cached {
                        s.tag_free |= 1u32 << tag;
                        return Err(GdmaError::SQ_FULL);
                    }
                }
            }

            let slot = (s.sq_tail & Self::MASK) as usize;
            let sq = unsafe { &mut *self.sq_ring.add(slot) };

            // Build the 16-DW SQ entry locally, then bulk-copy to MMIO.
            // This replaces ~24 individual STR instructions with 4 STM
            // (LDM from stack + STM to MMIO).
            let (src_fst_lo, src_fst_hi, src_snd_lo, src_snd_hi) = src_addr.to_dwords();
            let (dst_fst_lo, dst_fst_hi, dst_snd_lo, dst_snd_hi) = dst_addr.to_dwords();

            let ctrl = (tag as u32) << 16 | (src_addr.fmt_bit() << 11) | (dst_addr.fmt_bit() << 12);
            let src_ifc_val = src_ifc.ifc_slct() as u32;
            let dst_ifc_val = dst_ifc.ifc_slct() as u32;
            let ifc = src_ifc_val | (dst_ifc_val << 8) | (src_ifc_val << 16) | (dst_ifc_val << 24);

            let entry: [u32; 16] = [
                ctrl,       // DW0: ctrl
                ifc,        // DW1: ifc
                0,          // DW2: rsvd
                0,          // DW3: rsvd
                src_len,    // DW4: src_len
                dst_len,    // DW5: dst_len
                0,          // DW6: rsvd
                0,          // DW7: rsvd
                src_fst_lo, // DW8
                src_fst_hi, // DW9
                src_snd_lo, // DW10
                src_snd_hi, // DW11
                dst_fst_lo, // DW12
                dst_fst_hi, // DW13
                dst_snd_lo, // DW14
                dst_snd_hi, // DW15
            ];

            let sq_ptr = sq as *mut GdmaSqEntry as *mut u32;
            let sq_words = unsafe { core::slice::from_raw_parts_mut(sq_ptr, entry.len()) };
            azihsm_fw_bulk_copy::copy_slice(sq_words, &entry);

            // Ensure SQ entry write is visible to HW before doorbell
            cortex_m::asm::dmb();

            s.sq_tail = next_tail;
            self.regs.sq[self.channel as usize]
                .tail
                .write(SQ_CHANNEL_TAIL::TAIL.val(s.sq_tail.into()));

            Ok(tag)
        })
    }

    /// Submit a DMA copy from `src` to `dst` and await completion.
    ///
    /// Submits on the first poll, then checks for completion on subsequent
    /// polls. This avoids constructing a separate submit + wait future.
    ///
    /// # Errors
    ///
    /// Returns immediately:
    /// - [`GdmaError::ZERO_LENGTH`] — `src_len` or `dst_len` is zero.
    /// - [`GdmaError::INVALID_HOST_IFC`] — `Host { ctrl_id: 0 }` used.
    /// - [`GdmaError::NO_FREE_TAGS`] — all tag slots are in use.
    /// - [`GdmaError::SQ_FULL`] — SQ ring buffer is full.
    ///
    /// Returns on await:
    /// - [`GdmaError::dma_error`] — hardware reported an error.
    pub fn copy_mem(
        &self,
        src_addr: GdmaBuf,
        src_ifc: MemInterface,
        src_len: u32,
        dst_addr: GdmaBuf,
        dst_ifc: MemInterface,
        dst_len: u32,
    ) -> HsmResult<impl core::future::Future<Output = HsmResult<()>> + '_> {
        let tag = self.submit(src_addr, src_ifc, src_len, dst_addr, dst_ifc, dst_len)?;
        Ok(poll_fn(move |cx| {
            self.state.with(|s| {
                let slot = &mut s.tags[tag as usize];
                if slot.completed {
                    let status = slot.status;
                    slot.completed = false;
                    s.tag_free |= 1u32 << tag;
                    return Poll::Ready(if status == 0 {
                        Ok(())
                    } else {
                        Err(GdmaError::dma_error(status))
                    });
                }
                slot.waker.register(cx.waker());
                Poll::Pending
            })
        }))
    }

    /// Drain all available CQ entries and wake their awaiters.
    ///
    /// Processes every pending completion in one call, amortizing the
    /// SingleCell borrow and batching the MMIO head pointer write.
    /// Call from the GDMA_CQ IRQ handler or the main poll loop.
    pub fn wake(&self, irq: u16) {
        self.state.with(|s| {
            // Clear NVIC pending bit for this interrupt

            let tail = unsafe { self.cq_tail_shadow.read_volatile() } as u16;

            while s.cq_head != tail {
                let cq_slot = (s.cq_head & Self::MASK) as usize;
                let cq_entry = unsafe { &*self.cq_ring.add(cq_slot) };

                let tag = cq_entry.status.read(GDMA_CQ_STATUS::TAG) as u16;
                let status = if cq_entry.status.read(GDMA_CQ_STATUS::SUCCESS) != 0 {
                    0u8
                } else {
                    1u8
                };

                s.cq_head = (s.cq_head + 1) & Self::MASK;

                if (tag as usize) < DEPTH {
                    let slot = &mut s.tags[tag as usize];
                    slot.status = status;
                    slot.completed = true;
                    slot.waker.wake();
                }
            }

            self.regs.cq[self.channel as usize]
                .head
                .write(CQ_CHANNEL_HEAD::HEAD.val(s.cq_head.into()));
            azihsm_fw_uno_drivers_nvic::Nvic::unpend_raw(irq);
        });
    }
}
