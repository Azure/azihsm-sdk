// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::future::poll_fn;
use core::task::Poll;

use azihsm_fw_single_cell::SingleCell;
use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_error::HsmResult;
use azihsm_fw_uno_reg_soc::io_gsram::IoCqEntry;
use azihsm_fw_uno_reg_soc::io_gsram::IoMetaEntry;
use azihsm_fw_uno_reg_soc::io_gsram::OcqEntry;
use azihsm_fw_uno_reg_soc::io_gsram::OsqEntry;
use azihsm_fw_uno_reg_soc::io_gsram::IO_META_QUEUE;
use azihsm_fw_uno_reg_soc::io_gsram::OCQ_TAG;
use azihsm_fw_uno_reg_soc::io_gsram::OSQ_DESC;
use azihsm_fw_uno_reg_soc::io_gsram::OSQ_TAG;
use azihsm_fw_uno_reg_soc::oic::regs::OicRegs;
use azihsm_fw_uno_reg_soc::oic::*;
use azihsm_fw_uno_trace::tracing::*;
use embassy_sync::waitqueue::WakerRegistration;
use tock_registers::interfaces::ReadWriteable;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;

use crate::ChannelConfig;
use crate::OicError;

struct TagSlot {
    waker: WakerRegistration,
    completed: bool,
    status: u8,
}

struct OicState<const DEPTH: usize> {
    ocq_head: u16,
    osq_tail: u16,
    tag_free: u32,
    tags: [TagSlot; DEPTH],
}

/// Async OIC (Outbound IO Controller) driver.
///
/// One instance per (controller, channel) pair. The controller base
/// address comes from the generated `OIC_BASE` constant.
///
/// Zero-copy: the OSQ entry points directly to the IO CQ entry in DTCM.
/// Work item metadata (controller_id, queue_id, queue_index) is read
/// from the IO_META sidecar.
///
/// # Type Parameters
///
/// - `DEPTH`: Queue depth and tag count. Must be a power of 2, at most 32.
pub struct OicDriver<const DEPTH: usize> {
    /// Physical channel index.
    channel: u8,

    /// OSQ ring in DTCM (typed overlay).
    osq_ring: *mut OsqEntry,

    /// OCQ ring in DTCM (typed overlay).
    ocq_ring: *const OcqEntry,

    /// OCQ tail shadow address (FW reads this instead of MMIO).
    ocq_tail_shadow: *const u32,

    /// IO_CQ array in DTCM.
    io_cq: *const IoCqEntry,

    /// IO_META sidecar array in DTCM.
    io_meta: *const IoMetaEntry,

    /// Mutable state protected by single-threaded access.
    state: SingleCell<OicState<DEPTH>>,

    /// Controller MMIO registers.
    regs: StaticRef<OicRegs>,

    /// Saved channel configuration, consumed by [`init`](Self::init).
    config: ChannelConfig,
}

// SAFETY: Single-core Cortex-M with cooperative scheduling.
unsafe impl<const DEPTH: usize> Send for OicDriver<DEPTH> {}
unsafe impl<const DEPTH: usize> Sync for OicDriver<DEPTH> {}

impl<const DEPTH: usize> core::fmt::Debug for OicDriver<DEPTH> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OicDriver")
            .field("DEPTH", &DEPTH)
            .field("channel", &self.channel)
            .finish()
    }
}

impl<const DEPTH: usize> OicDriver<DEPTH> {
    const MASK: u16 = (DEPTH - 1) as u16;

    const _ASSERT_POW2: () = assert!(DEPTH.is_power_of_two(), "DEPTH must be power of 2");
    const _ASSERT_MAX: () = assert!(DEPTH <= 32, "DEPTH must be <= 32 (u32 tag bitmap)");
    const _ASSERT_MIN: () = assert!(DEPTH >= 32, "DEPTH must be at least 32");

    /// Encoded depth for hardware registers: 0h=32, 1h=64, ..., Bh=65536.
    const ENCODED_DEPTH: u32 = DEPTH.trailing_zeros() - 5;

    /// Construct the driver for a specific channel without touching MMIO.
    ///
    /// Only stores configuration and initializes software state. Hardware
    /// registers and DTCM shadow words are programmed by [`init`](Self::init);
    /// the channel is then activated by [`enable`](Self::enable).
    ///
    /// Splitting construction from MMIO programming lets firmware build the
    /// driver instance early while deferring shared-register writes until after
    /// the boot handshake has completed.
    pub fn new(config: ChannelConfig) -> Self {
        #[allow(clippy::let_unit_value)]
        {
            let _ = Self::_ASSERT_POW2;
            let _ = Self::_ASSERT_MAX;
            let _ = Self::_ASSERT_MIN;
        }

        let regs = unsafe { StaticRef::new(OIC_BASE as *const OicRegs) };

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
            osq_ring: config.osq_base as *mut OsqEntry,
            ocq_ring: config.ocq_base as *const OcqEntry,
            ocq_tail_shadow: config.ocq_tail_shadow as *const u32,
            io_cq: config.io_cq_base as *const IoCqEntry,
            io_meta: config.io_meta_base as *const IoMetaEntry,
            state: SingleCell::new(OicState {
                ocq_head: 0,
                osq_tail: 0,
                tag_free,
                tags,
            }),
            regs,
            config,
        }
    }

    /// Program OCQ/OSQ channel registers and enable.
    ///
    /// Must only be called after any boot handshake completes. Calling this
    /// earlier can race the controller-side owner of shared common and IRQ
    /// registers.
    pub fn init(&self) {
        let config = self.config;
        let regs = self.regs;
        let ch = config.channel as usize;

        // Detect if channel was already programmed by another core
        let ocq_ctrl = regs.ocq_ch[ch].ctrl.get();
        let osq_ctrl = regs.osq_ch[ch].ctrl.get();
        if ocq_ctrl & 0x1 != 0 || osq_ctrl & 0x1 != 0 {
            warn!(
                "oic",
                "ch={} ALREADY ENABLED before init! ocq_ctrl={:#x} osq_ctrl={:#x}",
                config.channel,
                ocq_ctrl,
                osq_ctrl
            );
        }

        // ── Step 1: Reset TX queue shadow PI ───────────────────────
        unsafe { (config.ocq_tail_shadow as *mut u32).write_volatile(0) };

        // ── Step 2: Program OCQ channel ────────────────────────────
        let ocq = &regs.ocq_ch[ch];
        ocq.base_lo.set(config.ocq_base);
        ocq.base_hi.set(0);
        ocq.tail_shadow_lo.set(config.ocq_tail_shadow);
        ocq.tail_shadow_hi.set(0);
        ocq.tail.write(OCQ_CHANNEL_TAIL::TAIL.val(0));
        ocq.head.write(OCQ_CHANNEL_HEAD::HEAD.val(0));
        // Step 2.7: Enable interrupt before configuration_control
        if config.interrupt {
            let val = regs.irq_enable.read(IRQ_ENABLE::IRQ_EN) | (1 << config.channel);
            regs.irq_enable.write(IRQ_ENABLE::IRQ_EN.val(val));
        }
        ocq.ctrl.modify(
            OCQ_CHANNEL_CTRL::DEPTH.val(Self::ENCODED_DEPTH)
                + OCQ_CHANNEL_CTRL::IFC_SLCT.val(0)
                + OCQ_CHANNEL_CTRL::SHADOW_EN::SET,
        );

        // ── Step 3: Program OSQ channel ────────────────────────────
        let osq = &regs.osq_ch[ch];
        osq.base_lo.set(config.osq_base);
        osq.base_hi.set(0);
        osq.tail.write(OSQ_CHANNEL_TAIL::TAIL.val(0));
        osq.head.write(OSQ_CHANNEL_HEAD::HEAD.val(0));
        osq.ctrl.modify(
            OSQ_CHANNEL_CTRL::DEPTH.val(Self::ENCODED_DEPTH) + OSQ_CHANNEL_CTRL::IFC_SLCT.val(0),
        );

        // ── Step 4: Enable ─────────────────────────────────────────
        regs.ocq_ch[ch].ctrl.modify(OCQ_CHANNEL_CTRL::EN::SET);
        regs.osq_ch[ch].ctrl.modify(OSQ_CHANNEL_CTRL::EN::SET);
    }

    /// Allocate a tag, post an OSQ entry for the given IO index,
    /// and ring the doorbell.
    fn submit(&self, index: u16) -> HsmResult<u16> {
        let io_cq_entry = unsafe { &*self.io_cq.add(index as usize) };
        let data_addr = io_cq_entry as *const _ as u32;
        let meta = unsafe { &*self.io_meta.add(index as usize) };
        let queue_id = meta.queue.read(IO_META_QUEUE::QUEUE_ID) as u8;

        self.state.with(|s| {
            if s.tag_free == 0 {
                return Err(OicError::NO_FREE_TAGS);
            }
            let tag = s.tag_free.trailing_zeros() as u16;
            s.tag_free &= !(1u32 << tag);

            let osq_head = self.regs.osq_ch[self.channel as usize]
                .head
                .read(OSQ_CHANNEL_HEAD::HEAD) as u16;
            if (s.osq_tail + 1) & Self::MASK == osq_head {
                s.tag_free |= 1u32 << tag;
                return Err(OicError::OSQ_FULL);
            }

            // Write OSQ entry.
            // axi_id is always 0 (SoC) — HW routes via the queue manager
            // based on tx_queue_id, not via AXI port.
            let slot = (s.osq_tail & Self::MASK) as usize;
            let entry = unsafe { &mut *self.osq_ring.add(slot) };
            entry.addr_lo.set(data_addr);
            entry.addr_hi.set(0);
            entry.desc.write(
                OSQ_DESC::RX_QUEUE_ID.val(queue_id.into())
                    + OSQ_DESC::RX_CREDIT.val(0)
                    + OSQ_DESC::TX_QUEUE_ID.val(queue_id.into())
                    + OSQ_DESC::AXI_ID.val(0),
            );
            entry
                .tag
                .write(OSQ_TAG::TAG.val(tag.into()) + OSQ_TAG::CONTROL.val(0));

            cortex_m::asm::dmb();

            s.osq_tail = (s.osq_tail + 1) & Self::MASK;
            self.regs.osq_ch[self.channel as usize]
                .tail
                .write(OSQ_CHANNEL_TAIL::TAIL.val(s.osq_tail.into()));

            Ok(tag)
        })
    }

    /// Poll until the OCQ completion arrives for `tag`.
    fn wait_completion(&self, tag: u16) -> impl core::future::Future<Output = HsmResult<()>> + '_ {
        poll_fn(move |cx| {
            self.state.with(|s| {
                let slot = &mut s.tags[tag as usize];
                if slot.completed {
                    let status = slot.status;
                    slot.completed = false;
                    s.tag_free |= 1u32 << tag;
                    // HW status: 0x80 = Success, others = various errors
                    return Poll::Ready(if status == 0x80 {
                        Ok(())
                    } else {
                        Err(OicError::dma_error(status))
                    });
                }
                slot.waker.register(cx.waker());
                Poll::Pending
            })
        })
    }

    /// Send the IO CQ entry for the given work item index and wait
    /// for completion.
    ///
    /// Zero-copy: the OSQ entry points directly to `io_cq[index]` in
    /// DTCM. Metadata is read from `io_meta[index]`.
    ///
    /// # Errors
    ///
    /// Returns [`OicError::NO_FREE_TAGS`] if all tag slots are in use,
    /// or [`OicError::OSQ_FULL`] if the OSQ ring is full.
    pub fn send(
        &self,
        index: u16,
    ) -> HsmResult<impl core::future::Future<Output = HsmResult<()>> + '_> {
        let tag = self.submit(index)?;
        Ok(self.wait_completion(tag))
    }

    /// Drain all available OCQ entries and wake their awaiters.
    pub fn wake(&self, irq: u16) {
        self.state.with(|s| {
            let tail = unsafe { self.ocq_tail_shadow.read_volatile() } as u16;

            while s.ocq_head != tail {
                let ocq_slot = (s.ocq_head & Self::MASK) as usize;
                let ocq_entry = unsafe { &*self.ocq_ring.add(ocq_slot) };

                let tag = ocq_entry.tag.read(OCQ_TAG::TAG) as u16;
                let status = ocq_entry.tag.read(OCQ_TAG::STATUS) as u8;

                s.ocq_head = (s.ocq_head + 1) & Self::MASK;

                if (tag as usize) < DEPTH {
                    let slot = &mut s.tags[tag as usize];
                    slot.status = status;
                    slot.completed = true;
                    slot.waker.wake();
                }
            }

            self.regs.ocq_ch[self.channel as usize]
                .head
                .write(OCQ_CHANNEL_HEAD::HEAD.val(s.ocq_head.into()));
            azihsm_fw_uno_drivers_nvic::Nvic::unpend_raw(irq);
        });
    }
}
