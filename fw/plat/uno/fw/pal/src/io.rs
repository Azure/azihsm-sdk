// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno I/O controller — bridges IIC/OIC drivers to HSM IO traits.
//!
//! Implements [`HsmIoController`] and [`HsmIo`] for the Uno SoC by
//! mapping the IIC driver's submission/completion queues to the
//! platform-agnostic HSM I/O traits.
//!
//! # Memory regions
//!
//! Each IO slot `index` has four associated regions in the IO GSRAM
//! address map:
//!
//! | Region          | Array             | Purpose                              |
//! |-----------------|-------------------|--------------------------------------|
//! | `IO_SQ[index]`  | 64B SQE           | Submission queue entry (read-only)   |
//! | `IO_CQ[index]`  | 16B CQE           | Completion queue entry (write)       |
//! | `IO_META[index]` | 8B metadata      | Controller/queue IDs from IIC recv   |
//! | `DTCM_IO_BUF[index]` | 1.5KB fmem   | Fast DTCM workspace buffer           |
//! | `SRAM_IO_BUF[index]` | 16KB smem    | Large SRAM workspace buffer          |
//!
//! The IIC controller DMAs incoming SQE data directly into `IO_SQ[index]`
//! (configured via `io_pool_base`). The firmware reads the SQE in-place
//! and writes the CQE into `IO_CQ[index]` for OIC to transmit.

use core::mem;
use core::ops::AsyncFnOnce;

use azihsm_fw_hsm_pal_traits::HsmCqe;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmIoController;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSqe;
use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;
use azihsm_fw_uno_reg_soc::io_gsram::IO_META_CTLR;
use azihsm_fw_uno_reg_soc::io_gsram::IO_META_QUEUE;
use azihsm_fw_uno_reg_soc::io_gsram::IoCqEntry;
use azihsm_fw_uno_reg_soc::io_gsram::IoMetaEntry;
use azihsm_fw_uno_reg_soc::io_gsram::IoSqEntry;
use azihsm_fw_uno_reg_soc::io_gsram::regs::IoGsramRegs;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;

use crate::UnoHsmPal;
use crate::alloc::ADMIN_IO_INDEX;
use crate::alloc::UnoScopedAlloc;
use crate::alloc::reset_io_alloc;

/// Typed overlay of the IO GSRAM region.
const IO_Q: StaticRef<IoGsramRegs> = unsafe { StaticRef::new(IO_GSRAM_BASE as *const IoGsramRegs) };

/// An in-flight IO identified by its IO_SQ slot index.
///
/// Holds the slot index for the lifetime of a single IO operation.
/// Metadata (controller_id, queue_id, queue_index) is stored in
/// `IO_META[index]`, written by the IIC driver at recv time.
#[derive(Debug)]
pub struct UnoHsmIo {
    /// IO_SQ slot index. Host IO uses `0..ADMIN_IO_INDEX`; the reserved
    /// admin slot (`ADMIN_IO_INDEX`, the last of `IO_SLOTS`) is used only
    /// for PAL-internal provisioning crypto. So the valid range is
    /// `0..=ADMIN_IO_INDEX`, not just the host range.
    index: u16,
}

impl UnoHsmIo {
    /// Constructs a **bare, unscrubbed** IO handle over the dedicated admin
    /// slot ([`ADMIN_IO_INDEX`]), targeting partition `pid`.
    ///
    /// Internal provisioning (partition identity and enable-time keygen)
    /// runs without a host IO. Reusing the concrete [`UnoHsmIo`] /
    /// [`UnoScopedAlloc`] types — rather than a bespoke admin IO type —
    /// avoids re-monomorphizing the generic vault / crypto / DMA paths.
    /// The target `pid` is written into the admin slot's `IO_META` so
    /// [`pid`](HsmIo::pid) resolves correctly.
    ///
    /// # Prefer [`with_admin_io`](UnoHsmPal::with_admin_io)
    ///
    /// This constructor performs **no scrub**: anything the caller writes to
    /// the admin slot's bump heaps stays resident until some later scrub.
    /// Use it only on a path that provably dirties neither heap — today just
    /// the synchronous unwrapping-key import, which cannot `await` a scrub
    /// and copies straight from `&'static` GSRAM into vault storage. Every
    /// other admin path must go through
    /// [`with_admin_io`](UnoHsmPal::with_admin_io), which wipes the slot on
    /// completion. The name is deliberately blunt so a new call site has to
    /// opt into the hazard explicitly.
    ///
    /// [`ADMIN_IO_INDEX`]: crate::alloc::ADMIN_IO_INDEX
    /// [`UnoScopedAlloc`]: crate::alloc::UnoScopedAlloc
    pub(crate) fn admin_no_scrub(pid: HsmPartId) -> Self {
        let io = Self {
            index: ADMIN_IO_INDEX,
        };
        io.io_meta()
            .ctlr
            .write(IO_META_CTLR::CONTROLLER_ID.val(u8::from(pid) as u32));
        io
    }

    /// Returns a reference to the IO_META entry for this slot.
    #[inline]
    fn io_meta(&self) -> &IoMetaEntry {
        &IO_Q.io_meta[self.index as usize]
    }
}

impl HsmIo for UnoHsmIo {
    /// Returns the IO slot index.
    fn index(&self) -> u16 {
        self.index
    }

    /// Returns the partition ID (controller_id from IO_META).
    fn pid(&self) -> HsmPartId {
        HsmPartId::from(self.io_meta().ctlr.read(IO_META_CTLR::CONTROLLER_ID) as u8)
    }

    /// Returns the queue ID from IO_META.
    fn queue_id(&self) -> u16 {
        self.io_meta().queue.read(IO_META_QUEUE::QUEUE_ID) as u16
    }

    /// Returns the queue index from IO_META.
    fn queue_idx(&self) -> u16 {
        self.io_meta().queue.read(IO_META_QUEUE::QUEUE_INDEX) as u16
    }

    /// Returns the SQE from `IO_SQ[index]`.
    ///
    /// IIC DMAs the host-side 64-byte SQE directly into this slot, so it
    /// can be read in-place without a copy.
    fn sqe(&self) -> &HsmSqe {
        const _ASSERT_SQE_SIZE: () =
            assert!(mem::size_of::<IoSqEntry>() == mem::size_of::<HsmSqe>());
        const _ASSERT_SQE_ALIGN: () =
            assert!(mem::align_of::<IoSqEntry>() == mem::align_of::<HsmSqe>());

        let io_sq = &IO_Q.io_sq[self.index as usize];
        unsafe { &*(io_sq as *const IoSqEntry as *const HsmSqe) }
    }

    /// Returns a mutable reference to the CQE at `IO_CQ[index]`.
    ///
    /// The HSM core writes completion status here; the OIC driver
    /// reads it when sending the completion back to the host.
    fn cqe(&mut self) -> &mut HsmCqe {
        const _ASSERT_CQE_SIZE: () =
            assert!(mem::size_of::<IoCqEntry>() == mem::size_of::<HsmCqe>());
        const _ASSERT_CQE_ALIGN: () =
            assert!(mem::align_of::<IoCqEntry>() == mem::align_of::<HsmCqe>());

        unsafe {
            let ptr = core::ptr::addr_of!(IO_Q.io_cq[self.index as usize]) as *mut HsmCqe;
            &mut *ptr
        }
    }
}

impl HsmIoController for UnoHsmPal {
    type Io = UnoHsmIo;

    /// Awaits the next inbound IO from the IIC driver.
    async fn poll_io(&self) -> HsmResult<Self::Io> {
        let index = self.iic.recv().await;
        reset_io_alloc(self, index);
        Ok(UnoHsmIo { index })
    }

    /// Posts the completion (CQE) to the host via OIC.
    ///
    /// Posts the CQE only; the IO_SQ slot is returned to the ISQ
    /// separately by [`drop_io`](HsmIoController::drop_io) so the caller
    /// can run post-completion work over `io` first.
    async fn complete_io(&self, io: &mut Self::Io) -> HsmResult<()> {
        self.oic.send(io.index)?.await
    }

    /// Drops an IO without sending a completion (e.g. for disabled
    /// partitions). Scrubs the slot's scratch buffers, then returns the
    /// IO_SQ slot to the ISQ.
    ///
    /// This is the universal IO teardown point (the core dispatch loop
    /// calls it on both the completed and the dropped paths), so the
    /// per-IO buffer scrub lives here. See
    /// [`scrub_io_slot`](UnoHsmPal::scrub_io_slot).
    async fn drop_io(&self, io: Self::Io) -> HsmResult<()> {
        let queue_id = io.queue_id();
        // Scrub both per-IO scratch buffers *before* returning the slot to
        // the ISQ, so no key material from this IO can be observed by the
        // next IO that reuses the slot.
        self.scrub_io_slot(io.index).await;
        self.iic.free_io(io.index, queue_id);
        Ok(())
    }
}

impl UnoHsmPal {
    /// Runs `f` as an *admin session* over the dedicated admin IO slot
    /// ([`ADMIN_IO_INDEX`]), scrubbing that slot when `f` completes.
    ///
    /// This is the admin-side counterpart of
    /// [`drop_io`](HsmIoController::drop_io): internal provisioning
    /// (partition identity, enable-time keygen, boot-key masking, vault
    /// teardown) runs without a host IO, so it never reaches `drop_io` and
    /// its scratch would otherwise only be watermark-rewound, never wiped —
    /// leaving raw private-key material (e.g. the P-384 identity scalar)
    /// resident in the admin slot indefinitely.
    ///
    /// Binding the scrub to the session rather than to each caller means no
    /// admin path that dirties the slot can forget it. The one deliberate
    /// exception is [`UnoHsmIo::admin_no_scrub`], whose name states that it
    /// opts out; it is reserved for paths that provably write nothing to
    /// either bump heap. `f` also receives a [`UnoScopedAlloc`] rewound to
    /// the slot's base, so every admin sequence starts from a clean bump
    /// heap.
    ///
    /// Sessions must not nest — [`UnoScopedAlloc::for_admin`] rewinds the
    /// slot's watermarks, so an inner session would alias an outer one's
    /// live buffers. All current callers are strictly sequential.
    ///
    /// # Parameters
    /// - `pid`: partition the session targets; written into the admin
    ///   slot's `IO_META` so [`pid`](HsmIo::pid) resolves correctly.
    /// - `f`: async closure run with the admin IO handle and a rewound
    ///   scoped allocator.
    ///
    /// # Returns
    /// Whatever `f` returned. `R` cannot borrow anything the scrub will wipe:
    /// the higher-ranked bound stops it borrowing from the session's scoped
    /// allocator, and `R: 'static` additionally stops it returning a buffer
    /// obtained from the PAL-level allocator, whose lifetime is tied to the
    /// PAL and so outlives the session. Every current caller returns an owned
    /// value, so the bound costs nothing.
    pub(crate) async fn with_admin_io<R, F>(&self, pid: HsmPartId, f: F) -> R
    where
        R: 'static,
        F: for<'a> AsyncFnOnce(&'a UnoHsmIo, &'a UnoScopedAlloc<'a>) -> R,
    {
        let io = UnoHsmIo::admin_no_scrub(pid);
        let result = {
            let alloc = UnoScopedAlloc::for_admin(self);
            f(&io, &alloc).await
        };
        self.scrub_io_slot(ADMIN_IO_INDEX).await;
        result
    }
}
