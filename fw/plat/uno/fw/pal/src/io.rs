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
//! | `DTCM_IO_BUF[index]` | 2KB fmem     | Fast DTCM workspace buffer           |
//! | `SRAM_IO_BUF[index]` | 8KB smem     | Large SRAM workspace buffer          |
//!
//! The IIC controller DMAs incoming SQE data directly into `IO_SQ[index]`
//! (configured via `io_pool_base`). The firmware reads the SQE in-place
//! and writes the CQE into `IO_CQ[index]` for OIC to transmit.

use core::mem;

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
    /// Constructs an IO handle over the dedicated admin slot
    /// ([`ADMIN_IO_INDEX`]), targeting partition `pid`.
    ///
    /// Internal provisioning (partition identity and enable-time keygen)
    /// runs without a host IO. Reusing the concrete [`UnoHsmIo`] /
    /// [`UnoScopedAlloc`] types — rather than a bespoke admin IO type —
    /// avoids re-monomorphizing the generic vault / crypto / DMA paths.
    /// The target `pid` is written into the admin slot's `IO_META` so
    /// [`pid`](HsmIo::pid) resolves correctly.
    ///
    /// [`ADMIN_IO_INDEX`]: crate::alloc::ADMIN_IO_INDEX
    /// [`UnoScopedAlloc`]: crate::alloc::UnoScopedAlloc
    pub(crate) fn admin(pid: HsmPartId) -> Self {
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

    /// Sends the completed IO back to the host via OIC, then returns
    /// the IO_SQ slot to the ISQ for reuse.
    async fn complete_io(&self, io: Self::Io) -> HsmResult<()> {
        let queue_id = io.queue_id();
        let result = self.oic.send(io.index)?.await;
        self.iic.free_io(io.index, queue_id);
        result
    }

    /// Drops an IO without sending a completion (e.g. for disabled
    /// partitions). Returns the IO_SQ slot to the ISQ.
    #[allow(clippy::unused_async)]
    async fn drop_io(&self, io: Self::Io) -> HsmResult<()> {
        let queue_id = io.queue_id();
        self.iic.free_io(io.index, queue_id);
        Ok(())
    }
}
