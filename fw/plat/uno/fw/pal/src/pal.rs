// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno platform abstraction layer — lifecycle and NVIC polling.
//!
//! Implements [`HsmPal`] for the Uno SoC. The PAL owns the three
//! hardware drivers (IIC, OIC, GDMA) and manages their lifecycle:
//!
//! - **`init`**: Initialises the timer, enables all three peripheral
//!   channels with interrupt at source, and signals `SYS_READY` to the
//!   host via semihosting.
//!
//! - **`run`**: Enters a cooperative polling loop that checks NVIC
//!   pending bits for IIC_ICQ, OIC_OCQ, and GDMA_CQ. When a peripheral
//!   interrupt is pending, it wakes the corresponding driver's async
//!   waker so the Embassy executor can poll the driver's future.
//!   No NVIC-level ISRs are used — the NVIC pending bit is set by the
//!   hardware (level-triggered) and cleared by the driver after
//!   draining its queue.
//!
//! - **`deinit`**: No-op (no hardware teardown required).
//!
//! # Memory layout
//!
//! All queue memory lives in the IO GSRAM region starting at
//! [`IO_GSRAM_BASE`]. The IIC receive buffer pool (`io_pool_base`)
//! points to `IO_SQ` — each 64-byte SQE is DMA'd directly into
//! `IO_SQ[index]` by IIC, so the firmware can read the SQE in-place
//! without a copy.

use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_static_init::static_init;
use azihsm_fw_uno_drivers_aes::AesDriver;
use azihsm_fw_uno_drivers_gdma::ChannelConfig as GdmaChannelConfig;
use azihsm_fw_uno_drivers_gdma::GdmaDriver;
use azihsm_fw_uno_drivers_iic::ChannelConfig as IicChannelConfig;
use azihsm_fw_uno_drivers_iic::IicDriver;
use azihsm_fw_uno_drivers_ipc::IpcConfig;
use azihsm_fw_uno_drivers_ipc::IpcDriver;
use azihsm_fw_uno_drivers_ipc::IpcPairConfig;
use azihsm_fw_uno_drivers_ipc::IpcPairKind;
use azihsm_fw_uno_drivers_nvic::Nvic;
use azihsm_fw_uno_drivers_oic::ChannelConfig as OicChannelConfig;
use azihsm_fw_uno_drivers_oic::OicDriver;
use azihsm_fw_uno_drivers_rng::RngCalibration;
use azihsm_fw_uno_drivers_rng::RngDriver;
use azihsm_fw_uno_drivers_sha::ShaDriver;
use azihsm_fw_uno_drivers_systick as systick_driver;
use azihsm_fw_uno_drivers_upka::UpkaDriver;
use azihsm_fw_uno_pac::Interrupt;
use azihsm_fw_uno_reg_soc::io_gsram::GDMA_CQ_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::GDMA_CQ_TAIL_SHADOW_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::GDMA_SQ_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::ICQ_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::ICQ_TAIL_SHADOW_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::IO_CQ_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;
use azihsm_fw_uno_reg_soc::io_gsram::IO_META_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::IO_SQ_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::ISQ_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::OCQ_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::OCQ_TAIL_SHADOW_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::OSQ_OFFSET;
use azihsm_fw_uno_trace::tracing::*;

/// Queue depth for all IO queues (ISQ, ICQ, OSQ, OCQ, GDMA SQ/CQ).
const IO_QUEUE_DEPTH: usize = 32;

/// Number of IPC pairs configured for the firmware.
const IPC_PAIRS: usize = 2;

/// IPC ring depth (entries per ring).
const IPC_RING_DEPTH: u16 = 4;

/// IPC message length in DWORDs.
const IPC_MSG_LEN: u16 = 16;

/// SRAM base for IPC rings (after IO SRAM buffers: 32 × 8KB = 256KB).
const IPC_SRAM_BASE: u32 = 0x6104_0000;

// IPC pair 0: host→firmware message channel (desc 30 in, 31 out)
// Layout in SRAM at IPC_SRAM_BASE:
//   0x00: TX PI (4B)    0x04: TX CI (4B)
//   0x08: RX PI (4B)    0x0C: RX CI (4B)
//   0x10: TX ring (4 × 64B = 256B)
//   0x110: RX ring (4 × 64B = 256B)
const IPC_PAIR0_TX_PI: u32 = IPC_SRAM_BASE;
const IPC_PAIR0_TX_CI: u32 = IPC_SRAM_BASE + 4;
const IPC_PAIR0_RX_PI: u32 = IPC_SRAM_BASE + 8;
const IPC_PAIR0_RX_CI: u32 = IPC_SRAM_BASE + 12;
const IPC_PAIR0_TX_RING: u32 = IPC_SRAM_BASE + 0x10;
const IPC_PAIR0_RX_RING: u32 = IPC_SRAM_BASE + 0x110;

// ── NVIC wake dispatch ─────────────────────────────────────────

type WakeFn = fn(&UnoHsmPal, u16);

/// Wake the PKA driver engine that owns the given IRQ.
///
/// PKA IRQs are laid out as two contiguous ranges of 16: done IRQs
/// `UPKA_0_DONE..=UPKA_15_DONE` (192..=207) and error IRQs
/// `UPKA_0_ERROR..=UPKA_15_ERROR` (208..=223). Either edge maps to the
/// same engine index `irq & 0x0F`.
fn wake_pka(pal: &UnoHsmPal, irq: u16) {
    pal.pka.wake_engine((irq & 0x0F) as u8);
}

/// `(IRQ number, wake function)` pairs registered for NVIC dispatch.
///
/// Adding a new peripheral interrupt requires one entry here. The
/// [`ISPR_MASKS`] and [`WAKE_TABLE`] are derived automatically. Each
/// wake function receives the IRQ number so a single handler can
/// distinguish between multiple IRQs routed to the same driver — used
/// by [`wake_pka`] to derive the engine index from the IRQ.
const WAKE_ENTRIES: &[(u16, WakeFn)] = &[
    // Per-peripheral wakers — one IRQ per peripheral.
    (Interrupt::IIC_ICQ as u16, |pal, irq| pal.iic.wake(irq)),
    (Interrupt::OIC_OCQ as u16, |pal, irq| pal.oic.wake(irq)),
    (Interrupt::AES_DONE as u16, |pal, _| pal.aes.wake()),
    (Interrupt::SHA_DONE as u16, |pal, _| pal.sha.wake()),
    (Interrupt::GDMA_CQ as u16, |pal, irq| pal.gdma.wake(irq)),
    (Interrupt::INTC_IPC as u16, |pal, irq| pal.ipc.wake(irq)),
    // PKA done IRQs (192..=207) — `wake_pka` derives the engine index.
    (Interrupt::UPKA_0_DONE as u16, wake_pka),
    (Interrupt::UPKA_1_DONE as u16, wake_pka),
    (Interrupt::UPKA_2_DONE as u16, wake_pka),
    (Interrupt::UPKA_3_DONE as u16, wake_pka),
    (Interrupt::UPKA_4_DONE as u16, wake_pka),
    (Interrupt::UPKA_5_DONE as u16, wake_pka),
    (Interrupt::UPKA_6_DONE as u16, wake_pka),
    (Interrupt::UPKA_7_DONE as u16, wake_pka),
    (Interrupt::UPKA_8_DONE as u16, wake_pka),
    (Interrupt::UPKA_9_DONE as u16, wake_pka),
    (Interrupt::UPKA_10_DONE as u16, wake_pka),
    (Interrupt::UPKA_11_DONE as u16, wake_pka),
    (Interrupt::UPKA_12_DONE as u16, wake_pka),
    (Interrupt::UPKA_13_DONE as u16, wake_pka),
    (Interrupt::UPKA_14_DONE as u16, wake_pka),
    (Interrupt::UPKA_15_DONE as u16, wake_pka),
    // PKA error IRQs (208..=223) — same routing as the done IRQs.
    (Interrupt::UPKA_0_ERROR as u16, wake_pka),
    (Interrupt::UPKA_1_ERROR as u16, wake_pka),
    (Interrupt::UPKA_2_ERROR as u16, wake_pka),
    (Interrupt::UPKA_3_ERROR as u16, wake_pka),
    (Interrupt::UPKA_4_ERROR as u16, wake_pka),
    (Interrupt::UPKA_5_ERROR as u16, wake_pka),
    (Interrupt::UPKA_6_ERROR as u16, wake_pka),
    (Interrupt::UPKA_7_ERROR as u16, wake_pka),
    (Interrupt::UPKA_8_ERROR as u16, wake_pka),
    (Interrupt::UPKA_9_ERROR as u16, wake_pka),
    (Interrupt::UPKA_10_ERROR as u16, wake_pka),
    (Interrupt::UPKA_11_ERROR as u16, wake_pka),
    (Interrupt::UPKA_12_ERROR as u16, wake_pka),
    (Interrupt::UPKA_13_ERROR as u16, wake_pka),
    (Interrupt::UPKA_14_ERROR as u16, wake_pka),
    (Interrupt::UPKA_15_ERROR as u16, wake_pka),
];

/// Highest IRQ number in WAKE_ENTRIES — computed at compile time.
const MAX_IRQ_NUM: usize = {
    let mut max = 0usize;
    let mut i = 0;
    while i < WAKE_ENTRIES.len() {
        let irq = WAKE_ENTRIES[i].0 as usize;
        if irq > max {
            max = irq;
        }
        i += 1;
    }
    max
};

/// Number of ISPR registers to poll — derived from highest IRQ.
const ISPR_COUNT: usize = MAX_IRQ_NUM / 32 + 1;

/// Dispatch table size — one slot per IRQ up to the highest.
const MAX_IRQ: usize = ISPR_COUNT * 32;

/// Per-ISPR bitmask of registered IRQs — computed at compile time.
const ISPR_MASKS: [u32; ISPR_COUNT] = {
    let mut masks = [0u32; ISPR_COUNT];
    let mut i = 0;
    while i < WAKE_ENTRIES.len() {
        let irq = WAKE_ENTRIES[i].0 as usize;
        masks[irq / 32] |= 1 << (irq % 32);
        i += 1;
    }
    masks
};

/// Per-IRQ dispatch table — computed at compile time.
const WAKE_TABLE: [WakeFn; MAX_IRQ] = {
    fn noop(_: &UnoHsmPal, _: u16) {}
    let mut t = [noop as WakeFn; MAX_IRQ];
    let mut i = 0;
    while i < WAKE_ENTRIES.len() {
        t[WAKE_ENTRIES[i].0 as usize] = WAKE_ENTRIES[i].1;
        i += 1;
    }
    t
};

type Iic = IicDriver<IO_QUEUE_DEPTH>;
type Oic = OicDriver<IO_QUEUE_DEPTH>;
type Gdma = GdmaDriver<IO_QUEUE_DEPTH>;
type Ipc = IpcDriver<IPC_PAIRS>;
type Aes = AesDriver<IO_QUEUE_DEPTH>;
type Sha = ShaDriver<IO_QUEUE_DEPTH>;
type Upka = UpkaDriver<IO_QUEUE_DEPTH, 16>;

use crate::alloc::IO_ALLOC_INIT;
use crate::alloc::IoAllocTable;

/// The Uno HSM platform abstraction layer.
///
/// Holds static references to the IIC, OIC, GDMA, and IPC drivers.
/// Created once via [`Default::default`] and stored in the global
/// HSM singleton.
pub struct UnoHsmPal {
    /// Inbound IO Controller — receives SQEs from the host.
    pub iic: &'static Iic,

    /// Outbound IO Controller — sends CQEs back to the host.
    pub oic: &'static Oic,

    /// General DMA Controller — copies data between host and device.
    pub gdma: &'static Gdma,

    /// AES cryptographic engine.
    pub aes: &'static Aes,

    /// SHA cryptographic engine.
    pub sha: &'static Sha,

    /// PKA public key accelerator — 16 engines.
    pub pka: &'static Upka,

    /// Random number generator.
    pub rng: &'static RngDriver,

    /// IPC Controller — doorbell-based inter-processor communication.
    pub ipc: &'static Ipc,

    /// Per-IO bump allocator state (watermarks for Local + Global heaps).
    pub(crate) io_alloc: IoAllocTable,
}

impl core::fmt::Debug for UnoHsmPal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnoHsmPal").finish_non_exhaustive()
    }
}

impl Default for UnoHsmPal {
    fn default() -> Self {
        let iic_config = IicChannelConfig {
            channel: 0,
            isq_base: IO_GSRAM_BASE + ISQ_OFFSET,
            // IIC DMAs into IO_SQ so the firmware reads the SQE in-place.
            io_pool_base: IO_GSRAM_BASE + IO_SQ_OFFSET,
            io_size: 64,
            icq_base: IO_GSRAM_BASE + ICQ_OFFSET,
            icq_tail_shadow: IO_GSRAM_BASE + ICQ_TAIL_SHADOW_OFFSET,
            io_meta_base: IO_GSRAM_BASE + IO_META_OFFSET,
            interrupt: true,
        };

        let oic_config = OicChannelConfig {
            channel: 0,
            osq_base: IO_GSRAM_BASE + OSQ_OFFSET,
            ocq_base: IO_GSRAM_BASE + OCQ_OFFSET,
            ocq_tail_shadow: IO_GSRAM_BASE + OCQ_TAIL_SHADOW_OFFSET,
            io_cq_base: IO_GSRAM_BASE + IO_CQ_OFFSET,
            io_meta_base: IO_GSRAM_BASE + IO_META_OFFSET,
            interrupt: true,
        };

        let gdma_config = GdmaChannelConfig {
            channel: 0,
            sq_base: IO_GSRAM_BASE + GDMA_SQ_OFFSET,
            cq_base: IO_GSRAM_BASE + GDMA_CQ_OFFSET,
            cq_tail_shadow: IO_GSRAM_BASE + GDMA_CQ_TAIL_SHADOW_OFFSET,
            sq_head_shadow: IO_GSRAM_BASE + GDMA_CQ_TAIL_SHADOW_OFFSET + 4,
        };

        let ipc_config = IpcConfig {
            int_block: 1,
            pairs: &[
                // Pair 0: recv messages from host (desc 30 in, 31 out)
                IpcPairConfig {
                    kind: IpcPairKind::RecvMessage,
                    inbound_desc: 30,
                    outbound_desc: 31,
                    tx_ring_base: IPC_PAIR0_TX_RING,
                    tx_pi: IPC_PAIR0_TX_PI,
                    tx_ci: IPC_PAIR0_TX_CI,
                    rx_ring_base: IPC_PAIR0_RX_RING,
                    rx_pi: IPC_PAIR0_RX_PI,
                    rx_ci: IPC_PAIR0_RX_CI,
                    depth: IPC_RING_DEPTH,
                    msg_len: IPC_MSG_LEN,
                },
                // Pair 1: recv events from host (desc 28 in, 29 out)
                IpcPairConfig {
                    kind: IpcPairKind::RecvEvent,
                    inbound_desc: 28,
                    outbound_desc: 29,
                    tx_ring_base: 0,
                    tx_pi: 0,
                    tx_ci: 0,
                    rx_ring_base: 0,
                    rx_pi: 0,
                    rx_ci: 0,
                    depth: 0,
                    msg_len: 0,
                },
            ],
        };

        Self {
            iic: unsafe { static_init!(Iic, Iic::new(iic_config)) },
            oic: unsafe { static_init!(Oic, Oic::new(oic_config)) },
            gdma: unsafe { static_init!(Gdma, Gdma::new(gdma_config)) },
            aes: unsafe { static_init!(Aes, Aes::init(false)) },
            sha: unsafe { static_init!(Sha, Sha::init()) },
            pka: unsafe { static_init!(Upka, Upka::init()) },
            rng: unsafe { static_init!(RngDriver, RngDriver::init()) },
            ipc: unsafe { static_init!(Ipc, Ipc::init(ipc_config)) },
            io_alloc: IO_ALLOC_INIT,
        }
    }
}

impl UnoHsmPal {
    /// Poll the NVIC once and wake any PAL driver with a pending IRQ.
    ///
    /// NVIC pending bits are **not** cleared here. For level-triggered
    /// peripherals (IIC, OIC, GDMA, IPC) the source de-asserts after the
    /// driver reads the hardware status. For edge-triggered peripherals
    /// (AES, SHA, PKA) the pending bit remains until the next
    /// `poll_once` call — the driver's `wake()` reads and clears the
    /// hardware status register, so the subsequent call finds nothing
    /// to do and returns early.
    pub fn poll_once(&self) {
        for (reg, &mask) in ISPR_MASKS.iter().enumerate() {
            let pend = Nvic::pending_bits(reg) & mask;
            let mut bits = pend;
            while bits != 0 {
                let bit = bits.trailing_zeros();
                bits &= !(1 << bit);
                let irq = (reg * 32 + bit as usize) as u16;
                WAKE_TABLE[irq as usize](self, irq);
            }
        }
    }

    /// Minimum bring-up required before the boot handshake.
    ///
    /// Enables IPC pairs so the firmware can receive `NormalBoot` /
    /// `Start` messages from the Admin core. On real silicon the RNG
    /// calibration delay runs here to let Admin finish IPC setup.
    ///
    /// Everything else — crypto engines, IIC/OIC/GDMA — is deferred
    /// to [`HsmPal::init`] to match the azihsm boot sequence.
    pub fn pre_init(&self) {
        self.rng.init_calibrated(&RngCalibration::DEFAULT);
        self.ipc.enable(0);
        self.ipc.enable(1);
    }

    /// Async IPC message processing loop.
    ///
    /// Receives messages on pair 0 and events on pair 1, dispatching
    /// to the appropriate handler. Currently echoes messages back with
    /// the response bit set in the header and acknowledges events.
    pub async fn run_ipc(&self) {
        loop {
            let mut recv_msg = [0u32; 16];

            use embassy_futures::select::Either3;
            use embassy_futures::select::select3;

            let result = select3(
                self.ipc.recv(0, &mut recv_msg),
                self.ipc.recv_event(1),
                embassy_futures::yield_now(),
            )
            .await;
            match result {
                Either3::First(_) => {
                    // Set response bit in header and reply
                    recv_msg[0] |= 0x80;
                    self.ipc.reply(0, &recv_msg);
                }
                Either3::Second(value) => {
                    self.ipc.ack_event(1, value);
                }
                Either3::Third(()) => {}
            }
        }
    }
}

impl HsmPal for UnoHsmPal {
    /// Initialises the Uno platform.
    ///
    /// Sets up the Embassy timer driver, enables all three peripheral
    /// channels with interrupt at source, and signals `SYS_READY` so
    /// the host can begin submitting IOs.
    fn init(&self) {
        systick_driver::init();
        self.iic.init();
        self.oic.init();
        self.gdma.init();
        self.iic.enable();
        self.oic.enable();
        self.gdma.enable(true);
        self.ipc.enable(0);
        self.ipc.enable(1);
        info!("pal", "initialized");
        #[cfg(feature = "semihosting")]
        azihsm_fw_uno_drivers_semihosting::sys_ready();
    }

    /// Cooperative NVIC polling loop.
    ///
    /// Reads ISPR registers, masks to registered IRQs, and dispatches
    /// to driver wake functions via a const lookup table. One MMIO
    /// read per ISPR register, no per-IRQ reads, no branches on
    /// unregistered IRQs.
    ///
    /// Yields to the Embassy executor between iterations so other
    /// tasks (poll_io, handle_io) can run.
    async fn run(&self) {
        loop {
            self.poll_once();
            embassy_futures::yield_now().await;
        }
    }

    /// No-op — the emulated SoC does not require teardown.
    fn deinit(&self) {}
}
