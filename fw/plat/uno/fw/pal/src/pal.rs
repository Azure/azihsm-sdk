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

use core::cell::Cell;

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmPartId;
use azihsm_fw_static_init::static_init;
use azihsm_fw_uno_drivers_aes::AesDriver;
use azihsm_fw_uno_drivers_boot_status as boot_status;
use azihsm_fw_uno_drivers_boot_status::BootStatus;
use azihsm_fw_uno_drivers_core_status as core_status;
use azihsm_fw_uno_drivers_core_status::CoreStatus;
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
use azihsm_fw_uno_reg_soc::io_gsram::IPC_ADMIN_HSM_RX_CI_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::IPC_ADMIN_HSM_RX_PI_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::IPC_ADMIN_HSM_RX_RING_COUNT;
use azihsm_fw_uno_reg_soc::io_gsram::IPC_ADMIN_HSM_RX_RING_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::IPC_ADMIN_HSM_RX_RING_STRIDE;
use azihsm_fw_uno_reg_soc::io_gsram::IPC_ADMIN_HSM_TX_CI_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::IPC_ADMIN_HSM_TX_PI_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::IPC_ADMIN_HSM_TX_RING_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::ISQ_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::OCQ_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::OCQ_TAIL_SHADOW_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::OSQ_OFFSET;
use azihsm_fw_uno_trace::tracing::*;
use embassy_futures::select::Either3;
use embassy_futures::select::select3;

use crate::alloc::IO_ALLOC_INIT;
use crate::alloc::IoAllocTable;
use crate::ipc::*;

type Iic = IicDriver<IO_QUEUE_DEPTH>;
type Oic = OicDriver<IO_QUEUE_DEPTH>;
type Gdma = GdmaDriver<IO_QUEUE_DEPTH>;
type Ipc = IpcDriver<IPC_PAIRS>;
type Aes = AesDriver<IO_QUEUE_DEPTH>;
type Sha = ShaDriver<IO_QUEUE_DEPTH>;
type Upka = UpkaDriver<IO_QUEUE_DEPTH, 16>;

/// Boot handshake phase — tracks PAL lifecycle state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BootPhase {
    /// Waiting for `NormalBoot` from Admin.
    WaitNormalBoot,
    /// Waiting for `Start` from Admin.
    WaitStart,
    /// Boot complete — steady-state IPC.
    Running,
}

/// Queue depth for all IO queues (ISQ, ICQ, OSQ, OCQ, GDMA SQ/CQ).
const IO_QUEUE_DEPTH: usize = 32;

/// Number of IPC pairs configured for the firmware.
const IPC_PAIRS: usize = 2;

/// IPC channel identifiers.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpcChannel {
    /// Admin ↔ HSM command/response messages.
    AdminMessage = 0,
    /// Admin → HSM event notifications.
    AdminEvent = 1,
}

// ── NVIC wake dispatch ─────────────────────────────────────────

type WakeFn = fn(&UnoHsmPal, u16);

/// Wake the PKA driver engine that owns the given IRQ.
///
/// PKA IRQs are laid out as two contiguous ranges of 16: done IRQs
/// `UPKA_0_DONE..=UPKA_15_DONE` (32..=47) and error IRQs
/// `UPKA_0_ERROR..=UPKA_15_ERROR` (0..=15). Either edge maps to the
/// same engine index `irq & 0x0F`.
///
/// # Parameters
/// - `pal`: Shared PAL instance that owns the PKA driver.
/// - `irq`: Raw NVIC IRQ number in the PKA done/error ranges.
///
/// # Returns
/// Returns `()`.
///
/// # Side Effects
/// Wakes exactly one PKA engine by deriving its index from the low
/// nibble of `irq`.
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
    // PKA done IRQs (32..=47) — `wake_pka` derives the engine index.
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
    // PKA error IRQs (0..=15) — same routing as the done IRQs.
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

    /// Boot handshake phase (PAL lifecycle state).
    boot_phase: Cell<BootPhase>,

    /// Per-IO bump allocator state (watermarks for Local + Global heaps).
    pub(crate) io_alloc: IoAllocTable,
}

// SAFETY: UnoHsmPal is only accessed from a single-threaded Embassy
// executor on a single-core Cortex-M7 with no preemptive ISRs.
// The Cell<BootPhase> field is never accessed from interrupt context.
unsafe impl Sync for UnoHsmPal {}

impl Default for UnoHsmPal {
    fn default() -> Self {
        let iic_config = IicChannelConfig {
            channel: 3,
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
            channel: 3,
            osq_base: IO_GSRAM_BASE + OSQ_OFFSET,
            ocq_base: IO_GSRAM_BASE + OCQ_OFFSET,
            ocq_tail_shadow: IO_GSRAM_BASE + OCQ_TAIL_SHADOW_OFFSET,
            io_cq_base: IO_GSRAM_BASE + IO_CQ_OFFSET,
            io_meta_base: IO_GSRAM_BASE + IO_META_OFFSET,
            interrupt: true,
        };

        let gdma_config = GdmaChannelConfig {
            channel: 1,
            sq_base: IO_GSRAM_BASE + GDMA_SQ_OFFSET,
            cq_base: IO_GSRAM_BASE + GDMA_CQ_OFFSET,
            cq_tail_shadow: IO_GSRAM_BASE + GDMA_CQ_TAIL_SHADOW_OFFSET,
            sq_head_shadow: IO_GSRAM_BASE + GDMA_CQ_TAIL_SHADOW_OFFSET + 4,
            interrupt: true,
        };

        let ipc_config = IpcConfig {
            int_block: 1,
            pairs: &[
                // Pair 0: recv messages from host (desc 30 in, 31 out)
                IpcPairConfig {
                    kind: IpcPairKind::RecvMessage,
                    inbound_desc: 30,
                    outbound_desc: 31,
                    tx_ring_base: IO_GSRAM_BASE + IPC_ADMIN_HSM_TX_RING_OFFSET,
                    tx_pi: IO_GSRAM_BASE + IPC_ADMIN_HSM_TX_PI_OFFSET,
                    tx_ci: IO_GSRAM_BASE + IPC_ADMIN_HSM_TX_CI_OFFSET,
                    rx_ring_base: IO_GSRAM_BASE + IPC_ADMIN_HSM_RX_RING_OFFSET,
                    rx_pi: IO_GSRAM_BASE + IPC_ADMIN_HSM_RX_PI_OFFSET,
                    rx_ci: IO_GSRAM_BASE + IPC_ADMIN_HSM_RX_CI_OFFSET,
                    depth: IPC_ADMIN_HSM_RX_RING_COUNT as u16,
                    msg_len: (IPC_ADMIN_HSM_RX_RING_STRIDE / 4) as u16,
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
            aes: unsafe { static_init!(Aes, Aes::new(false)) },
            sha: unsafe { static_init!(Sha, Sha::new()) },
            pka: unsafe { static_init!(Upka, Upka::new()) },
            rng: unsafe { static_init!(RngDriver, RngDriver::new()) },
            ipc: unsafe { static_init!(Ipc, Ipc::new(ipc_config)) },
            boot_phase: Cell::new(BootPhase::WaitNormalBoot),
            io_alloc: IO_ALLOC_INIT,
        }
    }
}

impl UnoHsmPal {
    /// Returns the current boot phase.
    ///
    /// # Parameters
    /// - `self`: PAL instance containing the boot handshake state.
    ///
    /// # Returns
    /// Current [`BootPhase`] value:
    /// - `WaitNormalBoot` before first admin state transition
    /// - `WaitStart` after `NormalBoot` is acknowledged
    /// - `Running` after hardware channels are initialized
    pub fn boot_phase(&self) -> BootPhase {
        self.boot_phase.get()
    }

    /// Process one IPC receive cycle.
    ///
    /// Awaits the next message, event, or 60s keepalive tick, then
    /// dispatches to the appropriate handler. Returns after one iteration.
    ///
    /// # Parameters
    /// - `self`: PAL instance used to receive IPC traffic and dispatch handlers.
    ///
    /// # Returns
    /// Returns `()` after exactly one completed wait-and-dispatch cycle.
    /// This method does not return a status; callers should inspect PAL
    /// state (for example via [`Self::boot_phase`]) if needed.
    ///
    /// # Side Effects
    /// - Consumes one message from [`IpcChannel::Message`] when available.
    /// - Acknowledges one event on [`IpcChannel::Event`] when available.
    /// - Emits a periodic trace tick on timeout.
    pub async fn poll_ipc(&self) {
        let mut recv_msg = [0u32; 16];

        let result = select3(
            self.ipc.recv(IpcChannel::AdminMessage as u8, &mut recv_msg),
            self.ipc.recv_event(IpcChannel::AdminEvent as u8),
            embassy_time::Timer::after(embassy_time::Duration::from_millis(250)),
        )
        .await;
        match result {
            Either3::First(_) => {
                self.handle_ipc_message(IpcChannel::AdminMessage, &mut recv_msg)
                    .await;
            }
            Either3::Second(value) => {
                self.handle_ipc_event(IpcChannel::AdminEvent, value);
            }
            Either3::Third(()) => {
                self.heartbeat();
            }
        }
    }

    /// Write the core liveliness heartbeat to DTCM.
    ///
    /// SP polls CORE_RUN_STATUS and zeroes it; if zero on the next
    /// poll cycle, SP declares the core hung.
    fn heartbeat(&self) {
        core_status::set(CoreStatus::Alive);
    }

    /// Validate and acknowledge an expected boot state-change message.
    ///
    /// # Parameters
    /// - `self`: PAL instance used to send the ACK response.
    /// - `buf`: Inbound IPC payload buffer, expected to contain a state-change message.
    /// - `expected`: Required [`IoProcessorState`] for this boot phase.
    /// - `phase_name`: Human-readable phase label for trace diagnostics.
    ///
    /// # Returns
    /// - `true` if `buf` decoded as a state-change and matched `expected`.
    /// - `false` if decode failed or state did not match.
    ///
    /// # Side Effects
    /// Sends an ACK reply on [`IpcChannel::Message`] only on success.
    fn try_ack_state_change(
        &self,
        buf: &mut [u32; 16],
        expected: IoProcessorState,
        phase_name: &'static str,
    ) -> bool {
        let _ = phase_name;

        let Some(state) = decode_state_change(buf) else {
            warn!("boot", "non-StateChange msg during {}", phase_name);
            return false;
        };

        if state != expected {
            warn!("boot", "unexpected state during {}", phase_name);
            return false;
        }

        let reply = encode_state_change_ack(buf, state);
        self.ipc.reply(IpcChannel::AdminMessage as u8, &reply);
        true
    }

    /// Finalize boot transition to steady-state operation.
    ///
    /// # Parameters
    /// - `self`: PAL instance owning IIC/OIC/GDMA and boot state.
    ///
    /// # Returns
    /// Returns `()`.
    ///
    /// # Side Effects
    /// - Initializes IIC, OIC, and GDMA hardware drivers.
    /// - Moves boot phase to [`BootPhase::Running`].
    /// - Publishes `Run` to shared boot-status memory.
    /// - Optionally emits semihosting `SYS_READY` when feature-enabled.
    fn on_boot_complete(&self) {
        self.iic.init();
        self.oic.init();
        self.gdma.init();
        self.boot_phase.set(BootPhase::Running);
        boot_status::set(BootStatus::Run);

        #[cfg(feature = "semihosting")]
        azihsm_fw_uno_drivers_semihosting::sys_ready();

        info!("boot", "phase -> Running, status=Run");
    }

    /// Poll the NVIC once and wake any PAL driver with a pending IRQ.
    ///
    /// NVIC pending bits are **not** cleared here. For level-triggered
    /// peripherals (IIC, OIC, GDMA, IPC) the source de-asserts after the
    /// driver reads the hardware status. For edge-triggered peripherals
    /// (AES, SHA, PKA) the pending bit remains until the next
    /// `poll_once` call — the driver's `wake()` reads and clears the
    /// hardware status register, so the subsequent call finds nothing
    /// to do and returns early.
    ///
    /// # Parameters
    /// - `self`: PAL instance providing wake targets for registered IRQs.
    ///
    /// # Returns
    /// Returns `()` after scanning all relevant ISPR registers exactly once.
    ///
    /// # Side Effects
    /// Invokes zero or more driver wake functions from [`WAKE_TABLE`].
    ///
    /// This is also the entry point used by the synchronous firmware test
    /// harness, which drives test futures to completion outside the Embassy
    /// executor and must wake NVIC-gated drivers between polls. Production
    /// code uses [`HsmPal::run`] instead.
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

    /// Handle an incoming IPC message.
    ///
    /// During boot, advances the handshake state machine.
    /// In steady state, echoes the message back with the response bit set.
    ///
    /// # Parameters
    /// - `self`: PAL instance containing boot state and IPC driver.
    /// - `channel`: IPC channel that received `buf`; used for reply routing in running state.
    /// - `buf`: In-place message buffer containing one inbound IPC payload.
    ///
    /// # Returns
    /// Returns `()`.
    ///
    /// # Side Effects
    /// - May update boot phase (`WaitNormalBoot -> WaitStart -> Running`).
    /// - May initialize IIC/OIC/GDMA when transitioning to running state.
    /// - May send an ACK or response via IPC.
    async fn handle_ipc_message(&self, channel: IpcChannel, buf: &mut [u32; 16]) {
        match self.boot_phase.get() {
            BootPhase::WaitNormalBoot => {
                if !self.try_ack_state_change(buf, IoProcessorState::NormalBoot, "WaitNormalBoot") {
                    return;
                }
                self.boot_phase.set(BootPhase::WaitStart);
                info!("boot", "ACK'd NormalBoot, phase -> WaitStart");
            }
            BootPhase::WaitStart => {
                if !self.try_ack_state_change(buf, IoProcessorState::Start, "WaitStart") {
                    return;
                }
                self.on_boot_complete()
            }
            BootPhase::Running => {
                if self.try_handle_set_resource(channel, buf).await {
                    return;
                }
                if self.try_handle_pfn_enable(channel, buf).await {
                    return;
                }
                buf[0] |= 0x80;
                self.ipc.reply(channel as u8, buf);
            }
        }
    }

    /// Handle a `PfnEnableDisable` IPC in the running state.
    ///
    /// Decodes the message; if it is a `PfnEnableDisable`, drives the
    /// target partition's lifecycle (enable/disable, including enable-time
    /// key generation) and replies with an ACK. Returns `true` when the
    /// message was handled here, `false` otherwise so the caller falls back
    /// to the default echo path.
    async fn try_handle_pfn_enable(&self, channel: IpcChannel, buf: &[u32; 16]) -> bool {
        let Some(msg) = decode_pfn_enable_disable(buf) else {
            return false;
        };

        // Map the admin's PcieFunction to the partition's axi_id, rejecting
        // PFNs that map outside the partition-store range deterministically
        // here rather than relying on a generic error from a deeper layer.
        let axi_id = pfn_to_axi_id(msg.info.pfn);
        if axi_id as usize >= crate::part::NUM_PARTITIONS {
            let reply = encode_pfn_enable_disable_ack(buf, IpcMessageStatusCode::InvalidField);
            self.ipc.reply(channel as u8, &reply);
            return true;
        }
        let pid = HsmPartId::from(axi_id);
        // PF (PcieFunction::Pf == 64) is enabled before its resources are
        // assigned; a VF is enabled after. `part_enable` needs to know which.
        let is_pf = msg.info.pfn == 64;
        // Map the IPC action onto a partition-lifecycle primitive; Migrate
        // and any unknown action are not supported.
        let result = match PfnEnableDisableAction(msg.info.action) {
            PfnEnableDisableAction::Enable => self.part_enable(pid, is_pf).await,
            PfnEnableDisableAction::Disable => self.part_disable(pid).await,
            _ => Err(HsmError::UnsupportedCmd),
        };
        let status = match result {
            Ok(()) => IpcMessageStatusCode::Success,
            Err(_) => IpcMessageStatusCode::InvalidField,
        };

        let reply = encode_pfn_enable_disable_ack(buf, status);
        self.ipc.reply(channel as u8, &reply);
        true
    }

    /// Handle a `SetResource` IPC in the running state.
    ///
    /// Decodes the message; if it is a `SetResource`, applies the
    /// resource mask to the target partition (provisioning or freeing the
    /// partition identity) and replies with an ACK reporting the resulting
    /// owned-table count. Returns `true` when the message was a
    /// `SetResource` (and thus fully handled here), `false` otherwise so
    /// the caller falls back to the default echo path.
    async fn try_handle_set_resource(&self, channel: IpcChannel, buf: &[u32; 16]) -> bool {
        let Some(msg) = decode_set_resource(buf) else {
            return false;
        };

        // Map the admin's PcieFunction to the partition's axi_id, rejecting
        // out-of-range PFNs deterministically before touching the partition.
        let axi_id = pfn_to_axi_id(msg.info.pfn);
        if axi_id as usize >= crate::part::NUM_PARTITIONS {
            let reply = encode_set_resource_ack(buf, IpcMessageStatusCode::InvalidField, 0);
            self.ipc.reply(channel as u8, &reply);
            return true;
        }
        let pid = HsmPartId::from(axi_id);
        // PF (PcieFunction::Pf == 64) assigns resources after it is enabled;
        // a VF before. `part_alloc` provisions the enabled keys for the PF.
        let is_pf = msg.info.pfn == 64;
        let mask = msg.info.mask_u128();
        // The system has only `NUM_PARTITIONS` key-vault tables; any bit at
        // or above that index references a non-existent table and would
        // corrupt the ACK's owned-table count and the persisted `res_mask`.
        // Reject such a request before applying the allocation.
        let valid_tables = if crate::part::NUM_PARTITIONS >= u128::BITS as usize {
            u128::MAX
        } else {
            (1u128 << crate::part::NUM_PARTITIONS) - 1
        };
        if mask & !valid_tables != 0 {
            let reply = encode_set_resource_ack(buf, IpcMessageStatusCode::InvalidField, 0);
            self.ipc.reply(channel as u8, &reply);
            return true;
        }
        // A zero mask frees the partition; any other mask (re)allocates it.
        // The ACK's owned-table count is a pure function of the mask — an
        // IPC-reply concern, computed here rather than in the partition layer.
        let result = if mask == 0 {
            self.part_free(pid).await
        } else {
            self.part_alloc(pid, mask, is_pf).await
        };
        let (status, count) = match result {
            Ok(()) => (IpcMessageStatusCode::Success, mask.count_ones() as u8),
            Err(_) => (IpcMessageStatusCode::InvalidField, 0),
        };

        let reply = encode_set_resource_ack(buf, status, count);
        self.ipc.reply(channel as u8, &reply);
        true
    }

    /// Handle one IPC event notification.
    ///
    /// # Parameters
    /// - `self`: PAL instance providing the IPC driver.
    /// - `channel`: IPC event channel to acknowledge.
    /// - `value`: Raw event payload delivered by hardware.
    ///
    /// # Returns
    /// Returns `()`.
    ///
    /// # Side Effects
    /// Acknowledges the event in the IPC block for `channel`.
    fn handle_ipc_event(&self, channel: IpcChannel, value: u32) {
        self.ipc.ack_event(channel as u8, value);
    }
}

impl HsmPal for UnoHsmPal {
    /// Initialises the Uno platform (phase 1 only).
    ///
    /// Sets up the minimum needed for IPC communication:
    /// 1. SysTick (Embassy time driver) — needed for async timers
    /// 2. RNG calibration — settling delay for IPC
    /// 3. IPC init + enable — Admin communication channel
    ///
    /// IO hardware (IIC/OIC/GDMA) is deferred until the boot handshake
    /// completes (PAL transitions to [`BootPhase::Running`]).
    ///
    /// # Parameters
    /// - `self`: PAL instance to initialize for phase-1 boot.
    ///
    /// # Returns
    /// Returns `()`.
    ///
    /// # Side Effects
    /// - Initializes SysTick timing and RNG.
    /// - Initializes IPC and enables message/event channels.
    /// - Publishes boot status `Done` for host-side polling.
    fn init(&self) {
        systick_driver::init();
        self.rng.init();
        self.ipc.init();
        self.ipc.enable(IpcChannel::AdminMessage as u8);
        self.ipc.enable(IpcChannel::AdminEvent as u8);
        azihsm_fw_uno_drivers_part_store::PartStore::init_default();
        boot_status::set(BootStatus::Done);
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
    ///
    /// # Parameters
    /// - `self`: PAL instance used for repeated NVIC polling.
    ///
    /// # Returns
    /// This method does not return under normal execution. It is an
    /// intentionally infinite cooperative run loop.
    ///
    /// # Side Effects
    /// Continuously wakes driver tasks based on pending IRQ state.
    async fn run(&self) {
        loop {
            self.poll_once();
            embassy_futures::yield_now().await;
        }
    }

    /// No-op — the emulated SoC does not require teardown.
    ///
    /// # Parameters
    /// - `self`: PAL instance being deinitialized.
    ///
    /// # Returns
    /// Returns `()`.
    ///
    /// # Side Effects
    /// None.
    fn deinit(&self) {}
}

/// Convert the admin's PcieFunction id to the PCIe memory-location id (axi_id)
/// that IIC `recv` reports for host IO, so a provisioned/enabled partition
/// matches `io.pid()` (which reports the axi_id, mirroring cp/azihsm).
/// PF 64 -> 0x10, VFn n -> 0x20 + n.
#[inline]
fn pfn_to_axi_id(pfn: u8) -> u8 {
    const PF_PCIE_FN: u8 = 64;
    const PF_AXI_ID: u8 = 0x10;
    const VF_AXI_ID_START: u8 = 0x20;
    if pfn == PF_PCIE_FN {
        PF_AXI_ID
    } else {
        VF_AXI_ID_START.wrapping_add(pfn)
    }
}
