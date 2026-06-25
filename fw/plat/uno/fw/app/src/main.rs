// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno firmware application entry point.
//!
//! Wires the HSM core to the Uno PAL via Embassy tasks, following
//! the same task architecture as the std PAL platform crate.
//!
//! # Task architecture
//!
//! ```text
//!  main ──► init PAL ──► spawn poll_io ──► run (NVIC polling loop)
//!                            │
//!                        poll_io ──► iic.recv() ──► spawn handle_io
//!                                                       │
//!                                                   HSM core pipeline:
//!                                                   SQE parse → in-DMA
//!                                                   → DDI dispatch
//!                                                   → out-DMA → CQE
//!                                                   → complete_io
//! ```
//!
//! - **`main`**: Initialises the PAL (timer, IIC/OIC/GDMA channels),
//!   spawns the IO receive loop, then enters the NVIC polling loop.
//! - **`poll_io`** (single instance): Awaits IOs from the IIC driver
//!   and spawns a `handle_io` task for each one.
//! - **`handle_io`** (pool of 32): Owns one IO for its lifetime,
//!   delegating to the HSM core for SQE parsing, DMA, and CQE delivery.
//!
//! # Interrupt handling
//!
//! Peripheral interrupts (IIC, OIC, GDMA) are enabled at the source
//! (`irq_enable` register) so the hardware asserts the NVIC pending bit.
//! No ISR handlers are installed for these — the PAL's `run()` loop
//! polls `Nvic::is_pending()` and wakes the appropriate driver. The
//! SysTick exception is handled internally by the systick driver crate.

#![no_std]
#![no_main]

mod trampoline;

use azihsm_fw_hsm_core::Hsm;
use azihsm_fw_hsm_core_tracing::error;
use azihsm_fw_hsm_core_tracing::info;
use azihsm_fw_hsm_pal_traits::*;
use azihsm_fw_uno_drivers_profile as _;
use azihsm_fw_uno_pac as _;
use azihsm_fw_uno_pal::BootPhase;
use azihsm_fw_uno_pal::UnoHsmIo;
use azihsm_fw_uno_pal::UnoHsmPal;
use embassy_executor::Spawner;
use embassy_sync::once_lock::OnceLock;

// Placeholder so the linker emits a non-empty `.data` section.
//
// The 1SP bootloader that loads this image requires every loadable
// section to be at least 16 bytes long and a multiple of 16 bytes
// (it copies sections in 16-byte units during image staging). Until
// the firmware accumulates real mutable static state in `.data`,
// the section would otherwise be 0 bytes and the bootloader would
// reject the image. Once any genuine `.data` content lands and the
// section is naturally >= 16 bytes (and a multiple of 16 bytes in
// size), this dummy can be removed.
#[used]
#[unsafe(link_section = ".data")]
static mut DEFAULT_DATA: [u8; 16] = [0x1; 16];

/// Global HSM singleton, shared by all Embassy tasks.
///
/// Uses [`OnceLock`] for one-time initialisation in `main`. Subsequent
/// accesses via `HSM.get().await` are zero-cost after the first init.
static HSM: OnceLock<Hsm<UnoHsmPal>> = OnceLock::new();

/// IO receive loop — runs forever as a single Embassy task.
///
/// Awaits [`HsmIoController::poll_io`] for the next inbound IO from
/// the IIC driver, then spawns a [`handle_io`] task from the 32-slot
/// pool. If no pool slots are available, the IO token is silently
/// dropped and the loop retries on the next iteration.
///
/// # Parameters
/// - `spawner`: Embassy task spawner used to enqueue [`handle_io`] jobs.
///
/// # Returns
/// Never returns (`!`). This is a permanent receive-and-dispatch loop.
///
/// # Side Effects
/// - Continuously drains inbound IO work from PAL.
/// - Schedules per-IO tasks onto the executor when task slots are available.
#[embassy_executor::task]
async fn poll_io(spawner: Spawner) -> ! {
    loop {
        let Ok(io) = HSM.get().await.pal().poll_io().await else {
            continue;
        };

        let Ok(token) = handle_io(io) else {
            continue;
        };

        spawner.spawn(token);
    }
}

/// Processes a single IO to completion.
///
/// Takes ownership of the [`UnoHsmIo`], keeping the underlying
/// IO_SQ slot reserved until the completion DMA finishes. Delegates
/// SQE parsing, inbound/outbound DMA, DDI dispatch, and CQE
/// population to [`Hsm::handle_io`].
///
/// # Parameters
/// - `io`: Owned IO token for one request/response transaction.
///
/// # Returns
/// Returns `()` after this IO has been fully processed and completed.
///
/// # Side Effects
/// - Advances the HSM request pipeline for one IO.
/// - Triggers DMA activity and CQE completion for that IO.
#[embassy_executor::task(pool_size = 32)]
async fn handle_io(io: UnoHsmIo) {
    HSM.get().await.handle_io(io).await;
}

/// IPC message/event receive loop — runs forever as a single
/// Embassy task. PAL handles boot handshake internally;
/// app spawns [`poll_io`] once boot completes.
///
/// # Parameters
/// - `spawner`: Embassy task spawner used to start [`poll_io`] after boot.
///
/// # Returns
/// Never returns (`!`). This is a permanent IPC servicing loop.
///
/// # Side Effects
/// - Drains IPC traffic by repeatedly calling [`UnoHsmPal::poll_ipc`].
/// - Starts IO ingestion exactly once when PAL enters [`BootPhase::Running`].
#[embassy_executor::task]
async fn poll_ipc(spawner: Spawner) -> ! {
    let hsm = HSM.get().await;
    let mut booted = false;

    loop {
        hsm.pal().poll_ipc().await;
        if !booted && hsm.pal().boot_phase() == BootPhase::Running {
            booted = true;
            info!("app", "boot complete, spawning poll_io");
            if let Ok(token) = poll_io(spawner) {
                spawner.spawn(token);
            }
        }
    }
}

/// Firmware async entry point.
///
/// 1. Initialises the HSM singleton with a default [`UnoHsmPal`].
/// 2. Calls [`HsmPal::init`] — sets up SysTick, RNG, IPC, signals Done.
/// 3. Spawns [`poll_ipc`] which drives boot handshake + steady-state IPC.
/// 4. Enters [`HsmPal::run`] — the NVIC polling loop that wakes
///    drivers when peripheral interrupts are pending.
///
/// The NVIC loop runs from the start so `ipc.wake()` fires naturally
/// when Admin sends messages — no poll_once hack needed.
///
/// # Parameters
/// - `spawner`: Embassy task spawner used to start long-lived background tasks.
///
/// # Returns
/// Returns `()` if initialization fails to spawn IPC handling and exits early;
/// otherwise, this function does not normally return while firmware is running.
///
/// # Side Effects
/// - Initializes global singleton state.
/// - Initializes PAL platform services.
/// - Spawns IPC loop task and enters main NVIC polling loop.
#[embassy_executor::main]
async fn main(spawner: Spawner) {
    info!("app", "Azure Integrate HSM firmware starting up...");
    let _ = HSM.init(Hsm::new(UnoHsmPal::default()));
    let hsm = HSM.get().await;
    hsm.pal().init();

    if let Ok(token) = poll_ipc(spawner) {
        spawner.spawn(token);
    } else {
        return;
    }

    hsm.pal().run().await;
    hsm.pal().deinit();
}

/// Panic handler — emits an error trace and halts.
///
/// # Parameters
/// - `info`: Panic metadata (location and message) provided by core.
///
/// # Returns
/// Never returns (`!`).
///
/// # Side Effects
/// - Emits an error-level trace describing the panic to the configured
///   trace backend for diagnostic visibility.
/// - With the `semihosting` feature enabled (emulator), terminates via
///   `SYS_EXIT(-1)` so the host stops on a firmware panic. Otherwise
///   (e.g. silicon), halts forward progress by looping forever.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // Referenced unconditionally: `error!` compiles out without a trace
    // backend (the default firmware build), which would otherwise leave
    // `info` unused.
    let _ = &info;
    error!("panic", HsmError::InternalError, "{}", info);

    #[cfg(feature = "semihosting")]
    azihsm_fw_uno_drivers_semihosting::sys_exit(-1i32 as u32);

    loop {}
}
