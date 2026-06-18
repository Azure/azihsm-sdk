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

mod boot_handshake;

use azihsm_fw_hsm_core::Hsm;
use azihsm_fw_hsm_pal_traits::*;
use azihsm_fw_uno_drivers_profile as _;
use azihsm_fw_uno_pal::IoProcessorBootState;
use azihsm_fw_uno_pal::UnoHsmIo;
use azihsm_fw_uno_pal::UnoHsmPal;
use cortex_m as _;
use embassy_executor::Spawner;
use embassy_sync::once_lock::OnceLock;

use crate::boot_handshake::set_boot_status;

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
#[embassy_executor::task(pool_size = 32)]
async fn handle_io(io: UnoHsmIo) {
    HSM.get().await.handle_io(io).await;
}

/// IPC message/event receive loop — runs forever as a single
/// Embassy task. Delegates to [`UnoHsmPal::run_ipc`], which
/// processes inbound boot-handshake messages and dispatches IO
/// state-change events. Mirrors azihsm's `poll_ipc`.
#[embassy_executor::task]
async fn poll_ipc() -> ! {
    loop {
        HSM.get().await.pal().run_ipc().await;
    }
}

/// Firmware async entry point.
///
/// 1. Initialises the HSM singleton with a default [`UnoHsmPal`].
/// 2. Calls [`HsmPal::pre_init`] — minimum bring-up (IPC) so the boot
///    handshake can run if/when an Admin peer is implemented.
/// 3. Signals `BOOT_STATUS = Done` to GSRAM for silicon-faithful boot.
/// 4. Calls [`HsmPal::init`] — sets up timer, enables IIC/OIC/GDMA
///    channels, and signals `SYS_READY` to the host.
/// 5. Signals `BOOT_STATUS = Run` to GSRAM.
/// 6. Spawns the [`poll_io`] and [`poll_ipc`] receive loops.
/// 7. Enters [`HsmPal::run`] — the NVIC polling loop that wakes
///    drivers when peripheral interrupts are pending.
#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let _ = HSM.init(Hsm::new(UnoHsmPal::default()));
    let hsm = HSM.get().await;
    hsm.pal().pre_init();
    set_boot_status(IoProcessorBootState::Done);
    hsm.pal().init();
    set_boot_status(IoProcessorBootState::Run);

    if let Ok(token) = poll_io(spawner) {
        spawner.spawn(token);
    } else {
        return;
    }

    if let Ok(token) = poll_ipc() {
        spawner.spawn(token);
    } else {
        return;
    }

    hsm.pal().run().await;
    hsm.pal().deinit();
}

/// Panic handler — exits through semihosting with code 1.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    azihsm_fw_uno_drivers_semihosting::sys_exit(1);
    loop {}
}
