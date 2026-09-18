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
//! - **`handle_io`** (pool of 32, or 8 in ML-DSA builds): Owns one IO
//!   for its lifetime, delegating to the HSM core for SQE parsing, DMA,
//!   and CQE delivery.
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
#[cfg(feature = "mldsa-selftest")]
use azihsm_fw_hsm_core_tracing::error;
use azihsm_fw_hsm_core_tracing::info;
use azihsm_fw_hsm_pal_traits::*;
use azihsm_fw_uno_drivers_profile as _;
use azihsm_fw_uno_fault as _;
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
/// the IIC driver, then spawns a [`handle_io`] task from its pool
/// (32 slots, or 8 in builds carrying ML-DSA — see [`handle_io`]).
/// If no pool slots are available, the IO token is silently
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

        // Channel test: fire one empty IPC to FP1 on the first host IO.
        //
        // get_api_rev passes 3/3 with the FP data path parked, so host IO
        // reaches uno and this trigger does fire. No payload and no TCM write
        // -- this establishes only whether a CP1 -> FP1 message lands.
        #[cfg(feature = "mldsa-fp-probe")]
        {
            use core::sync::atomic::{AtomicBool, Ordering};
            static PROBED: AtomicBool = AtomicBool::new(false);
            if !PROBED.swap(true, Ordering::Relaxed) {
                if let Ok(token) = mldsa_fp_probe() {
                    spawner.spawn(token);
                }
                if let Ok(token) = mldsa_fp_probe2() {
                    spawner.spawn(token);
                }
            }
        }

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
// 32 concurrent IO futures cost 68,608 B of .bss - over 90% of the image's
// static RAM - leaving only a 113.5 KiB stack. ML-DSA needs far more than
// that: signing peaks at ~107.5 KiB of frame. Builds that run ML-DSA - the
// boot self-test, or the TBOR MlDsaSign/MlDsaVerify commands - cap
// concurrency at 8, which moves the end of .bss down and grows the stack
// region to 163.4 KiB.
//
// The cost is concurrency: `poll_io` silently drops an IO when the pool is
// full, so this lowers the depth at which that starts by 4x. An ML-DSA
// command also occupies its slot for milliseconds without yielding, so a
// build carrying PQC both has fewer slots and holds them longer.
//
// Shrinking the pool further was measured and does not unlock anything:
//
//     pool  stack      ML-DSA-65 keygen (235.5 KiB chain)
//        8  212.9 KiB  22.6 KiB short
//        2  225.4 KiB  10.1 KiB short
//        1  227.5 KiB   8.0 KiB short
//
// The whole task arena is only ~17 KiB, so there is no configuration of it
// that fits keygen, and each step costs concurrency on a path that silently
// drops IOs when full. 8 stands.
#[cfg_attr(
    any(
        feature = "mldsa-selftest",
        feature = "tbor-ml-dsa-44",
        feature = "tbor-ml-dsa-65"
    ),
    embassy_executor::task(pool_size = 8)
)]
#[cfg_attr(
    not(any(
        feature = "mldsa-selftest",
        feature = "tbor-ml-dsa-44",
        feature = "tbor-ml-dsa-65"
    )),
    embassy_executor::task(pool_size = 32)
)]
async fn handle_io(io: UnoHsmIo) {
    HSM.get().await.handle_io(io).await;
}

/// Dedicated core-liveliness heartbeat task.
///
/// Refreshes the SP-polled `CORE_RUN_STATUS` slot on its own independent
/// 250 ms timer, decoupled from IPC traffic. As a standalone
/// task, this timer is never raced by IPC and fires as long as the
/// cooperative executor makes forward progress — which is exactly the
/// liveness condition the SP is meant to observe.
///
/// # Returns
/// Never returns (`!`).
#[embassy_executor::task]
async fn heartbeat() -> ! {
    let hsm = HSM.get().await;

    // Run once, from a task rather than from `main`: the trace backend only
    // produces console output after the platform has finished bringing up
    // IO, so an earlier call is silent. Waiting for BootPhase::Running keeps
    // this long synchronous computation out of the boot handshake, which the
    // cooperative single-threaded executor would otherwise stall.
    #[cfg(feature = "mldsa-selftest")]
    {
        error!("app", "mldsa: waiting for BootPhase::Running");
        while hsm.pal().boot_phase() != BootPhase::Running {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(50)).await;
        }
        error!("app", "mldsa: boot running, starting self-test");
        // Report stack headroom first: the host-measured peak for import+sign is
        // ~91 KiB, so if far less than that is left below the current frame the
        // run cannot complete and will fault rather than return.
        let probe = 0u8;
        let sp = core::ptr::addr_of!(probe) as usize;
        // `.bss` ends just under 0x2001_3000 in this image; the stack grows down
        // from the top of the 187 KiB DTCM region.
        let headroom = sp.saturating_sub(0x2001_3000);
        if headroom >= 96 * 1024 {
            error!("app", "mldsa: stack headroom >= 96 KiB");
        } else if headroom >= 64 * 1024 {
            error!("app", "mldsa: stack headroom 64-96 KiB");
        } else if headroom >= 32 * 1024 {
            error!("app", "mldsa: stack headroom 32-64 KiB");
        } else {
            error!("app", "mldsa: stack headroom < 32 KiB");
        }

        mldsa_selftest();
        error!("app", "mldsa: self-test returned");
    }
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_millis(250)).await;
        hsm.pal().update_liveliness();
    }
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

/// Runs the ML-DSA-65 known-answer self-test on CP1 and reports the result.
///
/// Phase 1 of the PQC proof-of-concept: proves ML-DSA-65 import, deterministic
/// signing and verification execute correctly on this core, checked against a
/// pinned FIPS 204 vector rather than against itself. Deliberately independent
/// of the DDI surface, which is Phase 2.
///
/// The outcome is published in [`MLDSA_SELFTEST_RESULT`] so it is observable
/// from a debugger on builds without a trace backend.
#[cfg(feature = "mldsa-selftest")]
#[inline(never)]
fn mldsa_selftest() {
    use azihsm_fw_core_crypto_ml_dsa::SelfTestResult;

    error!("app", "mldsa: import+sign+verify begin");
    let mut mark = |stage: u32| match stage {
        azihsm_fw_core_crypto_ml_dsa::stage::IMPORT_DONE => {
            error!("app", "mldsa: stage import done")
        }
        azihsm_fw_core_crypto_ml_dsa::stage::SIGN_DONE => error!("app", "mldsa: stage sign done"),
        azihsm_fw_core_crypto_ml_dsa::stage::KAT_MATCH => error!("app", "mldsa: stage kat match"),
        _ => error!("app", "mldsa: stage verify done"),
    };
    let result = azihsm_fw_core_crypto_ml_dsa::selftest_staged(&mut mark);
    error!("app", "mldsa: import+sign+verify end");

    // SAFETY: single-threaded boot path, written once before any task runs.
    #[allow(unsafe_code)]
    unsafe {
        MLDSA_SELFTEST_RESULT = result as u32 + 1;
    }

    // Reported through the platform tracing facade rather than by poking the
    // UART directly: the facade owns backend setup, which is what actually
    // makes output appear on the console. Emitted at error level so it
    // survives a build that compiles in only that level, and as one literal
    // per outcome so the two-argument macro arm is selected and no runtime
    // formatting is pulled in.
    match result {
        SelfTestResult::Pass => error!("app", "ML-DSA-65 self-test: PASS"),
        SelfTestResult::ImportFailed => error!("app", "ML-DSA-65 self-test: FAIL import"),
        SelfTestResult::SignFailed => error!("app", "ML-DSA-65 self-test: FAIL sign"),
        SelfTestResult::SignatureMismatch => {
            error!("app", "ML-DSA-65 self-test: FAIL kat-mismatch")
        }
        SelfTestResult::VerifyFailed => error!("app", "ML-DSA-65 self-test: FAIL verify"),
    }
}

/// Result of [`mldsa_selftest`]: 0 = not run, 1 = pass, >1 = the failing stage.
#[cfg(feature = "mldsa-selftest")]
#[unsafe(no_mangle)]
pub static mut MLDSA_SELFTEST_RESULT: u32 = 0;

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    info!("app", "Azure Integrate HSM firmware starting up...");
    let _ = HSM.init(Hsm::new(UnoHsmPal::default()));
    let hsm = HSM.get().await;
    hsm.pal().init();

    // Diagnostic markers are emitted at error level so they survive a build
    // that compiles in only that level.
    #[cfg(feature = "mldsa-selftest")]
    error!("app", "mldsa: main reached, pal init done");

    if let Ok(token) = poll_ipc(spawner) {
        spawner.spawn(token);
    } else {
        return;
    }

    if let Ok(token) = heartbeat() {
        spawner.spawn(token);
    } else {
        return;
    }


    hsm.pal().run().await;
    hsm.pal().deinit();
}

/// Issues one ML-DSA keygen request to FP1 and reports what came back.
///
/// Keygen is the right first probe: the request is a 32-byte seed, the
/// smallest payload of the three, and the response is self-checking because
/// the key lengths are fixed per parameter set (ML-DSA-87: verifying key
/// 2,592 + signing key 4,896 = 7,488 bytes plus an 8-byte header).
///
/// The descriptor travels in the IPC slot; the payload lives at a fixed
/// address in FP1's DTCM, which the CP addresses at 0xA3200000.
#[cfg(feature = "mldsa-fp-probe")]
#[embassy_executor::task]
async fn mldsa_fp_probe2() {
    use azihsm_fw_uno_pal::IpcChannel;

    // Independent of mldsa_fp_probe. Every request after the first has failed
    // to appear, whether or not a read preceded it, which suggests the first
    // send's future never resolves and the task simply never proceeds. This
    // task shares no state with it: if this request arrives, the first send
    // is not completing and sending as such is fine.
    let hsm = HSM.get().await;
    embassy_time::Timer::after(embassy_time::Duration::from_millis(30_000)).await;

    let msg: [u32; 3] = [0x50 | (9 << 8), 5, 0];
    let mut resp = [0u32; 16];
    hsm.pal()
        .ipc
        .send(IpcChannel::FpMessage as u8, &msg, &mut resp)
        .await;
}

#[cfg(feature = "mldsa-fp-probe")]
#[embassy_executor::task]
async fn mldsa_fp_probe() {
    use azihsm_fw_uno_pal::IpcChannel;
    use core::ptr::read_volatile;
    use core::ptr::write_volatile;

    const PAYLOAD: u32 = 0xA320_0000;
    const OP_KEYGEN: u32 = 0x50;
    const OP_SIGN: u32 = 0x51;
    const PARAM_87: u32 = 5;
    const HDR: u32 = 8; // both payload structs put data[] at offset 8
    const SEED_LEN: u32 = 32;
    const MSG_LEN: u32 = 32;

    let hsm = HSM.get().await;
    let base = PAYLOAD as *mut u8;

    let rd = |off: u32| -> u8 { unsafe { read_volatile(base.add(off as usize)) } };
    let wr = |off: u32, v: u8| unsafe { write_volatile(base.add(off as usize), v) };
    let rd32 = |off: u32| -> u32 {
        (rd(off) as u32)
            | ((rd(off + 1) as u32) << 8)
            | ((rd(off + 2) as u32) << 16)
            | ((rd(off + 3) as u32) << 24)
    };
    let wr32 = |off: u32, v: u32| {
        wr(off, v as u8);
        wr(off + 1, (v >> 8) as u8);
        wr(off + 2, (v >> 16) as u8);
        wr(off + 3, (v >> 24) as u8);
    };

    // ---- 1. keygen: seed in, public and private key out ----
    wr32(0, 0);
    wr32(4, 0);
    for i in 0..SEED_LEN {
        wr(HDR + i, i as u8);
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    let msg: [u32; 3] = [OP_KEYGEN | (1 << 8), PARAM_87, HDR + SEED_LEN];
    let mut resp = [0u32; 16];
    hsm.pal()
        .ipc
        .send(IpcChannel::FpMessage as u8, &msg, &mut resp)
        .await;

    // ---- 2. read the keygen result back out of FP1 TCM ----
    //
    // The header tells us how much of each key FP1 wrote. If CP1 cannot read
    // FP1 TCM these come back as something other than 2,592 / 4,896 and the
    // signature below will fail, which is the answer either way.
    let vk_len = rd32(0);
    let sk_len = rd32(4);

    // ---- 3. reshape the buffer in place into a sign request ----
    //
    // Keygen left  [vk_len][sk_len][vk .. ][sk .. ]  and sign wants
    //              [sk_len][msg_len][sk .. ][msg .. ]. The signing key moves
    // down over the verifying key; copying ascending is safe because the
    // destination is below the source.
    //
    // Guard the copy: a bad read would otherwise scribble past the 10 KB
    // buffer and corrupt FP1's wolfCrypt pool, destroying the evidence. The
    // lengths are fixed for ML-DSA-87, so anything else is a failed read and
    // the sign request below still goes out carrying those bad lengths, which
    // FP1 logs.
    let sane = vk_len == 2592 && sk_len == 4896;
    let sk_src = HDR + vk_len;
    for i in 0..(if sane { sk_len } else { 0 }) {
        wr(HDR + i, rd(sk_src + i));
    }
    wr32(0, sk_len);
    wr32(4, MSG_LEN);
    if sane {
        for i in 0..MSG_LEN {
            wr(HDR + sk_len + i, 0xA5u8.wrapping_add(i as u8));
        }
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    // ---- 4. sign ----
    //
    // ML-DSA-87 produces a 4,627-byte signature, so a successful response
    // carries respLen 4627 and nothing else does.
    let payload_len = if sane { HDR + sk_len + MSG_LEN } else { HDR };
    let msg2: [u32; 3] = [OP_SIGN | (2 << 8), PARAM_87, payload_len];
    let mut resp2 = [0u32; 16];
    hsm.pal()
        .ipc
        .send(IpcChannel::FpMessage as u8, &msg2, &mut resp2)
        .await;

    let _ = (resp, resp2, vk_len, sk_len);
}
