// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end tests for `StdHsm`'s shutdown/drain lifecycle.
//!
//! These build a real `StdHsm` (each in its own process, since only one
//! `StdHsm` may ever be built per process — see the `HSM` singleton doc
//! comment in `lib.rs`) and assert that shutdown actually completes in
//! bounded time. This is a regression test for the bug this crate's
//! shutdown protocol fixes: the Embassy executor thread previously never
//! stopped, hanging any process (e.g. a hypervisor) that waited for it
//! to exit.

use std::sync::Arc;
use std::time::Duration;

use azihsm_fw_hsm_std::StdHsm;

const IO_PID: u8 = 1;

/// Build a minimal SQE with cmd_id and no DMA.
fn sqe(cmd_id: u16) -> [u32; 16] {
    let mut data = [0u32; 16];
    data[0] = (cmd_id as u32) << 16;
    data
}

/// Drives a handful of concurrent IOs through `hsm` so shutdown has
/// real in-flight work to drain, not just idle `poll_io`/`ipc_task`
/// loops.
async fn run_some_ios(hsm: &Arc<StdHsm>) {
    let _ = hsm.part_alloc(IO_PID, 1u128 << IO_PID).await;
    let _ = hsm.part_enable(IO_PID).await;

    let mut handles = Vec::new();
    for i in 0..16u16 {
        let hsm = Arc::clone(hsm);
        handles.push(tokio::spawn(async move {
            hsm.io(sqe(i), IO_PID, 0, 0).await.expect("io")
        }));
    }
    for h in handles {
        h.await.expect("io task panicked");
    }
}

/// `shutdown_async` must complete once in-flight IO drains, instead of
/// hanging forever waiting for the Embassy thread to stop.
///
/// Uses an HSM-owned tokio runtime (not an external one supplied via
/// `with_tokio`), so cancelling this future via `timeout` — if the
/// assertion below ever fires — stays within `shutdown_async`'s
/// documented safe-cancellation contract.
#[tokio::test]
async fn shutdown_async_completes_after_draining_in_flight_ios() {
    let hsm = Arc::new(StdHsm::new());
    run_some_ios(&hsm).await;

    let hsm = Arc::try_unwrap(hsm).unwrap_or_else(|_| panic!("StdHsm still shared"));
    tokio::time::timeout(Duration::from_secs(10), hsm.shutdown_async())
        .await
        .expect("shutdown_async did not complete — Embassy thread hung");
}

/// The blocking `shutdown` must also complete once in-flight IO
/// drains, when called from a plain OS thread outside the tokio
/// runtime backing the HSM (its documented, non-deadlocking usage).
#[test]
fn shutdown_completes_after_draining_in_flight_ios() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let hsm = Arc::new(StdHsm::with_tokio(rt.handle().clone()));
    rt.block_on(run_some_ios(&hsm));

    let hsm = Arc::try_unwrap(hsm).unwrap_or_else(|_| panic!("StdHsm still shared"));

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        hsm.shutdown();
        let _ = done_tx.send(());
    });
    done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("shutdown did not complete — Embassy thread hung");

    drop(rt);
}
