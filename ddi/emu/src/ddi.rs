// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI Implementation - AZIHSM Emulator - DDI Module.

use std::sync::Arc;
use std::sync::LazyLock;

use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_interface::DevInfo;
use azihsm_fw_hsm_std::StdHsm;
use tokio::runtime::Handle;
use tokio::runtime::Runtime;

use crate::dev::DdiEmuDev;
use crate::dev::EMU_DEVICE_PATH;

/// Process-global emulator context.
///
/// Owns the tokio runtime that backs the firmware platform tasks, and the
/// single [`StdHsm`] instance that runs the firmware. The `StdHsm` core
/// (`Hsm<StdHsmPal>`) lives in a global `OnceLock` inside
/// `azihsm_fw_hsm_std`, so only one instance can ever exist per process —
/// we hold it in a [`LazyLock`] to ensure exactly that.
struct EmuCtx {
    /// Multi-thread tokio runtime shared with [`StdHsm`].
    ///
    /// The runtime is built explicitly so that synchronous trait methods
    /// (`exec_op`) can use `Handle::block_on` to drive `StdHsm::io`. The
    /// runtime is also passed to [`StdHsm::with_tokio`] so the firmware's
    /// internal worker pool runs on the same threads.
    rt: Runtime,

    /// The single in-process firmware instance.
    hsm: Arc<StdHsm>,
}

impl EmuCtx {
    fn new() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .thread_name("azihsm-emu")
            .build()
            .expect("azihsm_ddi_emu: failed to build tokio runtime");

        let hsm = Arc::new(StdHsm::with_tokio(rt.handle().clone()));

        Self { rt, hsm }
    }
}

/// Global emulator context, lazily initialised on first access.
///
/// The runtime and HSM live for the rest of the process. Dropping the
/// `EmuCtx` would tear down the embassy thread inside `StdHsm`, but
/// because [`StdHsm`] holds the only handle to the global `OnceLock<Hsm>`
/// it would still be unsafe for another caller to construct a second
/// `StdHsm` afterwards. Keeping it alive via [`LazyLock`] sidesteps that.
static CTX: LazyLock<EmuCtx> = LazyLock::new(EmuCtx::new);

/// DDI Implementation - AZIHSM Emulator interface.
///
/// Implements [`Ddi`] for the in-process firmware emulator. Constructing
/// a `DdiEmu` is a no-op; the underlying [`StdHsm`] is initialised on
/// the first call to [`open_dev`](Ddi::open_dev).
#[derive(Default, Debug)]
pub struct DdiEmu {}

impl Ddi for DdiEmu {
    type Dev = DdiEmuDev;

    /// Returns a single virtual device entry for the emulator.
    ///
    /// The returned [`DevInfo`] always uses [`EMU_DEVICE_PATH`].
    fn dev_info_list(&self) -> Vec<DevInfo> {
        let devs = vec![DevInfo {
            path: EMU_DEVICE_PATH.to_owned(),
            driver_ver: env!("CARGO_PKG_VERSION").to_owned(),
            firmware_ver: env!("CARGO_PKG_VERSION").to_owned(),
            hardware_ver: env!("CARGO_PKG_VERSION").to_owned(),
            pci_info: String::from("0.0.0"),
            entropy_data: vec![0u8; 32],
        }];

        tracing::debug!(size = devs.len(), "Got DdiEmu device info list");
        devs
    }

    /// Open the emulator device.
    ///
    /// `path` must equal [`EMU_DEVICE_PATH`]; any other value yields
    /// [`DdiError::DeviceNotFound`](azihsm_ddi_interface::DdiError::DeviceNotFound).
    fn open_dev(&self, path: &str) -> DdiResult<Self::Dev> {
        DdiEmuDev::open(CTX.hsm.clone(), runtime_handle(), path)
    }
}

/// Borrow the runtime handle from the global emulator context.
fn runtime_handle() -> Handle {
    CTX.rt.handle().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_info_list_returns_emu_device() {
        let ddi = DdiEmu::default();
        let devs = ddi.dev_info_list();
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].path, EMU_DEVICE_PATH);
    }

    #[test]
    fn open_unknown_path_fails() {
        let ddi = DdiEmu::default();
        let res = ddi.open_dev("/dev/nonexistent");
        assert!(res.is_err(), "opening unknown path must fail");
    }
}
