// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Integrated HSM emulator implementation.
//!
//! This module provides [`AziHsmEmulator`], a software emulator for the Azure Integrated HSM.
//! The emulator runs async tasks on dedicated executor threads to simulate HSM behavior
//! in a standard environment without requiring actual HSM hardware.

use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;
use std::u32;

use azihsm_fw_mgmt_app::*;
use parking_lot::RwLock;
use strum::EnumCount;
use strum_macros::EnumCount;

use super::*;

/// Errors that can occur during emulator operations.
pub enum EmuError {
    /// Generic error.
    Internal,
    /// Controller Not Found.
    CtrlNotFound,
    /// Controller Timeout.
    CtrlTimeout,
    /// Controller Failure.
    CtrlFailure,
}

/// Identifies the dedicated executor threads used by the emulator.
///
/// Each variant corresponds to a specific subsystem that runs on its own thread.
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumCount)]
enum ThreadName {
    /// Management subsystem thread.
    Mgmt,
}

impl From<ThreadName> for usize {
    /// Converts a thread name to its corresponding executor slot index.
    fn from(name: ThreadName) -> Self {
        name as usize
    }
}

/// Global singleton instance of the Azure HSM emulator.
///
/// This is lazily initialized on first access and provides a shared emulator
/// instance that can be started and stopped as needed.
pub static AZIHSM_EMULATOR: LazyLock<AziHsmEmulator> = LazyLock::new(|| AziHsmEmulator::default());

/// Azure Integrated HSM software emulator.
///
/// Provides a thread-safe emulator that simulates HSM functionality using
/// Embassy async executors running on dedicated threads. The emulator can
/// be started and stopped, and is safe to clone (all clones share the same
/// underlying state).
#[derive(Clone)]
pub struct AziHsmEmulator {
    /// Thread-safe reference to the internal emulator state.
    inner: Arc<RwLock<Inner>>,
}

impl Default for AziHsmEmulator {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
        }
    }
}

impl AziHsmEmulator {
    /// Starts the emulator.
    ///
    /// Initializes and spawns all executor threads if not already running.
    /// If the emulator is already started, this is a no-op.
    pub fn start(&self) {
        self.with_write(|inner| {
            inner.start();
        });
    }

    /// Stops the emulator.
    ///
    /// Signals all executor threads to terminate and waits for them to complete.
    /// After stopping, the emulator can be started again with [`start`](Self::start).
    pub fn stop(&self) {
        self.with_write(|inner| {
            inner.stop();
        });
    }

    /// Triggers a PERST up (assertion) event on the emulated PCIe interface.
    ///
    /// This simulates a platform-level PCIe reset signal being asserted.
    pub fn do_perst_up(&self) {
        self.with_read(|inner| {
            inner.do_perst_up();
        });
    }

    /// Triggers a PERST down (deassertion) event on the emulated PCIe interface.
    ///
    /// This simulates a platform-level PCIe reset signal being deasserted.
    pub fn do_perst_down(&self) {
        self.with_read(|inner| {
            inner.do_perst_down();
        });
    }

    /// Triggers a Function Level Reset (FLR) event on the emulated PCIe interface.
    ///
    /// This simulates a PCIe function-level reset being initiated.
    pub fn do_flr(&self) {
        self.with_read(|inner| {
            inner.do_flr();
        });
    }

    /// Triggers a Virtual Function Level Reset (VFLR) event on the emulated PCIe interface.
    ///
    /// This simulates a PCIe virtual function reset being initiated for the specified controller.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the virtual function's controller to reset.
    pub fn do_vflr(&self, ctrl_id: u16) {
        self.with_read(|inner| {
            inner.do_vflr(ctrl_id);
        });
    }

    /// Reads the controller capability register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn ctrl_read_cap_reg(&self, ctrl_id: u16) -> Result<CtrlCapReg, EmuError> {
        self.with_read(|inner| inner.ctrl_read_cap_reg(ctrl_id))
    }

    /// Reads the controller version register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    pub fn ctrl_read_vs_reg(&self, ctrl_id: u16) -> Result<CtrlVsReg, EmuError> {
        self.with_read(|inner| inner.ctrl_read_vs_reg(ctrl_id))
    }

    /// Writes to the controller admin queue attribute register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The admin queue attribute register value to write.
    pub fn ctrl_write_aqa_reg(&self, ctrl_id: u16, reg: CtrlAqaReg) -> Result<(), EmuError> {
        self.with_read(|inner| inner.ctrl_write_aqa_reg(ctrl_id, reg))
    }

    /// Writes to the admin submission queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The admin submission queue base address register value to write.
    pub fn ctrl_write_asq_reg(&self, ctrl_id: u16, reg: CtrlAsqReg) -> Result<(), EmuError> {
        self.with_read(|inner| inner.ctrl_write_asq_reg(ctrl_id, reg))
    }

    /// Writes to the admin completion queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The admin completion queue base address register value to write.
    pub fn ctrl_write_acq_reg(&self, ctrl_id: u16, reg: CtrlAcqReg) -> Result<(), EmuError> {
        self.with_read(|inner| inner.ctrl_write_acq_reg(ctrl_id, reg))
    }

    /// Enables the specified controller.
    ///
    /// Configures the controller with default settings and sets the enable bit.
    /// Blocks until the controller reports ready.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to enable.
    pub fn ctrl_enable(&self, ctrl_id: u16) -> Result<(), EmuError> {
        self.with_read(|inner| inner.ctrl_enable(ctrl_id))
    }

    /// Disables the specified controller.
    ///
    /// Clears the enable bit in the controller configuration register and
    /// blocks until the controller reports not ready.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to disable.
    pub fn ctrl_disable(&self, ctrl_id: u16) -> Result<(), EmuError> {
        self.with_read(|inner| inner.ctrl_disable(ctrl_id))
    }

    /// Executes a closure with read access to the inner state.
    ///
    /// Acquires a read lock on the internal state, allowing concurrent readers.
    fn with_read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Inner) -> R,
    {
        let inner = self.inner.read();
        f(&inner)
    }

    /// Executes a closure with write access to the inner state.
    ///
    /// Acquires an exclusive write lock on the internal state.
    fn with_write<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Inner) -> R,
    {
        let mut inner = self.inner.write();
        f(&mut inner)
    }
}

/// Internal state of the emulator.
///
/// Manages the lifecycle of executor threads through the [`Executor`].
struct Inner {
    /// The executor manager, present only when the emulator is running.
    executor: Option<Executor>,
}

impl Default for Inner {
    fn default() -> Self {
        Self { executor: None }
    }
}

impl Inner {
    /// Starts the emulator by creating executor threads.
    ///
    /// Creates an [`Executor`] and spawns the management subsystem task.
    /// Does nothing if already started.
    fn start(&mut self) {
        if self.executor.is_none() {
            let mut executor = Executor::new(ThreadName::COUNT);
            executor.spawn(ThreadName::Mgmt.into(), azihsm_fw_mgmt_app::run);
            // executor.spawn(ThreadName::Hsm.into(), azihsm_fw_plat_std_hsm::run);
            self.executor = Some(executor);
        }
    }

    /// Stops the emulator by dropping the executor.
    ///
    /// Taking the executor triggers its [`Drop`] implementation,
    /// which signals all threads to stop and joins them.
    fn stop(&mut self) {
        self.executor.take();
    }

    /// Triggers a PERST up event via the management PAL.
    fn do_perst_up(&self) {
        let pal = azihsm_fw_mgmt_app::pal();
        pal.do_perst_up();
    }

    /// Triggers a PERST down event via the management PAL.
    fn do_perst_down(&self) {
        let pal = azihsm_fw_mgmt_app::pal();
        pal.do_perst_down();
    }

    /// Triggers a Function Level Reset event via the management PAL.
    fn do_flr(&self) {
        let pal = azihsm_fw_mgmt_app::pal();
        pal.do_flr();
    }

    /// Triggers a Virtual Function Level Reset event via the management PAL.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the virtual function's controller to reset.
    fn do_vflr(&self, ctrl_id: u16) {
        let pal = azihsm_fw_mgmt_app::pal();
        pal.do_vflr(ctrl_id);
    }

    /// Reads the controller capability register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn ctrl_read_cap_reg(&self, ctrl_id: u16) -> Result<CtrlCapReg, EmuError> {
        let pal = azihsm_fw_mgmt_app::pal();
        Ok(pal.ctrl_read_cap_reg(ctrl_id)?)
    }

    /// Reads the controller version register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to read from.
    fn ctrl_read_vs_reg(&self, ctrl_id: u16) -> Result<CtrlVsReg, EmuError> {
        let pal = azihsm_fw_mgmt_app::pal();
        Ok(pal.ctrl_read_vs_reg(ctrl_id)?)
    }

    /// Writes to the controller admin queue attribute register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The admin queue attribute register value to write.
    fn ctrl_write_aqa_reg(&self, ctrl_id: u16, reg: CtrlAqaReg) -> Result<(), EmuError> {
        let pal = azihsm_fw_mgmt_app::pal();
        pal.ctrl_write_aqa_reg(ctrl_id, reg)?;
        Ok(())
    }

    /// Writes to the admin submission queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The admin submission queue base address register value to write.
    fn ctrl_write_asq_reg(&self, ctrl_id: u16, reg: CtrlAsqReg) -> Result<(), EmuError> {
        let pal = azihsm_fw_mgmt_app::pal();
        pal.ctrl_write_asq_reg(ctrl_id, reg)?;
        Ok(())
    }

    /// Writes to the admin completion queue base address register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to write to.
    /// - `reg`: The admin completion queue base address register value to write.
    fn ctrl_write_acq_reg(&self, ctrl_id: u16, reg: CtrlAcqReg) -> Result<(), EmuError> {
        let pal = azihsm_fw_mgmt_app::pal();
        pal.ctrl_write_acq_reg(ctrl_id, reg)?;
        Ok(())
    }

    /// Enables the specified controller.
    ///
    /// Configures the controller with default settings (4KB memory page size,
    /// submission queue entry size of 64 bytes, completion queue entry size of 16 bytes)
    /// and sets the enable bit. Blocks until the controller reports ready.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to enable.
    fn ctrl_enable(&self, ctrl_id: u16) -> Result<(), EmuError> {
        let pal = azihsm_fw_mgmt_app::pal();
        let cc = pal
            .ctrl_read_cc_reg(ctrl_id)?
            .with_mps(0) // 4KB pages
            .with_iosqes(6) // 64-byte SQ entries
            .with_iocqes(4) // 16-byte CQ entries
            .with_en(true); // Enable
        pal.ctrl_write_cc_reg(ctrl_id, cc)?;
        self.wait_for_ctrl_ready(ctrl_id, true)
    }

    /// Disables the specified controller.
    ///
    /// Clears the enable bit in the controller configuration register and
    /// blocks until the controller reports not ready.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to disable.
    fn ctrl_disable(&self, ctrl_id: u16) -> Result<(), EmuError> {
        let pal = azihsm_fw_mgmt_app::pal();
        let cc = pal.ctrl_read_cc_reg(ctrl_id)?.with_en(false);
        pal.ctrl_write_cc_reg(ctrl_id, cc)?;
        self.wait_for_ctrl_ready(ctrl_id, false)
    }

    /// Waits for the controller to reach the expected ready state.
    ///
    /// Polls the controller status register until the ready bit matches the
    /// expected value or a timeout occurs. The timeout is derived from the
    /// controller's capability register.
    ///
    /// # Parameters
    /// - `ctrl_id`: The identifier of the controller to poll.
    /// - `rdy`: The expected ready state (`true` for ready, `false` for not ready).
    fn wait_for_ctrl_ready(&self, ctrl_id: u16, rdy: bool) -> Result<(), EmuError> {
        let pal = azihsm_fw_mgmt_app::pal();
        let mut to = self.ctrl_read_cap_reg(ctrl_id)?.to();
        if to == 0 {
            to = 1
        }
        let timeout = Duration::from_millis(to as u64 * 500);
        let start = std::time::Instant::now();
        loop {
            let csts = pal.ctrl_read_csts_reg(ctrl_id)?;
            if csts.rdy() == rdy {
                return Ok(());
            }
            if csts.cfs() {
                return Err(EmuError::CtrlFailure);
            }
            if start.elapsed() > timeout {
                return Err(EmuError::CtrlTimeout);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl From<u32> for EmuError {
    /// Converts a controller manager error code to an emulator error.
    ///
    /// # Parameters
    /// - `code`: The error code from the controller manager.
    fn from(code: u32) -> Self {
        match code {
            x if x == (CtrlMgrError::InvalidCtrlId).0 => EmuError::CtrlNotFound,
            _ => EmuError::Internal,
        }
    }
}

#[cfg(test)]
mod tests {

    use std::thread::sleep;
    use std::time::Duration;

    use tracing::metadata::LevelFilter;
    use tracing_subscriber::filter::Targets;
    use tracing_subscriber::prelude::*;

    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn test_emu_start() {
        static ONCE: std::sync::Once = std::sync::Once::new();

        ONCE.call_once(|| {
            let targets = if let Ok(var) = std::env::var("RUST_LOG") {
                var.parse()
                    .expect("Failed to parse RUST_LOG environment variable")
            } else {
                Targets::new().with_default(LevelFilter::DEBUG)
            };
            tracing_subscriber::fmt()
                .compact()
                .log_internal_errors(true)
                .with_test_writer()
                .with_max_level(LevelFilter::TRACE)
                .with_thread_ids(true)
                .finish()
                .with(targets)
                .init();
        });

        let emu = &AZIHSM_EMULATOR;

        emu.start();
        emu.do_perst_up();
        emu.do_perst_down();
        emu.do_flr();

        for _ in 0..1 {
            sleep(Duration::from_secs(2));
            let _ = emu.ctrl_enable(0);
            sleep(Duration::from_secs(2));
            let _ = emu.ctrl_disable(0);
        }

        emu.stop();
    }
}
