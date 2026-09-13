// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! UART driver implementation using tock-register MMIO.

use core::fmt;

use azihsm_fw_static_ref::StaticRef;
use azihsm_fw_uno_reg_soc::uart::regs::UartRegs;
use azihsm_fw_uno_reg_soc::uart::UART_BASE;
use azihsm_fw_uno_reg_soc::uart::*;
use tock_registers::interfaces::Readable;
use tock_registers::interfaces::Writeable;

/// MMIO register overlay for the UART peripheral.
const REGS: StaticRef<UartRegs> = unsafe { StaticRef::new(UART_BASE as *const UartRegs) };

/// Synchronous UART driver.
///
/// Provides blocking byte-level read and write operations by polling
/// the `STATUS.RX_READY` and `STATUS.TX_READY` flags.
#[derive(Default, Debug)]
pub struct Uart;

impl Uart {
    /// Creates a new UART driver instance.
    pub const fn new() -> Self {
        Self
    }

    /// Reads bytes from the UART into `buf` until a NUL byte is received
    /// or the buffer is full.
    ///
    /// # Arguments
    ///
    /// * `buf` — output buffer to fill with received bytes.
    ///
    /// # Returns
    ///
    /// The number of bytes read, or `None` if no data was available.
    pub fn read(&mut self, buf: &mut [u8]) -> Option<u8> {
        let mut i = 0;
        loop {
            let byte = self.read_byte()?;
            if byte == b'\0' || i >= buf.len() {
                return Some(i as u8);
            }
            buf[i] = byte;
            i += 1;
        }
    }

    /// Reads a single byte from the UART, blocking until `RX_READY` is set.
    ///
    /// # Returns
    ///
    /// The received byte, or `None` if an error occurs.
    fn read_byte(&mut self) -> Option<u8> {
        while REGS.status.read(STATUS::RX_READY) == 0 {}
        let val = REGS.rx_buf.read(RX_BUF::DATA);
        Some(val as u8)
    }

    /// Writes a string to the UART, filtering to printable ASCII plus
    /// newline and tab. Non-printable bytes are replaced with `0xFE`.
    ///
    /// # Arguments
    ///
    /// * `s` — the string to write.
    pub fn write(&mut self, s: &str) {
        for byte in s.bytes() {
            match byte {
                0x20..=0x7e | b'\n' | b'\t' => self.write_byte(byte),
                _ => self.write_byte(0xfe),
            }
        }
    }

    /// Writes a single byte to the UART, blocking until `TX_READY` is set.
    ///
    /// # Arguments
    ///
    /// * `byte` — the byte to transmit.
    fn write_byte(&mut self, byte: u8) {
        while REGS.status.read(STATUS::TX_READY) == 0 {}
        REGS.tx_hold.set(byte as u32);
    }

    /// Writes a string, giving up if the UART never becomes ready.
    ///
    /// [`write`](Self::write) spins on `STATUS.TX_READY` indefinitely, which
    /// deadlocks the caller if the peripheral was never configured — on the
    /// HSM core that manifests as the controller failing to reach ready and
    /// the host seeing an `ETIMEDOUT` probe failure. This variant bounds the
    /// wait so an unconfigured UART costs a bounded delay instead of a hang.
    ///
    /// # Arguments
    ///
    /// * `s` — the string to write.
    /// * `spin_limit` — maximum `TX_READY` polls to tolerate per byte.
    ///
    /// # Returns
    ///
    /// `true` if the whole string was written, `false` if the UART stalled.
    pub fn try_write(&mut self, s: &str, spin_limit: u32) -> bool {
        for byte in s.bytes() {
            let byte = match byte {
                0x20..=0x7e | b'\n' | b'\t' => byte,
                _ => 0xfe,
            };
            let mut spins = 0u32;
            while REGS.status.read(STATUS::TX_READY) == 0 {
                spins += 1;
                if spins >= spin_limit {
                    return false;
                }
            }
            REGS.tx_hold.set(byte as u32);
        }
        true
    }

    /// Writes a raw byte buffer to the UART.
    ///
    /// # Arguments
    ///
    /// * `buf` — bytes to transmit.
    pub fn write_bytes(&mut self, buf: &[u8]) {
        for &b in buf {
            self.write_byte(b);
        }
    }

    /// Reads exactly `buf.len()` bytes from the UART.
    ///
    /// # Arguments
    ///
    /// * `buf` — buffer to fill; blocks until all bytes are received.
    pub fn read_bytes(&mut self, buf: &mut [u8]) {
        for item in buf.iter_mut() {
            // read_byte spins until data is available, so unwrap is safe
            // in the current polling implementation.
            if let Some(b) = self.read_byte() {
                *item = b;
            }
        }
    }
}

impl fmt::Write for Uart {
    /// Writes a string to the UART via [`Uart::write`].
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write(s);
        Ok(())
    }
}
