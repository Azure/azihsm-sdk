// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Embassy time driver backed by the ARM Cortex-M SysTick timer.
//!
//! Configures SysTick as a periodic tick source at 32 Hz (31.25 ms per tick)
//! from a 450 MHz core clock. The 24-bit reload value of 14,062,499 fits
//! within the SysTick counter's maximum of 16,777,215.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │ SysTick (24-bit down-counter)            │
//! │   reload = 14,062,499                    │
//! │   clock  = 450 MHz core clock            │
//! │   ISR    = SysTick exception             │
//! └──────────┬───────────────────────────────┘
//!            │ every 31.25 ms
//!            ▼
//!    TICK_COUNT.fetch_add(1)
//!    queue.next_expiration() → wake Embassy tasks
//! ```
//!
//! # Usage
//!
//! ```ignore
//! // Call once during PAL init:
//! azihsm_fw_uno_drivers_systick::init();
//! ```

#![no_std]

use core::cell::RefCell;
use core::task::Waker;

use cortex_m_rt::exception;
use critical_section::Mutex;
use embassy_time_driver::Driver;
use embassy_time_queue_utils::Queue;
use portable_atomic::AtomicU64;
use portable_atomic::Ordering;

const SYSTICK_CLOCK_HZ: u32 = 450_000_000;
const TICK_RATE_HZ: u32 = 32;
const RELOAD_VALUE: u32 = SYSTICK_CLOCK_HZ / TICK_RATE_HZ - 1; // 14_062_499

/// Monotonic tick counter, incremented by the SysTick exception handler.
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

struct SysTickDriver {
    queue: Mutex<RefCell<Queue>>,
}

impl SysTickDriver {
    const fn new() -> Self {
        Self {
            queue: Mutex::new(RefCell::new(Queue::new())),
        }
    }

    fn set_alarm(&self, _cs: &critical_section::CriticalSection, at: u64) -> bool {
        self.now() < at
    }
}

impl Driver for SysTickDriver {
    fn now(&self) -> u64 {
        TICK_COUNT.load(Ordering::Relaxed)
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        critical_section::with(|cs| {
            let mut queue = self.queue.borrow(cs).borrow_mut();
            if queue.schedule_wake(at, waker) {
                let mut next = queue.next_expiration(self.now());
                while !self.set_alarm(&cs, next) {
                    next = queue.next_expiration(self.now());
                }
            }
        });
    }
}

embassy_time_driver::time_driver_impl!(static DRIVER: SysTickDriver = SysTickDriver::new());

/// Initialises the Cortex-M SysTick peripheral as the firmware time base.
///
/// Configures the SysTick for periodic interrupts using the processor clock.
/// Must be called exactly once during PAL init, before any Embassy timers
/// are used.
pub fn init() {
    // SAFETY: Single-core Cortex-M7, called once from PAL init before
    // any interrupts are enabled.
    let mut syst = unsafe { cortex_m::Peripherals::steal().SYST };
    syst.set_reload(RELOAD_VALUE);
    syst.clear_current();
    syst.set_clock_source(cortex_m::peripheral::syst::SystClkSource::Core);
    syst.enable_interrupt();
    syst.enable_counter();
}

#[exception]
fn SysTick() {
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);

    critical_section::with(|cs| {
        let mut queue = DRIVER.queue.borrow(cs).borrow_mut();
        queue.next_expiration(DRIVER.now());
    });
}
