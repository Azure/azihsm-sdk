// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Zero-cost interior mutability for single-core, cooperative environments.
//!
//! `SingleCell` wraps `UnsafeCell` in a safe API. The single `unsafe` is
//! confined to the `with` method. Callers never write `unsafe`.
//!
//! # Safety contract
//!
//! - Single-core only (no concurrent access from another core).
//! - No ISR may access the same `SingleCell` (use polling, not interrupt delivery).
//! - No reentrant calls to `with` on the same cell (the closure must not call
//!   back into `with` on the same instance).

#![no_std]

use core::cell::UnsafeCell;

/// Interior mutable cell with zero runtime overhead.
///
/// Unlike `RefCell`, there is no borrow flag. Unlike `Mutex<RefCell<T>>`,
/// there is no critical-section (PRIMASK) overhead.
///
/// Safe to use when:
/// - Single-core execution (Cortex-M with no SMP).
/// - The cell is not accessed from ISRs.
/// - `with` is not called reentrantly on the same cell.
pub struct SingleCell<T>(UnsafeCell<T>);

// SAFETY: On single-core targets with cooperative scheduling and no ISR
// access, there is no concurrent mutation. This impl allows SingleCell
// to be placed in statics.
unsafe impl<T> Sync for SingleCell<T> {}

impl<T> SingleCell<T> {
    /// Create a new `SingleCell` with the given value.
    pub const fn new(val: T) -> Self {
        Self(UnsafeCell::new(val))
    }

    /// Borrows the stored value mutably for the duration of a closure.
    ///
    /// # Arguments
    ///
    /// * `f` - A closure that receives a temporary `&mut T` reference to the cell contents.
    ///
    /// # Returns
    ///
    /// The value of type `R` returned by `f`.
    ///
    /// # Safety contract
    ///
    /// The caller must uphold the invariants documented on [`SingleCell`]:
    /// single-core execution, no ISR access, and no reentrant calls to
    /// `with` on the same cell.
    #[inline(always)]
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        // SAFETY: Caller upholds the single-core, no-ISR, no-reentrant
        // contract documented on the type.
        f(unsafe { &mut *self.0.get() })
    }
}
