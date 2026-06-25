// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed ex_data slot for `ENGINE` objects: attaches a `Box<T>` to an
//! `ENGINE`.
//!
//! No per-slot free callback is registered — `libcrypto`'s late `atexit`
//! cleanup can run after the engine `.so` is unmapped, leaving a dangling
//! function pointer. Callers must instead drop the box via [`take`] from a
//! [`DestroyHandler`](crate::engine::DestroyHandler), which runs while the
//! `.so` is loaded.
//!
//! `CRYPTO_get_ex_new_index` allocates a fresh slot per call (no dedupe), so
//! callers must cache the [`register`] result (e.g. in a `OnceLock`).
//!
//! [`register`]: EngineExData::register
//! [`take`]: EngineExData::take

use std::ffi::c_int;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::ptr::null_mut;

use openssl_sys_engine as ffi;

use crate::engine::Engine;
use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::ossl_check;

/// Sentinel `CRYPTO_get_ex_new_index` returns on allocation failure; any
/// other (non-negative) value is a valid slot index.
const EX_NEW_INDEX_FAILURE: c_int = -1;

/// Typed handle to an ex_data slot on `ENGINE` for values of type `T`. `Copy`
/// (holds only the slot index).
///
/// `T: Sync` is required: [`get`](Self::get) hands out a `&T` through a shared
/// `&Engine` (which is `Sync`), so the `&T` may be read from multiple threads.
pub struct EngineExData<T: Send + Sync + 'static> {
    idx: c_int,
    _marker: PhantomData<fn() -> T>,
}

impl<T: Send + Sync + 'static> Clone for EngineExData<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Send + Sync + 'static> Copy for EngineExData<T> {}

impl<T: Send + Sync + 'static> EngineExData<T> {
    /// Allocate a new ex_data index on the `ENGINE` class for `T`.
    ///
    /// Each call allocates a fresh slot, so callers must cache the result
    /// (see module docs). No per-slot free callback is registered — see
    /// module docs for the rationale; callers must `take()` to drop the
    /// stored value.
    pub fn register() -> EngineResult<Self> {
        // SAFETY: All inputs are constants or 'static. No callbacks are
        // registered (see module docs).
        #[allow(unsafe_code)]
        let idx = unsafe {
            ffi::CRYPTO_get_ex_new_index(
                ffi::CRYPTO_EX_INDEX_ENGINE as c_int,
                0,
                null_mut(),
                None,
                None,
                None,
            )
        };
        if idx == EX_NEW_INDEX_FAILURE {
            return Err(EngineError::ExDataRegisterFailed);
        }
        Ok(Self {
            idx,
            _marker: PhantomData,
        })
    }

    /// Attach `value`. Returns any previously-stored value, already detached
    /// from the `ENGINE` — drop it directly. (The newly stored `value` has no
    /// auto-free callback; reclaim it later via [`take`](Self::take).)
    ///
    /// `&mut Engine`: a live `&T` from [`get`](Self::get) then statically
    /// conflicts with detaching the value, closing a safe-code use-after-free.
    #[allow(unsafe_code)]
    pub fn set(&self, engine: &mut Engine, value: Box<T>) -> EngineResult<Option<Box<T>>> {
        let new_raw = Box::into_raw(value);
        // SAFETY: engine.as_ptr() is a valid ENGINE; self.idx is a registered slot.
        let prev = unsafe { ffi::ENGINE_get_ex_data(engine.as_ptr(), self.idx) } as *mut T;
        // SAFETY: same as above; new_raw is a fresh Box::into_raw of T.
        let rc =
            unsafe { ffi::ENGINE_set_ex_data(engine.as_ptr(), self.idx, new_raw.cast::<c_void>()) };
        if let Err(e) = ossl_check(rc, EngineError::ExDataSetFailed) {
            // SAFETY: OpenSSL did not take ownership; reclaim the box.
            let _ = unsafe { Box::from_raw(new_raw) };
            return Err(e);
        }
        if prev.is_null() {
            Ok(None)
        } else {
            // SAFETY: `prev` was put there by an earlier `set` (Box::into_raw of T).
            Ok(Some(unsafe { Box::from_raw(prev) }))
        }
    }

    /// Borrow the stored value, if any. Lifetime tied to the `engine` borrow.
    #[allow(unsafe_code)]
    pub fn get<'e>(&self, engine: &'e Engine) -> Option<&'e T> {
        // SAFETY: engine.as_ptr() is a valid ENGINE; self.idx is a registered slot.
        let ptr = unsafe { ffi::ENGINE_get_ex_data(engine.as_ptr(), self.idx) } as *const T;
        // SAFETY: non-null implies `set` placed a `Box::into_raw` of T here.
        unsafe { ptr.as_ref() }
    }

    /// Detach and return the stored value: `Ok(Some(_))` if present,
    /// `Ok(None)` if the slot was empty.
    ///
    /// Takes `&mut Engine` for the same reason as [`set`](Self::set): it must
    /// not run while a `&T` from [`get`](Self::get) is still live.
    ///
    /// Returns `Err(ExDataSetFailed)` if clearing the slot fails. In that case
    /// the value is intentionally left attached to the `ENGINE` (not reclaimed)
    /// so there is no use-after-free — the slot may still be populated.
    #[allow(unsafe_code)]
    pub fn take(&self, engine: &mut Engine) -> EngineResult<Option<Box<T>>> {
        // SAFETY: engine.as_ptr() is a valid ENGINE; self.idx is a registered slot.
        let ptr = unsafe { ffi::ENGINE_get_ex_data(engine.as_ptr(), self.idx) } as *mut T;
        if ptr.is_null() {
            return Ok(None);
        }
        // SAFETY: engine.as_ptr() is a valid ENGINE; self.idx is a registered slot.
        let rc =
            unsafe { ffi::ENGINE_set_ex_data(engine.as_ptr(), self.idx, null_mut::<c_void>()) };
        // Clear the slot before reclaiming the box. If the clear fails the
        // ENGINE still references `ptr`, so leave it attached and surface the
        // error rather than hand back a box the ENGINE could free later (UAF).
        ossl_check(rc, EngineError::ExDataSetFailed)?;
        // SAFETY: `ptr` was put there by `set`; the slot is now cleared.
        Ok(Some(unsafe { Box::from_raw(ptr) }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::ptr::NonNull;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use super::*;

    /// Create a fresh ENGINE for a test. Caller must `ENGINE_free` it.
    #[allow(unsafe_code)]
    fn new_engine() -> Engine {
        // SAFETY: ENGINE_new returns either a fresh, heap-allocated
        // ENGINE or NULL on allocation failure (which we treat as a
        // test setup failure).
        let raw = unsafe { ffi::ENGINE_new() };
        let nn = NonNull::new(raw).expect("ENGINE_new returned NULL");
        // SAFETY: nn is non-null and owned by us until ENGINE_free below.
        unsafe { Engine::from_ptr(nn) }
    }

    /// Release an ENGINE created by `new_engine`. Triggers free callbacks.
    #[allow(unsafe_code)]
    fn free_engine(e: Engine) {
        // SAFETY: e was obtained from new_engine and not consumed elsewhere.
        unsafe { ffi::ENGINE_free(e.as_ptr()) };
    }

    #[test]
    fn round_trip_set_get_take() {
        let slot = EngineExData::<u32>::register().unwrap();
        let mut e = new_engine();

        assert!(slot.get(&e).is_none());

        let prev = slot.set(&mut e, Box::new(0xDEAD_BEEF)).unwrap();
        assert!(prev.is_none(), "first set should have no previous value");

        assert_eq!(slot.get(&e), Some(&0xDEAD_BEEF));

        let taken = slot.take(&mut e).unwrap().expect("slot populated");
        assert_eq!(*taken, 0xDEAD_BEEF);
        assert!(slot.get(&e).is_none(), "slot should be empty after take");

        free_engine(e);
    }

    #[test]
    fn set_returns_previous_value() {
        let slot = EngineExData::<String>::register().unwrap();
        let mut e = new_engine();

        slot.set(&mut e, Box::new("first".to_owned())).unwrap();
        let prev = slot.set(&mut e, Box::new("second".to_owned())).unwrap();

        assert_eq!(prev.as_deref().map(String::as_str), Some("first"));
        assert_eq!(slot.get(&e).map(String::as_str), Some("second"));

        free_engine(e);
    }

    /// Counts Drop calls on the contained value.
    struct DropCounter(Arc<AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn take_drops_box_exactly_once() {
        let counter = Arc::new(AtomicUsize::new(0));
        let slot = EngineExData::<DropCounter>::register().unwrap();
        let mut e = new_engine();

        slot.set(&mut e, Box::new(DropCounter(Arc::clone(&counter))))
            .unwrap();
        let taken = slot.take(&mut e).unwrap().expect("slot populated");
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        drop(taken);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        free_engine(e);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "ENGINE_free must not re-drop after take()"
        );
    }

    /// Pins the contract that `register` does NOT install a libcrypto-side
    /// free callback. If this test ever fails to leak, revisit the module
    /// docs — the caller-side `take()` contract relies on libcrypto being
    /// unaware of `T` so a late `atexit` cleanup can never call back into
    /// our (possibly unmapped) `.so`.
    #[test]
    fn engine_free_without_take_leaks_the_box() {
        let counter = Arc::new(AtomicUsize::new(0));
        let slot = EngineExData::<DropCounter>::register().unwrap();
        let mut e = new_engine();

        slot.set(&mut e, Box::new(DropCounter(Arc::clone(&counter))))
            .unwrap();
        free_engine(e);
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "with no auto-free callback, ENGINE_free must NOT drop the box"
        );
    }

    #[test]
    fn distinct_types_get_distinct_indices() {
        let a = EngineExData::<u32>::register().unwrap();
        let b = EngineExData::<u64>::register().unwrap();
        assert_ne!(a.idx, b.idx);
    }
}
