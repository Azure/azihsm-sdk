// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-ENGINE ownership of engine-supplied EVP method copies, shared by
//! [`pkey_method`](crate::pkey_method), [`hkdf_method`](crate::hkdf_method)
//! and [`asn1_method`](crate::asn1_method).
//!
//! The engine framework **frees** whatever method the `pkey_meths` /
//! `pkey_asn1_meths` callback hands out when that ENGINE is destroyed
//! (`engine_pkey_meths_free` / `engine_pkey_asn1_meths_free` run right before
//! the destroy hook), so every ENGINE must own its own method copy per NID —
//! a shared process-global method would be freed at the first engine's
//! destruction and dangle for every other engine. Three rules keep the table
//! sound:
//!
//! - [`MethodTable::register`] **overwrites** an existing `(engine, nid)`
//!   entry: one can only pre-exist if a destroyed ENGINE at the same address
//!   was never released — it is necessarily stale.
//! - The lookup **never stores** on a miss: a miss means the entry was
//!   already released, i.e. this lookup is the framework's destruction-time
//!   free pass — it is handed a throwaway copy to free (inserting it would
//!   leave a dangling entry that a reused ENGINE address would later pick
//!   up).
//! - [`MethodTable::release`] drops the engine's entries address-only,
//!   dereferencing nothing — the framework frees the methods itself.

use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::OnceLock;

use azihsm_ossl_engine_sys as ffi;
use parking_lot::Mutex;

use crate::engine::Engine;
use crate::error::EngineError;
use crate::error::EngineResult;

thread_local! {
    /// The ENGINE that most recently resolved one of our methods on this
    /// thread; consumed by the method's `init` override. Sound because
    /// OpenSSL resolves the method and runs `init` back-to-back inside
    /// `int_ctx_new` on one thread, so the value is always freshly set by the
    /// context's own lookup before its only consumer reads it.
    static PENDING_ENGINE: Cell<usize> = const { Cell::new(0) };
}

/// Record `engine` as the pending ENGINE for this thread (the `on_stored`
/// hook of [`dispatch`]).
pub(crate) fn note_pending_engine(engine: *mut ffi::ENGINE) {
    PENDING_ENGINE.with(|c| c.set(engine as usize));
}

/// Consume the pending ENGINE handed off by the method lookup.
pub(crate) fn take_pending_engine() -> usize {
    PENDING_ENGINE.with(|c| c.take())
}

/// Builders + per-`(ENGINE, NID)` method table for one method type (see the
/// module docs). A NID's builder is set by its first registration — one
/// handler type per NID per process. `nids` is the 'static list the
/// enumeration branch of the lookup callback advertises.
pub(crate) struct MethodTable<M> {
    nids: &'static [c_int],
    builders: OnceLock<Mutex<HashMap<c_int, fn() -> EngineResult<*mut M>>>>,
    entries: OnceLock<Mutex<HashMap<(usize, c_int), usize>>>,
}

/// A resolved lookup.
enum Lookup<M> {
    /// The engine's stored entry: a live, registered ENGINE about to use the
    /// method.
    Stored(*mut M),
    /// Destruction-time free pass: a fresh copy for the framework to free,
    /// never stored.
    Throwaway(*mut M),
}

impl<M> MethodTable<M> {
    pub(crate) const fn new(nids: &'static [c_int]) -> Self {
        Self {
            nids,
            builders: OnceLock::new(),
            entries: OnceLock::new(),
        }
    }

    fn builders(&self) -> &Mutex<HashMap<c_int, fn() -> EngineResult<*mut M>>> {
        self.builders.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn entries(&self) -> &Mutex<HashMap<(usize, c_int), usize>> {
        self.entries.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Record `builder` for `nid` (first caller wins) and store a freshly
    /// built method as `engine`'s entry, overwriting any stale one. Building
    /// eagerly makes build errors surface at registration.
    pub(crate) fn register(
        &self,
        engine: &Engine,
        nid: c_int,
        builder: fn() -> EngineResult<*mut M>,
    ) -> EngineResult<()> {
        if !self.nids.contains(&nid) {
            return Err(EngineError::Other(format!(
                "NID {nid} is not advertised by this method table"
            )));
        }
        let builder = *self.builders().lock().entry(nid).or_insert(builder);
        let method = builder()? as usize;
        self.entries()
            .lock()
            .insert((engine.as_ptr() as usize, nid), method);
        Ok(())
    }

    /// Drop all of `engine`'s entries (address-only).
    pub(crate) fn release(&self, engine: &Engine) {
        let e = engine.as_ptr() as usize;
        self.entries().lock().retain(|(k, _), _| *k != e);
    }

    /// Resolve `(e, nid)`. `None` means the NID is not available for this
    /// engine (unregistered, no builder, or building a throwaway failed).
    fn lookup(&self, e: *mut ffi::ENGINE, nid: c_int) -> Option<Lookup<M>> {
        let e_addr = e as usize;
        {
            let entries = self.entries().lock();
            if let Some(&m) = entries.get(&(e_addr, nid)) {
                return Some(Lookup::Stored(m as *mut M));
            }
            // A live engine (it still has entries) asking for a NID it never
            // registered gets no method — a throwaway here would leak and
            // build contexts without the engine handoff. No entries at all
            // means the destruction free pass (release drops every entry):
            // hand the framework a throwaway to free.
            if entries.keys().any(|(k, _)| *k == e_addr) {
                return None;
            }
        }
        let builder = *self.builders().lock().get(&nid)?;
        builder().ok().map(Lookup::Throwaway)
    }
}

/// Shared body of the `ENGINE_PKEY_METHS_PTR` / `ENGINE_PKEY_ASN1_METHS_PTR`
/// callbacks: NID enumeration when `meth` is NULL, otherwise the table
/// lookup. `on_stored` runs only for a stored-entry hit (the thread-local
/// engine handoff): no context construction follows a throwaway, and a dying
/// engine must never be left pending.
///
/// # Safety
/// Must be called only from an engine-framework method-lookup callback, with
/// `meth`/`nids` the out-params OpenSSL passed per that contract.
#[allow(unsafe_code)]
pub(crate) unsafe fn dispatch<M>(
    table: &MethodTable<M>,
    e: *mut ffi::ENGINE,
    meth: *mut *mut M,
    nids: *mut *const c_int,
    nid: c_int,
    on_stored: fn(*mut ffi::ENGINE),
) -> c_int {
    if meth.is_null() {
        if nids.is_null() {
            return 0;
        }
        // SAFETY: nids is the enumeration out-param; table.nids is 'static.
        unsafe { *nids = table.nids.as_ptr() };
        return c_int::try_from(table.nids.len()).unwrap_or(0);
    }
    let resolved = if table.nids.contains(&nid) {
        table.lookup(e, nid)
    } else {
        None
    };
    let (method, rc) = match resolved {
        Some(Lookup::Stored(m)) => {
            on_stored(e);
            (m, 1)
        }
        Some(Lookup::Throwaway(m)) => (m, 1),
        None => (std::ptr::null_mut(), 0),
    };
    // SAFETY: meth is the method out-param; a non-NULL method lives until the
    // framework frees it at this ENGINE's destruction.
    unsafe { *meth = method };
    rc
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::ptr::NonNull;

    use super::*;

    static NIDS: [c_int; 2] = [101, 102];

    fn build() -> EngineResult<*mut u8> {
        Ok(Box::into_raw(Box::new(0u8)))
    }

    // A live engine asking for an unregistered NID gets no method; only an
    // engine with no live entries left (the destruction free pass) receives
    // a throwaway.
    #[test]
    #[allow(unsafe_code)]
    fn lookup_denies_unregistered_nid_on_live_engine() {
        let table: MethodTable<u8> = MethodTable::new(&NIDS);
        // SAFETY: fresh ENGINEs, freed below; methods are dummy heap bytes
        // reclaimed via Box::from_raw.
        unsafe {
            let raw_a = ffi::ENGINE_new();
            let raw_b = ffi::ENGINE_new();
            let engine_a = Engine::from_ptr(NonNull::new(raw_a).unwrap());
            let engine_b = Engine::from_ptr(NonNull::new(raw_b).unwrap());

            // a registers 101 only; b registers 102, making 102's builder
            // exist process-wide.
            table.register(&engine_a, 101, build).unwrap();
            table.register(&engine_b, 102, build).unwrap();

            let Some(Lookup::Stored(stored_a)) = table.lookup(raw_a, 101) else {
                unreachable!("registered NID must resolve to the stored entry")
            };
            assert!(
                table.lookup(raw_a, 102).is_none(),
                "live engine must not get a method for an unregistered NID"
            );

            // Fully released: the free pass gets throwaways for built NIDs.
            table.release(&engine_a);
            let Some(Lookup::Throwaway(throwaway)) = table.lookup(raw_a, 101) else {
                unreachable!("released engine must get a throwaway")
            };
            drop(Box::from_raw(throwaway));

            // Reclaim the dummy methods and engines.
            drop(Box::from_raw(stored_a));
            let Some(Lookup::Stored(stored_b)) = table.lookup(raw_b, 102) else {
                unreachable!("b's entry must still be stored")
            };
            table.release(&engine_b);
            drop(Box::from_raw(stored_b));
            ffi::ENGINE_free(raw_a);
            ffi::ENGINE_free(raw_b);
        }
    }
}
