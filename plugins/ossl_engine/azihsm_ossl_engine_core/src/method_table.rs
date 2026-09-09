// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-ENGINE ownership of engine-supplied EVP method copies, shared by
//! [`pkey_method`](crate::pkey_method) and [`asn1_method`](crate::asn1_method).
//!
//! The engine framework **frees** whatever method the `pkey_meths` /
//! `pkey_asn1_meths` callback hands out when that ENGINE is destroyed
//! (`engine_pkey_meths_free` / `engine_pkey_asn1_meths_free` run right before
//! the destroy hook), so every ENGINE must own its own method copy — a shared
//! process-global method would be freed at the first engine's destruction and
//! dangle for every other engine. Three rules keep the table sound:
//!
//! - [`MethodTable::register`] **overwrites** an existing entry: one can only
//!   pre-exist if a destroyed ENGINE at the same address was never released —
//!   it is necessarily stale.
//! - [`MethodTable::lookup`] **never stores** on a miss: a miss means the
//!   entry was already released, i.e. this lookup is the framework's
//!   destruction-time free pass — it is handed a throwaway copy to free
//!   (inserting it would leave a dangling entry that a reused ENGINE address
//!   would later pick up).
//! - [`MethodTable::release`] drops the entry address-only, dereferencing
//!   nothing — the framework frees the method itself.

use std::collections::HashMap;
use std::ffi::c_int;
use std::sync::OnceLock;

use azihsm_ossl_engine_sys as ffi;
use parking_lot::Mutex;

use crate::engine::Engine;
use crate::error::EngineError;
use crate::error::EngineResult;

/// The NID list the engine's method-lookup callbacks advertise (EC only).
static EC_NIDS: [c_int; 1] = [ffi::EVP_PKEY_EC as c_int];

/// Builder + per-ENGINE method table for one method type (see the module
/// docs). The builder is set by the first registration — one handler type per
/// process.
pub(crate) struct MethodTable<M> {
    builder: OnceLock<fn() -> EngineResult<*mut M>>,
    entries: OnceLock<Mutex<HashMap<usize, usize>>>,
}

/// A resolved [`MethodTable::lookup`].
enum Lookup<M> {
    /// The engine's stored entry: a live, registered ENGINE about to use the
    /// method.
    Stored(*mut M),
    /// Destruction-time free pass: a fresh copy for the framework to free,
    /// never stored.
    Throwaway(*mut M),
}

impl<M> MethodTable<M> {
    pub(crate) const fn new() -> Self {
        Self {
            builder: OnceLock::new(),
            entries: OnceLock::new(),
        }
    }

    fn entries(&self) -> &Mutex<HashMap<usize, usize>> {
        self.entries.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Record `builder` (first caller wins) and store a freshly built method
    /// as `engine`'s entry, overwriting any stale one. Building eagerly makes
    /// build errors surface at registration.
    pub(crate) fn register(
        &self,
        engine: &Engine,
        builder: fn() -> EngineResult<*mut M>,
    ) -> EngineResult<()> {
        let _ = self.builder.set(builder);
        let builder = self
            .builder
            .get()
            .ok_or(EngineError::Other("method builder missing".into()))?;
        let method = builder()? as usize;
        self.entries()
            .lock()
            .insert(engine.as_ptr() as usize, method);
        Ok(())
    }

    /// Drop `engine`'s entry (address-only).
    pub(crate) fn release(&self, engine: &Engine) {
        self.entries().lock().remove(&(engine.as_ptr() as usize));
    }

    /// Resolve `e`'s method. `None` means no builder was registered yet or
    /// building a throwaway failed.
    fn lookup(&self, e: *mut ffi::ENGINE) -> Option<Lookup<M>> {
        let builder = *self.builder.get()?;
        if let Some(&m) = self.entries().lock().get(&(e as usize)) {
            return Some(Lookup::Stored(m as *mut M));
        }
        builder().ok().map(Lookup::Throwaway)
    }
}

/// Shared body of the `ENGINE_PKEY_METHS_PTR` / `ENGINE_PKEY_ASN1_METHS_PTR`
/// callbacks: NID enumeration when `meth` is NULL, otherwise the table lookup
/// for EC. `on_stored` runs only for a stored-entry hit (the pkey callback's
/// thread-local engine handoff): no context construction follows a throwaway,
/// and a dying engine must never be left pending.
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
        // SAFETY: nids is the enumeration out-param; EC_NIDS is 'static.
        unsafe { *nids = EC_NIDS.as_ptr() };
        return c_int::try_from(EC_NIDS.len()).unwrap_or(0);
    }
    let resolved = if nid == ffi::EVP_PKEY_EC as c_int {
        table.lookup(e)
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
