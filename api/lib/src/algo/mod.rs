// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Acquires a write lock on a key's inner state for resiliency restore,
/// returning early with `Ok(())` if the key is already up-to-date.
///
/// Implements the double-checked epoch pattern:
/// 1. Fast path (no lock): returns if `self.last_restore_epoch() == epoch`.
/// 2. Slow path: acquires the write lock, re-checks, returns if already up-to-date.
///
/// On success, binds `$session`, `$restore_epoch`, and `$guard` (write lock)
/// for the caller to perform the DDI unmask call and
/// `$guard.restore(...)`.
macro_rules! acquire_restore_guard {
    ($self:expr => $session:ident, $restore_epoch:ident, $guard:ident) => {
        let $session = $self.session();
        let $restore_epoch = $session.partition().restore_epoch();

        // Fast path: if the current handle is already up-to-date, no need to acquire the lock.
        if $self.last_restore_epoch() == $restore_epoch {
            return Ok(());
        }

        let mut $guard = $self.inner.write();

        // Slow path: re-check under the lock to handle the case where another
        // thread already performed the restore.
        if $guard.last_restore_epoch() == $restore_epoch {
            return Ok(());
        }

        // Key was explicitly deleted — don't resurrect it.
        if $guard.deleted {
            return Err(HsmError::InvalidKey);
        }
    };
}

mod aes;
mod ecc;
mod hash;
mod hmac;
mod kdf;
mod rsa;
mod secret;

pub use aes::*;
pub use ecc::*;
pub use hash::*;
pub use hmac::*;
pub use kdf::*;
pub use rsa::*;
pub use secret::*;

use super::*;

pub(crate) trait HsmKeyHandleDelOp: Copy + PartialEq {
    /// Deletes a key from the HSM with epoch-aware barrier protection.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session used to perform the deletion.
    /// * `handle` - The key handle identifying the key in the HSM.
    /// * `epoch` - The restore epoch at which this handle was created or
    ///   last refreshed. Used by [`ddi::delete_key`] to skip the DDI call
    ///   when the device has been reset (epoch has advanced).
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, otherwise an [`HsmError`].
    fn delete_key(session: HsmSession, handle: Self, epoch: u64) -> Result<(), HsmError>;
}

impl HsmKeyHandleDelOp for ddi::HsmKeyHandle {
    fn delete_key(session: HsmSession, handle: Self, epoch: u64) -> Result<(), HsmError> {
        ddi::delete_key(&session, handle, epoch)
    }
}

impl HsmKeyHandleDelOp for (ddi::HsmKeyHandle, ddi::HsmKeyHandle) {
    fn delete_key(session: HsmSession, handle: Self, epoch: u64) -> Result<(), HsmError> {
        let res1 = ddi::delete_key(&session, handle.0, epoch);
        let res2 = ddi::delete_key(&session, handle.1, epoch);
        res1.and(res2)
    }
}

/// Shared state for HSM-backed key wrapper types.
///
/// Many of the typed N-API/Rust wrappers (AES/HMAC/RSA/etc.) are *thin handles* to
/// keys that live inside the HSM. Those typed wrappers often need to convert between
/// each other (e.g. a generic key handle into a typed AES key) without creating a
/// second owner that would double-delete the underlying device handle.
///
/// `HsmKeyInner` is that single shared owner:
/// - It holds the `session` used to talk to the device.
/// - It holds the device `handle` that identifies the key.
/// - It holds the `props` returned by the device for the key.
/// - It tracks whether deletion has already been performed.
///
/// Typed wrappers contain an `Arc<RwLock<HsmKeyInner>>`, so cloning a wrapper clones
/// only the pointer, not the device key.
pub(crate) struct HsmKeyInner<H: HsmKeyHandleDelOp> {
    /// Session used to perform operations on (and delete) the key.
    session: HsmSession,
    /// Device-reported key properties.
    props: HsmKeyProps,
    /// Opaque device handle for the key.
    handle: H,
    /// Whether the key has already been deleted.
    deleted: bool,
    /// Partition restore epoch at which this handle was last created or
    /// refreshed. Compared against `HsmPartition::restore_epoch()` before
    /// every DDI call to detect stale handles and prevent the ABA problem
    /// where a handle index is reused for a different key after a resiliency event.
    last_restore_epoch: u64,
}

impl<H: HsmKeyHandleDelOp> HsmKeyInner<H> {
    /// Constructs the shared key state.
    ///
    /// This is only called by typed key wrapper constructors/macros after a key is
    /// created or imported into the HSM and a valid handle + properties are known.
    fn new(session: HsmSession, props: HsmKeyProps, handle: H) -> Self {
        let epoch = session.partition().restore_epoch();
        Self {
            session,
            props,
            handle,
            deleted: false,
            last_restore_epoch: epoch,
        }
    }

    /// Returns the underlying device handle for this key.
    ///
    /// The handle is opaque and only meaningful to the DDI/device layer.
    fn handle(&self) -> H {
        self.handle
    }

    /// Returns the device-reported key properties.
    fn key_props(&self) -> &HsmKeyProps {
        &self.props
    }

    /// Returns the partition restore epoch at which this handle was last
    /// created or refreshed.
    fn last_restore_epoch(&self) -> u64 {
        self.last_restore_epoch
    }

    /// Deletes the device-side key handle.
    ///
    /// This is idempotent: after successful deletion, subsequent calls return `Ok(())`.
    /// The `deleted` flag also prevents `Drop` from attempting deletion again.
    ///
    /// After a resiliency event, the device key table is wiped.
    /// If this handle is stale (its epoch is behind the
    /// partition's restore epoch), the DDI call is skipped to avoid the
    /// ABA problem where a recycled handle index addresses a different key.
    fn delete_key(&mut self) -> Result<(), HsmError> {
        if self.deleted {
            return Ok(());
        }
        H::delete_key(self.session.clone(), self.handle, self.last_restore_epoch)?;
        self.deleted = true;
        Ok(())
    }

    /// Replaces the key handle and properties after an unmask operation.
    ///
    /// Called during key-operation resiliency recovery to restore a stale
    /// handle that was invalidated by a resiliency event.
    ///
    /// The old handle is not deleted: the resiliency event already wiped
    /// the device key table, so the old index is either gone or has been
    /// recycled for a different key's fresh handle.
    fn restore(&mut self, handle: H, props: HsmKeyProps, epoch: u64) {
        debug_assert!(
            epoch >= self.last_restore_epoch,
            "HsmKeyInner::restore: new epoch ({epoch}) < old epoch ({}); \
             epoch must never go backwards",
            self.last_restore_epoch,
        );
        self.handle = handle;
        self.props = props;
        self.deleted = false;
        self.last_restore_epoch = epoch;
    }
}

impl<H: HsmKeyHandleDelOp> Drop for HsmKeyInner<H> {
    fn drop(&mut self) {
        if !self.deleted {
            let _ = H::delete_key(self.session.clone(), self.handle, self.last_restore_epoch);
        }
    }
}

macro_rules! define_hsm_key {
    ($vis:vis $name:ident) => {
        define_hsm_key!($vis $name, ddi::HsmKeyHandle);

        // Single-handle keys get a standard restore_from_masked
        // implementation using ddi::unmask_key.
        #[allow(unused)]
        impl $name {
            /// Restores the device handle by unmasking the key's cached
            /// masked-key blob.
            ///
            /// Used during key-operation resiliency recovery after a live
            /// migration or firmware crash recovery event invalidates the
            /// current device handle.
            pub(crate) fn restore_from_masked(&self) -> HsmResult<()> {
                acquire_restore_guard!(self => session, part_restore_epoch, inner);

                let masked_key = inner.key_props()
                    .masked_key()
                    .ok_or(HsmError::InternalError)?
                    .to_vec();
                let (new_handle, new_props) = ddi::unmask_key_raw_no_res(&session, &masked_key)?;
                inner.restore(new_handle, new_props, part_restore_epoch);
                Ok(())
            }
        }
    };
    ($vis:vis $name:ident, $handle_ty:ty) => {
        pastey::paste! {
            /// Represents a $name key stored in the HSM.
            #[derive(Clone)]
            $vis struct $name {
                inner: std::sync::Arc<parking_lot::RwLock<HsmKeyInner<$handle_ty>>>,
            }

            #[allow(unused)]
            impl $name {
                /// Creates a new instance of the $name .
                ///
                /// # Arguments
                ///
                /// * `session` - The HSM session associated with the key.
                /// * `props` - The properties of the key.
                /// * `handle` - The handle identifying the key in the HSM.
                ///
                /// # Returns
                /// A new $name instance.
                pub(crate)
                fn new(
                    session: HsmSession,
                    props: HsmKeyProps,
                    handle: $handle_ty,
                ) -> Self {
                    Self {
                        inner: std::sync::Arc::new(parking_lot::RwLock::new(HsmKeyInner::<$handle_ty>::new(
                            session, props, handle,
                        ))),
                    }
                }

                /// Returns a clone of the shared key state for safe cross-type conversions.
                pub(crate) fn inner(
                    &self,
                ) -> std::sync::Arc<parking_lot::RwLock<HsmKeyInner<$handle_ty>>> {
                    self.inner.clone()
                }

                /// Creates a typed key wrapper from existing shared key state.
                pub(crate) fn from_inner(
                    inner: std::sync::Arc<parking_lot::RwLock<HsmKeyInner<$handle_ty>>>,
                ) -> Self {
                    Self { inner }
                }

                /// Returns the key handle.
                pub(crate) fn handle(&self) -> $handle_ty {
                    self.inner.read().handle()
                }

                /// Returns the partition restore epoch at which this
                /// key's device handle was last created or restored.
                pub(crate) fn last_restore_epoch(&self) -> u64 {
                    self.inner.read().last_restore_epoch()
                }

                /// Returns the session ID.
                pub(crate) fn sess_id(&self) -> u16 {
                    self.with_session(|s| s.id())
                }

                /// Returns the HSM session.
                pub(crate) fn session(&self) -> HsmSession {
                    self.with_session(|s| s.clone())
                }

                /// Returns the key properties.
                pub(crate) fn props(&self) -> HsmKeyProps {
                    let guard = self.inner.read();
                    guard.key_props().clone()
                }

                /// Returns the API revision.
                pub(crate) fn api_rev(&self) -> HsmApiRev {
                    self.with_session(|s| s.api_rev())
                }

                /// Executes a closure with access to the HSM session.
                ///
                /// # Arguments
                ///
                /// * `f` - The closure to execute with the session.
                ///
                /// # Returns
                /// The result of the closure execution.
                pub(crate) fn with_session<F, R>(&self, f: F) -> R
                where
                    F: FnOnce(&HsmSession) -> R,
                {
                    let guard = self.inner.read();
                    f(&guard.session)
                }

                /// Executes a closure with access to the HSM device.
                ///
                /// # Arguments
                ///
                /// * `f` - The closure to execute with the device.
                ///
                /// # Returns
                ///
                /// The result of the closure execution.
                pub(crate) fn with_dev<F, R>(&self, f: F) -> HsmResult<R>
                where
                    F: FnOnce(&crate::ddi::HsmDev) -> HsmResult<R>,
                {
                    self.with_session(|s| s.with_dev(f))
                }
            }

            impl HsmKey for $name {}

            impl HsmKeyCommonProps for $name {}

            impl HsmKeyPropsProvider for $name {
                fn with_props<F, R>(&self, f: F) -> R
                where
                    F: FnOnce(&HsmKeyProps) -> R,
                {
                    let guard = self.inner.read();
                    f(guard.key_props())
                }
            }

            impl HsmKeyDeleteOp for $name {
                type Error = HsmError;

                /// Deletes the key from the HSM if applicable.
                fn delete_key(self) -> Result<(), Self::Error> {
                    let mut guard = self.inner.write();
                    guard.delete_key()
                }
            }
        }
    };
}
/// Shared state for paired-key wrapper types (private key + public key).
///
/// This mirrors `HsmKeyInner` but additionally stores the associated public key
/// wrapper so both halves are tied to the same session and lifecycle.
pub(crate) struct HsmKeyPairInner<H: HsmKeyHandleDelOp, P> {
    /// Session used to perform operations on (and delete) the key.
    session: HsmSession,
    /// Device-reported key properties.
    props: HsmKeyProps,
    /// Opaque device handle for the key.
    handle: H,
    /// Associated public key wrapper.
    pub_key: P,
    /// Whether the key has already been deleted.
    deleted: bool,
    /// Partition restore epoch at which this handle was last created or
    /// refreshed.  See [`HsmKeyInner::last_restore_epoch`] for details.
    last_restore_epoch: u64,
}

impl<H: HsmKeyHandleDelOp, P> HsmKeyPairInner<H, P> {
    /// Creates a new instance of the shared key-pair state.
    fn new(session: HsmSession, props: HsmKeyProps, handle: H, pub_key: P) -> Self {
        let epoch = session.partition().restore_epoch();
        Self {
            session,
            props,
            handle,
            pub_key,
            deleted: false,
            last_restore_epoch: epoch,
        }
    }

    /// Returns the key properties.
    fn key_props(&self) -> &HsmKeyProps {
        &self.props
    }

    /// Returns the key handle.
    fn handle(&self) -> H {
        self.handle
    }

    /// Returns the associated public key.
    fn pub_key(&self) -> &P {
        &self.pub_key
    }

    /// Returns the partition restore epoch at which this handle was last
    /// created or refreshed.
    fn last_restore_epoch(&self) -> u64 {
        self.last_restore_epoch
    }

    /// Deletes the key from the HSM.
    ///
    /// After a resiliency event, the device key table is wiped.
    /// If this handle is stale (its epoch is behind the
    /// partition's restore epoch), the DDI call is skipped to avoid the
    /// ABA problem where a recycled handle index addresses a different key.
    fn delete_key(&mut self) -> Result<(), HsmError> {
        if self.deleted {
            return Ok(());
        }
        H::delete_key(self.session.clone(), self.handle, self.last_restore_epoch)?;
        self.deleted = true;
        Ok(())
    }

    /// Replaces the device handle and private-key properties after an
    /// unmask operation during resiliency recovery.
    ///
    /// The public key is not refreshed because it is a software-only
    /// object that remains valid across resiliency events.
    ///
    /// The old handle is not deleted: resiliency events already wiped the device
    /// key table, so the old index is either gone or has been recycled
    /// for a different key's fresh handle.
    fn restore(&mut self, handle: H, props: HsmKeyProps, epoch: u64) {
        debug_assert!(
            epoch >= self.last_restore_epoch,
            "HsmKeyPairInner::restore: new epoch ({epoch}) < old epoch ({}); \
             epoch must never go backwards",
            self.last_restore_epoch,
        );
        self.handle = handle;
        self.props = props;
        self.deleted = false;
        self.last_restore_epoch = epoch;
    }
}

impl<H: HsmKeyHandleDelOp, P> Drop for HsmKeyPairInner<H, P> {
    fn drop(&mut self) {
        if !self.deleted {
            let _ = H::delete_key(self.session.clone(), self.handle, self.last_restore_epoch);
        }
    }
}

macro_rules! define_hsm_key_pair {
    ($priv_vis:vis $priv_name:ident, $pub_vis:vis $pub_name:ident, $pub_key_ty:ty) => {
        pastey::paste! {
            #[derive(Clone)]
            $priv_vis struct [<$priv_name>]
            {
                inner: std::sync::Arc<parking_lot::RwLock<HsmKeyPairInner<ddi::HsmKeyHandle, $pub_name>>>,
            }

            impl [<$priv_name>] {
                /// Creates a new instance of the [<Hsm $name PrivateKey>].
                ///
                /// # Arguments
                ///
                /// * `session` - The HSM session associated with the key.
                /// * `props` - The properties of the key.
                /// * `handle` - The handle identifying the key in the HSM.
                /// * `masked_key` - The masked key material.
                /// * `pub_key` - The associated public key.
                ///
                /// # Returns
                /// A new [<Hsm $name PrivateKey>] instance.
                pub(crate)
                fn new(
                    session: HsmSession,
                    props: HsmKeyProps,
                    handle: ddi::HsmKeyHandle,
                    pub_key: $pub_name,
                ) -> Self {
                    Self {
                        inner: std::sync::Arc::new(parking_lot::RwLock::new(
                            HsmKeyPairInner::new(session, props, handle, pub_key),
                        )),
                    }
                }

                /// Returns the key handle.
                pub(crate) fn handle(&self) -> ddi::HsmKeyHandle {
                    self.inner.read().handle()
                }

                /// Returns the partition restore epoch at which this
                /// key's device handle was last created or restored.
                pub(crate) fn last_restore_epoch(&self) -> u64 {
                    self.inner.read().last_restore_epoch()
                }

                /// Returns the session ID.
                #[allow(unused)]
                pub(crate) fn sess_id(&self) -> u16 {
                    self.with_session(|s| s.id())
                }

                /// Returns the API revision.
                #[allow(unused)]
                pub(crate) fn api_rev(&self) -> HsmApiRev {
                    self.with_session(|s| s.api_rev())
                }

                /// Returns the HSM session.
                #[allow(unused)]
                pub(crate) fn session(&self) -> HsmSession {
                    self.with_session(|s| s.clone())
                }

                /// Executes a closure with access to the HSM session.
                ///
                /// # Arguments
                ///
                /// * `f` - The closure to execute with the session.
                ///
                /// # Returns
                /// The result of the closure execution.
                pub(crate) fn with_session<F, R>(&self, f: F) -> R
                where
                    F: FnOnce(&HsmSession) -> R,
                {
                    let guard = self.inner.read();
                    f(&guard.session)
                }

                /// Executes a closure with access to the HSM device.
                ///
                /// # Arguments
                ///
                /// * `f` - The closure to execute with the device.
                ///
                /// # Returns
                ///
                /// The result of the closure execution.
                pub(crate) fn with_dev<F, R>(&self, f: F) -> HsmResult<R>
                where
                    F: FnOnce(&crate::ddi::HsmDev) -> HsmResult<R>,
                {
                    self.with_session(|s| s.with_dev(f))
                }

                /// Restores the device handle by unmasking the key pair's
                /// cached masked-key blob.
                ///
                /// Only the private-key handle and properties are updated.
                /// The public key is a software-only object and remains valid
                /// across resiliency events.
                pub(crate) fn restore_from_masked(&self) -> HsmResult<()> {
                    acquire_restore_guard!(self => session, part_restore_epoch, inner);

                    let old_props = inner.key_props().clone();
                    let masked_key = old_props
                        .masked_key()
                        .ok_or(HsmError::InternalError)?
                        .to_vec();
                    let (new_handle, new_props, _pub_props) =
                        ddi::refresh_key_pair_raw_no_res(&session, &old_props, &masked_key)?;
                    inner.restore(new_handle, new_props, part_restore_epoch);
                    Ok(())
                }
            }

            impl HsmKey for [<$priv_name>] {}

            impl HsmPrivateKey for [<$priv_name>] {
                type PublicKey = $pub_name;

                /// Returns the associated public key.
                fn public_key(&self) -> Self::PublicKey {
                    let guard = self.inner.read();
                    guard.pub_key().clone()
                }
            }

            impl HsmKeyCommonProps for [<$priv_name>] {}

            impl HsmKeyPropsProvider for [<$priv_name>] {
                fn with_props<F, R>(&self, f: F) -> R
                where
                    F: FnOnce(&HsmKeyProps) -> R,
                {
                    let inner = self.inner.read();
                    f(inner.key_props())
                }
            }

            impl HsmKeyDeleteOp for $priv_name {
                type Error = HsmError;

                /// Deletes the key from the HSM if applicable.
                fn delete_key(self) -> Result<(), Self::Error> {
                    let mut guard = self.inner.write();
                    guard.delete_key()
                }
            }

            #[derive(Clone)]
            $pub_vis struct [<$pub_name>] {
                inner: std::sync::Arc<parking_lot::RwLock<[<$pub_name Inner>]>>,
            }

            impl [<$pub_name>] {
                /// Creates a new instance of the [<$pub_name>].
                ///
                /// # Arguments
                ///
                /// * `props` - The properties of the key.
                /// * `crypto_key` - crypto key
                ///
                /// # Returns
                /// A new [<$pub_name>] instance.
                pub(crate) fn new(props: HsmKeyProps, crypto_key: $pub_key_ty) -> Self {
                    Self {
                        inner: std::sync::Arc::new(parking_lot::RwLock::new([<$pub_name Inner>]::new(
                            props, crypto_key,
                        ))),
                    }
                }

                /// Executes a closure with access to the crypto key.
                ///
                /// # Arguments
                ///
                /// * `f` - The closure to execute with the crypto key.
                ///
                /// # Returns
                ///
                /// The result of the closure execution.
                pub(crate) fn with_crypto_key<F, R>(&self, f: F) -> R
                where
                    F: FnOnce(&$pub_key_ty) -> R,
                {
                    let guard = self.inner.read();
                    f(guard.crypto_key())
                }
            }

            impl HsmKey for [<$pub_name>] {}

            impl HsmPublicKey for [<$pub_name>] {}

            impl HsmKeyCommonProps for [<$pub_name>] {}

            impl HsmKeyPropsProvider for [<$pub_name>] {
                fn with_props<F, R>(&self, f: F) -> R
                where
                    F: FnOnce(&HsmKeyProps) -> R,
                {
                    let inner = self.inner.read();
                    f(inner.key_props())
                }
            }

            impl HsmKeyDeleteOp for $pub_name {
                type Error = HsmError;

                /// Deletes the key from the HSM if applicable.
                ///
                /// Public-key wrappers created by this macro do not own a device-side
                /// key handle. They hold a software `crypto_key` plus properties, so
                /// there is nothing to delete in the HSM and this is intentionally a
                /// no-op.
                fn delete_key(self) -> Result<(), Self::Error> {
                    Ok(())
                }
            }

            #[derive(Clone)]
            struct [<$pub_name Inner>] {
                props: HsmKeyProps,
                crypto_key: $pub_key_ty,
            }

            impl [<$pub_name Inner>] {
                /// Creates a new instance of the [<$pub_name>].
                ///
                /// # Arguments
                ///
                /// * `props` - The properties of the key.
                /// * `crypto_key` - crypto key
                ///
                /// # Returns
                /// A new [<$pub_name>] instance.
                fn new(props: HsmKeyProps, crypto_key: $pub_key_ty) -> Self {
                    Self { props, crypto_key }
                }

                /// Returns the key properties.
                fn key_props(&self) -> &HsmKeyProps {
                    &self.props
                }

                /// Returns the crypto key.
                fn crypto_key(&self) -> &$pub_key_ty {
                    &self.crypto_key
                }
            }
        }
    };
}

pub(crate) use define_hsm_key;
pub(crate) use define_hsm_key_pair;
