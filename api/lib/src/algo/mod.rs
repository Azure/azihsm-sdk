// Copyright (C) Microsoft Corporation. All rights reserved.

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
pub(crate) struct HsmKeyInner {
    /// Session used to perform operations on (and delete) the key.
    session: HsmSession,
    /// Device-reported key properties.
    props: HsmKeyProps,
    /// Opaque device handle for the key.
    handle: ddi::HsmKeyHandle,
    /// Whether the key has already been deleted.
    deleted: bool,
}

impl HsmKeyInner {
    /// Constructs the shared key state.
    ///
    /// This is only called by typed key wrapper constructors/macros after a key is
    /// created or imported into the HSM and a valid handle + properties are known.
    fn new(session: HsmSession, props: HsmKeyProps, handle: ddi::HsmKeyHandle) -> Self {
        Self {
            session,
            props,
            handle,
            deleted: false,
        }
    }

    /// Returns the underlying device handle for this key.
    ///
    /// The handle is opaque and only meaningful to the DDI/device layer.
    fn handle(&self) -> ddi::HsmKeyHandle {
        self.handle
    }

    /// Returns the device-reported key properties.
    fn key_props(&self) -> &HsmKeyProps {
        &self.props
    }

    /// Deletes the device-side key handle.
    ///
    /// This is idempotent: after successful deletion, subsequent calls return `Ok(())`.
    /// The `deleted` flag also prevents `Drop` from attempting deletion again.
    fn delete_key(&mut self) -> Result<(), HsmError> {
        // Idempotent deletion: safe to call multiple times.
        if self.deleted {
            return Ok(());
        }
        ddi::delete_key(&self.session, self.handle)?;
        self.deleted = true;
        Ok(())
    }
}

impl Drop for HsmKeyInner {
    fn drop(&mut self) {
        // Best-effort cleanup: dropping should never panic.
        if !self.deleted {
            let _ = ddi::delete_key(&self.session, self.handle);
        }
    }
}

macro_rules! define_hsm_key {
    ($vis:vis $name:ident) => {
        pastey::paste! {
            /// Represents a $name key stored in the HSM.
            #[derive(Clone)]
            $vis struct $name {
                inner: std::sync::Arc<std::sync::RwLock<HsmKeyInner>>,
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
                    handle: ddi::HsmKeyHandle,
                ) -> Self {
                    Self {
                        inner: std::sync::Arc::new(std::sync::RwLock::new(HsmKeyInner::new(
                            session, props, handle,
                        ))),
                    }
                }

                /// Returns a clone of the shared key state for safe cross-type conversions.
                pub(crate) fn inner(
                    &self,
                ) -> std::sync::Arc<std::sync::RwLock<HsmKeyInner>> {
                    self.inner.clone()
                }

                /// Creates a typed key wrapper from existing shared key state.
                pub(crate) fn from_inner(
                    inner: std::sync::Arc<std::sync::RwLock<HsmKeyInner>>,
                ) -> Self {
                    Self { inner }
                }

                /// Returns the key handle.
                pub(crate) fn handle(&self) -> ddi::HsmKeyHandle {
                    self.inner.read().unwrap().handle()
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
                    let guard = self.inner.read().unwrap();
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
                    let guard = self.inner.read().unwrap();
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
                    let guard = self.inner.read().unwrap();
                    f(guard.key_props())
                }
            }

            impl HsmKeyDeleteOp for $name {
                type Error = HsmError;

                /// Deletes the key from the HSM if applicable.
                fn delete_key(self) -> Result<(), Self::Error> {
                    let mut guard = self.inner.write().unwrap();
                    guard.delete_key()
                }
            }
        }
    };
}

macro_rules! define_hsm_key_pair {
    ($priv_vis:vis $priv_name:ident, $pub_vis:vis $pub_name:ident, $pub_key_ty:ty) => {
        pastey::paste! {
            #[derive(Clone)]
            $priv_vis struct [<$priv_name>]
            {
                inner: std::sync::Arc<std::sync::RwLock<[<$priv_name Inner>]>>,
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
                        inner: std::sync::Arc::new(std::sync::RwLock::new([<$priv_name Inner>]::new(
                            session, props, handle, pub_key,
                        ))),
                    }
                }

                /// Returns the key handle.
                pub(crate) fn handle(&self) -> ddi::HsmKeyHandle {
                    self.inner.read().unwrap().handle()
                }

                /// Returns the session ID.
                pub(crate) fn sess_id(&self) -> u16 {
                    self.with_session(|s| s.id())
                }

                /// Returns the API revision.
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
                    let guard = self.inner.read().unwrap();
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

            impl HsmKey for [<$priv_name>] {}

            impl HsmPrivateKey for [<$priv_name>] {
                type PublicKey = $pub_name;

                /// Returns the associated public key.
                fn public_key(&self) -> Self::PublicKey {
                    let guard = self.inner.read().unwrap();
                    guard.pub_key().clone()
                }
            }

            impl HsmKeyCommonProps for [<$priv_name>] {}

            impl HsmKeyPropsProvider for [<$priv_name>] {
                fn with_props<F, R>(&self, f: F) -> R
                where
                    F: FnOnce(&HsmKeyProps) -> R,
                {
                    let inner = self.inner.read().unwrap();
                    f(inner.key_props())
                }
            }

            impl HsmKeyDeleteOp for $priv_name {
                type Error = HsmError;

                /// Deletes the key from the HSM if applicable.
                fn delete_key(self) -> Result<(), Self::Error> {
                    let mut guard = self.inner.write().unwrap();
                    guard.delete_key()
                }
            }

            impl HsmKeyReportOp for $priv_name {
                type Error = HsmError;

                /// Generates an attestation report for the key.
                fn generate_key_report(
                    &mut self,
                    report_data: &[u8],
                    report: Option<&mut [u8]>
                ) -> Result<usize, Self::Error> {
                    let handle = self.handle();
                    self.with_session(|s| {
                         ddi::generate_key_report(s, handle, report_data, report)
                    })
                }
            }

            struct [<$priv_name Inner>] {
                session: HsmSession,
                props: HsmKeyProps,
                handle: ddi::HsmKeyHandle,
                pub_key: $pub_name,
                deleted: bool,
            }

            impl [<$priv_name Inner>] {
                /// Creates a new instance of the inner private key structure.
                ///
                /// # Arguments
                ///
                /// * `session` - The HSM session associated with the key.
                /// * `props` - The properties of the key.
                /// * `handle` - The handle identifying the key in the HSM.
                /// * `pub_key` - The associated public key.
                ///
                /// # Returns
                ///
                /// A new instance of the inner private key structure.
                fn new(
                    session: HsmSession,
                    props: HsmKeyProps,
                    handle: ddi::HsmKeyHandle,
                    pub_key: $pub_name,
                ) -> Self {
                    Self {
                        session,
                        props,
                        handle,
                        pub_key,
                        deleted: false,
                    }
                }

                // Returns the key properties.
                fn key_props(&self) -> &HsmKeyProps {
                    &self.props
                }

                /// Returns the key handle.
                fn handle(&self) -> ddi::HsmKeyHandle {
                    self.handle
                }

                /// Returns the associated public key.
                fn pub_key(&self) -> &$pub_name {
                    &self.pub_key
                }

                /// Deletes the key from the HSM if it is not a session key.
                fn delete_key(&mut self) -> Result<(), HsmError> {
                    if self.deleted {
                        return Ok(());
                    }
                    ddi::delete_key(&self.session, self.handle)?;
                    self.deleted = true;
                    Ok(())
                }
            }

            impl Drop for [<$priv_name Inner>] {
                /// Cleans up the key from the HSM if it is a session key.
                fn drop(&mut self) {
                    if !self.deleted {
                        let _ = ddi::delete_key(&self.session, self.handle);
                    }
                }
            }

            #[derive(Clone)]
            $pub_vis struct [<$pub_name>] {
                inner: std::sync::Arc<std::sync::RwLock<[<$pub_name Inner>]>>,
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
                        inner: std::sync::Arc::new(std::sync::RwLock::new([<$pub_name Inner>]::new(
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
                    let guard = self.inner.read().unwrap();
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
                    let inner = self.inner.read().unwrap();
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
