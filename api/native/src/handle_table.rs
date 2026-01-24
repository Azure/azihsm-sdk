// Copyright (C) Microsoft Corporation. All rights reserved.
#![allow(dead_code)]
use std::collections::HashMap;

use parking_lot::RwLock;

use super::*;

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum HandleType {
    PartitionList,
    Partition,
    Session,
    AesKey,
    AesCbcEncryptCtx,
    AesCbcDecryptCtx,
    EccPrivKey,
    EccPubKey,
    EccSignCtx,
    EccVerifyCtx,
    RsaPrivKey,
    RsaPubKey,
    ShaCtx,
    HmacKey,
    HmacSignCtx,
    HmacVerifyCtx,
    GenericSecretKey,
    RsaSignCtx,
    RsaVerifyCtx,
}

struct Entry {
    handle_type: HandleType,
    addr: usize,
}

/// Handle table
#[derive(Default)]
pub(crate) struct HandleTable {
    table: RwLock<HandleTableInner>,
}

impl HandleTable {
    pub(crate) fn alloc_handle<T>(&self, handle_type: HandleType, obj: Box<T>) -> AzihsmHandle {
        let mut table = self.table.write();
        table.alloc_handle(handle_type, obj)
    }

    #[allow(unsafe_code)]
    pub(crate) fn as_ref<T>(
        &self,
        handle: AzihsmHandle,
        handle_type: HandleType,
    ) -> Result<&T, AzihsmStatus> {
        let table = self.table.read();
        table.as_ref(handle, handle_type)
    }

    #[allow(unsafe_code)]
    pub fn as_mut<T>(
        &self,
        handle: AzihsmHandle,
        handle_type: HandleType,
    ) -> Result<&mut T, AzihsmStatus> {
        let mut table = self.table.write();
        table.as_mut(handle, handle_type)
    }

    #[allow(unsafe_code)]
    pub(crate) fn free_handle<T>(
        &self,
        handle: AzihsmHandle,
        handle_type: HandleType,
    ) -> Result<Box<T>, AzihsmStatus> {
        let mut table = self.table.write();
        table.free_handle(handle, handle_type)
    }

    /// Frees a handle without requiring the concrete type.
    ///
    /// This is used for generic cleanup operations where the caller
    /// doesn't need to recover the underlying object.
    pub(crate) fn drop_handle(&self, handle: AzihsmHandle) -> Result<(), AzihsmStatus> {
        let mut table = self.table.write();
        table
            .table
            .remove(&handle)
            .ok_or(AzihsmStatus::InvalidHandle)?;
        Ok(())
    }

    /// Get the handle type for a given handle.
    ///
    /// # Parameters
    /// * `handle` - The handle to look up.
    ///
    /// # Returns
    /// * `Ok(HandleType)` - The type of the handle
    /// * `Err(AzihsmError)` - If the handle is invalid
    pub(crate) fn get_handle_type(&self, handle: AzihsmHandle) -> Result<HandleType, AzihsmStatus> {
        let table = self.table.read();
        table.get_handle_type(handle)
    }
}

#[derive(Default)]
struct HandleTableInner {
    table: HashMap<AzihsmHandle, Entry>,
    id_counter: AzihsmHandle,
}

impl HandleTableInner {
    fn alloc_handle<T>(&mut self, handle_type: HandleType, obj: Box<T>) -> AzihsmHandle {
        while self.id_counter == AzihsmHandle(0) || self.table.contains_key(&self.id_counter) {
            self.id_counter += 1;
        }
        let id = self.id_counter;
        let addr = Box::leak(obj) as *mut T as usize;
        self.table.insert(id, Entry { handle_type, addr });
        id
    }

    fn addr(&self, handle: AzihsmHandle, handle_type: HandleType) -> Result<usize, AzihsmStatus> {
        self.table
            .get(&handle)
            .filter(|entry| entry.handle_type == handle_type)
            .map(|entry| entry.addr)
            .ok_or(AzihsmStatus::InvalidHandle)
    }

    #[allow(unsafe_code)]
    fn as_ref<'a, T>(
        &self,
        handle: AzihsmHandle,
        handle_type: HandleType,
    ) -> Result<&'a T, AzihsmStatus> {
        self.addr(handle, handle_type)
            // SAFETY: The caller must ensure that the handle is valid and points to a valid object.
            .map(|addr| unsafe { &*(addr as *const T) })
    }

    #[allow(unsafe_code)]
    fn as_mut<'a, T>(
        &mut self,
        handle: AzihsmHandle,
        handle_type: HandleType,
    ) -> Result<&'a mut T, AzihsmStatus> {
        self.addr(handle, handle_type)
            // SAFETY: The caller must ensure that the handle is valid and points to a valid object.
            .map(|addr| unsafe { &mut *(addr as *mut T) })
    }

    #[allow(unsafe_code)]
    fn free_handle<T>(
        &mut self,
        handle: AzihsmHandle,
        handle_type: HandleType,
    ) -> Result<Box<T>, AzihsmStatus> {
        match self.table.remove(&handle) {
            Some(entry) if entry.handle_type == handle_type => {
                // SAFETY: The entry has been removed from the table, so we own the pointer.
                Ok(unsafe { Box::from_raw(entry.addr as *mut T) })
            }
            _ => Err(AzihsmStatus::InvalidHandle),
        }
    }

    /// Get the handle type for a given handle.
    fn get_handle_type(&self, handle: AzihsmHandle) -> Result<HandleType, AzihsmStatus> {
        self.table
            .get(&handle)
            .map(|entry| entry.handle_type)
            .ok_or(AzihsmStatus::InvalidHandle)
    }
}

/// Frees a handle and releases associated resources.
///
/// The handle is invalidated and must not be used after this call.
///
/// # Returns
///
/// * `AZIHSM_STATUS_SUCCESS` - Handle freed successfully
/// * `AZIHSM_STATUS_INVALID_HANDLE` - Invalid or already freed handle
#[unsafe(no_mangle)]
#[allow(unsafe_code)]
pub unsafe extern "C" fn azihsm_free_handle(handle: AzihsmHandle) -> AzihsmStatus {
    abi_boundary(|| HANDLE_TABLE.drop_handle(handle))
}
