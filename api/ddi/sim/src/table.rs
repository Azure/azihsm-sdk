// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for Table. This is analogous to resource group in the physical Manticore.
//! It stores the keys and their metadata. There can be maximum 256 keys in a table
//! with a maximum of 16 KB of key data.

use std::sync::Arc;
use std::sync::Weak;
use std::time::Instant;

use parking_lot::RwLock;
use tracing::instrument;
use uuid::Uuid;

use self::entry::key::Key;
use self::entry::Entry;
use self::entry::EntryFlags;
use self::entry::Kind;
use crate::errors::ManticoreError;
use crate::vault::APP_ID_FOR_INTERNAL_KEYS;

pub(crate) mod entry;

pub(crate) const MAX_TABLE_KEY_COUNT: usize = 256;
pub(crate) const MAX_TABLE_BYTES: usize = 16 * 1024; // 16 KB
pub(crate) const KEY_LAZY_DELETE_TIMEOUT_IN_SECONDS: u64 = 2;

/// Table is a collection of keys and their metadata.
#[derive(Debug)]
pub(crate) struct Table {
    inner: Arc<RwLock<TableInner>>,
}

impl Table {
    /// Creates a new Table.
    ///
    /// # Returns
    /// * `Table` - A new Table.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(TableInner::new())),
        }
    }

    #[allow(unused)]
    fn with_inner(inner: Arc<RwLock<TableInner>>) -> Self {
        Self { inner }
    }

    #[allow(unused)]
    fn as_weak(&self) -> TableWeak {
        TableWeak::new(Arc::downgrade(&self.inner))
    }

    /// Adds a new key to the table.
    ///
    /// # Arguments
    /// * `app_id` - The app id of the key.
    /// * `kind` - The kind of the key.
    /// * `key` - The key.
    /// * `flags` - The flags for the key.
    /// * `sess_id_or_key_tag` - If a session_only key, the ID of the app session. If a app key, the tag of the key
    ///
    /// # Returns
    /// * `u8` - The index of the key in the table.
    ///
    /// # Errors
    /// * `ManticoreError::NotEnoughSpace` - If there is not enough space in the table for the key. It could be either because we reached 256 keys or 16 KB of key data.
    #[instrument(skip_all, fields(app_id = ?app_id, sess_id_or_key_tag))]
    pub(crate) fn add(
        &self,
        app_id: Uuid,
        kind: Kind,
        key: Key,
        flags: EntryFlags,
        sess_id_or_key_tag: u16,
    ) -> Result<u8, ManticoreError> {
        self.inner
            .write()
            .add(app_id, kind, key, flags, sess_id_or_key_tag)
    }

    pub(crate) fn get_session_count(&self) -> usize {
        // Search all entries with kind = Session

        self.inner
            .read()
            .entries
            .iter()
            .filter(|e| {
                if let Some(entry) = e {
                    entry.kind() == Kind::Session
                } else {
                    false
                }
            })
            .count()
    }

    /// Removes a key from the table.
    ///
    /// # Arguments
    /// * `index` - The index of the key in the table.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidKeyIndex` - If the index is invalid.
    /// * `ManticoreError::CannotDeleteKeyInUse` - The key could not be immediately deleted since the key is currently in use. Please try again later. However, the was disabled and new tasks cannot use the key anymore.
    ///
    /// # Behavior
    /// If the key is not in use, it will be deleted immediately.
    /// If the key is currently in use, it will be disabled for new uses instead of being deleted. New tasks cannot use the key anymore. Existing refernces can still continue to use the key.
    /// The key will only be deleted when the function is called again and the key is no longer in use.
    #[instrument(skip(self))]
    pub(crate) fn remove(&self, index: u8) -> Result<(), ManticoreError> {
        self.inner.write().remove(index)
    }

    /// Removes all session_only keys of a given app session from the table.
    ///
    /// # Arguments
    /// * `app_session_id` - ID of the App Session for which the session_only keys will be removed.
    ///
    /// # Returns
    /// * `u16` - The number of keys successfully removed
    ///
    /// # Errors
    /// * `ManticoreError::CannotDeleteKeyInUse` - If the key cannot be deleted.
    #[instrument(skip(self))]
    pub(crate) fn remove_all_session_only_keys(
        &self,
        app_session_id: u16,
    ) -> Result<u16, ManticoreError> {
        self.inner
            .write()
            .remove_all_session_only_keys(app_session_id)
    }

    /// Gets a key entry from the table.
    ///
    /// # Arguments
    /// * `index` - The index of the key in the table.
    ///
    /// # Returns
    /// * `Entry` - The key entry.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidKeyIndex` - If the index is invalid or the key has been disabled because of a call to remove().
    #[instrument(skip(self))]
    pub(crate) fn get(&self, index: u8) -> Result<Entry, ManticoreError> {
        self.inner.read().get(index)
    }

    /// Gets a key entry from the table.
    ///
    /// # Arguments
    /// * `index` - The index of the key in the table.
    ///
    /// # Returns
    /// * `Entry` - The key entry.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidKeyIndex` - If the index is invalid or the key has been disabled because of a call to remove().
    #[instrument(skip(self))]
    pub(crate) fn get_unchecked(&self, index: u8) -> Result<Entry, ManticoreError> {
        self.inner.read().get_unchecked(index)
    }

    #[instrument(skip(self))]
    pub(crate) fn get_index_by_name(&self, app_id: Uuid, name: u16) -> Result<u8, ManticoreError> {
        self.inner.read().get_index_by_tag(app_id, name)
    }
}

#[derive(Debug)]
struct TableInner {
    used_bytes: usize,
    entries: [Option<Entry>; MAX_TABLE_KEY_COUNT],
}

impl Default for TableInner {
    fn default() -> Self {
        const NONE: Option<Entry> = None;
        let entries: [Option<Entry>; MAX_TABLE_KEY_COUNT] = [NONE; MAX_TABLE_KEY_COUNT];
        Self {
            used_bytes: 0,
            entries,
        }
    }
}

impl TableInner {
    fn new() -> Self {
        Self::default()
    }

    fn add(
        &mut self,
        app_id: Uuid,
        kind: Kind,
        key: Key,
        flags: EntryFlags,
        sess_id_or_key_tag: u16,
    ) -> Result<u8, ManticoreError> {
        // Lets first attempt to lazy delete any keys that have been disabled for more than LAZY_DELETE_TIMEOUT seconds.
        self.lazy_delete();

        let size_needed = kind.size();

        if self.used_bytes + size_needed > MAX_TABLE_BYTES {
            Err(ManticoreError::NotEnoughSpace)?
        }

        // Cannot create a session_only key for the internal app
        if app_id == APP_ID_FOR_INTERNAL_KEYS && flags.session_only() {
            tracing::error!(id = ?app_id, sess_id_or_key_tag, "Cannot create a session_only key for the internal app");
            Err(ManticoreError::InvalidArgument)?
        }

        if !flags.session_only() && sess_id_or_key_tag != 0 {
            let key_tag_exists = self.get_index_by_tag(app_id, sess_id_or_key_tag);
            if key_tag_exists.is_ok() {
                tracing::error!(key_tag = ?sess_id_or_key_tag, "Key tag already exists");
                Err(ManticoreError::KeyTagAlreadyExists)?
            }
        }

        let (index, entry) = self
            .entries
            .iter_mut()
            .enumerate()
            .find(|(_, e)| e.is_none())
            .ok_or(ManticoreError::ReachedMaxKeys)?;

        *entry = Some(Entry::new(app_id, flags, kind, key, sess_id_or_key_tag));
        tracing::debug!(sess_id_or_key_tag, "New Entry created");

        self.used_bytes += size_needed;

        Ok(index as u8)
    }

    fn remove(&mut self, index: u8) -> Result<(), ManticoreError> {
        let entry = self.entries[index as usize].as_mut().ok_or_else(|| {
            tracing::error!(error = ?ManticoreError::InvalidKeyIndex, index, "Invalid key index in the table");
            ManticoreError::InvalidKeyIndex
        })?;

        entry.set_disabled();

        tracing::debug!(index, sess_id = ?entry.sess_id(), key_tag = ?entry.key_tag(), "Entry removed");
        self.used_bytes -= entry.size();
        self.entries[index as usize] = None;
        Ok(())
    }

    fn remove_all_session_only_keys(&mut self, app_session_id: u16) -> Result<u16, ManticoreError> {
        let indexes: Vec<u8> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                if let Some(entry) = e {
                    if entry.session_only() && entry.sess_id() == Some(app_session_id) {
                        return Some(i as u8);
                    }
                }

                None
            })
            .collect();

        let mut delete_count = 0;
        let mut failed_delete_count: u8 = 0;
        for index in indexes {
            match self.remove(index) {
                Ok(_) => delete_count += 1,
                Err(_) => {
                    tracing::error!(
                        index,
                        "Failed to remove during remove_all_session_only_keys"
                    );
                    failed_delete_count += 1;
                }
            }
        }

        match failed_delete_count {
            0 => Ok(delete_count),
            1 => Err(ManticoreError::CannotDeleteKeyInUse)?,
            _ => Err(ManticoreError::CannotDeleteSomeKeysInUse)?,
        }
    }

    fn get_unchecked(&self, index: u8) -> Result<Entry, ManticoreError> {
        let entry = self.entries[index as usize]
            .clone()
            .ok_or_else(|| {
                tracing::error!(error = ?ManticoreError::InvalidKeyIndex, index, "Invalid key index in the table");
                ManticoreError::InvalidKeyIndex
            })?;

        Ok(entry)
    }

    fn get(&self, index: u8) -> Result<Entry, ManticoreError> {
        let entry = self.get_unchecked(index)?;

        if entry.disabled() {
            tracing::debug!(error = ?ManticoreError::InvalidKeyIndex, index, "Entry is disabled");
            Err(ManticoreError::InvalidKeyIndex)?
        }

        Ok(entry)
    }

    fn get_index_by_tag(&self, app_id: Uuid, tag: u16) -> Result<u8, ManticoreError> {
        if tag == 0 {
            Err(ManticoreError::InvalidArgument)?
        }

        let (entry_index, entry) = self
            .entries
            .iter()
            .enumerate()
            .find(|(_, oe)| {
                if let Some(e) = oe {
                    e.app_id() == app_id && e.key_tag() == Some(tag)
                } else {
                    false
                }
            })
            .ok_or(ManticoreError::KeyNotFound)?;

        if let Some(entry) = entry {
            if entry.disabled() {
                tracing::debug!(error = ?ManticoreError::KeyNotFound, tag, "Entry is disabled");
                Err(ManticoreError::KeyNotFound)?
            }

            Ok(entry_index as u8)
        } else {
            Err(ManticoreError::KeyNotFound)
        }
    }

    fn lazy_delete(&mut self) {
        let now = Instant::now();
        let mut entries_to_delete = vec![];

        for (index, entry) in self.entries.iter_mut().enumerate() {
            if let Some(entry) = entry {
                if entry.disabled() {
                    if let Some(disabled_at) = entry.disabled_at() {
                        if now.duration_since(disabled_at).as_secs()
                            >= KEY_LAZY_DELETE_TIMEOUT_IN_SECONDS
                        {
                            entries_to_delete.push(index);
                        }
                    }
                }
            }
        }

        for index in entries_to_delete {
            // Ignore any failures since the key may have been deleted by another thread after the addition to the vector above
            // or the key still may be in use and cannot be deleted.
            let _ = self.remove(index as u8);
        }
    }
}

struct TableWeak {
    #[allow(unused)]
    weak: Weak<RwLock<TableInner>>,
}

impl TableWeak {
    #[allow(unused)]
    fn new(weak: Weak<RwLock<TableInner>>) -> Self {
        Self { weak }
    }

    #[allow(unused)]
    fn upgrade(&self) -> Option<Table> {
        self.weak.upgrade().map(Table::with_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::min;
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::crypto::ecc::generate_ecc;
    use crate::crypto::ecc::EccCurve;
    use crate::crypto::rsa::generate_rsa;
    use crate::crypto::rsa::RsaOp;

    #[test]
    fn test_new() {
        let table = Table::new();
        let table_inner = table.inner.read();

        assert_eq!(table_inner.used_bytes, 0);
        assert_eq!(table_inner.entries.len(), MAX_TABLE_KEY_COUNT);

        assert!(table_inner.entries[0].is_none());
        assert!(table_inner.entries[1].is_none());
        assert!(table_inner.entries[20].is_none());
        assert!(table_inner.entries[MAX_TABLE_KEY_COUNT - 1].is_none());
    }

    #[test]
    fn add_basic() {
        let key_tag = 0x5453;

        let table = Table::new();

        let test_app_id = Uuid::from_bytes([0xa1; 16]);

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();

        for i in 0..2 {
            let index = table
                .add(
                    test_app_id,
                    Kind::Rsa2kPublic,
                    Key::RsaPublic(rsa_public_key.clone()),
                    EntryFlags::default().with_session_only(true),
                    key_tag,
                )
                .unwrap();
            assert_eq!(index, i as u8);
        }

        let table_inner = table.inner.read();

        assert!(table_inner.entries[0].is_some());
        let entry = table_inner.entries[0].as_ref().unwrap();
        assert_eq!(entry.app_id(), test_app_id);
        assert_eq!(entry.kind(), Kind::Rsa2kPublic);
        assert!(matches!(entry.key(), Key::RsaPublic { .. }));

        assert!(table_inner.entries[1].is_some());
        let entry = table_inner.entries[1].as_ref().unwrap();
        assert_eq!(entry.app_id(), test_app_id);
        assert_eq!(entry.kind(), Kind::Rsa2kPublic);
        assert!(matches!(entry.key(), Key::RsaPublic { .. }));

        assert_eq!(table_inner.used_bytes, 2 * Kind::Rsa2kPublic.size());

        assert!(table_inner.entries[2].is_none());
        assert!(table_inner.entries[20].is_none());
        assert!(table_inner.entries[255].is_none());
    }

    #[test]
    fn add_max_keys() {
        let key_tag = 0x5453;

        let table = Table::new();

        let test_app_id = Uuid::from_bytes([0xa1; 16]);

        let (ecc_private_key, _ecc_public_key) = generate_ecc(EccCurve::P256).unwrap();
        let entry_kind = Kind::Ecc256Private;
        let allowed_entry_count = min(MAX_TABLE_BYTES / entry_kind.size(), MAX_TABLE_KEY_COUNT);

        for i in 0..allowed_entry_count {
            let index = table
                .add(
                    test_app_id,
                    entry_kind,
                    Key::EccPrivate(ecc_private_key.clone()),
                    EntryFlags::default().with_session_only(true),
                    key_tag,
                )
                .unwrap();
            assert_eq!(index, i as u8);
        }

        let table_inner = table.inner.read();

        assert!(table_inner.entries[0].is_some());
        assert!(table_inner.entries[3].is_some());
        let last_entry_index = allowed_entry_count - 1;
        assert!(table_inner.entries[last_entry_index].is_some());

        drop(table_inner);

        let error = table
            .add(
                test_app_id,
                entry_kind,
                Key::EccPrivate(ecc_private_key),
                EntryFlags::default(),
                key_tag,
            )
            .unwrap_err();
        assert_eq!(error, ManticoreError::ReachedMaxKeys);
    }

    #[test]
    fn add_max_bytes() {
        let key_tag = 0x5453;

        let table = Table::new();

        let test_app_id = Uuid::from_bytes([0xa1; 16]);

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let entry_kind = Kind::Rsa2kPublic;
        let allowed_entry_count = min(MAX_TABLE_BYTES / entry_kind.size(), MAX_TABLE_KEY_COUNT);

        for i in 0..allowed_entry_count {
            let index = table
                .add(
                    test_app_id,
                    entry_kind,
                    Key::RsaPublic(rsa_public_key.clone()),
                    EntryFlags::default().with_session_only(true),
                    key_tag,
                )
                .unwrap();
            assert_eq!(index, i as u8);
        }

        let table_inner = table.inner.read();

        assert!(table_inner.entries[0].is_some());
        assert!(table_inner.entries[3].is_some());
        let last_entry_index = allowed_entry_count - 1;
        assert!(table_inner.entries[last_entry_index].is_some());

        drop(table_inner);

        let error = table
            .add(
                test_app_id,
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key),
                EntryFlags::default(),
                key_tag,
            )
            .unwrap_err();
        assert_eq!(error, ManticoreError::NotEnoughSpace);
    }

    #[test]
    fn get() {
        let key_tag = 0x5453;

        let table = Table::new();

        let test_app_id = Uuid::from_bytes([0xa1; 16]);

        let (rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        assert!(table
            .add(
                test_app_id,
                Kind::Rsa2kPrivate,
                Key::RsaPrivate(rsa_private_key.clone()),
                EntryFlags::default().with_session_only(true),
                key_tag,
            )
            .is_ok());
        assert!(table
            .add(
                test_app_id,
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                EntryFlags::default().with_session_only(true),
                key_tag,
            )
            .is_ok());

        let entry = table.get(0).unwrap();

        // Ensure that the fields of the entry match.
        assert_eq!(entry.app_id(), test_app_id);
        assert_eq!(entry.kind(), Kind::Rsa2kPrivate);
        assert!(matches!(entry.key(), Key::RsaPrivate(_)));
        if let Key::RsaPrivate(key) = entry.key() {
            assert_eq!(key.to_der(), rsa_private_key.to_der());
        }

        let entry = table.get(1).unwrap();
        assert_eq!(entry.app_id(), test_app_id);
        assert_eq!(entry.kind(), Kind::Rsa2kPublic);
        assert!(matches!(entry.key(), Key::RsaPublic(_)));
        if let Key::RsaPublic(key) = entry.key() {
            assert_eq!(key.to_der(), rsa_public_key.to_der());
        }
    }

    #[test]
    fn remove_basic() {
        let key_tag = 0x5453;

        let table = Table::new();

        let test_app_id = Uuid::from_bytes([0xa1; 16]);

        let (rsa_private_key, rsa_public_key) = generate_rsa(4096).unwrap();

        for i in 0..2 {
            let index = table
                .add(
                    test_app_id,
                    Kind::Rsa4kPrivate,
                    Key::RsaPrivate(rsa_private_key.clone()),
                    EntryFlags::default().with_session_only(true),
                    key_tag,
                )
                .unwrap();
            assert_eq!(index, i as u8);
        }

        let table_inner = table.inner.read();
        assert!(table_inner.entries[0].is_some());
        let old_used_bytes = table_inner.used_bytes;
        drop(table_inner);

        let expected_bytes_freed = Kind::Rsa4kPrivate.size();

        assert!(table.remove(0).is_ok());

        let table_inner = table.inner.read();
        assert_eq!(
            table_inner.used_bytes,
            old_used_bytes - expected_bytes_freed
        );
        assert!(table_inner.entries[0].is_none());
        drop(table_inner);

        let index = table
            .add(
                test_app_id,
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key),
                EntryFlags::default(),
                key_tag,
            )
            .unwrap();
        assert_eq!(index, 0);

        let table_inner = table.inner.read();
        assert!(table_inner.entries[0].is_some());
        let old_used_bytes = table_inner.used_bytes;
        drop(table_inner);
        assert!(table.remove(0).is_ok());

        let expected_bytes_freed = Kind::Rsa2kPublic.size();

        let table_inner = table.inner.read();
        assert_eq!(
            table_inner.used_bytes,
            old_used_bytes - expected_bytes_freed
        );
        assert!(table_inner.entries[0].is_none());
        assert!(table_inner.entries[1].is_some());
        drop(table_inner);

        assert!(table.remove(1).is_ok());

        let table_inner = table.inner.read();
        assert!(table_inner.entries[1].is_none());
        drop(table_inner);

        let table_inner = table.inner.read();
        assert_eq!(table_inner.used_bytes, 0);
    }

    #[test]
    fn remove_invalid_key_index() {
        let key_tag = 0x5453;

        let table = Table::new();

        let test_app_id = Uuid::from_bytes([0xa1; 16]);

        let (rsa_private_key, _rsa_public_key) = generate_rsa(4096).unwrap();

        for i in 0..2 {
            let index = table
                .add(
                    test_app_id,
                    Kind::Rsa4kPrivate,
                    Key::RsaPrivate(rsa_private_key.clone()),
                    EntryFlags::default().with_session_only(true),
                    key_tag,
                )
                .unwrap();
            assert_eq!(index, i as u8);
        }

        let table_inner = table.inner.read();
        assert!(table_inner.entries[0].is_some());
        drop(table_inner);

        assert_eq!(
            table.remove(20).unwrap_err(),
            ManticoreError::InvalidKeyIndex
        );
        assert_eq!(
            table.remove(255).unwrap_err(),
            ManticoreError::InvalidKeyIndex
        );
    }

    #[test]
    fn test_add_remove_entry_in_use() {
        let key_tag = 0x5453;

        let table = Table::new();

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let flags = EntryFlags::new().with_generated(true);
        let kind = Kind::Rsa2kPublic;

        // Fill the table so no space left
        let max_keys = MAX_TABLE_BYTES / kind.size();
        for index in 0..max_keys {
            let app_id = Uuid::from_bytes([index as u8; 16]);
            let res = table.add(
                app_id,
                kind,
                Key::RsaPublic(rsa_public_key.clone()),
                flags,
                key_tag,
            );
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), index as u8);
        }

        let key1_id = 0;
        let key2_id = 5;

        // Hold reference to key1
        let entry = table.get(key1_id).unwrap();

        // Attempt to delete key1
        let res = table.remove(key1_id);
        assert!(res.is_ok());

        // Delete key2
        let res = table.remove(key2_id);
        assert!(res.is_ok());
        let res_after_remove = table.get(key2_id);
        assert!(res_after_remove.is_err());

        // Add and should get added at key2 slot.
        let app_id = Uuid::from_bytes([0xF0; 16]);
        let res = table.add(
            app_id,
            kind,
            Key::RsaPublic(rsa_public_key.clone()),
            flags,
            key_tag,
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), key1_id);

        // Release reference to key1
        drop(entry);

        // Delete key1
        let res = table.remove(key1_id);
        assert!(res.is_ok());
        let res_after_remove = table.get(key1_id);
        assert!(res_after_remove.is_err());

        // Add and should get added at key1 slot.
        let app_id = Uuid::from_bytes([0xF1; 16]);
        let res = table.add(app_id, kind, Key::RsaPublic(rsa_public_key), flags, key_tag);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), key1_id);
    }

    #[test]
    fn test_add_remove_entry_in_use_lazy_delete() {
        let key_tag = 0x5453;

        let table = Table::new();

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();
        let flags = EntryFlags::new().with_generated(true);
        let kind = Kind::Rsa2kPublic;

        // Fill the table so no space left
        let max_keys = MAX_TABLE_BYTES / kind.size();
        for index in 0..max_keys {
            let app_id = Uuid::from_bytes([index as u8; 16]);
            let res = table.add(
                app_id,
                kind,
                Key::RsaPublic(rsa_public_key.clone()),
                flags,
                key_tag,
            );
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), index as u8);
        }

        let key1_id = 0;
        let key2_id = 5;

        // Hold reference to key1
        let entry = table.get(key1_id).unwrap();

        // Attempt to delete key1
        let res = table.remove(key1_id);
        assert!(res.is_ok());

        // Delete key2
        let res = table.remove(key2_id);
        assert!(res.is_ok());
        let res_after_remove = table.get(key2_id);
        assert!(res_after_remove.is_err());

        // Add and should get added at key2 slot.
        let app_id = Uuid::from_bytes([0xF0; 16]);
        let res = table.add(
            app_id,
            kind,
            Key::RsaPublic(rsa_public_key.clone()),
            flags,
            key_tag,
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), key1_id);

        // Release reference to key1
        drop(entry);

        // Sleep for LAZY_DELETE_TIMEOUT_IN_SECONDS seconds to allow lazy delete to kick in during add.
        thread::sleep(Duration::from_secs(KEY_LAZY_DELETE_TIMEOUT_IN_SECONDS));

        // Add and should get added at key1 slot.
        let app_id = Uuid::from_bytes([0xF1; 16]);
        let res = table.add(app_id, kind, Key::RsaPublic(rsa_public_key), flags, key_tag);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), key2_id);
    }

    #[test]
    fn test_remove_session_only_keys_basic() {
        let key_tag = 0x5453;

        let table = Table::new();

        let test_app_id = Uuid::from_bytes([0xa1; 16]);
        let test_app_session_id: u16 = 1;
        let count_session_only_keys: u16 = 2;

        let (rsa_private_key, _rsa_public_key) = generate_rsa(4096).unwrap();

        // Create 2 app keys
        for i in 0..2 {
            let index = table
                .add(
                    test_app_id,
                    Kind::Rsa4kPrivate,
                    Key::RsaPrivate(rsa_private_key.clone()),
                    EntryFlags::default().with_session_only(true),
                    key_tag,
                )
                .unwrap();
            assert_eq!(index, i);
        }

        let mut flags = EntryFlags::default();
        flags.set_session_only(true);
        // Create some session_only keys
        for i in 0..count_session_only_keys {
            let index = table
                .add(
                    test_app_id,
                    Kind::Rsa4kPrivate,
                    Key::RsaPrivate(rsa_private_key.clone()),
                    flags,
                    test_app_session_id,
                )
                .unwrap();
            assert_eq!(index as u16, count_session_only_keys + i);
        }

        let delete_count = table.remove_all_session_only_keys(test_app_session_id);
        assert!(delete_count.is_ok());
        assert_eq!(delete_count.unwrap(), count_session_only_keys);

        // Test that newly added key's index is the same as the deleted session_only key's index
        let index = table
            .add(
                test_app_id,
                Kind::Rsa4kPrivate,
                Key::RsaPrivate(rsa_private_key),
                EntryFlags::default(),
                key_tag,
            )
            .unwrap();

        assert_eq!(index, 2);
    }

    #[test]
    fn test_remove_session_only_keys_in_use() {
        let key_tag = 0x5453;

        let table = Table::new();

        let test_app_id = Uuid::from_bytes([0xa1; 16]);
        let test_app_session_id: u16 = 1;

        let (rsa_private_key, _) = generate_rsa(4096).unwrap();

        let mut flags = EntryFlags::default();
        flags.set_session_only(true);
        // Create some session_only keys
        for i in 0..4 {
            let index = table
                .add(
                    test_app_id,
                    Kind::Rsa4kPrivate,
                    Key::RsaPrivate(rsa_private_key.clone()),
                    flags,
                    test_app_session_id,
                )
                .unwrap();
            assert_eq!(index, i);
        }

        // Hold ref to Entry
        let entry1 = table.get(0).unwrap();
        let entry2 = table.get(1).unwrap();

        let result = table.remove_all_session_only_keys(test_app_session_id);
        assert!(result.is_ok());

        // Test that newly added key's index is the same as the deleted session_only key's index
        let index = table
            .add(
                test_app_id,
                Kind::Rsa4kPrivate,
                Key::RsaPrivate(rsa_private_key),
                EntryFlags::default(),
                key_tag,
            )
            .unwrap();

        assert_eq!(index, 0);

        // Check the keys are disabled
        assert!(entry1.disabled());
        assert!(entry2.disabled());

        // Drop one key and delete again
        {
            drop(entry2);
            let result = table.remove_all_session_only_keys(test_app_session_id);
            assert!(result.is_ok());
        }

        // Drop all keys and delete again
        {
            drop(entry1);
            let result = table.remove_all_session_only_keys(test_app_session_id);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_get_entry_index_by_name() {
        let table = Table::new();

        let test_app_id = Uuid::from_bytes([0xa1; 16]);

        let (_rsa_private_key, rsa_public_key) = generate_rsa(2048).unwrap();

        for i in 0..8 {
            let index = table
                .add(
                    test_app_id,
                    Kind::Rsa2kPublic,
                    Key::RsaPublic(rsa_public_key.clone()),
                    EntryFlags::default(),
                    0,
                )
                .unwrap();
            assert_eq!(index, i as u8);
        }

        let table_inner = table.inner.read();

        assert!(table_inner.entries[0].is_some());
        let entry = table_inner.entries[0].as_ref().unwrap();
        assert_eq!(entry.app_id(), test_app_id);
        assert_eq!(entry.kind(), Kind::Rsa2kPublic);
        assert!(matches!(entry.key(), Key::RsaPublic { .. }));

        assert!(table_inner.entries[1].is_some());
        let entry = table_inner.entries[1].as_ref().unwrap();
        assert_eq!(entry.app_id(), test_app_id);
        assert_eq!(entry.kind(), Kind::Rsa2kPublic);
        assert!(matches!(entry.key(), Key::RsaPublic { .. }));

        assert_eq!(table_inner.used_bytes, 8 * Kind::Rsa2kPublic.size());

        assert!(table_inner.entries[2].is_some());
        assert!(table_inner.entries[3].is_some());
        assert!(table_inner.entries[7].is_some());
        assert!(table_inner.entries[8].is_none());
        assert!(table_inner.entries[20].is_none());
        assert!(table_inner.entries[255].is_none());

        drop(table_inner);
        let key_tag = 0x5453;

        let index = table
            .add(
                test_app_id,
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key.clone()),
                EntryFlags::default(),
                key_tag,
            )
            .unwrap();
        assert_eq!(index, 8);

        let result = table.get_index_by_name(test_app_id, key_tag);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), index);

        let result = table.remove(2);
        assert!(result.is_ok());

        let mut table_inner = table.inner.write();
        table_inner.entries[5].as_mut().unwrap().set_disabled();
        table_inner.entries[6].as_mut().unwrap().set_disabled();

        drop(table_inner);
        thread::sleep(Duration::from_secs(KEY_LAZY_DELETE_TIMEOUT_IN_SECONDS + 1));

        // table add will cause lazy delete to kick in
        let added_key = table
            .add(
                test_app_id,
                Kind::Rsa2kPublic,
                Key::RsaPublic(rsa_public_key),
                EntryFlags::default(),
                0,
            )
            .unwrap();
        assert_eq!(added_key, 2);

        let result = table.get_index_by_name(test_app_id, key_tag);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), index);

        let table_inner = table.inner.read();
        assert!(table_inner.entries[0].is_some());
        assert!(table_inner.entries[1].is_some());
        assert!(table_inner.entries[2].is_some());
        assert!(table_inner.entries[3].is_some());
        assert!(table_inner.entries[4].is_some());
        assert!(table_inner.entries[5].is_none());
        assert!(table_inner.entries[6].is_none());
        assert!(table_inner.entries[7].is_some());
        assert!(table_inner.entries[8].is_some());
        assert!(table_inner.entries[9].is_none());
    }

    // This test helps achieve 100% test coverage
    // as debug trait is mainly used for test purposes
    #[test]
    fn test_debug_trait_print() {
        let table = Table::new();
        println!("Table {:?}", table);

        let table_weak = table.as_weak();
        let table_weak_upgrade = table_weak.upgrade();
        println!("Table {:?}", table_weak_upgrade);
    }
}
