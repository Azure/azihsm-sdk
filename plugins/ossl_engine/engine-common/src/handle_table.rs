// Copyright (C) Microsoft Corporation. All rights reserved.

use std::collections::HashMap;
use std::sync::atomic::*;

use parking_lot::RwLock;

/// A handle to an object.
pub type Handle = usize;

/// A table of objects indexed by handle.
pub struct HandleTable<T: Clone> {
    table: RwLock<HashMap<Handle, T>>,
    next_handle: AtomicUsize,
}

impl<T: Clone> Default for HandleTable<T> {
    /// Returns the "default value" for a type.
    fn default() -> Self {
        Self {
            table: RwLock::new(HashMap::new()),
            next_handle: AtomicUsize::new(1),
        }
    }
}

impl<T: Clone> HandleTable<T> {
    /// Inserts an object into the table and returns a handle to it.
    ///
    /// # Arguments
    ///
    /// * `object` - The object to insert.
    ///
    /// # Returns
    ///
    /// A handle to the object.
    pub fn insert(&self, object: T) -> Handle {
        // Increment the handle by 2 to avoid conflicts with the handle 0.
        let handle = self
            .next_handle
            .fetch_add(2, std::sync::atomic::Ordering::Relaxed);

        self.table.write().insert(handle, object);

        handle
    }

    /// Removes an object from the table and returns it.
    ///
    /// # Arguments
    ///
    /// * `handle` - The handle of the object to remove.
    ///
    /// # Returns
    ///
    /// A handle to the removed object.
    pub fn remove(&self, handle: Handle) -> Option<T> {
        self.table.write().remove(&handle)
    }

    /// Returns the object associated with the handle.
    ///
    /// # Arguments
    ///
    /// * `handle` - The handle of the object to retrieve.
    ///
    /// # Returns
    ///
    /// A handle to the object.
    pub fn get(&self, handle: Handle) -> Option<T> {
        self.table.read().get(&handle).cloned()
    }

    /// Returns a list of all handles in the table.
    ///
    /// # Returns
    ///
    /// List of handles in the table as a vector.
    pub fn handles(&self) -> Vec<Handle> {
        self.table.read().keys().cloned().collect()
    }
}
