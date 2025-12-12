// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module maps physical session IDs to virtual session IDs.

use bitfield::Bit;
use bitfield::BitMut;
use zeroize::Zeroize;

use crate::errors::ManticoreError;
use crate::vault::MAX_SESSIONS;

/// Session indirection table that maps Virtual session ids to Physical sessions
/// ids (in the vault).
/// This aids in live migration, disaster recovery etc. Virtual session ids will
/// remain same to the customer even if the physical session id gets changed.
/// Notes:
/// - Originally named HsmPartSessionTable
/// - This will only be used under protection by RW locks at vault API level.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct SessionTable {
    /// Session Allocation Mask
    session_allocation_mask: u8,

    /// Session Renegotiation Mask
    session_renegotiation_mask: u8,

    /// Session Indirection Table
    table: [u16; MAX_SESSIONS],
}

impl SessionTable {
    /// Create Session Table Object
    ///
    /// # Returns
    ///
    /// `SessionTable` - A new SessionTable Instance
    pub(crate) fn new() -> Self {
        Self {
            session_allocation_mask: 0,
            session_renegotiation_mask: 0,
            table: [0; MAX_SESSIONS],
        }
    }

    /// Back up the current SessionTable allocation mask.
    ///
    /// # Returns
    ///
    /// * `u8` - Mask for which sessions are currently created
    #[allow(unused)]
    pub(crate) fn backup(&self) -> u8 {
        self.session_allocation_mask
    }

    /// Restore the SessionTable mask. This ensures that the session ids remain reserved.
    /// The restored sessions must be reestablished. To reestablish, reestablish credential
    /// DDI API needs to be used by the client.
    ///
    /// # Arguments
    ///
    /// * `mask` - Mask for which sessions were currently created and need to be reestablished
    pub(crate) fn restore(&mut self, mask: u8) {
        self.session_allocation_mask = mask;
        self.session_renegotiation_mask = mask;
        self.table.zeroize();
    }

    /// Get the count of number of sessions that can still be created
    #[cfg(test)]
    pub(crate) fn get_available_session_count(&self) -> u32 {
        self.session_allocation_mask.count_zeros()
    }

    /// Returns whether the session needs to be reestablished e.g. after
    /// a live migration or disaster recovery etc.
    ///
    /// # Arguments
    ///
    /// * `id` - Virtual session id in the SessionTable
    ///
    /// # Returns
    ///
    /// * `bool` - True if needs to be reestablished, false otherwise
    #[allow(unused)]
    pub(crate) fn needs_renegotiation(&self, id: u16) -> bool {
        if id as usize > MAX_SESSIONS - 1 {
            return false;
        }

        self.session_allocation_mask.bit(id.into())
            && self.session_renegotiation_mask.bit(id.into())
    }

    /// Returns whether the session is valid or not. A session is valid if it is currently
    /// present but does not need to be reestablished.
    ///
    /// # Arguments
    ///
    /// * `id` - Virtual session id in the SessionTable
    ///
    /// # Returns
    ///
    /// * `bool` - True if valid, false otherwise
    pub(crate) fn valid(&self, id: u16) -> bool {
        if id as usize > MAX_SESSIONS - 1 {
            return false;
        }

        self.session_allocation_mask.bit(id.into())
            && !self.session_renegotiation_mask.bit(id.into())
    }

    /// Similar to create_session but allows to map a specific virtual session to
    /// the physical session id. This is used for sessions that need renegotiation.
    ///
    /// # Arguments
    ///
    /// * `id` - Virtual session id in the SessionTable
    /// * `target_id` - Physical session id in the vault
    #[allow(unused)]
    pub(crate) fn recreate_session(&mut self, id: u16, target_id: u16) {
        if (id as usize) < MAX_SESSIONS && self.needs_renegotiation(id) {
            self.session_renegotiation_mask.set_bit(id.into(), false);
            self.table[id as usize] = target_id;
        }
    }

    /// Create a virtual session in the SessionTable
    ///
    /// # Arguments
    ///
    /// * `target_id` - Physical session id in the vault
    ///
    /// # Returns
    ///
    /// `u16` - Virtual session id
    pub(crate) fn create_session(&mut self, target_id: u16) -> Result<u16, ManticoreError> {
        let id = self.session_allocation_mask.trailing_ones() as u16;

        if id as usize > MAX_SESSIONS - 1 {
            return Err(ManticoreError::VaultSessionLimitReached);
        }

        self.table[id as usize] = target_id;
        self.session_allocation_mask.set_bit(id.into(), true);
        Ok(id)
    }

    /// Get Physical Session Id for the passed virtual id.
    ///
    /// # Arguments
    ///
    /// * `id` - Virtual session id in the SessionTable
    ///
    /// # Returns
    ///
    /// `u16` - Physical session id in the vault
    pub(crate) fn get_target_session(&self, id: u16) -> Option<u16> {
        if self.valid(id) {
            Some(self.table[id as usize])
        } else {
            None
        }
    }

    /// Delete the entry from SessionTable.
    ///
    /// # Arguments
    ///
    /// * `id` - Virtual session id in the SessionTable
    pub(crate) fn delete(&mut self, id: u16) {
        if (id as usize) < MAX_SESSIONS {
            self.session_allocation_mask.set_bit(id.into(), false);
            self.session_renegotiation_mask.set_bit(id.into(), false);
            self.table[id as usize] = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_create_new_table() {
        let mut session_table = SessionTable::new();

        let session_id = session_table.create_session(0);
        assert_eq!(session_id, Ok(0));
    }

    #[test]
    fn test_session_create_max_new_table() {
        let mut session_table = SessionTable::new();

        for i in 0..MAX_SESSIONS as u16 {
            let session_id = session_table.create_session(i);
            assert_eq!(session_id, Ok(i));
        }

        let session_id = session_table.create_session(130);
        assert_eq!(session_id, Err(ManticoreError::VaultSessionLimitReached));
    }

    #[test]
    fn test_get_target_session_new_table() {
        let mut session_table = SessionTable::new();

        let session_id = session_table.create_session(4);
        assert_eq!(session_id, Ok(0));

        let target_session = session_table.get_target_session(session_id.unwrap());
        assert_eq!(target_session, Some(4));

        assert!(session_table.get_target_session(1).is_none());
        assert!(session_table.get_target_session(4).is_none());
        assert!(session_table
            .get_target_session((MAX_SESSIONS - 1) as u16)
            .is_none());
        assert!(session_table
            .get_target_session(MAX_SESSIONS as u16)
            .is_none());
        assert!(session_table
            .get_target_session((MAX_SESSIONS + 20) as u16)
            .is_none());
    }

    #[test]
    fn test_get_target_session_max_new_table() {
        let mut session_table = SessionTable::new();

        for i in 0..MAX_SESSIONS as u16 {
            let session_id = session_table.create_session(i);
            assert_eq!(session_id, Ok(i));
        }

        for i in 0..MAX_SESSIONS as u16 {
            let target_session = session_table.get_target_session(i);
            assert_eq!(target_session, Some(i));
        }

        assert!(session_table
            .get_target_session(MAX_SESSIONS as u16)
            .is_none());
        assert!(session_table
            .get_target_session((MAX_SESSIONS + 50) as u16)
            .is_none());
    }

    #[test]
    fn test_backup_restore_renegotiate() {
        let mut session_table = SessionTable::new();

        assert!(!session_table.needs_renegotiation(500));

        for i in 0..MAX_SESSIONS as u16 {
            let session_id = session_table.create_session(i);
            assert_eq!(session_id, Ok(i));
        }

        assert!(session_table.valid(1));
        assert!(session_table.valid((MAX_SESSIONS - 1) as u16));
        assert!(session_table.valid(0));
        assert!(session_table.valid((MAX_SESSIONS - 2) as u16));
        assert!(!session_table.needs_renegotiation(1));
        assert!(!session_table.needs_renegotiation((MAX_SESSIONS - 1) as u16));
        assert!(!session_table.needs_renegotiation(0));
        assert!(!session_table.needs_renegotiation((MAX_SESSIONS - 2) as u16));
        assert_eq!(session_table.get_target_session(1), Some(1));
        assert_eq!(
            session_table.get_target_session((MAX_SESSIONS - 1) as u16),
            Some((MAX_SESSIONS - 1) as u16)
        );
        assert_eq!(session_table.get_target_session(0), Some(0));
        assert_eq!(
            session_table.get_target_session((MAX_SESSIONS - 2) as u16),
            Some((MAX_SESSIONS - 2) as u16)
        );

        for i in (0..MAX_SESSIONS as u16).step_by(2) {
            session_table.delete(i);
        }

        let backup = session_table.backup();
        assert_eq!(backup, 0b10101010);
        assert!(session_table.valid(1));
        assert!(session_table.valid((MAX_SESSIONS - 1) as u16));
        assert!(!session_table.valid(0));
        assert!(!session_table.valid((MAX_SESSIONS - 2) as u16));
        assert!(!session_table.needs_renegotiation(1));
        assert!(!session_table.needs_renegotiation((MAX_SESSIONS - 1) as u16));
        assert!(!session_table.needs_renegotiation(0));
        assert!(!session_table.needs_renegotiation((MAX_SESSIONS - 2) as u16));
        assert_eq!(session_table.get_target_session(1), Some(1));
        assert_eq!(
            session_table.get_target_session((MAX_SESSIONS - 1) as u16),
            Some((MAX_SESSIONS - 1) as u16)
        );
        assert!(session_table.get_target_session(0).is_none());
        assert!(session_table
            .get_target_session((MAX_SESSIONS - 2) as u16)
            .is_none());

        session_table.restore(backup);
        assert!(!session_table.valid(1));
        assert!(!session_table.valid((MAX_SESSIONS - 1) as u16));
        assert!(!session_table.valid(0));
        assert!(!session_table.valid((MAX_SESSIONS - 2) as u16));
        assert!(session_table.needs_renegotiation(1));
        assert!(session_table.needs_renegotiation((MAX_SESSIONS - 1) as u16));
        assert!(!session_table.needs_renegotiation(0));
        assert!(!session_table.needs_renegotiation((MAX_SESSIONS - 2) as u16));
        assert!(session_table.get_target_session(1).is_none());
        assert!(session_table
            .get_target_session((MAX_SESSIONS - 1) as u16)
            .is_none());
        assert!(session_table.get_target_session(0).is_none());
        assert!(session_table
            .get_target_session((MAX_SESSIONS - 2) as u16)
            .is_none());

        session_table.recreate_session(1, 101);
        session_table.recreate_session((MAX_SESSIONS - 1) as u16, 227);
        session_table.recreate_session(0, 100);
        session_table.recreate_session((MAX_SESSIONS - 2) as u16, 226);

        assert!(session_table.valid(1));
        assert!(session_table.valid((MAX_SESSIONS - 1) as u16));
        assert!(!session_table.valid(0));
        assert!(!session_table.valid((MAX_SESSIONS - 2) as u16));
        assert!(!session_table.needs_renegotiation(1));
        assert!(!session_table.needs_renegotiation((MAX_SESSIONS - 1) as u16));
        assert!(!session_table.needs_renegotiation(0));
        assert!(!session_table.needs_renegotiation((MAX_SESSIONS - 2) as u16));
        assert_eq!(session_table.get_target_session(1), Some(101));
        assert_eq!(
            session_table.get_target_session((MAX_SESSIONS - 1) as u16),
            Some(227)
        );
        assert!(session_table.get_target_session(0).is_none());
        assert!(session_table
            .get_target_session((MAX_SESSIONS - 2) as u16)
            .is_none());
    }
}
