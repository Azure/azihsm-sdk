// Copyright (C) Microsoft Corporation. All rights reserved.

use std::fs::File;
use std::io::Seek;
use std::process;

use ciborium::from_reader;
use ciborium::into_writer;
use fs2::FileExt;
use serde::Deserialize;
use serde::Serialize;

use crate::HsmError;
use crate::HsmResult;

/// Internal function. Read file content from file
/// Used in FileLockGuard constructors.
fn read_file(file: &mut File) -> HsmResult<FileContent> {
    // Check if file content is empty
    if file
        .metadata()
        .map_err(|error_stack| {
            tracing::error!(?error_stack);
            HsmError::DiskAccessFailed
        })?
        .len()
        == 0
    {
        return Ok(FileContent {
            sealed_bk3: None,
            masked_unwrapping_key: None,
            backup_masking_key: None,
        });
    }

    file.rewind().map_err(|error_stack| {
        tracing::error!(?error_stack);
        HsmError::DiskAccessFailed
    })?;

    let content = from_reader(file).map_err(|error_stack| {
        tracing::error!(?error_stack);
        HsmError::DiskAccessFailed
    })?;

    Ok(content)
}

/// Internal function. Write file content to file
/// Used in FileLockGuard ::drop.
fn write_file(file: &mut File, content: &FileContent) -> HsmResult<()> {
    // Clear existing content
    file.set_len(0).map_err(|error_stack| {
        tracing::error!(?error_stack);
        HsmError::DiskAccessFailed
    })?;
    file.rewind().map_err(|error_stack| {
        tracing::error!(?error_stack);
        HsmError::DiskAccessFailed
    })?;

    into_writer(content, file).map_err(|error_stack| {
        tracing::error!(?error_stack);
        HsmError::DiskAccessFailed
    })
}

#[derive(Debug, PartialEq)]
enum FileLockGuardType {
    WriteLock,
    #[allow(dead_code)]
    ReadLock,
}

pub(crate) struct FileLockGuard {
    file: File,
    content: FileContent,
    #[allow(dead_code)]
    lock_type: FileLockGuardType,
}

impl FileLockGuard {
    fn write_lock(file_path: &str) -> HsmResult<Self> {
        tracing::debug!(
            "FileLockGuard::write_lock. FileName={} ProcessId={}",
            file_path,
            process::id()
        );

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(file_path)
            .map_err(|error_stack| {
                tracing::error!(?error_stack);
                HsmError::DiskAccessFailed
            })?;

        fs2::FileExt::lock_exclusive(&file).map_err(|error_stack| {
            tracing::error!(?error_stack);
            HsmError::DiskAccessFailed
        })?;

        let content = read_file(&mut file).map_err(|error_stack| {
            tracing::error!(?error_stack);
            HsmError::DiskAccessFailed
        })?;

        Ok(FileLockGuard {
            file,
            content,
            lock_type: FileLockGuardType::WriteLock,
        })
    }

    #[allow(dead_code)]
    fn read_lock(file_path: &str) -> HsmResult<Self> {
        tracing::debug!(
            "FileLockGuard::read_lock. FileName={} ProcessId={}",
            file_path,
            process::id()
        );

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(file_path)
            .map_err(|error_stack| {
                tracing::error!(?error_stack);
                HsmError::DiskAccessFailed
            })?;

        fs2::FileExt::lock_shared(&file).map_err(|error_stack| {
            tracing::error!(?error_stack);
            HsmError::DiskAccessFailed
        })?;

        let content = read_file(&mut file).map_err(|error_stack| {
            tracing::error!(?error_stack);
            HsmError::DiskAccessFailed
        })?;

        Ok(FileLockGuard {
            file,
            content,
            lock_type: FileLockGuardType::ReadLock,
        })
    }

    /// Read sealed bk3 data from disk
    #[allow(dead_code)]
    pub(crate) fn get_sealed_bk3(&self) -> HsmResult<Option<Vec<u8>>> {
        Ok(self.content.sealed_bk3.clone())
    }

    /// Write sealed bk3 data on disk
    #[allow(dead_code)]
    pub(crate) fn set_sealed_bk3(&mut self, sealed_bk3: &[u8]) -> HsmResult<()> {
        if self.lock_type == FileLockGuardType::ReadLock {
            tracing::error!("Unexpected write method with shared_lock. GuardType={:?}, FileName={:?}, ProcessId={}",
                self.lock_type,
                self.file,
                process::id()
            );
            Err(HsmError::InternalError)?
        }

        self.content.sealed_bk3 = Some(sealed_bk3.to_vec());
        Ok(())
    }

    /// Read masked unwrapping key data from disk
    #[allow(dead_code)]
    pub(crate) fn get_masked_unwrapping_key(&self) -> HsmResult<Option<Vec<u8>>> {
        Ok(self.content.masked_unwrapping_key.clone())
    }

    /// Write masked unwrapping key data to disk
    #[allow(dead_code)]
    pub(crate) fn set_masked_unwrapping_key(
        &mut self,
        masked_unwrapping_key: &[u8],
    ) -> HsmResult<()> {
        if self.lock_type == FileLockGuardType::ReadLock {
            tracing::error!("Unexpected write method with shared_lock. GuardType={:?}, FileName={:?}, ProcessId={}",
                self.lock_type,
                self.file,
                process::id()
            );
            Err(HsmError::InternalError)?
        }

        self.content.masked_unwrapping_key = Some(masked_unwrapping_key.to_vec());
        Ok(())
    }

    /// Read backup masking key data from disk
    #[allow(dead_code)]
    pub(crate) fn get_backup_masking_key(&self) -> HsmResult<Option<Vec<u8>>> {
        Ok(self.content.backup_masking_key.clone())
    }

    /// Write backup masking key data to disk
    #[allow(dead_code)]
    pub(crate) fn set_backup_masking_key(&mut self, backup_masking_key: &[u8]) -> HsmResult<()> {
        if self.lock_type == FileLockGuardType::ReadLock {
            tracing::error!("Unexpected write method with shared_lock. GuardType={:?}, FileName={:?}, ProcessId={}",
                self.lock_type,
                self.file,
                process::id()
            );
            Err(HsmError::InternalError)?
        }

        self.content.backup_masking_key = Some(backup_masking_key.to_vec());
        Ok(())
    }
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        tracing::debug!(
            "FileLockGuard::drop. GuardType={:?}, FileName={:?}, ProcessId={}",
            self.lock_type,
            self.file,
            process::id()
        );
        let _ = write_file(&mut self.file, &self.content).map_err(|error_stack| {
            tracing::error!(?error_stack);
            HsmError::DiskAccessFailed
        });
        let _ = fs2::FileExt::unlock(&self.file).map_err(|error_stack| {
            tracing::error!(?error_stack);
            HsmError::DiskAccessFailed
        });
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FileContent {
    sealed_bk3: Option<Vec<u8>>,
    masked_unwrapping_key: Option<Vec<u8>>,
    backup_masking_key: Option<Vec<u8>>,
}

// Do not cache FileContent, as it could be out of sync.
// So we only read/write from file when we have read/write lock.
#[derive(Debug)]
pub(crate) struct MemoryManager {
    file_path: String,
}

impl MemoryManager {
    pub(crate) fn new(file_path: &str) -> Self {
        Self {
            file_path: file_path.to_string(),
        }
    }

    /// Holds a read lock on disk memory.
    #[allow(dead_code)]
    pub(crate) fn read_lock(&self) -> HsmResult<FileLockGuard> {
        FileLockGuard::read_lock(&self.file_path)
    }

    /// Holds a write lock on disk memory.
    pub(crate) fn write_lock(&self) -> HsmResult<FileLockGuard> {
        FileLockGuard::write_lock(&self.file_path)
    }

    /// Clear data stored on disk memory.
    /// This should only be used in testing.
    #[allow(dead_code)]
    pub(crate) fn clear_data(&self) -> HsmResult<()> {
        tracing::info!(
            "MemoryManager::clear_data. FileName={} ProcessId={}",
            self.file_path,
            process::id()
        );

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.file_path)
            .map_err(|error_stack| {
                tracing::error!(?error_stack);
                HsmError::DiskAccessFailed
            })?;

        file.lock_exclusive().map_err(|error_stack| {
            tracing::error!(?error_stack);
            HsmError::DiskAccessFailed
        })?;

        let blank_content = FileContent {
            sealed_bk3: None,
            masked_unwrapping_key: None,
            backup_masking_key: None,
        };

        file.set_len(0).map_err(|error_stack| {
            tracing::error!(?error_stack);
            HsmError::DiskAccessFailed
        })?;
        file.rewind().map_err(|error_stack| {
            tracing::error!(?error_stack);
            HsmError::DiskAccessFailed
        })?;

        into_writer(&blank_content, &mut file).map_err(|error_stack| {
            tracing::error!(?error_stack);
            HsmError::DiskAccessFailed
        })
    }

    /// Remove data at file path.
    /// This should only be used in testing.
    #[allow(dead_code)]
    pub(crate) fn delete_file(&self) -> HsmResult<()> {
        std::fs::remove_file(&self.file_path).map_err(|error_stack| {
            tracing::error!(?error_stack);
            HsmError::DiskAccessFailed
        })
    }
}

#[cfg(test)]
mod tests {

    // Hard-coded file path to store information on disk for tests
    const FILE_PATH: &str = "memory_manager_test_file";

    use crypto::rand::rand_bytes;
    use test_with_tracing::test;

    use crate::memory_manager::MemoryManager;

    #[test]
    fn test_memory_manager() {
        let memory_manager = MemoryManager::new(FILE_PATH);

        // Clear data in memory
        let result = memory_manager.clear_data();
        assert!(
            result.is_ok(),
            "memory manager clear data result {:?}",
            result
        );

        // Initialize data to save
        let mut sealed_bk3 = [0u8; 1024];
        let mut masked_unwrapping_key = [0u8; 1024];
        let mut backup_masking_key = [0u8; 1024];

        rand_bytes(&mut sealed_bk3).expect("rand_bytes failure");
        rand_bytes(&mut masked_unwrapping_key).expect("rand_bytes failure");
        rand_bytes(&mut backup_masking_key).expect("rand_bytes failure");

        {
            // Get write lock
            let mut write_locked_memory_manager =
                memory_manager.write_lock().expect("write lock failure");

            // Confirm that memory is blank
            assert_eq!(
                write_locked_memory_manager
                    .get_backup_masking_key()
                    .expect("get bmk failure"),
                None
            );
            assert_eq!(
                write_locked_memory_manager
                    .get_masked_unwrapping_key()
                    .expect("get masked key failure"),
                None
            );
            assert_eq!(
                write_locked_memory_manager
                    .get_sealed_bk3()
                    .expect("get bk3 failure"),
                None
            );

            // Write values to memory
            write_locked_memory_manager
                .set_backup_masking_key(&backup_masking_key)
                .expect("set bmk failure");
            write_locked_memory_manager
                .set_masked_unwrapping_key(&masked_unwrapping_key)
                .expect("set bmk failure");
            write_locked_memory_manager
                .set_sealed_bk3(&sealed_bk3)
                .expect("set bk3 failure");

            // Confirm values are reflected in memory
            assert_eq!(
                write_locked_memory_manager
                    .get_backup_masking_key()
                    .expect("get bmk failure"),
                Some(backup_masking_key.to_vec())
            );
            assert_eq!(
                write_locked_memory_manager
                    .get_masked_unwrapping_key()
                    .expect("get masked key failure"),
                Some(masked_unwrapping_key.to_vec())
            );
            assert_eq!(
                write_locked_memory_manager
                    .get_sealed_bk3()
                    .expect("get bk3 failure"),
                Some(sealed_bk3.to_vec())
            );

            // Drop the write lock
        }

        {
            // Get read lock
            let mut read_locked_memory_manager =
                memory_manager.read_lock().expect("write lock failure");

            // Confirm we can't set values
            let result = read_locked_memory_manager.set_backup_masking_key(&backup_masking_key);
            assert!(result.is_err(), "result {:?}", result);

            let result =
                read_locked_memory_manager.set_masked_unwrapping_key(&masked_unwrapping_key);
            assert!(result.is_err(), "result {:?}", result);

            let result = read_locked_memory_manager.set_sealed_bk3(&sealed_bk3);
            assert!(result.is_err(), "result {:?}", result);

            // Confirm values are reflected in memory
            assert_eq!(
                read_locked_memory_manager
                    .get_backup_masking_key()
                    .expect("get bmk failure"),
                Some(backup_masking_key.to_vec())
            );
            assert_eq!(
                read_locked_memory_manager
                    .get_masked_unwrapping_key()
                    .expect("get masked key failure"),
                Some(masked_unwrapping_key.to_vec())
            );
            assert_eq!(
                read_locked_memory_manager
                    .get_sealed_bk3()
                    .expect("get bk3 failure"),
                Some(sealed_bk3.to_vec())
            );

            // Drop the read lock
        }

        // Remove file
        memory_manager.delete_file().expect("delete file failure")
    }

    #[test]
    fn test_memory_manager_long_then_short() {
        // Test saving max data, then saving smaller data
        // An error here could indicate we are not using set_len, rewind for file correctly
        let memory_manager = MemoryManager::new(FILE_PATH);

        // Clear data in memory
        let result = memory_manager.clear_data();
        assert!(
            result.is_ok(),
            "memory manager clear data result {:?}",
            result
        );

        // Initialize data to save
        let mut sealed_bk3 = [0u8; 1024];
        let mut masked_unwrapping_key = [0u8; 1024];
        let mut backup_masking_key = [0u8; 1024];

        rand_bytes(&mut sealed_bk3).expect("rand_bytes failure");
        rand_bytes(&mut masked_unwrapping_key).expect("rand_bytes failure");
        rand_bytes(&mut backup_masking_key).expect("rand_bytes failure");

        {
            // Get write lock
            let mut write_locked_memory_manager =
                memory_manager.write_lock().expect("write lock failure");

            // Write full values to memory
            write_locked_memory_manager
                .set_backup_masking_key(&backup_masking_key)
                .expect("set bmk failure");
            write_locked_memory_manager
                .set_masked_unwrapping_key(&masked_unwrapping_key)
                .expect("set bmk failure");
            write_locked_memory_manager
                .set_sealed_bk3(&sealed_bk3)
                .expect("set bk3 failure");

            // Confirm values are reflected in memory
            assert_eq!(
                write_locked_memory_manager
                    .get_backup_masking_key()
                    .expect("get bmk failure"),
                Some(backup_masking_key.to_vec())
            );
            assert_eq!(
                write_locked_memory_manager
                    .get_masked_unwrapping_key()
                    .expect("get masked key failure"),
                Some(masked_unwrapping_key.to_vec())
            );
            assert_eq!(
                write_locked_memory_manager
                    .get_sealed_bk3()
                    .expect("get bk3 failure"),
                Some(sealed_bk3.to_vec())
            );

            // Drop the write lock
        }

        let truncate_size = 48;
        {
            // Get write lock
            let mut write_locked_memory_manager =
                memory_manager.write_lock().expect("write lock failure");

            // Write shorter values to memory
            write_locked_memory_manager
                .set_backup_masking_key(&backup_masking_key[..truncate_size])
                .expect("set bmk failure");
            write_locked_memory_manager
                .set_masked_unwrapping_key(&masked_unwrapping_key[..truncate_size])
                .expect("set bmk failure");
            write_locked_memory_manager
                .set_sealed_bk3(&sealed_bk3[..truncate_size])
                .expect("set bk3 failure");

            // Confirm values are reflected in memory
            assert_eq!(
                write_locked_memory_manager
                    .get_backup_masking_key()
                    .expect("get bmk failure"),
                Some(backup_masking_key[..truncate_size].to_vec())
            );
            assert_eq!(
                write_locked_memory_manager
                    .get_masked_unwrapping_key()
                    .expect("get masked key failure"),
                Some(masked_unwrapping_key[..truncate_size].to_vec())
            );
            assert_eq!(
                write_locked_memory_manager
                    .get_sealed_bk3()
                    .expect("get bk3 failure"),
                Some(sealed_bk3[..truncate_size].to_vec())
            );

            // Drop the write lock
        }

        {
            // Get read lock
            let read_locked_memory_manager =
                memory_manager.read_lock().expect("write lock failure");

            // Confirm shorter values are reflected in memory
            assert_eq!(
                read_locked_memory_manager
                    .get_backup_masking_key()
                    .expect("get bmk failure"),
                Some(backup_masking_key[..truncate_size].to_vec())
            );
            assert_eq!(
                read_locked_memory_manager
                    .get_masked_unwrapping_key()
                    .expect("get masked key failure"),
                Some(masked_unwrapping_key[..truncate_size].to_vec())
            );
            assert_eq!(
                read_locked_memory_manager
                    .get_sealed_bk3()
                    .expect("get bk3 failure"),
                Some(sealed_bk3[..truncate_size].to_vec())
            );

            // Drop the read lock
        }

        // Remove file
        memory_manager.delete_file().expect("delete file failure")
    }
}
