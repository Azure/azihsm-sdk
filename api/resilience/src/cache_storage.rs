// Copyright (C) Microsoft Corporation. All rights reserved.

use std::env;
use std::path::PathBuf;
use std::sync::OnceLock;

use mcr_api::*;

/// Shared state file name for resilience cache
const PARTITION_CACHE_FILE: &str = "partition_cache";

/// Prepares the resilience storage path on disk and converts it to an owned String.
/// Multi-process safe - Linux implementation.
#[cfg(target_os = "linux")]
fn prepare_storage_path(path: PathBuf) -> HsmResult<String> {
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    tracing::debug!("Initializing resilience storage path: {:?}", path);

    // Ensure parent directory exists (e.g., /var/tmp/azihsmguest for file /var/tmp/azihsmguest/partition_cache)
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            // Create directory with 0o1777 (drwxrwxrwt) - world writable with sticky bit
            // The sticky bit ensures only file owners can delete their own files
            // This allows multiple users to create the cache file without race conditions
            // Note: whoever creates the directory will be the owner
            // recursive(true) works like "mkdir -p" - creates intermediate dirs if needed
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o1777)
                .create(parent)
                .map_err(|error_stack| {
                    tracing::error!(
                        ?error_stack,
                        ?path,
                        "Failed to create parent directory during initialization"
                    );
                    HsmError::DiskAccessFailed
                })?;

            // Explicitly set permissions on the leaf directory to bypass umask
            // (intermediate directories may have umask-affected permissions, but we only care about the leaf)
            let permissions = std::fs::Permissions::from_mode(0o1777);
            std::fs::set_permissions(parent, permissions).map_err(|error_stack| {
                tracing::error!(
                    ?error_stack,
                    ?parent,
                    "Failed to set permissions on parent directory"
                );
                HsmError::DiskAccessFailed
            })?;

            tracing::info!("Created resilience state directory: {:?}", parent);
        }
    }

    // Check if file exists and has correct permissions before opening
    let needs_permission_fix = match std::fs::metadata(&path) {
        Ok(metadata) => {
            let current_mode = metadata.permissions().mode() & 0o777;
            if current_mode != 0o666 {
                tracing::debug!(
                    ?path,
                    current_mode = format!("{:o}", current_mode),
                    "File exists but has incorrect permissions, will attempt to fix"
                );
                true
            } else {
                tracing::debug!(?path, "File exists with correct permissions (0o666)");
                false
            }
        }
        Err(_) => {
            // File doesn't exist, we'll create it with correct permissions
            tracing::debug!(
                ?path,
                "File does not exist, will create with 0o666 permissions"
            );
            true
        }
    };

    // Validate we can create/open the file with read-write access
    let _file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o666) // Request rw-rw-rw- permissions (umask will be applied: actual = 0o666 & !umask)
        .open(&path)
        .map_err(|error_stack| {
            tracing::error!(
                ?error_stack,
                ?path,
                "Failed to open/create resilience state file during initialization"
            );
            HsmError::DiskAccessFailed
        })?;

    // Set permissions explicitly to bypass umask and ensure exactly 0o666
    // This is needed because:
    // - Newly created files: OpenOptionsExt::mode() applies umask (e.g., 0o666 & !0o022 = 0o644)
    // - Existing files with wrong perms: Need to fix to 0o666 (only owner can do this)
    if needs_permission_fix {
        let permissions = std::fs::Permissions::from_mode(0o666);
        if let Err(err) = std::fs::set_permissions(&path, permissions) {
            // Debug-level log: expected to fail if we're not the file owner
            // For newly created files by us, this should succeed and override umask
            tracing::debug!(
                ?err,
                ?path,
                "Could not set permissions (expected if not file owner)"
            );
        } else {
            tracing::debug!(?path, "Successfully set file permissions to 0o666");
        }
    }

    tracing::info!(
        "Successfully initialized resilience storage path: {:?}",
        path
    );

    // Convert to string, failing if path contains invalid UTF-8
    path.into_os_string()
        .into_string()
        .map_err(|_| HsmError::DiskAccessFailed)
}

/// Prepares the resilience storage path on disk and converts it to an owned String.
/// Multi-process safe - Windows implementation.
#[cfg(windows)]
fn prepare_storage_path(path: PathBuf) -> HsmResult<String> {
    tracing::debug!("Initializing resilience storage path: {:?}", path);

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|error_stack| {
                tracing::error!(
                    ?error_stack,
                    ?path,
                    "Failed to create parent directory during initialization"
                );
                HsmError::DiskAccessFailed
            })?;

            tracing::info!("Created resilience state directory: {:?}", parent);
        }
    }

    // Validate we can create/open the file with read-write access
    let _file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|error_stack| {
            tracing::error!(
                ?error_stack,
                ?path,
                "Failed to open/create resilience state file during initialization"
            );
            HsmError::DiskAccessFailed
        })?;

    tracing::info!(
        "Successfully initialized resilience storage path: {:?}",
        path
    );

    // Convert to string, failing if path contains invalid UTF-8
    path.into_os_string()
        .into_string()
        .map_err(|_| HsmError::DiskAccessFailed)
}

/// Resolves the storage file path with the following priority:
/// 1. AZIHSM_RESILIENCE_STATE_PATH environment variable (if set and non-empty)
/// 2. Platform-specific default (which may check for system-wide path on Windows)
fn resolve_storage_file_path() -> HsmResult<PathBuf> {
    // Priority 1: Environment variable override
    if let Some(override_path) = env::var_os("AZIHSM_RESILIENCE_STATE_PATH") {
        if !override_path.is_empty() {
            tracing::info!(
                "Using AZIHSM_RESILIENCE_STATE_PATH override: {:?}",
                override_path
            );
            return Ok(PathBuf::from(override_path));
        }
    }

    // Priority 2: Platform-specific default
    let default_path = platform_default_storage_path()?;
    tracing::info!("Using resilience state path: {:?}", default_path);
    Ok(default_path)
}

/// Returns the system-wide storage path for Windows (if ALLUSERSPROFILE is set)
/// This path is shared across all users on the system and typically requires
/// administrator privileges to create.
/// Currently KSP provider creates this path during installation.
#[cfg(target_os = "windows")]
fn system_wide_storage_path() -> Option<PathBuf> {
    env::var_os("ALLUSERSPROFILE")
        .filter(|value| !value.is_empty())
        .map(|base| {
            PathBuf::from(base)
                .join("Microsoft")
                .join("azihsmguest")
                .join(PARTITION_CACHE_FILE)
        })
}

/// Returns the platform-specific default storage path for Windows.
/// Priority:
/// 1. System-wide path: %ALLUSERSPROFILE%\Microsoft\azihsmguest\partition_cache
/// 2. User-local path: %LOCALAPPDATA%\Microsoft\azihsmguest\partition_cache
#[cfg(target_os = "windows")]
fn platform_default_storage_path() -> HsmResult<PathBuf> {
    // Check for admin-created system-wide path first
    if let Some(system_wide_path) = system_wide_storage_path() {
        if system_wide_path.exists() {
            tracing::debug!(
                "Found existing system-wide partition cache file: {:?}",
                system_wide_path
            );
            return Ok(system_wide_path);
        }
    }

    tracing::warn!("System-wide partition cache file not found, falling back to user-local path");
    let base = env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            tracing::error!("LOCALAPPDATA environment variable is not set or empty");
            HsmError::DiskAccessFailed
        })?;

    Ok(PathBuf::from(base)
        .join("Microsoft")
        .join("azihsmguest")
        .join(PARTITION_CACHE_FILE))
}

/// Returns the platform-specific default storage path for Linux
#[cfg(target_os = "linux")]
fn platform_default_storage_path() -> HsmResult<PathBuf> {
    Ok(PathBuf::from("/var/tmp")
        .join("azihsmguest")
        .join(PARTITION_CACHE_FILE))
}

/// Returns a clone of the cached resilience state path, initializing it with the default
/// logic if needed. This ensures the path is resolved and validated only once,
/// even when multiple ResilientDevice instances are created.
///
/// Path resolution priority:
/// 1. `AZIHSM_RESILIENCE_STATE_PATH` environment variable (if set and non-empty)
/// 2. Platform-specific defaults:
///    - Windows:
///      a. %ALLUSERSPROFILE%\Microsoft\azihsmguest\partition_cache (if file exists)
///      b. %LOCALAPPDATA%\Microsoft\azihsmguest\partition_cache (fallback)
///    - Linux: /var/tmp/azihsmguest/partition_cache
pub(crate) fn get_cache_file_path() -> HsmResult<String> {
    /// Cache for the resolved resilience storage path.
    /// This is shared across all ResilientDevice instances to avoid redundant I/O.
    static STORAGE_PATH: OnceLock<String> = OnceLock::new();

    // Return cloned cached value if already initialized
    if let Some(path) = STORAGE_PATH.get() {
        return Ok(path.clone());
    }

    // Otherwise, attempt initialization
    let path = resolve_storage_file_path()?;
    let prepared = prepare_storage_path(path)?;

    // Cache the result, handling concurrent initialization, then return a clone
    Ok(STORAGE_PATH.get_or_init(|| prepared).clone())
}
