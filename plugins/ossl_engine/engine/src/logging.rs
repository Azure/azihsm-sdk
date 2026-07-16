// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Env-var-driven `tracing_subscriber` install.
//!
//! Two env vars gate logging:
//!
//! | Var                       | Effect                                              |
//! |---------------------------|-----------------------------------------------------|
//! | `AZIHSM_ENGINE_LOG_STDERR`| presence → emit formatted events to stderr          |
//! | `AZIHSM_ENGINE_LOG_FILE`  | path → append formatted events to that file         |
//!
//! Level filtering comes from `RUST_LOG`; an unset or malformed value falls
//! back to `info`.
//!
//! Both env vars unset → no subscriber is installed and engine code emits
//! into the void (the current behavior).
//!
//! The subscriber is process-global: `set_global_default` is one-shot, so
//! [`install_from_env`] uses `try_init` and yields to any subscriber the host
//! (`openssl`, NGINX, …) already installed. The file sink's `WorkerGuard`
//! (whose Drop stops the writer thread) therefore also lives in a process
//! static, not per-engine `EngineData` — else the first `ENGINE_free` would
//! stop logging for everyone.

use std::env;
use std::fs::OpenOptions;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;

use openssl_engine::error::EngineError;
use openssl_engine::error::EngineResult;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::SECRET_FILE_MODE;

const ENV_LOG_STDERR: &str = "AZIHSM_ENGINE_LOG_STDERR";
const ENV_LOG_FILE: &str = "AZIHSM_ENGINE_LOG_FILE";

/// Mode bits compared against [`SECRET_FILE_MODE`]: the 9 permission bits plus
/// the setuid/setgid/sticky bits (i.e. everything but the file-type bits), so
/// the check is truly "exactly 0600" and rejects special-bit files too.
const MODE_BITS_MASK: u32 = 0o7777;

/// Owns the non-blocking writer's worker thread for the lifetime of the process.
static LOG_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

/// Parsed view of the logging env vars.
#[derive(Default)]
pub struct LogSettings {
    pub stderr: bool,
    pub file: Option<PathBuf>,
}

impl LogSettings {
    pub fn from_env() -> Self {
        Self {
            stderr: env::var_os(ENV_LOG_STDERR).is_some(),
            file: env::var_os(ENV_LOG_FILE).map(PathBuf::from),
        }
    }
}

/// Best-effort: install a global tracing subscriber based on env vars.
///
/// Returns Ok even when a subscriber is already installed (idempotent
/// across re-loads); only file-system or argument errors surface.
pub fn install_from_env() -> EngineResult<()> {
    install(LogSettings::from_env())
}

fn install(settings: LogSettings) -> EngineResult<()> {
    if !settings.stderr && settings.file.is_none() {
        return Ok(());
    }

    // RUST_LOG controls verbosity; default to `info` when it is unset
    // or malformed (an empty EnvFilter would suppress every event).
    let filter = std::env::var("RUST_LOG")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| EnvFilter::try_new(s).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));

    let mut layers: Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync + 'static>> =
        Vec::new();

    if settings.stderr {
        layers.push(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(true)
                .boxed(),
        );
    }
    let mut file_guard = None;
    if let Some(path) = settings.file.as_deref() {
        let (layer, guard) = open_file_layer(path)?;
        layers.push(layer);
        file_guard = Some(guard);
    }

    // EnvFilter goes last so it sits at the top of the layer stack and
    // filters events before they propagate into the fmt layers.
    let installed = tracing_subscriber::registry()
        .with(layers)
        .with(filter)
        .try_init()
        .is_ok();

    // Park the appender's worker guard only when we actually installed the
    // subscriber; if a host already had one, try_init fails and dropping the
    // guard here stops the otherwise-orphaned worker thread.
    if installed {
        if let Some(guard) = file_guard {
            let _ = LOG_GUARD.set(guard);
        }
    }
    Ok(())
}

/// Open `path` (mode 0600 on creation) for append, wrap it in a non-blocking
/// writer, and return the layer plus its `WorkerGuard`. The caller parks the
/// guard only if the subscriber is actually installed, so a dropped layer stops
/// its worker.
fn open_file_layer(
    path: &Path,
) -> EngineResult<(
    Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync + 'static>,
    WorkerGuard,
)> {
    // O_NONBLOCK so opening a FIFO at `path` can't block waiting for a reader
    // before the is_file() check below runs (it fails fast / is then rejected);
    // a no-op for a regular file. Mirrors read_regular_hardened in
    // engine-resiliency.
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(SECRET_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| EngineError::wrap(format!("AZIHSM_ENGINE_LOG_FILE {path:?}"), e))?;

    // O_NOFOLLOW already refuses a symlink at `path`. Also refuse a
    // pre-existing non-regular file (fifo, device, …) or one whose mode is not
    // exactly 0600, so enabling logging can't append into an unexpected file
    // type or leak events through a group/other-accessible file. Mirrors the
    // exact-mode requirement setup_storage_dir enforces for the storage dir.
    let meta = file
        .metadata()
        .map_err(|e| EngineError::wrap(format!("stat AZIHSM_ENGINE_LOG_FILE {path:?}"), e))?;
    if !meta.is_file() {
        return Err(EngineError::Other(format!(
            "AZIHSM_ENGINE_LOG_FILE {path:?} is not a regular file"
        )));
    }
    if meta.mode() & MODE_BITS_MASK != SECRET_FILE_MODE {
        return Err(EngineError::Other(format!(
            "AZIHSM_ENGINE_LOG_FILE {path:?} has insecure permissions \
             (must be owner-only, mode 0600)"
        )));
    }

    let (writer, guard) = tracing_appender::non_blocking(file);
    let layer = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_target(true)
        .boxed();
    Ok((layer, guard))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn settings_default_is_off() {
        let s = LogSettings::default();
        assert!(!s.stderr);
        assert!(s.file.is_none());
    }

    #[test]
    fn install_noop_when_both_disabled() {
        // With no layers there's nothing to fail on; this must not panic
        // even if a subscriber is already installed in the test process.
        install(LogSettings::default()).unwrap();
    }

    #[test]
    fn install_rejects_unwritable_file_path() {
        let s = LogSettings {
            stderr: false,
            file: Some(PathBuf::from("/no/such/directory/engine.log")),
        };
        assert!(install(s).is_err());
    }

    #[test]
    fn install_rejects_group_or_other_accessible_file() {
        use std::os::unix::fs::PermissionsExt;

        // A pre-existing log file readable by group/other must be rejected
        // (checked before any subscriber is installed, so this stays hermetic).
        let path = std::env::temp_dir().join(format!("engine-log-perm-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let r = install(LogSettings {
            stderr: false,
            file: Some(path.clone()),
        });
        let _ = std::fs::remove_file(&path);
        assert!(
            r.is_err(),
            "group/other-accessible log file must be rejected"
        );
    }

    #[test]
    fn install_rejects_owner_exec_file() {
        use std::os::unix::fs::PermissionsExt;

        // 0700 has no group/other access but is not exactly 0600; it must be
        // rejected to match the documented owner-only-0600 requirement.
        let path = std::env::temp_dir().join(format!("engine-log-exec-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

        let r = install(LogSettings {
            stderr: false,
            file: Some(path.clone()),
        });
        let _ = std::fs::remove_file(&path);
        assert!(
            r.is_err(),
            "a non-0600 (owner-exec) log file must be rejected"
        );
    }

    #[test]
    fn install_rejects_non_regular_file() {
        // A character device is not a regular file; the is_file() check must
        // reject it. O_NONBLOCK also keeps a special file's open from hanging
        // before that check runs. Uses /dev/null (opens without blocking),
        // since creating a FIFO would need unsafe mkfifo.
        let r = install(LogSettings {
            stderr: false,
            file: Some(PathBuf::from("/dev/null")),
        });
        assert!(r.is_err(), "a non-regular log file must be rejected");
    }

    #[test]
    fn file_layer_actually_emits() {
        use std::io::Read;

        // Guards against the "compiles but silently drops the layers" failure
        // mode: build the exact Vec<Box<dyn Layer>> stack install() composes,
        // make it the *scoped* default (with_default, so we avoid the global
        // one-shot try_init), emit an event, flush the appender, and assert the
        // file actually received it.
        let path = std::env::temp_dir().join(format!("engine-log-emit-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let (layer, guard) = open_file_layer(&path).unwrap();
        let subscriber = tracing_subscriber::registry()
            .with(vec![layer])
            .with(EnvFilter::new("info"));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "azihsm", "canary-emit-check");
        });
        drop(guard); // flush the non-blocking appender's worker thread

        let mut contents = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            contents.contains("canary-emit-check"),
            "the Vec-of-layers stack did not emit the event (silent drop?): {contents:?}"
        );
    }
}
