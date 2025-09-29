use tracing::level_filters::LevelFilter;
use tracing::Level;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;
use win_etw_macros::*;

#[trace_logging_provider(guid = "6f3b7e7a-7f98-4fb5-a0ce-e994136df3e2")]
trait AzIHsmKspLogProvider {
    fn log(module_path: &str, file: &str, line: u32, message: &str);
}

const ENV_VAR_NAME: &str = "AZIHSMKSP_LOG_LEVEL";
const UNKNOWN: &str = "UNKNOWN";

// A writer that writes log to ETW (Event Tracing for Windows)
struct ETWWriter {
    provider: AzIHsmKspLogProvider,
    level: Level,
    module: String,
    file: String,
    line: u32,
}

impl Default for ETWWriter {
    fn default() -> Self {
        ETWWriter {
            provider: AzIHsmKspLogProvider::new(),
            level: Level::INFO,
            module: UNKNOWN.to_string(),
            file: UNKNOWN.to_string(),
            line: 0,
        }
    }
}

impl std::io::Write for ETWWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = std::str::from_utf8(buf).unwrap_or("INVALID BUFFER: UNABLE TO DECODE");

        let etw_level = match self.level {
            Level::ERROR => win_etw_provider::Level::ERROR,
            Level::WARN => win_etw_provider::Level::WARN,
            Level::INFO => win_etw_provider::Level::INFO,
            Level::DEBUG => win_etw_provider::Level::VERBOSE,
            Level::TRACE => win_etw_provider::Level(6),
        };

        let options = win_etw_provider::EventOptions {
            level: Some(etw_level),
            ..Default::default()
        };

        self.provider
            .log(Some(&options), &self.module, &self.file, self.line, s);
        Ok(s.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Creates writer given metadata
struct MakeETWWriter {}

impl<'a> MakeWriter<'a> for MakeETWWriter {
    type Writer = ETWWriter;

    /// Return a ETWWriter with INFO level.
    ///
    /// This method is not used, but it is required to be implemented.
    /// So makes it returns a default Writer
    fn make_writer(&'a self) -> Self::Writer {
        ETWWriter::default()
    }

    /// Return a new ETWWriter with metadata
    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        ETWWriter {
            provider: AzIHsmKspLogProvider::new(),
            level: *meta.level(),
            module: meta.module_path().unwrap_or(UNKNOWN).to_string(),
            file: meta.file().unwrap_or(UNKNOWN).to_string(),
            line: meta.line().unwrap_or(0),
        }
    }
}

/// Create and register tracing subscriber that writes formatted log messages to ETW.
///
/// This function should only be called once before any other API call.
///
/// # Returns
/// * 0 - if the subscriber was successfully registered.
/// * 1 - if the subscriber failed to register. Possibly because it was already initialized.
pub fn register_tracing_subscriber() -> isize {
    // A Log Filter that reads log level from environment variable
    // If env variable is not set or empty, defaults to INFO log level
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .with_env_var(ENV_VAR_NAME)
        .from_env_lossy();

    // Create a filtered layer that writes formatted output to ETW
    let layer = layer()
        // Disable text with color
        .with_ansi(false)
        // Disable level, file and line number in message
        // As we manually collect them from metadata
        .with_level(false)
        .with_file(false)
        .with_line_number(false)
        // Collect thread ids for debugging multithreaded issues
        .with_thread_ids(true)
        .with_writer(MakeETWWriter {})
        .with_filter(filter);

    match tracing_subscriber::registry().with(layer).try_init() {
        Ok(()) => 0,
        // NOTE: New subscriber seems to be able to be registered despite the error
        Err(_) => 1,
    }
}
