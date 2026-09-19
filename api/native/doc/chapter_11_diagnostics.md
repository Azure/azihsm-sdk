# Diagnostics

## File-Based Tracing

The native API library uses Rust's `tracing` framework internally for structured logging across the entire SDK stack, from the API layer down through the DDI.
By default no trace output is emitted, but it can be directed to a file by setting environment variables before loading the library.

This is useful for diagnosing failures in any host process that loads `azihsm_api_native` (e.g., the OpenSSL provider, C/C++ test binaries, or custom applications).

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AZIHSM_NATIVEAPI_TRACE_FILE` | Yes | File path for trace output. When set, a tracing subscriber is installed on the first API call. |
| `AZIHSM_NATIVEAPI_TRACE_FILE_APPEND` | No | Set to `1` to append to an existing file. If unset or any other value, the file is truncated on each run. |
| `RUST_LOG` | No | Controls the trace filter level. Defaults to `info`. Accepts standard `tracing` filter syntax (see below). |

### Trace Filter Syntax

The `RUST_LOG` variable accepts directives in the format used by [`tracing-subscriber`'s `EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html).
A few examples:

| Value | Effect |
|-------|--------|
| `debug` | All crates at DEBUG level and above |
| `trace` | All crates at TRACE level (most verbose) |
| `info` | All crates at INFO level (the default) |
| `azihsm_api=debug,azihsm_ddi_mock=info` | DEBUG for the API, INFO for the mock DDI, WARN for others |

### Usage Example

```bash
# Linux
export AZIHSM_NATIVEAPI_TRACE_FILE=/tmp/azihsm_trace.log
export RUST_LOG=debug
./my_application

# Inspect the trace
head -50 /tmp/azihsm_trace.log
```

```powershell
# Windows (PowerShell)
$env:AZIHSM_NATIVEAPI_TRACE_FILE = "$env:TEMP\azihsm_trace.log"
$env:RUST_LOG = "debug"
.\my_application.exe

# Inspect the trace
Get-Content $env:AZIHSM_NATIVEAPI_TRACE_FILE | Select-Object -First 50
```

### Output Format

Each line in the trace file contains a structured event with the following fields:

* **Timestamp** — UTC wall-clock time (e.g., `2026-06-12T17:13:42.223204Z`)
* **Level** — `TRACE`, `DEBUG`, `INFO`, `WARN`, or `ERROR`
* **Thread ID** — Identifies the originating thread (e.g., `ThreadId(01)`)
* **Span context** — Nested call chain showing the path through the SDK
* **Target** — The Rust module that emitted the event (e.g., `azihsm_api::partition`)
* **Message** — The log message and any structured fields

Example output:

```text
2026-06-12T17:13:42.223204Z  INFO ThreadId(01) partition_info_list: azihsm_api::partition: enter
2026-06-12T17:13:42.224544Z DEBUG ThreadId(01) partition_info_list:dev_paths:dev_info_list{self=DdiMock}: azihsm_ddi_mock::ddi: Got DdiMock device info list size=1
```

### Behavior Notes

* Tracing initialization occurs exactly once, on the first API call.
  Subsequent calls incur no overhead.
* If `AZIHSM_NATIVEAPI_TRACE_FILE` is not set, no subscriber is installed and there is no performance impact.
* If the trace file cannot be opened (e.g., invalid path or permission denied), the library silently continues without tracing.
* The trace subscriber is global to the process.
  If another subscriber has already been installed (e.g., by the host application), the library's subscriber will not replace it.

