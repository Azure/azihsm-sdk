// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AZIHSM Simulator Service
//!
//! A standalone service that hosts the AZIHSM simulator (`Dispatcher`) and exposes
//! it over a Unix Domain Socket. Multiple client processes can connect simultaneously
//! and share the same simulated HSM device state.
//!
//! # Usage
//!
//! ```sh
//! # Start the service (uses default socket path)
//! azihsm-sim-service
//!
//! # Start with a custom socket path
//! AZIHSM_SIM_SOCKET=/tmp/my-sim.sock azihsm-sim-service
//!
//! # Start with custom table count via features
//! azihsm-sim-service  # uses TABLE_COUNT based on compiled features
//! ```

use std::io::BufReader;
use std::io::BufWriter;
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::thread;

use azihsm_ddi_sim::dispatcher::Dispatcher;
use azihsm_ddi_sim_service::protocol::*;
use parking_lot::RwLock;

/// Default socket path if `AZIHSM_SIM_SOCKET` is not set.
const DEFAULT_SOCKET_PATH: &str = "/tmp/azihsm-sim.sock";

/// Environment variable to override the socket path.
const SOCKET_PATH_ENV: &str = "AZIHSM_SIM_SOCKET";

#[cfg(feature = "table-4")]
const TABLE_COUNT: usize = 4;
#[cfg(feature = "table-64")]
const TABLE_COUNT: usize = 64;
#[cfg(not(any(feature = "table-4", feature = "table-64")))]
const TABLE_COUNT: usize = 1;

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let socket_path = std::env::var(SOCKET_PATH_ENV).unwrap_or_else(|_| {
        DEFAULT_SOCKET_PATH.to_string()
    });

    // Clean up stale socket file
    if std::path::Path::new(&socket_path).exists() {
        tracing::info!("Removing stale socket file: {}", socket_path);
        if let Err(e) = std::fs::remove_file(&socket_path) {
            tracing::error!("Failed to remove stale socket: {}", e);
            std::process::exit(1);
        }
    }

    // Create the shared dispatcher
    let dispatcher = match Dispatcher::new(TABLE_COUNT) {
        Ok(d) => Arc::new(RwLock::new(d)),
        Err(e) => {
            tracing::error!("Failed to create dispatcher: {:?}", e);
            std::process::exit(1);
        }
    };

    // Bind to the UDS
    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to {}: {}", socket_path, e);
            std::process::exit(1);
        }
    };

    tracing::info!("AZIHSM sim-service listening on {}", socket_path);

    // Set up signal handler so we clean up the socket on shutdown
    let socket_path_cleanup = socket_path.clone();
    if let Err(e) = ctrlc_handler(&socket_path_cleanup) {
        tracing::warn!("Failed to set Ctrl-C handler: {}", e);
    }

    // Accept connections
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let dispatcher = dispatcher.clone();
                thread::spawn(move || {
                    handle_client(stream, dispatcher);
                });
            }
            Err(e) => {
                tracing::error!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Set up a Ctrl-C handler that removes the socket file before exit.
fn ctrlc_handler(socket_path: &str) -> Result<(), std::io::Error> {
    let path = socket_path.to_string();

    // Use a simple approach: register a SIGTERM/SIGINT handler
    // We'll rely on the process exiting to trigger cleanup via Drop or atexit.
    // For now, just ensure the socket is cleaned up on normal exit.
    // A more robust approach can be added later.
    let _ = path; // Placeholder for future signal handler

    Ok(())
}

/// Handle a single client connection. Runs in its own thread.
fn handle_client(stream: std::os::unix::net::UnixStream, dispatcher: Arc<RwLock<Dispatcher>>) {
    let peer = stream
        .peer_addr()
        .map(|a| format!("{a:?}"))
        .unwrap_or_else(|_| "unknown".to_string());
    tracing::info!("Client connected: {}", peer);

    let read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to clone stream: {}", e);
            return;
        }
    };

    let mut reader = BufReader::new(read_stream);
    let mut writer = BufWriter::new(stream);

    loop {
        let request = match read_request(&mut reader) {
            Ok(Some(req)) => req,
            Ok(None) => {
                tracing::info!("Client disconnected: {}", peer);
                break;
            }
            Err(e) => {
                tracing::error!("Error reading request from {}: {}", peer, e);
                break;
            }
        };

        if let Err(e) = process_request(&dispatcher, request, &mut writer) {
            tracing::error!("Error processing request for {}: {}", peer, e);
            break;
        }
    }
}

/// Process a single request and write the response.
fn process_request(
    dispatcher: &Arc<RwLock<Dispatcher>>,
    request: Request,
    writer: &mut impl std::io::Write,
) -> std::io::Result<()> {
    match request {
        Request::SlowPath {
            session_info,
            req_buf,
        } => {
            let mut resp_buf = vec![0u8; 8192];
            match dispatcher
                .read()
                .dispatch(session_info, &req_buf, &mut resp_buf)
            {
                Ok(session_info_response) => {
                    let resp_len = session_info_response.response_length as usize;
                    write_slow_path_response(
                        writer,
                        &session_info_response,
                        &resp_buf[..resp_len],
                    )
                }
                Err(err) => write_error_response(writer, MessageType::SlowPath, err),
            }
        }

        Request::FpGcm {
            mode,
            request,
            source_buffers,
        } => {
            let mut destination_buffers: Vec<Vec<u8>> = source_buffers
                .iter()
                .map(|inner| vec![0; inner.len()])
                .collect();

            match dispatcher.read().dispatch_fp_aes_gcm_encrypt_decrypt(
                mode,
                request,
                source_buffers,
                &mut destination_buffers,
            ) {
                Ok(resp) => write_fp_gcm_response(writer, &resp, &destination_buffers),
                Err(err) => write_error_response(writer, MessageType::FpGcm, err),
            }
        }

        Request::FpXts {
            mode,
            request,
            source_buffers,
        } => {
            let mut destination_buffers: Vec<Vec<u8>> = source_buffers
                .iter()
                .map(|inner| vec![0; inner.len()])
                .collect();

            match dispatcher.read().dispatch_fp_aes_xts_encrypt_decrypt(
                mode,
                request,
                source_buffers,
                &mut destination_buffers,
            ) {
                Ok(resp) => write_fp_xts_response(writer, &resp, &destination_buffers),
                Err(err) => write_error_response(writer, MessageType::FpXts, err),
            }
        }

        Request::FlushSession { session_id } => {
            match dispatcher.read().flush_session(session_id) {
                Ok(_) => write_ok_response(writer, MessageType::FlushSession),
                Err(err) => write_error_response(writer, MessageType::FlushSession, err),
            }
        }

        Request::MigrationSim => match dispatcher.write().dispatch_migration_sim() {
            Ok(()) => write_ok_response(writer, MessageType::MigrationSim),
            Err(err) => write_error_response(writer, MessageType::MigrationSim, err),
        },
    }
}
