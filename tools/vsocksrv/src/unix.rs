// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::Read;
use std::io::Write;
use std::io::{self};
use std::os::fd::RawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use azihsm_ddi_sock_proto::OobItem;
use azihsm_ddi_sock_proto::Request;
use azihsm_ddi_sock_proto::Response;
use azihsm_fw_hsm_io::Cqe;
use azihsm_fw_hsm_io::Sqe;
use azihsm_fw_hsm_std::StdHsm;
use clap::Parser;
use clap::ValueEnum;
use log::debug;
use nix::sys::socket::accept4;
use nix::sys::socket::bind;
use nix::sys::socket::listen;
use nix::sys::socket::send;
use nix::sys::socket::setsockopt;
use nix::sys::socket::socket;
use nix::sys::socket::sockopt::ReceiveTimeout;
use nix::sys::socket::sockopt::SendTimeout;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::MsgFlags;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockType;
use nix::sys::socket::VsockAddr;
use nix::sys::time::TimeVal;
use nix::unistd::close;
use nix::unistd::read;
use tracing_subscriber::EnvFilter;

const PAGE_SIZE: usize = 4096;
const MAX_SRC_LEN: usize = PAGE_SIZE;
const MAX_DST_LEN: usize = 2 * PAGE_SIZE;
const OOB_DESCRIPTOR_SIZE: usize = 16;
const TRANSPORT_ERROR: u32 = 1;
/// Connections are served one at a time (see `serve_connection_logged`), so
/// an idle or stalled AF_VSOCK client must not be allowed to occupy the
/// server indefinitely and lock out every other client. Any accepted
/// connection that doesn't send a full request within this window is
/// treated the same as a disconnect: the partition is reset and the
/// connection is dropped so the next client can be accepted.
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Adjusts a stream's per-syscall socket timeouts.
///
/// `SO_RCVTIMEO`/`SO_SNDTIMEO` only bound a single blocking syscall, not
/// however many syscalls a multi-read/write operation (e.g.
/// `Request::read_from`, `Response::write_to`) ends up making. [`DeadlineRead`]
/// and [`DeadlineWrite`] use this to shrink the underlying socket timeout to
/// whatever time remains of their overall deadline before every syscall, so
/// a peer that paces bytes just under the *socket* timeout still cannot
/// exceed the overall deadline.
trait SetSocketTimeouts {
    fn set_read_timeout(&self, timeout: Duration) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Duration) -> io::Result<()>;
}

impl SetSocketTimeouts for UnixStream {
    fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
        UnixStream::set_read_timeout(self, Some(timeout))
    }

    fn set_write_timeout(&self, timeout: Duration) -> io::Result<()> {
        UnixStream::set_write_timeout(self, Some(timeout))
    }
}

impl SetSocketTimeouts for VsockStream {
    fn set_read_timeout(&self, timeout: Duration) -> io::Result<()> {
        setsockopt(self.0, ReceiveTimeout, &duration_to_timeval(timeout)).map_err(nix_to_io)
    }

    fn set_write_timeout(&self, timeout: Duration) -> io::Result<()> {
        setsockopt(self.0, SendTimeout, &duration_to_timeval(timeout)).map_err(nix_to_io)
    }
}

fn duration_to_timeval(duration: Duration) -> TimeVal {
    let micros = duration.as_micros().max(1);
    TimeVal::new((micros / 1_000_000) as i64, (micros % 1_000_000) as i64)
}

/// Returns the time remaining until `deadline`, or an
/// [`io::ErrorKind::TimedOut`] error if it has already passed.
fn remaining_or_timed_out(deadline: Instant) -> io::Result<Duration> {
    let now = Instant::now();
    if now >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "connection deadline exceeded",
        ));
    }
    Ok(deadline - now)
}

/// Wraps a `Read` with an overall deadline that bounds the *total* time
/// spent reading a single frame, not just each individual blocking
/// syscall.
///
/// The AF_VSOCK/AF_UNIX socket-level `SO_RCVTIMEO` (see
/// `CONNECTION_READ_TIMEOUT`) only bounds how long a single `read()`
/// syscall can block; it does not bound how long `Request::read_from` (or
/// any other multi-read parse) takes overall. A peer that drips one byte
/// just under that timeout apart could otherwise keep completing
/// individual reads forever while still taking arbitrarily long to
/// deliver a full frame, defeating the timeout and occupying this
/// single-threaded server indefinitely. Shrinking the socket's own
/// `SO_RCVTIMEO` to whatever remains of the overall deadline before every
/// read (rather than just checking the deadline before calling into a
/// `read()` that can still block for the full socket timeout) bounds the
/// total wall-clock time regardless of how the peer paces its writes.
struct DeadlineRead<'a, T: Read + SetSocketTimeouts> {
    inner: &'a mut T,
    deadline: Instant,
}

impl<T: Read + SetSocketTimeouts> Read for DeadlineRead<'_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = remaining_or_timed_out(self.deadline)?;
        self.inner.set_read_timeout(remaining)?;
        self.inner.read(buf)
    }
}

/// Wraps a `Write` with an overall deadline that bounds the *total* time
/// spent writing a single response, not just each individual blocking
/// syscall. Mirrors [`DeadlineRead`]'s reasoning: `SO_SNDTIMEO` only bounds
/// one `write()` syscall, so a peer that drains just a few bytes right
/// before each timeout could otherwise keep `Response::write_to` blocked
/// indefinitely across many individually-timed-out-but-successful writes.
struct DeadlineWrite<'a, T: Write + SetSocketTimeouts> {
    inner: &'a mut T,
    deadline: Instant,
}

impl<T: Write + SetSocketTimeouts> Write for DeadlineWrite<'_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = remaining_or_timed_out(self.deadline)?;
        self.inner.set_write_timeout(remaining)?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SocketType {
    Vsock,
    Unix,
}

#[derive(Debug, Parser)]
#[command(about = "Serve StdHsm requests over AF_VSOCK or AF_UNIX")]
struct Args {
    /// AF_VSOCK listen port or AF_UNIX guest destination port.
    #[arg(long)]
    port: u32,

    /// Socket transport to use.
    #[arg(long, value_enum, default_value_t = SocketType::Vsock)]
    socket_type: SocketType,

    /// Cloud Hypervisor AF_UNIX socket path.
    #[arg(long, required_if_eq("socket_type", "unix"))]
    unix_socket: Option<PathBuf>,

    /// Local CID on which to listen. Defaults to any local CID.
    #[arg(long, default_value_t = libc::VMADDR_CID_ANY)]
    cid: u32,

    /// HSM partition used for submitted requests.
    #[arg(long, default_value_t = 3)]
    partition_id: u8,
}

#[repr(C, align(4096))]
struct DmaPages<const SIZE: usize>([u8; SIZE]);

impl<const SIZE: usize> DmaPages<SIZE> {
    fn zeroed() -> Self {
        Self([0; SIZE])
    }

    fn address(&self) -> u64 {
        self.0.as_ptr() as u64
    }
}

struct PreparedRequest {
    sqe: [u32; 16],
    destination: Box<DmaPages<MAX_DST_LEN>>,
    _source: Box<DmaPages<MAX_SRC_LEN>>,
    _oob_descriptors: Option<Box<DmaPages<PAGE_SIZE>>>,
    _oob_data: Vec<Vec<u8>>,
}

impl PreparedRequest {
    fn new(request: Request) -> Result<Self> {
        let src_len = request.sqe[1] as usize;
        let dst_len = request.sqe[6] as usize;
        let oob_len = request.sqe[15] as usize;

        debug!(
            "src_len {:?} dst_len {:?} oob_len {:?}",
            src_len, dst_len, oob_len
        );
        if src_len == 0 || src_len > MAX_SRC_LEN || request.payload.len() != src_len {
            bail!("Invalid source payload length");
        }
        if dst_len == 0 || dst_len > MAX_DST_LEN {
            bail!("Invalid destination length");
        }
        let expected_oob_len = request
            .oob
            .len()
            .checked_mul(OOB_DESCRIPTOR_SIZE)
            .context("OOB descriptor length overflow")?;
        if oob_len != expected_oob_len || oob_len > PAGE_SIZE {
            bail!("Invalid OOB descriptor length");
        }

        tracing::trace!(
            src_len,
            dst_len,
            oob_descriptors = request.oob.len(),
            oob_bytes = request
                .oob
                .iter()
                .map(|item| item.data.len())
                .sum::<usize>(),
            "Validated request buffers"
        );

        let mut source = Box::new(DmaPages::<MAX_SRC_LEN>::zeroed());
        source.0[..src_len].copy_from_slice(&request.payload);
        let destination = Box::new(DmaPages::<MAX_DST_LEN>::zeroed());

        let mut oob_data: Vec<Vec<u8>> = request.oob.iter().map(|item| item.data.clone()).collect();
        let mut oob_descriptors =
            (!request.oob.is_empty()).then(|| Box::new(DmaPages::<PAGE_SIZE>::zeroed()));
        if let Some(page) = oob_descriptors.as_mut() {
            for (index, (item, data)) in request.oob.iter().zip(&mut oob_data).enumerate() {
                tracing::trace!(index, len = data.len(), "Re-homing OOB item");
                let descriptor = rehome_oob_descriptor(item, data)?;
                let offset = index * OOB_DESCRIPTOR_SIZE;
                page.0[offset..offset + OOB_DESCRIPTOR_SIZE].copy_from_slice(&descriptor);
            }
        }

        let mut sqe = request.sqe;
        set_address(&mut sqe, 2, source.address());
        set_address(&mut sqe, 4, 0);
        set_address(&mut sqe, 7, destination.address());
        let dst_prp2 = if dst_len > PAGE_SIZE {
            destination.address() + PAGE_SIZE as u64
        } else {
            0
        };
        set_address(&mut sqe, 9, dst_prp2);
        set_address(
            &mut sqe,
            13,
            oob_descriptors.as_ref().map_or(0, |page| page.address()),
        );

        Ok(Self {
            sqe,
            destination,
            _source: source,
            _oob_descriptors: oob_descriptors,
            _oob_data: oob_data,
        })
    }

    fn response(self, mut cqe: [u32; 4]) -> Response {
        let cqe_view = Cqe::from(&mut cqe);
        let dst_len = cqe_view.dst_len() as usize;
        if dst_len > self.sqe[6] as usize || dst_len > self.destination.0.len() {
            tracing::warn!(
                dst_len,
                requested_len = self.sqe[6],
                "HSM completion reported an invalid destination length"
            );
            return error_response();
        }
        tracing::debug!(status = cqe_view.status(), dst_len, "Prepared HSM response");
        Response {
            status: 0,
            cqe,
            payload: self.destination.0[..dst_len].to_vec(),
        }
    }
}

fn rehome_oob_descriptor(item: &OobItem, data: &mut [u8]) -> Result<[u8; 16]> {
    let descriptor_len = u32::from_le_bytes([
        item.descriptor[8],
        item.descriptor[9],
        item.descriptor[10],
        item.descriptor[11],
    ]) as usize;
    if descriptor_len != data.len() {
        bail!("OOB descriptor length does not match its data");
    }

    let mut descriptor = item.descriptor;
    descriptor[..8].copy_from_slice(&(data.as_ptr() as u64).to_le_bytes());
    Ok(descriptor)
}

fn set_address(sqe: &mut [u32; 16], dword: usize, address: u64) {
    sqe[dword] = address as u32;
    sqe[dword + 1] = (address >> 32) as u32;
}

fn error_response() -> Response {
    Response {
        status: TRANSPORT_ERROR,
        cqe: [0; 4],
        payload: Vec::new(),
    }
}

struct VsockListener(RawFd);

impl VsockListener {
    fn bind(cid: u32, port: u32) -> io::Result<Self> {
        let fd = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(nix_to_io)?;
        bind(fd, &VsockAddr::new(cid, port)).map_err(nix_to_io)?;
        listen(fd, 128).map_err(nix_to_io)?;
        Ok(Self(fd))
    }

    fn accept(&self) -> io::Result<VsockStream> {
        let fd = accept4(self.0, SockFlag::SOCK_CLOEXEC).map_err(nix_to_io)?;
        // Bound how long a single connection can occupy the server (see
        // `CONNECTION_READ_TIMEOUT`).
        let timeout = TimeVal::new(
            CONNECTION_READ_TIMEOUT.as_secs() as i64,
            i64::from(CONNECTION_READ_TIMEOUT.subsec_micros()),
        );
        if let Err(error) = setsockopt(fd, ReceiveTimeout, &timeout) {
            let _ = close(fd);
            return Err(nix_to_io(error));
        }
        if let Err(error) = setsockopt(fd, SendTimeout, &timeout) {
            let _ = close(fd);
            return Err(nix_to_io(error));
        }
        Ok(VsockStream(fd))
    }
}

impl Drop for VsockListener {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

struct VsockStream(RawFd);

impl Read for VsockStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        read(self.0, buffer).map_err(nix_to_io)
    }
}

impl Write for VsockStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        send(self.0, buffer, MsgFlags::MSG_NOSIGNAL).map_err(nix_to_io)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}

fn nix_to_io(error: nix::Error) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn write_connect_command(stream: &mut impl Write, port: u32) -> io::Result<()> {
    writeln!(stream, "CONNECT {port}")?;
    stream.flush()
}

fn connect_unix(path: &Path, port: u32) -> io::Result<UnixStream> {
    loop {
        match UnixStream::connect(path) {
            Ok(mut stream) => {
                // Bound how long a single connection can occupy the server
                // (see `CONNECTION_READ_TIMEOUT`), matching the timeouts
                // `VsockListener::accept` applies to AF_VSOCK connections.
                // Without this, a stalled AF_UNIX peer could block
                // `serve_connection_and_reset` forever, preventing the
                // single-threaded server from resetting and serving any
                // other client.
                stream.set_read_timeout(Some(CONNECTION_READ_TIMEOUT))?;
                stream.set_write_timeout(Some(CONNECTION_READ_TIMEOUT))?;
                write_connect_command(&mut stream, port)?;
                return Ok(stream);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                tracing::debug!(socket = %path.display(), ?error, "Waiting for AF_UNIX listener");
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
}

/// Number of attempts to re-enable a partition after a disconnect-triggered
/// reset before giving up and logging at `error` level. `part_alloc`/
/// `part_enable` failures are expected to be rare and transient (e.g.
/// contention with a concurrent request), so a few immediate retries are
/// cheap insurance against leaving the partition disabled - and therefore
/// unusable by every subsequent connection - after a single failed
/// attempt.
const PARTITION_ENABLE_RETRIES: u32 = 3;

/// Frees then re-allocates and re-enables `partition_id`, which clears its
/// keys, nonce, vault, *and* fully releases its sessions. Called when a
/// client disconnects, since a disconnect signals a device reset.
///
/// This deliberately uses `part_free`/`part_alloc`, not
/// `part_disable`/`part_enable`: `part_disable` preserves any live sessions
/// across the cycle (marked `NeedsRenegotiation`, so a later `ReopenSession`
/// can re-key them), mirroring real hardware NSSR semantics - it does not
/// free session slots. Since vsocksrv drops a client's connection without
/// ever explicitly closing its sessions, `part_disable`/`part_enable` would
/// leak one session slot per connection until the partition's session table
/// is exhausted. `part_free` clears the session table outright, so each
/// reset starts the next client with zero live sessions.
///
/// Retries `part_alloc`/`part_enable` a few times on failure. Once
/// `part_alloc` succeeds, later attempts only retry `part_enable` -
/// re-calling `part_alloc` on an already-`Allocated` partition would just
/// fail, permanently stranding the partition after a single transient
/// `part_enable` failure. Returns an error if the partition could not be
/// returned to a usable (`Enabled`) state after all retries; the caller
/// must treat that as fatal (stop serving further clients), since
/// continuing on a partition that isn't known to be freshly reset would
/// violate the isolation invariant this reset exists to uphold.
fn reset_partition(hsm: &StdHsm, runtime: &tokio::runtime::Handle, partition_id: u8) -> Result<()> {
    if let Err(error) = runtime.block_on(hsm.part_free(partition_id)) {
        tracing::warn!(?error, "Failed to free partition on reset");
    }
    let res_mask = 1u128 << u32::from(partition_id);
    let mut allocated = false;
    let mut last_error = None;
    for attempt in 1..=PARTITION_ENABLE_RETRIES {
        if !allocated {
            match runtime.block_on(hsm.part_alloc(partition_id, res_mask)) {
                Ok(()) => allocated = true,
                Err(error) => {
                    tracing::warn!(?error, attempt, "Failed to re-allocate partition on reset");
                    last_error = Some(error);
                    continue;
                }
            }
        }
        match runtime.block_on(hsm.part_enable(partition_id)) {
            Ok(()) => return Ok(()),
            Err(error) => {
                tracing::warn!(?error, attempt, "Failed to re-enable partition on reset");
                last_error = Some(error);
            }
        }
    }
    let error = last_error.expect("loop runs at least once and only exits early via return Ok");
    tracing::error!(
        ?error,
        "Failed to reset partition after all retries; partition is unusable until the server \
         is restarted"
    );
    Err(anyhow!(
        "Failed to reset partition after all retries: {error:?}"
    ))
}

/// Serves a single connection until it ends (cleanly, via timeout, or via
/// error), then unconditionally resets the partition, since *any* end of a
/// connection signals a device reset. This must not be skipped for any exit
/// path (including protocol/decode errors or a failed response write),
/// otherwise the next client on the same shared partition could observe the
/// previous client's live keys/sessions/vault state.
///
/// A connection-level error (protocol decode failure, I/O error, etc.) is
/// logged here and does not fail this function - only a *reset* failure
/// does, since that is the condition callers must treat as fatal (see
/// `reset_partition`).
fn serve_connection_and_reset(
    stream: &mut (impl Read + Write + SetSocketTimeouts),
    hsm: &StdHsm,
    runtime: &tokio::runtime::Handle,
    partition_id: u8,
) -> Result<()> {
    match serve_connection(stream, hsm, runtime, partition_id) {
        Ok(()) => tracing::info!("HSM client connection closed"),
        Err(error) => tracing::warn!(?error, "HSM client connection closed with an error"),
    }
    reset_partition(hsm, runtime, partition_id)
}

fn serve_connection(
    stream: &mut (impl Read + Write + SetSocketTimeouts),
    hsm: &StdHsm,
    runtime: &tokio::runtime::Handle,
    partition_id: u8,
) -> Result<()> {
    let mut request_id = 0u64;
    loop {
        debug!("Waiting for request frame");
        tracing::trace!("Waiting for request frame");
        let mut deadline_stream = DeadlineRead {
            inner: stream,
            deadline: Instant::now() + CONNECTION_READ_TIMEOUT,
        };
        let request = match Request::read_from(&mut deadline_stream) {
            Ok(request) => request,
            Err(azihsm_ddi_sock_proto::ProtoError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) =>
            {
                // WouldBlock/TimedOut means the connection's read timeout
                // (see `CONNECTION_READ_TIMEOUT`) expired; treat a stalled
                // client the same as a disconnect so it can't hold up every
                // other client waiting to be served.
                debug!("Client disconnected");
                tracing::debug!(kind = ?error.kind(), "Client disconnected");
                // The caller (`serve_connection_and_reset`) resets the
                // partition unconditionally, since any end of a connection
                // signals a device reset.
                return Ok(());
            }
            Err(error) => {
                debug!("Failed to decode request frame");
                tracing::warn!(?error, "Failed to decode request frame");
                return Err(error.into());
            }
        };

        request_id += 1;
        let sqe = Sqe::from(&request.sqe);
        let request_span = tracing::debug_span!(
            "request",
            request_id,
            command_id = sqe.cmd_id(),
            opcode = sqe.op(),
            src_len = sqe.src_len(),
            dst_len = sqe.dst_len(),
            oob_count = request.oob.len(),
        );
        let _request_guard = request_span.enter();
        debug!("Received request frame");
        tracing::debug!("Received request frame");
        let started = Instant::now();
        let response = match PreparedRequest::new(request) {
            Ok(prepared) => {
                debug!("Submitting request to StdHsm");
                tracing::trace!(partition_id, "Submitting request to StdHsm");
                match runtime.block_on(hsm.io(prepared.sqe, partition_id, 0, 0)) {
                    Ok(cqe) => {
                        debug!("StdHsm request completed");
                        tracing::debug!(
                            elapsed_us = started.elapsed().as_micros(),
                            "StdHsm request completed"
                        );
                        prepared.response(cqe)
                    }
                    Err(error) => {
                        debug!("HSM request failed");
                        tracing::warn!(
                            ?error,
                            elapsed_us = started.elapsed().as_micros(),
                            "HSM request failed"
                        );
                        error_response()
                    }
                }
            }
            Err(error) => {
                debug!("Invalid HSM request");
                tracing::warn!(?error, "Invalid HSM request");
                error_response()
            }
        };
        debug!("Writing response frame");
        tracing::trace!(
            transport_status = response.status,
            payload_len = response.payload.len(),
            "Writing response frame"
        );
        response.write_to(&mut DeadlineWrite {
            inner: stream,
            deadline: Instant::now() + CONNECTION_READ_TIMEOUT,
        })?;
        debug!("Request finished");
        tracing::debug!(
            transport_status = response.status,
            elapsed_us = started.elapsed().as_micros(),
            "Request finished"
        );
    }
}

/// Serves one accepted connection under a per-connection tracing span,
/// then propagates any partition reset failure (see
/// `serve_connection_and_reset`) so the caller can stop accepting further
/// clients rather than serving them on a partition that isn't known to be
/// freshly reset.
fn serve_connection_logged(
    mut stream: impl Read + Write + SetSocketTimeouts,
    hsm: &StdHsm,
    runtime: &tokio::runtime::Handle,
    partition_id: u8,
) -> Result<()> {
    let connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    tracing::info!(connection_id, "Connected HSM client");
    let connection_span = tracing::info_span!("connection", connection_id);
    let _connection_guard = connection_span.enter();
    tracing::debug!("Started connection worker");
    serve_connection_and_reset(&mut stream, hsm, runtime, partition_id)
}

pub(crate) fn main() -> Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("vsocksrv=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let args = Args::parse();
    if args.partition_id >= 65 {
        bail!("Partition ID must be less than 65");
    }

    let unix_stream = if matches!(args.socket_type, SocketType::Unix) {
        debug!("Setting up UNIX socket");
        let path = args
            .unix_socket
            .as_ref()
            .context("AF_UNIX socket is required")?;
        tracing::info!(socket = %path.display(), port = args.port, "Connecting to Cloud Hypervisor");
        let stream = connect_unix(path, args.port).context("Failed to connect to AF_UNIX")?;
        tracing::info!(
            socket = %path.display(),
            port = args.port,
            "Connected to Cloud Hypervisor"
        );
        debug!("Set up UNIX socket");
        Some(stream)
    } else {
        None
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_time()
        .build()
        .context("Failed to create Tokio runtime")?;
    tracing::debug!("Created Tokio runtime");
    let hsm = Arc::new(StdHsm::with_tokio(runtime.handle().clone()));
    tracing::debug!(partition_id = args.partition_id, "Created StdHsm");

    let result = serve(&args, &runtime, &hsm, unix_stream);
    if result.is_err() {
        // `StdHsm::drop` joins its Embassy background thread, but that
        // thread's `run()` future is intentionally pending forever (the
        // Embassy tasks that actually do work - `poll_io`/`ipc_task` - are
        // spawned separately and never make `run()` itself return). So
        // once any fatal error occurs here, letting `hsm` drop normally
        // would hang the process forever instead of exiting with an
        // error. Skip its destructor: the process is about to exit
        // anyway, so the OS reclaims every resource `StdHsm` holds.
        std::mem::forget(hsm);
    }
    result
}

fn serve(
    args: &Args,
    runtime: &tokio::runtime::Runtime,
    hsm: &Arc<StdHsm>,
    mut unix_stream: Option<UnixStream>,
) -> Result<()> {
    runtime
        .block_on(hsm.part_alloc(args.partition_id, 1u128 << u32::from(args.partition_id)))
        .map_err(|error| anyhow!("Failed to allocate HSM partition: {error:?}"))?;
    tracing::info!(partition_id = args.partition_id, "Allocated HSM partition");
    runtime
        .block_on(hsm.part_enable(args.partition_id))
        .map_err(|error| anyhow!("Failed to enable HSM partition: {error:?}"))?;
    tracing::info!(partition_id = args.partition_id, "Enabled HSM partition");

    match args.socket_type {
        SocketType::Vsock => {
            debug!("Socket Type VSOCK");
            let listener =
                VsockListener::bind(args.cid, args.port).context("Failed to bind AF_VSOCK")?;
            tracing::info!(
                cid = args.cid,
                port = args.port,
                "Listening for HSM requests"
            );
            loop {
                let stream = listener
                    .accept()
                    .context("Failed to accept AF_VSOCK connection")?;
                // Serve one connection at a time: a disconnect resets the
                // shared HSM partition (see `serve_connection`), and
                // `partition_id` is a single process-wide value, so
                // concurrent connections would let one client's
                // disconnect wipe another's live sessions/keys. Handling
                // connections serially also removes any need to bound
                // concurrent threads against this untrusted listener.
                serve_connection_logged(stream, hsm, runtime.handle(), args.partition_id).context(
                    "Partition reset failed after a client disconnected; refusing to \
                         serve further clients on a partition that isn't known to be reset",
                )?;
            }
        }
        SocketType::Unix => {
            debug!("Socket Type UNIX");
            let path = args
                .unix_socket
                .as_ref()
                .context("AF_UNIX socket is required")?;
            let mut stream = unix_stream.take().context("AF_UNIX stream is missing")?;
            loop {
                serve_connection_and_reset(&mut stream, hsm, runtime.handle(), args.partition_id)
                    .context(
                    "Partition reset failed after a client disconnected; refusing to \
                         serve further clients on a partition that isn't known to be reset",
                )?;
                debug!("HSM client disconnected; reconnecting");
                tracing::info!("HSM client disconnected; reconnecting");
                stream = connect_unix(path, args.port).context("Failed to reconnect to AF_UNIX")?;
                tracing::info!(
                    socket = %path.display(),
                    port = args.port,
                    "Reconnected to Cloud Hypervisor"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn request(payload: Vec<u8>, destination_len: u32, oob: Vec<OobItem>) -> Request {
        let mut sqe = [0; 16];
        sqe[1] = payload.len() as u32;
        sqe[6] = destination_len;
        sqe[15] = (oob.len() * OOB_DESCRIPTOR_SIZE) as u32;
        Request { sqe, payload, oob }
    }

    #[test]
    fn prepares_local_dma_addresses() {
        let mut descriptor = [0; OOB_DESCRIPTOR_SIZE];
        descriptor[8..12].copy_from_slice(&4u32.to_le_bytes());
        let prepared = PreparedRequest::new(request(
            vec![1, 2, 3],
            MAX_DST_LEN as u32,
            vec![OobItem {
                descriptor,
                data: vec![4, 5, 6, 7],
            }],
        ))
        .unwrap();

        let address =
            |dword| u64::from(prepared.sqe[dword]) | (u64::from(prepared.sqe[dword + 1]) << 32);
        assert_eq!(address(2), prepared._source.address());
        assert_eq!(address(7), prepared.destination.address());
        assert_eq!(
            address(9),
            prepared.destination.address() + PAGE_SIZE as u64
        );
        assert_eq!(
            address(13),
            prepared._oob_descriptors.as_ref().unwrap().address()
        );
        assert_eq!(address(2) % PAGE_SIZE as u64, 0);
        assert_eq!(address(7) % PAGE_SIZE as u64, 0);
        assert_eq!(address(13) % PAGE_SIZE as u64, 0);

        let page = &prepared._oob_descriptors.as_ref().unwrap().0;
        let oob_address = u64::from_le_bytes(page[..8].try_into().unwrap());
        assert_eq!(oob_address, prepared._oob_data[0].as_ptr() as u64);
    }

    #[test]
    fn rejects_payload_length_mismatch() {
        let mut request = request(vec![1, 2, 3], PAGE_SIZE as u32, Vec::new());
        request.sqe[1] = 4;
        assert!(PreparedRequest::new(request).is_err());
    }

    #[test]
    fn rejects_oob_count_mismatch() {
        let mut request = request(vec![1], PAGE_SIZE as u32, Vec::new());
        request.sqe[15] = OOB_DESCRIPTOR_SIZE as u32;
        assert!(PreparedRequest::new(request).is_err());
    }

    #[test]
    fn writes_unix_connect_command() {
        let mut command = Vec::new();
        write_connect_command(&mut command, 1234).unwrap();
        assert_eq!(command, b"CONNECT 1234\n");
    }
}
