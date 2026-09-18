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
use nix::sys::socket::socket;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::SockFlag;
use nix::sys::socket::SockType;
use nix::sys::socket::VsockAddr;
use nix::unistd::close;
use nix::unistd::read;
use nix::unistd::write;
use tracing_subscriber::EnvFilter;

const PAGE_SIZE: usize = 4096;
const MAX_SRC_LEN: usize = PAGE_SIZE;
const MAX_DST_LEN: usize = 2 * PAGE_SIZE;
const OOB_DESCRIPTOR_SIZE: usize = 16;
const TRANSPORT_ERROR: u32 = 1;
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

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
        accept4(self.0, SockFlag::SOCK_CLOEXEC)
            .map(VsockStream)
            .map_err(nix_to_io)
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
        write(self.0, buffer).map_err(nix_to_io)
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

fn serve_connection(
    stream: &mut (impl Read + Write),
    hsm: &StdHsm,
    runtime: &tokio::runtime::Handle,
    partition_id: u8,
) -> Result<()> {
    let mut request_id = 0u64;
    loop {
        debug!("Waiting for request frame");
        tracing::trace!("Waiting for request frame");
        let request = match Request::read_from(stream) {
            Ok(request) => request,
            Err(azihsm_ddi_sock_proto::ProtoError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                debug!("Client disconnected");
                tracing::debug!(kind = ?error.kind(), "Client disconnected");
                // A disconnect signals a device reset, so reset the partition here
                if let Err(reset_error) = runtime.block_on(hsm.part_disable(partition_id)) {
                    tracing::warn!(?reset_error, "Failed to disable partition on reset");
                }
                if let Err(reset_error) = runtime.block_on(hsm.part_enable(partition_id)) {
                    tracing::warn!(?reset_error, "Failed to re-enable partition on reset");
                }
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
        response.write_to(stream)?;
        debug!("Request finished");
        tracing::debug!(
            transport_status = response.status,
            elapsed_us = started.elapsed().as_micros(),
            "Request finished"
        );
    }
}

fn serve_connection_logged(
    mut stream: impl Read + Write,
    hsm: &StdHsm,
    runtime: &tokio::runtime::Handle,
    partition_id: u8,
) {
    let connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    tracing::info!(connection_id, "Connected HSM client");
    let connection_span = tracing::info_span!("connection", connection_id);
    let _connection_guard = connection_span.enter();
    tracing::debug!("Started connection worker");
    if let Err(error) = serve_connection(&mut stream, hsm, runtime, partition_id) {
        tracing::warn!(?error, "HSM client connection closed with an error");
    } else {
        tracing::info!("HSM client connection closed");
    }
}

fn main() -> Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("vsocksrv=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    let args = Args::parse();
    if args.partition_id >= 65 {
        bail!("Partition ID must be less than 65");
    }

    let mut unix_stream = if matches!(args.socket_type, SocketType::Unix) {
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
                serve_connection_logged(stream, &hsm, runtime.handle(), args.partition_id);
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
                match serve_connection(&mut stream, &hsm, runtime.handle(), args.partition_id) {
                    Ok(()) => {
                        debug!("HSM client disconnected; reconnecting");
                        tracing::info!("HSM client disconnected; reconnecting");
                    }
                    Err(error) => {
                        debug!("HSM connection failed; reconnecting");
                        tracing::warn!(?error, "HSM connection failed; reconnecting");
                    }
                }
                stream = connect_unix(path, args.port)
                    .context("Failed to reconnect to AF_UNIX")?;
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
