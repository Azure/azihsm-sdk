// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io;
use std::os::fd::AsRawFd;
use std::os::raw::c_int;
use std::sync::Arc;

use azihsm_ddi_sock_proto::MAX_FRAME;
use azihsm_ddi_sock_proto::ProtoError;
use azihsm_ddi_sock_proto::Request;
use azihsm_ddi_sock_proto::Response;
use azihsm_fw_hsm_std::StdHsm;
use tokio::io::unix::AsyncFd;

const AF_VSOCK: c_int = 40;
const SOCK_STREAM: c_int = 1;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const O_NONBLOCK: c_int = 0x800;
const VMADDR_CID_ANY: u32 = u32::MAX;
const VSOCK_PORT: u32 = 1234;
const HSM_PARTITION_ID: u8 = 10;
const DMA_PAGE_SIZE: usize = 4096;
const TRANSPORT_INVALID_REQUEST: u32 = 1;
const TRANSPORT_HSM_ERROR: u32 = 2;

#[repr(C)]
struct SockAddrVm {
    family: u16,
    reserved: u16,
    port: u32,
    cid: u32,
    zero: [u8; 4],
}

#[repr(align(4096))]
struct DmaPage([u8; DMA_PAGE_SIZE]);

struct Socket {
    fd: c_int,
}

impl Socket {
    fn new_nonblocking(fd: c_int) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let socket = Self { fd };
        let flags = sys::fcntl_get_flags(fd);
        if flags < 0 || sys::fcntl_set_flags(fd, flags | O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }

    fn accept(&self) -> io::Result<Self> {
        Self::new_nonblocking(sys::accept(self.fd))
    }

    fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let received = sys::read(self.fd, buffer);
        if received < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(received as usize)
        }
    }

    fn write(&self, buffer: &[u8]) -> io::Result<usize> {
        let written = sys::write(self.fd, buffer);
        if written < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(written as usize)
        }
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> c_int {
        self.fd
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        sys::close(self.fd);
    }
}

#[allow(unsafe_code)]
mod sys {
    use std::os::raw::{c_int, c_void};

    use super::SockAddrVm;

    pub fn socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int {
        // SAFETY: The arguments are plain integers and socket reports errors through its return value.
        unsafe { c_socket(domain, socket_type, protocol) }
    }

    pub fn bind(socket: c_int, address: &SockAddrVm) -> c_int {
        // SAFETY: address points to a valid C-compatible SockAddrVm for the duration of the call.
        unsafe { c_bind(socket, address, std::mem::size_of::<SockAddrVm>() as u32) }
    }

    pub fn listen(socket: c_int, backlog: c_int) -> c_int {
        // SAFETY: The arguments are plain integers and listen reports errors through its return value.
        unsafe { c_listen(socket, backlog) }
    }

    pub fn accept(socket: c_int) -> c_int {
        // SAFETY: Null address pointers are permitted when the peer address is not requested.
        unsafe { c_accept(socket, std::ptr::null_mut(), std::ptr::null_mut()) }
    }

    pub fn read(fd: c_int, buffer: &mut [u8]) -> isize {
        // SAFETY: The mutable slice supplies a valid writable buffer of the provided length.
        unsafe { c_read(fd, buffer.as_mut_ptr().cast(), buffer.len()) }
    }

    pub fn write(fd: c_int, buffer: &[u8]) -> isize {
        // SAFETY: The slice supplies a valid readable buffer of the provided length.
        unsafe { c_write(fd, buffer.as_ptr().cast(), buffer.len()) }
    }

    pub fn fcntl_get_flags(fd: c_int) -> c_int {
        // SAFETY: F_GETFL takes no variadic argument and reports invalid descriptors as errors.
        unsafe { c_fcntl(fd, super::F_GETFL) }
    }

    pub fn fcntl_set_flags(fd: c_int, flags: c_int) -> c_int {
        // SAFETY: F_SETFL requires one integer variadic argument, supplied here as flags.
        unsafe { c_fcntl(fd, super::F_SETFL, flags) }
    }

    pub fn close(fd: c_int) {
        // SAFETY: close accepts any integer descriptor and reports invalid descriptors as errors.
        unsafe {
            c_close(fd);
        }
    }

    unsafe extern "C" {
        #[link_name = "socket"]
        fn c_socket(domain: c_int, socket_type: c_int, protocol: c_int) -> c_int;
        #[link_name = "bind"]
        fn c_bind(socket: c_int, address: *const SockAddrVm, address_len: u32) -> c_int;
        #[link_name = "listen"]
        fn c_listen(socket: c_int, backlog: c_int) -> c_int;
        #[link_name = "accept"]
        fn c_accept(socket: c_int, address: *mut c_void, address_len: *mut u32) -> c_int;
        #[link_name = "read"]
        fn c_read(fd: c_int, buffer: *mut c_void, count: usize) -> isize;
        #[link_name = "write"]
        fn c_write(fd: c_int, buffer: *const c_void, count: usize) -> isize;
        #[link_name = "fcntl"]
        fn c_fcntl(fd: c_int, command: c_int, ...) -> c_int;
        #[link_name = "close"]
        fn c_close(fd: c_int) -> c_int;
    }
}

fn patch_prp1(sqe: &mut [u32; 16], low_dword: usize, address: u64) {
    sqe[low_dword] = address as u32;
    sqe[low_dword + 1] = (address >> 32) as u32;
}

fn transport_error(status: u32) -> Response {
    Response {
        status,
        cqe: [0; 4],
        payload: Vec::new(),
    }
}

async fn execute_request(hsm: &StdHsm, request: Request) -> Response {
    let src_len = request.sqe[1] as usize;
    let dst_cap = request.sqe[6] as usize;
    if src_len != request.payload.len()
        || src_len > DMA_PAGE_SIZE
        || dst_cap == 0
        || dst_cap > DMA_PAGE_SIZE
    {
        return transport_error(TRANSPORT_INVALID_REQUEST);
    }

    let mut src = Box::new(DmaPage([0; DMA_PAGE_SIZE]));
    let mut dst = Box::new(DmaPage([0; DMA_PAGE_SIZE]));
    src.0[..src_len].copy_from_slice(&request.payload);

    let mut sqe = request.sqe;
    patch_prp1(&mut sqe, 2, src.0.as_ptr() as u64);
    patch_prp1(&mut sqe, 7, dst.0.as_mut_ptr() as u64);

    let cqe = match hsm.io(sqe, HSM_PARTITION_ID, 0, 0).await {
        Ok(cqe) => cqe,
        Err(error) => {
            eprintln!("StdHsm request failed: {error:?}");
            return transport_error(TRANSPORT_HSM_ERROR);
        }
    };
    let dst_len = (cqe[0] & 0xffff) as usize;
    if dst_len > dst_cap {
        return transport_error(TRANSPORT_HSM_ERROR);
    }

    Response {
        status: 0,
        cqe,
        payload: dst.0[..dst_len].to_vec(),
    }
}

async fn read_exact(stream: &AsyncFd<Socket>, mut buffer: &mut [u8]) -> io::Result<()> {
    while !buffer.is_empty() {
        let mut ready = stream.readable().await?;
        match ready.try_io(|inner| inner.get_ref().read(buffer)) {
            Ok(Ok(0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(Ok(count)) => buffer = &mut buffer[count..],
            Ok(Err(error)) => return Err(error),
            Err(_) => {}
        }
    }
    Ok(())
}

async fn write_all(stream: &AsyncFd<Socket>, mut buffer: &[u8]) -> io::Result<()> {
    while !buffer.is_empty() {
        let mut ready = stream.writable().await?;
        match ready.try_io(|inner| inner.get_ref().write(buffer)) {
            Ok(Ok(0)) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(Ok(count)) => buffer = &buffer[count..],
            Ok(Err(error)) => return Err(error),
            Err(_) => {}
        }
    }
    Ok(())
}

async fn read_request(stream: &AsyncFd<Socket>) -> Result<Request, ProtoError> {
    let mut length = [0; 4];
    read_exact(stream, &mut length).await?;
    let length = u32::from_le_bytes(length);
    if length > MAX_FRAME {
        return Err(ProtoError::TooLarge(length));
    }
    let mut body = vec![0; length as usize];
    read_exact(stream, &mut body).await?;
    Request::decode(&body)
}

async fn write_response(stream: &AsyncFd<Socket>, response: &Response) -> Result<(), ProtoError> {
    let body = response.encode()?;
    write_all(stream, &(body.len() as u32).to_le_bytes()).await?;
    write_all(stream, &body).await?;
    Ok(())
}

async fn serve_connection(stream: AsyncFd<Socket>, hsm: Arc<StdHsm>) -> Result<(), String> {
    loop {
        let request = match read_request(&stream).await {
            Ok(request) => request,
            Err(ProtoError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(error) => return Err(format!("failed to read DDI request: {error}")),
        };
        let response = execute_request(&hsm, request).await;
        write_response(&stream, &response)
            .await
            .map_err(|error| format!("failed to write DDI response: {error}"))?;
    }
}

async fn run_server(hsm: Arc<StdHsm>) -> Result<(), String> {
    hsm.part_alloc(HSM_PARTITION_ID, 1u128 << HSM_PARTITION_ID)
        .await
        .map_err(|error| format!("failed to allocate HSM partition: {error:?}"))?;
    hsm.part_enable(HSM_PARTITION_ID)
        .await
        .map_err(|error| format!("failed to enable HSM partition: {error:?}"))?;

    let listener = Socket::new_nonblocking(sys::socket(AF_VSOCK, SOCK_STREAM, 0))
        .map_err(|error| format!("failed to create vsock listener: {error}"))?;
    let address = SockAddrVm {
        family: AF_VSOCK as u16,
        reserved: 0,
        port: VSOCK_PORT,
        cid: VMADDR_CID_ANY,
        zero: [0; 4],
    };
    if sys::bind(listener.fd, &address) < 0 {
        return Err(format!(
            "failed to bind vsock listener: {}",
            io::Error::last_os_error()
        ));
    }
    if sys::listen(listener.fd, 16) < 0 {
        return Err(format!(
            "failed to listen on vsock: {}",
            io::Error::last_os_error()
        ));
    }

    let listener = AsyncFd::new(listener)
        .map_err(|error| format!("failed to register vsock listener: {error}"))?;
    println!("AZIHSM DDI server listening on vsock port {VSOCK_PORT}");
    loop {
        let stream = loop {
            let mut ready = listener
                .readable()
                .await
                .map_err(|error| format!("failed to poll vsock listener: {error}"))?;
            match ready.try_io(|inner| inner.get_ref().accept()) {
                Ok(Ok(stream)) => break stream,
                Ok(Err(error)) => return Err(format!("failed to accept connection: {error}")),
                Err(_) => {}
            }
        };
        let stream = AsyncFd::new(stream)
            .map_err(|error| format!("failed to register vsock connection: {error}"))?;
        println!("DDI client connected");
        let hsm = Arc::clone(&hsm);
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, hsm).await {
                eprintln!("DDI client connection failed: {error}");
            } else {
                println!("DDI client disconnected");
            }
        });
    }
}

fn run() -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| format!("failed to create Tokio runtime: {error}"))?;
    let hsm = Arc::new(StdHsm::with_tokio(runtime.handle().clone()));
    runtime.block_on(run_server(hsm))
}

fn main() {
    if let Err(error) = run() {
        eprintln!("AZIHSM DDI socket server failed: {error}");
        std::process::exit(1);
    }
}
