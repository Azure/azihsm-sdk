# Vsock StdHsm Server

`vsocksrv` exposes one in-process `StdHsm` over `AF_VSOCK` or `AF_UNIX`. It
accepts the framed SQE/CQE protocol from `azihsm_ddi_sock_proto`, replaces all
client addresses with service-local DMA buffers, and returns the CQE and output
payload.

The server allocates and enables its HSM partition during startup. Partition 3
is used by default to match the Manticore device.

## Build

```bash
cargo build --release -p vsocksrv
```

## Run

Run the service with an `AF_VSOCK` listener in the VM that hosts `StdHsm`:

```bash
RUST_LOG=vsocksrv=info cargo run --release -p vsocksrv -- --port 5000
```

To run the service on the host and connect to the Unix socket created by Cloud
Hypervisor's `--manticorevsock` option:

```bash
cargo run --release -p vsocksrv -- \
	--socket-type unix --unix-socket /path/to/manticore.sock --port 5000
```

Unix mode sends `CONNECT <port>\n` before the framed protocol begins. Vsock
mode does not send this command. The socket type defaults to `vsock`. Unix mode
automatically reconnects and resends `CONNECT` when the connection closes.

Set `RUST_LOG=vsocksrv=debug` to trace connection and request lifecycles, HSM
completion status, and request latency. Use `RUST_LOG=vsocksrv=trace` for frame
and OOB marshalling details. Payload and OOB contents are never logged.

The listener binds any local CID by default. Use `--cid <cid>` to bind a
specific local CID and `--partition-id <id>` to select another HSM partition.

Cloud Hypervisor uses the corresponding endpoint as follows:

```text
--manticorevsock cid=<guest_cid>,socket=<unix_socket>,port=5000
```
