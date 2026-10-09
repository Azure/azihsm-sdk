# Bridging an AziHSM VM to a second `vsocksrv` VM

This document describes how to reproduce a two-VM test topology where a guest
using the Cloud Hypervisor `azihsmvsock` device (VM1) talks to a `StdHsm`
hosted by `vsocksrv` running as a real `AF_VSOCK` listener inside a *second*
VM (VM2), instead of `vsocksrv` running directly on the host against VM1's
Unix socket.

## Why a host-side proxy is required

Both endpoints involved are passive listeners that never dial out:

- `azihsmvsock` (VM1) exposes a Unix socket (e.g. `/tmp/mcr.vsock1`) and
  only *accepts* a single incoming connection per controller-enable cycle
  (`VsockHsmClient::connect` -> `accept_host_stream`).
- `vsocksrv --socket-type vsock` (VM2) binds a real `AF_VSOCK` CID/port and
  only *accepts* incoming connections.

Two listeners cannot connect directly to each other, so a small host-side
proxy is used to dial into both Unix sockets as a client and splice the
bytes together:

```
VM1 guest (azihsm_api_tests)
   -> azihsmvsock device -> /tmp/mcr.vsock1 (Unix socket, CH-managed)
        <-> host proxy (dials both sockets, relays bytes)
   -> /tmp/vsock2.sock (Unix socket, CH's built-in --vsock backend for VM2)
        -> virtio-vsock -> VM2 guest kernel -> vsocksrv (AF_VSOCK listener)
        -> StdHsm partition 3
```

The proxy used here is `~/vsockproxy2.py` (a host-local script, not part of
either repository). It dials `CONNECT <port>\n` into both endpoints, reads
and validates each side's `OK <port>\n` acknowledgement, then relays raw
SQE/CQE bytes bidirectionally with auto-reconnect. Any equivalent proxy must:

1. Connect to both Unix sockets.
2. Send `CONNECT <port>\n` on each.
3. Read and discard the `OK <digits>\n` acknowledgement line from each side
   before relaying any payload bytes (both `azihsmvsock` and Cloud
   Hypervisor's built-in vsock backend send this ack today).
4. Splice bytes bidirectionally until either side closes.

## Prerequisites

- VM1 launch script (`~/doit.sh`): boots with
  `--vsock cid=4,socket=/tmp/chv.vsock` and
  `--azihsmvsock cid=3,socket=/tmp/mcr.vsock1,port=5000`.
- VM2 launch script (`~/doit2.sh`): boots with a plain
  `--vsock cid=4,socket=/tmp/vsock2.sock` (no `azihsmvsock`), sharing the
  same bridge (`br0`) as VM1 for networking/SSH access.
- A `vsocksrv` binary built for the guest architecture:
  ```bash
  cargo build -p vsocksrv
  ```

## Steps

1. **Start VM1** via `~/doit.sh` (or launch `cloud-hypervisor` directly with
   the same flags if `br0`/`tap0` already exist from a prior run).

2. **Start VM2** via `~/doit2.sh`. Find its IP via ARP if there's no DHCP
   lease file, matching the MAC configured in the script:
   ```bash
   ip neigh show dev br0
   ```

3. **Copy `vsocksrv` into VM2** and run it as a real `AF_VSOCK` listener:
   ```bash
   scp target/debug/vsocksrv root@<vm2-ip>:/usr/local/bin/vsocksrv
   ssh root@<vm2-ip> chmod +x /usr/local/bin/vsocksrv
   ssh root@<vm2-ip> \
     'setsid /usr/local/bin/vsocksrv --socket-type vsock --port 5000 \
        --partition-id 3 >/tmp/vsocksrv_vm2.log 2>&1 < /dev/null &'
   ```
   Confirm it's listening:
   ```bash
   ssh root@<vm2-ip> tail -5 /tmp/vsocksrv_vm2.log
   # ... Listening for HSM requests cid=... port=5000
   ```

4. **Start the host proxy**, pointing it at VM1's azihsmvsock socket and
   VM2's vsock backend socket:
   ```bash
   sudo python3 ~/vsockproxy2.py \
     --vm1-socket /tmp/mcr.vsock1 --vm2-socket /tmp/vsock2.sock \
     --port 5000 -v
   ```
   Both `/tmp/mcr.vsock1` and `/tmp/vsock2.sock` are root-owned, so the
   proxy must run with `sudo` (or as root).

   On success, the proxy logs a `CONNECT`/`OK` handshake on each side and
   `Bridge established: ...`.

5. **Run the test in VM1** to exercise the full path:
   ```bash
   ssh root@192.168.249.55 \
     "/usr/bin/azihsm/azihsm_api_tests --test-threads 1 \
        --test algo::aes::cbc_tests::test_cbc_streaming_no_pad_128"
   ```

## Timing / backlog caveat

`azihsmvsock`'s `accept_host_stream()` only calls `accept()` once, during
the controller's enable path (triggered once at guest boot when the
`azihsm` kernel module probes the device). If the proxy has already been
retrying connections against `/tmp/mcr.vsock1` before that enable happens
(or is retrying in a loop against a device that keeps failing), stale,
already-closed connections pile up in the Unix listener's backlog. The next
`accept_host_stream()` call then dequeues one of those dead connections
instead of a live one, fails immediately, and the real proxy connection is
left stranded.

To avoid this:

- Prefer starting the proxy **after** VM1 has booted and its first enable
  attempt is already blocked waiting on `accept()` (visible in
  `/tmp/chv.log` as `Connecting to HSM proxy` with no corresponding
  `Controller Enabled Failed` yet), so the proxy's first connection attempt
  is the one that gets accepted.
- If the backlog does get polluted (e.g. after several failed attempts),
  restart VM1 cleanly (`sudo rm -f /tmp/chv.sock /tmp/chv.vsock
  /tmp/mcr.vsock1` before relaunching) to reset the listener, then restart
  the proxy immediately.
- To retrigger the controller's enable path without rebooting VM1, reload
  the `azihsm` kernel module inside the guest:
  ```bash
  ssh root@192.168.249.55 "rmmod azihsm && modprobe azihsm"
  ```
  This causes a fresh `enable`/`disable` cycle, so the proxy's live
  connection attempt (already in progress) can be accepted cleanly.

## Troubleshooting

- **`socket operation timed out` in the proxy log**: the proxy connected at
  the OS level but never received an `OK <port>\n` ack — usually the stale
  backlog issue above. Restart VM1 and retry with correct timing.
- **`Permission denied` connecting to the sockets**: both
  `/tmp/mcr.vsock1` and `/tmp/vsock2.sock` are root-owned; run the proxy
  with `sudo`.
- Check `/tmp/chv.log` (VM1) for `azihsmvsock`/`vsock_client` messages
  and `/tmp/vsocksrv_vm2.log` (via SSH into VM2) for connection/request
  activity on the `StdHsm` side.
