# Resiliency Stress Tool

Long-running stress tool for testing AZIHSM SDK resiliency under continuous
device resets. Multiple worker threads perform crypto operations while a
dedicated thread triggers resets at configurable intervals.

## Building

```bash
# For hardware (no feature flags)
cargo build --release -p resiliency_stress

# For in-process mock simulator
cargo build --release -p resiliency_stress --features mock
```

## Usage

### Mock Simulator (single-process, in-process sim)

The mock feature runs everything in a single process — workers and the
reset thread share the same in-process simulator. Multi-process mode
(`-p > 1`) is not supported with mock.

```bash
# Default: 4 workers, 200ms reset interval, 60s duration, all operations
cargo run --release -p resiliency_stress --features mock -- -d 60

# Run indefinitely with unlimited error tolerance
cargo run --release -p resiliency_stress --features mock -- -w 4 -d 0 -r 1000 -e -1

# Quick smoke test
cargo run --release -p resiliency_stress --features mock -- -w 2 -d 10 -r 500

# Specific operations only
cargo run --release -p resiliency_stress --features mock -- -d 60 -o aes-cbc,aes-xts,aes-gcm
```

### Hardware

```bash
# Default: 4 workers, 200ms reset interval, 60s duration
cargo run --release -p resiliency_stress -- -d 60

# Custom parameters
cargo run --release -p resiliency_stress -- \
    --workers 8 \
    --reset-interval-ms 100 \
    --duration-secs 300 \
    --ops aes-cbc,ecc-sign

# Fail-fast on first error (legacy behavior)
cargo run --release -p resiliency_stress -- -w 2 -d 60 -e 0
```

### Multi-Process Mode

Simulate multiple independent clients accessing the same device:

```bash
# 3 processes, each with 2 workers (6 total threads across 3 partitions)
cargo run --release -p resiliency_stress -- -p 3 -w 2 -r 10000 -d 0

# Multi-process with unlimited error tolerance
cargo run --release -p resiliency_stress -- -p 4 -w 4 -r 10000 -d 300 -e -1
```

In multi-process mode, each child process opens its own partition and
session. The parent process runs the reset thread and aggregates
statistics across all children. Per-process columns appear in the live
stats display.

### Performance Comparison

```bash
# Baseline: no resiliency support at all
cargo run --release -p resiliency_stress -- --no-resiliency -d 60

# Resiliency overhead: resiliency enabled but no resets
cargo run --release -p resiliency_stress -- --no-reset -d 60

# Full: resiliency enabled with resets (default)
cargo run --release -p resiliency_stress -- -d 60
```

### Random DDI Fault Injection

Injects NSSR faults on random DDI operations mid-call, providing much
better race coverage than timer-based resets. Requires the `res-test`
feature:

```bash
# Build with res-test feature
cargo build --release -p resiliency_stress --features res-test

# Run with random fault injection
cargo run --release -p resiliency_stress --features res-test -- --random-fault -d 60

# Random faults with faster injection interval
cargo run --release -p resiliency_stress --features res-test -- --random-fault -r 100 -d 300
```

## Command-Line Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--workers` | `-w` | 4 | Number of worker threads |
| `--reset-interval-ms` | `-r` | 200 | Milliseconds between device resets |
| `--duration-secs` | `-d` | 60 | Run duration in seconds (0 = infinite) |
| `--stats-interval-secs` | `-s` | 5 | Seconds between stats printouts |
| `--ops` | `-o` | all | Comma-separated list of operations |
| `--stall-timeout-secs` | | 30 | Stall detection timeout (0 = disabled) |
| `--verbose` | `-v` | false | Enable verbose logging |
| `--no-resiliency` | | false | Disable resiliency (baseline perf) |
| `--no-reset` | | false | Resiliency enabled but no resets |
| `--random-fault` | | false | Random DDI fault injection (needs `res-test`) |
| `--max-errors` | `-e` | 10 | Max operation errors before stopping (0 = fail-fast, -1 = unlimited) |
| `--processes` | `-p` | 1 | Number of separate OS processes (each with own partition) |

## Available Operations

| Name | Description |
|------|-------------|
| `all` | All operations below (except standalone keygen) |
| `aes-cbc` | AES-CBC encrypt + decrypt roundtrip |
| `aes-xts` | AES-XTS encrypt + decrypt roundtrip |
| `aes-gcm` | AES-GCM encrypt + decrypt roundtrip |
| `ecc-sign` | ECC P-256 signing |
| `hmac-sign` | HMAC-SHA256 signing |
| `rsa-sign` | RSA PKCS#1 signing |
| `rsa-decrypt` | RSA PKCS#1 decryption |
| `rsa` | RSA sign + decrypt |
| `aes-keygen` | AES-256 key generation (not in `all`) |
| `ecc-keygen` | ECC P-256 key pair generation (not in `all`) |
| `aes-xts-keygen` | AES-XTS-512 key generation (not in `all`) |
| `unwrapping-keygen` | RSA-2048 unwrapping key pair generation (not in `all`) |
| `ecdh` | ECDH shared secret derivation |
| `hkdf` | HKDF key derivation |
| `aes-unwrap` | AES key unwrap (RSA-AES) |
| `ecc-unwrap` | ECC key pair unwrap (RSA-AES) |
| `xts-unwrap` | AES-XTS key unwrap (RSA-AES) |
| `unwrap` | All unwrap operations |
| `aes-unmask` | AES key unmask |
| `ecc-unmask` | ECC key pair unmask |
| `xts-unmask` | AES-XTS key unmask |
| `unmask` | All unmask operations |
| `ecc-key-report` | ECC key attestation report |
| `rsa-key-report` | RSA key attestation report |
| `unwrapping-key-report` | Unwrapping key attestation report |
| `key-report` | All key report operations |
| `cert-chain` | Partition cert chain retrieval |
| `aes-keygen-delete` | AES keygen + immediate delete |
| `ecc-keygen-delete` | ECC keygen + immediate delete |
| `xts-keygen-delete` | AES-XTS keygen + immediate delete |
| `keygen-delete` | All keygen-delete operations |

## How It Works

1. Opens and initializes an HSM partition with resiliency enabled
   (in multi-process mode, each child opens its own partition)
2. Spawns N worker threads, all sharing a single cloned session with
   pre-created keys
3. Spawns a reset thread with a **separate** partition handle (same device)
4. Workers continuously perform random crypto operations
5. The reset thread triggers device resets at the configured interval
6. Each DDI call in the workers has `#[resiliency_key_op]` or
   `#[resiliency_key_gen]` — on a reset error, the SDK automatically
   restores the partition, reopens the session, refreshes the key, and
   retries the operation
7. If all retries are exhausted, the error is logged and the worker
   continues. Errors are tracked per-operation and displayed in the
   live stats with `!!` markers. The tool stops when total errors
   reach `--max-errors` (default 10). Use `-e 0` for fail-fast or
   `-e -1` for unlimited tolerance
8. If any operation fails with a non-retryable error (e.g., `InvalidPermissions`
   indicating a potential ABA violation), the same error budget applies
9. A deadlock detector thread runs in the background using
   `parking_lot`'s deadlock detection — if a deadlock is found, it
   dumps all thread stack traces to stderr and exits
10. A stall detector monitors progress; if no operations complete within
   `--stall-timeout-secs`, it dumps diagnostics and exits with code 2

## Troubleshooting

- **No partitions found:** Ensure the HSM simulator is available (build
  with `--features mock` for simulator mode)
- **All ops fail immediately:** Check that the `mock` feature is enabled
  for simulator mode (`--features mock`). The `res-test` feature must be
  explicitly enabled when using `--random-fault`
  (`--features mock,res-test`)
- **Very low ops/sec:** Increase `--reset-interval-ms` to reduce reset
  frequency