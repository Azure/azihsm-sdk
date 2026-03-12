# Resiliency Stress Tool

Long-running stress tool for testing AZIHSM SDK resiliency under continuous
device resets. Multiple worker threads perform crypto operations while a
dedicated thread triggers resets at configurable intervals.

## Building

```bash
cargo build --release -p resiliency_stress
```

## Usage

```bash
# Default: 4 workers, 200ms reset interval, 60s duration, all operations
cargo run --release -p resiliency_stress

# Custom parameters
cargo run --release -p resiliency_stress -- \
    --workers 8 \
    --reset-interval-ms 100 \
    --duration-secs 300 \
    --ops aes-cbc,ecc-sign

# Run indefinitely (Ctrl-C to stop)
cargo run --release -p resiliency_stress -- --duration-secs 0

# Quick smoke test
cargo run --release -p resiliency_stress -- -w 2 -d 10 -r 500
```

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

## Available Operations

| Name | Description |
|------|-------------|
| `all` | All available operations (default) |
| `aes-cbc` | AES-CBC encrypt + decrypt |
| `aes-cbc-encrypt` | AES-CBC encrypt only |
| `aes-cbc-decrypt` | AES-CBC decrypt only |
| `ecc-sign` | ECC P-256 signing |
| `hmac-sign` | HMAC-SHA256 signing |
| `rsa-sign` | RSA PKCS#1 signing |
| `rsa-decrypt` | RSA PKCS#1 decryption |
| `rsa` | RSA sign + decrypt |
| `aes-keygen` | AES-256 key generation |
| `ecc-keygen` | ECC P-256 key pair generation |
| `aes-xts-keygen` | AES-XTS-512 key generation |
| `unwrapping-keygen` | RSA-2048 unwrapping key pair generation |
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
| `key-report` | All key report operations |
| `cert-chain` | Partition cert chain retrieval |
| `aes-keygen-delete` | AES keygen + immediate delete |
| `ecc-keygen-delete` | ECC keygen + immediate delete |
| `xts-keygen-delete` | AES-XTS keygen + immediate delete |
| `keygen-delete` | All keygen-delete operations |

## How It Works

1. Opens and initializes an HSM partition with resiliency enabled
2. Spawns N worker threads, all sharing a single cloned session with
   pre-created keys
3. Spawns a reset thread with a **separate** partition handle (same device)
4. Workers continuously perform random crypto operations
5. The reset thread triggers device resets at the configured interval
6. Each DDI call in the workers has `#[resiliency_key_op]` or
   `#[resiliency_key_gen]` — on a reset error, the SDK automatically
   restores the partition, reopens the session, refreshes the key, and
   retries the operation
7. If any operation fails with a non-retryable error (e.g., `InvalidPermissions`
   indicating a potential ABA violation), the tool stops and reports
8. A deadlock detector thread runs in the background using
   `parking_lot`'s deadlock detection — if a deadlock is found, it
   dumps all thread stack traces to stderr and exits
9. A stall detector monitors progress; if no operations complete within
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
