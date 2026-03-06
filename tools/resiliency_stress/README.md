# Resiliency Stress Tool

Long-running stress tool for testing AZIHSM SDK resiliency under continuous
device resets. Multiple worker threads perform crypto operations while a
dedicated thread triggers resets at configurable intervals.

## Building

```bash
# Add to workspace members first (see below), then:
cargo build --release -p resiliency_stress
```

**Note:** Add `"tools/resiliency_stress"` to the `[workspace] members` list in
the root `Cargo.toml` before building.

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

## Command-Line Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--workers` | `-w` | 4 | Number of worker threads |
| `--reset-interval-ms` | `-r` | 200 | Milliseconds between device resets |
| `--duration-secs` | `-d` | 60 | Run duration in seconds (0 = infinite) |
| `--stats-interval-secs` | `-s` | 5 | Seconds between stats printouts |
| `--ops` | `-o` | all | Comma-separated list of operations |

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

## Output

Periodic stats are printed to stderr:

```
=== Resiliency Stress Tool ===
Workers:        4
Reset interval: 200ms
Duration:       60s
Operations:     AES-CBC encrypt, AES-CBC decrypt, ECC sign, HMAC sign, AES key gen

[00:00:05] ops: 1284 | resets: 24 | ops/s: 257
[00:00:10] ops: 2847 | resets: 49 | ops/s: 285
[00:00:15] ops: 4102 | resets: 74 | ops/s: 274

=== Final Stats ===
Elapsed:    00:01:00
Total ops:  16542
Resets:     299
Ops/sec:    276

All operations completed successfully.
```

On failure, the tool stops immediately and prints the failing scenario:

```
=== FAILURE ===
Thread:     2
Operation:  AES-CBC encrypt
Error:      InvalidPermissions
Ops before: 12847
```

## How It Works

1. Opens and initializes an HSM partition with resiliency enabled
2. Spawns N worker threads, each with its own session and pre-created keys
3. Spawns a reset thread with a **separate** partition handle (same device)
4. Workers continuously perform random crypto operations
5. The reset thread triggers device resets at the configured interval
6. Each DDI call in the workers has `#[resiliency_key_op]` or
   `#[resiliency_key_gen]` — on a reset error, the SDK automatically
   restores the partition, reopens the session, refreshes the key, and
   retries the operation
7. If any operation fails with a non-retryable error (e.g., `InvalidPermissions`
   indicating a potential ABA violation), the tool stops and reports

## Troubleshooting

- **No partitions found:** Ensure the HSM simulator is available
- **All ops fail immediately:** Check that the `mock` and `res-test`
  features are enabled (they are by default)
- **Very low ops/sec:** Increase `--reset-interval-ms` to reduce reset
  frequency
