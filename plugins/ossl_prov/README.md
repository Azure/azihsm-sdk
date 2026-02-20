# Azure Integrated HSM OpenSSL Provider

An [OpenSSL 3.0 provider](https://docs.openssl.org/3.0/man7/provider/) that delegates cryptographic operations to an Azure Integrated Hardware Security Module (HSM). Private keys never leave the HSM; the provider operates on opaque handles and uses **masked keys** for persistent storage outside the device.

## Supported Algorithms

| Operation | Algorithms |
|-----------|-----------|
| **Key Management** | EC (P-256, P-384, P-521), RSA (2048, 3072, 4096), RSA-PSS |
| **Signature** | ECDSA, RSA PKCS#1 v1.5, RSA-PSS |
| **Key Exchange** | ECDH |
| **Asymmetric Encryption** | RSA-OAEP, RSA PKCS#1 v1.5 |
| **Digest** | SHA-1, SHA-256, SHA-384, SHA-512 |
| **KDF** | HKDF (RFC 5869) |
| **Encoder** | DER (SubjectPublicKeyInfo for public keys only), Text |
| **Store** | `azihsm://` URI scheme for masked key loading |

> **Note:** EC keys are generated natively inside the HSM. RSA keys must be generated externally and **imported** into the HSM via the `azihsm.input_key` parameter.

## Key Usage and Operation Dependencies

The `azihsm.key_usage` parameter set during key generation determines which operations a key can perform. Using a key for an operation that doesn't match its usage will fail.

| `azihsm.key_usage` | Key Types | Allowed Operations |
|---------------------|-----------|-------------------|
| `digitalSignature` (default) | EC, RSA, RSA-PSS | Sign, Verify, Certificate Generation |
| `keyAgreement` | EC only | ECDH Key Exchange |
| `keyEncipherment` | RSA only | Encrypt, Decrypt |

The following diagram shows how operations chain together. Each arrow represents a masked key blob written to disk.

```
EC genpkey (digitalSignature) ──> masked_key.bin ──> dgst -sign / pkeyutl -sign
                                                 ──> req -new -x509

EC genpkey (keyAgreement) ──> ecdh_key.bin ──> pkeyutl -derive ──> shared_secret.bin
                                                                        │
                                                                        ▼
                                                                   kdf HKDF
                                                                    │       │
                                                          (aes) ◄───┘       └───► (hmac)
                                                     aes_key.bin         hmac_key.bin

RSA genpkey (digitalSignature) ──> masked_key.bin ──> dgst -sign / pkeyutl -sign
                                                  ──> req -new -x509

RSA genpkey (keyEncipherment)  ──> masked_key.bin ──> pkeyutl -encrypt / -decrypt
```

**Key dependencies:**

- **ECDSA / RSA Sign & Verify** require a key generated or imported with `digitalSignature` (the default).
- **RSA Encrypt & Decrypt** require a key imported with `keyEncipherment`. A `digitalSignature` key cannot be used for encryption.
- **ECDH** requires an EC key generated with `keyAgreement`. A `digitalSignature` EC key cannot be used for ECDH.
- **HKDF** requires a masked key file as input (`azihsm.ikm_file`). In practice this is the output of an ECDH derive (`shared_secret.bin`). There is no other way to provide the input keying material from the CLI besides using a masked key file.
- **HMAC** (once merged) will require a masked HMAC key derived via HKDF with `derived_key_type:hmac`. The HKDF `digest` parameter determines the HMAC key kind baked into the masked blob (SHA256 → HMAC-SHA256, SHA384 → HMAC-SHA384, SHA512 → HMAC-SHA512). When using the key, the MAC digest must match — e.g., a key derived with `digest:SHA384` can only be used with `-macopt digest:SHA384`. The `derived_key_bits` should match the hash output size (256, 384, or 512).

## Building

### Prerequisites

- Linux (x86_64)
- Rust toolchain (1.92+)
- CMake, GCC/Clang, pkg-config
- `libbsd-dev`, `libssl-dev` (system OpenSSL 3.x headers)

### Quick Build (Mock HSM)

For development and testing without physical HSM hardware, build with the `mock` feature:

```bash
cd azihsm-sdk
cargo build --features mock,provider
```

This produces `target/debug/azihsm_provider.so`.

### Production Build (Static OpenSSL Linkage)

For deployment alongside applications that ship their own OpenSSL (e.g., nginx), the Rust HSM library must be statically linked against a dedicated OpenSSL build to avoid symbol conflicts:

```bash
# 1. Build a static OpenSSL (no-shared, hidden visibility)
OPENSSL_VERSION=3.0.16
curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    | tar xz -C /tmp
cd /tmp/openssl-${OPENSSL_VERSION}
./Configure --prefix=/opt/openssl-static --libdir=lib \
    no-shared no-dso -fvisibility=hidden -fPIC
make -j"$(nproc)" && make install_sw

# 2. Build the Rust native API library with static OpenSSL
cd azihsm-sdk
OPENSSL_DIR=/opt/openssl-static OPENSSL_STATIC=1 \
    cargo build -p azihsm_api_native --features mock

# 3. Build the provider (links against system libssl-dev)
cargo build -p azihsm_ossl_provider --features mock
```

### Installation

After building, copy the provider shared library into the system OpenSSL modules directory so it can be loaded without `-provider-path`:

```bash
# Find the system modules directory
openssl version -m
# MODULESDIR: "/usr/lib64/ossl-modules"

# Install the provider
sudo cp target/debug/azihsm_provider.so /usr/lib64/ossl-modules/

# Create the working directory for masked key material
sudo mkdir -p /var/lib/azihsm
```

The provider stores and loads masked key blobs from `/var/lib/azihsm`. This directory must exist before running any key generation or import commands.

Once installed, the `-provider-path` flag is no longer needed — OpenSSL will find the provider automatically. All command examples below omit `-provider-path` and assume the provider is installed system-wide.

### Docker (nginx Example)

A complete Dockerfile is provided under `plugins/ossl_prov/nginx-example/`:

```bash
docker build -f plugins/ossl_prov/nginx-example/Dockerfile -t azihsm-nginx .
docker run --rm -p 8443:8443 azihsm-nginx
curl -k https://localhost:8443/
```

## Provider Flags

Every `openssl` command that uses the provider requires these flags:

```bash
openssl <command> \
    -propquery "?provider=azihsm" \
    -provider default \
    -provider azihsm_provider \
    ...
```

| Flag | Purpose |
|------|---------|
| `-propquery "?provider=azihsm"` | Route operations to the HSM provider when available; the `?` prefix allows fallback to the default provider for operations the HSM doesn't handle |
| `-provider default` | Load the default OpenSSL provider (needed for hashing, PEM encoding, etc.) |
| `-provider azihsm_provider` | Load the HSM provider |

> **Important:** `-propquery` **must** come before the `-provider` flags. OpenSSL processes CLI arguments left to right. Loading the provider triggers an HSM session that instantiates the DRBG (random number generator). If `-propquery` is applied afterwards, `RAND_set_DRBG_type` fails because the DRBG is already running. The error message from OpenSSL 3.0.x is misleading — it reports "odd number of digits" due to an upstream error code collision (`RAND_R_ALREADY_INSTANTIATED` and `CRYPTO_R_ODD_NUMBER_OF_DIGITS` are both 103, and the code uses `ERR_LIB_CRYPTO` instead of `ERR_LIB_RAND`).

> **Note:** If the provider is not installed system-wide, add `-provider-path /path/to/directory` pointing to the directory containing `azihsm_provider.so`.

> **Note:** On physical hardware, provider commands require `sudo` to access TPM operations.

For brevity, the examples below use `${PROV}` as shorthand for these three flags.

## Commands

### EC Key Generation

Generate an EC key pair inside the HSM. The private key stays in the HSM; a masked key blob is written to disk for later reloading.

**Requires:** Nothing (standalone operation).

```bash
openssl genpkey ${PROV} \
    -algorithm EC \
    -pkeyopt group:P-384 \
    -pkeyopt azihsm.masked_key:./ec_p384.bin \
    -outform DER -out /dev/null
```

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `group` | Yes | EC curve: `P-256`, `P-384`, or `P-521` |
| `azihsm.masked_key` | Yes | Output path for the masked key blob |
| `azihsm.key_usage` | No | `digitalSignature` (default) or `keyAgreement` |
| `azihsm.session` | No | `true` for ephemeral session key, `false` (default) for persistent. Also accepts `yes`/`no` and `1`/`0` |

**Key usage matters:** Keys generated with `digitalSignature` can only sign/verify. Keys generated with `keyAgreement` can only be used for ECDH. Attempting to use a signing key for ECDH (or vice versa) will fail.

```bash
# ECDH key (required for ECDH key exchange)
openssl genpkey ${PROV} \
    -algorithm EC -pkeyopt group:P-384 \
    -pkeyopt azihsm.key_usage:keyAgreement \
    -pkeyopt azihsm.masked_key:./ec_p384_ecdh.bin \
    -outform DER -out /dev/null

# Ephemeral session key (deleted when HSM session ends)
openssl genpkey ${PROV} \
    -algorithm EC -pkeyopt group:P-256 \
    -pkeyopt azihsm.session:true \
    -pkeyopt azihsm.masked_key:./ec_p256_session.bin \
    -outform DER -out /dev/null
```

### EC Key Import

Import an externally generated EC private key (DER-encoded, SEC1 or PKCS#8) into the HSM.

**Requires:** An external DER-encoded EC private key.

```bash
# Generate key externally
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
    -outform DER -out external_ec.der

# Import into HSM
openssl genpkey ${PROV} \
    -algorithm EC -pkeyopt group:P-384 \
    -pkeyopt azihsm.input_key:./external_ec.der \
    -pkeyopt azihsm.masked_key:./ec_imported.bin \
    -outform DER -out /dev/null
```

### RSA Key Import

The HSM cannot generate RSA keys natively. RSA keys must be generated externally and imported. The provider wraps the key using RSA-AES-WRAP and unwraps it inside the HSM.

**Requires:** An external DER-encoded RSA private key.

```bash
# Generate RSA key externally
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -outform DER -out external_rsa.der

# Import for signing
openssl genpkey ${PROV} \
    -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -pkeyopt azihsm.input_key:./external_rsa.der \
    -pkeyopt azihsm.key_usage:digitalSignature \
    -pkeyopt azihsm.masked_key:./rsa_2048_sign.bin \
    -outform DER -out /dev/null

# Import for encryption (note: keyEncipherment, not digitalSignature)
openssl genpkey ${PROV} \
    -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
    -pkeyopt azihsm.input_key:./external_rsa_4096.der \
    -pkeyopt azihsm.key_usage:keyEncipherment \
    -pkeyopt azihsm.masked_key:./rsa_4096_enc.bin \
    -outform DER -out /dev/null
```

**RSA parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `rsa_keygen_bits` | Yes | Key size: `2048`, `3072`, or `4096` |
| `azihsm.input_key` | Yes | Path to DER-encoded private key (PKCS#1 or PKCS#8) |
| `azihsm.masked_key` | Yes | Output path for masked key blob |
| `azihsm.key_usage` | No | `digitalSignature` (default) or `keyEncipherment` |

RSA-PSS keys are imported the same way using `-algorithm RSA-PSS`.

### ECDSA Sign and Verify

**Requires:** An EC key generated or imported with `digitalSignature` usage (the default).

**Streaming (digest + sign in one pass):**

```bash
# Sign
openssl dgst -sha384 ${PROV} \
    -sign "azihsm://./ec_p384.bin;type=ec" \
    -out signature.sig \
    data.bin

# Verify
openssl dgst -sha384 ${PROV} \
    -verify "azihsm://./ec_p384.bin;type=ec" \
    -signature signature.sig \
    data.bin
```

**One-shot (pre-hashed data):**

```bash
# Pre-hash
openssl dgst -sha384 -binary -out data.hash data.bin

# Sign
openssl pkeyutl -sign ${PROV} \
    -inkey "azihsm://./ec_p384.bin;type=ec" \
    -in data.hash \
    -out data.sig

# Verify
openssl pkeyutl -verify ${PROV} \
    -inkey "azihsm://./ec_p384.bin;type=ec" \
    -in data.hash \
    -sigfile data.sig
```

Any combination of curve and hash is supported (e.g., P-256 with SHA-512).

### RSA Sign and Verify

**Requires:** An RSA key imported with `digitalSignature` usage (the default).

**PKCS#1 v1.5:**

```bash
openssl dgst -sha256 ${PROV} \
    -sign "azihsm://./rsa_2048_sign.bin;type=rsa" \
    -out rsa_sig.bin data.bin

openssl dgst -sha256 ${PROV} \
    -verify "azihsm://./rsa_2048_sign.bin;type=rsa" \
    -signature rsa_sig.bin data.bin
```

**RSA-PSS:**

```bash
openssl dgst -sha256 ${PROV} \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:max \
    -sign "azihsm://./rsa_2048_sign.bin;type=rsa" \
    -out rsa_pss_sig.bin data.bin

openssl dgst -sha256 ${PROV} \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:auto \
    -verify "azihsm://./rsa_2048_sign.bin;type=rsa" \
    -signature rsa_pss_sig.bin data.bin
```

**PSS signature options:**

| Option | Values |
|--------|--------|
| `rsa_padding_mode` | `pss` |
| `rsa_pss_saltlen` | `digest` (hash length), `max` (maximum), `auto` (auto-detect on verify), or an integer |
| `rsa_mgf1_md` | Hash for MGF1 (defaults to same as digest) |

### RSA Encryption and Decryption

**Requires:** An RSA key imported with `keyEncipherment` usage. A `digitalSignature` key cannot encrypt/decrypt.

**RSA-OAEP:**

```bash
openssl pkeyutl -encrypt ${PROV} \
    -inkey "azihsm://./rsa_4096_enc.bin;type=rsa" \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256 \
    -in plaintext.bin -out ciphertext.bin

openssl pkeyutl -decrypt ${PROV} \
    -inkey "azihsm://./rsa_4096_enc.bin;type=rsa" \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256 \
    -in ciphertext.bin -out decrypted.bin
```

**PKCS#1 v1.5:**

```bash
openssl pkeyutl -encrypt ${PROV} \
    -inkey "azihsm://./rsa_4096_enc.bin;type=rsa" \
    -pkeyopt rsa_padding_mode:pkcs1 \
    -in plaintext.bin -out ciphertext.bin
```

**Encryption options:**

| Option | Values |
|--------|--------|
| `rsa_padding_mode` | `oaep` (recommended) or `pkcs1` |
| `rsa_oaep_md` | Hash for OAEP: `sha256`, `sha384`, `sha512` (SHA-1 rejected) |
| `rsa_mgf1_md` | MGF1 hash (defaults to `rsa_oaep_md`) |

### ECDH Key Exchange

Derive a shared secret with a peer's public key. The output is always a masked key blob written to a file (not raw bytes) — `output_file` is mandatory. The caller's output buffer is not used; `secretlen` is set to 0. This masked key file is the required input for HKDF key derivation.

**Requires:** An EC key generated with `keyAgreement` usage. A `digitalSignature` EC key cannot be used for ECDH.

```bash
# Generate peer key (no HSM)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out peer_priv.pem
openssl pkey -in peer_priv.pem -pubout -out peer_pub.pem

# Derive shared secret (output is a masked key blob)
openssl pkeyutl -derive ${PROV} \
    -inkey "azihsm://./ec_p384_ecdh.bin;type=ec" \
    -peerkey peer_pub.pem \
    -pkeyopt output_file:shared_secret.bin
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `output_file` | Yes | Path for output masked key blob. Unlike HKDF, there is no buffer fallback — the derive call fails if this is not set |

> **API note:** This breaks the standard `EVP_PKEY_derive` contract, which expects the shared secret to be written into the caller's buffer. The azihsm provider ignores the buffer and sets `secretlen` to 0 instead. This is by design — the HSM cannot expose raw shared secret bytes, so the only output path is a masked key file. Existing code using `EVP_PKEY_derive` must be adapted to read the masked key from `output_file` rather than from the returned buffer.

### HKDF Key Derivation

Derive AES or HMAC keys from a masked key file using HKDF (RFC 5869). The input keying material (IKM) must be a masked key blob — typically the output of an ECDH derive. The output is also a masked key blob.

**Requires:** A masked key file as IKM, produced by ECDH derive or another HKDF derivation.

```bash
# Derive an AES-256 key from an ECDH shared secret
openssl kdf ${PROV} \
    -keylen 4096 \
    -kdfopt digest:SHA256 \
    -kdfopt azihsm.ikm_file:./shared_secret.bin \
    -kdfopt output_file:./derived_aes_key.bin \
    -kdfopt derived_key_type:aes \
    -kdfopt derived_key_bits:256 \
    -binary -out /dev/null \
    HKDF

# Derive an HMAC key with salt and info
openssl kdf ${PROV} \
    -keylen 4096 \
    -kdfopt digest:SHA384 \
    -kdfopt azihsm.ikm_file:./shared_secret.bin \
    -kdfopt output_file:./derived_hmac_key.bin \
    -kdfopt derived_key_type:hmac \
    -kdfopt derived_key_bits:384 \
    -kdfopt hexsalt:000102030405060708090a0b0c \
    -kdfopt hexinfo:f0f1f2f3f4f5f6f7f8f9 \
    -binary -out /dev/null \
    HKDF
```

**Output behavior:** The derive function receives both a caller-provided buffer (`key`/`keylen` from `-keylen` on the CLI or `EVP_KDF_derive`) and an optional `output_file` path:

- When `output_file` is set, the masked key blob is written to that file. The caller's buffer is ignored.
- When `output_file` is **not** set, the masked key blob is written into the caller's buffer. `-keylen` must be large enough to hold the masked blob or the call fails with `OUTPUT_BUFFER_TOO_SMALL`.

The actual derived key size inside the HSM is determined by `derived_key_bits`. `-keylen` only controls the buffer capacity for the masked blob output.

**HKDF parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `digest` | No | Hash algorithm: `SHA256` (default), `SHA384`, `SHA512`. For `derived_key_type:hmac`, this also determines the HMAC key kind (must match the digest used later with HMAC) |
| `azihsm.ikm_file` | Yes | Path to masked key file used as input keying material |
| `output_file` | No | Path for output masked key blob. When set, takes priority over the caller's buffer |
| `derived_key_type` | No | `aes` (default) or `hmac` |
| `derived_key_bits` | No | Output key size in bits (default: 256). Must be >0 and divisible by 8. See HMAC table below for required values |
| `hexsalt` | No | Optional salt in hex |
| `hexinfo` | No | Optional context/info in hex |

**HMAC key derivation:** When using `derived_key_type:hmac`, the `digest` and `derived_key_bits` must match:

| `digest` | `derived_key_bits` | Resulting HMAC key | MAC `-macopt digest:` |
|----------|-------------------|--------------------|-----------------------|
| `SHA256` | `256` | HMAC-SHA256 | `SHA256` |
| `SHA384` | `384` | HMAC-SHA384 | `SHA384` |
| `SHA512` | `512` | HMAC-SHA512 | `SHA512` |

Using a mismatched digest when consuming the key (e.g., deriving with `SHA384` but using `-macopt digest:SHA256`) will fail.

### Digest (Hashing)

The provider implements SHA-1, SHA-256, SHA-384, and SHA-512. These are used internally by signature operations but can also be invoked directly.

**Requires:** Nothing (standalone operation).

```bash
openssl dgst -sha256 ${PROV} data.bin
```

## The `azihsm://` URI Scheme

The provider registers a custom OpenSSL store that handles `azihsm://` URIs. These URIs reference masked key files on disk and tell the provider to unmask and load the key into the HSM.

### URI Format

```
azihsm://<file_path>;type=<key_type>
```

| Component | Required | Description |
|-----------|----------|-------------|
| `<file_path>` | Yes | Path to the masked key file (relative or absolute) |
| `type` | Yes | Key type: `ec`, `rsa`, or `rsa-pss` |

### Examples

```bash
# Relative path
azihsm://./masked_key_p384.bin;type=ec

# Absolute path
azihsm:///var/lib/azihsm/server_key.bin;type=rsa

# RSA-PSS key
azihsm://./rsa_pss_key.bin;type=rsa-pss
```

### How It Works

1. OpenSSL encounters an `azihsm://` URI (e.g., via `-key` or `-sign`)
2. The store provider parses the file path and `type` attribute
3. Reads the masked key blob from disk
4. Calls `azihsm_key_unmask_pair()` to recover key handles inside the HSM
5. Returns an `EVP_PKEY` backed by the HSM key handles

The masked key blob is encrypted by an HSM-internal key unique to each device. Masked keys are only usable on the same HSM that created them.

### Verifying Key Loading

Use `storeutl` to verify a masked key can be loaded:

```bash
openssl storeutl ${PROV} "azihsm://./ec_p384.bin;type=ec"
```

## Full Chain Example: ECDH to HKDF

A typical workflow combining key agreement and key derivation:

```bash
# 1. Generate an ECDH key
openssl genpkey ${PROV} -algorithm EC -pkeyopt group:P-384 \
    -pkeyopt azihsm.key_usage:keyAgreement \
    -pkeyopt azihsm.masked_key:./ecdh_key.bin -outform DER -out /dev/null

# 2. Generate a peer key and perform ECDH
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out peer.pem
openssl pkey -in peer.pem -pubout -out peer_pub.pem

openssl pkeyutl -derive ${PROV} \
    -inkey "azihsm://./ecdh_key.bin;type=ec" \
    -peerkey peer_pub.pem \
    -pkeyopt output_file:shared_secret.bin

# 3. Derive an AES key via HKDF
openssl kdf ${PROV} -keylen 4096 \
    -kdfopt digest:SHA384 \
    -kdfopt azihsm.ikm_file:./shared_secret.bin \
    -kdfopt output_file:./aes_key.bin \
    -kdfopt derived_key_type:aes -kdfopt derived_key_bits:256 \
    -binary -out /dev/null HKDF
```
