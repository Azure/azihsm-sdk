# Azure Integrated HSM OpenSSL Provider

An [OpenSSL 3.0 provider](https://docs.openssl.org/3.0/man7/provider/) that delegates cryptographic operations to an Azure Integrated Hardware Security Module (HSM). Private keys never leave the HSM; the provider operates on opaque handles and uses **masked keys** for persistent storage outside the device.

## Supported Algorithms

| Operation | Algorithms |
|-----------|-----------|
| **Key Management** | EC (P-256, P-384, P-521), RSA (2048, 3072, 4096) |
| **Signature** | ECDSA, RSA PKCS#1 v1.5, RSA-PSS |
| **Key Exchange** | ECDH |
| **Asymmetric Encryption** | RSA-OAEP |
| **Symmetric Encryption** | AES-CBC (128/192/256), AES-GCM (256), AES-XTS (256) — **OpenSSL 3.5+** |
| **Digest** | SHA-1, SHA-256, SHA-384, SHA-512 |
| **MAC** | HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 |
| **KDF** | HKDF (RFC 5869), KBKDF (SP 800-108 Counter Mode) |
| **Encoder** | DER (SubjectPublicKeyInfo for public keys; PrivateKeyInfo metadata-only — keys are not exportable), Text |
| **Store** | `azihsm://` URI scheme for masked key loading |

> **Note:** EC keys are generated natively inside the HSM. RSA keys must be generated externally and **imported** into the HSM via the `azihsm.input_key` parameter (plaintext DER) or `azihsm.wrapped_key` parameter (pre-wrapped blob).

> **Note:** AES symmetric keys are opaque **`EVP_SKEY`** objects and require **OpenSSL 3.5+** (they use the 3.5 `SKEYMGMT` API). They are generated inside the HSM (or re-imported from a masked blob) and are never exposed as raw bytes. On OpenSSL versions before 3.5 the opaque-key manager is unavailable, so AES keys cannot be created or bound — the cipher names still resolve but are unusable. See [AES Symmetric Encryption](#aes-symmetric-encryption).

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

EC genpkey (keyAgreement) ──> ecdh_masked.bin ──> pkeyutl -derive ──> shared_masked.bin
                                                                            │
                                                                            ▼
                                                                       kdf HKDF
                                                                        │       │
                                                              (aes) ◄───┘       └───► (hmac)
                                                        aes_masked.bin         hmac_masked.bin

RSA genpkey (digitalSignature) ──> masked_key.bin ──> dgst -sign / pkeyutl -sign
                                                  ──> req -new -x509

RSA genpkey (keyEncipherment)  ──> masked_key.bin ──> pkeyutl -encrypt / -decrypt
```

**Key dependencies:**

- **ECDSA / RSA Sign & Verify** require a key generated or imported with `digitalSignature` (the default).
- **RSA Encrypt & Decrypt** require a key imported with `keyEncipherment`. A `digitalSignature` key cannot be used for encryption.
- **ECDH** requires an EC key generated with `keyAgreement`. A `digitalSignature` EC key cannot be used for ECDH.
- **HKDF** requires a masked key file as input (`azihsm.ikm_file`). In practice this is the output of an ECDH derive (`shared_masked.bin`). There is no other way to provide the input keying material from the CLI besides using a masked key file.
- **KBKDF** (SP 800-108 Counter Mode) works like HKDF: it requires a masked key file as input (`azihsm.ikm_file`, typically an ECDH derive output) and derives AES or HMAC keys. The standard `salt` / `info` parameters map to the SP 800-108 label / context, and at least one of them must be provided.
- **HMAC** requires a masked HMAC key derived via HKDF or KBKDF with `derived_key_type:hmac`. The KDF `digest` parameter determines the HMAC key kind baked into the masked blob (SHA256 → HMAC-SHA256, SHA384 → HMAC-SHA384, SHA512 → HMAC-SHA512). When using the key, the MAC digest must match — e.g., a key derived with `digest:SHA384` can only be used with `-macopt digest:SHA384`. The `derived_key_bits` should match the hash output size (256, 384, or 512).
- **AES** (CBC / GCM / XTS) uses opaque symmetric `EVP_SKEY` keys generated inside the HSM, selected by the `azihsm.key_kind` skey option rather than `azihsm.key_usage`. Requires OpenSSL 3.5+. See [AES Symmetric Encryption](#aes-symmetric-encryption).

## Building

### Prerequisites

- Linux (x86_64)
- Rust toolchain (1.92+)
- CMake, GCC/Clang, pkg-config, curl
- `libbsd-dev`, `libssl-dev` (system OpenSSL 3.x headers)

### Build

The provider consists of two shared libraries that both link dynamically against the same `libcrypto.so`. Circular dispatch is avoided because the provider registers its algorithms with the property `"provider=azihsm"` and the library's internal OpenSSL calls use bare algorithm names (no property query), which route to the OpenSSL **default** provider.

> **Important:** The default provider **must** be available alongside the azihsm provider. During initialisation the provider force-loads the OpenSSL `default` provider into the process's default library context to prevent infinite recursion; if this fails the provider will refuse to start.

```bash
# 1. Build OpenSSL 3.0.3 (shared)
OPENSSL_VERSION=3.0.3
curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    | tar xz -C /tmp
cd /tmp/openssl-${OPENSSL_VERSION}
./Configure --prefix=/opt/openssl-3.0.3 --libdir=lib
make -j"$(nproc)" && sudo make install_sw

# 2. Build both libraries against OpenSSL 3.0.3
cd azihsm-sdk
export LD_LIBRARY_PATH=/opt/openssl-3.0.3/lib
OPENSSL_DIR=/opt/openssl-3.0.3 cargo build -p azihsm_api_native --features mock
OPENSSL_DIR=/opt/openssl-3.0.3 cargo build -p azihsm_ossl_provider --features mock
```

On real hardware, omit `mock` from both build commands.

This produces two shared libraries in `target/debug/`:
- `azihsm_provider.so` — the OpenSSL provider
- `libazihsm_api_native.so` — the Rust HSM API (runtime dependency of the provider)

### Installation

Install the provider and its runtime dependency:

```bash
# Find the system modules directory
openssl version -m

# Install the provider
sudo cp target/debug/azihsm_provider.so /usr/lib/x86_64-linux-gnu/ossl-modules/

# Install the Rust HSM API library
sudo cp target/debug/libazihsm_api_native.so /usr/lib/
sudo ldconfig

# (Optional) Create a dedicated directory for masked key material.
# By default the provider reads and writes key files in the current working
# directory. Override paths via openssl.cnf — see Configuration below.
```

Once installed, the `-provider-path` flag is no longer needed — OpenSSL will find the provider automatically. All command examples below omit `-provider-path` and assume the provider is installed system-wide.

## Configuration

The provider reads its configuration from two sources, in priority order:

1. **`openssl.cnf`** — provider-specific keys in the `[azihsm_sect]` section (key material paths, API revision, OBK/POTA source)
2. **Defaults** — CWD-relative paths (`./bmk.bin`, `./muk.bin`, etc.) used when the above is not set

Credentials (ID and PIN) are handled separately via **environment variables** as hex-encoded strings. If the env vars are unset, the provider falls back to reading default credential files (`./credentials_id.bin`, `./credentials_pin.bin`) from CWD.

> Credentials are intentionally **not** readable from `openssl.cnf` to reduce the risk of them appearing in config files.

### Configuration via `openssl.cnf`

The provider uses the standard OpenSSL 3.x provider configuration mechanism. When OpenSSL loads the provider it passes an `OSSL_FUNC_CORE_GET_PARAMS` callback; the provider uses this to read its named parameters from its own section in `openssl.cnf`. No custom configuration parsing is involved.

OpenSSL locates `openssl.cnf` via (in priority order):
1. `OPENSSL_CONF` environment variable
2. Compiled-in default (`OPENSSLDIR`, e.g. `/etc/ssl/openssl.cnf`)

A minimal `openssl.cnf` that loads the provider and sets custom key paths:

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
azihsm = azihsm_sect

[default_sect]
activate = 1

[azihsm_sect]
module = /path/to/azihsm_provider.so
activate = 1
azihsm-bmk-path = /var/lib/azihsm/bmk.bin
azihsm-muk-path = /var/lib/azihsm/muk.bin
azihsm-obk-path = /var/lib/azihsm/obk.bin
azihsm-obk-source = caller
azihsm-pota-source = caller
azihsm-pota-private-key-path = /var/lib/azihsm/pota_private_key.der
azihsm-pota-public-key-path = /var/lib/azihsm/pota_public_key.der
azihsm-api-revision = 1.0
```

All configuration parameters and their defaults:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `azihsm-bmk-path` | `./bmk.bin` | Backup Masking Key |
| `azihsm-muk-path` | `./muk.bin` | Masked Unwrapping Key |
| `azihsm-obk-path` | `./obk.bin` | Owner Backup Key — 48-byte random binary file |
| `azihsm-obk-source` | `caller` | OBK source: `caller` (file) or `tpm` |
| `azihsm-pota-source` | `caller` | POTA source: `caller` (file) or `tpm` |
| `azihsm-pota-private-key-path` | `./pota_private_key.der` | POTA P-384 private key — legacy EC DER (ECPrivateKey / RFC 5915) |
| `azihsm-pota-public-key-path` | `./pota_public_key.der` | POTA P-384 public key — SubjectPublicKeyInfo DER |
| `azihsm-api-revision` | `1.0` | HSM API revision (`major.minor`) |

| Environment Variable | Fallback | Description |
|---------------------|----------|-------------|
| `AZIHSM_CREDENTIALS_ID` | `./credentials_id.bin` | Hex-encoded credential ID (32 hex chars = 16 bytes). If unset, reads from the fallback file. |
| `AZIHSM_CREDENTIALS_PIN` | `./credentials_pin.bin` | Hex-encoded credential PIN (32 hex chars = 16 bytes). If unset, reads from the fallback file. |

When using `openssl.cnf`, providers are auto-loaded — no `-provider-path` or `-provider` CLI flags needed:

```bash
OPENSSL_CONF=/path/to/openssl.cnf \
LD_LIBRARY_PATH=/path/to/target/debug \
openssl genpkey -propquery "?provider=azihsm" ...
```

**BMK** and **MUK** are generated and persisted automatically on first use — no setup required.

**OBK** (when `azihsm-obk-source = caller`) must be provided as a 48-byte random binary file. The provider returns a descriptive error if it is absent.

**POTA keys** (when `azihsm-pota-source = caller`) must be provided as a P-384 key pair: the private key encoded as legacy EC DER (ECPrivateKey / RFC 5915) and the public key as SubjectPublicKeyInfo DER. Both files must be present — providing only one is an error. The provider returns a descriptive error if either or both are absent.

**Credentials** must always be present at the configured paths.

## Provider Flags

> When using `openssl.cnf`, the provider is auto-loaded and only `-propquery` is needed — the flags below are not required.

When loading the provider via `-provider-path`, every `openssl` command requires these flags. Define them once in your shell:

```bash
PROV="-propquery ?provider=azihsm -provider default -provider azihsm_provider"
```

| Flag | Purpose |
|------|---------|
| `-propquery "?provider=azihsm"` | Route operations to the HSM provider when available; the `?` prefix allows fallback to the default provider for operations the HSM doesn't handle |
| `-provider default` | Load the default OpenSSL provider (needed for hashing, PEM encoding, etc.) |
| `-provider azihsm_provider` | Load the HSM provider |

> **Important:** `-propquery` **must** come before the `-provider` flags. OpenSSL processes CLI arguments left to right. Loading the provider triggers an HSM session that instantiates the DRBG (random number generator). If `-propquery` is applied afterwards, `RAND_set_DRBG_type` fails because the DRBG is already running. The error message from OpenSSL 3.0.x is misleading — it reports "odd number of digits" due to an upstream error code collision (`RAND_R_ALREADY_INSTANTIATED` and `CRYPTO_R_ODD_NUMBER_OF_DIGITS` are both 103, and the code uses `ERR_LIB_CRYPTO` instead of `ERR_LIB_RAND`).

> **Note:** If the provider is not installed system-wide, add `-provider-path /path/to/directory` pointing to the directory containing `azihsm_provider.so`. If `libazihsm_api_native.so` is also not in a system library path, set `LD_LIBRARY_PATH` to include its directory (e.g., `export LD_LIBRARY_PATH=/path/to/target/debug:$LD_LIBRARY_PATH`).

> **Note:** On physical hardware, provider commands require `sudo` to access TPM operations.

All examples below use `${PROV}` as shorthand for these three flags.

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

> `-out /dev/null` discards the standard OpenSSL key output. The real output is the masked key blob written to the path specified by `azihsm.masked_key`.

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
    -pkeyopt azihsm.masked_key:./ec_p384_ecdh_masked.bin \
    -outform DER -out /dev/null

# Ephemeral session key (deleted when HSM session ends)
openssl genpkey ${PROV} \
    -algorithm EC -pkeyopt group:P-256 \
    -pkeyopt azihsm.session:true \
    -pkeyopt azihsm.masked_key:./ec_p256_session.bin \
    -outform DER -out /dev/null
```

### EC Key Import

Import an externally generated EC private key (DER-encoded, SEC1 or PKCS#8) into the HSM. For pre-wrapped blobs, see [Wrapped Key Import](#wrapped-key-import).

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

The HSM cannot generate RSA keys natively. RSA keys must be generated externally and imported. The provider wraps the key using RSA-AES-WRAP and unwraps it inside the HSM. For pre-wrapped blobs, see [Wrapped Key Import](#wrapped-key-import).

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
| `azihsm.input_key` | Yes* | Path to DER-encoded private key (PKCS#1 or PKCS#8) |
| `azihsm.wrapped_key` | Yes* | Path to a pre-wrapped key blob (from `wrap_key` tool) |
| `azihsm.masked_key` | Yes | Output path for masked key blob |
| `azihsm.key_usage` | No | `digitalSignature` (default) or `keyEncipherment` |

> \* Exactly one of `azihsm.input_key` or `azihsm.wrapped_key` must be provided. Setting both is an error.

RSA-PSS keys are imported the same way using `-algorithm RSA-PSS`.

### Wrapped Key Import

Import a pre-wrapped key blob into the HSM. This is useful when keys are wrapped offline or by a separate system using the HSM's RSA-AES key wrapping mechanism. The blob must be wrapped using the HSM's RSA-AES-WRAP algorithm with the device's wrapping key pair.

**Requires:** A pre-wrapped key blob (PKCS#8 key wrapped with the HSM's RSA-AES-WRAP mechanism).

```bash
# Import a wrapped EC key
openssl genpkey ${PROV} \
    -algorithm EC -pkeyopt group:P-384 \
    -pkeyopt azihsm.wrapped_key:./wrapped_ec.bin \
    -pkeyopt azihsm.masked_key:./ec_from_wrapped.bin \
    -outform DER -out /dev/null

# Import a wrapped RSA key
openssl genpkey ${PROV} \
    -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -pkeyopt azihsm.wrapped_key:./wrapped_rsa.bin \
    -pkeyopt azihsm.key_usage:digitalSignature \
    -pkeyopt azihsm.masked_key:./rsa_from_wrapped.bin \
    -outform DER -out /dev/null
```

### ECDSA Sign and Verify

**Requires:** An EC key generated or imported with `digitalSignature` usage (the default).

**Digest + Sign (single command):**

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

**Pre-hashed (sign raw digest):**

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
    -sigopt rsa_pss_saltlen:digest \
    -verify "azihsm://./rsa_2048_sign.bin;type=rsa" \
    -signature rsa_pss_sig.bin data.bin
```

**PSS signature options:**

| Option | Values |
|--------|--------|
| `rsa_padding_mode` | `pss` |
| `rsa_pss_saltlen` | `digest` (hash length), `max` (maximum), or an integer (`auto` is not supported) |
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

**Encryption options:**

| Option | Values |
|--------|--------|
| `rsa_padding_mode` | `oaep` |
| `rsa_oaep_md` | Hash for OAEP: `sha256`, `sha384`, `sha512` (SHA-1 rejected) |
| `rsa_mgf1_md` | MGF1 hash (defaults to `rsa_oaep_md`) |

### AES Symmetric Encryption

AES uses the OpenSSL 3.5 opaque symmetric-key (`EVP_SKEY` / `SKEYMGMT`) API. Keys are opaque, HSM-resident objects — generated inside the HSM and never exposed as raw bytes; a masked blob is written to disk for later re-import, just like the asymmetric keys.

**Requires:** OpenSSL 3.5+ — the opaque-key manager (`SKEYMGMT`) and the cipher's `EVP_SKEY` init hooks exist only in 3.5+, so on any OpenSSL before 3.5 AES keys cannot be created or bound (raw-key init is refused). Note the build example earlier in this README uses OpenSSL 3.0.3; build and run against 3.5+ to use AES. No other prerequisite — the key is generated in the first step below.

Three kinds are supported, selected by the `azihsm.key_kind` skey option:

| `azihsm.key_kind` | Modes | `key-length` (bytes) |
|-------------------|-------|----------------------|
| `AES` (default) | CBC | 16 / 24 / 32 (AES-128/192/256) |
| `AES-GCM` | GCM | 32 (AES-256 only) |
| `AES-XTS` | XTS | 64 (an AES-256 key pair) |

Generate an opaque AES key with `skeyutl -genkey`; the masked blob is written to the `azihsm.masked_key` path:

```bash
# AES-256 (CBC-capable) key
openssl skeyutl -genkey ${PROV} \
    -skeymgmt AES \
    -skeyopt key-length:32 \
    -skeyopt azihsm.masked_key:./aes256_masked.bin

# AES-256-GCM key
openssl skeyutl -genkey ${PROV} \
    -skeymgmt AES \
    -skeyopt key-length:32 \
    -skeyopt azihsm.key_kind:AES-GCM \
    -skeyopt azihsm.masked_key:./aes256_gcm_masked.bin

# AES-256-XTS key (64-byte key pair)
openssl skeyutl -genkey ${PROV} \
    -skeymgmt AES \
    -skeyopt key-length:64 \
    -skeyopt azihsm.key_kind:AES-XTS \
    -skeyopt azihsm.masked_key:./aes256_xts_masked.bin
```

Encrypt and decrypt with AES-CBC via `openssl enc`. The opaque key is re-imported from its masked blob with the same `-skeymgmt AES -skeyopt azihsm.masked_key:...` options; the IV is supplied with `-iv`:

```bash
# Encrypt
openssl enc -e -aes-256-cbc ${PROV} \
    -skeymgmt AES \
    -skeyopt azihsm.masked_key:./aes256_masked.bin \
    -iv 000102030405060708090a0b0c0d0e0f \
    -in plaintext.bin -out ciphertext.bin

# Decrypt
openssl enc -d -aes-256-cbc ${PROV} \
    -skeymgmt AES \
    -skeyopt azihsm.masked_key:./aes256_masked.bin \
    -iv 000102030405060708090a0b0c0d0e0f \
    -in ciphertext.bin -out decrypted.bin
```

PKCS#7 padding is applied by default, so the input need not be block-aligned. `-aes-128-cbc` and `-aes-192-cbc` work the same way with 16- and 24-byte keys.

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-skeymgmt AES` | Yes | Select the azihsm AES opaque-key manager |
| `key-length` | No | (`-genkey` only) Raw key length in **bytes**; defaults to 32 for `AES`/`AES-GCM`, 64 for `AES-XTS`. On `enc` the length comes from the masked blob |
| `azihsm.key_kind` | No | `AES` (default, CBC), `AES-GCM`, or `AES-XTS` |
| `azihsm.masked_key` | Yes | On `-genkey`: output path for the masked blob. On `enc`: the masked blob to re-import |

> **GCM and XTS are not reachable through `openssl enc`** — the `enc` app's `opt_cipher()` rejects AEAD and XTS ciphers, so a GCM nonce/AAD/tag or an XTS tweak cannot be passed through the CLI. These modes are driven through the `EVP_CipherInit_SKEY` C API instead. (On decrypt, AES-GCM requires the tag to be set *before* the ciphertext, since the HSM decrypts and verifies in a single operation.)

> **Opacity:** AES keys are non-exportable — `EVP_SKEY_get0_raw_key()` fails by design, so raw key bytes never leave the HSM.

### ECDH Key Exchange

Derive a shared secret with a peer's public key. The output is a masked key blob (not raw bytes). The provider supports two output modes: when `output_file` is set, the masked blob is written to that file and `secretlen` is set to 0; when `output_file` is not set, the masked blob is written into the caller's buffer. This masked key is the required input for HKDF key derivation.

**Requires:** An EC key generated with `keyAgreement` usage. A `digitalSignature` EC key cannot be used for ECDH.

```bash
# Generate peer key (no HSM)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out peer_priv.pem
openssl pkey -in peer_priv.pem -pubout -out peer_pub.pem

# Derive shared secret — write masked blob to a named file
openssl pkeyutl -derive ${PROV} \
    -inkey "azihsm://./ec_p384_ecdh_masked.bin;type=ec" \
    -peerkey peer_pub.pem \
    -pkeyopt output_file:shared_masked.bin

# Derive shared secret — write masked blob via the caller's buffer
openssl pkeyutl -derive ${PROV} \
    -inkey "azihsm://./ec_p384_ecdh_masked.bin;type=ec" \
    -peerkey peer_pub.pem \
    -out shared_masked.bin
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `output_file` | No | Path for output masked key blob. When set, the blob is written directly to the file and `secretlen` is set to 0. When not set, the blob is returned in the caller's buffer (written to `-out` on the CLI) and `secretlen` reflects the blob size |

> **API note:** The azihsm provider returns a masked key blob instead of the raw shared secret. Both output modes produce the same opaque blob — the difference is only in how it reaches the caller:
>
> - **With `output_file`:** The blob is written directly to the named file. `secretlen` is set to 0, so the caller's buffer is empty — read from the file instead.
> - **Without `output_file`:** The blob is copied into the caller's buffer and `secretlen` reflects the blob size. On the CLI, `-out` writes this buffer to a file.

### HKDF Key Derivation

Derive AES or HMAC keys from a masked key file using HKDF (RFC 5869). The input keying material (IKM) must be a masked key blob — typically the output of an ECDH derive. The output is also a masked key blob.

**Requires:** A masked key file as IKM, produced by ECDH derive or another HKDF derivation.

```bash
# Derive an AES-256 key from an ECDH shared secret
openssl kdf ${PROV} \
    -keylen 4096 \
    -kdfopt digest:SHA256 \
    -kdfopt azihsm.ikm_file:./shared_masked.bin \
    -kdfopt output_file:./aes_masked.bin \
    -kdfopt derived_key_type:aes \
    -kdfopt derived_key_bits:256 \
    -binary -out /dev/null \
    HKDF

# Derive an HMAC key with salt and info
openssl kdf ${PROV} \
    -keylen 4096 \
    -kdfopt digest:SHA384 \
    -kdfopt azihsm.ikm_file:./shared_masked.bin \
    -kdfopt output_file:./hmac_masked.bin \
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

### KBKDF Key Derivation

Derive AES or HMAC keys from a masked key file using KBKDF (NIST SP 800-108 Counter Mode with an HMAC PRF). Like HKDF, the input keying material (IKM) must be a masked key blob — typically the output of an ECDH derive — and the output is also a masked key blob. The standard `salt` / `info` parameters map to the SP 800-108 **label** and **context**; at least one of them must be provided.

**Requires:** A masked key file as IKM, produced by ECDH derive or another KDF derivation.

```bash
# Derive an AES-256 key from an ECDH shared secret (label only)
openssl kdf ${PROV} \
    -keylen 4096 \
    -kdfopt digest:SHA256 \
    -kdfopt mode:counter \
    -kdfopt azihsm.ikm_file:./shared_masked.bin \
    -kdfopt output_file:./aes_masked.bin \
    -kdfopt derived_key_type:aes \
    -kdfopt derived_key_bits:256 \
    -kdfopt hexsalt:000102030405060708090a0b0c \
    -binary -out /dev/null \
    KBKDF

# Derive an HMAC key with label and context
openssl kdf ${PROV} \
    -keylen 4096 \
    -kdfopt digest:SHA384 \
    -kdfopt azihsm.ikm_file:./shared_masked.bin \
    -kdfopt output_file:./hmac_masked.bin \
    -kdfopt derived_key_type:hmac \
    -kdfopt derived_key_bits:384 \
    -kdfopt hexsalt:000102030405060708090a0b0c \
    -kdfopt hexinfo:f0f1f2f3f4f5f6f7f8f9 \
    -binary -out /dev/null \
    KBKDF
```

**Output behavior** is identical to [HKDF](#hkdf-key-derivation): when `output_file` is set the masked blob is written there, otherwise it is written into the caller's buffer (which `-keylen` must be large enough to hold).

**KBKDF parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `digest` | No | HMAC PRF hash: `SHA1`, `SHA256` (default), `SHA384`, `SHA512`. For `derived_key_type:hmac`, this also determines the HMAC key kind |
| `mode` | No | KBKDF mode; only `counter` is supported (default) |
| `mac` | No | PRF MAC; only `HMAC` is supported (default) |
| `azihsm.ikm_file` | Yes | Path to masked key file used as input keying material |
| `output_file` | No | Path for output masked key blob. When set, takes priority over the caller's buffer |
| `derived_key_type` | No | `aes` (default) or `hmac` |
| `derived_key_bits` | No | Output key size in bits (default: 256). Must be >0 and divisible by 8 |
| `hexsalt` | No\* | SP 800-108 **label** in hex |
| `hexinfo` | No\* | SP 800-108 **context** in hex |

\* At least one of `hexsalt` (label) / `hexinfo` (context) must be provided; deriving with both absent is rejected.

When using `derived_key_type:hmac`, the `digest` ↔ `derived_key_bits` ↔ HMAC key-kind matching rules are identical to [HKDF](#hkdf-key-derivation) (SHA256/256, SHA384/384, SHA512/512).

### HMAC

Compute an HMAC tag using a masked HMAC key from the HSM. HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512 are supported. HMAC-SHA1 is intentionally unsupported.

**Requires:** A masked HMAC key derived via HKDF with `derived_key_type:hmac`. See [HKDF Key Derivation](#hkdf-key-derivation) for how to produce one.

```bash
# HMAC-SHA256
openssl mac -digest SHA256 ${PROV} \
    -macopt key:./hmac_sha256_key.bin \
    -in data.bin \
    HMAC

# HMAC-SHA384
openssl mac -digest SHA384 ${PROV} \
    -macopt key:./hmac_sha384_key.bin \
    -in data.bin \
    HMAC

# HMAC-SHA512
openssl mac -digest SHA512 ${PROV} \
    -macopt key:./hmac_sha512_key.bin \
    -in data.bin \
    HMAC

# Write binary HMAC output to file
openssl mac -digest SHA256 ${PROV} \
    -macopt key:./hmac_sha256_key.bin \
    -in data.bin \
    -binary -out data.hmac \
    HMAC
```

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-digest` | No | Hash algorithm: `SHA256` (default), `SHA384`, `SHA512`. Must match the digest used when deriving the key via HKDF |
| `-macopt key:<path>` | Yes | Path to the masked HMAC key file |
| `-in` | Yes | Input file to compute the HMAC over |
| `-binary -out <path>` | No | Write raw binary MAC to file instead of hex to stdout |

> **Important:** The `-digest` must match the HKDF `digest` used when the key was derived. A key derived with `digest:SHA384` can only be used with `-digest SHA384`. Using a mismatched digest will fail during key unmasking.

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
    -pkeyopt azihsm.masked_key:./ecdh_masked.bin -outform DER -out /dev/null

# 2. Generate a peer key and perform ECDH
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out peer.pem
openssl pkey -in peer.pem -pubout -out peer_pub.pem

openssl pkeyutl -derive ${PROV} \
    -inkey "azihsm://./ecdh_masked.bin;type=ec" \
    -peerkey peer_pub.pem \
    -pkeyopt output_file:shared_masked.bin

# 3. Derive an AES key via HKDF
openssl kdf ${PROV} -keylen 4096 \
    -kdfopt digest:SHA384 \
    -kdfopt azihsm.ikm_file:./shared_masked.bin \
    -kdfopt output_file:./aes_masked.bin \
    -kdfopt derived_key_type:aes -kdfopt derived_key_bits:256 \
    -binary -out /dev/null HKDF
```

## Full Chain Example: ECDH to HKDF to HMAC

A complete workflow from key agreement through key derivation to message authentication:

```bash
# 1. Generate an ECDH key
openssl genpkey ${PROV} -algorithm EC -pkeyopt group:P-384 \
    -pkeyopt azihsm.key_usage:keyAgreement \
    -pkeyopt azihsm.masked_key:./ecdh_masked.bin -outform DER -out /dev/null

# 2. Generate a peer key and perform ECDH
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out peer.pem
openssl pkey -in peer.pem -pubout -out peer_pub.pem

openssl pkeyutl -derive ${PROV} \
    -inkey "azihsm://./ecdh_masked.bin;type=ec" \
    -peerkey peer_pub.pem \
    -pkeyopt output_file:shared_masked.bin

# 3. Derive an HMAC-SHA256 key via HKDF
openssl kdf ${PROV} -keylen 4096 \
    -kdfopt digest:SHA256 \
    -kdfopt azihsm.ikm_file:./shared_masked.bin \
    -kdfopt output_file:./hmac_masked.bin \
    -kdfopt derived_key_type:hmac -kdfopt derived_key_bits:256 \
    -binary -out /dev/null HKDF

# 4. Compute HMAC over data
openssl mac -digest SHA256 ${PROV} \
    -macopt key:./hmac_masked.bin \
    -in data.bin \
    HMAC
```
