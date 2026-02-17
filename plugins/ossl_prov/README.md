# Azure Integrated HSM - OpenSSL Provider

An OpenSSL 3.0 provider that delegates cryptographic operations to an Azure
Integrated Hardware Security Module (HSM). Private keys never leave the HSM;
the provider operates on opaque handles and supports masked key import/export
for persistent storage outside the HSM.

## Supported Operations

| Operation | Algorithms | CLI | C API |
|-----------|-----------|-----|-------|
| Key Generation | EC (P-256, P-384, P-521), RSA | `genpkey` | `EVP_PKEY_generate` |
| Signing | ECDSA with SHA-1/256/384/512 | `dgst -sign` | `EVP_DigestSign` |
| Verification | ECDSA with SHA-1/256/384/512 | `dgst -verify` | `EVP_DigestVerify` |
| Key Exchange | ECDH | `pkeyutl -derive` | `EVP_PKEY_derive` |
| Key Derivation | HKDF (SHA-256/384/512) | `kdf` | `EVP_KDF_derive` |
| Digest | SHA-1, SHA-256, SHA-384, SHA-512 | `dgst` | `EVP_Digest` |
| Key Encoding | EC and RSA (DER, text) | `pkey` | `i2d_PUBKEY` |
| Key Loading | `azihsm://` URI scheme | any `-inkey` | `OSSL_STORE_open` |

## Building

```bash
cd azihsm-sdk/plugins/ossl_prov && cargo build
```

The output is `azihsm_provider.so` in `azihsm-sdk/target/debug/`.

For development without physical HSM hardware, the library can be built with
mock functionality that simulates HSM operations:

```bash
cd azihsm-sdk/plugins/ossl_prov && cargo build --features mock
```

## Provider Loading

The provider is loaded alongside the `default` provider. A property query
with the `?` prefix tells OpenSSL to **prefer** the azihsm provider but
**fall back** to the default provider for operations the HSM does not
implement (e.g. PEM encoding, X.509 parsing):

```
-provider default -provider azihsm_provider -propquery '?provider=azihsm'
```

Without the `?` prefix, any operation not implemented by the azihsm
provider would fail instead of falling back.

### CLI Setup

The examples below assume these shell variables:

```bash
export LD_LIBRARY_PATH=$(pwd)/openssl-build/lib64
export OSSL=$(pwd)/openssl-build/bin/openssl
export PROV="-provider-path $(pwd)/azihsm-sdk/target/debug \
    -provider default -provider azihsm_provider \
    -propquery ?provider=azihsm"
```

### openssl.cnf

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
azihsm  = azihsm_sect

[default_sect]
activate = 1

[azihsm_sect]
module   = /path/to/azihsm_provider.so
activate = 1
```

When configured via `openssl.cnf`, set the default property query to prefer
the provider:

```ini
[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[algorithm_sect]
default_properties = ?provider=azihsm
```

### C API

```c
#include <openssl/provider.h>

OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
OSSL_PROVIDER_load(libctx, "default");
OSSL_PROVIDER_load(libctx, "azihsm_provider");

/* All EVP_*_fetch calls accept a property query string */
EVP_MD *md = EVP_MD_fetch(libctx, "SHA-256", "?provider=azihsm");
```

## Masked Keys

The HSM has limited storage. Keys are exported as **masked keys** -- private
keys encrypted by an HSM-internal key unique to each device. This allows safe
off-device storage while ensuring keys are only usable on the originating HSM.

**Lifecycle:**

1. Generate key pair in HSM (`genpkey` with `azihsm.masked_key`)
2. Masked key blob is written to the specified file
3. Load later via `azihsm://` URI (any `-inkey` or `OSSL_STORE` API)
4. HSM unmasks the key internally; private key material is never exposed

## The `azihsm://` URI Scheme

Masked key files are loaded through a custom `OSSL_STORE` implementation that
handles `azihsm://` URIs.

**Format:**

```
azihsm://<file-path>;type=<ec|rsa>
```

| Component | Description |
|-----------|-------------|
| `<file-path>` | Path to the masked key file (relative or absolute) |
| `type=ec` | Elliptic curve key |
| `type=rsa` | RSA key |

**Examples:**

```
azihsm://./masked_key_p384.bin;type=ec
azihsm:///var/lib/azihsm/rsa_key.bin;type=rsa
```

## Key Generation

The provider implements key generation via `openssl genpkey` or the
`EVP_PKEY_generate` API for EC and RSA keys.

```bash
$OSSL genpkey $PROV \
    -algorithm EC \
    -pkeyopt group:P-384 \
    -pkeyopt azihsm.masked_key:./my_key.bin \
    -outform DER -out pub_key.der
```

**Key generation parameters (`-pkeyopt`):**

| Parameter | Values | Default | Description |
|-----------|--------|---------|-------------|
| `group` | `P-256`, `P-384`, `P-521` | -- | EC curve (required for EC) |
| `azihsm.masked_key` | file path | -- | Output path for masked key blob |
| `azihsm.key_usage` | `digitalSignature`, `keyAgreement` | `digitalSignature` | Key purpose |
| `azihsm.session` | `true`, `false` | `false` | Session (ephemeral) vs. persistent key |
| `azihsm.input_key` | file path | -- | Import an existing DER-encoded key into the HSM |

RSA key generation follows the same pattern with `-algorithm RSA`.

**C API:** Custom parameters are passed via `OSSL_PARAM` arrays to
`EVP_PKEY_CTX_set_params` before calling `EVP_PKEY_generate`:

```c
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", "?provider=azihsm");
EVP_PKEY *pkey = NULL;

EVP_PKEY_keygen_init(ctx);

OSSL_PARAM params[] = {
    OSSL_PARAM_utf8_string("group", "P-384", 0),
    OSSL_PARAM_utf8_string("azihsm.masked_key", "./my_key.bin", 0),
    OSSL_PARAM_utf8_string("azihsm.key_usage", "digitalSignature", 0),
    OSSL_PARAM_END,
};
EVP_PKEY_CTX_set_params(ctx, params);
EVP_PKEY_generate(ctx, &pkey);
```

## Signing and Verification

The provider implements ECDSA signing and verification via `openssl dgst`
or the `EVP_DigestSign`/`EVP_DigestVerify` API.

**Sign** a file with an HSM-resident EC key:

```bash
$OSSL dgst -sha384 $PROV \
    -sign "azihsm://./my_key.bin;type=ec" \
    -out document.sig \
    document.txt
```

**Verify** using the DER-encoded public key:

```bash
$OSSL dgst -sha384 $PROV \
    -verify pub_key.der -keyform DER \
    -signature document.sig \
    document.txt
```

Supported digest algorithms: SHA-1, SHA-256, SHA-384, SHA-512.

## Key Exchange (ECDH)

The provider implements ECDH key exchange via `openssl pkeyutl -derive` or
the `EVP_PKEY_derive` API. The derived shared secret is a masked key blob,
not raw bytes -- it can be used as input to HKDF or other HSM operations.

```bash
# 1. Generate an ECDH key pair
$OSSL genpkey $PROV \
    -algorithm EC \
    -pkeyopt group:P-384 \
    -pkeyopt azihsm.key_usage:keyAgreement \
    -pkeyopt azihsm.masked_key:./ecdh_key.bin \
    -outform DER -out /dev/null

# 2. Generate a peer key pair (plain OpenSSL, no HSM)
$OSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out peer_priv.pem
$OSSL pkey -in peer_priv.pem -pubout -out peer_pub.pem

# 3. Derive shared secret (masked key blob written to file)
$OSSL pkeyutl -derive $PROV \
    -inkey "azihsm://./ecdh_key.bin;type=ec" \
    -peerkey peer_pub.pem \
    -pkeyopt azihsm.output_file:shared_secret.bin
```

When `azihsm.output_file` is not set, the masked key blob is returned in the
caller's output buffer instead (programmatic path via `EVP_PKEY_derive`).

## Key Derivation (HKDF)

The provider implements HKDF (RFC 5869) via `openssl kdf` or the
`EVP_KDF_derive` API. Derives a new masked key from an existing shared secret.

```bash
$OSSL kdf $PROV \
    -kdfopt digest:SHA256 \
    -kdfopt azihsm.ikm_file:shared_secret.bin \
    -kdfopt azihsm.output_file:derived_key.bin \
    -kdfopt azihsm.derived_key_type:aes \
    -kdfopt azihsm.derived_key_bits:256 \
    -kdfopt salt:00112233 \
    -kdfopt info:6170706C6963617469F6E \
    -binary -out /dev/null \
    HKDF
```

**HKDF parameters (`-kdfopt`):**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `digest` | string | `SHA256` | Hash algorithm (SHA256, SHA384, SHA512) |
| `key` | hex octet string | -- | Masked key bytes (`OSSL_KDF_PARAM_KEY`) |
| `azihsm.ikm_file` | file path | -- | Path to masked IKM file |
| `salt` | hex octet string | -- | Optional salt |
| `info` | hex octet string | -- | Optional context/info |
| `azihsm.output_file` | file path | -- | Output path for derived masked key |
| `azihsm.derived_key_type` | string | `aes` | `aes` or `hmac` |
| `azihsm.derived_key_bits` | integer | `256` | Key size in bits (must be divisible by 8) |

`key` and `azihsm.ikm_file` are mutually exclusive -- setting both is an
error. `azihsm.output_file` takes priority over the caller's output buffer --
if set, the masked key blob is written to that file and nothing is returned in
the buffer. Only when `azihsm.output_file` is **not** set does the masked key
blob get written into the caller's output buffer (via `EVP_KDF_derive`).

## Digest

The provider implements SHA-1, SHA-256, SHA-384, and SHA-512 via `openssl dgst`
or the `EVP_Digest` API.

```bash
$OSSL dgst -sha384 $PROV document.txt
```

## Custom Parameter Reference

All provider-specific parameters use the `azihsm.` prefix to distinguish them
from standard OpenSSL parameters.

| Parameter | Type | Used By | Description |
|-----------|------|---------|-------------|
| `azihsm.masked_key` | file path | Key Generation | Write masked key blob to this file |
| `azihsm.key_usage` | string | Key Generation | `digitalSignature` (default) or `keyAgreement` |
| `azihsm.session` | boolean | Key Generation | `true` for ephemeral, `false` for persistent (default) |
| `azihsm.input_key` | file path | Key Generation | DER-encoded key to import into the HSM |
| `azihsm.output_file` | file path | ECDH, HKDF | Write derived masked key blob to this file |
| `azihsm.ikm_file` | file path | HKDF | Read input keying material from this masked key file |
| `azihsm.derived_key_type` | string | HKDF | `aes` (default) or `hmac` |
| `azihsm.derived_key_bits` | uint32 | HKDF | Key size in bits, must be divisible by 8 (default: 256) |

## Limitations

- **Device-bound keys**: Masked keys are encrypted with an HSM-internal key and
  can only be used on the same HSM that created them.
- **No raw key export**: Private key bytes are never exposed. All outputs are
  masked key blobs.
- **RSA signing**: Not yet implemented (key generation and encoding are
  supported).
- **AES/cipher operations**: Not yet implemented.
- **HMAC**: Not yet implemented.
- **RSA asymmetric encryption**: Not yet implemented.
- **HKDF modes**: Only full HKDF (extract-and-expand) is supported; extract-only
  and expand-only modes are not available.
