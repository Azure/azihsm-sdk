# TBOR — Tabular Binary Object Representation

A compact, `#![no_std]` binary protocol for host ↔ device communication, with a derive macro that generates zero-copy decoders, zero-storage typestate encoders, and compile-time schema validation.

📄 **[Protocol Specification](docs/spec.md)**

## Features

- **Zero-copy decoding** — views borrow the wire buffer, no allocations
- **Zero-storage encoding** — typestate encoder writes directly to the buffer, no field buffering
- **Compile-time safety** — field order, required fields, and type mismatches are caught at compile time
- **`#![no_std]`** — runs on bare-metal (Cortex-M) with no heap
- **Optional fields** — `Option<T>` with `None` TOC entries, skip-ahead, early `finish()`
- **Alignment padding** — `#[tbor(align = N)]` for DMA-friendly data layout
- **Field groups** — `#[tbor(fields)]` + `#[tbor(include)]` for shared field definitions
- **Dispatch traits** — `TborRequest::OPCODE` for opcode-based routing

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
azihsm_tbor = { path = "tbor" }
```

## Usage

### Define a Message Schema

```rust
use azihsm_tbor::tbor;

#[tbor(opcode = 0x0A)]
pub struct MyRequest<'a> {
    #[tbor(session_id)]
    session: u16,
    #[tbor(max_len = 256)]
    data: &'a [u8],
}

#[tbor(response)]
pub struct MyResponse<'a> {
    #[tbor(max_len = 256)]
    result: &'a [u8],
}
```

### Encode

```rust
fn encode_request(buf: &mut [u8]) -> Result<&[u8], EncodeError> {
    let frame = MyRequest::encode(buf)?
        .session(SessionId(43))?
        .data(b"Hello")?
        .finish();

    Ok(frame.as_bytes())
}
```

### Decode

```rust
fn decode_request(wire: &[u8]) -> Result<(), DecodeError> {
    let view = MyRequest::decode(wire)?;

    let session = view.session();   // SessionId(43)
    let data = view.data();         // b"Hello"
    Ok(())
}
```

### Wire Format

**Request** (17 bytes): `session_id=43, buffer="Hello"`

```
Hex dump:
0000  01 00 01 0a  00 00 00 2b  1c 00 a0 00  48 65 6c 6c  ·······+····Hell
0010  6f                                                    o

Decoded:
Request v1 opcode=0x0A toc_count=2 (17 bytes)
  TOC[0]: session_id  = 0x002B (43)
  TOC[1]: buffer      [5 bytes] 48 65 6c 6c 6f
```

**Response** (15 bytes): `status=Success, FIPS=true, buffer="OK!"`

```
Hex dump:
0000  01 01 00 00  00 00 00 00  1c 00 60 00  4f 4b 21     ··········`·OK!

Decoded:
Response v1 status=0x00000000 (Success) flags=[FIPS] toc_count=1 (15 bytes)
  TOC[0]: buffer      [3 bytes] 4f 4b 21
```

### Optional Fields

```rust
#[tbor(opcode = 0x50)]
pub struct EncryptReq<'a> {
    #[tbor(session_id)]
    session: u16,
    algorithm: u8,
    iv: Option<[u8; 12]>,              // optional fixed array
    #[tbor(align = 4, max_len = 4096)]
    plaintext: &'a [u8],               // aligned buffer
}
```

```rust
// Set all fields
EncryptReq::encode(&mut buf)?
    .session(SessionId(7))?
    .algorithm(3)?
    .iv(Some(&[0u8; 12]))?
    .plaintext(b"data")?
    .finish()

// Skip optional iv — jump straight to plaintext
EncryptReq::encode(&mut buf)?
    .session(SessionId(7))?
    .algorithm(3)?
    .plaintext(b"data")?      // auto-emits None for iv
    .finish()
```

### Field Groups (Shared Fields)

```rust
#[tbor(fields)]
pub struct CryptoHeader {
    #[tbor(session_id)]
    session: u16,
    #[tbor(key_id)]
    key: u16,
    algorithm: u8,
}

#[tbor(opcode = 0x50)]
pub struct EncryptReq<'a> {
    #[tbor(include)]
    header: CryptoHeader,
    #[tbor(align = 4, max_len = 4096)]
    plaintext: &'a [u8],
}
```

```rust
EncryptReq::encode(&mut buf)?
    .header(|h| h.session(SessionId(7))?.key(KeyId(42))?.algorithm(3))?
    .plaintext(b"data")?
    .finish()
```

### Opcode Dispatch

```rust
use azihsm_tbor::{TborRequest, RequestView};

fn dispatch(wire: &[u8]) -> Result<(), DecodeError> {
    let raw = RequestView::parse(wire)?;

    match raw.opcode() {
        EncryptReq::OPCODE  => handle_encrypt(EncryptReq::decode(wire)?),
        DecryptReq::OPCODE  => handle_decrypt(DecryptReq::decode(wire)?),
        _ => Err(DecodeError::OpcodeMismatch { expected: 0, actual: raw.opcode() })
    }
}
```

### Stack-Allocated Buffer

```rust
// MAX_ENCODED_SIZE is a compile-time constant
let mut buf = [0u8; EncryptReq::MAX_ENCODED_SIZE];
let frame = EncryptReq::encode(&mut buf)?
    .session(SessionId(7))?
    .algorithm(3)?
    .plaintext(b"data")?
    .finish();
```

## Crate Structure

| Crate | Purpose |
|-------|---------|
| `azihsm_tbor_core` | `#![no_std]` wire format: error types, TOC helpers, generic encoder/decoder |
| `azihsm_tbor_derive` | `#[tbor]` proc macro: typestate encoder, zero-copy view, validation |
| `azihsm_tbor` | Re-exports core + derive, provides `SessionId`/`KeyId` newtypes |

## Schema Attributes

| Attribute | Applies to | Description |
|-----------|-----------|-------------|
| `#[tbor(opcode = N)]` | struct | Request message with opcode N |
| `#[tbor(response)]` | struct | Response message |
| `#[tbor(fields)]` | struct | Reusable field group (no encoder/decoder) |
| `#[tbor(include)]` | field | Include a field group's fields at this position |
| `#[tbor(session_id)]` | field | Wire type: inline 16-bit session ID |
| `#[tbor(key_id)]` | field | Wire type: inline 16-bit key ID |
| `#[tbor(sealed_key)]` | field | Wire type: sealed key blob |
| `#[tbor(align = N)]` | field | Align data to N-byte boundary (power of 2) |
| `#[tbor(max_len = N)]` | field | Maximum buffer length (required on `&[u8]`) |
| `#[tbor(min_len = N)]` | field | Minimum buffer length |

## License

Copyright (c) Microsoft Corporation. Licensed under the MIT License.
