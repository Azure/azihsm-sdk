# Tabular Binary Object Representation (TBOR) Specification

## Version

0.3

## Table of Contents

- [Overview](#overview)
  - [Purpose](#purpose)
  - [Scope](#scope)
  - [Terminology](#terminology)
  - [Byte Ordering](#byte-ordering)
- [Request Format](#request-format)
  - [Header Fields](#header-fields)
  - [Field Details](#field-details)
- [Response Format](#response-format)
  - [Header Fields](#header-fields-1)
  - [Field Details](#field-details-1)
  - [Well-Known Status Codes](#well-known-status-codes)
- [TOC Entry Format](#toc-entry-format)
  - [Entry Types](#entry-types)
  - [Encoding: Inline None](#encoding-inline-none)
  - [Encoding: Inline 8-bit](#encoding-inline-8-bit)
  - [Encoding: Inline 16-bit](#encoding-inline-16-bit)
  - [Encoding: Offset/Length](#encoding-offsetlength)
  - [Data Alignment](#data-alignment)
- [Protocol Rules](#protocol-rules)
- [Schema Features](#schema-features)
  - [Optional Fields](#optional-fields)
  - [Alignment Padding](#alignment-padding)
  - [Typed Slices](#typed-slices)
  - [Fixed-Size Arrays](#fixed-size-arrays)
  - [Length Constraints](#length-constraints)
  - [Field Groups](#field-groups)
  - [Dispatch Traits](#dispatch-traits)
- [Security Considerations](#security-considerations)
- [Worked Examples](#worked-examples)
  - [Example 1 — Simple Request](#example-1--simple-request)
  - [Example 2 — Simple Response](#example-2--simple-response)
  - [Example 3 — Request with Optional Field](#example-3--request-with-optional-field)
- [Revision History](#revision-history)

---

## Overview

### Purpose

This document defines the binary request/response protocol used for communication between host software and device hardware. The protocol provides a compact, structured wire format that enables the host to issue commands (requests) to the device and receive structured results (responses). It is designed for low-overhead, deterministic communication in environments where bandwidth and latency are constrained.

### Scope

This specification covers:

- The wire format for request and response messages.
- The framing structure, including the fixed header and Table of Contents (TOC) mechanism.
- The encoding rules for TOC entries and the variable-length data section.
- The `none` entry type for representing absent optional fields.
- The `padding` entry type for aligning field data within the variable-length data section.
- Protocol-level rules for versioning, ordering, error handling, and timeouts.

This specification does **not** cover:

- The transport layer (e.g., SPI, I2C, USB, shared memory). The protocol is transport-agnostic and assumes a reliable, ordered byte-stream or message-based transport.
- The application-layer opcode catalog. Opcodes and their semantics are defined by the application layer built on top of this protocol.
- Session management beyond the `session_id` TOC entry type.

### Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

### Byte Ordering

All multi-byte integer fields in the header and TOC structures are encoded in **little-endian** byte order. All reserved fields MUST be set to zero by senders and MUST be ignored by receivers.

> **Note:** Inline 16-bit values within TOC entries are an exception — see [Encoding: Inline 16-bit](#encoding-inline-16-bit) for details.

---

## Request Format

A request is sent by the host to the device to initiate an operation. It consists of a **fixed 4-byte header** followed by 1–32 [TOC entries](#toc-entry-format) and an optional variable-length data section. The TOC entries describe the parameters of the operation; each entry either inlines a small value directly or provides an offset and length into the variable-length data section that follows the TOC.

**Message size bounds:**

| Component             | Minimum  | Maximum  |
|-----------------------|----------|----------|
| Header                | 4 bytes  | 4 bytes  |
| TOC entries (1–32)    | 4 bytes  | 128 bytes|
| Variable-length data  | 0 bytes  | 8191 bytes |
| **Total**             | **8 bytes** | **8323 bytes** |

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |    Reserved   | Rsv |TOC Count|     Opcode    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TOC Entry 1                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TOC Entry 2                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TOC Entry 32                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Variable-Length Data ...                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Header Fields

| Offset | Size    | Field       | Description                                      |
|--------|---------|-------------|--------------------------------------------------|
| 0      | 1 byte  | Version     | Protocol version. Current version is `0x01`.      |
| 1      | 1 byte  | Reserved    | Reserved for future use. MUST be `0x00`.          |
| 2      | 3 bits  | Reserved    | Reserved for future use. MUST be `0b000`.         |
| 2.3    | 5 bits  | TOC Count   | Number of entries in the Table of Contents (1–32). Encoded as count minus 1 (`0x00` = 1 entry, `0x1F` = 32 entries). |
| 3      | 1 byte  | Opcode      | Operation code identifying the request type.      |

### Field Details

#### Version (Byte 0)

Identifies the protocol version. A receiver MUST reject requests with an unsupported version by responding with opcode `0xFF` and status code `0x00000001` (Unsupported Version). See [Well-Known Status Codes](#well-known-status-codes).

| Value  | Meaning            |
|--------|--------------------|
| `0x01` | Protocol version 1 |

#### Reserved (Byte 1)

Reserved for future protocol extensions. Senders MUST set this byte to `0x00`. Receivers MUST ignore its value.

#### Reserved / TOC Count (Byte 2)

```
Bit layout of byte 2:

  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
|  Rsvd (3) |   TOC Count (5)   |
+---+---+---+---+---+---+---+---+
```

- **Bits 7–5 (Reserved):** MUST be `0`. Reserved for future use.
- **Bits 4–0 (TOC Count):** Encoded as **count minus 1** (unsigned). A value of `0x00` means 1 TOC entry; `0x1F` means 32 TOC entries. Every request MUST contain at least one TOC entry. Each TOC entry describes a parameter or data section of the request payload. See [TOC Entry Format](#toc-entry-format) for the structure of individual entries.

#### Opcode (Byte 3)

Identifies the operation to be performed. Opcode values are defined by the application layer. The following opcode is reserved by the protocol:

| Value  | Meaning                    |
|--------|----------------------------|
| `0xFF` | Version Not Supported      |
| Others | Application-defined        |

---

## Response Format

A response is sent by the device back to the host after processing a request. Every request MUST produce exactly one response. The response consists of a **fixed 8-byte header** followed by 1–32 [TOC entries](#toc-entry-format) and an optional variable-length data section. The TOC entries describe the output data returned by the operation.

**Message size bounds:**

| Component             | Minimum   | Maximum   |
|-----------------------|-----------|-----------|
| Header                | 8 bytes   | 8 bytes   |
| TOC entries (1–32)    | 4 bytes   | 128 bytes |
| Variable-length data  | 0 bytes   | 8191 bytes |
| **Total**             | **12 bytes** | **8327 bytes** |

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Flags     |    Reserved   | Rsv |TOC Count|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Status Code                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TOC Entry 1                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TOC Entry 2                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TOC Entry 32                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Variable-Length Data ...                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Header Fields

| Offset | Size    | Field       | Description                                      |
|--------|---------|-------------|--------------------------------------------------|
| 0      | 1 byte  | Version     | Protocol version. MUST match the version of the corresponding request. |
| 1      | 1 byte  | Flags       | Bit flags (see [Flags](#flags-byte-1) below).     |
| 2      | 1 byte  | Reserved    | Reserved for future use. MUST be `0x00`.          |
| 3      | 3 bits  | Reserved    | Reserved for future use. MUST be `0b000`.         |
| 3.3    | 5 bits  | TOC Count   | Number of TOC entries (1–32). Encoded as count minus 1 (`0x00` = 1 entry, `0x1F` = 32 entries). |
| 4      | 4 bytes | Status Code | Application-defined status code indicating the result of the request. See [Well-Known Status Codes](#well-known-status-codes). |

### Field Details

#### Version (Byte 0)

Identifies the protocol version. The response version MUST match the version field of the corresponding request, even in error responses. This allows the sender to correlate the response with the protocol version it used.

| Value  | Meaning            |
|--------|--------------------|
| `0x01` | Protocol version 1 |

#### Flags (Byte 1)

```
Bit layout of byte 1:

  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
|        Reserved (7)       | F |
+---+---+---+---+---+---+---+---+
```

| Bit | Name          | Description                                                  |
|-----|---------------|--------------------------------------------------------------|
| 0   | FIPS_APPROVED | Set to `1` if the operation was performed using only FIPS 140-2/140-3 approved cryptographic algorithms and modules. Set to `0` otherwise. This flag is informational and MUST NOT be used as the sole mechanism for enforcing compliance policy (see [Security Considerations](#security-considerations)). |
| 1–7 | Reserved      | MUST be `0`. Reserved for future use.                        |

#### Reserved (Byte 2)

Reserved for future protocol extensions. Senders MUST set this byte to `0x00`. Receivers MUST ignore its value.

#### Reserved / TOC Count (Byte 3)

```
Bit layout of byte 3:

  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
|  Rsvd (3) |   TOC Count (5)   |
+---+---+---+---+---+---+---+---+
```

- **Bits 7–5 (Reserved):** MUST be `0`. Reserved for future use.
- **Bits 4–0 (TOC Count):** Encoded as **count minus 1** (unsigned). A value of `0x00` means 1 TOC entry; `0x1F` means 32 TOC entries. Every response MUST contain at least one TOC entry.

#### Status Code (Bytes 4–7)

A 4-byte little-endian unsigned integer indicating the result of the requested operation. A value of `0x00000000` indicates success. Non-zero values indicate an error or an informational condition. See [Well-Known Status Codes](#well-known-status-codes) for protocol-level codes; additional codes are defined by the application layer.

### Well-Known Status Codes

The following status codes are defined at the protocol level. Application-layer status codes SHOULD use values `0x00010000` and above to avoid collisions with future protocol-level codes.

| Code           | Name                 | Description                                                                 |
|----------------|----------------------|-----------------------------------------------------------------------------|
| `0x00000000`   | Success              | The operation completed successfully.                                        |
| `0x00000001`   | Unsupported Version  | The receiver does not support the protocol version specified in the request. |
| `0x00000002`   | Invalid Opcode       | The opcode is not recognized by the receiver.                                |
| `0x00000003`   | Malformed Request    | The request could not be parsed (e.g., invalid TOC structure, offset/length out of bounds). |
| `0x00000004`   | Internal Error       | The device encountered an unspecified internal error while processing the request. |
| `0x00000005`   | Session Not Found    | The `session_id` in the request does not correspond to an active session.    |
| `0x00000006`   | Key Not Found        | The `key_id` in the request does not correspond to a known key.              |
| `0x00000007`   | Permission Denied    | The operation is not permitted in the current context.                        |
| `0x0000FFFF`   | *(Reserved)*         | Upper bound of the protocol-level status code range.                         |

---

## TOC Entry Format

The Table of Contents (TOC) is the central mechanism for passing structured parameters in requests and returning structured results in responses. Each TOC entry is a **4-byte (32-bit)** structure that is self-describing: the first 6 bits identify the entry type, and the remaining 26 bits carry a type-specific encoding.

This design achieves two goals:

1. **Compactness.** Small values (8-bit or 16-bit integers, session IDs, key IDs) are inlined directly in the TOC entry, requiring no additional space in the variable-length data section.
2. **Flexibility.** Larger or variable-length values (buffers, sealed keys, 32/64-bit integers) are stored in the variable-length data section and referenced by offset and length from the TOC entry.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Entry Type|               Type-Specific Encoding              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Fields

| Offset | Size    | Field                  | Description                                                        |
|--------|---------|------------------------|--------------------------------------------------------------------|
| 0      | 6 bits  | Entry Type             | Unsigned integer (0–63) identifying the type of this TOC entry.    |
| 0.6    | 26 bits | Type-Specific Encoding | Interpretation depends on the Entry Type. See type definitions below. |

### Entry Types

| Type Value | Name       | Encoding   | Description                        |
|------------|------------|------------|------------------------------------|
| 0          | session_id | [Inline 16](#encoding-inline-16-bit)  | Session identifier (2 bytes).      |
| 1          | key_id     | [Inline 16](#encoding-inline-16-bit)  | Key identifier (2 bytes).          |
| 2          | sealed_key | [Offset/Len](#encoding-offsetlength) | Sealed key blob in variable-length data. |
| 3          | uint8      | [Inline 8](#encoding-inline-8-bit)   | 8-bit unsigned integer.            |
| 4          | uint16     | [Inline 16](#encoding-inline-16-bit)  | 16-bit unsigned integer.           |
| 5          | uint32     | [Offset/Len](#encoding-offsetlength) | 32-bit unsigned integer (length MUST be 4). |
| 6          | uint64     | [Offset/Len](#encoding-offsetlength) | 64-bit unsigned integer (length MUST be 8). |
| 7          | buffer     | [Offset/Len](#encoding-offsetlength) | Variable-length byte buffer.       |
| 8          | none       | [Inline None](#encoding-inline-none) | Absent value. Used as a placeholder for optional fields that are not present in this message. |
| 9          | padding    | [Offset/Len](#encoding-offsetlength) | Alignment padding in the variable-length data section. Length is 0 to N−1 bytes where N is the desired alignment. Data bytes SHOULD be zero. Receivers MUST ignore the content of padding entries. |
| 10–63      | —          | —          | Reserved for future use. Receivers MUST ignore TOC entries with unrecognized Entry Type values (see [Protocol Rules](#protocol-rules), rule 6). |

### Encoding: Inline None

Used by: **none**.

Represents an absent or unset value. The entire 26-bit type-specific encoding region is reserved and MUST be zero. This entry type carries no value and does not reference the variable-length data section. It is used as a placeholder for optional fields that are not present in a message, allowing the TOC count to remain fixed regardless of which optional fields are populated.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Entry Type|                  Reserved                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Size    | Field      | Description                                |
|--------|---------|------------|--------------------------------------------|
| 0      | 6 bits  | Entry Type | Type identifier (`0x08` for none).         |
| 0.6    | 26 bits | Reserved   | MUST be `0`.                               |

### Encoding: Inline 8-bit

Used by: **uint8**.

The value is stored directly in the TOC entry. Bits 6–23 are reserved and MUST be zero.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Entry Type|              Reserved             |     Value     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Size    | Field    | Description                                |
|--------|---------|----------|--------------------------------------------|
| 0      | 6 bits  | Entry Type | Type identifier (`0x03` for uint8).      |
| 0.6    | 18 bits | Reserved | MUST be `0`.                               |
| 3      | 8 bits  | Value    | Unsigned 8-bit value.                      |

### Encoding: Inline 16-bit

Used by: **session_id**, **key_id**, **uint16**.

The value is stored directly in the TOC entry. Bits 6–15 are reserved and MUST be zero. The 16-bit value occupies bytes 2–3 of the TOC entry and is encoded in **big-endian** byte order.

> **Note:** This is the one exception to the protocol's little-endian convention. The inline 16-bit value is stored big-endian to preserve natural reading order when inspecting raw bytes.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Entry Type|      Reserved     |             Value             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Size    | Field    | Description                                |
|--------|---------|----------|--------------------------------------------|
| 0      | 6 bits  | Entry Type | Type identifier.                         |
| 0.6    | 10 bits | Reserved | MUST be `0`.                               |
| 2      | 16 bits | Value    | Unsigned 16-bit value (big-endian).        |

### Encoding: Offset/Length

Used by: **sealed_key**, **uint32**, **uint64**, **buffer**.

The data resides in the variable-length data section that follows all TOC entries. The TOC entry stores a 13-bit length and a 13-bit offset, both unsigned.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Entry Type|          Length         |          Offset         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Size    | Field    | Description                                                          |
|--------|---------|----------|----------------------------------------------------------------------|
| 0      | 6 bits  | Entry Type | Type identifier.                                                   |
| 0.6    | 13 bits | Length   | Length in bytes of the data in the variable-length data section (0–8191). |
| 2.3    | 13 bits | Offset   | Byte offset from the start of the variable-length data section (0–8191). |

For fixed-size types the Length field MUST be set as follows. A receiver MUST reject a message where a fixed-size type has an incorrect length (status code `0x00000003`, Malformed Request):

| Type       | Required Length |
|------------|-----------------|
| uint32     | 4               |
| uint64     | 8               |
| sealed_key | Variable        |
| buffer     | Variable        |

A receiver MUST verify that `Offset + Length` does not exceed the actual size of the variable-length data section. If it does, the message MUST be rejected with status code `0x00000003` (Malformed Request).

### Data Alignment

Data in the variable-length data section is **not** required to be aligned to any particular boundary by default. Implementations that operate on architectures requiring aligned memory access MUST perform appropriate byte-level reads (e.g., `memcpy` into an aligned buffer) rather than assuming natural alignment of referenced data.

To support aligned access, a sender MAY insert a `padding` TOC entry (Entry Type `9`) immediately before a data-bearing TOC entry. The padding entry references zero-filled bytes in the variable-length data section whose purpose is to advance the data offset so that the subsequent entry's data begins at a naturally aligned boundary relative to the start of the data section. The padding length is between 0 and N−1 bytes, where N is the desired alignment. A receiver MUST ignore the content of padding entries.

Multiple TOC entries MAY reference overlapping regions of the variable-length data section, though this is NOT RECOMMENDED and the behavior is application-defined.

---

## Protocol Rules

The following rules govern the behavior of all conforming implementations.

### 1. Request-Response Semantics

Every request MUST receive exactly one response. A sender that does not receive a response within the configured timeout period (see rule 5) SHOULD treat the request as failed. The recovery strategy (retry, session teardown, or device reset) is application-defined, but implementations SHOULD document their chosen behavior. A receiver MUST NOT send more than one response per request.

### 2. Ordering and Pipelining

Multiple requests MAY be issued concurrently without waiting for prior responses (pipelining). Responses are **not** guaranteed to arrive in the order the corresponding requests were sent; a receiver MAY process requests in parallel and return responses in any order. Request-response correlation is performed using a command identifier carried by the external transport or framing protocol — this specification does not define a command ID field. Implementations MUST rely on the external protocol's command ID to match each response to its originating request.

### 3. Version Negotiation

A receiver that does not support the protocol version specified in the request MUST respond with:

- **Version:** the version from the request (echoed back, so the sender can correlate the response).
- **Status Code:** `0x00000001` (Unsupported Version).
- **TOC:** a single `uint8` entry (Entry Type `3`) whose value is the highest protocol version the receiver supports.

This allows the sender to retry with a mutually supported version.

### 4. Maximum TOC Entries

A message MUST contain between 1 and 32 TOC entries (inclusive). This constraint is enforced by the 5-bit TOC Count field, which encodes the count as `count minus 1` (range `0x00`–`0x1F`).

### 5. Timeouts

Implementations SHOULD enforce a configurable idle timeout to detect unresponsive peers. The RECOMMENDED default timeout is **5 seconds**. When a timeout fires, the sender SHOULD consider the outstanding request as failed and MAY initiate error recovery. Implementations MUST document their timeout behavior.

### 6. Unknown TOC Entry Types

A receiver MUST silently ignore TOC entries whose Entry Type value is not recognized. This ensures forward compatibility: a sender using a newer version of the application-layer TOC catalog can communicate with an older receiver, provided the older receiver can still process the entries it understands. The ignored entries' data regions (if any) in the variable-length section MAY be skipped without parsing.

### 7. Maximum Message Size

The maximum total size of a single message (header + TOC entries + variable-length data) is **8323 bytes** for a request and **8327 bytes** for a response. These limits are derived from the 32-entry TOC maximum and the 13-bit offset/length fields (maximum addressable data = 8191 bytes). Implementations MUST reject messages that exceed these limits.

### 8. Malformed Message Handling

A receiver that cannot parse a request (e.g., the TOC Count implies more TOC entries than the message contains, an Offset/Length pair references data beyond the message boundary, or a fixed-size type has an incorrect length) MUST respond with status code `0x00000003` (Malformed Request). The receiver MUST NOT partially process a malformed request.

### 9. Reserved Fields

All reserved fields and reserved bits MUST be set to zero by the sender. A receiver MUST ignore the values of reserved fields and MUST NOT reject a message solely because a reserved field is non-zero. This allows future protocol extensions to use these fields without breaking existing receivers.

---

## Schema Features

The following features describe conventions for structured message schemas built on top of the wire format. These are implemented by the `azihsm_tbor_derive` macro but are not required by the protocol itself.

### Optional Fields

A schema field may be declared optional. When an optional field is absent from a message, its TOC slot contains a `none` entry (Entry Type `8`). The TOC count remains fixed regardless of which optional fields are present, allowing deterministic message layout.

### Alignment Padding

A schema field may request alignment to a power-of-two boundary within the variable-length data section. When alignment is specified, a `padding` TOC entry (Entry Type `9`) is inserted immediately before the field's TOC entry. The padding entry references zero-filled bytes that advance the data offset to the requested alignment boundary. Padding entries are always present (even with zero length) to maintain a fixed TOC count.

Alignment is requested **explicitly** via a fixed power-of-two boundary annotation on the field. Typed-slice fields (see [Typed Slices](#typed-slices)) are **not** auto-aligned: their element type is required to be `Unaligned` (alignment 1), so the borrow is sound at any offset and no padding entry is inserted.

### Typed Slices

A variable-length `buffer` field may be declared as a typed slice `&[T]` (where `T` is a `#[repr(C)]` POD with no padding) instead of a raw `&[u8]`. The wire encoding is identical — raw little-endian bytes whose length is a multiple of `size_of::<T>()` — but the generated decoder borrows the bytes directly as `&[T]` (zero-copy) and the encoder accepts `&[T]`. `T` MUST be `Unaligned` (alignment 1) — use little-endian wire integer types (e.g. `tbor_int::U16`/`U32`/`U64`) rather than native `u16`/`u32`/`u64` — so the borrow is sound at any data-section offset with no alignment padding; a length that is not a whole number of elements yields an empty slice rather than a panic.

### Fixed-Size Arrays

A schema field declared as `[u8; N]` is encoded as a `buffer` TOC entry (Entry Type `7`) with a fixed length of exactly N bytes. The encoder and decoder validate that the buffer length matches N.

### Length Constraints

Variable-length buffer and sealed_key fields may specify minimum and maximum length constraints. The encoder validates constraints at write time and the decoder validates at parse time.

### Field Groups

Schema fields may be grouped into reusable field group types. A field group contributes its fields to the enclosing message's TOC layout without introducing any additional TOC entries of its own. Groups may be nested. An optional group (where the group type is wrapped in `Option`) emits `none` entries for all group field positions when absent.

### Dispatch Traits

Each request schema type exposes its opcode as an associated constant (`OPCODE`), enabling opcode-based dispatch without hardcoding opcode values in match arms.

---

## Security Considerations

The following security considerations apply to implementations of this protocol.

### FIPS_APPROVED Flag

The `FIPS_APPROVED` flag in the response header (bit 0 of the Flags byte) indicates whether the device used FIPS 140-2/140-3 approved cryptographic algorithms to process the request. This flag is **informational only**. Host software that requires FIPS compliance MUST independently verify the device's FIPS certification status through out-of-band means (e.g., hardware attestation, certificate chain validation) and MUST NOT rely solely on this flag for compliance decisions.

### Sealed Key Handling

The `sealed_key` TOC entry type carries opaque, device-sealed key material. Intermediaries and host software MUST treat sealed key blobs as opaque byte sequences and MUST NOT attempt to parse, modify, or interpret their contents. Sealed keys SHOULD be stored in secure, access-controlled memory when held by the host.

### Input Validation

Implementations MUST perform thorough bounds-checking on all incoming messages:

- Verify that `Offset + Length` for every Offset/Length TOC entry falls within the actual variable-length data section.
- Verify that the total message size is consistent with the TOC Count and the referenced data regions.
- Reject messages that fail validation with status code `0x00000003` (Malformed Request) and do not process them further.

Failure to validate inputs can lead to buffer over-reads or other memory safety vulnerabilities, which are especially critical in device driver contexts.

### Transport Security

This protocol does not define encryption or authentication at the wire level. If the transport channel is not physically secured (e.g., communication over a shared bus), implementations SHOULD layer appropriate transport security (encryption, message authentication) beneath this protocol.

---

## Worked Examples

The following examples demonstrate how requests and responses are encoded on the wire. All values are shown in hexadecimal. Byte offsets are zero-indexed from the start of the message.

### Example 1 — Simple Request

A request with protocol version 1, opcode `0x0A`, containing two TOC entries:

1. A `session_id` (Entry Type 0, Inline 16-bit) with value `0x002B` (session 43).
2. A `buffer` (Entry Type 7, Offset/Length) containing 5 bytes of payload data: `48 65 6C 6C 6F` (ASCII "Hello").

#### Field Breakdown

| Byte Offset | Hex Value | Field             | Explanation                                                   |
|-------------|-----------|-------------------|---------------------------------------------------------------|
| 0           | `01`      | Version           | Protocol version 1.                                           |
| 1           | `00`      | Reserved          | Must be zero.                                                 |
| 2           | `01`      | Rsv(3) + TOC Count(5) | Reserved bits = `000`, TOC Count = `00001` (count minus 1 = 1, so 2 entries). |
| 3           | `0A`      | Opcode            | Application-defined opcode `0x0A`.                            |
| 4–7         | `00 00 00 2B` | TOC Entry 1    | Entry Type = `000000` (0 = session_id), Reserved = `0000000000`, Value = `0x002B`. |
| 8–11        | `1C 0A 00 00` | TOC Entry 2    | Entry Type = `000111` (7 = buffer), Length = `0000000000101` (5), Offset = `0000000000000` (0). |
| 12–16       | `48 65 6C 6C 6F` | Variable data | The 5-byte buffer payload: "Hello".                          |

**Total message size:** 17 bytes.

#### Hex Dump

```
Offset  Bytes
 0000   01 00 01 0A
 0004   00 00 00 2B
 0008   1C 0A 00 00
 000C   48 65 6C 6C 6F
```

#### Decoding the TOC Entries

**TOC Entry 1** (`00 00 00 2B` as a 32-bit little-endian value = `0x2B000000`):
- Bits 31–26: `000000` = Entry Type 0 (`session_id`)
- Bits 25–16: `0000000000` = Reserved (all zeros)
- Bits 15–0: `0x002B` = Value 43 (big-endian inline 16-bit)

**TOC Entry 2** (`1C 0A 00 00` as a 32-bit little-endian value = `0x00000A1C`):
- Bits 31–26: `000111` = Entry Type 7 (`buffer`)
- Bits 25–13: `0000000000101` = Length 5
- Bits 12–0: `0000000000000` = Offset 0

### Example 2 — Simple Response

A response to the above request, indicating success with the FIPS_APPROVED flag set, returning a single `buffer` TOC entry containing 3 bytes of output data: `4F 4B 21` (ASCII "OK!").

#### Field Breakdown

| Byte Offset | Hex Value      | Field                | Explanation                                                     |
|-------------|----------------|----------------------|-----------------------------------------------------------------|
| 0           | `01`           | Version              | Protocol version 1 (matches the request).                       |
| 1           | `01`           | Flags                | Bit 0 (FIPS_APPROVED) = 1; bits 1–7 = 0.                       |
| 2           | `00`           | Reserved             | Must be zero.                                                   |
| 3           | `00`           | Rsv(3) + TOC Count(5)| Reserved bits = `000`, TOC Count = `00000` (count minus 1 = 0, so 1 entry). |
| 4–7         | `00 00 00 00`  | Status Code          | `0x00000000` = Success.                                         |
| 8–11        | `1C 06 00 00`  | TOC Entry 1          | Entry Type = `000111` (7 = buffer), Length = `0000000000011` (3), Offset = `0000000000000` (0). |
| 12–14       | `4F 4B 21`     | Variable data        | The 3-byte buffer payload: "OK!".                               |

**Total message size:** 15 bytes.

#### Hex Dump

```
Offset  Bytes
 0000   01 01 00 00
 0004   00 00 00 00
 0008   1C 06 00 00
 000C   4F 4B 21
```

#### Decoding the TOC Entry

**TOC Entry 1** (`1C 06 00 00` as a 32-bit little-endian value = `0x0000061C`):
- Bits 31–26: `000111` = Entry Type 7 (`buffer`)
- Bits 25–13: `0000000000011` = Length 3
- Bits 12–0: `0000000000000` = Offset 0

### Example 3 — Request with Optional Field

A request with opcode `0x20`, a required `uint8` field (value 5), an absent optional `uint16` field, and a present optional `uint8` field (value 42).

**TOC layout:** 3 entries (required uint8, none, optional uint8).

| Offset | Bytes | Description |
|--------|-------|-------------|
| 0–3    | `01 00 02 20` | Header: v1, reserved, 3 entries, opcode 0x20 |
| 4–7    | `0C 00 00 05` | TOC[0]: uint8, value = 5 |
| 8–11   | `20 00 00 00` | TOC[1]: none (absent optional field) |
| 12–15  | `0C 00 00 2A` | TOC[2]: uint8, value = 42 |

Total message: 16 bytes, no variable-length data section.

---

## Revision History

| Version | Date       | Summary                                                                                       |
|---------|------------|-----------------------------------------------------------------------------------------------|
| 0.1     | —          | Initial draft. Defined core request/response framing, TOC structure, and basic entry types.    |
| 0.2     | —          | Added well-known status codes, security considerations, data alignment rules, and worked examples. Expanded protocol rules (pipelining, unknown TOC types, malformed message handling, maximum message size). Clarified endianness convention and FIPS_APPROVED flag semantics. |
| 0.3     | —          | Added Entry Type 8 (`none`) for optional fields. Added Entry Type 9 (`padding`) for data alignment. Added Schema Features section describing optional fields, alignment, fixed arrays, length constraints, field groups, and dispatch traits. |
