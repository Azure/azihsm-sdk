# ShaDigest (Opcode 2006)

**Handler:** `fw/core/lib/src/ddi/sha_digest.rs`
**Session:** NoSession (will move to InSession)

## Description

Computes a cryptographic hash of the input message using the specified SHA algorithm.

## Request

```rust
pub struct DdiShaDigestReq<'a> {
    pub sha_mode: DdiHashAlgorithm,    // Sha1, Sha256, Sha384, Sha512
    pub msg: &'a [u8],                 // Input message
}
```

## Response

```rust
pub struct DdiShaDigestResp<'a> {
    pub digest: &'a [u8],    // Hash output (20/32/48/64 bytes)
}
```

## Encoding Pattern

**Frame-then-fill** — the digest is computed directly into the reserved response slot:

```
1. Map algorithm:  DdiHashAlgorithm → HsmHashAlgo
2. Get digest len: algo.digest_len()
3. Encode frame:   DdiShaDigestResp::frame(encoder, digest_len) → frame
4. Hash in-place:  pal.hash(algo, body.msg, frame.digest)
```

Zero intermediate copies — the SHA engine writes directly into the output buffer.

## Supported Algorithms

| DdiHashAlgorithm | Output Size | FIPS Approved |
|-------------------|------------|---------------|
| Sha1 | 20 bytes | No (for signing) |
| Sha256 | 32 bytes | Yes |
| Sha384 | 48 bytes | Yes |
| Sha512 | 64 bytes | Yes |

## Errors

| Error | Cause |
|-------|-------|
| `InvalidArg` | Unknown `sha_mode` value |
