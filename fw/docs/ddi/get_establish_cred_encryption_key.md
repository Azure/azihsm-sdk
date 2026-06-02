# GetEstablishCredEncryptionKey (Opcode 1101)

**Handler:** `fw/core/lib/src/ddi/get_establish_cred_encryption_key.rs`
**Session:** NoSession

## Description

Returns the establish-credential encryption public key, a partition nonce, and an ECDSA P-384 signature over the public key (signed with the partition identity private key). The host uses this public key to encrypt credentials during the `EstablishCredential` flow.

## Request

```rust
pub struct DdiGetEstablishCredEncryptionKeyReq {}    // Empty body
```

## Response

```rust
pub struct DdiGetEstablishCredEncryptionKeyResp<'a> {
    #[ddi(id = 1, frame)]
    pub pub_key: DdiPublicKey<'a>,        // Raw P-384 public key (x∥y) + key kind
    #[ddi(id = 2, len = 32)]
    pub nonce: &'a [u8],                   // 32-byte random nonce
    #[ddi(id = 3, max_len = 192)]
    pub pub_key_signature: &'a [u8],       // ECDSA P-384 signature (r∥s, 96 bytes)
}
```

Where `DdiPublicKey` is:
```rust
pub struct DdiPublicKey<'a> {
    pub raw: &'a [u8],              // Raw key bytes (x∥y coordinates)
    pub key_kind: DdiKeyType,       // Ecc384Public
}
```

## Handler Flow

```
1. Validate: establish-cred key exists (not consumed)
2. Query sizes via PAL (None calls)
3. Encode frame: pub_key (nested via #[ddi(frame)]), nonce, signature — all reserved
4. Fill pub_key.raw in-place from PAL
5. Fill nonce in-place from PAL
6. Hash pub_key.raw with SHA-384 (into fmem)
7. Sign hash with partition identity key → directly into signature slot
```

## Encoding Pattern

**Nested frame-then-fill** — uses `#[ddi(frame)]` on the `pub_key` field so that `DdiPublicKey`'s `raw` bytes get a reserved slot via `MborFrameable`. All three variable fields (pub key, nonce, signature) are filled directly into encoder-reserved slots — fully zero-copy. The SHA-384 digest is stored in `fmem` to minimize async future size.

## Signature Details

| Property | Value |
|----------|-------|
| Algorithm | ECDSA P-384 |
| Hash | SHA-384 |
| Signed data | `pub_key.raw` (96-byte x∥y coordinates) |
| Signing key | Partition identity private key (from vault) |
| Signature format | Raw r∥s (96 bytes) |

The signature allows the host to verify the public key's authenticity by checking it against the partition's leaf certificate (cert index 3), which contains the identity public key.

## Verification (E2E)

To verify the returned signature:

1. Retrieve the partition leaf cert via `GetCertChainInfo` + `GetCertificate(slot=0, idx=3)`
2. Extract the public key from the leaf cert
3. Compute `SHA-384(pub_key.raw)`
4. Verify the ECDSA signature using the leaf cert's public key

## One-Time-Use Pattern

The establish-credential encryption key is generated at `part_enable` and cleared after `EstablishCredential` completes. Calling `GetEstablishCredEncryptionKey` after the key has been consumed returns `KeyNotFound`.

## Idempotency

Before consumption, repeated calls return the same public key and nonce. The signature may differ (ECDSA is non-deterministic) but will always verify against the same public key.

## Errors

| Error | Cause |
|-------|-------|
| `KeyNotFound` | Establish-cred key already consumed by `EstablishCredential` |
| `InvalidArg` | Partition not in `Enabled` state |
| `InternalError` | Identity key missing from vault |
