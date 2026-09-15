# Vendored `ml-dsa`

`ml-dsa/` is [RustCrypto `ml-dsa` 0.1.1][upstream] (Apache-2.0 OR MIT), vendored
verbatim except for one additive change, kept here as
`keygen-encoded-into.patch`.

[upstream]: https://github.com/RustCrypto/signatures/tree/master/ml-dsa

## Why

Upstream key generation computes the encoded verifying key -- it is the input to
the `tr` hash -- and then discards it. Recovering it afterwards with
`verifying_key()` repeats the entire `A * s1 + s2` product and its
`power2round`, which costs a 54 KiB stack frame on top of the key generation
frame. The crate caches the encoded form only under its `alloc` feature, which
we cannot use on the firmware target.

That is not a micro-optimisation. Measured on CP1 with the 212.9 KiB stack:

| ML-DSA-65 key generation | peak chain |
|--------------------------|-----------|
| upstream (`from_seed` + `verifying_key()`) | 235.5 KiB -- does not fit |
| patched (`keygen_encoded_into`)            | 130.6 KiB |

The patch is what makes on-device key generation possible at ML-DSA-65. It also
brings ML-DSA-87 key generation down from 397.5 KiB to 197.1 KiB, inside the
stack for the first time.

## The change

A single new associated function, `SigningKey::keygen_encoded_into`, plus the
import it needs. 55 lines, purely additive; no existing item is modified, so
upstream behaviour is unchanged.

It writes the encoded signing key through `&mut` and returns the encoded
verifying key that key generation already computed. Writing through `&mut`
matters as much as the reuse: a value that size returned across a call boundary
is materialised twice.

It also serialises the signing key from the components directly rather than
building an `ExpandedSigningKey` and calling `to_expanded`. The encoding is
identical, and it avoids both the intermediate NTT forms and a rustc 1.93 ICE
triggered by calling `to_expanded` from a new generic context.

## Local modifications beyond the patch

- `Cargo.toml` gains an empty `[workspace]` table so cargo treats the crate as
  standalone rather than as a stray member of the surrounding workspace.
- The packaging artifacts `.cargo-ok`, `Cargo.lock` and `Cargo.toml.orig` are
  removed.

## Upgrading

Re-apply `keygen-encoded-into.patch` to the new release, then redo the two local
modifications above. If upstream accepts an equivalent API, drop this directory
and the two `[patch.crates-io]` entries in the root `Cargo.toml` and
`fw/plat/uno/fw/Cargo.toml`.
