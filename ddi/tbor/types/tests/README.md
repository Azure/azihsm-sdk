<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# `azihsm_ddi_tbor_types` integration test suite

A single test binary, [`azihsm_ddi_tbor_tests.rs`](azihsm_ddi_tbor_tests.rs),
exposes two top-level modules:

* [`harness/`](harness/mod.rs) — shared test infrastructure: per-test
  [`TestCtx`](harness/ctx.rs) fixture, [`SessionGuard`](harness/session_guard.rs)
  RAII close, session-establishment + per-command crypto helpers,
  canonical error-shape assertions.
* [`commands/`](commands/mod.rs) — one file (or directory) per TBOR DDI
  command, each grouping happy-path / FW-reject / crypto-reject /
  default-PSK-gate tests.

## Backend feature regimes

Three build modes; see the module doc in
[`harness/mod.rs`](harness/mod.rs) for the full per-feature gating
table.

* `--features emu` — canonical configuration, runs the full suite.
* `--features mock` — transport-contract probes only.
* No backend feature — native OS backend (`nix` on Linux / `win` on
  Windows); hardware-eligible command tests run against real silicon.

For `PartFinal`, emulator tests transport the real PTA certificate chain
through OOB descriptors and exercise full chain validation. Native M1.0
tests send one schema-required placeholder descriptor with no OOB payload
because the current hardware firmware intentionally ignores certificate
descriptors; native certificate-chain validation remains M1.5 work.

The canonical command is:

```bash
cargo test -p azihsm_ddi_tbor_types --tests --features emu
```

## Spec coverage matrix

[`SPEC_COVERAGE.md`](SPEC_COVERAGE.md) maps each TBOR wire-protocol
requirement to the integration test that proves it, plus a short list
of known gaps. Update it alongside any test added, renamed, or
removed; the file's footer documents the maintenance rules.
