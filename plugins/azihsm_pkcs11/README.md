# AZIHSM PKCS#11 module

A standalone **PKCS#11 (Cryptoki) v3.1** module for the AZIHSM. It links the
native C API (`azihsm.h`, generated from `api/native`) the same way
`plugins/ossl_prov` does.

## Status — framework + login + first key-backed slice

Unimplemented PKCS#11 entry points return `CKR_FUNCTION_NOT_SUPPORTED`.
Implemented so far:

- **Library / slots / sessions** — `C_Initialize`, `C_GetInfo`, slot/token/
  mechanism enumeration (real AZIHSM partitions become slots), sessions and the
  login state machine, and the `C_GetInterface` "PKCS 11" interface.
- **`C_Login`** — runs the AZIHSM provisioning ceremony and opens a session.
  Provisioning is done lazily: login opens a session and provisions the
  partition only if the device reports it is not yet provisioned (provisioning
  is one-shot per power cycle; a session is the repeatable per-login primitive).
- **Host objects** — `C_CreateObject` / `C_DestroyObject` / `C_GetAttributeValue`
  / `C_FindObjects*` against an in-memory object store (see the seam below).
- **`C_Digest*` (`CKM_SHA256`)** — a host-side SHA-256 digest (one-shot and
  multi-part); every other digest mechanism returns `CKR_MECHANISM_INVALID`.
- **`C_GenerateKey` (`CKM_AES_KEY_GEN`)** — generates an AES-128/192/256 key on
  the device and stores its **masked blob** (the AZIHSM key's only durable form)
  as the object's key body. Generated keys are always sensitive, unextractable
  and local — a template asking otherwise is rejected (note: OpenSC
  `pkcs11-tool --keygen` needs its `--sensitive` flag for this reason).
- **`C_Encrypt` / `C_Decrypt` one-shot (`CKM_AES_CBC`, `CKM_AES_CBC_PAD`)** —
  each `C_EncryptInit`/`C_DecryptInit` unmasks the stored blob into a fresh
  session-scoped device key that lives exactly as long as the operation.
  Multi-part (`C_EncryptUpdate`…), AES-GCM/XTS and the other key-backed
  mechanisms (RSA/ECDSA, wrap/unwrap, derive) are not implemented yet.

## Layering

| Layer | Files | Responsibility |
|---|---|---|
| C ABI | `azihsm_pkcs11_dispatch.c` | `CK_FUNCTION_LIST` + `_3_0` + the "PKCS 11" interface |
| Framework | `azihsm_pkcs11_module.c`, `azihsm_pkcs11_slot.c`, `azihsm_pkcs11_session.c` | init, slots, sessions, login, operation state machine |
| Object store | `azihsm_pkcs11_objstore.h`, `azihsm_pkcs11_objstore_mem.c` | host-side objects behind a vtable seam (in-memory now; a persistent backend implements the same ops later) |
| Key operations | `azihsm_pkcs11_crypt.c` | key-backed entry points: template normalisation, operation state, masked-blob store/unmask flow (CK_RV only) |
| HSM binding | `azihsm_pkcs11_hsm.c`, `azihsm_pkcs11_key.c`, `azihsm_pkcs11_status.c`, `azihsm_pkcs11_config.c` | the only code that calls `azihsm_*` and maps `azihsm_status` → `CK_RV` |
| Not implemented | `azihsm_pkcs11_stubs.c` (generated) | everything else → `CKR_FUNCTION_NOT_SUPPORTED` |

The object store is the emulation layer PKCS#11 requires and the device does not
provide (no persistent, attribute-templated, searchable key store). It is fronted
by the `azihsm_pkcs11_objstore` vtable so the in-memory backend can be replaced by a
persistent one without changing any caller.

## Build

```sh
# Against the simulator / mock DDI (no physical device):
cargo build -p azihsm_pkcs11 --features mock
# -> target/debug/azihsm_pkcs11.so

# Standalone (no device linked) framework smoke build:
gcc -shared -fPIC -Iinclude/pkcs11-v3.1 src/*.c -o azihsm_pkcs11.so -lpthread
```

`build.rs` drives CMake, which imports `azihsm_api_native` via Corrosion and
generates `azihsm.h` with cbindgen.

## Configuration

Credentials are read from the environment (`AZIHSM_PKCS11_ID` /
`AZIHSM_PKCS11_PIN`, each 32 hex characters); simulator defaults are used when
unset. `AZIHSM_PKCS11_CONF` is reserved for a configuration file (key-material
paths, slot layout) once persistent objects land. Set `AZIHSM_PKCS11_DEBUG=1`
for stderr tracing.

## Testing

`tests/run_validation.sh` builds the module and drives it with OpenSC
`pkcs11-tool` (interactive smoke). `tests/aes_test.c` is a functional harness
for the AES slice (keygen templates, CBC round trips, the two-call sizing
discipline, operation state machine); it drives the real module ABI via
`dlopen`, so it needs the mock-backed build. The CI workflow
(`.github/workflows/pkcs11.yml`) runs on pushes/PRs to the staging branch.
