# AZIHSM PKCS#11 module

A standalone **PKCS#11 (Cryptoki) v3.1** module for the AZIHSM. It links the
native C API (`azihsm.h`, generated from `api/native`) the same way
`plugins/ossl_prov` does.

## Status — framework + login slice

This is the first implementation slice. **Every PKCS#11 entry point returns
`CKR_FUNCTION_NOT_SUPPORTED` except the demo path:**

- **Library / slots / sessions** — `C_Initialize`, `C_GetInfo`, slot/token/
  mechanism enumeration (real AZIHSM partitions become slots), sessions and the
  login state machine, and the `C_GetInterface` "PKCS 11" interface.
- **`C_Login`** — runs the AZIHSM provisioning ceremony and opens a session.
  Provisioning is done lazily: login opens a session and provisions the
  partition only if the device reports it is not yet provisioned (provisioning
  is one-shot per power cycle; a session is the repeatable per-login primitive).
- **Host objects** — `C_CreateObject` / `C_DestroyObject` / `C_GetAttributeValue`
  / `C_FindObjects*` against an in-memory object store (see the seam below).
- **`C_Digest` (SHA-256)** — a host-side digest, the one demonstrable crypto
  operation. Key-backed mechanisms (AES/RSA/ECDSA, wrap/unwrap, derive) are not
  implemented yet.

## Layering

| Layer | Files | Responsibility |
|---|---|---|
| C ABI | `p11_dispatch.c` | `CK_FUNCTION_LIST` + `_3_0` + the "PKCS 11" interface |
| Framework | `p11_module.c`, `p11_slot.c`, `p11_session.c` | init, slots, sessions, login, operation state machine |
| Object store | `p11_objstore.h`, `p11_objstore_mem.c` | host-side objects behind a vtable seam (in-memory now; a persistent backend implements the same ops later) |
| HSM binding | `p11_hsm.c`, `p11_status.c`, `p11_config.c` | the only code that calls `azihsm_*` and maps `azihsm_status` → `CK_RV` |
| Not implemented | `p11_stubs.c` (generated) | everything else → `CKR_FUNCTION_NOT_SUPPORTED` |

The object store is the emulation layer PKCS#11 requires and the device does not
provide (no persistent, attribute-templated, searchable key store). It is fronted
by the `p11_objstore` vtable so the in-memory backend can be replaced by a
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
`pkcs11-tool` (interactive smoke). The CI workflow (`.github/workflows/pkcs11.yml`) is **manual only**
(`workflow_dispatch`) while the module is still mostly unimplemented.
