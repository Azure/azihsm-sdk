# Security Domain API

The security-domain (SD) API opens a session to a partition and provisions
its security domain. A security-domain session (opened with
[`azihsm_sess_ex_open`](#azihsm_sess_ex_open)) is required to issue the
provisioning command in this chapter.

## azihsm_sess_ex_open

Open a security-domain session to the device.

The session uses the API revision that was selected when the partition was
opened with [`azihsm_part_open`](#azihsm_part_open). The `session_type`
selects the channel integrity profile pinned for the session (see
[azihsm_session_ex_type](#azihsm_session_ex_type)), and a handle to the new
session is returned.

```cpp
azihsm_status azihsm_sess_ex_open(
    azihsm_handle dev_handle,
    azihsm_session_ex_type session_type,
    azihsm_handle *sess_handle
    );
```

**Parameters**

 | Parameter         | Name                                                | Description                                    |
 | ----------------- | --------------------------------------------------- | ---------------------------------------------- |
 | [in] dev_handle   | [azihsm_handle](#azihsm_handle)                     | partition handle                               |
 | [in] session_type | [azihsm_session_ex_type](#azihsm_session_ex_type)   | channel integrity profile to pin               |
 | [out] sess_handle | [azihsm_handle *](#azihsm_handle)                   | new security-domain session handle      &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

## azihsm_sess_ex_part_init

Provision a partition's security domain over a security-domain session.

Initializes the partition from the caller-supplied machine seed
(`mach_seed`) and unified partition policy (`part_policy`), together with
the partition-owner (`pota_thumbprint`), security-administrator
(`sata_thumbprint`), and optional secondary-owner (`sapota_thumbprint`)
trust-anchor thumbprints. On success it returns the partition's
certificate-signing request (`pta_csr`) and attestation report
(`pta_report`).

The provisioning inputs are grouped into an
[`azihsm_sess_ex_part_init_params`](#azihsm_sess_ex_part_init_params)
structure. `pta_csr` and `pta_report` are caller-provided output buffers:
on input `len` is the buffer capacity; on success `len` is set to the
number of bytes written. Because provisioning is a one-shot operation, an
undersized buffer (or a NULL `ptr` with `len == 0`) is rejected with
`AZIHSM_STATUS_BUFFER_TOO_SMALL` and `len` set to the maximum possible
output size **before** the partition is provisioned. The buffer is
validated up-front against a fixed upper bound, so the probe reports that
bound rather than the exact size for the current device — callers should
expect to allocate up to that maximum. The standard two-call size probe
(call once with a zero-length buffer to learn the required capacity, then
retry with a buffer of at least that size) is therefore safe for this
command. A NULL `ptr` with a non-zero `len` is rejected with
`AZIHSM_STATUS_INVALID_ARGUMENT`.

```cpp
azihsm_status azihsm_sess_ex_part_init(
    azihsm_handle sess_handle,
    const struct azihsm_sess_ex_part_init_params *params,
    struct azihsm_buffer *pta_csr,
    struct azihsm_buffer *pta_report
    );
```

**Parameters**

 | Parameter            | Name                                                                  | Description                                     |
 | -------------------- | --------------------------------------------------------------------- | ----------------------------------------------- |
 | [in] sess_handle     | [azihsm_handle](#azihsm_handle)                                       | security-domain session handle                  |
 | [in] params          | [azihsm_sess_ex_part_init_params*](#azihsm_sess_ex_part_init_params)   | provisioning input buffers                      |
 | [in, out] pta_csr    | [azihsm_buffer *](#azihsm_buffer)                                     | output buffer for the DER PKCS#10 CSR           |
 | [in, out] pta_report | [azihsm_buffer *](#azihsm_buffer)                                     | output buffer for the attestation report &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_sess_ex_part_init_params

Provisioning input buffers for
[`azihsm_sess_ex_part_init`](#azihsm_sess_ex_part_init). Each field points
to an [azihsm_buffer](#azihsm_buffer); `sapota_thumbprint` is optional and
may be NULL to omit it.

```cpp
struct azihsm_sess_ex_part_init_params {
    const struct azihsm_buffer *mach_seed;
    const struct azihsm_buffer *part_policy;
    const struct azihsm_buffer *pota_thumbprint;
    const struct azihsm_buffer *sata_thumbprint;
    const struct azihsm_buffer *sapota_thumbprint;
};
```

 | Field             | Name                             | Description                              |
 | ----------------- | -------------------------------- | ---------------------------------------- |
 | mach_seed         | [azihsm_buffer*](#azihsm_buffer) | machine seed plaintext                   |
 | part_policy       | [azihsm_buffer*](#azihsm_buffer) | unified partition policy image           |
 | pota_thumbprint   | [azihsm_buffer*](#azihsm_buffer) | POTA public-key thumbprint               |
 | sata_thumbprint   | [azihsm_buffer*](#azihsm_buffer) | SATA public-key thumbprint               |
 | sapota_thumbprint | [azihsm_buffer*](#azihsm_buffer) | optional SAPOTA thumbprint (may be NULL) |
