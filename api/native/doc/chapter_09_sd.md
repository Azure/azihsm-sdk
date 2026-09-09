# Security Domain API

The security-domain (SD) API opens a session to a partition and provisions
its security domain. A security-domain session (opened with
[`azihsm_sess_ex_open`](#azihsm_sess_ex_open)) is required to issue the
provisioning command in this chapter.

## azihsm_sess_ex_open

Open a security-domain session to the device.

The session uses the API revision that was selected when the partition was
opened with [`azihsm_part_open`](#azihsm_part_open). `psk` must be a non-NULL
pointer to an [`azihsm_session_psk`](#azihsm_session_psk) selecting the role
slot; only its inner `psk` buffer may be NULL, which selects the partition
default PSK for the slot. A NULL `psk` pointer is rejected with
`AZIHSM_STATUS_INVALID_ARGUMENT`. The `session_type` selects the channel
integrity profile pinned for the session (see
[azihsm_session_ex_type](#azihsm_session_ex_type)), and a handle to the new
session is returned.

```cpp
azihsm_status azihsm_sess_ex_open(
    azihsm_handle dev_handle,
    const azihsm_session_psk *psk,
    azihsm_session_ex_type session_type,
    azihsm_handle *sess_handle
    );
```

**Parameters**

 | Parameter         | Name                                                | Description                                    |
 | ----------------- | --------------------------------------------------- | ---------------------------------------------- |
 | [in] dev_handle   | [azihsm_handle](#azihsm_handle)                     | partition handle                               |
 | [in] psk          | const azihsm_session_psk *                          | PSK credential (non-NULL); inner `psk` buffer NULL = default |
 | [in] session_type | [azihsm_session_ex_type](#azihsm_session_ex_type)   | channel integrity profile to pin               |
 | [out] sess_handle | [azihsm_handle *](#azihsm_handle)                   | new security-domain session handle      &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_session_psk

PSK credential for [`azihsm_sess_ex_open`](#azihsm_sess_ex_open): the PSK
slot plus an optional caller-supplied PSK. When the `psk` buffer is NULL,
the partition **default** PSK for the slot is used — required for the first
session, before the default is rotated via
[`azihsm_sess_ex_psk_change`](#azihsm_sess_ex_psk_change). After rotation,
point `psk` at the rotated 32-byte secret.

```cpp
struct azihsm_session_psk {
    uint8_t psk_id;
    const struct azihsm_buffer *psk;
};
```

 | Field  | Name                             | Description                                        |
 | ------ | -------------------------------- | -------------------------------------------------- |
 | psk_id | uint8_t                          | PSK slot: 0 = Crypto Officer, 1 = Crypto User      |
 | psk    | [azihsm_buffer*](#azihsm_buffer) | optional PSK (exactly 32 bytes); NULL = default PSK |

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

## azihsm_sess_ex_part_final

Finalize a partition's security domain over a security-domain session.

Completes provisioning started by
[`azihsm_sess_ex_part_init`](#azihsm_sess_ex_part_init): re-supplies the
unified partition policy and the PTA certificate chain (root to leaf),
optionally restoring a prior `local_mk` backup, and returns the current
`local_mk` backup envelope the firmware produced.

The inputs are grouped into an
[`azihsm_sess_ex_part_final_params`](#azihsm_sess_ex_part_final_params)
structure. `local_mk_backup` is a caller-provided output buffer with the
same capacity/length contract and two-call size-probe behavior as the
`azihsm_sess_ex_part_init` outputs: an undersized buffer (or a NULL `ptr`
with `len == 0`) is rejected with `AZIHSM_STATUS_BUFFER_TOO_SMALL` and
`len` set to the maximum **before** the partition is finalized. A NULL
`ptr` with a non-zero `len` is rejected with
`AZIHSM_STATUS_INVALID_ARGUMENT`.

```cpp
azihsm_status azihsm_sess_ex_part_final(
    azihsm_handle sess_handle,
    const struct azihsm_sess_ex_part_final_params *params,
    struct azihsm_buffer *local_mk_backup
    );
```

**Parameters**

 | Parameter                 | Name                                                                      | Description                                  |
 | ------------------------- | ------------------------------------------------------------------------- | -------------------------------------------- |
 | [in] sess_handle          | [azihsm_handle](#azihsm_handle)                                           | security-domain session handle               |
 | [in] params               | [azihsm_sess_ex_part_final_params*](#azihsm_sess_ex_part_final_params)     | finalization input buffers                   |
 | [in, out] local_mk_backup | [azihsm_buffer *](#azihsm_buffer)                                         | output buffer for the local_mk backup &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_sess_ex_part_final_params

Finalization input buffers for
[`azihsm_sess_ex_part_final`](#azihsm_sess_ex_part_final). `pta_cert_chain`
points to an array of `pta_cert_chain_len` [azihsm_buffer](#azihsm_buffer)s,
each holding one DER-encoded PTA certificate (root to leaf; at most
`MAX_CERTS`). `prev_local_mk_backup` is optional and may be NULL to omit it.

```cpp
struct azihsm_sess_ex_part_final_params {
    const struct azihsm_buffer *part_policy;
    const struct azihsm_buffer *pta_cert_chain;
    uint32_t pta_cert_chain_len;
    const struct azihsm_buffer *prev_local_mk_backup;
};
```

 | Field                | Name                             | Description                                     |
 | -------------------- | -------------------------------- | ----------------------------------------------- |
 | part_policy          | [azihsm_buffer*](#azihsm_buffer) | unified partition policy (must match part_init) |
 | pta_cert_chain       | [azihsm_buffer*](#azihsm_buffer) | array of DER PTA certificates (root to leaf)    |
 | pta_cert_chain_len   | uint32_t                         | number of certificates in the chain             |
 | prev_local_mk_backup | [azihsm_buffer*](#azihsm_buffer) | optional prior local_mk backup (may be NULL)    |

## azihsm_sess_ex_psk_change

Rotate the calling session's own partition PSK.

Replaces the PSK of the slot implied by the session role (CO session → CO,
CU session → CU) with `new_psk`, sealed under the session key. This is
required **once** on a fresh partition to move past the default-PSK gate
before provisioning, and may also be used later to re-rotate. `new_psk`
must be exactly 32 bytes.

```cpp
azihsm_status azihsm_sess_ex_psk_change(
    azihsm_handle sess_handle,
    const struct azihsm_buffer *new_psk
    );
```

**Parameters**

 | Parameter        | Name                              | Description                              |
 | ---------------- | --------------------------------- | ---------------------------------------- |
 | [in] sess_handle | [azihsm_handle](#azihsm_handle)   | security-domain session handle           |
 | [in] new_psk     | [azihsm_buffer *](#azihsm_buffer) | new PSK buffer (exactly 32 bytes) &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

## azihsm_sd_create_remote_backup

Create a new security domain and its remote backup over a security-domain
session.

Creates a security domain under the calling session's partition from the
unified partition policy, using the sender's masked SD-sealing key (from
`azihsm_key_gen`) and the receiver's attestation evidence, and returns the
three backups the firmware produces: the remote partition-owner-key backup
(an HPKE-Auth seal of BKS3, 161 bytes), the local partition-owner-key backup
(180 bytes), and the security-domain masking-key backup (164 bytes).

The inputs are grouped into an
[`azihsm_sd_create_remote_backup_params`](#azihsm_sd_create_remote_backup_params)
structure. All three output buffers follow the two-call size-probe contract:
an undersized buffer (or a NULL `ptr` with `len == 0`) is rejected with
`AZIHSM_STATUS_BUFFER_TOO_SMALL` and `len` set to the required size, and
every output buffer is validated **before** the one-shot domain-creation
command is issued, so a too-small buffer never consumes it. A NULL `params`
pointer is rejected with `AZIHSM_STATUS_INVALID_ARGUMENT`. Creating a domain
is a once-per-partition operation; a second create on an initialized
partition returns `AZIHSM_STATUS_SD_ALREADY_INITIALIZED`.

```cpp
azihsm_status azihsm_sd_create_remote_backup(
    azihsm_handle sess_handle,
    const struct azihsm_sd_create_remote_backup_params *params,
    struct azihsm_buffer *pok_remote_backup,
    struct azihsm_buffer *pok_local_backup,
    struct azihsm_buffer *sd_mk_backup
    );
```

**Parameters**

 | Parameter                   | Name                                                                                                     | Description                                       |
 | --------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
 | [in] sess_handle            | [azihsm_handle](#azihsm_handle)                                                                          | security-domain session handle                    |
 | [in] params                 | [azihsm_sd_create_remote_backup_params*](#azihsm_sd_create_remote_backup_params)         | create-backup input buffers                       |
 | [in, out] pok_remote_backup | [azihsm_buffer *](#azihsm_buffer)                                                                        | output buffer for the remote pok backup (161 B)   |
 | [in, out] pok_local_backup  | [azihsm_buffer *](#azihsm_buffer)                                                                        | output buffer for the local pok backup (180 B)    |
 | [in, out] sd_mk_backup      | [azihsm_buffer *](#azihsm_buffer)                                                                        | output buffer for the sd masking-key backup (164 B) &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_sd_create_remote_backup_params

Input buffers for
[`azihsm_sd_create_remote_backup`](#azihsm_sd_create_remote_backup).

```cpp
struct azihsm_sd_create_remote_backup_params {
    const struct azihsm_buffer *masked_sealing_key;
    const struct azihsm_sd_evidence *receiver_evidence;
    const struct azihsm_buffer *policy;
};
```

 | Field              | Name                                       | Description                                        |
 | ------------------ | ------------------------------------------ | -------------------------------------------------- |
 | masked_sealing_key | [azihsm_buffer*](#azihsm_buffer)           | sender's masked SD-sealing key (180 B)             |
 | receiver_evidence  | [azihsm_sd_evidence*](#azihsm_sd_evidence) | receiver attestation evidence                      |
 | policy             | [azihsm_buffer*](#azihsm_buffer)           | unified partition-policy image (484 B)             |

## azihsm_sd_reseal_remote_backup

Reseal an existing remote backup to a new recipient over a security-domain
session.

HPKE-opens the source remote backup with the receiver's masked SD-sealing
key (authenticated by the source sender in `src_evidence`) and reseals the
recovered backup to the destination receiver (`dest_evidence`), returning the
resealed remote backup (161 bytes).

The inputs are grouped into an
[`azihsm_sd_reseal_remote_backup_params`](#azihsm_sd_reseal_remote_backup_params)
structure. `dst_remote_backup` follows the same two-call size-probe contract
as the create outputs and is validated **before** the reseal is performed. A
NULL `params` pointer is rejected with `AZIHSM_STATUS_INVALID_ARGUMENT`.

```cpp
azihsm_status azihsm_sd_reseal_remote_backup(
    azihsm_handle sess_handle,
    const struct azihsm_sd_reseal_remote_backup_params *params,
    struct azihsm_buffer *dst_remote_backup
    );
```

**Parameters**

 | Parameter                   | Name                                                                                                     | Description                                       |
 | --------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
 | [in] sess_handle            | [azihsm_handle](#azihsm_handle)                                                                          | security-domain session handle                    |
 | [in] params                 | [azihsm_sd_reseal_remote_backup_params*](#azihsm_sd_reseal_remote_backup_params)         | reseal-backup input buffers                       |
 | [in, out] dst_remote_backup | [azihsm_buffer *](#azihsm_buffer)                                                                        | output buffer for the resealed remote backup (161 B) &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_sd_reseal_remote_backup_params

Input buffers for
[`azihsm_sd_reseal_remote_backup`](#azihsm_sd_reseal_remote_backup).

```cpp
struct azihsm_sd_reseal_remote_backup_params {
    const struct azihsm_buffer *masked_sealing_key;
    const struct azihsm_sd_evidence *src_evidence;
    const struct azihsm_sd_evidence *dest_evidence;
    const struct azihsm_buffer *policy;
    const struct azihsm_buffer *src_remote_backup;
};
```

 | Field              | Name                                       | Description                                        |
 | ------------------ | ------------------------------------------ | -------------------------------------------------- |
 | masked_sealing_key | [azihsm_buffer*](#azihsm_buffer)           | receiver's masked SD-sealing key (180 B)           |
 | src_evidence       | [azihsm_sd_evidence*](#azihsm_sd_evidence) | source (sender) attestation evidence               |
 | dest_evidence      | [azihsm_sd_evidence*](#azihsm_sd_evidence) | destination (receiver) attestation evidence        |
 | policy             | [azihsm_buffer*](#azihsm_buffer)           | unified partition-policy image (484 B)             |
 | src_remote_backup  | [azihsm_buffer*](#azihsm_buffer)           | source remote backup to reseal (161 B)             |

## azihsm_sd_restore_remote_backup

Restore a security domain from a remote backup over a security-domain
session.

HPKE-opens the remote backup with the receiver's masked SD-sealing key
(authenticated by the sender in `sender_evidence`), recovers the
security-domain masking key from `prev_sd_mk_backup`, and returns the
refreshed device-local backups: the local partition-owner-key backup
(180 bytes) and the security-domain masking-key backup (164 bytes).

The inputs are grouped into an
[`azihsm_sd_restore_remote_backup_params`](#azihsm_sd_restore_remote_backup_params)
structure. Both output buffers follow the two-call size-probe contract and
are validated **before** the restore is performed. A NULL `params` pointer
is rejected with `AZIHSM_STATUS_INVALID_ARGUMENT`. Restore is a
once-per-partition operation; a restore on an already-initialized partition
returns `AZIHSM_STATUS_SD_ALREADY_INITIALIZED`.

```cpp
azihsm_status azihsm_sd_restore_remote_backup(
    azihsm_handle sess_handle,
    const struct azihsm_sd_restore_remote_backup_params *params,
    struct azihsm_buffer *pok_local_backup,
    struct azihsm_buffer *sd_mk_backup
    );
```

**Parameters**

 | Parameter                  | Name                                                                                                      | Description                                       |
 | -------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
 | [in] sess_handle           | [azihsm_handle](#azihsm_handle)                                                                           | security-domain session handle                    |
 | [in] params                | [azihsm_sd_restore_remote_backup_params*](#azihsm_sd_restore_remote_backup_params)        | restore-backup input buffers                      |
 | [in, out] pok_local_backup | [azihsm_buffer *](#azihsm_buffer)                                                                         | output buffer for the local pok backup (180 B)    |
 | [in, out] sd_mk_backup     | [azihsm_buffer *](#azihsm_buffer)                                                                         | output buffer for the sd masking-key backup (164 B) &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_sd_restore_remote_backup_params

Input buffers for
[`azihsm_sd_restore_remote_backup`](#azihsm_sd_restore_remote_backup).

```cpp
struct azihsm_sd_restore_remote_backup_params {
    const struct azihsm_buffer *masked_sealing_key;
    const struct azihsm_sd_evidence *sender_evidence;
    const struct azihsm_buffer *policy;
    const struct azihsm_buffer *src_remote_backup;
    const struct azihsm_buffer *prev_sd_mk_backup;
};
```

 | Field              | Name                                       | Description                                        |
 | ------------------ | ------------------------------------------ | -------------------------------------------------- |
 | masked_sealing_key | [azihsm_buffer*](#azihsm_buffer)           | receiver's masked SD-sealing key (180 B)           |
 | sender_evidence    | [azihsm_sd_evidence*](#azihsm_sd_evidence) | sender attestation evidence                        |
 | policy             | [azihsm_buffer*](#azihsm_buffer)           | unified partition-policy image (484 B)             |
 | src_remote_backup  | [azihsm_buffer*](#azihsm_buffer)           | remote backup to restore (161 B)                   |
 | prev_sd_mk_backup  | [azihsm_buffer*](#azihsm_buffer)           | previous security-domain masking-key backup (164 B)|

## azihsm_sd_create_peer_backup

Create a peer-transferable backup of a security domain over a
security-domain session.

Recovers BKS3 from `pok_local_backup` and HPKE-Auth-seals it to the
destination peer named by `dst_evidence` (authenticated by the sender's
masked SD-sealing key), returning the peer backup (161 bytes). Peer
cloning is gated by the security domain's `allow_peer_cloning` policy flag.

The inputs are grouped into an
[`azihsm_sd_create_peer_backup_params`](#azihsm_sd_create_peer_backup_params)
structure. The output buffer follows the two-call size-probe contract and
is validated **before** the peer backup is created. A NULL `params` pointer
is rejected with `AZIHSM_STATUS_INVALID_ARGUMENT`.

```cpp
azihsm_status azihsm_sd_create_peer_backup(
    azihsm_handle sess_handle,
    const struct azihsm_sd_create_peer_backup_params *params,
    struct azihsm_buffer *pok_peer_backup
    );
```

**Parameters**

 | Parameter                | Name                                                                                              | Description                                     |
 | ------------------------ | ------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
 | [in] sess_handle         | [azihsm_handle](#azihsm_handle)                                                                   | security-domain session handle                  |
 | [in] params              | [azihsm_sd_create_peer_backup_params*](#azihsm_sd_create_peer_backup_params)      | create-peer-backup input buffers                |
 | [in, out] pok_peer_backup | [azihsm_buffer *](#azihsm_buffer)                                                                | output buffer for the peer backup (161 B) &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_sd_create_peer_backup_params

Input buffers for
[`azihsm_sd_create_peer_backup`](#azihsm_sd_create_peer_backup).

```cpp
struct azihsm_sd_create_peer_backup_params {
    const struct azihsm_buffer *masked_sealing_key;
    const struct azihsm_sd_evidence *dst_evidence;
    const struct azihsm_buffer *policy;
    const struct azihsm_buffer *pok_local_backup;
};
```

 | Field              | Name                                       | Description                                        |
 | ------------------ | ------------------------------------------ | -------------------------------------------------- |
 | masked_sealing_key | [azihsm_buffer*](#azihsm_buffer)           | sender's masked SD-sealing key (180 B)             |
 | dst_evidence       | [azihsm_sd_evidence*](#azihsm_sd_evidence) | destination (peer) attestation evidence            |
 | policy             | [azihsm_buffer*](#azihsm_buffer)           | unified partition-policy image (484 B)             |
 | pok_local_backup   | [azihsm_buffer*](#azihsm_buffer)           | device-local partition-owner-key backup (180 B)    |

## azihsm_sd_restore_peer_backup

Restore a security domain from a peer backup over a security-domain
session.

HPKE-opens the peer backup with the receiver's masked SD-sealing key
(authenticated by the source peer in `src_evidence`), recovers the
security-domain masking key from `prev_sd_mk_backup`, and returns the
refreshed device-local backups: the local partition-owner-key backup
(180 bytes) and the security-domain masking-key backup (164 bytes). Peer
cloning is gated by the security domain's `allow_peer_cloning` policy flag.

The inputs are grouped into an
[`azihsm_sd_restore_peer_backup_params`](#azihsm_sd_restore_peer_backup_params)
structure. Both output buffers follow the two-call size-probe contract and
are validated **before** the restore is performed. A NULL `params` pointer
is rejected with `AZIHSM_STATUS_INVALID_ARGUMENT`. Restore is a
once-per-partition operation; a restore on an already-initialized partition
returns `AZIHSM_STATUS_SD_ALREADY_INITIALIZED`.

```cpp
azihsm_status azihsm_sd_restore_peer_backup(
    azihsm_handle sess_handle,
    const struct azihsm_sd_restore_peer_backup_params *params,
    struct azihsm_buffer *pok_local_backup,
    struct azihsm_buffer *sd_mk_backup
    );
```

**Parameters**

 | Parameter                  | Name                                                                                                  | Description                                       |
 | -------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
 | [in] sess_handle           | [azihsm_handle](#azihsm_handle)                                                                       | security-domain session handle                    |
 | [in] params                | [azihsm_sd_restore_peer_backup_params*](#azihsm_sd_restore_peer_backup_params)        | restore-backup input buffers                      |
 | [in, out] pok_local_backup | [azihsm_buffer *](#azihsm_buffer)                                                                     | output buffer for the local pok backup (180 B)    |
 | [in, out] sd_mk_backup     | [azihsm_buffer *](#azihsm_buffer)                                                                     | output buffer for the sd masking-key backup (164 B) &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_sd_restore_peer_backup_params

Input buffers for
[`azihsm_sd_restore_peer_backup`](#azihsm_sd_restore_peer_backup).

```cpp
struct azihsm_sd_restore_peer_backup_params {
    const struct azihsm_buffer *masked_sealing_key;
    const struct azihsm_sd_evidence *src_evidence;
    const struct azihsm_buffer *policy;
    const struct azihsm_buffer *pok_peer_backup;
    const struct azihsm_buffer *prev_sd_mk_backup;
};
```

 | Field              | Name                                       | Description                                        |
 | ------------------ | ------------------------------------------ | -------------------------------------------------- |
 | masked_sealing_key | [azihsm_buffer*](#azihsm_buffer)           | receiver's masked SD-sealing key (180 B)           |
 | src_evidence       | [azihsm_sd_evidence*](#azihsm_sd_evidence) | source (peer) attestation evidence                 |
 | policy             | [azihsm_buffer*](#azihsm_buffer)           | unified partition-policy image (484 B)             |
 | pok_peer_backup    | [azihsm_buffer*](#azihsm_buffer)           | peer backup to restore (161 B)                     |
 | prev_sd_mk_backup  | [azihsm_buffer*](#azihsm_buffer)           | previous security-domain masking-key backup (164 B)|

## azihsm_sd_restore_local_backup

Restore a security domain from its device-local backups over a
security-domain session.

Restores the security domain from the device-local partition-owner-key
backup and security-domain masking-key backup, returning the refreshed
device-local backups: the local partition-owner-key backup (180 bytes) and
the security-domain masking-key backup (164 bytes). Unlike the remote/peer
restores, this carries no attestation evidence — the backups are masked
under the device-local key.

The inputs are grouped into an
[`azihsm_sd_restore_local_backup_params`](#azihsm_sd_restore_local_backup_params)
structure. Both output buffers follow the two-call size-probe contract and
are validated **before** the restore is performed. A NULL `params` pointer
is rejected with `AZIHSM_STATUS_INVALID_ARGUMENT`. Restore is a
once-per-partition operation; a restore on an already-initialized partition
returns `AZIHSM_STATUS_SD_ALREADY_INITIALIZED`.

```cpp
azihsm_status azihsm_sd_restore_local_backup(
    azihsm_handle sess_handle,
    const struct azihsm_sd_restore_local_backup_params *params,
    struct azihsm_buffer *pok_local_backup,
    struct azihsm_buffer *sd_mk_backup
    );
```

**Parameters**

 | Parameter                  | Name                                                                                                    | Description                                       |
 | -------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
 | [in] sess_handle           | [azihsm_handle](#azihsm_handle)                                                                         | security-domain session handle                    |
 | [in] params                | [azihsm_sd_restore_local_backup_params*](#azihsm_sd_restore_local_backup_params)        | restore-backup input buffers                      |
 | [in, out] pok_local_backup | [azihsm_buffer *](#azihsm_buffer)                                                                       | output buffer for the local pok backup (180 B)    |
 | [in, out] sd_mk_backup     | [azihsm_buffer *](#azihsm_buffer)                                                                       | output buffer for the sd masking-key backup (164 B) &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_sd_restore_local_backup_params

Input buffers for
[`azihsm_sd_restore_local_backup`](#azihsm_sd_restore_local_backup).

```cpp
struct azihsm_sd_restore_local_backup_params {
    const struct azihsm_buffer *pok_local_backup;
    const struct azihsm_buffer *sd_mk_backup;
};
```

 | Field             | Name                             | Description                                        |
 | ----------------- | -------------------------------- | -------------------------------------------------- |
 | pok_local_backup  | [azihsm_buffer*](#azihsm_buffer) | device-local partition-owner-key backup (180 B)    |
 | sd_mk_backup      | [azihsm_buffer*](#azihsm_buffer) | security-domain masking-key backup (164 B)         |

### azihsm_sd_evidence

Attestation evidence for one security-domain-backup party: three certificate
chains (manufacturer, owner, partition-owner) and a COSE_Sign1 attestation
report. The DER bytes are borrowed, not copied, and must outlive the call.

```cpp
struct azihsm_sd_evidence {
    struct azihsm_sd_cert_chain mfgr_cert_chain;
    struct azihsm_sd_cert_chain owner_cert_chain;
    struct azihsm_sd_cert_chain part_owner_cert_chain;
    const struct azihsm_buffer *report;
};
```

 | Field                 | Name                                         | Description                                  |
 | --------------------- | -------------------------------------------- | -------------------------------------------- |
 | mfgr_cert_chain       | [azihsm_sd_cert_chain](#azihsm_sd_cert_chain) | manufacturer certificate chain               |
 | owner_cert_chain      | [azihsm_sd_cert_chain](#azihsm_sd_cert_chain) | owner certificate chain                      |
 | part_owner_cert_chain | [azihsm_sd_cert_chain](#azihsm_sd_cert_chain) | partition-owner certificate chain            |
 | report                | [azihsm_buffer*](#azihsm_buffer)             | COSE_Sign1 attestation report                |

### azihsm_sd_cert_chain

One certificate chain in an SD attestation-evidence party: an array of `len`
[azihsm_buffer](#azihsm_buffer)s, each holding one DER-encoded certificate
ordered root to leaf (at most `EVIDENCE_CHAIN_MAX_CERTS`).

```cpp
struct azihsm_sd_cert_chain {
    const struct azihsm_buffer *certs;
    uint32_t len;
};
```

 | Field | Name                             | Description                                   |
 | ----- | -------------------------------- | --------------------------------------------- |
 | certs | [azihsm_buffer*](#azihsm_buffer) | array of DER certificates (root to leaf)      |
 | len   | uint32_t                         | number of certificates in the chain           |
