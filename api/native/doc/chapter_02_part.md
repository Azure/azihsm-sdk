# Partition API

## azihsm_part_get_list

Allocates and returns the device list.

```cpp
azihsm_status azihsm_part_get_list(
    azihsm_handle *handle
    );
```

**Parameters**

| Parameter    | Name                              | Description                               |
| :----------- | --------------------------------- | ----------------------------------------- |
| [out] handle | [azihsm_handle *](#azihsm_handle) | device list handle                 &nbsp; |

**Returns**

 `AZIHSM_STATUS_SUCCESS` on success, error code otherwise

## azihsm_part_free_list

Releases the memory allocated for device list 

```cpp
azihsm_status azihsm_part_free_list(
    azihsm_handle handle
    );
```

**Parameters**

| Parameter   | Name                            | Description                                   |
| :---------- | ------------------------------- | --------------------------------------------- |
| [in] handle | [azihsm_handle](#azihsm_handle) | handle to free                         &nbsp; |

**Returns**

 `AZIHSM_STATUS_SUCCESS` on success, error code otherwise

## azihsm_part_get_count

Get the count of the devices in the list

```cpp
azihsm_u32 azihsm_part_get_count(
    azihsm_handle handle
    );
```

**Parameters**

| Parameter   | Name                            | Description                                   |
| :---------- | ------------------------------- | --------------------------------------------- |
| [in] handle | [azihsm_handle](#azihsm_handle) | device list handle                     &nbsp; |

**Returns**

 Device count on success, 0 on failure or empty list

## azihsm_part_get_info

Retrieves partition information at the given index, including the OS device path
and the supported API revision range.

```cpp
azihsm_status azihsm_part_get_info(
    azihsm_handle handle,
    azihsm_u32 index,
    struct azihsm_part_info *part_info
    );
```

**Parameters**

 | Parameter           | Name                                            | Description                               |
 | ------------------- | ----------------------------------------------- | ----------------------------------------- |
 | [in] handle         | [azihsm_handle](#azihsm_handle)                 | device list handle                        |
 | [in] index          | [azihsm_u32](#azihsm_u32)                       | index of the partition in list            |
 | [in, out] part_info | [struct azihsm_part_info *](#azihsm_part_info)  | partition info structure           &nbsp; |

On input, `part_info.path.len` is the capacity of the buffer pointed to by `part_info.path.str`,
expressed as a count of `azihsm_char` elements (including the null terminator).
On output, `part_info.path.len` is set to the required/written count of `azihsm_char` elements.
`part_info.api_rev_min` and `part_info.api_rev_max` are only valid when the
return status is `AZIHSM_STATUS_SUCCESS`.

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, `AZIHSM_STATUS_BUFFER_TOO_SMALL` if the path buffer is too
small (with `part_info.path.len` updated to the required count of elements), or a negative error code on failure

## azihsm_part_open

Open a handle to the partition with a specified API revision.

The caller selects an API revision within the range reported by
[`azihsm_part_get_info`](#azihsm_part_get_info). All subsequent operations on
this partition handle (including sessions opened from it) will use the
selected revision.

```cpp
azihsm_status azihsm_part_open(
    const struct azihsm_str *path,
    azihsm_handle *handle,
    struct azihsm_api_rev api_rev
    );

```

**Parameters**

 | Parameter    | Name                                     | Description                                          |
 | ------------ | ---------------------------------------- | ---------------------------------------------------- |
 | [in] path    | [const struct azihsm_str*](#azihsm_str)  | OS device path                                       |
 | [out] handle | [azihsm_handle *](#azihsm_handle)        | device handle                                        |
 | [in] api_rev | [struct azihsm_api_rev](#azihsm_api_rev) | API revision to use for this partition handle &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, `AZIHSM_STATUS_UNSUPPORTED_API_REVISION` if
`api_rev` is outside the partition's supported range, or a negative error code otherwise

## azihsm_owner_backup_key_config

Configuration for owner backup key (OBK) selection during partition initialization.

```cpp
struct azihsm_owner_backup_key_config {
    azihsm_owner_backup_key_source source;
    const struct azihsm_buffer *owner_backup_key;
};
```

**Fields**

| Field             | Type                                                  | Description |
| ----------------- | ----------------------------------------------------- | ----------- |
| source            | [azihsm_owner_backup_key_source](#azihsm_owner_backup_key_source) | OBK source selection |
| owner_backup_key  | [struct azihsm_buffer*](#azihsm_buffer)               | Optional OBK buffer; required when `source` is `AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER`, must be NULL otherwise |

## azihsm_owner_backup_key_source

Specifies the source of the owner backup key (OBK).

```cpp
typedef enum azihsm_owner_backup_key_source {
    AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER = 1,
    AZIHSM_OWNER_BACKUP_KEY_SOURCE_TPM    = 2,
} azihsm_owner_backup_key_source;
```

**Notes**
- When `source` is `AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER`, `owner_backup_key` must be non-NULL and non-empty.
- When `source` is `AZIHSM_OWNER_BACKUP_KEY_SOURCE_TPM`, `owner_backup_key` must be NULL.

## azihsm_pota_endorsement

Configuration for partition owner trust anchor (POTA) endorsement during partition initialization.

```cpp
struct azihsm_pota_endorsement {
    azihsm_pota_endorsement_source source;
    const struct azihsm_pota_endorsement_data *endorsement;
};
```

**Fields**

| Field       | Type                                                                         | Description |
| ----------- | ---------------------------------------------------------------------------- | ----------- |
| source      | [azihsm_pota_endorsement_source](#azihsm_pota_endorsement_source)           | POTA endorsement source selection |
| endorsement | [struct azihsm_pota_endorsement_data*](#azihsm_pota_endorsement_data)       | Endorsement data; required when `source` is `AZIHSM_POTA_ENDORSEMENT_SOURCE_CALLER`, must be NULL otherwise |

## azihsm_pota_endorsement_data

Caller-provided POTA endorsement data containing a signature and the corresponding public key.

```cpp
struct azihsm_pota_endorsement_data {
    const struct azihsm_buffer *signature;
    const struct azihsm_buffer *public_key;
};
```

**Fields**

| Field      | Type                                    | Description |
| ---------- | --------------------------------------- | ----------- |
| signature  | [struct azihsm_buffer*](#azihsm_buffer) | Pointer to the signature buffer (must be non-NULL and non-empty) |
| public_key | [struct azihsm_buffer*](#azihsm_buffer) | Pointer to the public key buffer (must be non-NULL and non-empty) |

## azihsm_pota_endorsement_source

Specifies the source of the POTA endorsement.

```cpp
typedef enum azihsm_pota_endorsement_source {
    AZIHSM_POTA_ENDORSEMENT_SOURCE_CALLER = 1,
    AZIHSM_POTA_ENDORSEMENT_SOURCE_TPM    = 2,
} azihsm_pota_endorsement_source;
```

**Notes**
- When `source` is `AZIHSM_POTA_ENDORSEMENT_SOURCE_CALLER`, `endorsement` must be non-NULL with non-empty `signature` and `public_key` buffers.
- When `source` is `AZIHSM_POTA_ENDORSEMENT_SOURCE_TPM`, `endorsement` must be NULL.
- Any other `source` value returns `AZIHSM_STATUS_INVALID_ARGUMENT`.

## azihsm_part_init

Initialize a partition with credentials

```cpp
azihsm_status azihsm_part_init(
    azihsm_handle handle,
    const struct azihsm_credentials *creds,
    const struct azihsm_buffer *bmk,
    const struct azihsm_buffer *muk,
    const struct azihsm_owner_backup_key_config *backup_key_config,
    const struct azihsm_pota_endorsement *pota_endorsement,
    const struct azihsm_resiliency_config *resiliency_config
    );
```

**Parameters**

| Parameter               | Name                                                                      | Description                                                      |
| ----------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| [in] handle             | [azihsm_handle](#azihsm_handle)                                           | device handle                                                    |
| [in] creds              | [struct azihsm_credentials*](#azihsm_credentials)                         | device credential                                                |
| [in] bmk                | [struct azihsm_buffer*](#azihsm_buffer)                                   | optional backup masking key (can be NULL)                        |
| [in] muk                | [struct azihsm_buffer*](#azihsm_buffer)                                   | optional masked unwrapping key (can be NULL)                     |
| [in] backup_key_config  | [struct azihsm_owner_backup_key_config*](#azihsm_owner_backup_key_config) | owner backup key configuration (must be non-NULL)                |
| [in] pota_endorsement   | [struct azihsm_pota_endorsement*](#azihsm_pota_endorsement)               | POTA endorsement configuration (must be non-NULL)                |
| [in] resiliency_config  | [struct azihsm_resiliency_config*](#azihsm_resiliency_config)             | optional resiliency configuration (can be NULL)                  |

When `resiliency_config` is non-NULL, the SDK enables automatic retry and recovery for transient hardware resets. The caller provides storage, lock, and (optionally) POTA re-endorsement and OBK provider callbacks. If POTA endorsement source is `AZIHSM_POTA_ENDORSEMENT_SOURCE_CALLER`, `pota_callback_ops` must be non-NULL. If source is `AZIHSM_POTA_ENDORSEMENT_SOURCE_TPM`, `pota_callback_ops` must be NULL. Similarly, if OBK source is `AZIHSM_OWNER_BACKUP_KEY_SOURCE_CALLER`, `obk_callback_ops` must be non-NULL. If source is `AZIHSM_OWNER_BACKUP_KEY_SOURCE_TPM`, `obk_callback_ops` must be NULL. Passing NULL for `resiliency_config` disables resiliency.

> **POTA callback:** The POTA `endorse` callback is
> invoked during resiliency recovery. The SDK retrieves the device's
> PID public key and certificate chain and passes them to the callback,
> so the implementation only needs to sign the provided key — it does
> not need to query the device. The callback is invoked while the
> partition's internal lock is held; its implementation must not call
> AZIHSM APIs on the same `azihsm_handle` being initialized or
> restored, to avoid deadlock.
> See [`azihsm_pota_callback_ops`](#azihsm_pota_callback_ops)
> for details.

> **OBK callback:** The OBK `get_obk` callback is invoked during
> resiliency recovery to re-provision the caller's Owner Backup Key.
> The SDK does not cache the plaintext OBK — it calls this callback
> on demand. The callback is invoked while the partition's internal
> lock is held; its implementation must not call AZIHSM APIs on the
> same `azihsm_handle` being initialized or restored, to avoid deadlock.
> See [`azihsm_obk_callback_ops`](#azihsm_obk_callback_ops)
> for details.

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

## azihsm_part_close

Close partition handle

```cpp
azihsm_status azihsm_part_close(
    azihsm_handle handle
    );

```

**Parameters**

 | Parameter    | Name                            | Description                |
 | ------------ | ------------------------------- | -------------------------- |
 | [in] handle | [azihsm_handle](#azihsm_handle) | device handle        &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

## azihsm_part_get_prop

Retrieve partition property

**Properties**

| Description                                        | Type                                     | Define                                            |
| -------------------------------------------------- | ---------------------------------------- | ------------------------------------------------- |
| device type                                        | [azihsm_part_type](#azihsm_part_type)    | \scriptsize AZIHSM_PART_PROP_ID_TYPE              |
| os device path                                     | [azihsm_char*](#azihsm_char)             | \scriptsize AZIHSM_PART_PROP_ID_PATH              |
| driver version                                     | [azihsm_char*](#azihsm_char)             | \scriptsize AZIHSM_PART_PROP_ID_DRIVER_VERSION    |
| firmware version                                   | [azihsm_char*](#azihsm_char)             | \scriptsize AZIHSM_PART_PROP_ID_FIRMWARE_VERSION  |
| hardware version                                   | [azihsm_char*](#azihsm_char)             | \scriptsize AZIHSM_PART_PROP_ID_HARDWARE_VERSION  |
| pci hardware id (bus:device:function)              | [azihsm_char*](#azihsm_char)             | \scriptsize AZIHSM_PART_PROP_ID_PCI_HW_ID         |
| min api revision supported by the device           | [struct azihsm_api_rev](#azihsm_api_rev) | \scriptsize AZIHSM_PART_PROP_ID_MIN_API_REV       |
| max api revision supported by the device           | [struct azihsm_api_rev](#azihsm_api_rev) | \scriptsize AZIHSM_PART_PROP_ID_MAX_API_REV       |
| manufacturer cert chain in PEM format              | [azihsm_char*](#azihsm_char)             | \scriptsize AZIHSM_PART_PROP_ID_MANUFACTURER_CERT_CHAIN |
| partition identity (PID) public key in DER format  | uint8_t*                                 | \scriptsize AZIHSM_PART_PROP_ID_PART_PUB_KEY    |

```cpp
azihsm_status azihsm_part_get_prop(
    azihsm_handle handle, 
    struct azihsm_part_prop *prop
    );
```

**Parameters**

 | Parameter   | Name                                         | Description           |
 | ----------- | -------------------------------------------- | --------------------- |
 | [in] handle | [azihsm_handle](#azihsm_handle)              | device handle         |
 | [out] prop   | [struct azihsm_part_prop *](#azihsm_part_prop) | property       &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

## azihsm_part_reset

Clears the partition and reinitializes to factory state.

```cpp
azihsm_status azihsm_part_reset(
    azihsm_handle handle
    );
```
**Parameters**

 | Parameter   | Name                            | Description                   |
 | ----------- | ------------------------------- | ----------------------------- |
 | [in] handle | [azihsm_handle](#azihsm_handle) | device handle          &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise
