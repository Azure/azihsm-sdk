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

## azihsm_part_get_path

Retrieves the OS device path

```cpp
const azihsm_char *azihsm_part_get_path(
    azihsm_handle handle, 
    azihsm_u32 index
    );
```

**Parameters**

 | Parameter   | Name                               | Description                              |
 | ----------- | ---------------------------------- | ---------------------------------------- |
 | [in] handle | [azihsm_handle](#azihsm_handle)    | device list handle                       |
 | [in] index  | [azihsm_u32](#azihsm_u32)          | index of the device in list       &nbsp; |

**Returns**

Device OS path on success, NULL on failure

## azihsm_part_open

Open a handle to the partition

```cpp
azihsm_status azihsm_part_open(
    const azihsm_char *path,
    azihsm_handle *handle
    );

```

**Parameters**

 | Parameter    | Name                               | Description                |
 | ------------ | ---------------------------------- | -------------------------- |
 | [in] path    | [const azihsm_char*](#azihsm_char) | OS device path             |
 | [out] handle | [azihsm_handle *](#azihsm_handle)  | device handle       &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

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

## azihsm_part_init

Initialize a partition with credentials

```cpp
azihsm_status azihsm_part_init(
    azihsm_handle handle,
    const struct azihsm_credentials *creds,
    const struct azihsm_buffer *bmk,
    const struct azihsm_buffer *muk,
    const struct azihsm_owner_backup_key_config *backup_key_config
    );
```

**Parameters**

| Parameter               | Name                                                        | Description                                                      |
| ----------------------- | ----------------------------------------------------------- | ---------------------------------------------------------------- |
| [in] handle             | [azihsm_handle](#azihsm_handle)                             | device handle                                                    |
| [in] creds              | [struct azihsm_credentials*](#azihsm_credentials)           | device credential                                                |
| [in] bmk                | [struct azihsm_buffer*](#azihsm_buffer)                     | optional backup masking key (can be NULL)                        |
| [in] muk                | [struct azihsm_buffer*](#azihsm_buffer)                     | optional masked unwrapping key (can be NULL)                     |
| [in] backup_key_config  | [struct azihsm_owner_backup_key_config*](#azihsm_owner_backup_key_config) | owner backup key configuration (must be non-NULL)      |

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
| partition identity (PID) public key in DER format  | uint8_t*                                 | \scriptsize AZIHSM_PART_PROP_ID_PARTITION_IDENTITY_PUBLIC_KEY    |

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
