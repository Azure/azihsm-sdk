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

 `AZIHSM_STATUS_OK` on success, error code otherwise

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

 `AZIHSM_STATUS_OK` on success, error code otherwise

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

`AZIHSM_STATUS_OK` on success, error code otherwise

## azihsm_part_init

Initialize a partition with credentials

```cpp
azihsm_status azihsm_part_init(
    azihsm_handle handle,
    const struct azihsm_credentials *creds,
    const struct azihsm_buffer *bmk,
    const struct azihsm_buffer *muk,
    const struct azihsm_buffer *mobk
    );
```

**Parameters**

 | Parameter         | Name                                              | Description                                           |
 | ----------------- | ------------------------------------------------- | ----------------------------------------------------- |
 | [in] handle       | [azihsm_handle](#azihsm_handle)                   | device handle                                         |
 | [in] creds        | [struct azihsm_credentials*](#azihsm_credentials) | device credential                                     |
 | [in] bmk          | [struct azihsm_buffer*](#azihsm_buffer)           | optional backup masking key (can be NULL)             |
 | [in] muk          | [struct azihsm_buffer*](#azihsm_buffer)           | optional masked unwrapping key (can be NULL)          |
 | [in] mobk         | [struct azihsm_buffer*](#azihsm_buffer)           | optional masked owner backup key (can be NULL) &nbsp; |
 

**Returns**

`AZIHSM_STATUS_OK` on success, error code otherwise

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

`AZIHSM_STATUS_OK` on success, error code otherwise

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
| device serial number                               | [azihsm_char*](#azihsm_char)             | \scriptsize AZIHSM_PART_PROP_ID_SERIAL_NUMBER     |
| pci hardware id (bus:device:function)              | [azihsm_char*](#azihsm_char)             | \scriptsize AZIHSM_PART_PROP_ID_PCI_HW_ID         |
| min api revision supported by the device           | [struct azihsm_api_rev](#azihsm_api_rev) | \scriptsize AZIHSM_PART_PROP_ID_MIN_API_REV       |
| max api revision supported by the device           | [struct azihsm_api_rev](#azihsm_api_rev) | \scriptsize AZIHSM_PART_PROP_ID_MAX_API_REV       |
| partition unique identifier                        | [struct azihsm_uuid](#azihsm_uuid)       | \scriptsize AZIHSM_PART_PROP_ID_UUID              |
| manufacturer cert chain in PEM format              | [azihsm_char*](#azihsm_char)             | \scriptsize AZIHSM_PART_PROP_ID_MANUFACTURER_CERT |
| device owner cert chain in PEM format              | [azihsm_char*](#azihsm_char)             | \scriptsize AZIHSM_PART_PROP_ID_DEV_OWNER_CERT    |
| partition owner cert chain in PEM format           | [azihsm_char*](#azihsm_char)             | \scriptsize AZIHSM_PART_PROP_ID_PART_OWNER_CERT   |
| partition owner cert signing request in PEM format | [azihsm_char*](#azihsm_char)             | \scriptsize AZIHSM_PART_PROP_ID_PART_OWNER_CSR    |

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

`AZIHSM_STATUS_OK` on success, error code otherwise

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

`AZIHSM_STATUS_OK` on success, error code otherwise
