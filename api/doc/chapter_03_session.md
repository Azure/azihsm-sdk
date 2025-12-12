# Session API

## azihsm_sess_open

Open a session to the device. Session is required to perform
cryptographic commands.

```cpp
azihsm_status azihsm_sess_open(
    azihsm_handle dev_handle,
    azihsm_sess_type kind,
    const struct azihsm_api_rev *api_rev,
    const struct azihsm_app_creds *creds,
    azihsm_handle *sess_handle
    );
```

**Parameters**

 | Parameter         | Name                                          | Description                                      |
 | ----------------- | --------------------------------------------- | ------------------------------------------------ |
 | [in] dev_handle   | [azihsm_handle](#azihsm_handle)               | device handle                                    |
 | [in] kind         | [azihsm_sess_type](#azihsm_sess_type)         | session kind (clear, authenticated or encrypted) |
 | [in] api_rev      | [struct azihsm_api_rev *](#azihsm_api_rev)    | api revision to open the session with            |
 | [in] creds        | [struct azihsm_app_creds*](#azihsm_app_creds) | application credential                           |
 | [out] sess_handle | [azihsm_handle *](#azihsm_handle)             | new session handle                               |

**Returns**

`AZIHSM_STATUS_OK` on success, error code otherwise

## azihsm_sess_close

Close a session

```cpp
azihsm_status azihsm_sess_close(
    azihsm_handle handle
    );
```

**Parameters**

 | Parameter   | Name                            | Description            |
 | ----------- | ------------------------------- | ---------------------- |
 | [in] handle | [azihsm_handle](#azihsm_handle) | session handle  &nbsp; |

**Returns**

`AZIHSM_STATUS_OK` on success, error code otherwise

## azihsm_sess_set_pin

This method changes the device PIN. Once the pin is change successfully a new
session must be open

```cpp
azihsm_status azihsm_sess_set_pin(
    azihsm_handle handle, 
    const azihsm_buffer *new_pin
    );
```

**Parameters**

 | Parameter    | Name                            | Description                |
 | ------------ | ------------------------------- | -------------------------- |
 | [in] handle  | [azihsm_handle](#azihsm_handle) | session handle             |
 | [in] new_pin | [azihsm_buffer](#azihsm_buffer) | new_pin             &nbsp; |

**Returns**

`AZIHSM_STATUS_OK` on success, error code otherwise

## azihsm_sess_set_part_owner_cert

Set the partition owner certificate chain

```cpp
azihsm_status azihsm_sess_set_part_owner_cert(
    azihsm_handle handle, 
    const azihsm_char *cert
    );
```

**Parameters**

 | Parameter   | Name                            | Description                       |
 | ----------- | ------------------------------- | --------------------------------- |
 | [in] handle | [azihsm_handle](#azihsm_handle) | session handle                    |
 | [in] cert   | [azihsm_char*](#azihsm_char)    | partition owner cert chain &nbsp; |

**Returns**

`AZIHSM_STATUS_OK` on success, error code otherwise

\pagebreak