# Session API

## azihsm_sess_open

Open a session to the device. Session is required to perform
cryptographic commands.

```cpp
azihsm_status azihsm_sess_open(
    azihsm_handle dev_handle,
    const struct azihsm_api_rev *api_rev,
    const struct azihsm_credentials *creds,
    const struct azihsm_buffer *seed,
    azihsm_handle *sess_handle
    );
```

**Parameters**

 | Parameter         | Name                                              | Description                                      |
 | ----------------- | ------------------------------------------------- | ------------------------------------------------ |
 | [in] dev_handle   | [azihsm_handle](#azihsm_handle)                   | device handle                                    |
 | [in] api_rev      | [struct azihsm_api_rev *](#azihsm_api_rev)        | api revision to open the session with            |
 | [in] creds        | [struct azihsm_credentials*](#azihsm_credentials) | application credential                           |
 | [in] seed         | [struct azihsm_buffer*](#azihsm_buffer)           | optional seed buffer (can be NULL)               |
 | [out] sess_handle | [azihsm_handle *](#azihsm_handle)                 | new session handle                               |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

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

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

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

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

## azihsm_session_get_prop

Retrieve session property

**Properties**

| Description                               | Type                                     | Define                                      |
| ----------------------------------------- | ---------------------------------------- | ------------------------------------------- |
| api revision negotiated for the session   | [struct azihsm_api_rev](#azihsm_api_rev) | \scriptsize AZIHSM_SESSION_PROP_ID_API_REV  |

```cpp
azihsm_status azihsm_session_get_prop(
    azihsm_handle handle, 
    struct azihsm_session_prop *prop
    );
```

**Parameters**

 | Parameter       | Name                                                 | Description           |
 | --------------- | ---------------------------------------------------- | --------------------- |
 | [in] handle     | [azihsm_handle](#azihsm_handle)                      | session handle        |
 | [in, out] prop  | [struct azihsm_session_prop *](#azihsm_session_prop) | property       &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

\pagebreak
