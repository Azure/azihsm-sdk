# Handle Operations

## azihsm_free_ctx_handle

Free a streaming context handle

```cpp
azihsm_status azihsm_free_ctx_handle(
    azihsm_handle handle
    );
```

**Parameters**

 | Parameter   | Name                            | Description                   |
 | ----------- | ------------------------------- | ----------------------------- |
 | [in] handle | [azihsm_handle](#azihsm_handle) | context handle to free &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

**Description**

This function releases a context handle (digest, sign, verify, encrypt, decrypt, HMAC sign, HMAC verify, RSA sign, or RSA verify) and frees all associated resources. The handle is invalidated and must not be used after this call.

Callers **must** call `azihsm_free_ctx_handle` for every valid context handle once it is no longer needed, whether the multi-step operation completed successfully, was abandoned due to an error, or was never fully executed.