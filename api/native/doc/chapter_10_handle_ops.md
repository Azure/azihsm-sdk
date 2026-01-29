# Handle Operations

## azihsm_free_handle

Free a streaming context handle

```cpp
azihsm_status azihsm_free_handle(
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

This function releases a context handle (digest, sign, verify, encrypt, or decrypt) without completing the operation. It should be used in error scenarios where a multi-step operation was initialized but cannot be completed normally.

For successful completion of multi-step operations, use the appropriate `_final` function instead (e.g., `azihsm_crypt_digest_final`, `azihsm_crypt_sign_final`, etc.).