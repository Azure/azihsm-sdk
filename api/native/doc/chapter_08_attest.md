# Attestation Operation

## azihsm_generate_key_report

Retrieve the attestation report for a specified key

```cpp
const azihsm_byte *azihsm_generate_key_report(
    azihsm_handle key_handle, 
    const azihsm_buffer *report_data,
    azihsm_buffer *report
    );
```
**Parameters**

| Parameter        | Name                              | Description                                  |
| ---------------- | --------------------------------- | -------------------------------------------- |
| [in] key_handle  | [azihsm_handle](#azihsm_handle)   | key handle to attest                         |
| [in] report_data | [azihsm_buffer*](#azihsm_buffer)  | additional data to be included in report     |
| [in, out] report | [azihsm_buffer *](#azihsm_buffer) | attestation report for the key        &nbsp; |

**Returns**

 `AZIHSM_STATUS_OK` on success, error code otherwise