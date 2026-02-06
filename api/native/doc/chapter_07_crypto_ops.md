# Cryptographic Operations

This section discusses the various cryptographic operation that can be performed
on an established session.

## Encrypt

### azihsm_crypt_encrypt

```cpp
azihsm_status azihsm_crypt_encrypt(
    azihsm_algo *algo,
    azihsm_handle key_handle,
    const azihsm_buffer *plain_text,
    azihsm_buffer *cipher_text,
    );
```

**Parameters**

 | Parameter             | Name                              | Description        |
 | --------------------- | --------------------------------- | ------------------ |
 | [in] algo             | [azihsm_algo *](#azihsm_algo)     | algorithm params   |
 | [in] key_handle       | [azihsm_handle](#azihsm_handle)   | key handle         |
 | [in] plain_text       | [azihsm_buffer *](#azihsm_buffer) | plain text         |
 | [in, out] cipher_text | [azihsm_buffer *](#azihsm_buffer) | cipher text &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_encrypt_init

```cpp
azihsm_status azihsm_crypt_encrypt_init(
    azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_handle *ctx_handle
    );
```

**Parameters**

 | Parameter        | Name                            | Description                 |
 | ---------------- | ------------------------------- | --------------------------- |
 | [in] algo        | [azihsm_algo *](#azihsm_algo)   | algorithm params            |
 | [in] key_handle  | [azihsm_handle](#azihsm_handle) | key handle       &nbsp;     |
 | [out] ctx_handle | [azihsm_handle](#azihsm_handle) | context handle       &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_encrypt_update

```cpp
azihsm_status azihsm_crypt_encrypt_update(
    azihsm_handle ctx_handle,
    const azihsm_buffer *plain_text,
    azihsm_buffer *cipher_text,
    );
```

**Parameters**

 | Parameter             | Name                              | Description        |
 | --------------------- | --------------------------------- | ------------------ |
 | [in] ctx_handle       | [azihsm_handle](#azihsm_handle)   | context handle     |
 | [in] plain_text       | [azihsm_buffer *](#azihsm_buffer) | plain text         |
 | [in, out] cipher_text | [azihsm_buffer *](#azihsm_buffer) | cipher text &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_encrypt_final

```cpp
azihsm_status azihsm_crypt_encrypt_final(
    azihsm_handle ctx_handle,
    azihsm_buffer *cipher_text,
    );
```

**Parameters**

 | Parameter             | Name                              | Description        |
 | --------------------- | --------------------------------- | ------------------ |
 | [in] ctx_handle       | [azihsm_handle](#azihsm_handle)   | context handle     |
 | [in, out] cipher_text | [azihsm_buffer *](#azihsm_buffer) | cipher text &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

## Decrypt

### azihsm_crypt_decrypt

```cpp
azihsm_status azihsm_crypt_decrypt(
    azihsm_algo *algo,
    azihsm_handle key_handle,
    const azihsm_buffer *cipher_text,
    azihsm_buffer *plain_text,
    );
```

**Parameters**

 | Parameter             | Name                              | Description        |
 | --------------------- | --------------------------------- | ------------------ |
 | [in] algo             | [azihsm_algo *](#azihsm_algo)     | algorithm params   |
 | [in] key_handle       | [azihsm_handle](#azihsm_handle)   | key handle         |
 | [in] cipher_text      | [azihsm_buffer *](#azihsm_buffer) | cipher text        |
 | [in, out] plain_text  | [azihsm_buffer *](#azihsm_buffer) | plain text &nbsp;  |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_decrypt_init

```cpp
azihsm_status azihsm_crypt_decrypt_init(
    azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_handle *ctx_handle
    );
```

**Parameters**

 | Parameter        | Name                            | Description                 |
 | ---------------- | ------------------------------- | --------------------------- |
 | [in] algo        | [azihsm_algo *](#azihsm_algo)   | algorithm params            |
 | [in] key_handle  | [azihsm_handle](#azihsm_handle) | key handle       &nbsp;     |
 | [out] ctx_handle | [azihsm_handle](#azihsm_handle) | context handle       &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_decrypt_update

```cpp
azihsm_status azihsm_crypt_decrypt_update(
    azihsm_handle ctx_handle,
    const azihsm_buffer *cipher_text,
    azihsm_buffer *plain_text,
    );
```

**Parameters**

 | Parameter             | Name                              | Description        |
 | --------------------- | --------------------------------- | ------------------ |
 | [in] ctx_handle       | [azihsm_handle](#azihsm_handle)   | context handle     |
 | [in] cipher_text      | [azihsm_buffer *](#azihsm_buffer) | cipher text        |
 | [in, out] plain_text  | [azihsm_buffer *](#azihsm_buffer) | plain text &nbsp;  |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_decrypt_final

```cpp
azihsm_status azihsm_crypt_decrypt_final(
    azihsm_handle ctx_handle,
    azihsm_buffer *plain_text,
    );
```

**Parameters**

 | Parameter             | Name                              | Description        |
 | --------------------- | --------------------------------- | ------------------ |
 | [in] ctx_handle       | [azihsm_handle](#azihsm_handle)   | context handle     |
 | [in, out] plain_text  | [azihsm_buffer *](#azihsm_buffer) | cipher text &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

## Sign

### azihsm_crypt_sign

```cpp
azihsm_status azihsm_crypt_sign(
    azihsm_algo *algo,
    azihsm_handle key_handle,
    const azihsm_buffer *data,
    azihsm_buffer *sig,
    );
```

**Parameters**

 | Parameter        | Name                              | Description           |
 | ---------------- | --------------------------------- | --------------------- |
 | [in] algo        | [azihsm_algo *](#azihsm_algo)     | algorithm params      |
 | [in] key_handle  | [azihsm_handle](#azihsm_handle)   | key handle            |
 | [in] data        | [azihsm_buffer *](#azihsm_buffer) | data to sign          |
 | [in, out] sig    | [azihsm_buffer *](#azihsm_buffer) | signature      &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_sign_init

```cpp
azihsm_status azihsm_crypt_sign_init(
    azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_handle *ctx_handle
    );
```

**Parameters**

 | Parameter        | Name                            | Description                 |
 | ---------------- | ------------------------------- | --------------------------- |
 | [in] algo        | [azihsm_algo *](#azihsm_algo)   | algorithm params            |
 | [in] key_handle  | [azihsm_handle](#azihsm_handle) | key handle       &nbsp;     |
 | [out] ctx_handle | [azihsm_handle](#azihsm_handle) | context handle       &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_sign_update

```cpp
azihsm_status azihsm_crypt_sign_update(
    azihsm_handle ctx_handle,
    const azihsm_buffer *data,
    );
```

**Parameters**

 | Parameter       | Name                              | Description               |
 | --------------- | --------------------------------- | ------------------------- |
 | [in] ctx_handle | [azihsm_handle](#azihsm_handle)   | context handle            |
 | [in] data       | [azihsm_buffer *](#azihsm_buffer) | data to sign       &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_sign_final

```cpp
azihsm_status azihsm_crypt_sign_final(
    azihsm_handle ctx_handle,
    azihsm_buffer *sig,
    );
```

**Parameters**

 | Parameter       | Name                              | Description               |
 | --------------- | --------------------------------- | ------------------------- |
 | [in] ctx_handle | [azihsm_handle](#azihsm_handle)   | context handle            |
 | [in, out] sig   | [azihsm_buffer *](#azihsm_buffer) | signature          &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

## Verify

### azihsm_crypt_verify

```cpp
azihsm_status azihsm_crypt_verify(
    azihsm_algo *algo,
    azihsm_handle key_handle,
    const azihsm_buffer *data,
    azihsm_buffer *sig,
    );
```

**Parameters**

 | Parameter        | Name                              | Description           |
 | ---------------- | --------------------------------- | --------------------- |
 | [in] algo        | [azihsm_algo *](#azihsm_algo)     | algorithm params      |
 | [in] key_handle  | [azihsm_handle](#azihsm_handle)   | key handle            |
 | [in] data        | [azihsm_buffer *](#azihsm_buffer) | data to sign          |
 | [in, out] sig    | [azihsm_buffer *](#azihsm_buffer) | signature      &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_verify_init

```cpp
azihsm_status azihsm_crypt_verify_init(
    azihsm_algo *algo,
    azihsm_handle key_handle,
    azihsm_handle *ctx_handle
    );
```

**Parameters**

 | Parameter        | Name                            | Description                 |
 | ---------------- | ------------------------------- | --------------------------- |
 | [in] algo        | [azihsm_algo *](#azihsm_algo)   | algorithm params            |
 | [in] key_handle  | [azihsm_handle](#azihsm_handle) | key handle                  |
 | [out] ctx_handle | [azihsm_handle](#azihsm_handle) | context handle       &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_verify_update

```cpp
azihsm_status azihsm_crypt_verify_update(
    azihsm_handle ctx_handle,
    const azihsm_buffer *data,
    );
```

**Parameters**

 | Parameter       | Name                              | Description               |
 | --------------- | --------------------------------- | ------------------------- |
 | [in] ctx_handle | [azihsm_handle](#azihsm_handle)   | context handle            |
 | [in] data       | [azihsm_buffer *](#azihsm_buffer) | data to sign       &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_verify_final

```cpp
azihsm_status azihsm_crypt_verify_final(
    azihsm_handle ctx_handle,
    const azihsm_buffer *sig,
    );
```

**Parameters**

 | Parameter       | Name                              | Description               |
 | --------------- | --------------------------------- | ------------------------- |
 | [in] ctx_handle | [azihsm_handle](#azihsm_handle)   | context handle            |
 | [in, out] sig   | [azihsm_buffer *](#azihsm_buffer) | signature          &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

## Digest

### azihsm_crypt_digest

```cpp
azihsm_status azihsm_crypt_digest(
    azihsm_handle sess_handle,
    azihsm_algo *algo,
    const azihsm_buffer *data,
    azihsm_buffer *digest
    );
```

**Parameters**

 | Parameter        | Name                              | Description              |
 | ---------------- | --------------------------------- | ------------------------ |
 | [in] sess_handle | [azihsm_handle](#azihsm_handle)   | session handle           |
 | [in] algo        | [azihsm_algo *](#azihsm_algo)     | algorithm params         |
 | [in] data        | [azihsm_buffer *](#azihsm_buffer) | data                     |
 | [in, out] digest | [azihsm_buffer *](#azihsm_buffer) | digest            &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_digest_init

```cpp
azihsm_status azihsm_crypt_digest_init(
    azihsm_handle sess_handle,
    azihsm_algo *algo,
    azihsm_handle *ctx_handle
    );
```

**Parameters**

 | Parameter        | Name                            | Description                 |
 | ---------------- | ------------------------------- | --------------------------- |
 | [in] sess_handle | [azihsm_handle](#azihsm_handle) | session handle              |
 | [in] algo        | [azihsm_algo *](#azihsm_algo)   | algorithm params            |
 | [out] ctx_handle | [azihsm_handle](#azihsm_handle) | context handle       &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_digest_update

```cpp
azihsm_status azihsm_crypt_digest_update(
    azihsm_handle ctx_handle,
    const azihsm_buffer *data,
    );
```

**Parameters**

 | Parameter       | Name                              | Description                |
 | --------------- | --------------------------------- | -------------------------- |
 | [in] ctx_handle | [azihsm_handle](#azihsm_handle)   | context handle             |
 | [in] data       | [azihsm_buffer *](#azihsm_buffer) | data                &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise

### azihsm_crypt_digest_final

```cpp
azihsm_status azihsm_crypt_decrypt_final(
    azihsm_handle ctx_handle,
    azihsm_buffer *digest
    );
```

**Parameters**

 | Parameter        | Name                              | Description              |
 | ---------------- | --------------------------------- | ------------------------ |
 | [in] ctx_handle  | [azihsm_handle](#azihsm_handle)   | context handle           |
 | [in, out] digest | [azihsm_buffer *](#azihsm_buffer) | digest            &nbsp; |

**Returns**

`AZIHSM_STATUS_SUCCESS` on success, error code otherwise
