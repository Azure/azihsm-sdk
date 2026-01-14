# Key Operations

## azihsm_key_gen

Generate symmetric key.

```cpp
azihsm_status azihsm_key_gen(
    azihsm_handle sess_handle,
    azihsm_algo *algo,
    const azihsm_key_prop_list *key_props,
    azihsm_handle *key_handle
    );
```

**Parameters**

 | Parameter        | Name                                                 | Description                  |
 | ---------------- | ---------------------------------------------------- | ---------------------------- |
 | [in] sess_handle | [azihsm_handle](#azihsm_handle)                      | session handle               |
 | [in] algo        | [azihsm_algo *](#azihsm_algo)                        | algorithm params             |
 | [in] key_props   | [const azihsm_key_prop_list*](#azihsm_key_prop_list) | key properties               |
 | [out] key_handle | [azihsm_handle *](#azihsm_handle)                    | key handle for generated key |

**Returns**

`AZIHSM_STATUS_OK` on success, error code otherwise

## azihsm_key_gen_pair

Generate asymmetric key pair

```cpp
azihsm_status azihsm_key_gen_pair(
    azihsm_handle sess_handle,
    azihsm_algo *algo,
    const azihsm_key_prop_list *priv_key_props,
    const azihsm_key_prop_list *pub_key_props,
    azihsm_handle *priv_key_handle
    azihsm_handle *pub_key_handle
    );
```

**Parameters**

 | Parameter             | Name                                                 | Description                          |
 | --------------------- | ---------------------------------------------------- | ------------------------------------ |
 | [in] sess_handle      | [azihsm_handle](#azihsm_handle)                      | session handle                       |
 | [in] algo             | [azihsm_algo *](#azihsm_algo)                        | algorithm params                     |
 | [in] priv_key_props   | [const azihsm_key_prop_list*](#azihsm_key_prop_list) | private key properties               |
 | [in] pub_key_props    | [const azihsm_key_prop_list*](#azihsm_key_prop_list) | public key properties                | 
 | [out] priv_key_handle | [azihsm_handle *](#azihsm_handle)                    | key handle for generated private key |
 | [out] pub_key_handle  | [azihsm_handle *](#azihsm_handle)                    | key handle for generated public key  | 

**Returns**

`AZIHSM_STATUS_OK` on success, error code otherwise

## azihsm_key_unwrap

Unwrap a key.

```cpp
azihsm_status azihsm_key_unwrap(
    azihsm_handle sess_handle,
    azihsm_algo *algo,
    azihsm_handle unwrapping_key,
    const azihsm_buffer *wrapped_key,
    const azihsm_key_prop_list *key_props,
    azihsm_handle *key_handle
    );
```

**Parameters**

 | Parameter           | Name                                                 | Description                  |
 | ------------------- | ---------------------------------------------------- | ---------------------------- |
 | [in] sess_handle    | [azihsm_handle](#azihsm_handle)                      | session handle               |
 | [in] algo           | [azihsm_algo *](#azihsm_algo)                        | algorithm params             |
 | [in] unwrapping_key | [azihsm_handle](#azihsm_handle)                      | unwrapping key handle        |
 | [in] wrapped_key    | [azihsm_buffer *](#azihsm_buffer)                    | wrapped key                  |
 | [in] key_props      | [const azihsm_key_prop_list*](#azihsm_key_prop_list) | key properties               |
 | [out] key_handle    | [azihsm_handle *](#azihsm_handle)                    | key handle for unwrapped key |

**Returns**

`AZIHSM_STATUS_OK` on success, error code otherwise

## azihsm_key_derive

Derive a key from an existing key.

```cpp
azihsm_status azihsm_key_derive(
    azihsm_handle sess_handle,
    azihsm_algo *algo,
    azihsm_handle base_key,
    const azihsm_key_prop_list *key_props,
    azihsm_handle *key_handle
    );
```

**Parameters**

 | Parameter        | Name                                                 | Description                |
 | ---------------- | ---------------------------------------------------- | -------------------------- |
 | [in] sess_handle | [azihsm_handle](#azihsm_handle)                      | session handle             |
 | [in] algo        | [azihsm_algo *](#azihsm_algo)                        | algorithm params           |
 | [in] base_key    | [azihsm_handle](#azihsm_handle)                      | base key handle            |
 | [in] key_props   | [const azihsm_key_prop_list*](#azihsm_key_prop_list) | key properties             |
 | [out] key_handle | [azihsm_handle *](#azihsm_handle)                    | key handle for derived key |

**Returns**

`AZIHSM_STATUS_OK` on success, error code otherwise

## azihsm_key_delete

Delete a key.

```cpp
azihsm_status azihsm_key_delete(
    azihsm_handle key,
    );
```

**Parameters**

 | Parameter        | Name                            | Description                   |
 | ---------------- | ------------------------------- | ----------------------------- |
 | [in] key         | [azihsm_handle](#azihsm_handle) | key to delete         &nsbsp; |

**Returns**

`AZIHSM_STATUS_OK` on success, error code otherwise

## azihsm_key_get_prop

Get key property.

```cpp
azihsm_status azihsm_key_get_prop(
    azihsm_handle sess_handle,
    azihsm_handle key,
    azihsm_key_prop *key_prop,
    );
```

**Parameters**

 | Parameter          | Name                                  | Description                   |
 | ------------------ | ------------------------------------- | ----------------------------- |
 | [in] sess_handle   | [azihsm_handle](#azihsm_handle)       | session handle                |
 | [in] key           | [azihsm_handle](#azihsm_handle)       | key to delete         &nsbsp; |
 | [in, out] key_prop | [azihsm_key_prop *](#azihsm_key_prop) | key property to retrieve      |

**Returns**

`AZIHSM_STATUS_OK` on success, error code otherwise

## azihsm_key_set_prop

Set key property.

```cpp
azihsm_status azihsm_key_set_prop(
    azihsm_handle sess_handle,
    azihsm_handle key,
    const azihsm_key_prop *key_prop,
    );
```

**Parameters**

 | Parameter        | Name                                  | Description                   |
 | ---------------- | ------------------------------------- | ----------------------------- |
 | [in] sess_handle | [azihsm_handle](#azihsm_handle)       | session handle                |
 | [in] key         | [azihsm_handle](#azihsm_handle)       | key to delete         &nsbsp; |
 | [in] key_prop    | [azihsm_key_prop *](#azihsm_key_prop) | key property to set           |

**Returns**

`AZIHSM_STATUS_OK` on success, error code otherwise
