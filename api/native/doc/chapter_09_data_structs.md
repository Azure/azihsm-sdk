# Data Structures

## Typedefs

### azihsm_byte

Boolean type

```cpp
typedef uint8_t azihsm_byte;
```

### azihsm_u8

Unsigned 8-bit integer

```cpp
typedef uint8_t azihsm_u8;
```

### azihsm_u16

Unsigned 16-bit integer

```cpp
typedef uint16_t azihsm_u16;
```

### azihsm_u32

Unsigned 32-bit integer

```cpp
typedef uint32_t azihsm_u32;
```

### azihsm_64

Unsigned 64-bit integer

```cpp
typedef uint64_t azihsm_u64;
```

### azihsm_void

Void type

```cpp
typedef void azihsm_void;
```

### azihsm_bool

Boolean type

```cpp
typedef uint32_t azihsm_bool;
```
Possible values are defined by [AZIHSM_BOOL_XXX](#azihsm_bool_xxx)

### azihsm_handle

Handle type

```cpp
typedef uint32_t azihsm_handle;
```

### azihsm_char

Character type

```cpp
#if !defined(_WIN32)
    typedef char azihsm_char;
#endif

#if defined(_WIN32)
    typedef wchar azihsm_char;
#endif
```
### azihsm_utf8_char

UTF-8 Character type

```cpp
typedef unsigned char azihsm_utf8_char;
```

### azihsm_part_type

Device type

```cpp
typedef uint32_t azihsm_part_type;
```

Possible values are defined by [AZIHSM_PART_TYPE_XXX](#azihsm_part_type_xxx)

### azihsm_part_prop_id

Device property id type

```cpp
typedef uint32_t azihsm_part_prop_id;
```

Possible values are defined by [AZIHSM_PART_PROP_ID_XXX](#azihsm_part_prop_id_xxx)

### azihsm_key_class

Key class type

```cpp
typedef uint32_t azihsm_key_class;
```

Possible values are defined by [AZIHSM_KEY_CLASS_XXX](#azihsm_key_class_xxx)

### azihsm_key_type

Key type type

```cpp
typedef uint32_t azihsm_key_type;
```

Possible values are defined by [AZIHSM_KEY_TYPE_XXX](#azihsm_key_type_xxx)

### azihsm_key_prop_id

Key Property ID type

```cpp
typedef uint32_t azihsm_key_prop_id;
```

Possible values are defined by [AZIHSM_KEY_PROP_ID_XXX](#azihsm_key_prop_id_xxx)

### azihsm_algo_id

Algorithm ID type

```cpp
typedef uint32_t azihsm_algo_id;
```

Possible values are defined by [AZIHSM_ALGO_ID_XXX](#azihsm_algo_id_xxx)

### azihsm_ec_curve_id

Elliptic Curve ID type

```cpp
typedef uint32_t azihsm_ec_curve_id;
```

Possible values are defined by [AZIHSM_EC_CURVE_ID_XXX](#azihsm_ec_curve_id_xxx)


### azihsm_mgf1_id

Mask Generation Function ID type

```cpp
typedef uint32_t azihsm_mgf1_id;
```

Possible values are defined by [AZIHSM_MGF1_ID_XXX](#azihsm_mgf1_id_xxx)

### azihsm_sess_type

Session kind type

```cpp
typedef uint32_t azihsm_sess_type;
```

Possible values are defined by [AZIHSM_SESS_TYPE_XXX](#azihsm_sess_type_xxx)


<!--

### azihsm_cert_chain_id

Certificate chain ID type

```cpp
typedef uint32_t azihsm_cert_chain_id;
```

Possible values are defined by [AZIHSM_CERT_CHAIN_ID_XXX](#azihsm_cert_chain_id_xxx)

-->

## Defines

### AZIHSM_BOOL_XXX

Boolean values

```cpp
#define AZIHSM_BOOL_FALSE 0
#define AZIHSM_BOOL_TRUE 1
```

### AZIHSM_PART_PROP_ID_XXX

Device property identifiers

```cpp
#define AZIHSM_PART_PROP_ID_TYPE 1
#define AZIHSM_PART_PROP_ID_PATH 2
#define AZIHSM_PART_PROP_ID_DRIVER_VERSION 3
#define AZIHSM_PART_PROP_ID_FIRMWARE_VERSION 4
#define AZIHSM_PART_PROP_ID_HARDWARE_VERSION 5
#define AZIHSM_PART_PROP_ID_PCI_HW_ID 6
#define AZIHSM_PART_PROP_ID_MIN_API_REV 7
#define AZIHSM_PART_PROP_ID_MAX_API_REV 8
#define AZIHSM_PART_PROP_ID_MANUFACTURER_CERT_CHAIN 9
#define AZIHSM_PART_PROP_ID_BACKUP_MASKING_KEY 10
#define AZIHSM_PART_PROP_ID_MASKED_OWNER_BACKUP_KEY 11
#define AZIHSM_PART_PROP_ID_PART_PUB_KEY 12
```

### AZIHSM_PART_TYPE_XXX

Device type values

```cpp
#define AZIHSM_PART_TYPE_VIRTUAL 1
#define AZIHSM_PART_TYPE_PHYSICAL 2
```

### AZIHSM_KEY_CLASS_XXX

Key class type values

```cpp
#define AZIHSM_KEY_CLASS_PRIVATE 1
#define AZIHSM_KEY_CLASS_PUBLIC 2
#define AZIHSM_KEY_CLASS_SECRET 3
```

### AZIHSM_KEY_TYPE_XXX

Key type values

```cpp
#define AZIHSM_KEY_TYPE_RSA 1
#define AZIHSM_KEY_TYPE_EC 2
#define AZIHSM_KEY_TYPE_AES 3
#define AZIHSM_KEY_TYPE_AES_XTS 4
#define AZIHSM_KEY_TYPE_AES_GCM 5
#define AZIHSM_KEY_TYPE_GENERIC 6
#define AZIHSM_KEY_TYPE_HMAC_SHA1 7
#define AZIHSM_KEY_TYPE_HMAC_SHA256 8
#define AZIHSM_KEY_TYPE_HMAC_SHA384 9
#define AZIHSM_KEY_TYPE_HMAC_SHA512 10
#define AZIHSM_KEY_TYPE_MASKING 11
```

### AZIHSM_KEY_PROP_ID_XXX

Key property ID type values

```cpp
#define AZIHSM_KEY_PROP_ID_CLASS 1
#define AZIHSM_KEY_PROP_ID_KIND 2
#define AZIHSM_KEY_PROP_ID_BIT_LEN 3
#define AZIHSM_KEY_PROP_ID_LABEL 4
#define AZIHSM_KEY_PROP_PUB_KEY_INFO 5
#define AZIHSM_KEY_PROP_ID_EC_CURVE 6
#define AZIHSM_KEY_PROP_ID_MASKED_KEY 7
#define AZIHSM_KEY_PROP_ID_SESSION 8
#define AZIHSM_KEY_PROP_ID_LOCAL 9
#define AZIHSM_KEY_PROP_ID_SENSITIVE 10
#define AZIHSM_KEY_PROP_ID_EXTRACTABLE 11
#define AZIHSM_KEY_PROP_ID_ENCRYPT 12
#define AZIHSM_KEY_PROP_ID_DECRYPT 13
#define AZIHSM_KEY_PROP_ID_SIGN 14
#define AZIHSM_KEY_PROP_ID_VERIFY 15
#define AZIHSM_KEY_PROP_ID_WRAP 16
#define AZIHSM_KEY_PROP_ID_UNWRAP 17
#define AZIHSM_KEY_PROP_ID_DERIVE 18
```

### AZIHSM_ALGO_ID_XXX

Algorithm ID type values

```cpp
#define AZIHSM_ALGO_ID_MASKING_KEY_GEN 0x00000001
#define AZIHSM_ALGO_ID_MASKING_KEYWRAP 0x00000002
#define AZIHSM_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN 0x00010001
#define AZIHSM_ALGO_ID_RSA_PKCS 0x00010002
#define AZIHSM_ALGO_ID_RSA_PKCS_SHA1 0x00010003
#define AZIHSM_ALGO_ID_RSA_PKCS_SHA256 0x00010004
#define AZIHSM_ALGO_ID_RSA_PKCS_SHA384 0x00010005
#define AZIHSM_ALGO_ID_RSA_PKCS_SHA512 0x00010006
#define AZIHSM_ALGO_ID_RSA_PKCS_PSS 0x00010007
#define AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA1 0x00010008
#define AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA256 0x00010009
#define AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA384 0x0001000A
#define AZIHSM_ALGO_ID_RSA_PKCS_PSS_SHA512 0x0001000B
#define AZIHSM_ALGO_ID_RSA_PKCS_OAEP 0x0001000C
#define AZIHSM_ALGO_ID_RSA_PKCS 0x0001000D
#define AZIHSM_ALGO_ID_RSA_AES_KEY_WRAP 0x0001000E
#define AZIHSM_ALGO_ID_EC_KEY_PAIR_GEN 0x00020001
#define AZIHSM_ALGO_ID_ECDSA 0x00020002
#define AZIHSM_ALGO_ID_ECDSA_SHA1 0x00020003
#define AZIHSM_ALGO_ID_ECDSA_SHA256 0x00020004
#define AZIHSM_ALGO_ID_ECDSA_SHA384 0x00020005
#define AZIHSM_ALGO_ID_ECDSA_SHA512 0x00020006
#define AZIHSM_ALGO_ID_ECDH 0x00020007
#define AZIHSM_ALGO_ID_AES_KEY_GEN 0x00030001
#define AZIHSM_ALGO_ID_AES_CBC 0x00030002
#define AZIHSM_ALGO_ID_AES_CBC_PAD 0x00030003
#define AZIHSM_ALGO_ID_AES_XTS_KEY_GEN 0x00030004
#define AZIHSM_ALGO_ID_AES_XTS 0x00030005
#define AZIHSM_ALGO_ID_AES_GCM_KEY_GEN 0x00030006
#define AZIHSM_ALGO_ID_AES_GCM 0x00030007
#define AZIHSM_ALGO_ID_SHA1 0x00040001
#define AZIHSM_ALGO_ID_SHA256 0x00040002
#define AZIHSM_ALGO_ID_SHA384 0x00040003
#define AZIHSM_ALGO_ID_SHA512 0x00040004
#define AZIHSM_ALGO_ID_HMAC_SHA1 0x00050001
#define AZIHSM_ALGO_ID_HMAC_SHA256 0x00050002
#define AZIHSM_ALGO_ID_HMAC_SHA384 0x00050003
#define AZIHSM_ALGO_ID_HMAC_SHA512 0x00050004
#define AZIHSM_ALGO_ID_HKDF_DERIVE 0x00060001
#define AZIHSM_ALGO_ID_KBKDF_COUNTER_DERIVE 0x00060002
```

### AZIHSM_MGF1_ID_XXX

```cpp
#define AZIHSM_MGF1_ID_SHA256 1
#define AZIHSM_MGF1_ID_SHA384 2
#define AZIHSM_MGF1_ID_SHA512 3
```
### AZIHSM_EC_CURVE_ID_XXX

```cpp
#define AZIHSM_EC_CURVE_ID_P256 1
#define AZIHSM_EC_CURVE_ID_P384 2
#define AZIHSM_EC_CURVE_ID_P521 3
```

### AZIHSM_SESS_TYPE_XXX

```cpp
#define AZIHSM_SESS_TYPE_CLEAR 1
#define AZIHSM_SESS_TYPE_AUTHENTICATED 2
#define AZIHSM_SESS_TYPE_ENCRYPTED 3
```

<!-- 
### AZIHSM_CERT_CHAIN_ID_XXX

```cpp
#define AZIHSM_CERT_CHAIN_ID_MANUFACTURER 1
#define AZIHSM_CERT_CHAIN_ID_DEV_OWNER 2
#define AZIHSM_CERT_CHAIN_ID_PART_OWNER 3
```
 -->

## Structures

### azihsm_part_prop

```cpp
struct azihsm_part_prop {
    azihsm_part_prop_id id;
    azihsm_void *val;
    azihsm_u32 len;
};
```

**Fields**

 | Field | Type                                        | Description                                    |
 | ----- | ------------------------------------------- | ---------------------------------------------- |
 | id    | [azihsm_part_prop_id](#azihsm_part_prop_id) | [device property id](#azihsm_part_prop_id_xxx) |
 | val   | [azihsm_void *](#azihsm_void)               | value of the property.                         |
 | len   | [azihsm_u32](#azihsm_u32)                   | size of the `val` field in bytes               |

### azihsm_api_rev

API Revision

 ```cpp
struct azihsm_api_rev {
    uint32_t major;
    uint32_t minor;
};
```

**Fields**

 | Field | Type | Description                                                 |
 | ----- | ---- | ----------------------------------------------------------- |
 | minor | u32  | minor version                                               |
 | major | u32  | major version                                        &nbsp; |


### azihsm_uuid

API Revision

 ```cpp
struct azihsm_uuid{
    azihsm_byte bytes[16];
};
```

**Fields**

 | Field | Type                            | Description                     |
 | ----- | ------------------------------- | ------------------------------- |
 | bytes | [azihsm_byte[16]](#azihsm_byte) | uuid bytes               &nbsp; |


### azihsm_credentials

Application credential

```cpp
struct azihsm_credentials {
    uint8_t id[16];
    uint8_t pin[16];
};

```

**Fields**

 | Field | Type        | Description                                                   |
 | ----- | ----------- | ------------------------------------------------------------- |
 | id    | uint8_t[16] | application id                                                |
 | pin   | uint8_t[16] | application pin                                        &nbsp; |


### azihsm_buffer

A sized buffer

```cpp
struct azihsm_buffer{
  azihsm_byte *ptr;
  azihsm_u32 len;
};

```

**Fields**

 | Field | Type                         | Description                                                       |
 | ----- | ---------------------------- | ----------------------------------------------------------------- |
 | ptr   | [azihsm_byte*](#azihsm_byte) | pointer to buffer                                                 |
 | len   | [azihsm_u32](#azihsm_u32)    | length of the buffer                                       &nbsp; |


### azihsm_key_prop

Key property

```cpp
struct azihsm_key_prop {
    azihsm_key_prop_id id;
    azihsm_void* val;
    azihsm_u32 len;
};

```

**Fields**

 | Field | Type                                      | Description                                |
 | ----- | ----------------------------------------- | ------------------------------------------ |
 | id    | [azihsm_key_prop_id](#azihsm_key_prop_id) | [key property id](#azihsm_key_prop_id_xxx) |
 | val   | [azihsm_void *](#azihsm_void)             | key property value                         |
 | len   | [azihsm_u32](#azihsm_u32)                 | size of the `val` field in bytes           |

### azihsm_key_prop_list

Key property list

```cpp
struct azihsm_key_prop_list {
    azihsm_key_prop* props;
    azihsm_u32 count;
};
```

**Fields**

 | Field | Type                                  | Description                    |
 | ----- | ------------------------------------- | ------------------------------ |
 | props | [azihsm_key_prop *](#azihsm_key_prop) | key property list              |
 | count | [azihsm_u32](#azihsm_u32)             | count of properties in `props` |

### azihsm_algo

Crypto algorithm

```cpp
struct azihsm_algo {
    azihsm_algo_id id;
    azihsm_void* params;
    azihsm_u32 len;
};

```

**Fields**

 | Field  | Type                              | Description                         |
 | ------ | --------------------------------- | ----------------------------------- |
 | id     | [azihsm_algo_id](#azihsm_algo_id) | [algorithm id](#azihsm_algo_id_xxx) |
 | params | [azihsm_void *](#azihsm_void)     | algorithm parameters                |
 | len    | [azihsm_u32](#azihsm_u32)         | size of the `param` field in bytes  |


### azihsm_algo_rsa_pkcs_pss_params

RSA PSS Algorithm parameters.

```cpp
struct azihsm_algo_rsa_pkcs_pss_params {
    azihsm_algo_id hash_algo_id;
    azihsm_mgf1_id mgf_id;
    azihsm_u32 salt_len;
};

```

**Fields**

 | Field        | Type                              | Description                                        |
 | ------------ | --------------------------------- | -------------------------------------------------- |
 | hash_algo_id | [azihsm_algo_id](#azihsm_algo_id) | [hash algorithm id](#azihsm_algo_id_xxx)           |
 | mgf1         | [azihsm_mgf1_id](#azihsm_mgf1_id) | [mask generation function id](#azihsm_mgf1_id_xxx) |
 | salt_len     | [azihsm_u32](#azihsm_u32)         | salt length                                        |

### azihsm_algo_rsa_pkcs_oaep_params

RSA OAEP Algorithm parameters.

```cpp
struct azihsm_algo_rsa_pkcs_oaep_params {
    azihsm_algo_id hash_algo_id;
    azihsm_mgf1_id mgf_id;
    const azihsm_buffer *label;
};
```

**Fields**

 | Field        | Type                              | Description                                        |
 | ------------ | --------------------------------- | -------------------------------------------------- |
 | hash_algo_id | [azihsm_algo_id](#azihsm_algo_id) | [hash algorithm id](#azihsm_algo_id_xxx)           |
 | mgf1         | [azihsm_mgf1_id](#azihsm_mgf1_id) | [mask generation function id](#azihsm_mgf1_id_xxx) |
 | label        | [azihsm_buffer *](#azihsm_buffer) | label                                              |


### azihsm_algo_rsa_aes_key_wrap_params

RSA AES Key wrap parameters.

```cpp
struct azihsm_algo_rsa_aes_key_wrap_params {
    azihsm_u32 aes_key_bits;
    azihsm_algo_rsa_pkcs_oaep_params *oaep_params;
};
```

| Field        | Type                               | Description                    |
| ------------ | ---------------------------------- | ------------------------------ |
| aes_key_bits | [azihsm_u32](#azihsm_u32)          | length of the AES key in bits. |
|              |                                    | can be only 128, 192 or 256    |
| oaep_params  | azihsm_algo_rsa_pkcs_oaep_params * | OAEP parameters                |

### azihsm_algo_echd_params

ECDH Algorithm parameters

Parameters for ECDH Algorithm

```cpp
struct azihsm_algo_ecdh_params {
    azihsm_buffer *pub_key;
};
```

| Field   | Type                              | Description                           |
| ------- | --------------------------------- | ------------------------------------- |
| pub_key | [azihsm_buffer *](#azihsm_buffer) | public key of the initiator    &nbsp; |

### azihsm_algo_aes_cbc_params

Parameters for AES CBC Algorithm

```cpp
struct azihsm_algo_aes_cbc_params {
    azihsm_buffer *iv;
};
```

| Field | Type                              | Description                                       |
| ----- | --------------------------------- | ------------------------------------------------- |
| iv    | [azihsm_buffer *](#azihsm_buffer) | initialization vector. must be 16 bytes    &nbsp; |

### azihsm_algo_aes_gcm_params

Parameters for AES GCM Algorithm

```cpp
struct azihsm_algo_aes_gcm_params {
    uint8_t iv[12];
    uint8_t tag[16];
    azihsm_buffer *aad;
};
```

| Field | Type                              | Description                                                               |
| ----- | --------------------------------- | ------------------------------------------------------------------------- |
| iv    | uint8_t[12]                       | initialization vector. must be 12 bytes                            &nbsp; |
| tag   | uint8_t[16]                       | authentication tag (16 bytes). required for decrypt                &nbsp; |
| aad   | [azihsm_buffer *](#azihsm_buffer) | additional authenticated data (optional). may be NULL             &nbsp;  |


### azihsm_algo_aes_xts_params

Parameters for AES XTS Algorithm

```cpp
struct azihsm_algo_aes_xts_params {
    uint8_t sector_num[16];
    uint32_t data_unit_length;
};
```

| Field            | Type     | Description                                                           |
| ---------------- | -------  | --------------------------------------------------------------------- |
| sector_num       | uint8_t  | sector or data unit sequence number                            &nbsp; |
| data_unit_length | uint32_t | data unit length                                               &nbsp; |


### azihsm_algo_hkdf_params

Parameters for HKDF Algorithm

```cpp
struct azihsm_algo_hkdf_params {
    azihsm_algo_id hmac_algo_id;
    azihsm_buffer *salt;
    azihsm_buffer *info;
};
```

| Field        | Type                              | Description                                      |
| ------------ | --------------------------------- | ------------------------------------------------ |
| hmac_algo_id | [azihsm_algo_id](#azihsm_algo_id) | HMAC algorithm                            &nbsp; |
| salt         | [azihsm_buffer *](#azihsm_buffer) | salt                                             |
| info         | [azihsm_buffer *](#azihsm_buffer) | info                                             |

### azihsm_algo_kbdf_counter_params

Parameters for SP 800-108 Counter KDF Algorithm

```cpp
struct azihsm_algo_kbdf_counter_params {
    azihsm_algo_id hmac_algo_id;
    azihsm_buffer *label;
    azihsm_buffer *context;
};
```

| Field        | Type                              | Description                                      |
| ------------ | --------------------------------- | ------------------------------------------------ |
| hmac_algo_id | [azihsm_algo_id](#azihsm_algo_id) | HMAC algorithm                            &nbsp; |
| label        | [azihsm_buffer *](#azihsm_buffer) | label                                            |
| context      | [azihsm_buffer *](#azihsm_buffer) | context                                          |
