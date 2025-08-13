## AES GCM
AES-GCM (Advanced Encryption Standard in Galois/Counter Mode) is an encryption algorithm that provides both confidentiality and data integrity. It combines the AES block cipher with Galois mode of operation, allowing it to encrypt and authenticate data efficiently. In AES-GCM, each block of plaintext is encrypted using a counter mode, and an authentication tag is generated using Galois field arithmetic to ensure the integrity of the data. 

### NCRYPT API Usage Targeting AES-GCM

#### Initialization
1. **Create an AES Key**
    - NCRYPT API to use: `NCryptCreatePersistedKey()`
    - Algorithm ID: `BCRYPT_AES_ALGORITHM`
    - Flags to use: `NCRYPT_DO_NOT_FINALIZE_FLAG`

2. **Set Property**
    - NCRYPT API to use: `NCryptSetProperty()`
    - **Setting the Encryption Mode**
        - Property Identifier to use to set the chaining mode: `NCRYPT_CHAINING_MODE_PROPERTY`
        - BCRYPT Identifier to set Encryption mode: `BCRYPT_CHAIN_MODE_GCM`
        - Flags to use for Set Property: None
    - **Setting the Key Length**
        - Property Identifier to use to set Key Length: `NCRYPT_LENGTH_PROPERTY`
        - Expected Key Length: 256
        - Flags to use for Set Property: None
        
3. **Call Finalize to finalize the key and its properties**
    - NCRYPT API to use: `NCryptFinalizeKey()`
    - Flags to use: `None`

#### Encryption
1. NCRYPT API to use: `NCryptEncrypt()`
2.  Flags used for `NCryptEncrypt()` call:  
    - In this case flag    `NCRYPT_PAD_CIPHER_FLAG` and `NCRYPT_CIPHER_OTHER_PADDING_FLAG` need to be specified.
3. Padding info is of type `NCRYPT_CIPHER_PADDING_INFO`
    The `NCRYPT_CIPHER_PADDING_INFO` structure is used to specify padding information for encryption operations. The fields that need to be populated in this structure are:
        `cbOtherInfo`: This field specifies the size of the other_info structure.
        `pbOtherInfo`: This parameter should be a pointer to a `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` structure. It contains additional information required for authenticated encryption.
        `dwFlags`: This field specifies the flags to be used for the padding operation. In this case, the flag `NCRYPT_CIPHER_OTHER_PADDING_FLAG` is used.
        Other fields in the `NCRYPT_CIPHER_PADDING_INFO` structure, such as `pbIV` and `cbIV`, are unused.

    The `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` structure is used to provide information for authenticated encryption modes like AES-GCM. The fields that need to be populated in this structure are:
        `cbSize`: The size of the structure.
        `dwInfoVersion`: The version of the structure.
        `pbNonce`: A pointer to the initialization vector (IV). The IV should be `12 bytes` in size.
        `cbNonce`: The size of the IV.
        `pbAuthData`: [Optional] A pointer to the additional authenticated data (AAD). The AAD should be a multiple of `32 bytes` in size.
        `cbAuthData`: The size of the AAD.
        `pbTag`: [Optional] An pointer to the authentication tag.
        `cbTag`: The size of the authentication tag.
        `dwFlags`: This field specifies the flags to be used for the authenticated encryption operation. In this case, the flag `NCRYPT_CIPHER_OTHER_PADDING_FLAG` is used.
        Other fields in the `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` structure, such as `pbMacContext`, `cbMacContext`, `cbAAD`, and `cbData`, are unused.`

#### Decryption
1. NCRYPT API to use: `NCryptDecrypt()`
2.  Flags used for `NCryptDecrypt()` call:  
    - In this case flag    `NCRYPT_PAD_CIPHER_FLAG` and `NCRYPT_CIPHER_OTHER_PADDING_FLAG` need to be specified.
3. Padding info is of type `NCRYPT_CIPHER_PADDING_INFO`
    The `NCRYPT_CIPHER_PADDING_INFO` structure is used to specify padding information for encryption operations. The fields that need to be populated in this structure are:
        `cbOtherInfo`: This field specifies the size of the other_info structure.
        `pbOtherInfo`: This parameter should be a pointer to a `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` structure. It contains additional information required for authenticated encryption.
        `dwFlags`: This field specifies the flags to be used for the padding operation. In this case, the flag `NCRYPT_CIPHER_OTHER_PADDING_FLAG` is used.
        Other fields in the `NCRYPT_CIPHER_PADDING_INFO` structure, such as `pbIV` and `cbIV`, are unused.

    The `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` structure is used to provide information for authenticated encryption modes like AES-GCM. The fields that need to be populated in this structure are:
        `cbSize`: The size of the structure.
        `dwInfoVersion`: The version of the structure.
        `pbNonce`: A pointer to the initialization vector (IV). The IV should be `12 bytes` in size.
        `cbNonce`: The size of the IV.
        `pbAuthData`: [Optional] A pointer to the additional authenticated data (AAD). The AAD should be `16 bytes` in size.
        `cbAuthData`: The size of the AAD.
        `pbTag`: [Optional] An pointer to the authentication tag.
        `cbTag`: The size of the authentication tag.
        `dwFlags`: This field specifies the flags to be used for the authenticated encryption operation. In this case, the flag `NCRYPT_CIPHER_OTHER_PADDING_FLAG` is used.
        Other fields in the `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` structure, such as `pbMacContext`, `cbMacContext`, `cbAAD`, and `cbData`, are unused.`

#### Note: 
1. For AES-GCM Decryption, both `NCRYPT_PAD_CIPHER_FLAG` in flags and `ppaddinginfo` should be provided as mandatory fields.

2. As shown in the below code snippet NCryptEncrypt\NcryptDecrypt require two consecutive calls:
    - The first call retrieves the length of the buffer needed for the operation.
    - The second call, with the allocated buffer passed in, writes the output bytes into the buffer

## Examples
Here is a code snippet to use AES-GCM:

```rust
    let mut azihsm_provider: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);
    let mut azihsm_key: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE(0);
    unsafe {
        // Open handle to the KSP.
        // AZIHSM_KSP_NAME = "Microsoft Azure Integrated HSM Key Storage Provider"; 
        let result = NCryptOpenStorageProvider(&mut azihsm_provider, AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            *azihsm_provider,
            azihsm_key,
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_GCM.as_ptr().cast::<u8>(),
            BCRYPT_CHAIN_MODE_GCM.to_string().unwrap().len() * size_of::<u16>(),
        );

        let result = NCryptSetProperty(
            *azihsm_key,
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 256u32;
        let result = NCryptSetProperty(
            *azihsm_key,
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the Key
        let result = NCryptFinalizeKey(*azihsm_key, NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Generate IV
        let mut iv = [0u8; 12];
        rand_bytes(&mut iv).unwrap();

        // Generate AAD
        let mut aad = [0u8; 16];
        rand_bytes(&mut aad).unwrap();

        // Get the tag length property size
        let mut tag_length_property_size = 0u32;
        let result = NCryptGetProperty(
            azihsm_key,
            BCRYPT_AUTH_TAG_LENGTH,
            None,
            ptr::addr_of_mut!(tag_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );
        assert!(result.is_ok());
        assert_eq!(tag_length_property_size, size_of::<u32>() as u32);

        // Get the tag length property value
        let mut tag_length_bytes = vec![0u8; tag_length_property_size as usize];
        let result = NCryptGetProperty(
            azihsm_key,
            BCRYPT_AUTH_TAG_LENGTH,
            Some(&mut tag_length_bytes),
            ptr::addr_of_mut!(tag_length_property_size),
            OBJECT_SECURITY_INFORMATION(0),
        );
        assert!(result.is_ok());

        let tag_length = u32::from_le_bytes(tag_length_bytes.try_into().unwrap());
        assert_eq!(tag_length, 16);

        // Create the tag buffer
        let tag = vec![0u8; tag_length as usize];

        let mut other_info: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO =
            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
                cbSize: size_of::<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>() as u32,
                dwInfoVersion: 0,
                pbNonce: iv.as_mut_ptr(),
                cbNonce: iv.len() as u32,
                pbAuthData: aad.as_mut_ptr(),
                cbAuthData: aad.len() as u32,
                pbTag: tag.as_mut_ptr(),
                cbTag: tag.len() as u32,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
            };

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: std::ptr::null_mut(),
            cbIV: 0,
            cbOtherInfo: std::mem::size_of_val(&other_info) as u32,
            pbOtherInfo: &mut other_info as *mut _ as *mut u8,
            dwFlags: NCRYPT_CIPHER_OTHER_PADDING_FLAG,
        };

        let mut plaintext = vec![0u8; 256 as usize];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key,
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, 256);
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key,
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());

        // Get Decrypt data length
        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key,
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, 256);
        let mut decrypted = vec![0u8; decrypted_len as usize];

        // Get decrypted data
        let result = NCryptDecrypt(
            azihsm_key,
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(
                NCRYPT_SILENT_FLAG.0
                    | NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG).0
                    | NCRYPT_FLAGS(NCRYPT_CIPHER_OTHER_PADDING_FLAG).0,
            ),
        );
        assert!(result.is_ok());
        // Decrypted data and plantext should be equal
        assert_eq!(plaintext, decrypted);

        let result = NCryptDeleteKey(azihsm_key, NCRYPT_SILENT_FLAG.0);
        assert!(result.is_ok());

        let result = NCryptFreeObject(azihsm_provider);
        assert!(result.is_ok());
    }
