## AES CBC
AES CBC mode provides confidentiality by chaining blocks of plaintext together. Each block of plaintext is XORed with the previous ciphertext block before being encrypted.

### NCRYPT API Usage Targeting AES-CBC

#### Initialization
1. **Create an AES Key**
    - NCRYPT API to use: `NCryptCreatePersistedKey()`
    - Algorithm ID: `BCRYPT_AES_ALGORITHM`
    - Flags to use: `NCRYPT_DO_NOT_FINALIZE_FLAG`

2. **Set Property**
    - NCRYPT API to use: `NCryptSetProperty()`
    - **Setting the Encryption Mode**
        - Property Identifier to use to set the chaining mode: `NCRYPT_CHAINING_MODE_PROPERTY`
        - BCRYPT Identifier to set Encryption mode: `BCRYPT_CHAIN_MODE_CBC`
        - Flags to use for Set Property: None
    - **Setting the Key Length**
        - Property Identifier to use to set Key Length: `NCRYPT_LENGTH_PROPERTY`
        - Expected Key Length: 128, 192, or 256
        - Flags to use for Set Property: None

3. **Call Finalize to finalize the key and its properties**
    - NCRYPT API to use: `NCryptFinalizeKey()`
    - Flags to use: `None`

#### Encryption
1. NCRYPT API to use: `NCryptEncrypt()`
2. Flags used for `NCryptEncrypt()` call:  
    - In this case flag    `NCRYPT_PAD_CIPHER_FLAG` need to be specified.
3. Padding info is of type `NCRYPT_CIPHER_PADDING_INFO`
    - Fields expected to be populated as part of the padding info structure: 
        `cbSize`: The size of the structure.
        `pbIV`: A pointer to the initialization vector (IV). The IV should be `16 bytes` in size.
        `cbIV`: The size of the IV.
        Other fields in the `NCRYPT_CIPHER_PADDING_INFO` structure, such as `cbOtherInfo`, `pbOtherInfo`, `dwFlags` are unused.

#### Decryption
1. NCRYPT API to use: `NCryptDecrypt()`
2. Flags used for `NCryptDecrypt()` call:  
    - In this case flag    `NCRYPT_PAD_CIPHER_FLAG` need to be specified.
3. Padding info is of type `NCRYPT_CIPHER_PADDING_INFO`
    - Fields expected to be populated as part of the padding info structure: 
        `cbSize`: The size of the structure.
        `pbIV`: A pointer to the initialization vector (IV). The IV should be `16 bytes` in size.
        `cbIV`: The size of the IV.
        Other fields in the `NCRYPT_CIPHER_PADDING_INFO` structure, such as `cbOtherInfo`, `pbOtherInfo`, `dwFlags` are unused.

#### Note: 
1. As shown in the below code snippet NCryptEncrypt\NcryptDecrypt require two two consecutive calls:
    - The first call retrieves the length of the buffer needed for the operation.
    - The second call, with the allocated buffer passed in, writes the output bytes into the buffer

## Examples
Here is a code snippet to use AES-CBC:

```rust
    let mut azihsm_provider: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);
    let mut azihsm_key: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE(0);
    unsafe{
        // Open handle to the KSP.
        // AZIHSM_KSP_NAME = "Microsoft Azure Integrated HSM Key Storage Provider";
        let result = NCryptOpenStorageProvider(&mut azihsm_provider, AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        // Create a Key using BCRYPT_AES_ALGORITHM as algo ID
        let result = NCryptCreatePersistedKey(
            azihsm_provider,
            &mut azihsm_key,
            BCRYPT_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Encryption Mode.
        let encryption_mode = std::slice::from_raw_parts(
            BCRYPT_CHAIN_MODE_CBC.as_ptr().cast::(),
            BCRYPT_CHAIN_MODE_CBC.to_string().unwrap().len() * size_of::(),
        );

        let result = NCryptSetProperty(
            azihsm_key,
            NCRYPT_CHAINING_MODE_PROPERTY,
            encryption_mode,
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 128u32;
        let result = NCryptSetProperty(
            azihsm_key,
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        // Finalize the key
        let result = NCryptFinalizeKey(azihsm_key, NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        // Initialize IV
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();
        let mut iv_orig = iv.clone();

        // Populate Pading info structure
        let mut padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::() as u32,
            pbIV: iv.as_mut_ptr(),
            cbIV: iv.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = [0u8; 128];
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        // Get Ciphertext length
        let result = NCryptEncrypt(
            azihsm_key,
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Allocate buffer for ciphertext
        let mut ciphertext = vec![0u8; ciphertext_len as usize];

        // Get Ciphertext
        let result = NCryptEncrypt(
            azihsm_key,
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Decrypt
        let mut decrypted_len = 0u32;

        // Get Decrypted length
        let result = NCryptDecrypt(
            azihsm_key,
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Allocate buffer for decrypted text
        let mut decrypted = vec![0u8; decrypted_len as usize];

        // Get Decrypted text
        let result = NCryptDecrypt(
            azihsm_key,
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(plaintext, decrypted);
    }