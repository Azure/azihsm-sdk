## AES XTS
AES-XTS (Advanced Encryption Standard in XEX-based Tweaked Codebook Mode with Ciphertext Stealing) is an encryption algorithm designed to provide confidentiality for fixed-size data blocks. It uses the AES block cipher as a subroutine and incorporates a tweakable block cipher to address threats.

### NCRYPT API Usage Targeting AES-XTS

#### Initialization
1. **Create an AES Key**
    - NCRYPT API to use: `NCryptCreatePersistedKey()`
    - Algorithm ID: `BCRYPT_XTS_AES_ALGORITHM`
    - Flags to use: `NCRYPT_DO_NOT_FINALIZE_FLAG`

2. **Set Property**
    - NCRYPT API to use: `NCryptSetProperty()`
    - **Setting the Key Length**
        - Property Identifier to use to set Key Length: `NCRYPT_LENGTH_PROPERTY`
        - Expected Key Length: 512
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
        `pbIV`: A pointer to the tweak used by XTS. The tweak should be `16 bytes` in size.
        `cbIV`: The size of the tweak.
        Other fields in the `NCRYPT_CIPHER_PADDING_INFO` structure, such as `cbOtherInfo`, `pbOtherInfo`, `dwFlags` are unused.
        

#### Decryption
1. NCRYPT API to use: `NCryptDecrypt()`
2. Flags used for `NCryptEncrypt()` call:  
    - In this case flag    `NCRYPT_PAD_CIPHER_FLAG` need to be specified.
3. Padding info is of type `NCRYPT_CIPHER_PADDING_INFO`
    - Fields expected to be populated as part of the padding info structure:
        `cbSize`: The size of the structure.
        `pbIV`: A pointer to the tweak used by XTS. The tweak should be `16 bytes` in size.
        `cbIV`: The size of the tweak.
        Other fields in the `NCRYPT_CIPHER_PADDING_INFO` structure, such as `cbOtherInfo`, `pbOtherInfo`, `dwFlags` are unused.

#### Note: 
1. As shown in the below code snippet NCryptEncrypt\NcryptDecrypt require two consecutive calls:
    - The first call retrieves the length of the buffer needed for the operation.
    - The second call, with the allocated buffer passed in, writes the output bytes into the buffer

## Examples
Here is a code snippet to use AES-XTS:

```rust
    let mut azihsm_provider: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);
    let mut azihsm_key: NCRYPT_KEY_HANDLE = NCRYPT_KEY_HANDLE(0);
    unsafe {
        let result = NCryptOpenStorageProvider(&mut azihsm_provider, AZIHSM_KSP_NAME, 0);
        assert!(result.is_ok());

        let result = NCryptCreatePersistedKey(
            azihsm_provider,
            &mut azihsm_key,
            BCRYPT_XTS_AES_ALGORITHM,
            None,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(NCRYPT_DO_NOT_FINALIZE_FLAG),
        );
        assert!(result.is_ok());

        // Set Key Length.
        let key_length = 512u32;
        let result = NCryptSetProperty(
            azihsm_key,
            NCRYPT_LENGTH_PROPERTY,
            &key_length.to_le_bytes()[..],
            NCRYPT_FLAGS(0),
        );
        assert!(result.is_ok());

        let result = NCryptFinalizeKey(azihsm_key, NCRYPT_FLAGS(0));
        assert!(result.is_ok());

        let mut tweak = [0u8; 16];
        rand_bytes(&mut tweak).unwrap();

        let padding_info: NCRYPT_CIPHER_PADDING_INFO = NCRYPT_CIPHER_PADDING_INFO {
            cbSize: size_of::<NCRYPT_CIPHER_PADDING_INFO>() as u32,
            pbIV: tweak.as_mut_ptr(),
            cbIV: tweak.len() as u32,
            cbOtherInfo: 0,
            pbOtherInfo: std::ptr::null_mut(),
            dwFlags: 0,
        };

        let mut plaintext = vec![0; 1024 * 1024];
        let plaintext_len = plaintext.len() as u32;
        let mut ciphertext_len = 0u32;
        rand_bytes(&mut plaintext).unwrap();

        // First call - Get the ciphertext length.
        let result = NCryptEncrypt(
            azihsm_key,
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(ciphertext_len, plaintext_len);

        // Second call - Encrypt the plaintext.
        let mut ciphertext = vec![0u8; ciphertext_len as usize];
        let result = NCryptEncrypt(
            azihsm_key,
            Some(&plaintext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut ciphertext),
            ptr::addr_of_mut!(ciphertext_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // First call - Get the decrypted data length.
        let mut decrypted_len = 0u32;
        let result = NCryptDecrypt(
            azihsm_key,
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            None,
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());
        assert_eq!(decrypted_len, plaintext_len);

        // Second call - Decrypt the ciphertext.
        let mut decrypted = vec![0u8; decrypted_len as usize];
        let result = NCryptDecrypt(
            azihsm_key,
            Some(&ciphertext),
            Some(ptr::addr_of!(padding_info) as *const std::ffi::c_void),
            Some(&mut decrypted),
            ptr::addr_of_mut!(decrypted_len),
            NCRYPT_FLAGS(NCRYPT_PAD_CIPHER_FLAG),
        );
        assert!(result.is_ok());

        // Compare the plaintext and decrypted data.
        assert_eq!(plaintext, decrypted);

        let result = NCryptDeleteKey(azihsm_key, NCRYPT_SILENT_FLAG.0);
        assert!(result.is_ok());

        let result = NCryptFreeObject(azihsm_provider);
        assert!(result.is_ok());
    }