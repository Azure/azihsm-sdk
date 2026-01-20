# OpenSSL Provider

The overall goal is to implement an OpenSSL provider for the Azure HSM that works with OpenSSL 3.0.x and above - however current focus is 3.0.2 and upwards. We are focusing on symmetric (AES), asymmetric (EC, RSA) key generation and SHA-1/256/384/512 calculation and respectively HMAC generation.

## Generic

### Masked Keys

The HSM has storage restrictions thus most of the generated key material need to be _exported_ as masked keys. Masked keys are keys that have been encrypted with an HSM-specific key. This allows the key to be exported in a safe manner and reimported on the same machine-only. Masked keys are not transferable between different HSMs.

### Parameters

For key generation we will pass in various parameters via the -pkeyopt flag. The parameters will always follow the following format: `azihsm.{varname}:{value}`. We currently have:
- `azihsm.session:` which can be `true` or `false`. Example: `azihsm.session:true`
- `azihsm.masked_key:` which points to the location where the masked key should be **written to**. Example: `azihsm.masked_key:./masked_key.bin`
- `azihsm.priv_key_usage:` indicates what usage is allowed on the private key. Possible values are `sign` or `derive`.
- `azihsm.pub_key_usage:` is similar to private key. Possible values are `verify` or `derive`.

When we pass in a key as parameter i.e. `-inkey` we will use `OSSL_STORE` to resolve the `azihsm://` URI. This will look like this: `-inkey azihsm://{file_location}` - `file_location` will be the location of the masked key.

## AES Key Generation

OpenSSL 3.0.x only supports asymmetric key generation. Symmetric key generation was introduced in OpenSSL 3.5 with `skeyutl`. For now we have to write a custom tool that interfaces with the azihsm-sdk library in order to generate the different AES keys. Depending on the command, we might be able to add masked AES keys as a parameter.

# Generate AES Keys (custom tooling - later skeyutl)

- Generate Session AES Keys
  - Export Masked AES Keys
- Generate Permanent AES Keys

# Generate RSA Keys

- Generate Session RSA Keys
  - Export Masked RSA Keys
- Generate Permanent RSA Keys

# Generate EC Keys

### Code Example: Generate session EC key and export masked key
```
LD_LIBRARY_PATH=$(pwd)/openssl-build/lib64 ./openssl-build/bin/openssl genpkey -provider-path ./azihsm-sdk/target/debug/. \
    -provider default \
    -provider azihsm_provider \
    -propquery "provider=azihsm" \
    -pkeyopt azihsm.session:true \
    -pkeyopt azihsm.masked_key:./masked_key.bin \
    -algorithm EC \
    -pkeyopt group:P-256 \
    -outform DER | xxd
```

### Questions:
- Parameter Design: priv_key_usage for usage?
- Parameter Design: session_key for session?

### Tasks:
- Generate Session EC Keys
  - Export Masked EC Keys
- Generate Permanent EC Keys

# Import Masked Keys
- Import Masked RSA Key
- Import Masked EC Key
- Import Masked AES Key (Custom Tooling)

# Sign and Verify EC

## OpenSSL Example: Sign a file with (masked) session key
```
openssl dgst -sha256 \
  -sign 'azihsm://./session_ec_key.masked' \
  -provider-path ./azihsm_provider \
  -provider azihsm \
  -provider default \
  ./document.txt > document.sig
```

## OpenSSL Example: Sign a file with a permanent key
```
openssl dgst -sha256 \
  -sign 'azihsm://0x12345678' \
  -provider-path ./azihsm_provider \
  -provider azihsm \
  -provider default \
  ./document.txt > document.sig
```

### Questions
- Do we need to support signing with permanent keys?

Tasks:
- Sign EC with specific azihsm handle
- Verify EC with specific azihsm handle

# Sign and Verify RSA

- Sign RSA with specific azihsm handle
- Verify RSA with specific azihsm handle

# HMAC

## OpenSSL Example: Compute HMAC with (masked) session key

```
openssl mac -mac hmac \
  -digest SHA256 \
  -provider-path ./azihsm_provider \
  -provider azihsm \
  -provider default \
  -key 'azihsm://./hmac_key.masked' \
  < ./data.txt > data.hmac
```

## Questions
- Do we need to support permanent keys?
