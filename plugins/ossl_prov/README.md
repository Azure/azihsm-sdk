# AZIHSM-OpenSSL-Provider
The OpenSSL Provider in combination with the azihsm-sdk library enables secure cryptographic operations using OpenSSL and the Azure Integrated HSM.

## Installation

To install and test the Azure Integrated HSM OpenSSL Provider, follow these steps:

## OpenSSL from Source

Set your current PWD as working directory and create a new directory for the OpenSSL build artifacts:
```
export OPENSSL_WORKSPACE=$(pwd)
mkdir $OPENSSL_WORKSPACE/openssl-build
```

Download the OpenSSL source from the Github repository:
```
git clone https://github.com/openssl/openssl.git
cd openssl
./Configure --prefix=$OPENSSL_WORKSPACE/openssl-build
make -j$(nproc)
```

Go back into your working directory:
```
cd $OPENSSL_WORKSPACE
```

Export the path to the OpenSSL libraries that should be used for building the OpenSSL Provider:
```
export OPENSSL_DIR=$OPENSSL_WORKSPACE/openssl
export OPENSSL_LIB_DIR=$OPENSSL_WORKSPACE/openssl/lib
export OPENSSL_INCLUDE_DIR=$OPENSSL_WORKSPACE/openssl/include
```

Clone the azihsm-sdk repository:
```
git clone https://github.com/Azure/azihsm-sdk.git
cd azihsm-sdk
```

Build the azihsm-sdk library:
```
cargo build --package azihsm
```

for development, you can use the mock library:
```
cargo build --features mock --package azihsm
```

Both libraries are built in debug mode. Once the build is complete, build the OpenSSL Provider:
```
cd plugins/openssl
./build.sh build-type debug
```

All necessary components have been built. Now you have to move back to the $OPENSSL_WORKSPACE directory and bring it all together.
```
cd $OPENSSL_WORKSPACE

mkdir -p "${OPENSSL_WORKSPACE}/openssl-build/bin"
mkdir -p "${OPENSSL_WORKSPACE}/openssl-build/lib64/ossl-modules"
mkdir -p "${OPENSSL_WORKSPACE}/openssl-build/lib64/pkgconfig"
mkdir -p "${OPENSSL_WORKSPACE}/openssl-build/include"


cp "${OPENSSL_WORKSPACE}/openssl/apps/openssl" "${OPENSSL_WORKSPACE}/openssl-build/bin/openssl"
chmod +x "${OPENSSL_WORKSPACE}/openssl-build/bin/openssl"

cp "${OPENSSL_WORKSPACE}/openssl/libssl.so.3" "${OPENSSL_WORKSPACE}/openssl-build/lib64/libssl.so.3"
cp "${OPENSSL_WORKSPACE}/openssl/libssl.so.4" "${OPENSSL_WORKSPACE}/openssl-build/lib64/libssl.so.4"
cp "${OPENSSL_WORKSPACE}/openssl/libcrypto.so.3" "${OPENSSL_WORKSPACE}/openssl-build/lib64/libcrypto.so"
cp "${OPENSSL_WORKSPACE}/openssl/libcrypto.so.4" "${OPENSSL_WORKSPACE}/openssl-build/lib64/libcrypto.so.4"

cd "${OPENSSL_WORKSPACE}/openssl-build/lib64"
ln -sf libssl.so.3 libssl.so
ln -sf libcrypto.so.3 libcrypto.so

cd $OPENSSL_WORKSPACE
cp "${OPENSSL_WORKSPACE}/openssl/libssl.a" "${OPENSSL_WORKSPACE}/openssl-build/lib64/libssl.a"
cp "${OPENSSL_WORKSPACE}/openssl/libcrypto.a" "${OPENSSL_WORKSPACE}/openssl-build/lib64/libcrypto.a"

cp "${OPENSSL_WORKSPACE}/openssl/providers/legacy.so" "${OPENSSL_WORKSPACE}/openssl-build/lib64/ossl-modules/legacy.so"
cp "${OPENSSL_WORKSPACE}/azihsm-sdk/plugins/openssl/build/azihsm.so" "${OPENSSL_WORKSPACE}/openssl-build/lib64/ossl-modules/azihsm.so"

cp "${OPENSSL_WORKSPACE}/azihsm-sdk/target/debug/libazihsm.so" "${OPENSSL_WORKSPACE}/openssl-build/lib64/libazihsm.so"

cp -r "${OPENSSL_WORKSPACE}/openssl/include/openssl" "${OPENSSL_WORKSPACE}/openssl-build/include/"
cp "${OPENSSL_WORKSPACE}/openssl/openssl.pc" "${OPENSSL_WORKSPACE}/openssl-build/lib64/pkgconfig/"
```

And now export the necessary environment variables:
```
export PATH="${OPENSSL_WORKSPACE}/openssl-build/bin:${PATH}"
export LD_LIBRARY_PATH="${OPENSSL_WORKSPACE}/openssl-build/lib64:${LD_LIBRARY_PATH}"
export PKG_CONFIG_PATH="${OPENSSL_WORKSPACE}/openssl-build/lib64/pkgconfig:${PKG_CONFIG_PATH}"
export OPENSSL_MODULES="${OPENSSL_WORKSPACE}/openssl-build/lib64/ossl-modules"
```

and run the following command to verify the installation:
```
openssl version -a
```

## Usage
TBD
