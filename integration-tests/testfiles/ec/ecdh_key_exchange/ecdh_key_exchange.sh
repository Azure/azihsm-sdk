# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file @curve @cleanup

test -z "$OPENSSL_BIN" && OPENSSL_BIN=../../openssl-build/bin/openssl
test -z "$PROVIDER_PATH" && PROVIDER_PATH=../target/debug
test -z "$PROPQUERY" && PROPQUERY="?provider=azihsm"
test -z "$OPENSSL_LIB" && OPENSSL_LIB=../../openssl-build/lib64
export LD_LIBRARY_PATH="$OPENSSL_LIB"

curve=P-$1
cleanup=$2
keyfile_priv=./ecdh_peer_ec_"$curve"_priv.pem
keyfile_pub=./ecdh_peer_ec_"$curve"_pub.pem
maskedkeyfile=./ecdh_masked_"$curve"_imported.bin
shared_secret=./ecdh_shared_secret_"$curve".bin

"$OPENSSL_BIN" genpkey \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -algorithm EC \
    -pkeyopt "group:$curve" \
    -pkeyopt azihsm.key_usage:keyAgreement \
    -pkeyopt "azihsm.masked_key:"$maskedkeyfile""\
    -outform DER \
    -out /dev/null

"$OPENSSL_BIN" genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:$curve \
    -out $keyfile_priv

"$OPENSSL_BIN" pkey -in "$keyfile_priv" \
        -pubout -out "$keyfile_pub" \
        2>/dev/null

"$OPENSSL_BIN" pkeyutl \
    -derive \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -inkey "azihsm://"$maskedkeyfile";type=ec" \
    -peerkey "$keyfile_pub" \
    -pkeyopt "output_file:$shared_secret"


#CHECK: file created
if [[ -f $shared_secret && -s $shared_secret ]]; then
  echo "file created"
fi

if [[ "$cleanup" == "true" ]]; then
    rm $keyfile_priv
    rm $keyfile_pub
    rm $maskedkeyfile
    rm $shared_secret
fi
