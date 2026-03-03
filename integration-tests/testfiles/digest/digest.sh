# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# RUN: @bash -ea @file  @dgst @cleanup

test -z "$OPENSSL_BIN" && OPENSSL_BIN=../../openssl-build/bin/openssl
test -z "$PROVIDER_PATH" && PROVIDER_PATH=../target/debug
test -z "$PROPQUERY" && PROPQUERY="?provider=azihsm"
test -z "$OPENSSL_LIB" && OPENSSL_LIB=../../openssl-build/lib64
export LD_LIBRARY_PATH="$OPENSSL_LIB"

parent_folder="$(dirname "$0")"
dgst=sha$1
cleanup=$2
testdata=testdata.bin

# Create test data
dd if=/dev/urandom of="$testdata" bs=1024 count=1

# Compute digest via provider
provider_dgst=$("$OPENSSL_BIN" dgst -"$dgst" \
    -provider-path "$PROVIDER_PATH" \
    -provider default \
    -provider azihsm_provider \
    -propquery "$PROPQUERY" \
    -r "$testdata" | awk '{print $1}')

# Compute digest via default provider for reference
default_dgst=$("$OPENSSL_BIN" dgst -"$dgst" -r "$testdata" | awk '{print $1}')

#CHECK: digests match
if [[ "$provider_dgst" == "$default_dgst" ]]; then
  echo "digests match"
else
  echo "FAIL - digest mismatch"
  echo "provider: $provider_dgst"
  echo "default:  $default_dgst"
  exit 1
fi

if [[ "$cleanup" == "true" ]]; then
  rm -f "$testdata"
fi
