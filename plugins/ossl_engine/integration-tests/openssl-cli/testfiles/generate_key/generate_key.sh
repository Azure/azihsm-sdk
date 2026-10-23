# RUN: @bash -ea @file @keydir
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# HSM AES key generation through the engine's key generation ctrl command, run
# by openssl engine -t -post. Every AES key kind and size writes an owner-only
# masked key file; unsupported sizes and a non-AES type fail and write
# nothing. The keys serve the C API only, so their round trips are in the unit
# and C-API tests.
# (lit treats an uppercase word followed by a colon as a directive — keep such
# tokens out of comments here; the command name comes from $cmd.)
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

cmd=GENERATE_KEY

# Run the command on key URI $1; print openssl's status tag for it.
generate() {
    "$OPENSSL_BIN" engine -t -post "$cmd:$1" azihsm | grep -o -E '^\[(Success|Failure)\]'
}

for cfg in "aes 128" "aes 192" "aes 256" "aes-gcm 256" "aes-xts 512"; do
    read -r ktype bits <<< "$cfg"
    key="$KEYDIR/generated_${ktype}_${bits}.bin"
    rm -f "$key"
    test "$(generate "azihsm://$key;type=$ktype;bits=$bits")" = "[Success]"
    test -s "$key"
    test "$(stat -c %a "$key")" = 600
    echo "generate ok: $ktype $bits"
done

# Without bits=, an aes key is 256 bits (the unit tests check the size).
key="$KEYDIR/generated_default.bin"
rm -f "$key"
test "$(generate "azihsm://$key;type=aes")" = "[Success]"
test -s "$key"
echo "generate ok: aes default"

key="$KEYDIR/generated_bad.bin"
for attrs in "type=aes;bits=100" "type=aes-gcm;bits=128" "type=aes-xts;bits=256" "type=ec"; do
    rm -f "$key"
    test "$(generate "azihsm://$key;$attrs")" = "[Failure]"
    test ! -e "$key"
done
echo "generate rejects bad sizes and types"

# CHECK: generate ok: aes 128
# CHECK: generate ok: aes 192
# CHECK: generate ok: aes 256
# CHECK: generate ok: aes-gcm 256
# CHECK: generate ok: aes-xts 512
# CHECK: generate ok: aes default
# CHECK: generate rejects bad sizes and types
