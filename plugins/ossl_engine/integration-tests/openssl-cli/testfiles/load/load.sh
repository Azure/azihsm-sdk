# RUN: @bash -ea @file @keydir
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Stage a masked EC key blob, then load it through the engine's
# ENGINE_load_private_key path and print its public half.
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

blob="$KEYDIR/ec_key.bin"
rm -f "$blob"

# Generate the masked blob out-of-process (shares the keymat set above).
"$MASKED_KEYGEN" "$blob"

# Load it via the engine (real ENGINE_load_private_key) and emit the public key.
"$OPENSSL_BIN" pkey -engine azihsm -inform engine -in "azihsm://$blob;type=ec" -pubout

# CHECK: BEGIN PUBLIC KEY
