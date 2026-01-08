#!/usr/bin/env bash

set -eux

# Default values
SDK_PATH="../../"
BUILD_TYPE="release"

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --sdk-path)
            SDK_PATH="$2"
            shift 2
            ;;
        --build-type)
            BUILD_TYPE="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# Convert SDK_PATH to absolute path if it's relative
if [[ ! "$SDK_PATH" = /* ]]; then
    SDK_PATH="$(cd "$(dirname "$SDK_PATH")" && pwd)/$(basename "$SDK_PATH")"
fi

mkdir -p build
cd build
cmake .. \
    -DAZIHSM_SDK_PATH="$SDK_PATH" \
    -DAZIHSM_BUILD_TYPE="$BUILD_TYPE"
cmake --build .

