# Build the wrap_key tool against the azihsm provider and native API.
#
# Prerequisites:
#   - The ossl_prov CMake build must have run (produces azihsm.h and libazihsm_api_native.so)
#   - OpenSSL 3.x dev headers, libbsd-dev
#
# Usage:
#   make                          # debug build (default)
#   make BUILD_TYPE=release       # release build
#   make clean

BUILD_TYPE ?= debug
REPO_ROOT  := $(abspath ../..)

# Paths into the Cargo/CMake build tree
TARGET_DIR  := $(REPO_ROOT)/target/$(BUILD_TYPE)
# cbindgen header is generated under the ossl_provider CMake build directory.
# Filter to the provider build (not api_tests) so we get azihsm.h, not azihsm_api.h.
AZIHSM_H_DIR := $(shell find $(TARGET_DIR)/build -path '*/azihsm_ossl_provider-*/cbindgen/azihsm_api_native/include' 2>/dev/null | sort | tail -1)

# Provider sources (for azihsm_ossl_hsm.c / azihsm_ossl_base.c)
PROV_SRC := $(REPO_ROOT)/plugins/ossl_prov/src
PROV_INC := $(REPO_ROOT)/plugins/ossl_prov/inc

CC      ?= gcc
CFLAGS  := -Wall -Wextra -std=c11 -D_GNU_SOURCE
CFLAGS  += -I$(PROV_INC) -I$(AZIHSM_H_DIR)
LDFLAGS := -L$(TARGET_DIR)/deps -L$(TARGET_DIR)
LDLIBS  := -lazihsm_api_native -lcrypto -lbsd

SRCS := wrap_key.c \
        $(PROV_SRC)/azihsm_ossl_hsm.c \
        $(PROV_SRC)/azihsm_ossl_pkey_param.c

.PHONY: all clean

all: wrap_key

wrap_key: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f wrap_key
