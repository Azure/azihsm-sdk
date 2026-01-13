# Copyright (C) Microsoft Corporation. All rights reserved.

SDK_PATH ?= ../../
BUILD_TYPE ?= debug
ENABLE_WERROR ?= OFF

BUILD_DIR := build
PROVIDER_LIB := $(BUILD_DIR)/azihsm.so

RM := rm -rf
MKDIR := mkdir -p
CMAKE := cmake

# Convert relative SDK_PATH to absolute
ifeq ($(shell echo $(SDK_PATH) | head -c 1),/)
    SDK_PATH_ABS := $(SDK_PATH)
else
    SDK_PATH_ABS := $(shell cd $(SDK_PATH) && pwd)
endif

.PHONY: build clean help all rebuild test check warnings strict
.DEFAULT_GOAL := build

build:
	@echo "Building provider (BUILD_TYPE=$(BUILD_TYPE), SDK_PATH=$(SDK_PATH_ABS))..."
	@$(MKDIR) $(BUILD_DIR)
	cd $(BUILD_DIR) && \
		$(CMAKE) .. \
			-DAZIHSM_SDK_PATH="$(SDK_PATH_ABS)" \
			-DAZIHSM_BUILD_TYPE="$(BUILD_TYPE)" \
			-DENABLE_WERROR="$(ENABLE_WERROR)" && \
		$(CMAKE) --build . --verbose

clean:
	@echo "Cleaning build artifacts..."
	@$(RM) $(BUILD_DIR)

all: build
