# AES Algorithm Support in Azure Integrated HSM (AZIHSM) KSP

## Introduction
This document provides a detailed description of the technical implementation of the AES Algorithm support in AZIHSM Key Storage Provider (AZIHSM-KSP). It covers the usage of NCRYPT APIs to target the AES algorithm, including specific data sizes, buffers, flags, and other relevant details.

## Overview
The AES (Advanced Encryption Standard) algorithm is widely used for securing data. This document describes how to use the AES algorithm using NCRYPT APIs. The focus is on three modes of AES: CBC (Cipher Block Chaining), GCM (Galois/Counter Mode), and XTS.

## AES Algorithm Modes
- [AES-CBC](./aes-cbc.md)
- [AES-GCM](./aes-gcm.md)
- [AES-XTS](./aes-xts.md)