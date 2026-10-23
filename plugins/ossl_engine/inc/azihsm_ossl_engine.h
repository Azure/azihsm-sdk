// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/*
 * Public constants of the azihsm OpenSSL 1.1.x engine.
 */

/*
 * EVP_CIPHER_CTX_ctrl() type: attach an HSM AES key to an AES-CBC context of
 * the engine's ciphers. ptr is a NUL-terminated
 * "azihsm://<masked-key-file>;type=aes[;bits=<n>]" URI and arg must be 0. The
 * key size must match the cipher (e.g. 256 bits for NID_aes_256_cbc).
 *
 * Pass the engine to the first init, attach the key, then set the IV:
 *
 *   EVP_EncryptInit_ex(ctx, ENGINE_get_cipher(e, NID_aes_256_cbc), e, NULL, NULL);
 *   EVP_CIPHER_CTX_ctrl(ctx, AZIHSM_CTRL_SET_KEY_URI, 0,
 *                       (void *)"azihsm:///keys/aes256.bin;type=aes");
 *   EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv);
 *   EVP_EncryptUpdate(ctx, ...);
 *   EVP_EncryptFinal_ex(ctx, ...);
 *
 * The last key set wins: the key stays attached across inits that keep the
 * cipher (e.g. a new IV for the next message) until a raw-key init or another
 * AZIHSM_CTRL_SET_KEY_URI replaces it. The HSM-side key is released when it
 * is replaced or the context is cleaned up; the masked key file is not
 * modified.
 */
#define AZIHSM_CTRL_SET_KEY_URI 0x415A0001

/*
 * ENGINE_ctrl_cmd_string() command: generate an AES key in the HSM and write
 * its masked key file, replacing any file there. The argument is
 * "azihsm://<masked-key-file>;type=<t>[;bits=<n>]" with type aes (128, 192 or
 * 256 bits; default 256), aes-gcm (256) or aes-xts (512). An aes key attaches
 * to the AES-CBC cipher of its size with AZIHSM_CTRL_SET_KEY_URI.
 *
 *   ENGINE_ctrl_cmd_string(e, AZIHSM_CMD_GENERATE_KEY,
 *                          "azihsm:///keys/aes256.bin;type=aes", 0);
 *
 * From the command line:
 *
 *   openssl engine -t -post 'GENERATE_KEY:azihsm:///keys/aes256.bin;type=aes' <engine>
 */
#define AZIHSM_CMD_GENERATE_KEY "GENERATE_KEY"
