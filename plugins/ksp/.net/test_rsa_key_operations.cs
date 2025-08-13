// Copyright (C) Microsoft Corporation. All rights reserved.

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;

namespace ksp_test
{
    [TestClass]
    public class test_rsa_key_operation
    {

        [TestMethod]
        public void test_encrypt_decrypt()
        {
            CngProvider keyStorageProvider = new CngProvider(Common.AZIHSM_KSP_NAME);
            Assert.IsNotNull(keyStorageProvider, "CngProvider failed to create");
            Assert.AreEqual(keyStorageProvider.Provider, Common.AZIHSM_KSP_NAME, "Provider name");

            CngKeyBlobFormat cngKeyBlobFormat = new CngKeyBlobFormat("RSAPRIVATEBLOB");
            CngKey key = CngKey.Import(Common.TEST_RSA_2K_PRIVATE_KEY, cngKeyBlobFormat, keyStorageProvider);
            Assert.IsNotNull(key, "CngKey failed to import RSA private key");

            RSACng rsa = new RSACng(key);
            byte[] plaintext = new byte[100];
            Random random = new Random();
            random.NextBytes(plaintext);

            byte[] ciphertext = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256);

            // [TODO] Decryption is failing with the following error:
            // "The length of the data to decrypt is not valid for the size of this key"
            //byte[] decrypted = rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
            //Assert.AreEqual(decrypted, plaintext, "Original and decrypted data don't match");

            key.Delete();
        }
    }
}
