// Copyright (C) Microsoft Corporation. All rights reserved.

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;
using System.Text;

namespace ksp_test
{
    [TestClass]
    public class test_key_operation
    {
        [TestMethod]
        public void test_create_delete_key()
        {
            CngProvider keyStorageProvider = new CngProvider(Common.AZIHSM_KSP_NAME);
            Assert.IsNotNull(keyStorageProvider, "CngProvider failed to create");
            Assert.AreEqual(keyStorageProvider.Provider, Common.AZIHSM_KSP_NAME, "Provider name");

            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.Provider = keyStorageProvider;
            keyCreationParameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(128), CngPropertyOptions.None));
            keyCreationParameters.Parameters.Add(new CngProperty("Chaining Mode", Encoding.Unicode.GetBytes("ChainingModeCBC"), CngPropertyOptions.None));

            CngKey key = CngKey.Create(new CngAlgorithm("AES"), null, keyCreationParameters);
            Assert.IsNotNull(key, "CngKey failed to create");

            key.Delete();
        }

        [TestMethod]
        public void test_create_fail_persisted_key()
        {

            CngProvider keyStorageProvider = new CngProvider(Common.AZIHSM_KSP_NAME);
            Assert.IsNotNull(keyStorageProvider, "CngProvider failed to create");
            Assert.AreEqual(keyStorageProvider.Provider, Common.AZIHSM_KSP_NAME, "Provider name");

            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.Provider = keyStorageProvider;
            keyCreationParameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(128), CngPropertyOptions.None));
            keyCreationParameters.Parameters.Add(new CngProperty("Chaining Mode", Encoding.Unicode.GetBytes("ChainingModeCBC"), CngPropertyOptions.None));

            try
            {
                CngKey cngKey = CngKey.Create(new CngAlgorithm("AES"), "test_key", keyCreationParameters);
                Assert.IsTrue(false, "CngKey should not be created");
            }
            catch (CryptographicException e)
            {
                Assert.AreEqual((UInt32)e.HResult, (UInt32)Common.HRESULT.NTE_NOT_SUPPORTED);
            }
        }
    }
}
