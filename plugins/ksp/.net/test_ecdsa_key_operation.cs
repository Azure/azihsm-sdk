using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using System.Text;

namespace ksp_test
{
    [TestClass]
    public class test_ecdsa_key_operation
    {
        [TestMethod]
        public void test_ecdsa_p256_sign_verify()
        {
            var keyStorageProvider = new CngProvider(Common.AZIHSM_KSP_NAME);
            Assert.IsNotNull(keyStorageProvider, "CngProvider failed to create");
            Assert.AreEqual(keyStorageProvider.Provider, Common.AZIHSM_KSP_NAME, "Provider name");

            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.Provider = keyStorageProvider;
            keyCreationParameters.Parameters.Add(new CngProperty("ECCCurveName", Encoding.Unicode.GetBytes("nistP256"), CngPropertyOptions.None));

            CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, null, keyCreationParameters);
            Assert.IsNotNull(key, "CngKey failed to create");

            ECDsaCng ecdsa = new ECDsaCng(key);
            byte[] data = RandomNumberGenerator.GetBytes(20);
            var signature = ecdsa.SignData(data);
            Assert.AreEqual(64, signature.Length, "Signature length");
            var isVerified = ecdsa.VerifyData(data, signature);
            Assert.IsTrue(isVerified, "Signature verification failed.");

            key.Delete();
        }

        [TestMethod]
        public void test_ecdsa_p384_sign_verify()
        {
            var keyStorageProvider = new CngProvider(Common.AZIHSM_KSP_NAME);
            Assert.IsNotNull(keyStorageProvider, "CngProvider failed to create");
            Assert.AreEqual(keyStorageProvider.Provider, Common.AZIHSM_KSP_NAME, "Provider name");

            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.Provider = keyStorageProvider;
            keyCreationParameters.Parameters.Add(new CngProperty("ECCCurveName", Encoding.Unicode.GetBytes("nistP384"), CngPropertyOptions.None));

            CngKey key = CngKey.Create(CngAlgorithm.ECDsaP384, null, keyCreationParameters);
            Assert.IsNotNull(key, "CngKey failed to create");

            ECDsaCng ecdsa = new ECDsaCng(key);
            byte[] data = RandomNumberGenerator.GetBytes(20);
            var signature = ecdsa.SignData(data);
            Assert.AreEqual(96, signature.Length, "Signature length");

            var isVerified = ecdsa.VerifyData(data, signature);
            Assert.IsTrue(isVerified, "Signature verification failed.");

            key.Delete();
        }

        [TestMethod]
        public void test_ecdsa_p521_sign_verify()
        {
            var keyStorageProvider = new CngProvider(Common.AZIHSM_KSP_NAME);
            Assert.IsNotNull(keyStorageProvider, "CngProvider failed to create");
            Assert.AreEqual(keyStorageProvider.Provider, Common.AZIHSM_KSP_NAME, "Provider name");

            CngKeyCreationParameters keyCreationParameters = new CngKeyCreationParameters();
            keyCreationParameters.Provider = keyStorageProvider;
            keyCreationParameters.Parameters.Add(new CngProperty("ECCCurveName", Encoding.Unicode.GetBytes("nistP521"), CngPropertyOptions.None));

            CngKey key = CngKey.Create(CngAlgorithm.ECDsaP521, null, keyCreationParameters);
            Assert.IsNotNull(key, "CngKey failed to create");

            ECDsaCng ecdsa = new ECDsaCng(key);
            byte[] data = RandomNumberGenerator.GetBytes(20);
            var signature = ecdsa.SignData(data);
            Assert.AreEqual(132, signature.Length, "Signature length");

            var isVerified = ecdsa.VerifyData(data, signature);
            Assert.IsTrue(isVerified, "Signature verification failed.");

            key.Delete();
        }
    }
}
