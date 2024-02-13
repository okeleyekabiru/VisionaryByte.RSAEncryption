using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;
using System.Text;

namespace DotNetRSAEncryption
{
    public static class RsaProviderFactory
    {
        public static string CreateFromPemFile(string pemFilePath)
        {
            try
            {
                return File.ReadAllText(pemFilePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating RSA provider: {ex.Message}");
                throw;
            }
        }

        public static IRsaProvider CreateFromPemString(string pemFilePath)
        {
            try
            {
                var pemContent = CreateFromPemFile(pemFilePath);
                using (var txtreader = new StringReader(pemContent))
                {
                    var pemReader = new PemReader(txtreader);
                    var keyPair = (RsaKeyParameters)pemReader.ReadObject();
                    var rsaEngine = new Pkcs1Encoding(new RsaEngine());
                    return new RsaCryptoServiceProvider(rsaEngine, keyPair);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating RSA provider: {ex.Message}");
                throw;
            }
        }
    }

    public interface IRsaProvider
    {
        string EncryptWithPublic(string clearText);

        string DecryptWithPrivate(string encryptedText);
    }

    public class RsaCryptoServiceProvider : IRsaProvider
    {
        private readonly IAsymmetricBlockCipher rsaEngine;
        private readonly AsymmetricKeyParameter keyPair;

        public RsaCryptoServiceProvider(IAsymmetricBlockCipher rsaEngine, RsaKeyParameters keyPair)
        {
            this.rsaEngine = rsaEngine;
            this.keyPair = keyPair;
        }

        public string EncryptWithPublic(string clearText)
        {
            if (keyPair.IsPrivate)
            {
                throw new InvalidOperationException("This instance does not contain a public key.");
            }

            var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);
            rsaEngine.Init(true, keyPair);
            var encryptedBytes = rsaEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length);
            return Convert.ToBase64String(encryptedBytes);
        }

        public string DecryptWithPrivate(string encryptedText)
        {
            if (!keyPair.IsPrivate)
            {
                throw new InvalidOperationException("This instance does not contain a private key.");
            }

            var bytesToDecrypt = Convert.FromBase64String(encryptedText);
            rsaEngine.Init(false, keyPair);
            var decryptedBytes = rsaEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}