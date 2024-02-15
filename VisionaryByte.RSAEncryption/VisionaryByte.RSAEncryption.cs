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
                    var result = pemReader.ReadObject();
                    var rsaEngine = new Pkcs1Encoding(new RsaEngine());
                    return new RsaCryptoServiceProvider(rsaEngine, result);
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
        private readonly object keyPair;

        public RsaCryptoServiceProvider(IAsymmetricBlockCipher rsaEngine, object keyPair)
        {
            this.rsaEngine = rsaEngine;
            this.keyPair = keyPair;
        }

        public string EncryptWithPublic(string clearText)
        {
            var cipher = keyPair as AsymmetricCipherKeyPair;
            var parameter = default(RsaKeyParameters);
            if (cipher == null)
            {
                parameter = keyPair as RsaKeyParameters;
            }
            if ((parameter != null && parameter.IsPrivate) || (cipher != null && cipher.Private.IsPrivate))
            {
                throw new InvalidOperationException("This instance does not contain a private key.");
            }

            var bytesToEncrypt = Encoding.UTF8.GetBytes(clearText);
            rsaEngine.Init(true, parameter ?? cipher!.Public);
            var encryptedBytes = rsaEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length);
            return Convert.ToBase64String(encryptedBytes);
        }

        public string DecryptWithPrivate(string encryptedText)
        {
            var cipher = keyPair as AsymmetricCipherKeyPair;
            var parameter = default(RsaKeyParameters);
            if (cipher == null)
            {
                parameter = keyPair as RsaKeyParameters;
            }
            if ((parameter != null && !parameter.IsPrivate) || (cipher != null && !cipher.Private.IsPrivate))
            {
                throw new InvalidOperationException("This instance does not contain a private key.");
            }

            var bytesToDecrypt = Convert.FromBase64String(encryptedText);
            rsaEngine.Init(false, parameter ?? cipher!.Private);
            var decryptedBytes = rsaEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}