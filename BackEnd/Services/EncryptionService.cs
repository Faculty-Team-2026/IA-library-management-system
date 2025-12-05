using System;
using System.Security.Cryptography;
using System.Text;

namespace BackEnd.Services
{
    public class EncryptionService : IEncryptionService
    {
        private readonly IConfiguration _configuration;

        public EncryptionService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        /// <summary>
        /// Encrypts a string using AES encryption
        /// </summary>
        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            // Configuration values are base64 encoded
            var keyBase64 = _configuration["Encryption:Key"] ?? throw new InvalidOperationException("Encryption key not configured");
            var ivBase64 = _configuration["Encryption:IV"] ?? throw new InvalidOperationException("Encryption IV not configured");
            
            var key = Convert.FromBase64String(keyBase64);
            var iv = Convert.FromBase64String(ivBase64);

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;

                var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (var streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }
                        return Convert.ToBase64String(memoryStream.ToArray());
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts an AES-encrypted string
        /// </summary>
        public string Decrypt(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText))
                return cipherText;

            try
            {
                // Configuration values are base64 encoded
                var keyBase64 = _configuration["Encryption:Key"];
                var ivBase64 = _configuration["Encryption:IV"];
                
                var key = Convert.FromBase64String(keyBase64);
                var iv = Convert.FromBase64String(ivBase64);
                var buffer = Convert.FromBase64String(cipherText);

                using (var aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                    using (var memoryStream = new MemoryStream(buffer))
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (var streamReader = new StreamReader(cryptoStream))
                            {
                                return streamReader.ReadToEnd();
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Decryption failed. Data may be corrupted.", ex);
            }
        }

        /// <summary>
        /// Generates a random encryption key (32 bytes for AES-256)
        /// </summary>
        public static string GenerateKey()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] keyBytes = new byte[32];
                rng.GetBytes(keyBytes);
                return Convert.ToBase64String(keyBytes);
            }
        }

        /// <summary>
        /// Generates a random IV (16 bytes)
        /// </summary>
        public static string GenerateIV()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] ivBytes = new byte[16];
                rng.GetBytes(ivBytes);
                return Convert.ToBase64String(ivBytes);
            }
        }
    }

    public interface IEncryptionService
    {
        string Encrypt(string plainText);
        string Decrypt(string cipherText);
    }
}
