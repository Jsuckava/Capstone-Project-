using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace Client_app.Services
{
    public class ChatMessageEncryption : IChatMessageEncryption
    {
        private const string Prefix = "v1";
        private readonly byte[] _key;

        public ChatMessageEncryption(IConfiguration configuration)
        {
            var configuredKey = Environment.GetEnvironmentVariable("CHAT_ENCRYPTION_KEY")
                ?? configuration["Chat:EncryptionKey"]
                ?? Environment.GetEnvironmentVariable("JWT_SECRET")
                ?? throw new InvalidOperationException("CHAT_ENCRYPTION_KEY or JWT_SECRET is required for chat message encryption.");

            _key = BuildKey(configuredKey);
        }

        public string Encrypt(string plaintext)
        {
            var nonce = RandomNumberGenerator.GetBytes(12);
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext ?? string.Empty);
            var ciphertext = new byte[plaintextBytes.Length];
            var tag = new byte[16];

            using var aes = new AesGcm(_key, tag.Length);
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

            return string.Join(":",
                Prefix,
                Convert.ToBase64String(nonce),
                Convert.ToBase64String(tag),
                Convert.ToBase64String(ciphertext));
        }

        public string Decrypt(string storedValue)
        {
            if (string.IsNullOrEmpty(storedValue)) return string.Empty;

            var parts = storedValue.Split(':', 4);
            if (parts.Length != 4 || parts[0] != Prefix)
            {
                return storedValue;
            }

            var nonce = Convert.FromBase64String(parts[1]);
            var tag = Convert.FromBase64String(parts[2]);
            var ciphertext = Convert.FromBase64String(parts[3]);
            var plaintext = new byte[ciphertext.Length];

            using var aes = new AesGcm(_key, tag.Length);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);

            return Encoding.UTF8.GetString(plaintext);
        }

        private static byte[] BuildKey(string configuredKey)
        {
            var trimmed = configuredKey.Trim();
            try
            {
                var decoded = Convert.FromBase64String(trimmed);
                if (decoded.Length == 32) return decoded;
            }
            catch (FormatException)
            {
            }

            return SHA256.HashData(Encoding.UTF8.GetBytes(trimmed));
        }
    }
}
