using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Konscious.Security.Cryptography;

namespace FileEncryptor.Security;

public sealed class FileEncryptionService
{
    private const int FekLength = 32;
    private const int SaltLength = 16;
    private const int NonceLength = 12;
    private const int TagLength = 16;

    private readonly NonceRegistry _nonceRegistry = new();

    public EncryptedFilePackage Encrypt(ReadOnlySpan<byte> fileContent, ReadOnlySpan<char> password)
    {
        byte[] fek = RandomNumberGenerator.GetBytes(FekLength);
        byte[] kekSalt = RandomNumberGenerator.GetBytes(SaltLength);
        byte[]? kek = null;

        byte[] dataCiphertext = new byte[fileContent.Length];
        byte[] dataTag = new byte[TagLength];

        byte[] wrappedFekCiphertext = new byte[FekLength];
        byte[] wrappedFekTag = new byte[TagLength];

        byte[] dataNonce = _nonceRegistry.CreateUniqueNonceForKey(fek, NonceLength);

        try
        {
            using (var dataAes = new AesGcm(fek, TagLength))
            {
                dataAes.Encrypt(dataNonce, fileContent, dataCiphertext, dataTag);
            }

            kek = DeriveKek(password, kekSalt);

            byte[] wrappingNonce = _nonceRegistry.CreateUniqueNonceForKey(kek, NonceLength);
            using var wrappingAes = new AesGcm(kek, TagLength);
            wrappingAes.Encrypt(wrappingNonce, fek, wrappedFekCiphertext, wrappedFekTag);

            return new EncryptedFilePackage(
                dataCiphertext,
                dataTag,
                dataNonce,
                wrappedFekCiphertext,
                wrappedFekTag,
                wrappingNonce,
                kekSalt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fek);

            if (kek is not null)
            {
                CryptographicOperations.ZeroMemory(kek);
            }
        }
    }

    public byte[] Decrypt(EncryptedFilePackage encryptedFile, ReadOnlySpan<char> password)
    {
        byte[]? kek = null;
        byte[] fek = new byte[FekLength];
        byte[] plaintext = new byte[encryptedFile.Ciphertext.Length];

        try
        {
            kek = DeriveKek(password, encryptedFile.KekSalt);

            using (var wrappingAes = new AesGcm(kek, TagLength))
            {
                wrappingAes.Decrypt(
                    encryptedFile.WrappingNonce,
                    encryptedFile.WrappedFekCiphertext,
                    encryptedFile.WrappedFekTag,
                    fek);
            }

            using (var dataAes = new AesGcm(fek, TagLength))
            {
                dataAes.Decrypt(
                    encryptedFile.DataNonce,
                    encryptedFile.Ciphertext,
                    encryptedFile.CiphertextTag,
                    plaintext);
            }

            return plaintext;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException("Failed to decrypt file.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fek);

            if (kek is not null)
            {
                CryptographicOperations.ZeroMemory(kek);
            }
        }
    }

    private static byte[] DeriveKek(ReadOnlySpan<char> password, ReadOnlySpan<byte> salt)
    {
        char[] passwordChars = password.ToArray();
        byte[] passwordBytes = new byte[passwordChars.Length * sizeof(char)];
        byte[] saltBytes = salt.ToArray();

        try
        {
            Buffer.BlockCopy(passwordChars, 0, passwordBytes, 0, passwordBytes.Length);

            var argon2 = new Argon2id(passwordBytes)
            {
                Salt = saltBytes,
                Iterations = 3,
                DegreeOfParallelism = 2,
                MemorySize = 64 * 1024
            };

            return argon2.GetBytes(FekLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(saltBytes);
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(passwordChars.AsSpan()));
        }
    }

    private sealed class NonceRegistry
    {
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, byte>> _noncesByKey = new();

        public byte[] CreateUniqueNonceForKey(ReadOnlySpan<byte> key, int nonceLength)
        {
            string keyId = Convert.ToHexString(SHA256.HashData(key));
            var knownNonces = _noncesByKey.GetOrAdd(keyId, _ => new ConcurrentDictionary<string, byte>());

            while (true)
            {
                byte[] nonce = RandomNumberGenerator.GetBytes(nonceLength);
                string nonceId = Convert.ToHexString(nonce);

                if (knownNonces.TryAdd(nonceId, 0))
                {
                    return nonce;
                }

                CryptographicOperations.ZeroMemory(nonce);
            }
        }
    }
}

public sealed record EncryptedFilePackage(
    byte[] Ciphertext,
    byte[] CiphertextTag,
    byte[] DataNonce,
    byte[] WrappedFekCiphertext,
    byte[] WrappedFekTag,
    byte[] WrappingNonce,
    byte[] KekSalt);
