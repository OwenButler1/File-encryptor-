using System.Security.Cryptography;
using FileEncryptor.Core;

namespace FileEncryptor.Security;

public sealed class AesGcmEncryptionService(
    IKdfService kdfService,
    ISecureRandomService randomService) : IEncryptionService
{
    private const int SaltLength = 16;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int KeyLength = 32;
    private const int Iterations = 120_000;

    public EncryptionResult Encrypt(ReadOnlySpan<byte> plaintext, string password)
    {
        var salt = randomService.GetBytes(SaltLength);
        var nonce = randomService.GetBytes(NonceLength);
        var key = kdfService.DeriveKey(password, salt, Iterations, KeyLength);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagLength];

        using var aes = new AesGcm(key, TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        var payload = new EncryptedPayload(salt, nonce, ciphertext, tag, Iterations);
        return new EncryptionResult(payload, string.Empty);
    }

    public byte[] Decrypt(EncryptedPayload payload, string password)
    {
        ArgumentNullException.ThrowIfNull(payload);

        var key = kdfService.DeriveKey(password, payload.Salt, payload.KdfIterations, KeyLength);
        var plaintext = new byte[payload.Ciphertext.Length];

        using var aes = new AesGcm(key, TagLength);
        aes.Decrypt(payload.Nonce, payload.Ciphertext, payload.Tag, plaintext);

        return plaintext;
    }
}
