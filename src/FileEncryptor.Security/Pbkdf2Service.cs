using System.Security.Cryptography;
using FileEncryptor.Core;

namespace FileEncryptor.Security;

public sealed class Pbkdf2Service : IKdfService
{
    public byte[] DeriveKey(string password, byte[] salt, int iterations, int keyLengthBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        ArgumentNullException.ThrowIfNull(salt);

        return Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            keyLengthBytes);
    }
}
