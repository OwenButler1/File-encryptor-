using System.Security.Cryptography;
using FileEncryptor.Core;

namespace FileEncryptor.Security;

public sealed class SecureRandomService : ISecureRandomService
{
    public byte[] GetBytes(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);

        var bytes = new byte[length];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }
}
