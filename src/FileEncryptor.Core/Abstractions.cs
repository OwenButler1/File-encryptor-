namespace FileEncryptor.Core;

public interface IEncryptionService
{
    EncryptionResult Encrypt(ReadOnlySpan<byte> plaintext, string password);
    byte[] Decrypt(EncryptedPayload payload, string password);
}

public interface IKdfService
{
    byte[] DeriveKey(string password, byte[] salt, int iterations, int keyLengthBytes);
}

public interface IContainerFormatService
{
    byte[] Serialize(EncryptedPayload payload);
    EncryptedPayload Parse(ReadOnlySpan<byte> bytes);
}

public interface ISecureRandomService
{
    byte[] GetBytes(int length);
}
