namespace FileEncryptor.Core;

public sealed record EncryptionRequest(string InputPath, string OutputPath, string Password);

public sealed record EncryptionResult(EncryptedPayload Payload, string OutputPath);

public sealed record EncryptedPayload(
    byte[] Salt,
    byte[] Nonce,
    byte[] Ciphertext,
    byte[] Tag,
    int KdfIterations,
    string Algorithm = "AES-256-GCM");
