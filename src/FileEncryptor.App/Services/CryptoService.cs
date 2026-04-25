using System.Security.Cryptography;
using System.Text;

namespace FileEncryptor.App.Services;

public static class CryptoService
{
    private static readonly byte[] Magic = Encoding.UTF8.GetBytes("FENC1");

    public static void EncryptFile(string inputPath, string outputPath, string password)
    {
        var plain = File.ReadAllBytes(inputPath);
        var salt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var key = DeriveKey(password, salt);
        var cipher = new byte[plain.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plain, cipher, tag);

        using var fs = File.Create(outputPath);
        fs.Write(Magic);
        fs.Write(salt);
        fs.Write(nonce);
        fs.Write(tag);
        fs.Write(cipher);
    }

    public static void DecryptFile(string inputPath, string outputPath, string password)
    {
        var allBytes = File.ReadAllBytes(inputPath);

        if (allBytes.Length < Magic.Length + 16 + 12 + 16)
        {
            throw new InvalidDataException("Input file is too short or malformed.");
        }

        var cursor = 0;
        var magic = allBytes[cursor..(cursor + Magic.Length)];
        cursor += Magic.Length;

        if (!magic.SequenceEqual(Magic))
        {
            throw new InvalidDataException("This file is not a supported encrypted file.");
        }

        var salt = allBytes[cursor..(cursor + 16)];
        cursor += 16;
        var nonce = allBytes[cursor..(cursor + 12)];
        cursor += 12;
        var tag = allBytes[cursor..(cursor + 16)];
        cursor += 16;
        var cipher = allBytes[cursor..];

        var plain = new byte[cipher.Length];
        var key = DeriveKey(password, salt);

        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, cipher, tag, plain);

        File.WriteAllBytes(outputPath, plain);
    }

    private static byte[] DeriveKey(string password, byte[] salt)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(32);
    }
}
