using System;
using System.Buffers.Binary;

namespace FileEncryptor.Format;

/// <summary>
/// Binary format contract for encrypted files.
/// This parser performs strict bounds checks before any decryption work starts.
/// </summary>
public static class SecureFileFormat
{
    public const string NeutralOutputExtension = ".securefile";

    // 8-byte magic marker: "SECFILE\0"
    public static ReadOnlySpan<byte> MagicBytes => "SECFILE\0"u8;

    public const ushort CurrentVersion = 1;

    // Compatibility fields for future versions.
    // HeaderLength allows newer parsers to skip unknown fixed fields.
    // Flags are reserved for forward-compatible behavior switches.
    private const ushort FixedHeaderLengthV1 = 36;

    private const int MaxSaltLength = 1024;
    private const int MaxNonceLength = 128;
    private const int MaxWrappedFekLength = 4096;
    private const int MaxEncryptedMetadataLength = 1024 * 1024;

    public enum AlgorithmId : byte
    {
        Unknown = 0,
        Aes256Gcm = 1,
        XChaCha20Poly1305 = 2
    }

    public enum KdfId : byte
    {
        Unknown = 0,
        Argon2id = 1
    }

    public readonly record struct Argon2Parameters(uint TimeCost, uint MemoryKiB, uint Parallelism);

    public readonly record struct Header(
        ushort Version,
        ushort HeaderLength,
        AlgorithmId Algorithm,
        KdfId Kdf,
        ushort Flags,
        Argon2Parameters Argon2,
        byte[] Salt,
        byte[] FileNonce,
        byte[] FekWrapNonce,
        byte[] WrappedFek,
        byte[] EncryptedMetadata);

    public static byte[] Serialize(Header header)
    {
        if (header.Version != CurrentVersion)
        {
            throw new ArgumentOutOfRangeException(nameof(header.Version), "Only the current format version can be serialized.");
        }

        ValidateKnownIds(header.Algorithm, header.Kdf);
        ValidateLengths(header.Salt, header.FileNonce, header.FekWrapNonce, header.WrappedFek, header.EncryptedMetadata);

        ushort headerLength = header.HeaderLength == 0 ? FixedHeaderLengthV1 : header.HeaderLength;
        if (headerLength < FixedHeaderLengthV1)
        {
            throw new ArgumentOutOfRangeException(nameof(header.HeaderLength), "Header length must be at least the fixed V1 length.");
        }

        int total = checked(
            MagicBytes.Length + // magic
            2 +                 // version
            2 +                 // header length
            1 +                 // algorithm id
            1 +                 // kdf id
            2 +                 // flags
            4 + 4 + 4 +         // Argon2 params
            2 + header.Salt.Length +
            2 + header.FileNonce.Length +
            2 + header.FekWrapNonce.Length +
            2 + header.WrappedFek.Length +
            4 + header.EncryptedMetadata.Length);

        byte[] output = new byte[total];
        Span<byte> span = output;
        int offset = 0;

        MagicBytes.CopyTo(span[offset..]);
        offset += MagicBytes.Length;

        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], header.Version);
        offset += 2;

        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], headerLength);
        offset += 2;

        span[offset++] = (byte)header.Algorithm;
        span[offset++] = (byte)header.Kdf;

        BinaryPrimitives.WriteUInt16LittleEndian(span[offset..], header.Flags);
        offset += 2;

        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], header.Argon2.TimeCost);
        offset += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], header.Argon2.MemoryKiB);
        offset += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], header.Argon2.Parallelism);
        offset += 4;

        WriteBlob(span, ref offset, header.Salt);
        WriteBlob(span, ref offset, header.FileNonce);
        WriteBlob(span, ref offset, header.FekWrapNonce);
        WriteBlob(span, ref offset, header.WrappedFek);

        BinaryPrimitives.WriteUInt32LittleEndian(span[offset..], checked((uint)header.EncryptedMetadata.Length));
        offset += 4;
        header.EncryptedMetadata.CopyTo(span[offset..]);

        return output;
    }

    public static bool TryDeserialize(ReadOnlySpan<byte> input, out Header header, out string error)
    {
        header = default;
        error = string.Empty;

        try
        {
            header = Deserialize(input);
            return true;
        }
        catch (FormatException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public static Header Deserialize(ReadOnlySpan<byte> input)
    {
        int minLength = MagicBytes.Length + FixedHeaderLengthV1 - 8; // fixed fields after magic
        if (input.Length < minLength)
        {
            throw new FormatException($"Input too short for secure file header. Expected at least {minLength} bytes.");
        }

        int offset = 0;

        if (!input[offset..].StartsWith(MagicBytes))
        {
            throw new FormatException("Invalid magic bytes.");
        }

        offset += MagicBytes.Length;

        EnsureReadable(input, offset, 2, "version");
        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(input[offset..]);
        offset += 2;

        if (version != CurrentVersion)
        {
            throw new FormatException($"Unsupported format version: {version}. Expected {CurrentVersion}.");
        }

        EnsureReadable(input, offset, 2, "header length");
        ushort headerLength = BinaryPrimitives.ReadUInt16LittleEndian(input[offset..]);
        offset += 2;

        if (headerLength < FixedHeaderLengthV1)
        {
            throw new FormatException($"Malformed header length: {headerLength}.");
        }

        EnsureReadable(input, offset, 1, "algorithm id");
        AlgorithmId algorithm = (AlgorithmId)input[offset++];

        EnsureReadable(input, offset, 1, "kdf id");
        KdfId kdf = (KdfId)input[offset++];

        ValidateKnownIds(algorithm, kdf);

        EnsureReadable(input, offset, 2, "flags");
        ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(input[offset..]);
        offset += 2;

        EnsureReadable(input, offset, 4, "Argon2 time cost");
        uint timeCost = BinaryPrimitives.ReadUInt32LittleEndian(input[offset..]);
        offset += 4;

        EnsureReadable(input, offset, 4, "Argon2 memory");
        uint memoryKiB = BinaryPrimitives.ReadUInt32LittleEndian(input[offset..]);
        offset += 4;

        EnsureReadable(input, offset, 4, "Argon2 parallelism");
        uint parallelism = BinaryPrimitives.ReadUInt32LittleEndian(input[offset..]);
        offset += 4;

        byte[] salt = ReadBlob(input, ref offset, MaxSaltLength, "salt");
        byte[] fileNonce = ReadBlob(input, ref offset, MaxNonceLength, "file nonce");
        byte[] fekWrapNonce = ReadBlob(input, ref offset, MaxNonceLength, "FEK-wrap nonce");
        byte[] wrappedFek = ReadBlob(input, ref offset, MaxWrappedFekLength, "wrapped FEK");

        EnsureReadable(input, offset, 4, "encrypted metadata length");
        uint metadataLength = BinaryPrimitives.ReadUInt32LittleEndian(input[offset..]);
        offset += 4;

        if (metadataLength > MaxEncryptedMetadataLength)
        {
            throw new FormatException($"Encrypted metadata length {metadataLength} exceeds maximum allowed {MaxEncryptedMetadataLength}.");
        }

        EnsureReadable(input, offset, checked((int)metadataLength), "encrypted metadata blob");
        byte[] encryptedMetadata = input.Slice(offset, checked((int)metadataLength)).ToArray();

        return new Header(
            Version: version,
            HeaderLength: headerLength,
            Algorithm: algorithm,
            Kdf: kdf,
            Flags: flags,
            Argon2: new Argon2Parameters(timeCost, memoryKiB, parallelism),
            Salt: salt,
            FileNonce: fileNonce,
            FekWrapNonce: fekWrapNonce,
            WrappedFek: wrappedFek,
            EncryptedMetadata: encryptedMetadata);
    }

    private static void WriteBlob(Span<byte> destination, ref int offset, byte[] blob)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(destination[offset..], checked((ushort)blob.Length));
        offset += 2;
        blob.CopyTo(destination[offset..]);
        offset += blob.Length;
    }

    private static byte[] ReadBlob(ReadOnlySpan<byte> source, ref int offset, int maxLength, string fieldName)
    {
        EnsureReadable(source, offset, 2, fieldName + " length");
        ushort length = BinaryPrimitives.ReadUInt16LittleEndian(source[offset..]);
        offset += 2;

        if (length > maxLength)
        {
            throw new FormatException($"{fieldName} length {length} exceeds maximum allowed {maxLength}.");
        }

        EnsureReadable(source, offset, length, fieldName);
        byte[] blob = source.Slice(offset, length).ToArray();
        offset += length;

        return blob;
    }

    private static void EnsureReadable(ReadOnlySpan<byte> source, int offset, int needed, string fieldName)
    {
        if (offset < 0 || needed < 0 || offset > source.Length - needed)
        {
            throw new FormatException($"Malformed header: not enough bytes for {fieldName}.");
        }
    }

    private static void ValidateKnownIds(AlgorithmId algorithm, KdfId kdf)
    {
        if (algorithm == AlgorithmId.Unknown)
        {
            throw new FormatException("Unsupported algorithm id.");
        }

        if (kdf != KdfId.Argon2id)
        {
            throw new FormatException("Unsupported KDF id.");
        }
    }

    private static void ValidateLengths(byte[] salt, byte[] fileNonce, byte[] fekWrapNonce, byte[] wrappedFek, byte[] encryptedMetadata)
    {
        ArgumentNullException.ThrowIfNull(salt);
        ArgumentNullException.ThrowIfNull(fileNonce);
        ArgumentNullException.ThrowIfNull(fekWrapNonce);
        ArgumentNullException.ThrowIfNull(wrappedFek);
        ArgumentNullException.ThrowIfNull(encryptedMetadata);

        if (salt.Length == 0 || salt.Length > MaxSaltLength)
        {
            throw new ArgumentOutOfRangeException(nameof(salt), $"Salt length must be between 1 and {MaxSaltLength} bytes.");
        }

        if (fileNonce.Length == 0 || fileNonce.Length > MaxNonceLength)
        {
            throw new ArgumentOutOfRangeException(nameof(fileNonce), $"File nonce length must be between 1 and {MaxNonceLength} bytes.");
        }

        if (fekWrapNonce.Length == 0 || fekWrapNonce.Length > MaxNonceLength)
        {
            throw new ArgumentOutOfRangeException(nameof(fekWrapNonce), $"FEK-wrap nonce length must be between 1 and {MaxNonceLength} bytes.");
        }

        if (wrappedFek.Length == 0 || wrappedFek.Length > MaxWrappedFekLength)
        {
            throw new ArgumentOutOfRangeException(nameof(wrappedFek), $"Wrapped FEK length must be between 1 and {MaxWrappedFekLength} bytes.");
        }

        if (encryptedMetadata.Length > MaxEncryptedMetadataLength)
        {
            throw new ArgumentOutOfRangeException(nameof(encryptedMetadata), $"Encrypted metadata length cannot exceed {MaxEncryptedMetadataLength} bytes.");
        }
    }
}
