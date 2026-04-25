using System.Buffers.Binary;
using FileEncryptor.Core;

namespace FileEncryptor.Format;

public sealed class ContainerFormatService : IContainerFormatService
{
    private static readonly byte[] Magic = "FENC"u8.ToArray();
    private const byte Version = 1;

    public byte[] Serialize(EncryptedPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms);

        bw.Write(Magic);
        bw.Write(Version);
        bw.Write(payload.KdfIterations);
        bw.Write((byte)payload.Salt.Length);
        bw.Write((byte)payload.Nonce.Length);
        bw.Write((byte)payload.Tag.Length);
        bw.Write(payload.Ciphertext.Length);
        bw.Write(payload.Salt);
        bw.Write(payload.Nonce);
        bw.Write(payload.Tag);
        bw.Write(payload.Ciphertext);

        return ms.ToArray();
    }

    public EncryptedPayload Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 16)
        {
            throw new InvalidDataException("Container is too small.");
        }

        var offset = 0;
        var magic = bytes.Slice(offset, 4);
        offset += 4;

        if (!magic.SequenceEqual(Magic))
        {
            throw new InvalidDataException("Invalid magic header.");
        }

        var version = bytes[offset++];
        if (version != Version)
        {
            throw new InvalidDataException($"Unsupported version: {version}.");
        }

        var iterations = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(offset, 4));
        offset += 4;

        var saltLength = bytes[offset++];
        var nonceLength = bytes[offset++];
        var tagLength = bytes[offset++];

        var cipherLength = BinaryPrimitives.ReadInt32LittleEndian(bytes.Slice(offset, 4));
        offset += 4;

        var requiredLength = offset + saltLength + nonceLength + tagLength + cipherLength;
        if (bytes.Length < requiredLength)
        {
            throw new InvalidDataException("Container is truncated.");
        }

        var salt = bytes.Slice(offset, saltLength).ToArray();
        offset += saltLength;

        var nonce = bytes.Slice(offset, nonceLength).ToArray();
        offset += nonceLength;

        var tag = bytes.Slice(offset, tagLength).ToArray();
        offset += tagLength;

        var ciphertext = bytes.Slice(offset, cipherLength).ToArray();

        return new EncryptedPayload(salt, nonce, ciphertext, tag, iterations);
    }
}
