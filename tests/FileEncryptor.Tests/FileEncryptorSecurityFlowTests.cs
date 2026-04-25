using System;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;

namespace FileEncryptor.Tests;

/// <summary>
/// Contract/integration tests for end-to-end file-container behavior.
/// These tests intentionally use deterministic, non-secret fixtures and avoid logging password values.
/// </summary>
public sealed class FileEncryptorSecurityFlowTests
{
    private static readonly byte[] Empty = Array.Empty<byte>();

    private const string GoodPassword = "correct-horse-battery-staple";
    private const string BadPassword = "Tr0ub4dor&3";

    [Fact]
    public async Task EncryptDecrypt_RoundTrip_ProducesByteEquality()
    {
        var sut = EncryptorHarness.CreateOrSkip();
        var plaintext = DeterministicFixtures.Bytes(4096, seed: 7);

        var container = await sut.EncryptAsync(plaintext, GoodPassword);
        var decrypted = await sut.DecryptAsync(container, GoodPassword);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task Decrypt_WithWrongPassword_Fails()
    {
        var sut = EncryptorHarness.CreateOrSkip();
        var plaintext = DeterministicFixtures.Bytes(1536, seed: 17);

        var container = await sut.EncryptAsync(plaintext, GoodPassword);

        await Assert.ThrowsAnyAsync<Exception>(() => sut.DecryptAsync(container, BadPassword));
    }

    [Fact]
    public async Task Decrypt_WithModifiedCiphertext_FailsAuthentication()
    {
        var sut = EncryptorHarness.CreateOrSkip();
        var plaintext = DeterministicFixtures.Bytes(2048, seed: 31);

        var container = await sut.EncryptAsync(plaintext, GoodPassword);
        var tampered = ContainerMutator.FlipSingleByteInCiphertext(container);

        await Assert.ThrowsAnyAsync<Exception>(() => sut.DecryptAsync(tampered, GoodPassword));
    }

    [Fact]
    public async Task Decrypt_WithModifiedHeader_IsSafelyRejected()
    {
        var sut = EncryptorHarness.CreateOrSkip();
        var plaintext = DeterministicFixtures.Bytes(1024, seed: 97);

        var container = await sut.EncryptAsync(plaintext, GoodPassword);
        var tampered = ContainerMutator.FlipSingleByteInHeader(container);

        await Assert.ThrowsAnyAsync<Exception>(() => sut.DecryptAsync(tampered, GoodPassword));
    }

    [Fact]
    public async Task Encrypt_Twice_ProducesDistinctNonces()
    {
        var sut = EncryptorHarness.CreateOrSkip();
        var plaintext = DeterministicFixtures.Bytes(300, seed: 3);

        var c1 = await sut.EncryptAsync(plaintext, GoodPassword);
        var c2 = await sut.EncryptAsync(plaintext, GoodPassword);

        var n1 = ContainerReader.ExtractNonce(c1);
        var n2 = ContainerReader.ExtractNonce(c2);

        Assert.NotEqual(Convert.ToHexString(n1), Convert.ToHexString(n2));
        Assert.NotEqual(c1, c2);
    }

    [Fact]
    public async Task EncryptDecrypt_EmptyFile_Works()
    {
        var sut = EncryptorHarness.CreateOrSkip();

        var container = await sut.EncryptAsync(Empty, GoodPassword);
        var decrypted = await sut.DecryptAsync(container, GoodPassword);

        Assert.Equal(Empty, decrypted);
    }

    [Fact]
    public async Task EncryptDecrypt_LargeFileFlow_Works()
    {
        var sut = EncryptorHarness.CreateOrSkip();
        var plaintext = DeterministicFixtures.Bytes(8 * 1024 * 1024, seed: 1234);

        var container = await sut.EncryptAsync(plaintext, GoodPassword);
        var decrypted = await sut.DecryptAsync(container, GoodPassword);

        Assert.Equal(plaintext.Length, decrypted.Length);
        Assert.Equal(SHA256.HashData(plaintext), SHA256.HashData(decrypted));
    }

    [Fact]
    public async Task MultipleFileProcessing_WorksAcrossDifferentInputs()
    {
        var sut = EncryptorHarness.CreateOrSkip();
        var files = new[]
        {
            DeterministicFixtures.Bytes(11, seed: 1),
            DeterministicFixtures.Bytes(4096, seed: 2),
            DeterministicFixtures.Bytes(65536, seed: 3),
        };

        foreach (var plaintext in files)
        {
            var container = await sut.EncryptAsync(plaintext, GoodPassword);
            var decrypted = await sut.DecryptAsync(container, GoodPassword);
            Assert.Equal(plaintext, decrypted);
        }
    }

    [Fact]
    public async Task Decrypt_WithUnsupportedVersion_IsRejected()
    {
        var sut = EncryptorHarness.CreateOrSkip();
        var plaintext = DeterministicFixtures.Bytes(350, seed: 5);

        var container = await sut.EncryptAsync(plaintext, GoodPassword);
        var mutated = ContainerMutator.OverwriteVersion(container, 0x7F);

        await Assert.ThrowsAnyAsync<Exception>(() => sut.DecryptAsync(mutated, GoodPassword));
    }

    [Fact]
    public async Task Decrypt_WithCorruptContainer_IsRejected()
    {
        var sut = EncryptorHarness.CreateOrSkip();

        // Truncated/random-ish container payload that should never deserialize/decrypt.
        var corrupt = DeterministicFixtures.Bytes(24, seed: 0x5A);

        await Assert.ThrowsAnyAsync<Exception>(() => sut.DecryptAsync(corrupt, GoodPassword));
    }

    private static class DeterministicFixtures
    {
        public static byte[] Bytes(int length, int seed)
        {
            var rng = new Random(seed);
            var data = new byte[length];
            rng.NextBytes(data);
            return data;
        }
    }

    private static class ContainerMutator
    {
        private const int HeaderPrefixLength = 8; // version+magic (format-specific: adjust if needed)

        public static byte[] FlipSingleByteInCiphertext(byte[] container)
        {
            var clone = container.ToArray();
            if (clone.Length == 0)
            {
                return clone;
            }

            var idx = Math.Max(HeaderPrefixLength, clone.Length / 2);
            idx = Math.Min(idx, clone.Length - 1);
            clone[idx] ^= 0x01;
            return clone;
        }

        public static byte[] FlipSingleByteInHeader(byte[] container)
        {
            var clone = container.ToArray();
            if (clone.Length == 0)
            {
                return clone;
            }

            var idx = Math.Min(1, clone.Length - 1);
            clone[idx] ^= 0x80;
            return clone;
        }

        public static byte[] OverwriteVersion(byte[] container, byte unsupportedVersion)
        {
            var clone = container.ToArray();
            if (clone.Length > 0)
            {
                clone[0] = unsupportedVersion;
            }

            return clone;
        }
    }

    private static class ContainerReader
    {
        // Assumes [version:1][magic:3][nonce:12] as a common container layout.
        // If your format differs, keep these checks but point to the actual nonce location.
        private const int NonceOffset = 4;
        private const int NonceLength = 12;

        public static byte[] ExtractNonce(byte[] container)
        {
            if (container.Length < NonceOffset + NonceLength)
            {
                throw new InvalidDataException("Container too short to extract nonce.");
            }

            return container.AsSpan(NonceOffset, NonceLength).ToArray();
        }
    }

    private sealed class EncryptorHarness
    {
        public Func<byte[], string, Task<byte[]>> EncryptAsyncImpl { get; init; } = default!;
        public Func<byte[], string, Task<byte[]>> DecryptAsyncImpl { get; init; } = default!;

        public Task<byte[]> EncryptAsync(byte[] plaintext, string password) => EncryptAsyncImpl(plaintext, password);
        public Task<byte[]> DecryptAsync(byte[] container, string password) => DecryptAsyncImpl(container, password);

        public static EncryptorHarness CreateOrSkip()
        {
            // Wire these delegates to your actual encrypt/decrypt implementation.
            // This placeholder makes the test file self-contained without leaking secrets in logs.
            throw new Xunit.Sdk.SkipException(
                "Encryptor harness is not wired. Connect EncryptAsyncImpl/DecryptAsyncImpl to production implementation.");
        }
    }
}
