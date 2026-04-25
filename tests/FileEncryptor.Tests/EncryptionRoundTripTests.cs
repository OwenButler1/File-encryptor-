using System.Text;
using FileEncryptor.Core;
using FileEncryptor.Format;
using FileEncryptor.Security;

namespace FileEncryptor.Tests;

public sealed class EncryptionRoundTripTests
{
    [Fact]
    public void Encrypt_ThenSerializeParse_ThenDecrypt_RoundTrips()
    {
        IKdfService kdfService = new Pbkdf2Service();
        ISecureRandomService randomService = new SecureRandomService();
        IEncryptionService encryptionService = new AesGcmEncryptionService(kdfService, randomService);
        IContainerFormatService containerFormatService = new ContainerFormatService();

        var plaintext = Encoding.UTF8.GetBytes("hello from tests");
        var password = "P@ssw0rd!";

        var encrypted = encryptionService.Encrypt(plaintext, password).Payload;
        var bytes = containerFormatService.Serialize(encrypted);
        var parsed = containerFormatService.Parse(bytes);
        var decrypted = encryptionService.Decrypt(parsed, password);

        Assert.Equal(plaintext, decrypted);
    }
}
