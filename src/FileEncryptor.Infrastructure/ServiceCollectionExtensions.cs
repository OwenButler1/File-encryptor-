using FileEncryptor.Core;
using FileEncryptor.Format;
using FileEncryptor.Security;
using Microsoft.Extensions.DependencyInjection;

namespace FileEncryptor.Infrastructure;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddFileEncryptorServices(this IServiceCollection services)
    {
        services.AddSingleton<IKdfService, Pbkdf2Service>();
        services.AddSingleton<ISecureRandomService, SecureRandomService>();
        services.AddSingleton<IEncryptionService, AesGcmEncryptionService>();
        services.AddSingleton<IContainerFormatService, ContainerFormatService>();
        services.AddSingleton<IErrorHandler, LoggingErrorHandler>();

        return services;
    }
}
