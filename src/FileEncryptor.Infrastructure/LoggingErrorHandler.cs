using Microsoft.Extensions.Logging;

namespace FileEncryptor.Infrastructure;

public sealed class LoggingErrorHandler(ILogger<LoggingErrorHandler> logger) : IErrorHandler
{
    public void Handle(Exception exception, string contextMessage)
    {
        logger.LogError(exception, "{ContextMessage}", contextMessage);
    }
}
