namespace FileEncryptor.Infrastructure;

public interface IErrorHandler
{
    void Handle(Exception exception, string contextMessage);
}
