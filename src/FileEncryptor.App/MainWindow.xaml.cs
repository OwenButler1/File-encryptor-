using FileEncryptor.Core;
using Microsoft.UI.Xaml;

namespace FileEncryptor.App;

public sealed partial class MainWindow : Window
{
    public MainWindow(
        IEncryptionService encryptionService,
        IKdfService kdfService,
        IContainerFormatService containerFormatService,
        ISecureRandomService secureRandomService)
    {
        InitializeComponent();

        _ = encryptionService;
        _ = kdfService;
        _ = containerFormatService;
        _ = secureRandomService;
    }
}
