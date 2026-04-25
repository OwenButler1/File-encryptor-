using FileEncryptor.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.UI.Xaml;

namespace FileEncryptor.App;

public partial class App : Application
{
    private Window? _window;

    public App()
    {
        InitializeComponent();

        Services = ConfigureServices();
    }

    public static IServiceProvider Services { get; private set; } = default!;

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        _window = Services.GetRequiredService<MainWindow>();
        _window.Activate();
    }

    private static IServiceProvider ConfigureServices()
    {
        var services = new ServiceCollection();

        services.AddLogging(logging =>
        {
            logging.AddDebug();
        });

        services.AddFileEncryptorServices();
        services.AddTransient<MainWindow>();

        return services.BuildServiceProvider();
    }
}
