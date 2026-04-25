using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Platform.Storage;
using FileEncryptor.App.ViewModels;
using MsBox.Avalonia;
using MsBox.Avalonia.Dto;
using MsBox.Avalonia.Enums;

namespace FileEncryptor.App;

public partial class MainWindow : Window
{
    private MainWindowViewModel ViewModel => (MainWindowViewModel)DataContext!;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainWindowViewModel();

        ViewModel.ShowInfoAsync = (title, message) => ShowMessageAsync(title, message, ButtonEnum.Ok, Icon.Success);
        ViewModel.ShowErrorAsync = (title, message) => ShowMessageAsync(title, message, ButtonEnum.Ok, Icon.Warning);
        ViewModel.ConfirmAsync = async (title, message) =>
        {
            var box = MessageBoxManager.GetMessageBoxStandard(new MessageBoxStandardParams
            {
                ContentTitle = title,
                ContentMessage = message,
                ButtonDefinitions = ButtonEnum.YesNo,
                Icon = Icon.Question,
                WindowStartupLocation = WindowStartupLocation.CenterOwner
            });

            var result = await box.ShowWindowDialogAsync(this);
            return result == ButtonResult.Yes;
        };

        ViewModel.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(MainWindowViewModel.UseDarkTheme))
            {
                RequestedThemeVariant = ViewModel.UseDarkTheme ? ThemeVariant.Dark : ThemeVariant.Light;
            }
        };
    }

    private async Task ShowMessageAsync(string title, string message, ButtonEnum buttons, Icon icon)
    {
        var box = MessageBoxManager.GetMessageBoxStandard(new MessageBoxStandardParams
        {
            ContentTitle = title,
            ContentMessage = message,
            ButtonDefinitions = buttons,
            Icon = icon,
            WindowStartupLocation = WindowStartupLocation.CenterOwner
        });

        await box.ShowWindowDialogAsync(this);
    }

    private void DropTarget_OnDragOver(object? sender, DragEventArgs e)
    {
        e.DragEffects = e.Data.Contains(DataFormats.Files) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    private void DropTarget_OnDrop(object? sender, DragEventArgs e)
    {
        if (!e.Data.Contains(DataFormats.Files))
        {
            return;
        }

        var files = e.Data.GetFiles()?.Select(x => x.TryGetLocalPath()).OfType<string>().ToList();
        if (files is { Count: > 0 })
        {
            ViewModel.AddFiles(files);
        }
    }

    private async void AddFiles_OnClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        var result = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            AllowMultiple = true,
            Title = "Select files to encrypt/decrypt"
        });

        var files = result.Select(x => x.TryGetLocalPath()).OfType<string>();
        ViewModel.AddFiles(files);
    }

    private async void PickOutputFolder_OnClick(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        var result = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            AllowMultiple = false,
            Title = "Choose output folder"
        });

        var folder = result.FirstOrDefault()?.TryGetLocalPath();
        if (!string.IsNullOrWhiteSpace(folder))
        {
            ViewModel.OutputFolder = folder;
        }
    }
}
