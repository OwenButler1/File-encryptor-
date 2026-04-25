using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FileEncryptor.App.Models;
using FileEncryptor.App.Services;

namespace FileEncryptor.App.ViewModels;

public partial class MainWindowViewModel : ObservableObject
{
    public ObservableCollection<FileItem> Files { get; } = [];

    [ObservableProperty]
    private string _password = string.Empty;

    [ObservableProperty]
    private string _confirmPassword = string.Empty;

    [ObservableProperty]
    private bool _isPasswordVisible;

    [ObservableProperty]
    private string _outputFolder = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private double _progressValue;

    [ObservableProperty]
    private string _statusText = "Ready";

    [ObservableProperty]
    private bool _useDarkTheme;

    public Func<string, string, Task>? ShowInfoAsync { get; set; }
    public Func<string, string, Task>? ShowErrorAsync { get; set; }
    public Func<string, string, Task<bool>>? ConfirmAsync { get; set; }

    public string PasswordGuidance => PasswordAdvisor.Evaluate(Password).guidance;

    partial void OnPasswordChanged(string value)
    {
        OnPropertyChanged(nameof(PasswordGuidance));
    }

    [RelayCommand]
    private void TogglePasswordVisibility() => IsPasswordVisible = !IsPasswordVisible;

    [RelayCommand]
    private void RemoveSelectedFiles()
    {
        foreach (var item in Files.Where(x => x.IsSelected).ToList())
        {
            Files.Remove(item);
        }
    }

    [RelayCommand]
    private async Task EncryptAsync() => await RunCryptoAsync(isEncrypt: true);

    [RelayCommand]
    private async Task DecryptAsync() => await RunCryptoAsync(isEncrypt: false);

    public void AddFiles(IEnumerable<string> paths)
    {
        foreach (var path in paths.Where(File.Exists).Distinct())
        {
            if (Files.All(existing => !string.Equals(existing.Path, path, StringComparison.OrdinalIgnoreCase)))
            {
                Files.Add(new FileItem(path));
            }
        }

        StatusText = Files.Count == 0 ? "Ready" : $"{Files.Count} file(s) queued";
    }

    private async Task RunCryptoAsync(bool isEncrypt)
    {
        if (IsBusy)
        {
            return;
        }

        var selected = Files.Where(f => f.IsSelected).ToList();
        if (selected.Count == 0)
        {
            await (ShowErrorAsync?.Invoke("No files selected", "Select at least one file.") ?? Task.CompletedTask);
            return;
        }

        if (!Directory.Exists(OutputFolder))
        {
            await (ShowErrorAsync?.Invoke("Invalid output folder", "Choose a valid output folder.") ?? Task.CompletedTask);
            return;
        }

        if (string.IsNullOrWhiteSpace(Password) || Password != ConfirmPassword)
        {
            await (ShowErrorAsync?.Invoke("Password mismatch", "Password and confirmation must match.") ?? Task.CompletedTask);
            return;
        }

        if (PasswordAdvisor.IsWeak(Password))
        {
            var proceed = await (ConfirmAsync?.Invoke("Weak password warning", "This password appears weak. Continue anyway?") ?? Task.FromResult(false));
            if (!proceed)
            {
                return;
            }
        }

        IsBusy = true;
        ProgressValue = 0;
        var done = 0;
        var failures = new List<string>();

        try
        {
            foreach (var item in selected)
            {
                var outputPath = BuildOutputPath(item.Path, isEncrypt);

                if (File.Exists(outputPath))
                {
                    var overwrite = await (ConfirmAsync?.Invoke("Overwrite file?", $"{Path.GetFileName(outputPath)} already exists. Overwrite?") ?? Task.FromResult(false));
                    if (!overwrite)
                    {
                        failures.Add($"Skipped {item.Name} (overwrite declined)");
                        done++;
                        ProgressValue = done * 100d / selected.Count;
                        continue;
                    }
                }

                StatusText = $"Processing {item.Name}...";

                try
                {
                    await Task.Run(() =>
                    {
                        if (isEncrypt)
                        {
                            CryptoService.EncryptFile(item.Path, outputPath, Password);
                        }
                        else
                        {
                            CryptoService.DecryptFile(item.Path, outputPath, Password);
                        }
                    });
                }
                catch (Exception ex)
                {
                    failures.Add($"{item.Name}: {ex.Message}");
                }

                done++;
                ProgressValue = done * 100d / selected.Count;
            }

            if (failures.Count == 0)
            {
                await (ShowInfoAsync?.Invoke("Operation complete", isEncrypt ? "Files encrypted successfully." : "Files decrypted successfully.") ?? Task.CompletedTask);
            }
            else
            {
                await (ShowErrorAsync?.Invoke("Completed with warnings", string.Join(Environment.NewLine, failures.Take(8))) ?? Task.CompletedTask);
            }
        }
        finally
        {
            IsBusy = false;
            StatusText = "Ready";
        }
    }

    private string BuildOutputPath(string inputPath, bool isEncrypt)
    {
        var fileName = Path.GetFileName(inputPath);
        var outputName = isEncrypt
            ? fileName + ".fenc"
            : fileName.EndsWith(".fenc", StringComparison.OrdinalIgnoreCase)
                ? fileName[..^5]
                : $"{fileName}.decrypted";

        return Path.Combine(OutputFolder, outputName);
    }
}
