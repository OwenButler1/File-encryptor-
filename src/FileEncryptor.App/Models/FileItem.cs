using CommunityToolkit.Mvvm.ComponentModel;

namespace FileEncryptor.App.Models;

public partial class FileItem(string path) : ObservableObject
{
    [ObservableProperty]
    private bool _isSelected = true;

    public string Path { get; } = path;
    public string Name => System.IO.Path.GetFileName(path);
    public long SizeBytes => new System.IO.FileInfo(path).Length;
}
