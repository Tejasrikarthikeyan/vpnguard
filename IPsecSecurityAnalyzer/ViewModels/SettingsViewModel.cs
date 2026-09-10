using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for System Configuration, Engine Paths, and Environment Status.
/// </summary>
public class SettingsViewModel : ViewModelBase
{
    private readonly ISettingsService _settingsService;
    private ApplicationSettings _settings = new();
    private string _statusMessage = string.Empty;

    public SettingsViewModel(ISettingsService settingsService)
    {
        _settingsService = settingsService;
        SaveSettingsCommand = new RelayCommand(async () => await SaveSettingsAsync());
        _ = LoadSettingsAsync();
    }

    public ApplicationSettings Settings
    {
        get => _settings;
        set => SetProperty(ref _settings, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public ICommand SaveSettingsCommand { get; }

    private async Task LoadSettingsAsync()
    {
        Settings = await _settingsService.LoadSettingsAsync();
    }

    private async Task SaveSettingsAsync()
    {
        await _settingsService.SaveSettingsAsync(Settings);
        StatusMessage = "Settings saved successfully.";
    }
}
