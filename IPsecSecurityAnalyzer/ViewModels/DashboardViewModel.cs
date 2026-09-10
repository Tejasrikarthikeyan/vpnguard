using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for the executive SOC Overview Dashboard.
/// </summary>
public class DashboardViewModel : ViewModelBase
{
    private readonly IPcapAnalyzer _pcapAnalyzer;
    private readonly IFileDialogService _fileDialogService;
    private readonly INavigationService _navigationService;

    private PcapFileInfo? _selectedFile;
    private string _statusMessage = "Awaiting analysis";
    private string _errorMessage = string.Empty;

    public DashboardViewModel(
        IPcapAnalyzer pcapAnalyzer,
        IFileDialogService fileDialogService,
        INavigationService navigationService)
    {
        _pcapAnalyzer = pcapAnalyzer;
        _fileDialogService = fileDialogService;
        _navigationService = navigationService;

        SelectPcapCommand = new RelayCommand(ExecuteSelectPcap);
        NavigateToPcapPageCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.PcapAnalysis));

        _pcapAnalyzer.FileChanged += (s, file) =>
        {
            SelectedFile = file;
            if (file != null)
            {
                StatusMessage = "PCAP selected — analysis engine not yet connected.";
            }
        };
    }

    public PcapFileInfo? SelectedFile
    {
        get => _selectedFile;
        set
        {
            if (SetProperty(ref _selectedFile, value))
            {
                OnPropertyChanged(nameof(HasSelectedFile));
                OnPropertyChanged(nameof(DisplayFileName));
                OnPropertyChanged(nameof(DisplayFilePath));
                OnPropertyChanged(nameof(DisplayFileSize));
                OnPropertyChanged(nameof(DisplayExtension));
            }
        }
    }

    public bool HasSelectedFile => _selectedFile != null;
    public string DisplayFileName => _selectedFile?.FileName ?? "No file selected";
    public string DisplayFilePath => _selectedFile?.FilePath ?? "Not available";
    public string DisplayFileSize => _selectedFile?.FormattedFileSize ?? "Not available";
    public string DisplayExtension => _selectedFile?.FileExtension?.ToUpperInvariant() ?? "Not available";

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public string ErrorMessage
    {
        get => _errorMessage;
        set
        {
            if (SetProperty(ref _errorMessage, value))
            {
                OnPropertyChanged(nameof(HasError));
            }
        }
    }

    public bool HasError => !string.IsNullOrWhiteSpace(_errorMessage);

    public ICommand SelectPcapCommand { get; }
    public ICommand NavigateToPcapPageCommand { get; }

    private async void ExecuteSelectPcap()
    {
        ErrorMessage = string.Empty;
        try
        {
            var filePath = _fileDialogService.OpenPcapFileDialog();
            if (!string.IsNullOrEmpty(filePath))
            {
                await _pcapAnalyzer.LoadPcapFileAsync(filePath);
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Failed to open capture file: {ex.Message}";
        }
    }
}
