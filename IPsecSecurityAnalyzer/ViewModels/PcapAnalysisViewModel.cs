using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for PCAP Analysis workspace page.
/// </summary>
public class PcapAnalysisViewModel : ViewModelBase
{
    private readonly IPcapAnalyzer _pcapAnalyzer;
    private readonly IFileDialogService _fileDialogService;

    private PcapFileInfo? _selectedFile;
    private string _analysisStatus = "Not analyzed";
    private string _errorMessage = string.Empty;

    public PcapAnalysisViewModel(
        IPcapAnalyzer pcapAnalyzer,
        IFileDialogService fileDialogService)
    {
        _pcapAnalyzer = pcapAnalyzer;
        _fileDialogService = fileDialogService;

        SelectPcapCommand = new RelayCommand(ExecuteSelectPcap);
        AnalyzePcapCommand = new RelayCommand(ExecuteAnalyzePcap, () => false); // Disabled for Phase 1

        _pcapAnalyzer.FileChanged += (s, file) =>
        {
            SelectedFile = file;
            AnalysisStatus = file != null
                ? "PCAP selected — analysis engine not yet connected."
                : "Not analyzed";
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
                OnPropertyChanged(nameof(DisplayFileType));
                OnPropertyChanged(nameof(DisplayCreatedDate));
                OnPropertyChanged(nameof(DisplayModifiedDate));
            }
        }
    }

    public bool HasSelectedFile => _selectedFile != null;
    public string DisplayFileName => _selectedFile?.FileName ?? "No file selected";
    public string DisplayFilePath => _selectedFile?.FilePath ?? "Not available";
    public string DisplayFileSize => _selectedFile?.FormattedFileSize ?? "Not available";
    public string DisplayFileType => _selectedFile?.FileExtension?.ToUpperInvariant() ?? "Not available";
    public string DisplayCreatedDate => _selectedFile != null ? _selectedFile.CreatedDate.ToString("yyyy-MM-dd HH:mm:ss") : "Not available";
    public string DisplayModifiedDate => _selectedFile != null ? _selectedFile.LastModifiedDate.ToString("yyyy-MM-dd HH:mm:ss") : "Not available";

    public string AnalysisStatus
    {
        get => _analysisStatus;
        set => SetProperty(ref _analysisStatus, value);
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
    public ICommand AnalyzePcapCommand { get; }

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
            ErrorMessage = $"Error loading capture: {ex.Message}";
        }
    }

    private void ExecuteAnalyzePcap()
    {
        // Intentionally disabled in Phase 1
    }
}
