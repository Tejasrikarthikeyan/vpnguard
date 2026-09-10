using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for the executive SOC Overview Dashboard.
/// Synchronizes real PCAP analysis metrics without fake data.
/// </summary>
public class DashboardViewModel : ViewModelBase
{
    private readonly IPcapAnalyzer _pcapAnalyzer;
    private readonly IFileDialogService _fileDialogService;
    private readonly INavigationService _navigationService;

    private PcapFileInfo? _selectedFile;
    private PcapAnalysisResult? _analysisResult;
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
                StatusMessage = "PCAP selected — ready for analysis on PCAP page.";
            }
            else
            {
                StatusMessage = "Awaiting analysis";
                AnalysisResult = null;
            }
        };

        _pcapAnalyzer.AnalysisCompleted += (s, result) =>
        {
            AnalysisResult = result;
            if (result != null)
            {
                StatusMessage = $"Analysis completed: {result.PacketCount:N0} packets processed ({result.IpsecPacketCount:N0} IPsec).";
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

    public PcapAnalysisResult? AnalysisResult
    {
        get => _analysisResult;
        set
        {
            if (SetProperty(ref _analysisResult, value))
            {
                OnPropertyChanged(nameof(HasAnalysisResult));
                OnPropertyChanged(nameof(DisplayTotalPackets));
                OnPropertyChanged(nameof(DisplayIpsecPackets));
                OnPropertyChanged(nameof(DisplayIkePackets));
                OnPropertyChanged(nameof(DisplayEspPackets));
                OnPropertyChanged(nameof(DisplaySubTextTotalPackets));
                OnPropertyChanged(nameof(DisplaySubTextIpsec));
                OnPropertyChanged(nameof(DisplaySubTextIke));
                OnPropertyChanged(nameof(DisplaySubTextEsp));
            }
        }
    }

    public bool HasSelectedFile => _selectedFile != null;
    public bool HasAnalysisResult => _analysisResult != null;

    public string DisplayFileName => _selectedFile?.FileName ?? "No file selected";
    public string DisplayFilePath => _selectedFile?.FilePath ?? "Not available";
    public string DisplayFileSize => _selectedFile?.FormattedFileSize ?? "Not available";
    public string DisplayExtension => _selectedFile?.FileExtension?.ToUpperInvariant() ?? "Not available";

    // Overview Cards - Real Analysis Results
    public string DisplayTotalPackets => AnalysisResult != null ? $"{AnalysisResult.PacketCount:N0} Packets" : "No analysis available";
    public string DisplaySubTextTotalPackets => AnalysisResult != null ? $"{AnalysisResult.FormattedTotalBytes} total volume" : (HasSelectedFile ? SelectedFile?.FormattedFileSize ?? "Awaiting capture file" : "Awaiting capture file");

    public string DisplayIpsecPackets => AnalysisResult != null ? $"{AnalysisResult.IpsecPacketCount:N0} Packets" : "Awaiting analysis";
    public string DisplaySubTextIpsec => AnalysisResult != null ? $"{AnalysisResult.FormattedIpsecPercentage} of total traffic" : "0 Active Handshakes";

    public string DisplayIkePackets => AnalysisResult != null ? $"{AnalysisResult.IkePacketCount:N0} Packets" : "Awaiting analysis";
    public string DisplaySubTextIke => AnalysisResult != null ? $"Version: {AnalysisResult.IkeVersion}" : "0 IKE sessions";

    public string DisplayEspPackets => AnalysisResult != null ? $"{AnalysisResult.EspPacketCount:N0} Packets" : "Awaiting analysis";
    public string DisplaySubTextEsp => AnalysisResult != null ? (AnalysisResult.EspSpi != "Unknown" ? $"SPI: {AnalysisResult.EspSpi}" : $"{AnalysisResult.EspPacketCount:N0} ESP frames") : "0 ESP tunnels";

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
