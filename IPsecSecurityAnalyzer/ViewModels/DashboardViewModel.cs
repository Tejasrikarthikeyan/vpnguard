using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for the executive SOC Overview Dashboard.
/// Synchronizes real PCAP analysis and Phase 4 Security Assessment metrics without fake data.
/// </summary>
public class DashboardViewModel : ViewModelBase
{
    private readonly IPcapAnalyzer _pcapAnalyzer;
    private readonly ISecurityAssessmentService _securityService;
    private readonly IFileDialogService _fileDialogService;
    private readonly INavigationService _navigationService;
    private readonly IAnalysisHistoryService? _historyService;
    private readonly IAiAnalysisService? _aiAnalysisService;

    private PcapFileInfo? _selectedFile;
    private PcapAnalysisResult? _analysisResult;
    private SecurityAssessment? _securityAssessment;
    private AiAnalysisResult? _aiResult;
    private string _statusMessage = "Awaiting analysis";
    private string _errorMessage = string.Empty;
    private int _totalHistoryCount = 0;
    private AnalysisHistory? _latestHistoryRecord;

    public DashboardViewModel(
        IPcapAnalyzer pcapAnalyzer,
        ISecurityAssessmentService securityService,
        IFileDialogService fileDialogService,
        INavigationService navigationService,
        IAnalysisHistoryService? historyService = null,
        IAiAnalysisService? aiAnalysisService = null)
    {
        _pcapAnalyzer = pcapAnalyzer;
        _securityService = securityService;
        _fileDialogService = fileDialogService;
        _navigationService = navigationService;
        _historyService = historyService;
        _aiAnalysisService = aiAnalysisService;

        SelectPcapCommand = new RelayCommand(ExecuteSelectPcap);
        NavigateToPcapPageCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.PcapAnalysis));
        NavigateToSecurityAssessmentCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.SecurityAssessment));
        NavigateToFindingsCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.Findings));
        NavigateToHistoryCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.History));
        NavigateToAiCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.AiAnalysis));
        NavigateToReportsCommand = new RelayCommand(() => _navigationService.NavigateTo(NavigationPage.Reports));

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
                SecurityAssessment = null;
                AiResult = null;
            }
        };

        _pcapAnalyzer.AnalysisCompleted += async (s, result) =>
        {
            AnalysisResult = result;
            if (result != null)
            {
                StatusMessage = $"Analysis completed: {result.PacketCount:N0} packets processed ({result.IpsecPacketCount:N0} IPsec).";
                if (_aiAnalysisService != null)
                {
                    try
                    {
                        var ai = await _aiAnalysisService.GetAiAnalysisAsync(result.PacketDetails);
                        AiResult = ai;
                    }
                    catch
                    {
                        AiResult = null;
                    }
                }
            }
        };

        _securityService.AssessmentCompleted += (s, assessment) =>
        {
            SecurityAssessment = assessment;
        };

        if (_historyService != null)
        {
            _historyService.HistoryChanged += async (s, e) =>
            {
                await RefreshHistoryMetricsAsync();
            };
            _ = RefreshHistoryMetricsAsync();
        }
    }

    private async Task RefreshHistoryMetricsAsync()
    {
        if (_historyService == null) return;
        TotalHistoryCount = await _historyService.GetHistoryCountAsync();
        LatestHistoryRecord = await _historyService.GetLatestAnalysisAsync();
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

    public SecurityAssessment? SecurityAssessment
    {
        get => _securityAssessment;
        set
        {
            if (SetProperty(ref _securityAssessment, value))
            {
                OnPropertyChanged(nameof(HasSecurityAssessment));
                OnPropertyChanged(nameof(DisplaySecurityScore));
                OnPropertyChanged(nameof(DisplayRiskLevel));
                OnPropertyChanged(nameof(DisplayFindingsSummary));
                OnPropertyChanged(nameof(DisplayHighCriticalFindings));
                OnPropertyChanged(nameof(DisplayCoverage));
                OnPropertyChanged(nameof(RiskBadgeColor));
            }
        }
    }

    public bool HasSelectedFile => _selectedFile != null;
    public bool HasAnalysisResult => _analysisResult != null;
    public bool HasSecurityAssessment => _securityAssessment != null && _securityAssessment.HasAssessment;

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

    // Phase 4 Security Assessment Displays
    public string DisplaySecurityScore => HasSecurityAssessment ? $"{_securityAssessment!.OverallRiskScore:F0} / 100" : "No assessment available";
    public string DisplayRiskLevel => HasSecurityAssessment ? _securityAssessment!.RiskLevel.ToString() : "Awaiting analysis";
    public string DisplayFindingsSummary => HasSecurityAssessment ? $"{_securityAssessment!.TotalFindingsCount} Finding(s)" : "No assessment available";
    public string DisplayHighCriticalFindings => HasSecurityAssessment ? $"{_securityAssessment!.CriticalCount} Critical, {_securityAssessment!.HighCount} High" : "Awaiting analysis";
    public string DisplayCoverage => HasSecurityAssessment ? $"{_securityAssessment!.AssessmentCoverage:F0}% Parameter Coverage" : "Awaiting capture analysis";
    public string RiskBadgeColor => HasSecurityAssessment ? _securityAssessment!.RiskBadgeColor : "#6B7280";

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

    public int TotalHistoryCount
    {
        get => _totalHistoryCount;
        set
        {
            if (SetProperty(ref _totalHistoryCount, value))
            {
                OnPropertyChanged(nameof(DisplayTotalHistoryCount));
                OnPropertyChanged(nameof(HasHistoryRecords));
            }
        }
    }

    public AnalysisHistory? LatestHistoryRecord
    {
        get => _latestHistoryRecord;
        set
        {
            if (SetProperty(ref _latestHistoryRecord, value))
            {
                OnPropertyChanged(nameof(DisplayLatestAnalysis));
                OnPropertyChanged(nameof(DisplayLatestRisk));
                OnPropertyChanged(nameof(DisplayLatestScore));
            }
        }
    }

    public bool HasHistoryRecords => _totalHistoryCount > 0;
    public string DisplayTotalHistoryCount => _totalHistoryCount > 0 ? $"{_totalHistoryCount} Analyses" : "No history recorded";
    public string DisplayLatestAnalysis => _latestHistoryRecord != null ? $"{_latestHistoryRecord.FileName} ({_latestHistoryRecord.FormattedDate})" : "No previous analyses in SQLite";
    public string DisplayLatestRisk => _latestHistoryRecord != null ? $"Risk: {_latestHistoryRecord.RiskLevel}" : "Awaiting analysis";
    public string DisplayLatestScore => _latestHistoryRecord?.SecurityScore.HasValue == true ? $"{_latestHistoryRecord.SecurityScore.Value:F0} / 100" : "N/A";

    public AiAnalysisResult? AiResult
    {
        get => _aiResult;
        set
        {
            if (SetProperty(ref _aiResult, value))
            {
                OnPropertyChanged(nameof(HasAiResult));
                OnPropertyChanged(nameof(DisplayAiTrafficType));
                OnPropertyChanged(nameof(DisplayAiConfidence));
                OnPropertyChanged(nameof(DisplayAiAnomalyStatus));
            }
        }
    }

    public bool HasAiResult => _aiResult != null && _aiResult.IsModelConnected;
    public string DisplayAiTrafficType => HasAiResult ? _aiResult!.DisplayTrafficType : "Awaiting analysis";
    public string DisplayAiConfidence => HasAiResult ? _aiResult!.DisplayConfidence : "Awaiting analysis";
    public string DisplayAiAnomalyStatus => HasAiResult ? (_aiResult!.HasAnomalies ? "Potentially unusual pattern" : "Normal profile") : "Awaiting analysis";

    public ICommand SelectPcapCommand { get; }
    public ICommand NavigateToPcapPageCommand { get; }
    public ICommand NavigateToSecurityAssessmentCommand { get; }
    public ICommand NavigateToFindingsCommand { get; }
    public ICommand NavigateToHistoryCommand { get; }
    public ICommand NavigateToAiCommand { get; }
    public ICommand NavigateToReportsCommand { get; }

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
