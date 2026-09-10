using System.Collections.ObjectModel;
using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for PCAP Analysis workspace page, coordinating TShark packet extraction, real metrics aggregation, and UI data presentation.
/// </summary>
public class PcapAnalysisViewModel : ViewModelBase
{
    private readonly IPcapAnalyzer _pcapAnalyzer;
    private readonly IFileDialogService _fileDialogService;
    private readonly IAnalysisHistoryService? _historyService;
    private readonly IIpsecAnalyzer? _ipsecAnalyzer;
    private readonly ISecurityAssessmentService? _assessmentService;
    private readonly IAiAnalysisService? _aiAnalysisService;

    private PcapFileInfo? _selectedFile;
    private AnalysisStatus _status = AnalysisStatus.NotSelected;
    private string _analysisStatusText = "No PCAP selected.";
    private string _errorMessage = string.Empty;
    private PcapAnalysisResult? _analysisResult;
    private CancellationTokenSource? _analysisCts;
    private string _packetSummaryText = string.Empty;

    private const int MaxDisplayedPackets = 1000;

    public PcapAnalysisViewModel(
        IPcapAnalyzer pcapAnalyzer,
        IFileDialogService fileDialogService,
        IAnalysisHistoryService? historyService = null,
        IIpsecAnalyzer? ipsecAnalyzer = null,
        ISecurityAssessmentService? assessmentService = null,
        IAiAnalysisService? aiAnalysisService = null)
    {
        _pcapAnalyzer = pcapAnalyzer;
        _fileDialogService = fileDialogService;
        _historyService = historyService;
        _ipsecAnalyzer = ipsecAnalyzer;
        _assessmentService = assessmentService;
        _aiAnalysisService = aiAnalysisService;

        SelectPcapCommand = new RelayCommand(ExecuteSelectPcap, () => !IsAnalyzing);
        AnalyzePcapCommand = new RelayCommand(async () => await ExecuteAnalyzePcapAsync(), () => CanAnalyze);
        CancelAnalysisCommand = new RelayCommand(ExecuteCancelAnalysis, () => IsAnalyzing);

        _pcapAnalyzer.FileChanged += (s, file) =>
        {
            SelectedFile = file;
            if (file != null)
            {
                Status = AnalysisStatus.Ready;
                AnalysisStatusText = "PCAP loaded — ready for analysis.";
                AnalysisResult = null;
                DisplayedPackets.Clear();
                DisplayedProtocols.Clear();
                PacketSummaryText = string.Empty;
            }
            else
            {
                Status = AnalysisStatus.NotSelected;
                AnalysisStatusText = "No PCAP selected.";
                AnalysisResult = null;
                DisplayedPackets.Clear();
                DisplayedProtocols.Clear();
                PacketSummaryText = string.Empty;
            }
        };
    }

    public ObservableCollection<PacketInfo> DisplayedPackets { get; } = new();
    public ObservableCollection<ProtocolStatistics> DisplayedProtocols { get; } = new();

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
                OnPropertyChanged(nameof(CanAnalyze));
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

    public AnalysisStatus Status
    {
        get => _status;
        set
        {
            if (SetProperty(ref _status, value))
            {
                OnPropertyChanged(nameof(IsAnalyzing));
                OnPropertyChanged(nameof(CanAnalyze));
                OnPropertyChanged(nameof(CanCancel));
                OnPropertyChanged(nameof(HasCompletedAnalysis));
            }
        }
    }

    public string AnalysisStatusText
    {
        get => _analysisStatusText;
        set => SetProperty(ref _analysisStatusText, value);
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
    public bool IsAnalyzing => _status == AnalysisStatus.Analyzing;
    public bool CanAnalyze => HasSelectedFile && !IsAnalyzing;
    public bool CanCancel => IsAnalyzing;
    public bool HasCompletedAnalysis => _status == AnalysisStatus.Completed && _analysisResult != null;

    public PcapAnalysisResult? AnalysisResult
    {
        get => _analysisResult;
        set
        {
            if (SetProperty(ref _analysisResult, value))
            {
                OnPropertyChanged(nameof(HasCompletedAnalysis));
                OnPropertyChanged(nameof(DisplayTotalPackets));
                OnPropertyChanged(nameof(DisplayTotalBytes));
                OnPropertyChanged(nameof(DisplayDuration));
                OnPropertyChanged(nameof(DisplayIpsecPackets));
                OnPropertyChanged(nameof(DisplayIkePackets));
                OnPropertyChanged(nameof(DisplayEspPackets));
                OnPropertyChanged(nameof(DisplayAhPackets));
                OnPropertyChanged(nameof(DisplayIpsecDetected));
                OnPropertyChanged(nameof(DisplayIkeVersion));
                OnPropertyChanged(nameof(IpsecSummaryMessage));
            }
        }
    }

    public string PacketSummaryText
    {
        get => _packetSummaryText;
        set => SetProperty(ref _packetSummaryText, value);
    }

    // Real Statistics Cards Display Properties (No Fake Data)
    public string DisplayTotalPackets => AnalysisResult != null ? AnalysisResult.PacketCount.ToString("N0") : "No data";
    public string DisplayTotalBytes => AnalysisResult != null ? AnalysisResult.FormattedTotalBytes : "No data";
    public string DisplayDuration => AnalysisResult != null ? AnalysisResult.FormattedDuration : "No data";
    public string DisplayIpsecPackets => AnalysisResult != null ? AnalysisResult.IpsecPacketCount.ToString("N0") : "No data";
    public string DisplayIkePackets => AnalysisResult != null ? AnalysisResult.IkePacketCount.ToString("N0") : "No data";
    public string DisplayEspPackets => AnalysisResult != null ? AnalysisResult.EspPacketCount.ToString("N0") : "No data";
    public string DisplayAhPackets => AnalysisResult != null ? AnalysisResult.AhPacketCount.ToString("N0") : "No data";

    // IPsec Summary Section
    public string DisplayIpsecDetected => AnalysisResult != null ? AnalysisResult.DisplayIpsecDetected : "NO";
    public string DisplayIkeVersion => AnalysisResult != null ? AnalysisResult.IkeVersion : "Unknown";
    public string IpsecSummaryMessage
    {
        get
        {
            if (AnalysisResult == null) return "Awaiting PCAP analysis.";
            if (AnalysisResult.IpsecPacketCount == 0) return "No IPsec traffic detected in this PCAP.";
            return $"Detected {AnalysisResult.IpsecPacketCount:N0} IPsec packets ({AnalysisResult.FormattedIpsecPercentage} of total traffic).";
        }
    }

    public ICommand SelectPcapCommand { get; }
    public ICommand AnalyzePcapCommand { get; }
    public ICommand CancelAnalysisCommand { get; }

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

    private async Task ExecuteAnalyzePcapAsync()
    {
        if (SelectedFile == null || string.IsNullOrWhiteSpace(SelectedFile.FilePath))
        {
            ErrorMessage = "Please select a PCAP file first.";
            return;
        }

        ErrorMessage = string.Empty;
        Status = AnalysisStatus.Analyzing;
        AnalysisStatusText = "Analyzing...";

        _analysisCts = new CancellationTokenSource();

        try
        {
            var result = await _pcapAnalyzer.AnalyzeAsync(SelectedFile.FilePath, _analysisCts.Token);
            AnalysisResult = result;
            Status = AnalysisStatus.Completed;
            AnalysisStatusText = "Analysis completed.";

            // Populate protocols collection
            DisplayedProtocols.Clear();
            foreach (var proto in result.Protocols)
            {
                DisplayedProtocols.Add(proto);
            }

            // Populate packet table with UI safety limit (e.g. 1000 items)
            DisplayedPackets.Clear();
            var itemsToShow = result.PacketDetails.Take(MaxDisplayedPackets).ToList();
            foreach (var packet in itemsToShow)
            {
                DisplayedPackets.Add(packet);
            }

            if (result.PacketCount > MaxDisplayedPackets)
            {
                PacketSummaryText = $"Showing {itemsToShow.Count:N0} of {result.PacketCount:N0} packets";
            }
            else
            {
                PacketSummaryText = $"Showing {result.PacketCount:N0} of {result.PacketCount:N0} packets";
            }

            // Phase 6: Automatically persist completed analysis to SQLite database
            if (_historyService != null)
            {
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var reportData = new AnalysisReportData
                        {
                            AnalysisId = Guid.NewGuid().ToString(),
                            AnalysisTimestamp = DateTime.UtcNow,
                            FileName = SelectedFile.FileName,
                            FilePath = SelectedFile.FilePath,
                            FileSizeBytes = SelectedFile.FileSize,
                            CaptureDurationSeconds = result.Duration.TotalSeconds,
                            TotalPackets = result.PacketCount,
                            TotalBytes = result.TotalBytes,
                            IpsecDetected = result.IpsecPacketCount > 0,
                            IpsecPacketCount = result.IpsecPacketCount,
                            IkePacketCount = result.IkePacketCount,
                            EspPacketCount = result.EspPacketCount,
                            AhPacketCount = result.AhPacketCount,
                            TcpPacketCount = result.TcpPacketCount,
                            UdpPacketCount = result.UdpPacketCount,
                            IcmpPacketCount = result.Protocols.FirstOrDefault(p => p.ProtocolName.Equals("ICMP", StringComparison.OrdinalIgnoreCase))?.PacketCount ?? 0,
                            ProtocolDistribution = result.Protocols.ToList()
                        };

                        if (_ipsecAnalyzer != null)
                        {
                            var ipsec = await _ipsecAnalyzer.GetIpsecAnalysisAsync();
                            if (ipsec != null && ipsec.IsAnalyzed)
                            {
                                reportData.HasIpsecAnalysis = true;
                                reportData.IkeVersion = ipsec.IkevVersion;
                                reportData.ExchangeType = ipsec.ExchangeType;
                                reportData.AuthenticationMethod = ipsec.AuthenticationMethod;
                                reportData.EncryptionAlgorithm = ipsec.EncryptionAlgorithm;
                                reportData.IntegrityAlgorithm = ipsec.IntegrityAlgorithm;
                                reportData.DhGroup = ipsec.DhGroup;
                                reportData.PfsEnabled = ipsec.PfsEnabled;
                                reportData.ReplayProtectionEnabled = ipsec.ReplayProtectionEnabled;
                                reportData.IpsecMode = ipsec.IpsecMode;
                                reportData.Spi = ipsec.Spi;
                                reportData.KeyLifetime = ipsec.KeyLifetime;
                                reportData.SaProposals = ipsec.SaProposals.ToList();
                                reportData.Handshakes = ipsec.Handshakes.ToList();
                                reportData.EspSessions = ipsec.EspSessions.ToList();
                            }
                        }

                        if (_assessmentService != null)
                        {
                            var assessment = await _assessmentService.GetSecurityAssessmentAsync();
                            if (assessment != null && assessment.HasAssessment)
                            {
                                reportData.HasSecurityAssessment = true;
                                reportData.OverallRiskScore = assessment.OverallRiskScore;
                                reportData.RiskLevel = assessment.RiskLevel;
                                reportData.AssessmentCoverage = assessment.AssessmentCoverage;
                                reportData.AssessedParameterCount = assessment.AssessedParameterCount;
                                reportData.UnknownParameterCount = assessment.UnknownParameterCount;
                                reportData.AssessmentSummary = assessment.Summary;
                                reportData.CriticalFindingCount = assessment.CriticalCount;
                                reportData.HighFindingCount = assessment.HighCount;
                                reportData.MediumFindingCount = assessment.MediumCount;
                                reportData.LowFindingCount = assessment.LowCount;
                                reportData.InformationalFindingCount = assessment.InformationalCount;
                                reportData.Findings = assessment.Findings.ToList();
                                reportData.Recommendations = assessment.Recommendations.ToList();
                            }
                        }

                        if (_aiAnalysisService != null)
                        {
                            var ai = await _aiAnalysisService.GetAiAnalysisAsync(result.PacketDetails);
                            if (ai != null && ai.IsModelConnected)
                            {
                                reportData.HasAiAnalysis = true;
                                reportData.AiTrafficType = ai.TrafficType;
                                reportData.AiConfidence = ai.Confidence;
                                reportData.AiPrediction = ai.Prediction;
                                reportData.AnomalyDetected = ai.HasAnomalies;
                                reportData.AiExplanation = ai.Explanation;
                                reportData.TopFeatures = ai.TopFeatures.ToList();
                                reportData.AiFeatures = ai.Features.ToDictionary(k => k.Key, v => v.Value);
                                reportData.AiAnomalies = ai.Anomalies.ToList();
                            }
                        }

                        await _historyService.SaveAnalysisAsync(reportData);
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[PcapAnalysisViewModel] Auto-save to history failed: {ex.Message}");
                    }
                });
            }
        }
        catch (OperationCanceledException)
        {
            Status = AnalysisStatus.Cancelled;
            AnalysisStatusText = "Analysis cancelled.";
        }
        catch (Exception ex)
        {
            Status = AnalysisStatus.Failed;
            AnalysisStatusText = "Analysis failed.";
            ErrorMessage = ex.Message;
        }
        finally
        {
            _analysisCts?.Dispose();
            _analysisCts = null;
        }
    }

    private void ExecuteCancelAnalysis()
    {
        try
        {
            _analysisCts?.Cancel();
        }
        catch
        {
            // Ignore cancellation disposal exceptions
        }
    }
}
