using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for AI/ML Traffic Classification and Anomaly Detection (Phase 5).
/// </summary>
public class AiAnalysisViewModel : ViewModelBase
{
    private readonly IAiAnalysisService _aiAnalysisService;
    private readonly IPcapAnalyzer? _pcapAnalyzer;
    private AiAnalysisResult _aiResult = new();
    private bool _isAnalyzing;
    private string _statusMessage = "Click 'Run AI Analysis' to begin.";

    public AiAnalysisViewModel(
        IAiAnalysisService aiAnalysisService,
        IPcapAnalyzer? pcapAnalyzer = null)
    {
        _aiAnalysisService = aiAnalysisService;
        _pcapAnalyzer = pcapAnalyzer;
        RunAnalysisCommand = new RelayCommand(async () => await RunAnalysisAsync(), () => !IsAnalyzing);
    }

    public ICommand RunAnalysisCommand { get; }

    public AiAnalysisResult AiResult
    {
        get => _aiResult;
        set
        {
            if (SetProperty(ref _aiResult, value))
            {
                OnPropertyChanged(nameof(IsModelConnected));
                OnPropertyChanged(nameof(HasResults));
                OnPropertyChanged(nameof(ModelStatusText));
            }
        }
    }

    public bool IsAnalyzing
    {
        get => _isAnalyzing;
        set => SetProperty(ref _isAnalyzing, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public bool IsModelConnected => _aiResult.IsModelConnected;
    public bool HasResults => _aiResult.IsModelConnected && _aiResult.TrafficType != null;
    public string ModelStatusText => _aiResult.IsModelConnected
        ? "AI Engine Connected"
        : "Python AI environment is not configured.";

    private async Task RunAnalysisAsync()
    {
        IsAnalyzing = true;
        StatusMessage = "Running AI inference...";

        try
        {
            var packets = _pcapAnalyzer?.LastAnalysisResult?.PacketDetails;
            AiResult = await Task.Run(() => _aiAnalysisService.GetAiAnalysisAsync(packets));

            if (AiResult.IsModelConnected)
            {
                StatusMessage = $"Analysis complete — AI-Inferred Traffic Type: {AiResult.TrafficType ?? "Unknown"}";
            }
            else
            {
                StatusMessage = AiResult.ErrorMessage ?? "Python AI environment is not configured.";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Analysis failed: {ex.Message}";
            AiResult = new AiAnalysisResult { IsModelConnected = false, ErrorMessage = ex.Message };
        }
        finally
        {
            IsAnalyzing = false;
        }
    }
}

