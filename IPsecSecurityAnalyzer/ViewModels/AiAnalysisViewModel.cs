using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for AI/ML Traffic Classification and Anomaly Detection (Phase 4).
/// </summary>
public class AiAnalysisViewModel : ViewModelBase
{
    private readonly IAiAnalysisService _aiAnalysisService;
    private AiAnalysisResult _aiResult = new();

    public AiAnalysisViewModel(IAiAnalysisService aiAnalysisService)
    {
        _aiAnalysisService = aiAnalysisService;
        _ = LoadAiAnalysisAsync();
    }

    public AiAnalysisResult AiResult
    {
        get => _aiResult;
        set
        {
            if (SetProperty(ref _aiResult, value))
            {
                OnPropertyChanged(nameof(IsModelConnected));
            }
        }
    }

    public bool IsModelConnected => _aiResult.IsModelConnected;
    public string ModelStatusText => _aiResult.IsModelConnected ? "Model Active" : "No model has been connected.";
    public string EmptyNoticeText => "AI analysis not available yet.";

    private async Task LoadAiAnalysisAsync()
    {
        AiResult = await _aiAnalysisService.GetAiAnalysisAsync();
    }
}
