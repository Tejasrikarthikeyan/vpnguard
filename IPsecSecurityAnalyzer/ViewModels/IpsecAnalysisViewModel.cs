using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for the IPsec / IKE Protocol Dissection Page.
/// </summary>
public class IpsecAnalysisViewModel : ViewModelBase
{
    private readonly IIpsecAnalyzer _ipsecAnalyzer;
    private IpsecAnalysisResult _analysisResult = new();

    public IpsecAnalysisViewModel(IIpsecAnalyzer ipsecAnalyzer)
    {
        _ipsecAnalyzer = ipsecAnalyzer;
        _ = LoadAnalysisAsync();
    }

    public IpsecAnalysisResult AnalysisResult
    {
        get => _analysisResult;
        set => SetProperty(ref _analysisResult, value);
    }

    private async Task LoadAnalysisAsync()
    {
        AnalysisResult = await _ipsecAnalyzer.GetIpsecAnalysisAsync();
    }
}
