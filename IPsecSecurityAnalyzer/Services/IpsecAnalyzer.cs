using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Dissects IKE / ESP transforms, security associations, and key exchanges.
/// Prepared for Phase 3 deep protocol dissection engine.
/// </summary>
public class IpsecAnalyzer : IIpsecAnalyzer
{
    public Task<IpsecAnalysisResult> GetIpsecAnalysisAsync()
    {
        // Phase 1: Return unanalyzed state (strictly adheres to No Fake Data rule)
        return Task.FromResult(new IpsecAnalysisResult
        {
            IsAnalyzed = false
        });
    }
}
