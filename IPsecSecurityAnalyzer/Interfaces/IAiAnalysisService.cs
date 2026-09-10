using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for AI/ML-driven protocol identification, traffic classification, and anomaly detection (Phase 4).
/// </summary>
public interface IAiAnalysisService
{
    /// <summary>
    /// Gets the current AI traffic analysis and anomaly detection inference results.
    /// </summary>
    Task<AiAnalysisResult> GetAiAnalysisAsync();
}
