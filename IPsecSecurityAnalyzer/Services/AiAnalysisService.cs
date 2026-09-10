using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Performs machine learning protocol classification and anomaly detection.
/// Prepared for Phase 4 ML / Random Forest / Neural Network model integration.
/// </summary>
public class AiAnalysisService : IAiAnalysisService
{
    public Task<AiAnalysisResult> GetAiAnalysisAsync()
    {
        // Phase 1: Return clean empty state (strictly adhering to No Fake Data rule)
        return Task.FromResult(new AiAnalysisResult
        {
            IsModelConnected = false,
            Protocol = null,
            TrafficType = null,
            Prediction = null,
            Confidence = null,
            Features = new Dictionary<string, string>(),
            Anomalies = new List<string>()
        });
    }
}
