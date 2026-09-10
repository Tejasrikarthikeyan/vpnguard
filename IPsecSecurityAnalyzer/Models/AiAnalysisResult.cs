namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Machine learning / AI classification and anomaly detection results.
/// </summary>
public class AiAnalysisResult
{
    public bool IsModelConnected { get; set; } = false;
    public string? Protocol { get; set; }
    public string? TrafficType { get; set; }
    public string? Prediction { get; set; }
    public double? Confidence { get; set; }
    public Dictionary<string, string> Features { get; set; } = new();
    public List<string> Anomalies { get; set; } = new();

    public string DisplayProtocol => !string.IsNullOrWhiteSpace(Protocol) ? Protocol : "Awaiting analysis";
    public string DisplayTrafficType => !string.IsNullOrWhiteSpace(TrafficType) ? TrafficType : "Awaiting analysis";
    public string DisplayPrediction => !string.IsNullOrWhiteSpace(Prediction) ? Prediction : "Awaiting analysis";
    public string DisplayConfidence => Confidence.HasValue ? $"{Confidence.Value * 100:F1}%" : "Awaiting analysis";
}
