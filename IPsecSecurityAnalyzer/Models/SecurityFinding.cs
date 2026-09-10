namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Represents an identified security vulnerability, misconfiguration, or compliance deviation.
/// </summary>
public class SecurityFinding
{
    public string Id { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Evidence { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; }
    public double RiskContribution { get; set; }
    public string Recommendation { get; set; } = string.Empty;
    public double Confidence { get; set; }
    public string ObservedOrInferred { get; set; } = "Observed";
    public FindingStatus Status { get; set; } = FindingStatus.Open;

    public string FormattedSeverity => Severity.ToString().ToUpperInvariant();
    public string FormattedRiskContribution => $"{RiskContribution:F1}";
    public string FormattedConfidence => $"{Confidence * 100:F0}%";
}
