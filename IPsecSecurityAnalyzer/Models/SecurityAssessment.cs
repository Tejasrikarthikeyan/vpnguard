namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Overall security assessment aggregating cryptographic strength, compliance, and findings.
/// </summary>
public class SecurityAssessment
{
    public double? OverallRiskScore { get; set; }
    public RiskLevel RiskLevel { get; set; } = RiskLevel.Unknown;
    public List<SecurityFinding> Findings { get; set; } = new();
    public List<Recommendation> Recommendations { get; set; } = new();
    public string AssessmentSummary { get; set; } = string.Empty;
    public DateTime? AssessmentTimestamp { get; set; }

    // Section status properties
    public string CryptographicStrengthStatus { get; set; } = "Awaiting analysis";
    public string ProtocolSecurityStatus { get; set; } = "Awaiting analysis";
    public string KeyExchangeSecurityStatus { get; set; } = "Awaiting analysis";
    public string PfsStatus { get; set; } = "Awaiting analysis";
    public string ReplayProtectionStatus { get; set; } = "Awaiting analysis";
    public string SaConfigurationStatus { get; set; } = "Awaiting analysis";
    public string ConfigurationComplianceStatus { get; set; } = "Awaiting analysis";
    public string MetadataExposureStatus { get; set; } = "Awaiting analysis";

    public bool HasAssessment => OverallRiskScore.HasValue && AssessmentTimestamp.HasValue;

    public string FormattedRiskScore => OverallRiskScore.HasValue ? $"{OverallRiskScore.Value:F1} / 100" : "Not available";
    public string FormattedRiskLevel => RiskLevel != RiskLevel.Unknown ? RiskLevel.ToString() : "Awaiting analysis";
    public string FormattedTimestamp => AssessmentTimestamp.HasValue ? AssessmentTimestamp.Value.ToString("yyyy-MM-dd HH:mm:ss") : "Not available";
}
