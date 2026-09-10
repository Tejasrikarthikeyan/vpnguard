namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Navigation pages supported within the application.
/// </summary>
public enum NavigationPage
{
    Dashboard,
    PcapAnalysis,
    LiveCapture,
    IpsecAnalysis,
    AiAnalysis,
    SecurityAssessment,
    Findings,
    Recommendations,
    Reports,
    History,
    Settings
}

/// <summary>
/// Severity levels for security findings and recommendations.
/// </summary>
public enum SeverityLevel
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Overall risk classification levels.
/// </summary>
public enum RiskLevel
{
    Unknown,
    Low,
    Moderate,
    High,
    Critical
}

/// <summary>
/// Status of security findings.
/// </summary>
public enum FindingStatus
{
    Open,
    Investigating,
    Mitigated,
    FalsePositive,
    Resolved
}

/// <summary>
/// Types of protocol analysis available in the framework.
/// </summary>
public enum AnalysisType
{
    PcapStatic,
    LiveStream,
    IkeHandshake,
    EspTraffic,
    HybridAi
}

/// <summary>
/// Execution status states for the PCAP analyzer engine.
/// </summary>
public enum AnalysisStatus
{
    NotSelected,
    Ready,
    Analyzing,
    Completed,
    Failed,
    Cancelled
}

