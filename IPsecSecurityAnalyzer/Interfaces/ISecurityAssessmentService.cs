using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for evaluating cryptographic strength, rule sets, compliance, and scoring overall risk (Phase 5 & 6).
/// </summary>
public interface ISecurityAssessmentService
{
    /// <summary>
    /// Gets the current comprehensive security assessment.
    /// </summary>
    Task<SecurityAssessment> GetSecurityAssessmentAsync();

    /// <summary>
    /// Gets the list of identified security findings.
    /// </summary>
    Task<IReadOnlyList<SecurityFinding>> GetFindingsAsync();

    /// <summary>
    /// Gets prioritized remediation recommendations.
    /// </summary>
    Task<IReadOnlyList<Recommendation>> GetRecommendationsAsync();
}
