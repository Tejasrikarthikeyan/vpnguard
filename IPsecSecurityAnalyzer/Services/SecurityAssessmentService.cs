using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Evaluates cryptographic parameters, compliance policies, and risk calculations.
/// Prepared for Phase 5 & 6 rule engine and scoring.
/// </summary>
public class SecurityAssessmentService : ISecurityAssessmentService
{
    public Task<SecurityAssessment> GetSecurityAssessmentAsync()
    {
        // Phase 1: Return empty assessment state (strictly adhering to No Fake Data rule)
        return Task.FromResult(new SecurityAssessment
        {
            OverallRiskScore = null,
            RiskLevel = RiskLevel.Unknown,
            Findings = new List<SecurityFinding>(),
            Recommendations = new List<Recommendation>(),
            AssessmentSummary = "Security assessment will be generated after IPsec analysis.",
            AssessmentTimestamp = null
        });
    }

    public Task<IReadOnlyList<SecurityFinding>> GetFindingsAsync()
    {
        return Task.FromResult<IReadOnlyList<SecurityFinding>>(new List<SecurityFinding>());
    }

    public Task<IReadOnlyList<Recommendation>> GetRecommendationsAsync()
    {
        return Task.FromResult<IReadOnlyList<Recommendation>>(new List<Recommendation>());
    }
}
