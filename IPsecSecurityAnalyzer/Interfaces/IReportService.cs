namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for generating and exporting PDF/HTML security audit reports (Phase 7).
/// </summary>
public interface IReportService
{
    /// <summary>
    /// Generates a comprehensive PDF security assessment report for the active analysis.
    /// </summary>
    Task<string> GeneratePdfReportAsync(string destinationPath);

    /// <summary>
    /// Retrieves a list of previously generated report records.
    /// </summary>
    Task<IReadOnlyList<string>> GetGeneratedReportsAsync();
}
