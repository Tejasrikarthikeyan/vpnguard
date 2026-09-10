using IPsecSecurityAnalyzer.Interfaces;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Generates PDF and structured compliance reports.
/// Prepared for Phase 7 QuestPDF / MigraDoc report generator.
/// </summary>
public class ReportService : IReportService
{
    private readonly List<string> _generatedReports = new();

    public Task<string> GeneratePdfReportAsync(string destinationPath)
    {
        // Phase 1 placeholder
        return Task.FromResult(string.Empty);
    }

    public Task<IReadOnlyList<string>> GetGeneratedReportsAsync()
    {
        return Task.FromResult<IReadOnlyList<string>>(_generatedReports);
    }
}
