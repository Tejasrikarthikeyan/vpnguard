using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Manages historical audit sessions and query records.
/// Prepared for Phase 7 SQLite database connection.
/// </summary>
public class AnalysisHistoryService : IAnalysisHistoryService
{
    private readonly List<AnalysisHistory> _inMemoryHistory = new();

    public Task<IReadOnlyList<AnalysisHistory>> GetHistoryAsync()
    {
        // Phase 1: Return empty history list
        return Task.FromResult<IReadOnlyList<AnalysisHistory>>(_inMemoryHistory);
    }

    public Task AddHistoryRecordAsync(AnalysisHistory record)
    {
        _inMemoryHistory.Add(record);
        return Task.CompletedTask;
    }
}
