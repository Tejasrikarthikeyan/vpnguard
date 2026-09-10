using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for persisting and querying historical analysis records via SQLite (Phase 7).
/// </summary>
public interface IAnalysisHistoryService
{
    /// <summary>
    /// Retrieves historic analysis execution records from the database.
    /// </summary>
    Task<IReadOnlyList<AnalysisHistory>> GetHistoryAsync();

    /// <summary>
    /// Saves a newly completed analysis run to history.
    /// </summary>
    Task AddHistoryRecordAsync(AnalysisHistory record);
}
