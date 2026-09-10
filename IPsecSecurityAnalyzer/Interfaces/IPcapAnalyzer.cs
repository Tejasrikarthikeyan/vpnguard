using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Interfaces;

/// <summary>
/// Service interface for PCAP file selection, validation, metadata extraction, and future packet inspection.
/// </summary>
public interface IPcapAnalyzer
{
    /// <summary>
    /// Currently loaded PCAP file metadata, or null if none loaded.
    /// </summary>
    PcapFileInfo? CurrentFile { get; }

    /// <summary>
    /// Event triggered when the active PCAP file changes.
    /// </summary>
    event EventHandler<PcapFileInfo?>? FileChanged;

    /// <summary>
    /// Loads and inspects basic file metadata from the specified PCAP/PCAPNG file path.
    /// </summary>
    /// <param name="filePath">Absolute path to .pcap or .pcapng file.</param>
    /// <returns>PcapFileInfo metadata.</returns>
    Task<PcapFileInfo> LoadPcapFileAsync(string filePath);

    /// <summary>
    /// Gets aggregated traffic statistics (to be populated by real analyzer in Phase 2).
    /// </summary>
    Task<TrafficStatistics> GetTrafficStatisticsAsync();
}
