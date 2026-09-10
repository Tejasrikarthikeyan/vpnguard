namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Record of a previous PCAP or live stream security analysis stored in history/database.
/// </summary>
public class AnalysisHistory
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string FileName { get; set; } = string.Empty;
    public string AnalysisType { get; set; } = "PCAP Static";
    public DateTime Date { get; set; } = DateTime.UtcNow;
    public string Status { get; set; } = "Completed";
    public RiskLevel RiskLevel { get; set; } = RiskLevel.Unknown;
    public long FileSizeBytes { get; set; }

    public string FormattedDate => Date.ToString("yyyy-MM-dd HH:mm:ss");
    public string FormattedRiskLevel => RiskLevel.ToString();
}
