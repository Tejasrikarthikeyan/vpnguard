using System.IO;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Handles PCAP file metadata extraction and validation.
/// Prepared for Phase 2 TShark / PyShark packet dissection integration.
/// </summary>
public class PcapAnalyzer : IPcapAnalyzer
{
    private PcapFileInfo? _currentFile;

    public PcapFileInfo? CurrentFile => _currentFile;

    public event EventHandler<PcapFileInfo?>? FileChanged;

    public Task<PcapFileInfo> LoadPcapFileAsync(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("File path cannot be empty.", nameof(filePath));
        }

        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException("The specified PCAP capture file does not exist.", filePath);
        }

        var ext = Path.GetExtension(filePath).ToLowerInvariant();
        if (ext != ".pcap" && ext != ".pcapng")
        {
            throw new NotSupportedException($"Unsupported capture file format '{ext}'. Only .pcap and .pcapng files are supported.");
        }

        var fileInfo = new FileInfo(filePath);

        _currentFile = new PcapFileInfo
        {
            FileName = fileInfo.Name,
            FilePath = fileInfo.FullName,
            FileSize = fileInfo.Length,
            FileExtension = fileInfo.Extension.ToLowerInvariant(),
            CreatedDate = fileInfo.CreationTime,
            LastModifiedDate = fileInfo.LastWriteTime
        };

        FileChanged?.Invoke(this, _currentFile);

        return Task.FromResult(_currentFile);
    }

    public Task<TrafficStatistics> GetTrafficStatisticsAsync()
    {
        // Phase 1: Return empty statistics without fake numerical values
        return Task.FromResult(new TrafficStatistics());
    }
}
