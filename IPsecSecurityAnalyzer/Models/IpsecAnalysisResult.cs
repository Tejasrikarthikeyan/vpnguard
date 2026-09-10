namespace IPsecSecurityAnalyzer.Models;

/// <summary>
/// Detailed parameters extracted from IKE/IPsec/ESP handshake and tunnel negotiations.
/// </summary>
public class IpsecAnalysisResult
{
    public bool IsAnalyzed { get; set; } = false;

    // IKE Information
    public string? IkevVersion { get; set; }
    public string? ExchangeType { get; set; }
    public string? AuthenticationMethod { get; set; }
    public string? EncryptionAlgorithm { get; set; }
    public string? IntegrityAlgorithm { get; set; }
    public string? DhGroup { get; set; }

    // IPsec / ESP Information
    public bool? PfsEnabled { get; set; }
    public bool? ReplayProtectionEnabled { get; set; }
    public string? IpsecMode { get; set; }
    public string? Protocol { get; set; }
    public string? Spi { get; set; }
    public string? KeyLifetime { get; set; }

    // Real Packet Counts
    public long? IkePacketCount { get; set; }
    public long? EspPacketCount { get; set; }
    public long? AhPacketCount { get; set; }

    // Traffic Information
    public string? SourceAddress { get; set; }
    public string? DestinationAddress { get; set; }
    public long? PacketCount { get; set; }
    public string? TrafficType { get; set; }

    // Display helpers that adhere strictly to "No fake data rule"
    public string DisplayIkeVersion => !string.IsNullOrWhiteSpace(IkevVersion) ? IkevVersion : (IsAnalyzed ? "Unknown" : "Awaiting analysis");
    public string DisplayExchangeType => !string.IsNullOrWhiteSpace(ExchangeType) ? ExchangeType : (IsAnalyzed ? "Unknown" : "Awaiting analysis");
    public string DisplayAuthMethod => !string.IsNullOrWhiteSpace(AuthenticationMethod) ? AuthenticationMethod : (IsAnalyzed ? "Not analyzed yet" : "Awaiting analysis");
    public string DisplayEncryption => !string.IsNullOrWhiteSpace(EncryptionAlgorithm) ? EncryptionAlgorithm : (IsAnalyzed ? "Not analyzed yet" : "Awaiting analysis");
    public string DisplayIntegrity => !string.IsNullOrWhiteSpace(IntegrityAlgorithm) ? IntegrityAlgorithm : (IsAnalyzed ? "Not analyzed yet" : "Awaiting analysis");
    public string DisplayDhGroup => !string.IsNullOrWhiteSpace(DhGroup) ? DhGroup : (IsAnalyzed ? "Not analyzed yet" : "Awaiting analysis");
    
    public string DisplayPfs => PfsEnabled.HasValue ? (PfsEnabled.Value ? "Enabled" : "Disabled") : (IsAnalyzed ? "Not analyzed yet" : "Awaiting analysis");
    public string DisplayReplayProtection => ReplayProtectionEnabled.HasValue ? (ReplayProtectionEnabled.Value ? "Enabled" : "Disabled") : (IsAnalyzed ? "Not analyzed yet" : "Awaiting analysis");
    public string DisplayIpsecMode => !string.IsNullOrWhiteSpace(IpsecMode) ? IpsecMode : (IsAnalyzed ? "Not analyzed yet" : "Awaiting analysis");
    public string DisplayProtocol => !string.IsNullOrWhiteSpace(Protocol) ? Protocol : (IsAnalyzed ? "Unknown" : "Awaiting analysis");
    public string DisplaySpi => !string.IsNullOrWhiteSpace(Spi) ? Spi : (IsAnalyzed ? "Unknown" : "Awaiting analysis");
    public string DisplayKeyLifetime => !string.IsNullOrWhiteSpace(KeyLifetime) ? KeyLifetime : (IsAnalyzed ? "Not analyzed yet" : "Awaiting analysis");

    public string DisplayIkePackets => IkePacketCount.HasValue ? IkePacketCount.Value.ToString("N0") : (IsAnalyzed ? "0" : "Awaiting analysis");
    public string DisplayEspPackets => EspPacketCount.HasValue ? EspPacketCount.Value.ToString("N0") : (IsAnalyzed ? "0" : "Awaiting analysis");
    public string DisplayAhPackets => AhPacketCount.HasValue ? AhPacketCount.Value.ToString("N0") : (IsAnalyzed ? "0" : "Awaiting analysis");

    public string DisplaySourceAddress => !string.IsNullOrWhiteSpace(SourceAddress) ? SourceAddress : (IsAnalyzed ? "Not observed" : "Awaiting analysis");
    public string DisplayDestAddress => !string.IsNullOrWhiteSpace(DestinationAddress) ? DestinationAddress : (IsAnalyzed ? "Not observed" : "Awaiting analysis");
    public string DisplayPacketCount => PacketCount.HasValue ? PacketCount.Value.ToString("N0") : (IsAnalyzed ? "0" : "Awaiting analysis");
    public string DisplayTrafficType => !string.IsNullOrWhiteSpace(TrafficType) ? TrafficType : (IsAnalyzed ? "Unknown" : "Awaiting analysis");
}
