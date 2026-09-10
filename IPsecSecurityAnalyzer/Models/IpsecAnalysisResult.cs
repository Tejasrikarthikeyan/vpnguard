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

    // Traffic Information
    public string? SourceAddress { get; set; }
    public string? DestinationAddress { get; set; }
    public long? PacketCount { get; set; }
    public string? TrafficType { get; set; }

    // Display helpers that adhere strictly to "No fake data rule"
    public string DisplayIkeVersion => !string.IsNullOrWhiteSpace(IkevVersion) ? IkevVersion : "Awaiting analysis";
    public string DisplayExchangeType => !string.IsNullOrWhiteSpace(ExchangeType) ? ExchangeType : "Awaiting analysis";
    public string DisplayAuthMethod => !string.IsNullOrWhiteSpace(AuthenticationMethod) ? AuthenticationMethod : "Awaiting analysis";
    public string DisplayEncryption => !string.IsNullOrWhiteSpace(EncryptionAlgorithm) ? EncryptionAlgorithm : "Awaiting analysis";
    public string DisplayIntegrity => !string.IsNullOrWhiteSpace(IntegrityAlgorithm) ? IntegrityAlgorithm : "Awaiting analysis";
    public string DisplayDhGroup => !string.IsNullOrWhiteSpace(DhGroup) ? DhGroup : "Awaiting analysis";
    
    public string DisplayPfs => PfsEnabled.HasValue ? (PfsEnabled.Value ? "Enabled" : "Disabled") : "Awaiting analysis";
    public string DisplayReplayProtection => ReplayProtectionEnabled.HasValue ? (ReplayProtectionEnabled.Value ? "Enabled" : "Disabled") : "Awaiting analysis";
    public string DisplayIpsecMode => !string.IsNullOrWhiteSpace(IpsecMode) ? IpsecMode : "Awaiting analysis";
    public string DisplayProtocol => !string.IsNullOrWhiteSpace(Protocol) ? Protocol : "Awaiting analysis";
    public string DisplaySpi => !string.IsNullOrWhiteSpace(Spi) ? Spi : "Awaiting analysis";
    public string DisplayKeyLifetime => !string.IsNullOrWhiteSpace(KeyLifetime) ? KeyLifetime : "Awaiting analysis";

    public string DisplaySourceAddress => !string.IsNullOrWhiteSpace(SourceAddress) ? SourceAddress : "Awaiting analysis";
    public string DisplayDestAddress => !string.IsNullOrWhiteSpace(DestinationAddress) ? DestinationAddress : "Awaiting analysis";
    public string DisplayPacketCount => PacketCount.HasValue ? PacketCount.Value.ToString("N0") : "Awaiting analysis";
    public string DisplayTrafficType => !string.IsNullOrWhiteSpace(TrafficType) ? TrafficType : "Awaiting analysis";
}
