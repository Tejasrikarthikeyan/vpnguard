using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Dissects IKE / ESP transforms, security associations, and key exchanges.
/// Populates observable Phase 2 parameters from real PCAP dissections.
/// </summary>
public class IpsecAnalyzer : IIpsecAnalyzer
{
    private readonly IPcapAnalyzer _pcapAnalyzer;

    public IpsecAnalyzer(IPcapAnalyzer pcapAnalyzer)
    {
        _pcapAnalyzer = pcapAnalyzer;
    }

    public Task<IpsecAnalysisResult> GetIpsecAnalysisAsync()
    {
        var lastResult = _pcapAnalyzer.LastAnalysisResult;
        if (lastResult == null)
        {
            return Task.FromResult(new IpsecAnalysisResult
            {
                IsAnalyzed = false
            });
        }

        var result = new IpsecAnalysisResult
        {
            IsAnalyzed = true,
            IkePacketCount = lastResult.IkePacketCount,
            EspPacketCount = lastResult.EspPacketCount,
            AhPacketCount = lastResult.AhPacketCount,
            PacketCount = lastResult.IpsecPacketCount
        };

        if (lastResult.IkePacketCount > 0)
        {
            result.IkevVersion = lastResult.IkeVersion != "Unknown" ? lastResult.IkeVersion : "IKE Detected";
            result.ExchangeType = lastResult.IkeExchangeType != "Unknown" ? lastResult.IkeExchangeType : "Unknown";
        }

        if (lastResult.EspPacketCount > 0)
        {
            result.Protocol = "ESP";
            result.Spi = lastResult.EspSpi != "Unknown" ? lastResult.EspSpi : "Observed in stream";
        }
        else if (lastResult.IkePacketCount > 0)
        {
            result.Protocol = "ISAKMP / IKE";
            result.Spi = lastResult.IkeInitiatorSpi != "Unknown" ? lastResult.IkeInitiatorSpi : "Observed in stream";
        }
        else if (lastResult.AhPacketCount > 0)
        {
            result.Protocol = "AH";
        }
        else
        {
            result.Protocol = "None";
            result.TrafficType = "No IPsec traffic detected";
        }

        if (lastResult.HasIpsecTraffic)
        {
            result.TrafficType = $"IPsec ({lastResult.IpsecPacketCount:N0} packets: {lastResult.IkePacketCount:N0} IKE, {lastResult.EspPacketCount:N0} ESP, {lastResult.AhPacketCount:N0} AH)";
        }

        if (lastResult.SourceAddresses.Count > 0)
        {
            result.SourceAddress = string.Join(", ", lastResult.SourceAddresses.Take(3));
        }

        if (lastResult.DestinationAddresses.Count > 0)
        {
            result.DestinationAddress = string.Join(", ", lastResult.DestinationAddresses.Take(3));
        }

        return Task.FromResult(result);
    }
}
