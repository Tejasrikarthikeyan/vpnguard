using System.Globalization;
using System.IO;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Real PCAP / PCAPNG packet analysis engine powered by TShark packet dissection.
/// Extracts observable protocol frames, validates IPsec/IKE/ESP/AH indicators, and aggregates traffic metrics.
/// </summary>
public class PcapAnalyzer : IPcapAnalyzer
{
    private readonly ITsharkService _tsharkService;
    private PcapFileInfo? _currentFile;
    private PcapAnalysisResult? _lastAnalysisResult;

    public PcapFileInfo? CurrentFile => _currentFile;
    public PcapAnalysisResult? LastAnalysisResult => _lastAnalysisResult;

    public event EventHandler<PcapFileInfo?>? FileChanged;
    public event EventHandler<PcapAnalysisResult?>? AnalysisCompleted;

    public PcapAnalyzer(ITsharkService tsharkService)
    {
        _tsharkService = tsharkService;
    }

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

    public async Task<PcapAnalysisResult> AnalyzeAsync(string filePath, CancellationToken cancellationToken = default)
    {
        // 1. Validation
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("Capture file path cannot be empty.", nameof(filePath));
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
        if (fileInfo.Length == 0)
        {
            throw new InvalidOperationException("The capture file is empty (0 bytes).");
        }

        // 2. Verify TShark availability
        if (!_tsharkService.IsTsharkAvailable())
        {
            throw new InvalidOperationException("TShark was not found. Install Wireshark or configure the TShark path in Settings.");
        }

        // 3. Build TShark arguments for direct extraction
        // Field extraction query using -T fields
        var arguments = new List<string>
        {
            "-r", filePath,
            "-T", "fields",
            "-E", "header=y",
            "-E", "separator=\t",
            "-E", "occurrence=f",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "frame.len",
            "-e", "frame.protocols",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ipv6.src",
            "-e", "ipv6.dst",
            "-e", "ip.proto",
            "-e", "ipv6.nxt",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "esp.spi",
            "-e", "esp.sequence",
            "-e", "ah.spi",
            "-e", "ah.sequence",
            "-e", "isakmp.version",
            "-e", "isakmp.exchangetype",
            "-e", "isakmp.ispi",
            "-e", "isakmp.rspi",
            "-e", "isakmp.msgid",
            "-e", "_ws.col.Protocol",
            "-e", "_ws.col.Info"
        };

        var execResult = await _tsharkService.ExecuteAsync(arguments, null, TimeSpan.FromSeconds(90), cancellationToken);

        if (execResult.IsCancelled)
        {
            throw new OperationCanceledException("Analysis cancelled by user.");
        }

        if (execResult.IsTimeout)
        {
            throw new TimeoutException("TShark execution timed out while analyzing the capture file.");
        }

        if (!execResult.IsSuccess && string.IsNullOrWhiteSpace(execResult.StandardOutput))
        {
            throw new InvalidOperationException($"TShark analysis failed: {execResult.StandardError}");
        }

        // 4. Parse extracted fields into structured result
        var result = ParseTsharkOutput(execResult.StandardOutput, fileInfo);

        _lastAnalysisResult = result;
        AnalysisCompleted?.Invoke(this, result);

        return result;
    }

    public Task<TrafficStatistics> GetTrafficStatisticsAsync()
    {
        if (_lastAnalysisResult == null)
        {
            return Task.FromResult(new TrafficStatistics());
        }

        var stats = new TrafficStatistics
        {
            TotalPackets = _lastAnalysisResult.PacketCount,
            TotalBytes = _lastAnalysisResult.TotalBytes,
            Duration = _lastAnalysisResult.Duration,
            SourceCount = _lastAnalysisResult.SourceAddresses.Count,
            DestinationCount = _lastAnalysisResult.DestinationAddresses.Count
        };

        return Task.FromResult(stats);
    }

    public static PcapAnalysisResult ParseTsharkOutput(string tsharkStdout, FileInfo fileInfo)
    {
        var result = new PcapAnalysisResult
        {
            FileName = fileInfo.Name,
            FilePath = fileInfo.FullName,
            FileSize = fileInfo.Length
        };

        if (string.IsNullOrWhiteSpace(tsharkStdout))
        {
            return result;
        }

        using var reader = new StringReader(tsharkStdout);
        var headerLine = reader.ReadLine();
        if (string.IsNullOrWhiteSpace(headerLine))
        {
            return result;
        }

        var headers = headerLine.Split('\t');
        var colMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < headers.Length; i++)
        {
            colMap[headers[i].Trim()] = i;
        }

        // Validate that this is indeed valid TShark field output containing known frame/packet columns
        if (!colMap.ContainsKey("frame.number") && !colMap.ContainsKey("frame.len") && !colMap.ContainsKey("ip.src"))
        {
            return result;
        }

        string GetCol(string[] cols, string colName)
        {
            if (colMap.TryGetValue(colName, out var idx) && idx < cols.Length)
            {
                return cols[idx].Trim();
            }
            return string.Empty;
        }

        double minEpoch = double.MaxValue;
        double maxEpoch = double.MinValue;
        var sourceSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var destSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Protocol counters (Name -> (Packets, Bytes))
        var protocolMap = new Dictionary<string, (long packets, long bytes)>(StringComparer.OrdinalIgnoreCase);

        void AccumulateProto(string protoName, long bytes)
        {
            if (string.IsNullOrWhiteSpace(protoName)) return;
            if (protocolMap.TryGetValue(protoName, out var val))
            {
                protocolMap[protoName] = (val.packets + 1, val.bytes + bytes);
            }
            else
            {
                protocolMap[protoName] = (1, bytes);
            }
        }

        string? line;
        long packetCount = 0;
        long totalBytes = 0;

        while ((line = reader.ReadLine()) != null)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            var cols = line.Split('\t');
            packetCount++;

            // Packet number
            long.TryParse(GetCol(cols, "frame.number"), out var frameNum);
            if (frameNum <= 0) frameNum = packetCount;

            // Frame length & bytes
            long.TryParse(GetCol(cols, "frame.len"), out var frameLen);
            totalBytes += frameLen;

            // Epoch & Timestamp
            var epochStr = GetCol(cols, "frame.time_epoch");
            var timestampFormatted = "Unknown";
            if (double.TryParse(epochStr, NumberStyles.Float, CultureInfo.InvariantCulture, out var epoch))
            {
                if (epoch < minEpoch) minEpoch = epoch;
                if (epoch > maxEpoch) maxEpoch = epoch;

                try
                {
                    var dto = DateTimeOffset.FromUnixTimeMilliseconds((long)(epoch * 1000));
                    timestampFormatted = dto.ToString("yyyy-MM-dd HH:mm:ss.fff");
                }
                catch
                {
                    timestampFormatted = epoch.ToString("F3", CultureInfo.InvariantCulture);
                }
            }

            // IPs
            var ipSrc = GetCol(cols, "ip.src");
            var ipDst = GetCol(cols, "ip.dst");
            var ipv6Src = GetCol(cols, "ipv6.src");
            var ipv6Dst = GetCol(cols, "ipv6.dst");

            var srcIp = !string.IsNullOrEmpty(ipSrc) ? ipSrc : (!string.IsNullOrEmpty(ipv6Src) ? ipv6Src : "Unknown");
            var dstIp = !string.IsNullOrEmpty(ipDst) ? ipDst : (!string.IsNullOrEmpty(ipv6Dst) ? ipv6Dst : "Unknown");

            if (!string.IsNullOrEmpty(ipSrc)) sourceSet.Add(ipSrc);
            else if (!string.IsNullOrEmpty(ipv6Src)) sourceSet.Add(ipv6Src);

            if (!string.IsNullOrEmpty(ipDst)) destSet.Add(ipDst);
            else if (!string.IsNullOrEmpty(ipv6Dst)) destSet.Add(ipv6Dst);

            // Protocol tree & dissectors
            var frameProtocols = GetCol(cols, "frame.protocols").ToLowerInvariant();
            var colProto = GetCol(cols, "_ws.col.Protocol");
            var colInfo = GetCol(cols, "_ws.col.Info");
            var ipProto = GetCol(cols, "ip.proto");
            var ipv6Nxt = GetCol(cols, "ipv6.nxt");
            var udpSrc = GetCol(cols, "udp.srcport");
            var udpDst = GetCol(cols, "udp.dstport");

            // IPsec indicators
            var espSpi = GetCol(cols, "esp.spi");
            var espSeq = GetCol(cols, "esp.sequence");
            var ahSpi = GetCol(cols, "ah.spi");
            var ahSeq = GetCol(cols, "ah.sequence");

            var isakmpVer = GetCol(cols, "isakmp.version");
            var isakmpEx = GetCol(cols, "isakmp.exchangetype");
            var isakmpIspi = GetCol(cols, "isakmp.ispi");
            var isakmpRspi = GetCol(cols, "isakmp.rspi");
            var isakmpMsgid = GetCol(cols, "isakmp.msgid");

            // Detect layers
            bool isIpv4 = frameProtocols.Contains("ip:") || frameProtocols.EndsWith(":ip") || !string.IsNullOrEmpty(ipSrc);
            bool isIpv6 = frameProtocols.Contains("ipv6:") || frameProtocols.EndsWith(":ipv6") || !string.IsNullOrEmpty(ipv6Src);

            if (isIpv4)
            {
                result.Ipv4PacketCount++;
                AccumulateProto("IPv4", frameLen);
            }
            if (isIpv6)
            {
                result.Ipv6PacketCount++;
                AccumulateProto("IPv6", frameLen);
            }

            bool isTcp = frameProtocols.Contains(":tcp") || colProto.Equals("TCP", StringComparison.OrdinalIgnoreCase) || ipProto == "6" || ipv6Nxt == "6";
            if (isTcp)
            {
                result.TcpPacketCount++;
                AccumulateProto("TCP", frameLen);
            }

            bool isUdp = frameProtocols.Contains(":udp") || colProto.Equals("UDP", StringComparison.OrdinalIgnoreCase) || ipProto == "17" || ipv6Nxt == "17";
            if (isUdp)
            {
                result.UdpPacketCount++;
                AccumulateProto("UDP", frameLen);
            }

            bool isIcmp = frameProtocols.Contains(":icmp") || frameProtocols.Contains(":icmpv6") || colProto.StartsWith("ICMP", StringComparison.OrdinalIgnoreCase) || ipProto == "1" || ipProto == "58" || ipv6Nxt == "58";
            if (isIcmp)
            {
                AccumulateProto("ICMP", frameLen);
            }

            // IPsec Detection
            bool isIke = frameProtocols.Contains("isakmp") || frameProtocols.Contains("ikev2") || frameProtocols.Contains("ike") ||
                         colProto.StartsWith("IKE", StringComparison.OrdinalIgnoreCase) || colProto.Equals("ISAKMP", StringComparison.OrdinalIgnoreCase) ||
                         udpSrc == "500" || udpDst == "500" || udpSrc == "4500" || udpDst == "4500" ||
                         !string.IsNullOrEmpty(isakmpVer) || !string.IsNullOrEmpty(isakmpIspi);

            bool isEsp = frameProtocols.Contains(":esp") || colProto.Equals("ESP", StringComparison.OrdinalIgnoreCase) || ipProto == "50" || ipv6Nxt == "50" || !string.IsNullOrEmpty(espSpi);
            bool isAh = frameProtocols.Contains(":ah") || colProto.Equals("AH", StringComparison.OrdinalIgnoreCase) || ipProto == "51" || ipv6Nxt == "51" || !string.IsNullOrEmpty(ahSpi);

            string primaryProtocol = !string.IsNullOrEmpty(colProto) ? colProto : "Unknown";

            if (isIke)
            {
                result.IkePacketCount++;
                result.IpsecPacketCount++;
                AccumulateProto("IKE", frameLen);

                primaryProtocol = !string.IsNullOrEmpty(colProto) ? colProto : "IKE";

                // Parse IKE parameters if observable
                if (result.IkeVersion == "Unknown" && !string.IsNullOrEmpty(isakmpVer))
                {
                    result.IkeVersion = FormatIkeVersion(isakmpVer);
                }
                else if (result.IkeVersion == "Unknown" && (colProto.Contains("IKEv2", StringComparison.OrdinalIgnoreCase) || frameProtocols.Contains("ikev2")))
                {
                    result.IkeVersion = "IKEv2";
                }
                else if (result.IkeVersion == "Unknown" && (colProto.Contains("ISAKMP", StringComparison.OrdinalIgnoreCase) || colProto.Contains("IKEv1", StringComparison.OrdinalIgnoreCase)))
                {
                    result.IkeVersion = "IKEv1";
                }

                if (result.IkeExchangeType == "Unknown" && !string.IsNullOrEmpty(isakmpEx))
                {
                    result.IkeExchangeType = FormatIkeExchangeType(isakmpEx);
                }

                if (result.IkeInitiatorSpi == "Unknown" && !string.IsNullOrEmpty(isakmpIspi))
                {
                    result.IkeInitiatorSpi = isakmpIspi;
                }

                if ((result.IkeResponderSpi == "Unknown" || result.IkeResponderSpi == "0000000000000000" || result.IkeResponderSpi == "0x0000000000000000") &&
                    !string.IsNullOrEmpty(isakmpRspi) &&
                    isakmpRspi != "0000000000000000" &&
                    isakmpRspi != "0x0000000000000000")
                {
                    result.IkeResponderSpi = isakmpRspi;
                }
                else if (result.IkeResponderSpi == "Unknown" && !string.IsNullOrEmpty(isakmpRspi))
                {
                    result.IkeResponderSpi = isakmpRspi;
                }

                if (result.IkeMessageId == "Unknown" && !string.IsNullOrEmpty(isakmpMsgid))
                {
                    result.IkeMessageId = isakmpMsgid;
                }

                result.IpsecPackets.Add(new IpsecPacketInfo
                {
                    PacketNumber = frameNum,
                    Timestamp = timestampFormatted,
                    Source = srcIp,
                    Destination = dstIp,
                    Protocol = primaryProtocol,
                    Spi = !string.IsNullOrEmpty(isakmpIspi) ? isakmpIspi : "Unknown",
                    SequenceNumber = !string.IsNullOrEmpty(isakmpMsgid) ? isakmpMsgid : "Unknown",
                    Length = frameLen,
                    Info = !string.IsNullOrEmpty(colInfo) ? colInfo : "IKE Handshake / Message"
                });
            }
            else if (isEsp)
            {
                result.EspPacketCount++;
                result.IpsecPacketCount++;
                AccumulateProto("ESP", frameLen);

                primaryProtocol = "ESP";

                if (result.EspSpi == "Unknown" && !string.IsNullOrEmpty(espSpi))
                {
                    result.EspSpi = espSpi;
                }

                result.IpsecPackets.Add(new IpsecPacketInfo
                {
                    PacketNumber = frameNum,
                    Timestamp = timestampFormatted,
                    Source = srcIp,
                    Destination = dstIp,
                    Protocol = "ESP",
                    Spi = !string.IsNullOrEmpty(espSpi) ? espSpi : "Unknown",
                    SequenceNumber = !string.IsNullOrEmpty(espSeq) ? espSeq : "Unknown",
                    Length = frameLen,
                    Info = !string.IsNullOrEmpty(colInfo) ? colInfo : $"ESP Packet (SPI={espSpi}, SEQ={espSeq})"
                });
            }
            else if (isAh)
            {
                result.AhPacketCount++;
                result.IpsecPacketCount++;
                AccumulateProto("AH", frameLen);

                primaryProtocol = "AH";

                result.IpsecPackets.Add(new IpsecPacketInfo
                {
                    PacketNumber = frameNum,
                    Timestamp = timestampFormatted,
                    Source = srcIp,
                    Destination = dstIp,
                    Protocol = "AH",
                    Spi = !string.IsNullOrEmpty(ahSpi) ? ahSpi : "Unknown",
                    SequenceNumber = !string.IsNullOrEmpty(ahSeq) ? ahSeq : "Unknown",
                    Length = frameLen,
                    Info = !string.IsNullOrEmpty(colInfo) ? colInfo : $"AH Packet (SPI={ahSpi}, SEQ={ahSeq})"
                });
            }
            else if (!string.IsNullOrEmpty(colProto) && !colProto.Equals("TCP", StringComparison.OrdinalIgnoreCase) && !colProto.Equals("UDP", StringComparison.OrdinalIgnoreCase) && !colProto.Equals("IPv4", StringComparison.OrdinalIgnoreCase) && !colProto.Equals("IPv6", StringComparison.OrdinalIgnoreCase))
            {
                AccumulateProto(colProto, frameLen);
            }

            result.PacketDetails.Add(new PacketInfo
            {
                PacketNumber = frameNum,
                Timestamp = timestampFormatted,
                Source = srcIp,
                Destination = dstIp,
                Protocol = primaryProtocol,
                Length = frameLen,
                Info = !string.IsNullOrEmpty(colInfo) ? colInfo : $"{primaryProtocol} traffic"
            });
        }

        result.PacketCount = packetCount;
        result.TotalBytes = totalBytes;
        result.SourceAddresses = sourceSet.OrderBy(x => x).ToList();
        result.DestinationAddresses = destSet.OrderBy(x => x).ToList();

        if (minEpoch != double.MaxValue && maxEpoch != double.MinValue && maxEpoch >= minEpoch)
        {
            result.Duration = TimeSpan.FromSeconds(maxEpoch - minEpoch);
            try
            {
                result.FirstPacketTimestamp = DateTimeOffset.FromUnixTimeMilliseconds((long)(minEpoch * 1000)).ToString("yyyy-MM-dd HH:mm:ss.fff");
                result.LastPacketTimestamp = DateTimeOffset.FromUnixTimeMilliseconds((long)(maxEpoch * 1000)).ToString("yyyy-MM-dd HH:mm:ss.fff");
            }
            catch
            {
                result.FirstPacketTimestamp = minEpoch.ToString(CultureInfo.InvariantCulture);
                result.LastPacketTimestamp = maxEpoch.ToString(CultureInfo.InvariantCulture);
            }
        }

        // Calculate protocol statistics
        var statsList = new List<ProtocolStatistics>();
        foreach (var kvp in protocolMap.OrderByDescending(p => p.Value.packets))
        {
            statsList.Add(new ProtocolStatistics
            {
                ProtocolName = kvp.Key,
                PacketCount = kvp.Value.packets,
                ByteCount = kvp.Value.bytes,
                Percentage = packetCount > 0 ? (double)kvp.Value.packets / packetCount * 100.0 : 0.0
            });
        }
        result.Protocols = statsList;

        return result;
    }

    private static string FormatIkeVersion(string ver)
    {
        var trimmed = ver.Trim();
        if (trimmed.Equals("0x10", StringComparison.OrdinalIgnoreCase) || trimmed.Equals("16") || trimmed.Equals("1.0") || trimmed.Equals("1"))
            return "IKEv1";
        if (trimmed.Equals("0x20", StringComparison.OrdinalIgnoreCase) || trimmed.Equals("32") || trimmed.Equals("2.0") || trimmed.Equals("2"))
            return "IKEv2";
        return trimmed;
    }

    private static string FormatIkeExchangeType(string ex)
    {
        var trimmed = ex.Trim();
        return trimmed switch
        {
            "34" or "0x22" => "IKE_SA_INIT (34)",
            "35" or "0x23" => "IKE_AUTH (35)",
            "36" or "0x24" => "CREATE_CHILD_SA (36)",
            "37" or "0x25" => "INFORMATIONAL (37)",
            "2" => "Identity Protection / Main Mode (2)",
            "4" => "Aggressive Mode (4)",
            "5" => "Informational (5)",
            _ => trimmed
        };
    }
}
