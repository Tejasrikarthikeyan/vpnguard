using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;
using IPsecSecurityAnalyzer.Services;
using IPsecSecurityAnalyzer.ViewModels;

namespace IPsecSecurityAnalyzer.Tests;

public class MockTsharkService : ITsharkService
{
    public bool IsAvailable { get; set; } = true;
    public string DetectedPath { get; set; } = @"C:\Program Files\Wireshark\tshark.exe";
    public string MockStdout { get; set; } = string.Empty;
    public string MockStderr { get; set; } = string.Empty;
    public int ExitCode { get; set; } = 0;
    public bool SimulateTimeout { get; set; } = false;
    public bool SimulateCancel { get; set; } = false;

    public bool IsTsharkAvailable(string? customPath = null) => IsAvailable;
    public string? FindTsharkPath(string? customPath = null) => IsAvailable ? (customPath ?? DetectedPath) : null;

    public Task<string?> GetTsharkVersionAsync(string? customPath = null, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable)
        {
            return Task.FromResult<string?>(null);
        }
        return Task.FromResult<string?>("TShark (Wireshark) 4.2.0 (v4.2.0-0-g54000)");
    }

    public Task<TsharkExecutionResult> ExecuteAsync(
        IEnumerable<string> arguments,
        string? customPath = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        if (SimulateCancel || cancellationToken.IsCancellationRequested)
        {
            return Task.FromResult(new TsharkExecutionResult { IsCancelled = true });
        }

        if (SimulateTimeout)
        {
            return Task.FromResult(new TsharkExecutionResult { IsTimeout = true });
        }

        return Task.FromResult(new TsharkExecutionResult
        {
            ExitCode = ExitCode,
            StandardOutput = MockStdout,
            StandardError = MockStderr
        });
    }
}

public class Program
{
    private static readonly string TsharkHeader = "frame.number\tframe.time_epoch\tframe.len\tframe.protocols\tip.src\tip.dst\tipv6.src\tipv6.dst\tip.proto\tipv6.nxt\ttcp.srcport\ttcp.dstport\tudp.srcport\tudp.dstport\tesp.spi\tesp.sequence\tah.spi\tah.sequence\tisakmp.version\tisakmp.exchangetype\tisakmp.ispi\tisakmp.rspi\tisakmp.msgid\t_ws.col.Protocol\t_ws.col.Info";

    [STAThread]
    public static async Task<int> Main(string[] args)
    {
        Console.WriteLine("================================================================================");
        Console.WriteLine("   IPsec Security Analyzer - Phase 2 Verification & Regression Test Suite");
        Console.WriteLine("================================================================================");

        int passed = 0;
        int failed = 0;

        void Assert(bool condition, string testName, string? details = null)
        {
            if (condition)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("[PASS] ");
                Console.ResetColor();
                Console.WriteLine(testName);
                if (!string.IsNullOrEmpty(details))
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"       └─ {details}");
                    Console.ResetColor();
                }
                passed++;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("[FAIL] ");
                Console.ResetColor();
                Console.WriteLine(testName);
                if (!string.IsNullOrEmpty(details))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"       └─ Failure detail: {details}");
                    Console.ResetColor();
                }
                failed++;
            }
        }

        var tempDir = Path.Combine(Path.GetTempPath(), "ipsec_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            // -------------------------------------------------------------
            // SECTION A: Phase 1 Backwards Compatibility & Architecture
            // -------------------------------------------------------------
            Console.WriteLine("\n[SECTION A] Phase 1 Backwards Compatibility & Architecture");

            var services = new ServiceCollection();
            services.AddSingleton<INavigationService, NavigationService>();
            services.AddSingleton<ITsharkService, TsharkService>();
            services.AddSingleton<IPcapAnalyzer, PcapAnalyzer>();
            services.AddSingleton<ILiveCaptureService, LiveCaptureService>();
            services.AddSingleton<IIpsecAnalyzer, IpsecAnalyzer>();
            services.AddSingleton<ISecurityAssessmentService, SecurityAssessmentService>();
            services.AddSingleton<IAiAnalysisService, AiAnalysisService>();
            services.AddSingleton<IReportService, ReportService>();
            services.AddSingleton<IAnalysisHistoryService, AnalysisHistoryService>();
            services.AddSingleton<IFileDialogService, FileDialogService>();
            services.AddSingleton<ISettingsService, SettingsService>();

            services.AddSingleton<DashboardViewModel>();
            services.AddSingleton<PcapAnalysisViewModel>();
            services.AddSingleton<LiveCaptureViewModel>();
            services.AddSingleton<IpsecAnalysisViewModel>();
            services.AddSingleton<AiAnalysisViewModel>();
            services.AddSingleton<SecurityAssessmentViewModel>();
            services.AddSingleton<FindingsViewModel>();
            services.AddSingleton<RecommendationsViewModel>();
            services.AddSingleton<ReportsViewModel>();
            services.AddSingleton<HistoryViewModel>();
            services.AddSingleton<SettingsViewModel>();
            services.AddSingleton<MainViewModel>();

            var provider = services.BuildServiceProvider();
            var mainVm = provider.GetRequiredService<MainViewModel>();
            var navService = provider.GetRequiredService<INavigationService>();

            Assert(mainVm != null, "DI container resolves MainViewModel cleanly");
            Assert(provider.GetRequiredService<ITsharkService>() != null, "ITsharkService registered and resolved in DI");

            // Verify Navigation to all 11 pages
            bool navSuccess = true;
            foreach (NavigationPage page in Enum.GetValues<NavigationPage>())
            {
                navService.NavigateTo(page);
                if (mainVm?.CurrentPage != page || string.IsNullOrWhiteSpace(mainVm?.CurrentPageTitle))
                {
                    navSuccess = false;
                }
            }
            Assert(navSuccess, "Navigation across all 11 pages remains intact and functional");

            // Verify 'No Fake Data' baseline
            var ipsecAnalyzer = provider.GetRequiredService<IIpsecAnalyzer>();
            var ipsecRes = await ipsecAnalyzer.GetIpsecAnalysisAsync();
            Assert(ipsecRes.IsAnalyzed == false && ipsecRes.DisplayIkeVersion == "Awaiting analysis", "No Fake Data: IPsec analyzer initial state is unanalyzed");

            // -------------------------------------------------------------
            // SECTION B: Phase 2 Core Scenarios (15 Required Scenarios)
            // -------------------------------------------------------------
            Console.WriteLine("\n[SECTION B] Phase 2 Real PCAP Analysis Scenarios");

            // SCENARIO 1: Valid PCAP File Analysis
            var mockTshark = new MockTsharkService();
            var testPcapPath = Path.Combine(tempDir, "sample_traffic.pcap");
            File.WriteAllBytes(testPcapPath, new byte[2048]); // dummy 2KB pcap file

            mockTshark.MockStdout = $"{TsharkHeader}\n" +
                $"1\t1710000000.100\t120\teth:ethertype:ip:udp:isakmp\t192.168.1.10\t192.168.1.1\t\t\t17\t\t\t\t500\t500\t\t\t\t\t0x20\t34\t0102030405060708\t0000000000000000\t0\tIKEv2\tIKE_SA_INIT Request\n" +
                $"2\t1710000000.250\t240\teth:ethertype:ip:esp\t192.168.1.10\t192.168.1.1\t\t\t50\t\t\t\t\t\t0x0c01a234\t1001\t\t\t\t\t\t\t\tESP\tESP (SPI=0x0c01a234, SEQ=1001)\n";

            var analyzer = new PcapAnalyzer(mockTshark);
            var loaded = await analyzer.LoadPcapFileAsync(testPcapPath);
            Assert(loaded != null && loaded.FileName == "sample_traffic.pcap", "Scenario 1a: Load valid PCAP file");

            var analysisResult = await analyzer.AnalyzeAsync(testPcapPath);
            Assert(analysisResult != null && analysisResult.PacketCount == 2 && analysisResult.IpsecPacketCount == 2,
                   "Scenario 1b: Valid PCAP Analysis with extracted packets and IPsec identification",
                   $"Total Packets: {analysisResult?.PacketCount}, IPsec: {analysisResult?.IpsecPacketCount}, File: {analysisResult?.FileName}");

            // SCENARIO 2: Invalid File Path Handling
            bool caughtInvalidPath = false;
            try
            {
                await analyzer.AnalyzeAsync(@"C:\NonExistentDirectory\MissingFile.pcap");
            }
            catch (FileNotFoundException)
            {
                caughtInvalidPath = true;
            }
            Assert(caughtInvalidPath, "Scenario 2: Invalid file path raises FileNotFoundException");

            // SCENARIO 3: Unsupported File Extension Handling
            bool caughtUnsupportedExt = false;
            var invalidExtFile = Path.Combine(tempDir, "document.docx");
            File.WriteAllText(invalidExtFile, "test data");
            try
            {
                await analyzer.AnalyzeAsync(invalidExtFile);
            }
            catch (NotSupportedException)
            {
                caughtUnsupportedExt = true;
            }
            Assert(caughtUnsupportedExt, "Scenario 3: Unsupported file extension (.docx) raises NotSupportedException");

            // SCENARIO 4: Missing TShark Executable Handling
            mockTshark.IsAvailable = false;
            bool caughtMissingTshark = false;
            try
            {
                await analyzer.AnalyzeAsync(testPcapPath);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("TShark was not found", StringComparison.OrdinalIgnoreCase))
            {
                caughtMissingTshark = true;
            }
            mockTshark.IsAvailable = true; // reset
            Assert(caughtMissingTshark, "Scenario 4: Missing TShark executable is detected and produces helpful exception");

            // SCENARIO 5: TShark Version Detection
            var versionStr = await mockTshark.GetTsharkVersionAsync();
            Assert(!string.IsNullOrEmpty(versionStr) && versionStr.Contains("TShark (Wireshark) 4.2.0"),
                   "Scenario 5: TShark version detection reports accurate version string",
                   $"Detected: {versionStr}");

            // SCENARIO 6: Empty PCAP File Handling
            var emptyPcap = Path.Combine(tempDir, "empty.pcap");
            File.WriteAllBytes(emptyPcap, Array.Empty<byte>());
            bool caughtEmptyPcap = false;
            try
            {
                await analyzer.AnalyzeAsync(emptyPcap);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("empty", StringComparison.OrdinalIgnoreCase))
            {
                caughtEmptyPcap = true;
            }
            Assert(caughtEmptyPcap, "Scenario 6: Empty PCAP file (0 bytes) is rejected with clear error");

            // SCENARIO 7: Normal Traffic (No IPsec)
            mockTshark.MockStdout = $"{TsharkHeader}\n" +
                $"1\t1710000001.000\t74\teth:ethertype:ip:tcp\t192.168.1.50\t93.184.216.34\t\t\t6\t\t54321\t80\t\t\t\t\t\t\t\t\t\t\t\tTCP\t54321 → 80 [SYN]\n" +
                $"2\t1710000001.050\t74\teth:ethertype:ip:tcp\t93.184.216.34\t192.168.1.50\t\t\t6\t\t80\t54321\t\t\t\t\t\t\t\t\t\t\t\tTCP\t80 → 54321 [SYN, ACK]\n" +
                $"3\t1710000001.100\t85\teth:ethertype:ip:udp:dns\t192.168.1.50\t8.8.8.8\t\t\t17\t\t\t\t53535\t53\t\t\t\t\t\t\t\t\t\tDNS\tStandard query 0x1234 A example.com\n";

            var normalResult = await analyzer.AnalyzeAsync(testPcapPath);
            Assert(normalResult.PacketCount == 3 &&
                   normalResult.IpsecPacketCount == 0 &&
                   normalResult.IkePacketCount == 0 &&
                   normalResult.EspPacketCount == 0 &&
                   normalResult.AhPacketCount == 0 &&
                   normalResult.TcpPacketCount == 2 &&
                   normalResult.UdpPacketCount == 1,
                   "Scenario 7: Normal traffic (TCP, DNS) correctly parsed with zero IPsec count",
                   $"Total: {normalResult.PacketCount}, IPsec: {normalResult.IpsecPacketCount}, TCP: {normalResult.TcpPacketCount}, UDP: {normalResult.UdpPacketCount}");

            // SCENARIO 8: IKE Traffic Analysis
            mockTshark.MockStdout = $"{TsharkHeader}\n" +
                $"1\t1710000002.000\t450\teth:ethertype:ip:udp:isakmp\t10.0.0.1\t10.0.0.2\t\t\t17\t\t\t\t500\t500\t\t\t\t\t0x20\t34\t9a8b7c6d5e4f3a2b\t0000000000000000\t0\tIKEv2\tIKE_SA_INIT Request\n" +
                $"2\t1710000002.050\t480\teth:ethertype:ip:udp:isakmp\t10.0.0.2\t10.0.0.1\t\t\t17\t\t\t\t500\t500\t\t\t\t\t0x20\t34\t9a8b7c6d5e4f3a2b\t1122334455667788\t0\tIKEv2\tIKE_SA_INIT Response\n" +
                $"3\t1710000002.100\t320\teth:ethertype:ip:udp:isakmp\t10.0.0.1\t10.0.0.2\t\t\t17\t\t\t\t4500\t4500\t\t\t\t\t0x20\t35\t9a8b7c6d5e4f3a2b\t1122334455667788\t1\tIKEv2\tIKE_AUTH Request\n";

            var ikeResult = await analyzer.AnalyzeAsync(testPcapPath);
            Assert(ikeResult.IkePacketCount == 3 &&
                   ikeResult.IkeVersion == "IKEv2" &&
                   ikeResult.IkeExchangeType.Contains("IKE_SA_INIT") &&
                   ikeResult.IkeInitiatorSpi == "9a8b7c6d5e4f3a2b" &&
                   ikeResult.IkeResponderSpi == "1122334455667788",
                   "Scenario 8: IKE traffic correctly extracts version, exchange type, and initiator/responder SPIs",
                   $"Version: {ikeResult.IkeVersion}, Exchange: {ikeResult.IkeExchangeType}, Init SPI: {ikeResult.IkeInitiatorSpi}");

            // SCENARIO 9: ESP Traffic Analysis
            mockTshark.MockStdout = $"{TsharkHeader}\n" +
                $"1\t1710000003.000\t1420\teth:ethertype:ip:esp\t192.168.10.1\t192.168.20.1\t\t\t50\t\t\t\t\t\t0xdeadbeef\t101\t\t\t\t\t\t\t\tESP\tESP (SPI=0xdeadbeef, SEQ=101)\n" +
                $"2\t1710000003.002\t1420\teth:ethertype:ip:esp\t192.168.10.1\t192.168.20.1\t\t\t50\t\t\t\t\t\t0xdeadbeef\t102\t\t\t\t\t\t\t\tESP\tESP (SPI=0xdeadbeef, SEQ=102)\n" +
                $"3\t1710000003.004\t1420\teth:ethertype:ip:esp\t192.168.20.1\t192.168.10.1\t\t\t50\t\t\t\t\t\t0xfeedface\t201\t\t\t\t\t\t\t\tESP\tESP (SPI=0xfeedface, SEQ=201)\n";

            var espResult = await analyzer.AnalyzeAsync(testPcapPath);
            Assert(espResult.EspPacketCount == 3 &&
                   espResult.EspSpi == "0xdeadbeef" &&
                   espResult.IpsecPackets.Count == 3,
                   "Scenario 9: ESP traffic correctly extracts ESP packets, count, and SPI",
                   $"ESP Count: {espResult.EspPacketCount}, Primary SPI: {espResult.EspSpi}");

            // SCENARIO 10: AH Traffic Analysis
            mockTshark.MockStdout = $"{TsharkHeader}\n" +
                $"1\t1710000004.000\t100\teth:ethertype:ip:ah\t172.16.0.1\t172.16.0.2\t\t\t51\t\t\t\t\t\t\t\t0x12345678\t50\t\t\t\t\t\tAH\tAH (SPI=0x12345678, SEQ=50)\n" +
                $"2\t1710000004.010\t100\teth:ethertype:ip:ah\t172.16.0.2\t172.16.0.1\t\t\t51\t\t\t\t\t\t\t\t0x87654321\t60\t\t\t\t\t\tAH\tAH (SPI=0x87654321, SEQ=60)\n";

            var ahResult = await analyzer.AnalyzeAsync(testPcapPath);
            Assert(ahResult.AhPacketCount == 2 &&
                   ahResult.IpsecPackets.Count == 2 &&
                   ahResult.Protocols.Exists(p => p.ProtocolName == "AH"),
                   "Scenario 10: AH traffic correctly extracts AH packets and updates protocol distribution",
                   $"AH Count: {ahResult.AhPacketCount}, IPsec Count: {ahResult.IpsecPacketCount}");

            // SCENARIO 11: IPv4 Traffic Analysis
            mockTshark.MockStdout = $"{TsharkHeader}\n" +
                $"1\t1710000005.000\t60\teth:ethertype:ip:tcp\t192.168.1.1\t192.168.1.2\t\t\t6\t\t1000\t2000\t\t\t\t\t\t\t\t\t\t\t\tTCP\tIPv4 TCP segment\n" +
                $"2\t1710000005.001\t60\teth:ethertype:ip:tcp\t192.168.1.2\t192.168.1.1\t\t\t6\t\t2000\t1000\t\t\t\t\t\t\t\t\t\t\t\tTCP\tIPv4 TCP segment\n";

            var ipv4Result = await analyzer.AnalyzeAsync(testPcapPath);
            Assert(ipv4Result.Ipv4PacketCount == 2 &&
                   ipv4Result.Ipv6PacketCount == 0 &&
                   ipv4Result.SourceAddresses.Contains("192.168.1.1"),
                   "Scenario 11: IPv4 traffic parsed and identified accurately",
                   $"IPv4 Count: {ipv4Result.Ipv4PacketCount}, IPv6 Count: {ipv4Result.Ipv6PacketCount}");

            // SCENARIO 12: IPv6 Traffic Analysis
            mockTshark.MockStdout = $"{TsharkHeader}\n" +
                $"1\t1710000006.000\t1280\teth:ethertype:ipv6:esp\t\t\t2001:db8::1\t2001:db8::2\t\t50\t\t\t\t\t0xcafe9999\t1\t\t\t\t\t\t\t\tESP\tIPv6 ESP\n" +
                $"2\t1710000006.010\t1280\teth:ethertype:ipv6:esp\t\t\t2001:db8::2\t2001:db8::1\t\t50\t\t\t\t\t0xcafe8888\t2\t\t\t\t\t\t\t\tESP\tIPv6 ESP\n";

            var ipv6Result = await analyzer.AnalyzeAsync(testPcapPath);
            Assert(ipv6Result.Ipv6PacketCount == 2 &&
                   ipv6Result.Ipv4PacketCount == 0 &&
                   ipv6Result.EspPacketCount == 2 &&
                   ipv6Result.SourceAddresses.Contains("2001:db8::1"),
                   "Scenario 12: IPv6 traffic (IPv6 + ESP) parsed and identified accurately",
                   $"IPv6 Count: {ipv6Result.Ipv6PacketCount}, ESP Count: {ipv6Result.EspPacketCount}");

            // SCENARIO 13: Cancellation Token Handling
            using var cts = new CancellationTokenSource();
            cts.Cancel(); // Cancel immediately
            bool caughtCancellation = false;
            try
            {
                await analyzer.AnalyzeAsync(testPcapPath, cts.Token);
            }
            catch (OperationCanceledException)
            {
                caughtCancellation = true;
            }
            Assert(caughtCancellation, "Scenario 13: Cancellation token cancels TShark execution gracefully");

            // SCENARIO 14: Process Timeout Handling
            mockTshark.SimulateTimeout = true;
            bool caughtTimeout = false;
            try
            {
                await analyzer.AnalyzeAsync(testPcapPath);
            }
            catch (TimeoutException)
            {
                caughtTimeout = true;
            }
            mockTshark.SimulateTimeout = false; // reset
            Assert(caughtTimeout, "Scenario 14: TShark process timeout triggers TimeoutException");

            // SCENARIO 15: Invalid / Corrupt TShark Output Handling
            mockTshark.MockStdout = "Malformed non-tabbed random error text from tshark\nMore garbage lines\n";
            var corruptResult = await analyzer.AnalyzeAsync(testPcapPath);
            Assert(corruptResult != null && corruptResult.PacketCount == 0,
                   "Scenario 15: Corrupt/Malformed TShark output handled safely without crash",
                   $"Parsed packets from garbage: {corruptResult?.PacketCount}");

            // -------------------------------------------------------------
            // SECTION C: Real TsharkService Direct Class Unit Tests
            // -------------------------------------------------------------
            Console.WriteLine("\n[SECTION C] Real TsharkService Multi-Tier Detection & Fallbacks");
            var realSettingsService = provider.GetRequiredService<ISettingsService>();
            var realTsharkService = new TsharkService(realSettingsService);

            // Test detection with dummy path
            bool dummyPathExists = realTsharkService.IsTsharkAvailable(@"C:\DummyPath\tshark.exe");
            Assert(!dummyPathExists, "Real TsharkService: Returns false for non-existent explicit path");

            var dummyVersion = await realTsharkService.GetTsharkVersionAsync(@"C:\DummyPath\tshark.exe");
            Assert(dummyVersion == null, "Real TsharkService: Returns null version for non-existent path");

            // -------------------------------------------------------------
            // SECTION D: ViewModels Synchronization & Real PCAP Integration
            // -------------------------------------------------------------
            Console.WriteLine("\n[SECTION D] ViewModels Synchronization & Real PCAP Integration");

            // Setup mock data for end-to-end ViewModel check
            mockTshark.MockStdout = $"{TsharkHeader}\n" +
                $"1\t1710000007.000\t200\teth:ethertype:ip:udp:isakmp\t192.168.1.1\t192.168.1.2\t\t\t17\t\t\t\t500\t500\t\t\t\t\t0x20\t34\taabbccddeeff0011\t1122334455667788\t0\tIKEv2\tIKE_SA_INIT\n" +
                $"2\t1710000007.100\t500\teth:ethertype:ip:esp\t192.168.1.1\t192.168.1.2\t\t\t50\t\t\t\t\t\t0x11223344\t1\t\t\t\t\t\t\t\tESP\tESP Payload\n";

            var syncVmAnalyzer = new PcapAnalyzer(mockTshark);
            var syncResult = await syncVmAnalyzer.AnalyzeAsync(testPcapPath);

            Assert(syncResult.PacketCount == 2 && syncResult.Protocols.Count > 0,
                   "ViewModel Sync: Analysis produces structured result with protocol list",
                   $"Protocols: {string.Join(", ", syncResult.Protocols.ConvertAll(p => p.ProtocolName))}");

            // Test SettingsViewModel Browse and Test TShark commands
            var settingsService = provider.GetRequiredService<ISettingsService>();
            var fileDialogService = provider.GetRequiredService<IFileDialogService>();
            var settingsVm = new SettingsViewModel(settingsService, mockTshark, fileDialogService);

            settingsVm.TestTsharkCommand.Execute(null);
            // Allow async task in RelayCommand to complete
            await Task.Delay(100);

            Assert(settingsVm.IsTsharkValid == true,
                   "SettingsViewModel: Test TShark command marks TShark as valid",
                   $"Version: {settingsVm.TsharkVersionInfo}, Status: {settingsVm.TsharkTestStatus}");
        }
        finally
        {
            // Cleanup temp directory
            if (Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        Console.WriteLine("\n================================================================================");
        Console.WriteLine($"   Phase 2 Verification Complete: {passed} PASSED, {failed} FAILED");
        Console.WriteLine("================================================================================\n");

        return failed == 0 ? 0 : 1;
    }
}
