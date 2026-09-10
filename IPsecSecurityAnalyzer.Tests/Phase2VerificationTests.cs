using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    private static readonly string TsharkHeader = "frame.number\tframe.time_epoch\tframe.len\tframe.protocols\tip.src\tip.dst\tipv6.src\tipv6.dst\tip.proto\tipv6.nxt\ttcp.srcport\ttcp.dstport\tudp.srcport\tudp.dstport\tesp.spi\tesp.sequence\tah.spi\tah.sequence\tisakmp.version\tisakmp.exchangetype\tisakmp.ispi\tisakmp.rspi\tisakmp.msgid\t_ws.col.Protocol\t_ws.col.Info\tisakmp.payload\tisakmp.sa.transform.enc\tisakmp.sa.transform.auth\tisakmp.sa.transform.hash\tisakmp.sa.transform.dh\tisakmp.sa.transform.attr.keylen\tisakmp.sa.transform.attr.lifeduration\tikev2.payload\tikev2.transform.enc\tikev2.transform.integ\tikev2.transform.dh\tikev2.transform.prf\tikev2.nonce\tikev2.ke.dh_group\tikev2.ke.data\tikev2.auth.method";

    [STAThread]
    public static async Task<int> Main(string[] args)
    {
        Console.WriteLine("================================================================================");
        Console.WriteLine("   IPsec Security Analyzer - Phase 3 Verification & Regression Test Suite");
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
                    Console.WriteLine($"       â””â”€ {details}");
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
                    Console.WriteLine($"       â””â”€ Failure detail: {details}");
                    Console.ResetColor();
                }
                failed++;
            }
        }

        var tempDir = Path.Combine(Path.GetTempPath(), "ipsec_phase3_test_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            // -------------------------------------------------------------
            // SECTION A: Foundation & DI Composition Architecture
            // -------------------------------------------------------------
            Console.WriteLine("\n[SECTION A] Architecture & Backwards Compatibility");

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

            // Navigation check
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

            // No Fake Data baseline check
            var ipsecAnalyzer = provider.GetRequiredService<IIpsecAnalyzer>();
            var ipsecRes = await ipsecAnalyzer.GetIpsecAnalysisAsync();
            Assert(ipsecRes.IsAnalyzed == false && ipsecRes.DisplayIkeVersion == "Awaiting analysis", "No Fake Data: IPsec analyzer initial state is unanalyzed");

            // -------------------------------------------------------------
            // SECTION B: Phase 2 Core Scenarios Verification
            // -------------------------------------------------------------
            Console.WriteLine("\n[SECTION B] Phase 2 Real PCAP Analysis Scenarios");

            var mockTshark = new MockTsharkService();
            var testPcapPath = Path.Combine(tempDir, "sample_traffic.pcap");
            File.WriteAllBytes(testPcapPath, new byte[2048]);

            mockTshark.MockStdout = $"{TsharkHeader}\n" +
                $"1\t1710000000.100\t120\teth:ethertype:ip:udp:isakmp\t192.168.1.10\t192.168.1.1\t\t\t17\t\t\t\t500\t500\t\t\t\t\t0x20\t34\t0102030405060708\t0000000000000000\t0\tIKEv2\tIKE_SA_INIT Request\tSA,KE,Ni\t\t\t\t\t\t\tSA,KE,Ni\t7\t12\t14\t4\tdeadbeef01\t14\t11223344\t1\n" +
                $"2\t1710000000.250\t240\teth:ethertype:ip:esp\t192.168.1.10\t192.168.1.1\t\t\t50\t\t\t\t\t\t0x0c01a234\t1001\t\t\t\t\t\t\t\tESP\tESP (SPI=0x0c01a234, SEQ=1001)\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\n";

            var analyzer = new PcapAnalyzer(mockTshark);
            var loaded = await analyzer.LoadPcapFileAsync(testPcapPath);
            Assert(loaded != null && loaded.FileName == "sample_traffic.pcap", "Scenario 1a: Load valid PCAP file");

            var analysisResult = await analyzer.AnalyzeAsync(testPcapPath);
            Assert(analysisResult != null && analysisResult.PacketCount == 2 && analysisResult.IpsecPacketCount == 2,
                   "Scenario 1b: Valid PCAP Analysis with extracted packets and IPsec identification");

            // -------------------------------------------------------------
            // SECTION C: Phase 3 IKEv1/v2 Handshake & SA Proposal Parsing
            // -------------------------------------------------------------
            Console.WriteLine("\n[SECTION C] Phase 3 IKEv1/v2 Handshake & SA Proposal Parsing");

            // TEST 1: IKEv2 SA Proposal with AES-256-CBC, HMAC-SHA256, DH Group 14, PRF
            Assert(analysisResult.SaProposals.Count > 0, "Phase 3: Extracted IKE Security Association proposal suite");
            var saProp = analysisResult.SaProposals.FirstOrDefault();
            Assert(saProp != null && saProp.EncryptionAlgorithm.Contains("AES-CBC") && saProp.IntegrityAlgorithm.Contains("SHA256") && saProp.DhGroup.Contains("Group 14"),
                   "Phase 3: Parsed cryptographic algorithms: AES-CBC, HMAC-SHA256-128, Group 14 (2048-bit MODP)",
                   $"Enc: {saProp?.EncryptionAlgorithm}, Integ: {saProp?.IntegrityAlgorithm}, DH: {saProp?.DhGroup}");

            // TEST 2: IKE Handshake Message Payloads, DH Group, and Nonce Observation
            Assert(analysisResult.NonceObserved && analysisResult.KeyExchangePayloadObserved,
                   "Phase 3: Nonce payload and Key Exchange (KE) payload observed in handshake",
                   $"Nonce: {analysisResult.NonceObserved}, KE: {analysisResult.KeyExchangePayloadObserved}");

            Assert(analysisResult.Handshakes.Count > 0 && analysisResult.Handshakes[0].DhGroup.Contains("Group 14"),
                   "Phase 3: Handshake timeline records exchange type, message ID, role, and DH group",
                   $"Handshake: {analysisResult.Handshakes[0].ExchangeType}, Role: {analysisResult.Handshakes[0].Role}");

            // TEST 3: IKEv1 Aggressive Mode & Legacy Transforms (3DES / MD5 / Group 2)
            mockTshark.MockStdout = $"{TsharkHeader}\n" +
                $"1\t1710000100.000\t350\teth:ethertype:ip:udp:isakmp\t10.10.10.1\t10.10.10.2\t\t\t17\t\t\t\t500\t500\t\t\t\t\t0x10\t4\taabbccddeeff0011\t0000000000000000\t0\tISAKMP\tAggressive Mode Request\tSA,KE,Ni,ID\t5\t1\t1\t2\t192\t28800\t\t\t\t\t\t\t\t\t\n";

            var aggressiveResult = await analyzer.AnalyzeAsync(testPcapPath);
            Assert(aggressiveResult.AggressiveModeDetected, "Phase 3: Detected IKEv1 Aggressive Mode");
            Assert(aggressiveResult.SaProposals.Count > 0 && aggressiveResult.SaProposals[0].IsWeak,
                   "Phase 3: Flagged legacy / weak cipher suite (3DES-CBC, HMAC-MD5, DH Group 2)",
                   $"Rating: {aggressiveResult.SaProposals[0].SecurityRating}, Enc: {aggressiveResult.SaProposals[0].EncryptionAlgorithm}");

            // -------------------------------------------------------------
            // SECTION D: Phase 3 ESP Session Tracking & Replay Detection
            // -------------------------------------------------------------
            Console.WriteLine("\n[SECTION D] Phase 3 ESP Session & Sequence Tracking");

            // TEST 4: ESP Streams Tracking & Monotonic Sequence
            mockTshark.MockStdout = $"{TsharkHeader}\n" +
                $"1\t1710000200.000\t1400\teth:ethertype:ip:esp\t192.168.1.100\t192.168.2.200\t\t\t50\t\t\t\t\t\t0xfeed0001\t1\t\t\t\t\t\t\t\tESP\tESP (SPI=0xfeed0001, SEQ=1)\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\n" +
                $"2\t1710000200.001\t1400\teth:ethertype:ip:esp\t192.168.1.100\t192.168.2.200\t\t\t50\t\t\t\t\t\t0xfeed0001\t2\t\t\t\t\t\t\t\tESP\tESP (SPI=0xfeed0001, SEQ=2)\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\n" +
                $"3\t1710000200.002\t1400\teth:ethertype:ip:esp\t192.168.1.100\t192.168.2.200\t\t\t50\t\t\t\t\t\t0xfeed0001\t3\t\t\t\t\t\t\t\tESP\tESP (SPI=0xfeed0001, SEQ=3)\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\n";

            var espSeqResult = await analyzer.AnalyzeAsync(testPcapPath);
            Assert(espSeqResult.EspSessions.Count == 1, "Phase 3: Tracked single ESP security session by SPI");
            Assert(espSeqResult.EspSessions[0].FirstSequence == 1 && espSeqResult.EspSessions[0].LastSequence == 3 && espSeqResult.EspSessions[0].DuplicateSequences == 0,
                   "Phase 3: Monotonic in-order sequence tracking (Seq 1 â†’ 3, 0 replays)",
                   $"Status: {espSeqResult.EspSessions[0].ReplayStatus}");
            Assert(espSeqResult.ReplayProtectionEnabled == true, "Phase 3: Replay protection verified clean");

            // TEST 5: ESP Duplicate Sequence / Replay Detection
            mockTshark.MockStdout = $"{TsharkHeader}\n" +
                $"1\t1710000300.000\t1400\teth:ethertype:ip:esp\t192.168.1.100\t192.168.2.200\t\t\t50\t\t\t\t\t\t0xdead0002\t10\t\t\t\t\t\t\t\tESP\tESP (SPI=0xdead0002, SEQ=10)\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\n" +
                $"2\t1710000300.001\t1400\teth:ethertype:ip:esp\t192.168.1.100\t192.168.2.200\t\t\t50\t\t\t\t\t\t0xdead0002\t10\t\t\t\t\t\t\t\tESP\tESP (SPI=0xdead0002, SEQ=10)\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\n";

            var replayResult = await analyzer.AnalyzeAsync(testPcapPath);
            Assert(replayResult.EspSessions.Count > 0 && replayResult.EspSessions[0].DuplicateSequences > 0,
                   "Phase 3: Detected duplicate ESP sequence numbers (Replay anomaly identified)",
                   $"Replay Status: {replayResult.EspSessions[0].ReplayStatus}");
            Assert(replayResult.ReplayProtectionEnabled == false, "Phase 3: Replay protection flagged when duplicates exist");

            // -------------------------------------------------------------
            // SECTION E: PFS (Perfect Forward Secrecy) Child SA Verification
            // -------------------------------------------------------------
            Console.WriteLine("\n[SECTION E] Phase 3 PFS (Perfect Forward Secrecy) Detection");

            // TEST 6: CREATE_CHILD_SA with DH Key Exchange (PFS Enabled)
            mockTshark.MockStdout = $"{TsharkHeader}\n" +
                $"1\t1710000400.000\t400\teth:ethertype:ip:udp:isakmp\t10.0.0.1\t10.0.0.2\t\t\t17\t\t\t\t4500\t4500\t\t\t\t\t0x20\t36\t0102030405060708\t1122334455667788\t2\tIKEv2\tCREATE_CHILD_SA Request\tSA,Ni,KE\t\t\t\t\t\t\tSA,Ni,KE\t7\t12\t19\t4\tdeadbeef\t19\taabbcc\t\n";

            var pfsResult = await analyzer.AnalyzeAsync(testPcapPath);
            Assert(pfsResult.PfsEnabled == true, "Phase 3: Verified PFS Enabled in CREATE_CHILD_SA with DH Group 19 exchange");

            // -------------------------------------------------------------
            // SECTION F: IpsecAnalyzer & IpsecAnalysisViewModel Integration
            // -------------------------------------------------------------
            Console.WriteLine("\n[SECTION F] Phase 3 Full ViewModel & IpsecAnalyzer Integration");

            var ipsecService = new IpsecAnalyzer(analyzer);
            var liveIpsecResult = await ipsecService.GetIpsecAnalysisAsync();
            Assert(liveIpsecResult.IsAnalyzed && liveIpsecResult.SaProposals.Count > 0 && liveIpsecResult.PfsEnabled == true,
                   "Phase 3: IpsecAnalyzer maps full parsed handshake suite, proposals, and PFS into IpsecAnalysisResult");

            var ipsecVm = new IpsecAnalysisViewModel(ipsecService, analyzer);
            await ipsecVm.RefreshAnalysisAsync();
            Assert(ipsecVm.AnalysisResult.DisplayEncryption.Contains("AES-CBC") && ipsecVm.AnalysisResult.DisplayDhGroup.Contains("Group 19"),
                   "Phase 3: IpsecAnalysisViewModel binds and updates UI cryptographic properties cleanly",
                   $"DisplayEnc: {ipsecVm.AnalysisResult.DisplayEncryption}, DisplayDh: {ipsecVm.AnalysisResult.DisplayDhGroup}");
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        Console.WriteLine("\n================================================================================");
        Console.WriteLine($"   Phase 3 Verification Complete: {passed} PASSED, {failed} FAILED");
        Console.WriteLine("================================================================================\n");

        return failed == 0 ? 0 : 1;
    }
}
