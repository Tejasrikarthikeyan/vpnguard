using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;
using IPsecSecurityAnalyzer.Services;
using IPsecSecurityAnalyzer.ViewModels;

namespace IPsecSecurityAnalyzer.Tests;

public class Program
{
    [STAThread]
    public static async Task<int> Main(string[] args)
    {
        Console.WriteLine("==================================================");
        Console.WriteLine("IPsec Security Analyzer - Phase 1 Verification Suite");
        Console.WriteLine("==================================================");

        int passed = 0;
        int failed = 0;

        void Assert(bool condition, string testName)
        {
            if (condition)
            {
                Console.WriteLine($"[PASS] {testName}");
                passed++;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[FAIL] {testName}");
                Console.ResetColor();
                failed++;
            }
        }

        // Test 1: Service Container & DI Registration
        Console.WriteLine("\n--- Testing Dependency Injection Container ---");
        var services = new ServiceCollection();
        services.AddSingleton<INavigationService, NavigationService>();
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
        Assert(mainVm != null, "MainViewModel resolved successfully from DI");
        Assert(mainVm.DashboardVM != null, "DashboardViewModel resolved");
        Assert(mainVm.PcapAnalysisVM != null, "PcapAnalysisViewModel resolved");
        Assert(mainVm.LiveCaptureVM != null, "LiveCaptureViewModel resolved");
        Assert(mainVm.IpsecAnalysisVM != null, "IpsecAnalysisViewModel resolved");
        Assert(mainVm.AiAnalysisVM != null, "AiAnalysisViewModel resolved");
        Assert(mainVm.SecurityAssessmentVM != null, "SecurityAssessmentViewModel resolved");
        Assert(mainVm.FindingsVM != null, "FindingsViewModel resolved");
        Assert(mainVm.RecommendationsVM != null, "RecommendationsViewModel resolved");
        Assert(mainVm.ReportsVM != null, "ReportsViewModel resolved");
        Assert(mainVm.HistoryVM != null, "HistoryViewModel resolved");
        Assert(mainVm.SettingsVM != null, "SettingsViewModel resolved");

        // Test 2: Navigation across all 11 pages
        Console.WriteLine("\n--- Testing Navigation Routing ---");
        var navService = provider.GetRequiredService<INavigationService>();
        foreach (NavigationPage page in Enum.GetValues<NavigationPage>())
        {
            navService.NavigateTo(page);
            Assert(mainVm.CurrentPage == page, $"Navigated to {page}");
            Assert(!string.IsNullOrWhiteSpace(mainVm.CurrentPageTitle), $"Page title populated for {page}: '{mainVm.CurrentPageTitle}'");
        }

        // Test 3: PCAP File Loader & Real Metadata
        Console.WriteLine("\n--- Testing PCAP File Loader & Metadata Validation ---");
        var pcapAnalyzer = provider.GetRequiredService<IPcapAnalyzer>();
        var tempPcap = Path.Combine(Path.GetTempPath(), "test_capture_sample.pcap");
        File.WriteAllBytes(tempPcap, new byte[1024 * 50]); // 50 KB dummy file

        var loadedInfo = await pcapAnalyzer.LoadPcapFileAsync(tempPcap);
        Assert(loadedInfo.FileName == "test_capture_sample.pcap", "PCAP filename extracted correctly");
        Assert(loadedInfo.FileSize == 1024 * 50, "PCAP file size calculated accurately");
        Assert(loadedInfo.FileExtension == ".pcap", "PCAP extension parsed correctly");
        Assert(mainVm.ActivePcapName == "test_capture_sample.pcap", "Active PCAP badge updated in MainViewModel");
        Assert(mainVm.DashboardVM.SelectedFile?.FileName == "test_capture_sample.pcap", "Dashboard selected file updated via event");
        Assert(mainVm.PcapAnalysisVM.SelectedFile?.FileName == "test_capture_sample.pcap", "PcapAnalysis selected file updated via event");

        // Test 4: Error Handling
        Console.WriteLine("\n--- Testing Error Handling & Constraints ---");
        bool threwOnMissing = false;
        try
        {
            await pcapAnalyzer.LoadPcapFileAsync("C:\\NonExistentPath\\missing.pcap");
        }
        catch (FileNotFoundException)
        {
            threwOnMissing = true;
        }
        Assert(threwOnMissing, "FileNotFoundException thrown when loading non-existent file");

        bool threwOnInvalidExt = false;
        var tempTxt = Path.Combine(Path.GetTempPath(), "invalid_ext.txt");
        File.WriteAllText(tempTxt, "invalid");
        try
        {
            await pcapAnalyzer.LoadPcapFileAsync(tempTxt);
        }
        catch (NotSupportedException)
        {
            threwOnInvalidExt = true;
        }
        Assert(threwOnInvalidExt, "NotSupportedException thrown when loading non-pcap extension");

        // Clean up temporary files
        if (File.Exists(tempPcap)) File.Delete(tempPcap);
        if (File.Exists(tempTxt)) File.Delete(tempTxt);

        // Test 5: No Fake Data Rule Validation
        Console.WriteLine("\n--- Testing 'No Fake Data' Compliance ---");
        var ipsecAnalyzer = provider.GetRequiredService<IIpsecAnalyzer>();
        var ipsecResult = await ipsecAnalyzer.GetIpsecAnalysisAsync();
        Assert(ipsecResult.IsAnalyzed == false, "IPsec analysis reports IsAnalyzed = false");
        Assert(ipsecResult.DisplayIkeVersion == "Awaiting analysis", "IKE Version displays 'Awaiting analysis'");
        Assert(ipsecResult.DisplayEncryption == "Awaiting analysis", "Encryption displays 'Awaiting analysis'");
        Assert(ipsecResult.DisplayPfs == "Awaiting analysis", "PFS displays 'Awaiting analysis'");

        var assessmentService = provider.GetRequiredService<ISecurityAssessmentService>();
        var assessment = await assessmentService.GetSecurityAssessmentAsync();
        Assert(assessment.OverallRiskScore == null, "OverallRiskScore is null (no fake score)");
        Assert(assessment.FormattedRiskScore == "Not available", "Risk score formatted as 'Not available'");
        Assert(assessment.Findings.Count == 0, "No fake findings generated in Phase 1");
        Assert(assessment.Recommendations.Count == 0, "No fake recommendations generated in Phase 1");

        var aiService = provider.GetRequiredService<IAiAnalysisService>();
        var aiResult = await aiService.GetAiAnalysisAsync();
        Assert(aiResult.IsModelConnected == false, "AI model reports IsModelConnected = false");
        Assert(aiResult.Confidence == null, "AI confidence is null (no fake prediction)");
        Assert(aiResult.DisplayConfidence == "Awaiting analysis", "AI confidence display is 'Awaiting analysis'");

        var stats = await pcapAnalyzer.GetTrafficStatisticsAsync();
        Assert(stats.TotalPackets == null, "TotalPackets is null (no fake count)");
        Assert(stats.FormattedPackets == "Not available", "TotalPackets displays 'Not available'");

        Console.WriteLine("\n==================================================");
        Console.WriteLine($"Test Results: {passed} PASSED, {failed} FAILED");
        Console.WriteLine("==================================================");

        return failed == 0 ? 0 : 1;
    }
}
