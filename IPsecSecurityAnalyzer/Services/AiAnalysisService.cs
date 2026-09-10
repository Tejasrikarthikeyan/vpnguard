using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.Services;

/// <summary>
/// Service that invokes the Python AI engine to classify traffic and detect anomalies.
/// </summary>
public class AiAnalysisService : IAiAnalysisService
{
    private const string PythonModule = "-m";
    private const string AiModule = "ai_engine.infer";
    private const string WorkingDirectory = "d:/vpn"; // project root

    /// <summary>
    /// Executes the Python inference script and returns a populated <see cref="AiAnalysisResult"/>.
    /// If the Python environment is unavailable or the script fails, a fallback result with
    /// <c>IsModelConnected = false</c> is returned.
    /// </summary>
    public async Task<AiAnalysisResult> GetAiAnalysisAsync(IEnumerable<object>? packets = null)
    {
        try
        {
            // Prepare JSON payload with packet metadata from Phase 2/3.
            var payload = JsonSerializer.Serialize(new { packets = packets ?? Array.Empty<object>() });

            var startInfo = new ProcessStartInfo
            {
                FileName = "python",
                Arguments = $"{PythonModule} {AiModule}",
                WorkingDirectory = WorkingDirectory,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var process = new Process { StartInfo = startInfo };
            var outputBuilder = new StringBuilder();
            var errorBuilder = new StringBuilder();

            var tcs = new TaskCompletionSource<bool>();
            process.OutputDataReceived += (s, e) => { if (e.Data != null) outputBuilder.AppendLine(e.Data); };
            process.ErrorDataReceived += (s, e) => { if (e.Data != null) errorBuilder.AppendLine(e.Data); };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            // Send JSON payload
            await process.StandardInput.WriteAsync(payload);
            await process.StandardInput.FlushAsync();
            process.StandardInput.Close();

            // Wait with timeout (e.g., 10 seconds)
            var exited = await Task.Run(() => process.WaitForExit(10_000));
            if (!exited)
            {
                process.Kill(true);
                throw new TimeoutException("Python AI inference timed out.");
            }

            // Ensure async read completion
            await Task.Delay(100); // small delay for async readers

            if (process.ExitCode != 0)
            {
                var err = errorBuilder.ToString();
                throw new InvalidOperationException($"Python inference failed: {err}");
            }

            var json = outputBuilder.ToString();
            var result = JsonSerializer.Deserialize<AiAnalysisResult>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
            }) ?? new AiAnalysisResult();
            result.IsModelConnected = true;
            return result;
        }
        catch (Exception ex)
        {
            // Log the exception details for debugging purposes.
            Debug.WriteLine($"AI analysis failed: {ex}");
            // Return a graceful fallback result.
            return new AiAnalysisResult
            {
                IsModelConnected = false,
                Protocol = null,
                TrafficType = null,
                Prediction = null,
                Confidence = null,
                Features = new Dictionary<string, string>(),
                Anomalies = new List<string>(),
                // Optionally expose the error message via a dedicated field in the model if desired.
            };
        }
    }
}

