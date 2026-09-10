using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// Production ViewModel for Analysis Audit History, SQLite search, filter, detailed inspection, and report export (Phase 6).
/// </summary>
public class HistoryViewModel : ViewModelBase
{
    private readonly IAnalysisHistoryService _historyService;
    private readonly IReportService _reportService;
    private readonly IFileDialogService _fileDialogService;

    private ObservableCollection<AnalysisHistory> _historyItems = new();
    private AnalysisHistory? _selectedHistoryItem;
    private AnalysisReportData? _selectedDetailSnapshot;
    private bool _isLoading;
    private string _statusMessage = string.Empty;

    // Filters & Search
    private string _searchText = string.Empty;
    private string _selectedRiskFilter = "All";
    private string _selectedIpsecFilter = "All";
    private string _selectedAnomalyFilter = "All";

    public HistoryViewModel(
        IAnalysisHistoryService historyService,
        IReportService reportService,
        IFileDialogService fileDialogService)
    {
        _historyService = historyService;
        _reportService = reportService;
        _fileDialogService = fileDialogService;

        RefreshHistoryCommand = new RelayCommand(async () => await LoadHistoryAsync());
        SearchCommand = new RelayCommand(async () => await ApplyFilterAsync());
        ResetFilterCommand = new RelayCommand(async () => await ResetFiltersAsync());
        DeleteRecordCommand = new RelayCommand<AnalysisHistory>(async item => await DeleteRecordAsync(item));
        ViewDetailsCommand = new RelayCommand<AnalysisHistory>(async item => await ViewDetailsAsync(item));
        CloseDetailsCommand = new RelayCommand(() => SelectedDetailSnapshot = null);
        ExportPdfCommand = new RelayCommand<AnalysisHistory>(async item => await ExportPdfAsync(item));
        ExportJsonCommand = new RelayCommand<AnalysisHistory>(async item => await ExportJsonAsync(item));
        ClearAllHistoryCommand = new RelayCommand(async () => await ClearAllHistoryAsync());

        _historyService.HistoryChanged += async (s, e) =>
        {
            await LoadHistoryAsync();
        };

        _ = LoadHistoryAsync();
    }

    public ObservableCollection<AnalysisHistory> HistoryItems
    {
        get => _historyItems;
        set
        {
            if (SetProperty(ref _historyItems, value))
            {
                OnPropertyChanged(nameof(HasHistory));
                OnPropertyChanged(nameof(TotalHistoryCount));
            }
        }
    }

    public AnalysisHistory? SelectedHistoryItem
    {
        get => _selectedHistoryItem;
        set => SetProperty(ref _selectedHistoryItem, value);
    }

    public AnalysisReportData? SelectedDetailSnapshot
    {
        get => _selectedDetailSnapshot;
        set
        {
            if (SetProperty(ref _selectedDetailSnapshot, value))
            {
                OnPropertyChanged(nameof(HasSelectedDetail));
            }
        }
    }

    public bool HasSelectedDetail => _selectedDetailSnapshot != null;
    public bool HasHistory => _historyItems.Count > 0;
    public int TotalHistoryCount => _historyItems.Count;
    public string EmptyStateText => "No analysis history available.";

    public bool IsLoading
    {
        get => _isLoading;
        set => SetProperty(ref _isLoading, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value))
            {
                _ = ApplyFilterAsync();
            }
        }
    }

    public string SelectedRiskFilter
    {
        get => _selectedRiskFilter;
        set
        {
            if (SetProperty(ref _selectedRiskFilter, value))
            {
                _ = ApplyFilterAsync();
            }
        }
    }

    public string SelectedIpsecFilter
    {
        get => _selectedIpsecFilter;
        set
        {
            if (SetProperty(ref _selectedIpsecFilter, value))
            {
                _ = ApplyFilterAsync();
            }
        }
    }

    public string SelectedAnomalyFilter
    {
        get => _selectedAnomalyFilter;
        set
        {
            if (SetProperty(ref _selectedAnomalyFilter, value))
            {
                _ = ApplyFilterAsync();
            }
        }
    }

    // Commands
    public ICommand RefreshHistoryCommand { get; }
    public ICommand SearchCommand { get; }
    public ICommand ResetFilterCommand { get; }
    public ICommand DeleteRecordCommand { get; }
    public ICommand ViewDetailsCommand { get; }
    public ICommand CloseDetailsCommand { get; }
    public ICommand ExportPdfCommand { get; }
    public ICommand ExportJsonCommand { get; }
    public ICommand ClearAllHistoryCommand { get; }

    public async Task LoadHistoryAsync()
    {
        IsLoading = true;
        try
        {
            var list = await _historyService.GetAnalysesAsync();
            HistoryItems.Clear();
            foreach (var item in list)
            {
                HistoryItems.Add(item);
            }
            OnPropertyChanged(nameof(HasHistory));
            OnPropertyChanged(nameof(TotalHistoryCount));
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to load history: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task ApplyFilterAsync()
    {
        IsLoading = true;
        try
        {
            bool? ipsec = SelectedIpsecFilter switch
            {
                "IPsec Only" => true,
                "Non-IPsec" => false,
                _ => null
            };

            bool? anomaly = SelectedAnomalyFilter switch
            {
                "Anomalous" => true,
                "Normal" => false,
                _ => null
            };

            var list = await _historyService.SearchAnalysesAsync(
                SearchText,
                SelectedRiskFilter,
                ipsec,
                anomaly);

            HistoryItems.Clear();
            foreach (var item in list)
            {
                HistoryItems.Add(item);
            }
            OnPropertyChanged(nameof(HasHistory));
            OnPropertyChanged(nameof(TotalHistoryCount));
        }
        catch (Exception ex)
        {
            StatusMessage = $"Filter failed: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task ResetFiltersAsync()
    {
        _searchText = string.Empty;
        _selectedRiskFilter = "All";
        _selectedIpsecFilter = "All";
        _selectedAnomalyFilter = "All";
        OnPropertyChanged(nameof(SearchText));
        OnPropertyChanged(nameof(SelectedRiskFilter));
        OnPropertyChanged(nameof(SelectedIpsecFilter));
        OnPropertyChanged(nameof(SelectedAnomalyFilter));
        await LoadHistoryAsync();
    }

    private async Task ViewDetailsAsync(AnalysisHistory? item)
    {
        var target = item ?? SelectedHistoryItem;
        if (target == null) return;

        IsLoading = true;
        try
        {
            var snapshot = await _historyService.GetAnalysisByIdAsync(target.AnalysisId);
            if (snapshot != null)
            {
                SelectedDetailSnapshot = snapshot;
            }
            else
            {
                StatusMessage = "Snapshot data could not be retrieved from the database.";
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Failed to load details: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task DeleteRecordAsync(AnalysisHistory? item)
    {
        var target = item ?? SelectedHistoryItem;
        if (target == null) return;

        var result = MessageBox.Show(
            $"Are you sure you want to delete this analysis from history?\n\nTarget File: {target.FileName}\nAnalysis Date: {target.FormattedDate}\n\nNote: Deleting history records will NOT delete the original PCAP file.",
            "Confirm Delete - VPNGuard History",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result == MessageBoxResult.Yes)
        {
            IsLoading = true;
            try
            {
                var success = await _historyService.DeleteAnalysisAsync(target.AnalysisId);
                if (success)
                {
                    if (SelectedDetailSnapshot?.AnalysisId == target.AnalysisId)
                    {
                        SelectedDetailSnapshot = null;
                    }
                    StatusMessage = $"Deleted record for {target.FileName}";
                }
                else
                {
                    StatusMessage = "Could not delete record from database.";
                }
            }
            catch (Exception ex)
            {
                StatusMessage = $"Error deleting record: {ex.Message}";
            }
            finally
            {
                IsLoading = false;
            }
        }
    }

    private async Task ExportPdfAsync(AnalysisHistory? item)
    {
        var target = item ?? SelectedHistoryItem;
        if (target == null) return;

        try
        {
            var snapshot = await _historyService.GetAnalysisByIdAsync(target.AnalysisId);
            if (snapshot == null)
            {
                MessageBox.Show("Analysis snapshot not found in database.", "VPNGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var defaultName = $"VPNGuard_Report_{Path.GetFileNameWithoutExtension(target.FileName)}_{DateTime.Now:yyyyMMdd_HHmmss}.pdf";
            var savePath = _fileDialogService.SaveFileDialog(defaultName, "PDF Security Report (*.pdf)|*.pdf");
            if (!string.IsNullOrEmpty(savePath))
            {
                IsLoading = true;
                StatusMessage = "Generating PDF report...";
                await _reportService.GeneratePdfReportAsync(snapshot, savePath);
                StatusMessage = $"PDF report exported to {savePath}";

                MessageBox.Show($"PDF report generated successfully:\n\n{savePath}", "Report Exported", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"PDF export failed: {ex.Message}";
            MessageBox.Show($"Failed to generate PDF: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task ExportJsonAsync(AnalysisHistory? item)
    {
        var target = item ?? SelectedHistoryItem;
        if (target == null) return;

        try
        {
            var snapshot = await _historyService.GetAnalysisByIdAsync(target.AnalysisId);
            if (snapshot == null)
            {
                MessageBox.Show("Analysis snapshot not found in database.", "VPNGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var defaultName = $"VPNGuard_Audit_{Path.GetFileNameWithoutExtension(target.FileName)}_{DateTime.Now:yyyyMMdd_HHmmss}.json";
            var savePath = _fileDialogService.SaveFileDialog(defaultName, "JSON Audit Snapshot (*.json)|*.json");
            if (!string.IsNullOrEmpty(savePath))
            {
                IsLoading = true;
                StatusMessage = "Exporting JSON audit snapshot...";
                await _reportService.ExportJsonAsync(snapshot, savePath);
                StatusMessage = $"JSON snapshot exported to {savePath}";

                MessageBox.Show($"JSON audit snapshot exported successfully:\n\n{savePath}", "JSON Exported", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"JSON export failed: {ex.Message}";
            MessageBox.Show($"Failed to export JSON: {ex.Message}", "Export Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task ClearAllHistoryAsync()
    {
        if (_historyItems.Count == 0) return;

        var result = MessageBox.Show(
            "Are you sure you want to clear all analysis history records from the SQLite database?\n\nOriginal PCAP files will not be affected.",
            "Clear History - VPNGuard",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result == MessageBoxResult.Yes)
        {
            IsLoading = true;
            try
            {
                await _historyService.ClearHistoryAsync();
                SelectedDetailSnapshot = null;
                StatusMessage = "History cleared.";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Failed to clear history: {ex.Message}";
            }
            finally
            {
                IsLoading = false;
            }
        }
    }
}
