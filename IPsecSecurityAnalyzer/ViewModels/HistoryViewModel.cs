using System.Collections.ObjectModel;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for Analysis Audit History and SQLite Persistence (Phase 7).
/// </summary>
public class HistoryViewModel : ViewModelBase
{
    private readonly IAnalysisHistoryService _historyService;
    private ObservableCollection<AnalysisHistory> _historyItems = new();

    public HistoryViewModel(IAnalysisHistoryService historyService)
    {
        _historyService = historyService;
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
            }
        }
    }

    public bool HasHistory => _historyItems.Count > 0;
    public string EmptyStateText => "No analysis history.";

    private async Task LoadHistoryAsync()
    {
        var list = await _historyService.GetHistoryAsync();
        HistoryItems.Clear();
        foreach (var item in list)
        {
            HistoryItems.Add(item);
        }
        OnPropertyChanged(nameof(HasHistory));
    }
}
