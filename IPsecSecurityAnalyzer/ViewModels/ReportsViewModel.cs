using System.Collections.ObjectModel;
using System.Windows.Input;
using IPsecSecurityAnalyzer.Interfaces;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for Security Reports Generation and PDF Audit Export (Phase 7).
/// </summary>
public class ReportsViewModel : ViewModelBase
{
    private readonly IReportService _reportService;
    private readonly IFileDialogService _fileDialogService;

    private ObservableCollection<string> _generatedReports = new();
    private string _statusMessage = "No reports generated.";

    public ReportsViewModel(
        IReportService reportService,
        IFileDialogService fileDialogService)
    {
        _reportService = reportService;
        _fileDialogService = fileDialogService;

        GenerateReportCommand = new RelayCommand(ExecuteGenerateReport, () => false); // Disabled in Phase 1
        ExportPdfCommand = new RelayCommand(ExecuteExportPdf, () => false);           // Disabled in Phase 1

        _ = LoadReportsAsync();
    }

    public ObservableCollection<string> GeneratedReports
    {
        get => _generatedReports;
        set => SetProperty(ref _generatedReports, value);
    }

    public bool HasReports => _generatedReports.Count > 0;

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public ICommand GenerateReportCommand { get; }
    public ICommand ExportPdfCommand { get; }

    private async Task LoadReportsAsync()
    {
        var list = await _reportService.GetGeneratedReportsAsync();
        GeneratedReports.Clear();
        foreach (var item in list)
        {
            GeneratedReports.Add(item);
        }
        OnPropertyChanged(nameof(HasReports));
    }

    private void ExecuteGenerateReport() { }
    private void ExecuteExportPdf() { }
}
