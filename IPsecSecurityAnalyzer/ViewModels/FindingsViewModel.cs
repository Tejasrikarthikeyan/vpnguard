using System.Collections.ObjectModel;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for Security Findings and Vulnerability Matrix.
/// </summary>
public class FindingsViewModel : ViewModelBase
{
    private readonly ISecurityAssessmentService _securityService;
    private ObservableCollection<SecurityFinding> _findings = new();
    private SecurityFinding? _selectedFinding;

    public FindingsViewModel(ISecurityAssessmentService securityService)
    {
        _securityService = securityService;
        _ = LoadFindingsAsync();
    }

    public ObservableCollection<SecurityFinding> Findings
    {
        get => _findings;
        set
        {
            if (SetProperty(ref _findings, value))
            {
                OnPropertyChanged(nameof(HasFindings));
            }
        }
    }

    public SecurityFinding? SelectedFinding
    {
        get => _selectedFinding;
        set => SetProperty(ref _selectedFinding, value);
    }

    public bool HasFindings => _findings.Count > 0;
    public string EmptyStateText => "No findings available.";

    private async Task LoadFindingsAsync()
    {
        var list = await _securityService.GetFindingsAsync();
        Findings.Clear();
        foreach (var item in list)
        {
            Findings.Add(item);
        }
        OnPropertyChanged(nameof(HasFindings));
    }
}
