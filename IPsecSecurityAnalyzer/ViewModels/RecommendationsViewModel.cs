using System.Collections.ObjectModel;
using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for Prioritized Security Remediation Recommendations.
/// </summary>
public class RecommendationsViewModel : ViewModelBase
{
    private readonly ISecurityAssessmentService _securityService;
    private ObservableCollection<Recommendation> _recommendations = new();

    public RecommendationsViewModel(ISecurityAssessmentService securityService)
    {
        _securityService = securityService;
        _ = LoadRecommendationsAsync();
    }

    public ObservableCollection<Recommendation> Recommendations
    {
        get => _recommendations;
        set
        {
            if (SetProperty(ref _recommendations, value))
            {
                OnPropertyChanged(nameof(HasRecommendations));
            }
        }
    }

    public bool HasRecommendations => _recommendations.Count > 0;
    public string EmptyStateText => "No recommendations available.";

    private async Task LoadRecommendationsAsync()
    {
        var list = await _securityService.GetRecommendationsAsync();
        Recommendations.Clear();
        foreach (var item in list)
        {
            Recommendations.Add(item);
        }
        OnPropertyChanged(nameof(HasRecommendations));
    }
}
