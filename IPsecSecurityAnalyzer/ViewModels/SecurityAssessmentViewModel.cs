using IPsecSecurityAnalyzer.Interfaces;
using IPsecSecurityAnalyzer.Models;

namespace IPsecSecurityAnalyzer.ViewModels;

/// <summary>
/// ViewModel for Comprehensive Security Assessment & Cryptographic Evaluation.
/// </summary>
public class SecurityAssessmentViewModel : ViewModelBase
{
    private readonly ISecurityAssessmentService _assessmentService;
    private SecurityAssessment _assessment = new();

    public SecurityAssessmentViewModel(ISecurityAssessmentService assessmentService)
    {
        _assessmentService = assessmentService;
        _ = LoadAssessmentAsync();
    }

    public SecurityAssessment Assessment
    {
        get => _assessment;
        set
        {
            if (SetProperty(ref _assessment, value))
            {
                OnPropertyChanged(nameof(HasAssessment));
                OnPropertyChanged(nameof(EmptyStateNotice));
            }
        }
    }

    public bool HasAssessment => _assessment.HasAssessment;
    public string EmptyStateNotice => "Security assessment will be generated after IPsec analysis.";

    private async Task LoadAssessmentAsync()
    {
        Assessment = await _assessmentService.GetSecurityAssessmentAsync();
    }
}
