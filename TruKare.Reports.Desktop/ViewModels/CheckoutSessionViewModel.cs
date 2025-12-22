using CommunityToolkit.Mvvm.ComponentModel;

namespace TruKare.Reports.Desktop.ViewModels;

public partial class CheckoutSessionViewModel : ObservableObject
{
    public CheckoutSessionViewModel(Guid sessionId, Guid reportId, string reportName, string localPath, DateTime startedAt)
    {
        SessionId = sessionId;
        ReportId = reportId;
        ReportName = reportName;
        LocalPath = localPath;
        StartedAt = startedAt;
    }

    public Guid SessionId { get; }

    public Guid ReportId { get; }

    public string ReportName { get; }

    public string LocalPath { get; }

    public DateTime StartedAt { get; }

    [ObservableProperty]
    private bool isOverridden;

    public string StatusText => IsOverridden
        ? "Override detected"
        : $"Opened {StartedAt:g}";
}
