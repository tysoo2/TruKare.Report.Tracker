namespace TruKare.Reports.Models;

public class Report
{
    public Guid ReportId { get; set; }

    public string CustomerName { get; set; } = string.Empty;

    public string UnitNumber { get; set; } = string.Empty;

    public string ReportType { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; }

    public ReportStatus Status { get; set; } = ReportStatus.InProgress;

    public string CanonicalPath { get; set; } = string.Empty;

    public string? FinalPath { get; set; }

    public int CurrentRevision { get; set; }

    public string? CurrentHash { get; set; }

    public DateTime? LastModifiedAt { get; set; }

    public string? LastModifiedBy { get; set; }
}
