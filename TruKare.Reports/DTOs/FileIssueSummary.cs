namespace TruKare.Reports.DTOs;

public class FileIssueSummary
{
    public string Category { get; set; } = string.Empty;

    public string FileName { get; set; } = string.Empty;

    public string FullPath { get; set; } = string.Empty;

    public string RelativePath { get; set; } = string.Empty;

    public long SizeBytes { get; set; }

    public DateTime LastModifiedAt { get; set; }

    public string? User { get; set; }

    public Guid? ReportId { get; set; }
}
