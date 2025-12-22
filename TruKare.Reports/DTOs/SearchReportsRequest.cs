namespace TruKare.Reports.DTOs;

public class SearchReportsRequest
{
    public string? CustomerName { get; set; }

    public string? UnitNumber { get; set; }

    public string? ReportType { get; set; }

    public bool IncludeArchived { get; set; }
}
