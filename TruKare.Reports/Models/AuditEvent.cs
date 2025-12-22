namespace TruKare.Reports.Models;

public class AuditEvent
{
    public DateTime Timestamp { get; set; }

    public string Actor { get; set; } = string.Empty;

    public string Action { get; set; } = string.Empty;

    public Guid ReportId { get; set; }

    public string Details { get; set; } = string.Empty;
}
