namespace TruKare.Reports.Models;

public class CheckoutSession
{
    public Guid SessionId { get; set; }

    public Guid ReportId { get; set; }

    public string User { get; set; } = string.Empty;

    public string LocalPath { get; set; } = string.Empty;

    public string BaseHash { get; set; } = string.Empty;

    public DateTime StartedAt { get; set; }

    public DateTime? EndedAt { get; set; }

    public SessionEndReason? EndReason { get; set; }

    public bool IsOverridden { get; set; }
}
