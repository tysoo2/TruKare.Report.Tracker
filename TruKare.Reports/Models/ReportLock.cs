namespace TruKare.Reports.Models;

public class ReportLock
{
    public Guid ReportId { get; set; }

    public string LockedBy { get; set; } = string.Empty;

    public DateTime LockedAt { get; set; }

    public string LockedFromHost { get; set; } = string.Empty;

    public LockState LockState { get; set; } = LockState.Active;

    public string? OverrideReason { get; set; }

    public string? OverriddenBy { get; set; }

    public DateTime? OverriddenAt { get; set; }
}
