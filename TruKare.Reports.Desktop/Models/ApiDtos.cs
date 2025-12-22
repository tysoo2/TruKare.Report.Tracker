namespace TruKare.Reports.Desktop.Models;

public record SearchReportsRequestDto(
    string? CustomerName,
    string? UnitNumber,
    string? ReportType,
    bool IncludeArchived);

public record CheckoutRequestDto
{
    public Guid ReportId { get; init; }

    public string User { get; init; } = string.Empty;

    public string Host { get; init; } = string.Empty;

    public bool IsAdmin { get; init; }

    public string? OverrideReason { get; init; }
}

public record CheckinRequestDto
{
    public Guid SessionId { get; init; }

    public string User { get; init; } = string.Empty;
}

public record CheckoutResponseDto
{
    public Guid SessionId { get; init; }

    public Guid ReportId { get; init; }

    public string LocalPath { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;
}

public record ReportStatusResponseDto
{
    public Guid ReportId { get; init; }

    public ReportStatusDto Status { get; init; }

    public ReportLockDto? Lock { get; init; }
}

public record ReportLockDto
{
    public Guid ReportId { get; init; }

    public string LockedBy { get; init; } = string.Empty;

    public DateTime LockedAt { get; init; }

    public string LockedFromHost { get; init; } = string.Empty;

    public LockStateDto LockState { get; init; }

    public string? OverrideReason { get; init; }

    public string? OverriddenBy { get; init; }

    public DateTime? OverriddenAt { get; init; }
}

public record ReportDto
{
    public Guid ReportId { get; init; }

    public string CustomerName { get; init; } = string.Empty;

    public string UnitNumber { get; init; } = string.Empty;

    public string ReportType { get; init; } = string.Empty;

    public DateTime CreatedAt { get; init; }

    public ReportStatusDto Status { get; init; }

    public string CanonicalPath { get; init; } = string.Empty;

    public string? FinalPath { get; init; }

    public int CurrentRevision { get; init; }

    public string? CurrentHash { get; init; }

    public DateTime? LastModifiedAt { get; init; }

    public string? LastModifiedBy { get; init; }
}

public enum ReportStatusDto
{
    InProgress,
    Done,
    Archived
}

public enum LockStateDto
{
    Active,
    Overridden
}
