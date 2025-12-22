using CommunityToolkit.Mvvm.ComponentModel;
using TruKare.Reports.Desktop.Models;

namespace TruKare.Reports.Desktop.ViewModels;

public partial class ReportItemViewModel : ObservableObject
{
    public ReportItemViewModel(ReportDto dto)
    {
        ReportId = dto.ReportId;
        CustomerName = dto.CustomerName;
        UnitNumber = dto.UnitNumber;
        ReportType = dto.ReportType;
        Status = dto.Status;
        LastModifiedBy = dto.LastModifiedBy;
        LastModifiedAt = dto.LastModifiedAt;
    }

    public Guid ReportId { get; }

    public string CustomerName { get; }

    public string UnitNumber { get; }

    public string ReportType { get; }

    public ReportStatusDto Status { get; private set; }

    [ObservableProperty]
    private string? lockedBy;

    [ObservableProperty]
    private DateTime? lockedAt;

    [ObservableProperty]
    private string? lockHost;

    public string? LastModifiedBy { get; }

    public DateTime? LastModifiedAt { get; }

    public string DisplayName => $"{ReportType} • {CustomerName} ({UnitNumber})";

    public bool IsLocked => !string.IsNullOrWhiteSpace(LockedBy);

    public void UpdateStatus(ReportStatusResponseDto status, string currentUser)
    {
        Status = status.Status;
        var reportLock = status.Lock;
        LockedBy = reportLock?.LockedBy;
        LockedAt = reportLock?.LockedAt;
        LockHost = reportLock?.LockedFromHost;
        OnPropertyChanged(nameof(Status));
        OnPropertyChanged(nameof(IsLocked));
        OnPropertyChanged(nameof(StatusBadge));
        OnPropertyChanged(nameof(StatusDescription));
    }

    public bool IsLockedByCurrentUser(string currentUser) =>
        !string.IsNullOrWhiteSpace(LockedBy) && string.Equals(LockedBy, currentUser, StringComparison.OrdinalIgnoreCase);

    public string StatusBadge => Status switch
    {
        ReportStatusDto.Done => "Done",
        ReportStatusDto.Archived => "Archived",
        _ when IsLocked => "Locked",
        _ => "In Progress"
    };

    public string StatusDescription
    {
        get
        {
            if (IsLocked && LockedAt.HasValue)
            {
                return $"Locked by {LockedBy} on {LockedAt:MM/dd HH:mm} ({LockHost})";
            }

            return Status switch
            {
                ReportStatusDto.Done => "Finalized",
                ReportStatusDto.Archived => "Archived",
                _ => "Available"
            };
        }
    }
}
