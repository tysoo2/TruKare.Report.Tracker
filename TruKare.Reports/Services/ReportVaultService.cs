using System.Collections.Generic;
using System.Text.Json;
using Microsoft.Extensions.Options;
using TruKare.Reports.DTOs;
using TruKare.Reports.Models;
using TruKare.Reports.Options;
using TruKare.Reports.Repositories;

namespace TruKare.Reports.Services;

public class ReportVaultService : IReportVaultService
{
    private readonly IReportRepository _repository;
    private readonly VaultOptions _options;
    private readonly IHashService _hashService;
    private readonly INotificationService _notificationService;

    public ReportVaultService(
        IReportRepository repository,
        IOptions<VaultOptions> options,
        IHashService hashService,
        INotificationService notificationService)
    {
        _repository = repository;
        _hashService = hashService;
        _notificationService = notificationService;
        _options = options.Value;
    }

    public IEnumerable<Report> SearchReports(SearchReportsRequest request)
    {
        return _repository
            .GetReports()
            .Where(r => request.IncludeArchived || r.Status != ReportStatus.Archived)
            .Where(r => string.IsNullOrWhiteSpace(request.CustomerName) || r.CustomerName.Contains(request.CustomerName, StringComparison.OrdinalIgnoreCase))
            .Where(r => string.IsNullOrWhiteSpace(request.UnitNumber) || r.UnitNumber.Contains(request.UnitNumber, StringComparison.OrdinalIgnoreCase))
            .Where(r => string.IsNullOrWhiteSpace(request.ReportType) || r.ReportType.Equals(request.ReportType, StringComparison.OrdinalIgnoreCase));
    }

    public ReportStatusResponse GetReportStatus(Guid reportId)
    {
        var report = _repository.GetReport(reportId) ?? throw new InvalidOperationException("Report not found.");
        var reportLock = _repository.GetLock(reportId);
        return new ReportStatusResponse
        {
            ReportId = reportId,
            Status = report.Status,
            Lock = reportLock
        };
    }

    public async Task<CheckoutResponse> CheckoutAsync(CheckoutRequest request, CancellationToken cancellationToken)
    {
        var report = _repository.GetReport(request.ReportId) ?? throw new InvalidOperationException("Report not found.");
        EnsureDirectories();
        EnsureCanonicalExists(report);

        var existingLock = _repository.GetLock(report.ReportId);
        if (existingLock != null && existingLock.LockState == LockState.Active && !string.Equals(existingLock.LockedBy, request.User, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Report is locked by {existingLock.LockedBy} since {existingLock.LockedAt:g}.");
        }

        var sessionId = Guid.NewGuid();
        var localPath = PrepareWorkspaceCopy(report, sessionId);
        var baseHash = _hashService.ComputeHash(localPath);

        var reportLock = new ReportLock
        {
            ReportId = report.ReportId,
            LockedAt = DateTime.UtcNow,
            LockedBy = request.User,
            LockedFromHost = request.Host,
            LockState = LockState.Active
        };

        _repository.SaveLock(reportLock);

        var session = new CheckoutSession
        {
            SessionId = sessionId,
            ReportId = report.ReportId,
            User = request.User,
            LocalPath = localPath,
            BaseHash = baseHash,
            StartedAt = DateTime.UtcNow
        };

        _repository.SaveSession(session);
        AppendAudit(report.ReportId, request.User, "Checkout", new { request.Host, request.IsAdmin });

        return new CheckoutResponse
        {
            SessionId = sessionId,
            ReportId = report.ReportId,
            LocalPath = localPath,
            Message = "Checkout successful. Launch Adobe Reader with the provided local path."
        };
    }

    public async Task<CheckoutResponse> OverrideCheckoutAsync(OverrideCheckoutRequest request, CancellationToken cancellationToken)
    {
        var report = _repository.GetReport(request.ReportId) ?? throw new InvalidOperationException("Report not found.");
        EnsureDirectories();
        EnsureCanonicalExists(report);

        var existingLock = _repository.GetLock(report.ReportId);
        if (existingLock != null && existingLock.LockState == LockState.Active)
        {
            existingLock.LockState = LockState.Overridden;
            existingLock.OverrideReason = request.Reason;
            existingLock.OverriddenBy = request.AdminUser;
            existingLock.OverriddenAt = DateTime.UtcNow;
            _repository.SaveLock(existingLock);

            string? conflictCopyPath = null;
            foreach (var session in _repository.GetSessions(report.ReportId))
            {
                session.IsOverridden = true;
                session.EndedAt = DateTime.UtcNow;
                session.EndReason = SessionEndReason.OverrideByAdmin;
                _repository.SaveSession(session);

                conflictCopyPath ??= await PreserveConflictCopyAsync(session, report, cancellationToken);
            }

            var message = $"Lock holder: {existingLock.LockedBy} (since {existingLock.LockedAt:u}). " +
                          $"Override reason: {request.Reason}. " +
                          $"Conflict copy: {conflictCopyPath ?? "unavailable"}.";

            var metadata = new Dictionary<string, string>
            {
                ["lockedBy"] = existingLock.LockedBy,
                ["lockedAtUtc"] = existingLock.LockedAt.ToString("u"),
                ["overrideReason"] = request.Reason
            };

            if (conflictCopyPath is not null)
            {
                metadata["conflictCopyPath"] = conflictCopyPath;
            }

            await _notificationService.NotifyAsync(new NotificationRequest
            {
                User = existingLock.LockedBy,
                Subject = "Lock overridden",
                Message = message,
                Channels = new[]
                {
                    NotificationChannel.Email,
                    NotificationChannel.Teams,
                    NotificationChannel.DesktopToast
                },
                Metadata = metadata
            }, cancellationToken);

            AppendAudit(report.ReportId, request.AdminUser, "OverrideCheckout", new { request.Host, request.Reason, existingLock.LockedBy, conflictCopyPath });
        }

        var checkoutRequest = new CheckoutRequest
        {
            Host = request.Host,
            ReportId = request.ReportId,
            User = request.AdminUser,
            IsAdmin = true,
            OverrideReason = request.Reason
        };

        return await CheckoutAsync(checkoutRequest, cancellationToken);
    }

    public async Task CheckinAsync(CheckinRequest request, CancellationToken cancellationToken)
    {
        var session = _repository.GetSession(request.SessionId) ?? throw new InvalidOperationException("Session not found.");
        var report = _repository.GetReport(session.ReportId) ?? throw new InvalidOperationException("Report not found.");
        var reportLock = _repository.GetLock(report.ReportId);

        if (session.IsOverridden || (reportLock?.LockState == LockState.Overridden && !string.Equals(reportLock.OverriddenBy, request.User, StringComparison.OrdinalIgnoreCase)))
        {
            await PreserveConflictCopyAsync(session, report, cancellationToken);
            throw new InvalidOperationException($"This report was overridden by {reportLock?.OverriddenBy}. Your copy is stale.");
        }

        EnsureFileClosed(session.LocalPath);

        var currentHash = _hashService.ComputeHash(session.LocalPath);
        if (string.Equals(currentHash, session.BaseHash, StringComparison.OrdinalIgnoreCase))
        {
            CompleteSession(session, SessionEndReason.NoChanges);
            ReleaseLock(report.ReportId);
            DeleteWorkspace(session.LocalPath);
            AppendAudit(report.ReportId, request.User, "NoChangeCheckin", new { session.SessionId });
            return;
        }

        var previousRevision = report.CurrentRevision;
        ArchivePreviousVersion(report, previousRevision);
        AtomicReplace(report.CanonicalPath, session.LocalPath);

        report.CurrentRevision = previousRevision + 1;
        report.CurrentHash = _hashService.ComputeHash(report.CanonicalPath);
        report.LastModifiedAt = DateTime.UtcNow;
        report.LastModifiedBy = request.User;
        _repository.UpsertReport(report);

        CompleteSession(session, SessionEndReason.CheckedIn);
        ReleaseLock(report.ReportId);
        DeleteWorkspace(session.LocalPath);

        AppendAudit(report.ReportId, request.User, "Checkin", new { session.SessionId, revision = report.CurrentRevision });
    }

    public async Task FinalizeAsync(FinalizeRequest request, CancellationToken cancellationToken)
    {
        var session = _repository.GetSession(request.SessionId) ?? throw new InvalidOperationException("Session not found.");
        var report = _repository.GetReport(session.ReportId) ?? throw new InvalidOperationException("Report not found.");
        var reportLock = _repository.GetLock(report.ReportId);

        if (reportLock == null || reportLock.LockState != LockState.Active || !string.Equals(reportLock.LockedBy, request.User, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("You must hold the active lock to finalize.");
        }

        EnsureFileClosed(session.LocalPath);

        var finalizeCheckin = new CheckinRequest { SessionId = request.SessionId, User = request.User };
        await CheckinAsync(finalizeCheckin, cancellationToken);

        var finalDirectory = _options.FinalRoot;
        Directory.CreateDirectory(finalDirectory);
        var canonicalName = Path.GetFileNameWithoutExtension(report.CanonicalPath);
        var extension = Path.GetExtension(report.CanonicalPath);
        var finalPath = Path.Combine(finalDirectory, $"{canonicalName}.FINAL{extension}");

        File.Copy(report.CanonicalPath, finalPath, overwrite: true);
        report.FinalPath = finalPath;
        report.Status = ReportStatus.Done;
        report.LastModifiedAt = DateTime.UtcNow;
        report.LastModifiedBy = request.User;
        _repository.UpsertReport(report);
        AppendAudit(report.ReportId, request.User, "Finalize", new { finalPath });
    }

    public IEnumerable<AuditEvent> GetAuditTrail(Guid reportId) => _repository.GetAudits(reportId);

    private void EnsureDirectories()
    {
        Directory.CreateDirectory(_options.CanonicalRoot);
        Directory.CreateDirectory(_options.FinalRoot);
        if (!string.IsNullOrWhiteSpace(_options.ArchiveRoot))
        {
            Directory.CreateDirectory(_options.ArchiveRoot);
        }
        if (!string.IsNullOrWhiteSpace(_options.ConflictsRoot))
        {
            Directory.CreateDirectory(_options.ConflictsRoot);
        }
        Directory.CreateDirectory(_options.WorkspaceRoot);
    }

    private void EnsureCanonicalExists(Report report)
    {
        if (File.Exists(report.CanonicalPath))
        {
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(report.CanonicalPath)!);
        File.WriteAllText(report.CanonicalPath, $"Seed content for {report.ReportType} - {report.CustomerName} ({report.UnitNumber})");
        report.CurrentHash = _hashService.ComputeHash(report.CanonicalPath);
        _repository.UpsertReport(report);
    }

    private string PrepareWorkspaceCopy(Report report, Guid sessionId)
    {
        var workspaceDirectory = Path.Combine(_options.WorkspaceRoot, report.ReportId.ToString(), sessionId.ToString());
        Directory.CreateDirectory(workspaceDirectory);
        var localPath = Path.Combine(workspaceDirectory, Path.GetFileName(report.CanonicalPath));
        File.Copy(report.CanonicalPath, localPath, overwrite: true);
        return localPath;
    }

    private void ArchivePreviousVersion(Report report, int previousRevision)
    {
        if (string.IsNullOrWhiteSpace(_options.ArchiveRoot) || !File.Exists(report.CanonicalPath))
        {
            return;
        }

        var archiveFolder = Path.Combine(_options.ArchiveRoot, report.ReportId.ToString());
        Directory.CreateDirectory(archiveFolder);
        var revisionLabel = previousRevision.ToString("D4");
        var archivedName = $"{Path.GetFileNameWithoutExtension(report.CanonicalPath)}_rev{revisionLabel}{Path.GetExtension(report.CanonicalPath)}";
        var archivePath = Path.Combine(archiveFolder, archivedName);
        File.Copy(report.CanonicalPath, archivePath, overwrite: true);
    }

    private void AtomicReplace(string targetPath, string sourcePath)
    {
        var tempPath = $"{targetPath}.tmp";
        File.Copy(sourcePath, tempPath, overwrite: true);
        Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
        File.Move(tempPath, targetPath, overwrite: true);
    }

    private void EnsureFileClosed(string path)
    {
        try
        {
            using var stream = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException)
        {
            throw new InvalidOperationException("Save and close the PDF before submitting.");
        }
    }

    private void ReleaseLock(Guid reportId)
    {
        _repository.RemoveLock(reportId);
    }

    private void CompleteSession(CheckoutSession session, SessionEndReason reason)
    {
        session.EndedAt = DateTime.UtcNow;
        session.EndReason = reason;
        _repository.SaveSession(session);
    }

    private void DeleteWorkspace(string path)
    {
        var directory = Path.GetDirectoryName(path);
        if (directory != null && Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private async Task<string?> PreserveConflictCopyAsync(CheckoutSession session, Report report, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.ConflictsRoot) || !File.Exists(session.LocalPath))
        {
            return null;
        }

        var conflictFolder = Path.Combine(_options.ConflictsRoot, session.User, report.ReportId.ToString());
        Directory.CreateDirectory(conflictFolder);
        var conflictName = $"{Path.GetFileNameWithoutExtension(session.LocalPath)}_{DateTime.UtcNow:yyyyMMddHHmmss}{Path.GetExtension(session.LocalPath)}";
        var conflictPath = Path.Combine(conflictFolder, conflictName);
        File.Copy(session.LocalPath, conflictPath, overwrite: true);
        await _notificationService.NotifyAsync(new NotificationRequest
        {
            User = session.User,
            Subject = "Stale copy quarantined",
            Message = $"A stale copy was preserved at {conflictPath}",
            Metadata = new Dictionary<string, string>
            {
                ["conflictCopyPath"] = conflictPath,
                ["reportId"] = report.ReportId.ToString()
            }
        }, cancellationToken);

        return conflictPath;
    }

    private void AppendAudit(Guid reportId, string actor, string action, object details)
    {
        var payload = JsonSerializer.Serialize(details);
        _repository.AppendAudit(new AuditEvent
        {
            Action = action,
            Actor = actor,
            ReportId = reportId,
            Timestamp = DateTime.UtcNow,
            Details = payload
        });
    }
}
