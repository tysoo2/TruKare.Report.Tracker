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

            foreach (var session in _repository.GetSessions(report.ReportId))
            {
                session.IsOverridden = true;
                session.EndedAt = DateTime.UtcNow;
                session.EndReason = SessionEndReason.OverrideByAdmin;
                _repository.SaveSession(session);
            }

            var notifyMessage = $"Your lock on report {report.ReportType} for {report.CustomerName} was overridden by {request.AdminUser}. Reason: {request.Reason}";
            await _notificationService.NotifyAsync(existingLock.LockedBy, "Lock overridden", notifyMessage, cancellationToken);
            AppendAudit(report.ReportId, request.AdminUser, "OverrideCheckout", new { request.Host, request.Reason, existingLock.LockedBy });
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
            await PreserveConflictCopyAsync(session, report);
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

    public DashboardSummaryResponse GetDashboardSummary()
    {
        var reports = _repository.GetReports().ToList();
        var reportLookup = reports.ToDictionary(r => r.ReportId);
        var activeLocks = _repository.GetLocks().Where(l => l.LockState == LockState.Active).ToList();
        var locksByReportId = activeLocks
            .GroupBy(l => l.ReportId)
            .ToDictionary(group => group.Key, group => group.OrderByDescending(lockRecord => lockRecord.LockedAt).First());

        var totals = new DashboardStatusCounts
        {
            InProgress = reports.Count(r => r.Status == ReportStatus.InProgress),
            Done = reports.Count(r => r.Status == ReportStatus.Done),
            Archived = reports.Count(r => r.Status == ReportStatus.Archived),
            Locked = activeLocks.Count
        };

        IEnumerable<DashboardGroupBreakdown> BuildGrouped(Func<Report, string> keySelector)
        {
            return reports
                .GroupBy(keySelector, StringComparer.OrdinalIgnoreCase)
                .Select(group => new DashboardGroupBreakdown
                {
                    Key = group.Key,
                    InProgress = group.Count(r => r.Status == ReportStatus.InProgress),
                    Done = group.Count(r => r.Status == ReportStatus.Done),
                    Archived = group.Count(r => r.Status == ReportStatus.Archived),
                    Locked = group.Count(r => locksByReportId.ContainsKey(r.ReportId))
                })
                .OrderByDescending(g => g.Locked)
                .ThenByDescending(g => g.InProgress)
                .ThenBy(g => g.Key)
                .ToArray();
        }

        var byLockedBy = activeLocks
            .GroupBy(l => l.LockedBy, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var statuses = group
                    .Select(l => reportLookup.TryGetValue(l.ReportId, out var report) ? report.Status : (ReportStatus?)null)
                    .Where(status => status.HasValue)
                    .Select(status => status!.Value)
                    .ToArray();

                return new DashboardGroupBreakdown
                {
                    Key = group.Key,
                    Locked = group.Count(),
                    InProgress = statuses.Count(status => status == ReportStatus.InProgress),
                    Done = statuses.Count(status => status == ReportStatus.Done),
                    Archived = statuses.Count(status => status == ReportStatus.Archived)
                };
            })
            .OrderByDescending(g => g.Locked)
            .ThenBy(g => g.Key)
            .ToArray();

        return new DashboardSummaryResponse
        {
            Totals = totals,
            ByCustomer = BuildGrouped(r => r.CustomerName),
            ByUnit = BuildGrouped(r => r.UnitNumber),
            ByLockedBy = byLockedBy
        };
    }

    public IEnumerable<FileIssueSummary> GetConflicts() => GetFileIssues(_options.ConflictsRoot, "Conflict");

    public IEnumerable<FileIssueSummary> GetOrphans() => GetFileIssues(_options.OrphansRoot, "Orphan");

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
        if (!string.IsNullOrWhiteSpace(_options.OrphansRoot))
        {
            Directory.CreateDirectory(_options.OrphansRoot);
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

    private async Task PreserveConflictCopyAsync(CheckoutSession session, Report report)
    {
        if (string.IsNullOrWhiteSpace(_options.ConflictsRoot) || !File.Exists(session.LocalPath))
        {
            return;
        }

        var conflictFolder = Path.Combine(_options.ConflictsRoot, session.User, report.ReportId.ToString());
        Directory.CreateDirectory(conflictFolder);
        var conflictName = $"{Path.GetFileNameWithoutExtension(session.LocalPath)}_{DateTime.UtcNow:yyyyMMddHHmmss}{Path.GetExtension(session.LocalPath)}";
        var conflictPath = Path.Combine(conflictFolder, conflictName);
        File.Copy(session.LocalPath, conflictPath, overwrite: true);
        await _notificationService.NotifyAsync(session.User, "Stale copy quarantined", $"A stale copy was preserved at {conflictPath}", CancellationToken.None);
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

    private IEnumerable<FileIssueSummary> GetFileIssues(string root, string category)
    {
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            return Array.Empty<FileIssueSummary>();
        }

        var rootPath = Path.GetFullPath(root);
        return Directory.EnumerateFiles(rootPath, "*", SearchOption.AllDirectories)
            .Select(path =>
            {
                var info = new FileInfo(path);
                var relative = Path.GetRelativePath(rootPath, path);
                return new FileIssueSummary
                {
                    Category = category,
                    FileName = Path.GetFileName(path),
                    FullPath = path,
                    RelativePath = relative,
                    SizeBytes = info.Length,
                    LastModifiedAt = info.LastWriteTimeUtc,
                    User = ParseUser(relative),
                    ReportId = ParseReportId(relative)
                };
            })
            .OrderByDescending(issue => issue.LastModifiedAt)
            .ThenBy(issue => issue.FileName)
            .ToArray();
    }

    private static string? ParseUser(string relativePath)
    {
        var segments = relativePath.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        return segments.Length > 0 ? segments[0] : null;
    }

    private static Guid? ParseReportId(string relativePath)
    {
        var segments = relativePath.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length > 1 && Guid.TryParse(segments[1], out var reportId))
        {
            return reportId;
        }

        return null;
    }
}
