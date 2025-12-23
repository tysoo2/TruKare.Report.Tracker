using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Options;
using TruKare.Reports.Authorization;
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
    private readonly IAdminAuthorizationService _adminAuthorizationService;

    public ReportVaultService(
        IReportRepository repository,
        IOptions<VaultOptions> options,
        IHashService hashService,
        INotificationService notificationService,
        IAdminAuthorizationService adminAuthorizationService)
    {
        _repository = repository;
        _hashService = hashService;
        _notificationService = notificationService;
        _adminAuthorizationService = adminAuthorizationService;
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

    public async Task<CheckoutResponse> CheckoutAsync(CheckoutRequest request, RequestUserContext userContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var report = _repository.GetReport(request.ReportId) ?? throw new InvalidOperationException("Report not found.");
        EnsureDirectories();
        EnsureCanonicalExists(report);

        var existingLock = _repository.GetLock(report.ReportId);
        if (existingLock != null &&
            existingLock.LockState == LockState.Active &&
            !string.Equals(existingLock.LockedBy, userContext.UserName, StringComparison.OrdinalIgnoreCase))
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
            LockedBy = userContext.UserName,
            LockedFromHost = userContext.Host,
            LockState = LockState.Active
        };

        _repository.SaveLock(reportLock);

        var session = new CheckoutSession
        {
            SessionId = sessionId,
            ReportId = report.ReportId,
            User = userContext.UserName,
            LocalPath = localPath,
            BaseHash = baseHash,
            StartedAt = DateTime.UtcNow
        };

        _repository.SaveSession(session);

        AppendAudit(report.ReportId, userContext.UserName, "Checkout", new { Host = userContext.Host, userContext.IsAdmin });

        return new CheckoutResponse
        {
            SessionId = sessionId,
            ReportId = report.ReportId,
            LocalPath = localPath,
            Message = "Checkout successful. Launch Adobe Reader with the provided local path."
        };
    }

    public async Task<CheckoutResponse> OverrideCheckoutAsync(OverrideCheckoutRequest request, RequestUserContext userContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        _adminAuthorizationService.EnsureAdmin();
        _ = _adminAuthorizationService.GetCurrentAdminUser(); // keep for auditing / future use if needed

        var report = _repository.GetReport(request.ReportId) ?? throw new InvalidOperationException("Report not found.");
        EnsureDirectories();
        EnsureCanonicalExists(report);

        if (!userContext.IsAdmin)
        {
            throw new UnauthorizedAccessException("Admin privileges are required to override a checkout.");
        }

        var existingLock = _repository.GetLock(report.ReportId);
        if (existingLock != null && existingLock.LockState == LockState.Active)
        {
            existingLock.LockState = LockState.Overridden;
            existingLock.OverrideReason = request.Reason;
            existingLock.OverriddenBy = userContext.UserName;
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

            var notifyMessage =
                $"Your lock on report {report.ReportType} for {report.CustomerName} was overridden by {userContext.UserName}. " +
                $"Reason: {request.Reason}";

            await _notificationService.NotifyAsync(existingLock.LockedBy, "Lock overridden", notifyMessage, cancellationToken);

            AppendAudit(report.ReportId, userContext.UserName, "OverrideCheckout", new
            {
                Host = userContext.Host,
                request.Reason,
                existingLock.LockedBy,
                conflictCopyPath
            });
        }

        var checkoutRequest = new CheckoutRequest
        {
            ReportId = request.ReportId,
            OverrideReason = request.Reason
        };

        return await CheckoutAsync(checkoutRequest, userContext, cancellationToken);
    }

    public async Task CheckinAsync(CheckinRequest request, RequestUserContext userContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var session = _repository.GetSession(request.SessionId) ?? throw new InvalidOperationException("Session not found.");
        var report = _repository.GetReport(session.ReportId) ?? throw new InvalidOperationException("Report not found.");
        var reportLock = _repository.GetLock(report.ReportId);

        if (session.IsOverridden ||
            (reportLock?.LockState == LockState.Overridden &&
             !string.Equals(reportLock.OverriddenBy, userContext.UserName, StringComparison.OrdinalIgnoreCase)))
        {
            _ = await PreserveConflictCopyAsync(session, report, cancellationToken);
            throw new InvalidOperationException($"This report was overridden by {reportLock?.OverriddenBy}. Your copy is stale.");
        }

        EnsureFileClosed(session.LocalPath);

        var currentHash = _hashService.ComputeHash(session.LocalPath);
        if (string.Equals(currentHash, session.BaseHash, StringComparison.OrdinalIgnoreCase))
        {
            CompleteSession(session, SessionEndReason.NoChanges);
            ReleaseLock(report.ReportId);
            DeleteWorkspace(session.LocalPath);
            AppendAudit(report.ReportId, userContext.UserName, "NoChangeCheckin", new { session.SessionId });
            return;
        }

        var previousRevision = report.CurrentRevision;
        ArchivePreviousVersion(report, previousRevision);
        AtomicReplace(GetCanonicalPath(report), session.LocalPath);

        report.CurrentRevision = previousRevision + 1;
        report.CurrentHash = _hashService.ComputeHash(GetCanonicalPath(report));
        report.LastModifiedAt = DateTime.UtcNow;
        report.LastModifiedBy = userContext.UserName;
        _repository.UpsertReport(report);

        CompleteSession(session, SessionEndReason.CheckedIn);
        ReleaseLock(report.ReportId);
        DeleteWorkspace(session.LocalPath);

        AppendAudit(report.ReportId, userContext.UserName, "Checkin", new { session.SessionId, revision = report.CurrentRevision });
    }

    public async Task FinalizeAsync(FinalizeRequest request, RequestUserContext userContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        _adminAuthorizationService.EnsureAdmin();
        _ = _adminAuthorizationService.GetCurrentAdminUser(); // keep for auditing / future use if needed

        var session = _repository.GetSession(request.SessionId) ?? throw new InvalidOperationException("Session not found.");
        var report = _repository.GetReport(session.ReportId) ?? throw new InvalidOperationException("Report not found.");
        var reportLock = _repository.GetLock(report.ReportId);

        if (reportLock == null ||
            reportLock.LockState != LockState.Active ||
            !string.Equals(reportLock.LockedBy, userContext.UserName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("You must hold the active lock to finalize.");
        }

        EnsureFileClosed(session.LocalPath);
        EnsureDirectories();

        var finalizeCheckin = new CheckinRequest { SessionId = request.SessionId };
        await CheckinAsync(finalizeCheckin, userContext, cancellationToken);

        var refreshedReport = _repository.GetReport(report.ReportId) ?? throw new InvalidOperationException("Report not found after check-in.");
        var finalPath = BuildFinalPath(refreshedReport);

        var finalizationMode = GenerateFinalArtifact(GetCanonicalPath(refreshedReport), finalPath);
        ApplyFinalAcls(finalPath);

        refreshedReport.FinalPath = finalPath;
        refreshedReport.Status = ReportStatus.Done;
        refreshedReport.LastModifiedAt = DateTime.UtcNow;
        refreshedReport.LastModifiedBy = userContext.UserName;
        _repository.UpsertReport(refreshedReport);

        AppendAudit(refreshedReport.ReportId, userContext.UserName, "Finalize", new { finalPath, finalizationMode });
    }

    public IEnumerable<AuditEvent> GetAuditTrail(Guid reportId) => _repository.GetAudits(reportId);

    public DashboardSummaryResponse GetDashboardSummary()
    {
        var reports = _repository.GetReports().ToList();
        var reportLookup = reports.ToDictionary(r => r.ReportId);

        var activeLocks = _repository.GetLocks().Where(l => l.LockState == LockState.Active).ToList();

        var locksByReportId = activeLocks
            .GroupBy(l => l.ReportId)
            .ToDictionary(
                group => group.Key,
                group => group.OrderByDescending(lockRecord => lockRecord.LockedAt).First());

        var totals = new DashboardStatusCounts
        {
            InProgress = reports.Count(r => r.Status == ReportStatus.InProgress),
            Done = reports.Count(r => r.Status == ReportStatus.Done),
            Archived = reports.Count(r => r.Status == ReportStatus.Archived),
            Locked = activeLocks.Count
        };

        DashboardGroupBreakdown[] BuildGrouped(Func<Report, string> keySelector)
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

    private IEnumerable<FileIssueSummary> GetFileIssues(string root, string category)
    {
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            return Array.Empty<FileIssueSummary>();
        }

        return Directory
            .EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Select(path =>
            {
                var info = new FileInfo(path);
                var relativePath = Path.GetRelativePath(root, path);
                var (user, reportId) = ParseUserAndReport(relativePath);

                return new FileIssueSummary
                {
                    Category = category,
                    FileName = info.Name,
                    FullPath = path,
                    RelativePath = relativePath,
                    SizeBytes = info.Length,
                    LastModifiedAt = info.LastWriteTimeUtc,
                    User = user,
                    ReportId = reportId
                };
            })
            .OrderByDescending(issue => issue.LastModifiedAt)
            .ThenBy(issue => issue.FileName)
            .ToArray();
    }

    private static (string? User, Guid? ReportId) ParseUserAndReport(string relativePath)
    {
        var segments = relativePath.Split(
            new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries);

        if (segments.Length >= 2 && Guid.TryParse(segments[1], out var reportId))
        {
            return (segments[0], reportId);
        }

        return (null, null);
    }

    private void EnsureDirectories()
    {
        Directory.CreateDirectory(_options.CanonicalRoot);
        Directory.CreateDirectory(_options.FinalRoot);
        Directory.CreateDirectory(_options.WorkspaceRoot);

        if (!string.IsNullOrWhiteSpace(_options.ArchiveRoot))
            Directory.CreateDirectory(_options.ArchiveRoot);

        if (!string.IsNullOrWhiteSpace(_options.ConflictsRoot))
            Directory.CreateDirectory(_options.ConflictsRoot);

        if (!string.IsNullOrWhiteSpace(_options.OrphansRoot))
            Directory.CreateDirectory(_options.OrphansRoot);

        if (!string.IsNullOrWhiteSpace(_options.IntakeRoot))
            Directory.CreateDirectory(_options.IntakeRoot);
    }

    private void EnsureCanonicalExists(Report report)
    {
        var canonicalPath = GetCanonicalPath(report);
        if (File.Exists(canonicalPath))
        {
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(canonicalPath)!);

        // Seed file: for PDFs we create an empty placeholder. For non-PDF, simple text.
        if (Path.GetExtension(canonicalPath).Equals(".pdf", StringComparison.OrdinalIgnoreCase))
        {
            // Minimal placeholder; PDF generation requires a PDF library which isn't guaranteed installed.
            File.WriteAllBytes(canonicalPath, Array.Empty<byte>());
        }
        else
        {
            File.WriteAllText(canonicalPath, $"Seed content for {report.ReportType} - {report.CustomerName} ({report.UnitNumber})");
        }

        report.CanonicalPath = canonicalPath;
        report.CurrentHash = _hashService.ComputeHash(canonicalPath);
        _repository.UpsertReport(report);
    }

    private string PrepareWorkspaceCopy(Report report, Guid sessionId)
    {
        var canonicalPath = GetCanonicalPath(report);
        var workspaceDirectory = Path.Combine(_options.WorkspaceRoot, report.ReportId.ToString(), sessionId.ToString());
        Directory.CreateDirectory(workspaceDirectory);
        var localPath = Path.Combine(workspaceDirectory, Path.GetFileName(canonicalPath));
        File.Copy(canonicalPath, localPath, overwrite: true);
        return localPath;
    }

    private void ArchivePreviousVersion(Report report, int previousRevision)
    {
        var canonicalPath = GetCanonicalPath(report);
        if (string.IsNullOrWhiteSpace(_options.ArchiveRoot) || !File.Exists(canonicalPath))
        {
            return;
        }

        var archiveFolder = Path.Combine(_options.ArchiveRoot, report.ReportId.ToString());
        Directory.CreateDirectory(archiveFolder);
        var revisionLabel = previousRevision.ToString("D4");
        var archivedName = $"{Path.GetFileNameWithoutExtension(canonicalPath)}_rev{revisionLabel}{Path.GetExtension(canonicalPath)}";
        var archivePath = Path.Combine(archiveFolder, archivedName);
        File.Copy(canonicalPath, archivePath, overwrite: true);
    }

    private static void AtomicReplace(string targetPath, string sourcePath)
    {
        var tempPath = $"{targetPath}.tmp";
        Directory.CreateDirectory(Path.GetDirectoryName(targetPath)!);
        File.Copy(sourcePath, tempPath, overwrite: true);
        File.Move(tempPath, targetPath, overwrite: true);
    }

    private static void EnsureFileClosed(string path)
    {
        try
        {
            using var _ = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException)
        {
            throw new InvalidOperationException("Save and close the PDF before submitting.");
        }
    }

    private void ReleaseLock(Guid reportId) => _repository.RemoveLock(reportId);

    private void CompleteSession(CheckoutSession session, SessionEndReason reason)
    {
        session.EndedAt = DateTime.UtcNow;
        session.EndReason = reason;
        _repository.SaveSession(session);
    }

    private static void DeleteWorkspace(string path)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory))
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

        await _notificationService.NotifyAsync(
            session.User,
            "Stale copy quarantined",
            $"A stale copy was preserved at {conflictPath}",
            cancellationToken);

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

    private string BuildFinalPath(Report report)
    {
        var canonicalPath = GetCanonicalPath(report);
        var relativeCanonical = Path.GetRelativePath(_options.CanonicalRoot, canonicalPath);
        if (relativeCanonical.StartsWith("..", StringComparison.Ordinal))
        {
            relativeCanonical = Path.GetFileName(canonicalPath);
        }

        var relativeDirectory = Path.GetDirectoryName(relativeCanonical);
        var finalName = $"{Path.GetFileNameWithoutExtension(relativeCanonical)}.FINAL{Path.GetExtension(relativeCanonical)}";

        return string.IsNullOrWhiteSpace(relativeDirectory)
            ? Path.Combine(_options.FinalRoot, finalName)
            : Path.Combine(_options.FinalRoot, relativeDirectory, finalName);
    }

    private static string GenerateFinalArtifact(string canonicalPath, string finalPath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(finalPath)!);

        // iText not guaranteed installed -> just copy as the final artifact.
        File.Copy(canonicalPath, finalPath, overwrite: true);
        return "Copy";
    }

    private void ApplyFinalAcls(string finalPath)
    {
        if (OperatingSystem.IsWindows())
        {
            var info = new FileInfo(finalPath);
            var security = info.GetAccessControl();
            security.SetAccessRuleProtection(true, false);

            foreach (var rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)).OfType<FileSystemAccessRule>().ToList())
            {
                security.RemoveAccessRuleSpecific(rule);
            }

            var currentUser = WindowsIdentity.GetCurrent();
            var adminSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

            security.AddAccessRule(new FileSystemAccessRule(adminSid, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));

            if (currentUser?.User != null)
            {
                security.AddAccessRule(new FileSystemAccessRule(
                    currentUser.User,
                    FileSystemRights.Modify | FileSystemRights.ReadAndExecute,
                    AccessControlType.Allow));
            }

            security.AddAccessRule(new FileSystemAccessRule(usersSid, FileSystemRights.ReadAndExecute | FileSystemRights.Read, AccessControlType.Allow));

            info.SetAccessControl(security);
            File.SetAttributes(finalPath, File.GetAttributes(finalPath) | FileAttributes.ReadOnly);
            return;
        }

        TrySetPosixReadOnly(finalPath);
    }

    private static void TrySetPosixReadOnly(string path)
    {
        try
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        }
        catch (Exception) when (OperatingSystem.IsMacOS() || OperatingSystem.IsLinux())
        {
            File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.ReadOnly);
        }
    }

    private string GetCanonicalPath(Report report)
    {
        // Prefer persisted canonical path if already set.
        if (!string.IsNullOrWhiteSpace(report.CanonicalPath))
        {
            return report.CanonicalPath;
        }

        // Fallback: store by Customer/Unit/Type under canonical root.
        // (This gives stable, readable paths even if CanonicalPath wasn't set at report creation.)
        var safeCustomer = SanitizePathSegment(report.CustomerName);
        var safeUnit = SanitizePathSegment(report.UnitNumber);
        var safeType = SanitizePathSegment(report.ReportType);

        var fileName = $"{safeType}.pdf";
        return Path.Combine(_options.CanonicalRoot, safeCustomer, safeUnit, fileName);
    }

    private static string SanitizePathSegment(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "Unknown";
        }

        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(value.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray());
        return cleaned.Trim().Length == 0 ? "Unknown" : cleaned.Trim();
    }
}
