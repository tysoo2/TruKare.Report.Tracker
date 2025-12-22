using Microsoft.Extensions.Options;
using TruKare.Reports.Models;
using TruKare.Reports.Options;
using TruKare.Reports.Repositories;

namespace TruKare.Reports.Services;

public class LockPolicyBackgroundService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<LockPolicyBackgroundService> _logger;
    private readonly LockPolicyOptions _options;
    private readonly Dictionary<string, DateOnly> _lastRun = new();

    public LockPolicyBackgroundService(
        IServiceScopeFactory scopeFactory,
        ILogger<LockPolicyBackgroundService> logger,
        IOptions<LockPolicyOptions> options)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Lock policy service started with poll interval {Interval}", _options.PollInterval);
        var interval = _options.PollInterval <= TimeSpan.Zero ? TimeSpan.FromMinutes(1) : _options.PollInterval;

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessSchedulesAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error enforcing lock policy");
            }

            await Task.Delay(interval, stoppingToken);
        }
    }

    private async Task ProcessSchedulesAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.Now;

        foreach (var reminder in _options.ReminderTimes ?? Enumerable.Empty<TimeOnly>())
        {
            if (ShouldRun(reminder, now, "reminder"))
            {
                await SendRemindersAsync(now, cancellationToken);
            }
        }

        foreach (var release in _options.AutoReleaseTimes ?? Enumerable.Empty<TimeOnly>())
        {
            if (ShouldRun(release, now, "release"))
            {
                await AutoReleaseLocksAsync(now, cancellationToken);
            }
        }

        if (_options.DailySweepTime.HasValue && ShouldRun(_options.DailySweepTime.Value, now, "daily"))
        {
            await SweepExpiredLocksAsync(now, cancellationToken);
        }
    }

    private async Task SendRemindersAsync(DateTime now, CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IReportRepository>();
        var notification = scope.ServiceProvider.GetRequiredService<INotificationService>();

        var activeLocks = repository
            .GetLocks()
            .Where(l => l.LockState == LockState.Active && l.LockedAt <= now - _options.MinimumLockAgeBeforeRelease)
            .ToList();

        foreach (var lockInfo in activeLocks)
        {
            var report = repository.GetReport(lockInfo.ReportId);
            var subject = "Reminder: Report lock ending soon";
            var message = $"Your lock on report {report?.ReportType ?? "Unknown"} for {report?.CustomerName ?? "unknown customer"} will be released soon.";
            await notification.NotifyAsync(lockInfo.LockedBy, subject, message, cancellationToken);
            AppendAudit(repository, lockInfo.ReportId, "system", "LockReminder", new { lockInfo.LockedBy, lockInfo.LockedAt });
        }

        _logger.LogInformation("Sent {Count} reminder notifications for active locks", activeLocks.Count);
    }

    private async Task AutoReleaseLocksAsync(DateTime now, CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IReportRepository>();
        var notification = scope.ServiceProvider.GetRequiredService<INotificationService>();

        var eligibleLocks = repository
            .GetLocks()
            .Where(l => l.LockState == LockState.Active && l.LockedAt <= now - _options.MinimumLockAgeBeforeRelease)
            .ToList();

        foreach (var lockInfo in eligibleLocks)
        {
            await EndSessionsAsync(repository, notification, lockInfo, now, cancellationToken);

            lockInfo.LockState = LockState.Released;
            lockInfo.OverrideReason = "Automatically released by policy.";
            lockInfo.OverriddenBy = "system";
            lockInfo.OverriddenAt = now;
            repository.SaveLock(lockInfo);

            var report = repository.GetReport(lockInfo.ReportId);
            await notification.NotifyAsync(lockInfo.LockedBy, "Report lock released", $"Your lock on report {report?.ReportType ?? "Unknown"} for {report?.CustomerName ?? "unknown customer"} was automatically released.", cancellationToken);
            AppendAudit(repository, lockInfo.ReportId, "system", "AutoRelease", new { lockInfo.LockedBy, lockInfo.LockedAt });
        }

        _logger.LogInformation("Automatically released {Count} locks", eligibleLocks.Count);
    }

    private async Task SweepExpiredLocksAsync(DateTime now, CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IReportRepository>();
        var notification = scope.ServiceProvider.GetRequiredService<INotificationService>();

        var expiredLocks = repository
            .GetLocks()
            .Where(l => l.LockState == LockState.Active && l.LockedAt <= now - _options.MaxLockAge)
            .ToList();

        foreach (var lockInfo in expiredLocks)
        {
            await EndSessionsAsync(repository, notification, lockInfo, now, cancellationToken);

            lockInfo.LockState = LockState.Released;
            lockInfo.OverrideReason = "Automatically released after max duration.";
            lockInfo.OverriddenBy = "system";
            lockInfo.OverriddenAt = now;
            repository.SaveLock(lockInfo);

            var report = repository.GetReport(lockInfo.ReportId);
            await notification.NotifyAsync(lockInfo.LockedBy, "Report lock expired", $"Your lock on report {report?.ReportType ?? "Unknown"} for {report?.CustomerName ?? "unknown customer"} expired and was released.", cancellationToken);
            AppendAudit(repository, lockInfo.ReportId, "system", "DailyLockSweep", new { lockInfo.LockedBy, lockInfo.LockedAt });
        }

        _logger.LogInformation("Released {Count} locks during daily sweep", expiredLocks.Count);
    }

    private async Task EndSessionsAsync(IReportRepository repository, INotificationService notification, ReportLock lockInfo, DateTime now, CancellationToken cancellationToken)
    {
        var sessions = repository
            .GetSessions(lockInfo.ReportId)
            .Where(s => s.EndedAt == null)
            .ToList();

        foreach (var session in sessions)
        {
            session.EndedAt = now;
            session.EndReason = SessionEndReason.AutoReleased;
            session.IsOverridden = true;
            repository.SaveSession(session);

            await notification.NotifyAsync(session.User, "Session ended", $"Your checkout session for report {lockInfo.ReportId} ended because the lock was released.", cancellationToken);
        }
    }

    private bool ShouldRun(TimeOnly scheduled, DateTime now, string keyPrefix)
    {
        var today = DateOnly.FromDateTime(now);
        var cacheKey = $"{keyPrefix}:{scheduled}";
        if (_lastRun.TryGetValue(cacheKey, out var lastDate) && lastDate >= today)
        {
            return false;
        }

        if (now.TimeOfDay >= scheduled.ToTimeSpan())
        {
            _lastRun[cacheKey] = today;
            return true;
        }

        return false;
    }

    private static void AppendAudit(IReportRepository repository, Guid reportId, string actor, string action, object details)
    {
        repository.AppendAudit(new AuditEvent
        {
            Action = action,
            Actor = actor,
            ReportId = reportId,
            Timestamp = DateTime.UtcNow,
            Details = System.Text.Json.JsonSerializer.Serialize(details)
        });
    }
}
