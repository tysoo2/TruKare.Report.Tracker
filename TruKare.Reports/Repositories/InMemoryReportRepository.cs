using System.Collections.Concurrent;
using TruKare.Reports.Models;

namespace TruKare.Reports.Repositories;

public class InMemoryReportRepository : IReportRepository
{
    private readonly ConcurrentDictionary<Guid, Report> _reports = new();
    private readonly ConcurrentDictionary<Guid, ReportLock> _locks = new();
    private readonly ConcurrentDictionary<Guid, CheckoutSession> _sessions = new();
    private readonly ConcurrentDictionary<Guid, List<AuditEvent>> _audits = new();

    public IEnumerable<Report> GetReports() => _reports.Values;

    public Report? GetReport(Guid id) => _reports.TryGetValue(id, out var report) ? report : null;

    public IEnumerable<ReportLock> GetLocks() => _locks.Values;

    public void UpsertReport(Report report)
    {
        _reports.AddOrUpdate(report.ReportId, report, (_, _) => report);
    }

    public ReportLock? GetLock(Guid reportId) => _locks.TryGetValue(reportId, out var reportLock) ? reportLock : null;

    public IEnumerable<ReportLock> GetLocks() => _locks.Values;

    public void SaveLock(ReportLock? reportLock)
    {
        if (reportLock == null)
        {
            return;
        }

        _locks.AddOrUpdate(reportLock.ReportId, reportLock, (_, _) => reportLock);
    }

    public void RemoveLock(Guid reportId)
    {
        _locks.TryRemove(reportId, out _);
    }

    public CheckoutSession? GetSession(Guid sessionId) => _sessions.TryGetValue(sessionId, out var session) ? session : null;

    public IEnumerable<CheckoutSession> GetSessions(Guid reportId)
    {
        return _sessions.Values.Where(s => s.ReportId == reportId).ToArray();
    }

    public void SaveSession(CheckoutSession session)
    {
        _sessions.AddOrUpdate(session.SessionId, session, (_, _) => session);
    }

    public void AppendAudit(AuditEvent auditEvent)
    {
        var list = _audits.GetOrAdd(auditEvent.ReportId, _ => []);
        lock (list)
        {
            list.Add(auditEvent);
        }
    }

    public IEnumerable<AuditEvent> GetAudits(Guid reportId)
    {
        return _audits.TryGetValue(reportId, out var events)
            ? events.ToArray()
            : Array.Empty<AuditEvent>();
    }
}
