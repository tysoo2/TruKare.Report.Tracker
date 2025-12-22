using TruKare.Reports.Models;

namespace TruKare.Reports.Repositories;

public interface IReportRepository
{
    IEnumerable<Report> GetReports();

    Report? GetReport(Guid id);

    IEnumerable<ReportLock> GetLocks();

    void UpsertReport(Report report);

    ReportLock? GetLock(Guid reportId);

    void SaveLock(ReportLock? reportLock);

    void RemoveLock(Guid reportId);

    CheckoutSession? GetSession(Guid sessionId);

    IEnumerable<CheckoutSession> GetSessions(Guid reportId);

    void SaveSession(CheckoutSession session);

    void AppendAudit(AuditEvent auditEvent);

    IEnumerable<AuditEvent> GetAudits(Guid reportId);
}
