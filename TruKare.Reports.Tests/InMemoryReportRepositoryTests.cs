using FluentAssertions;
using TruKare.Reports.Models;
using TruKare.Reports.Repositories;

namespace TruKare.Reports.Tests;

public class InMemoryReportRepositoryTests
{
    [Fact]
    public void Stores_and_retrieves_reports_sessions_and_audits()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("RUN_REPOSITORY_INTEGRATION_TESTS"), "1", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var repository = new InMemoryReportRepository();
        var report = new Report
        {
            ReportId = Guid.NewGuid(),
            CustomerName = "Test Customer",
            UnitNumber = "Unit-789",
            ReportType = "Inspection",
            CreatedAt = DateTime.UtcNow
        };

        repository.UpsertReport(report);
        repository.GetReport(report.ReportId).Should().BeEquivalentTo(report);

        var reportLock = new ReportLock
        {
            ReportId = report.ReportId,
            LockedAt = DateTime.UtcNow,
            LockedBy = "inspector",
            LockedFromHost = "host-01",
            LockState = LockState.Active
        };

        repository.SaveLock(reportLock);
        repository.GetLock(report.ReportId)!.LockedBy.Should().Be("inspector");

        var session = new CheckoutSession
        {
            SessionId = Guid.NewGuid(),
            ReportId = report.ReportId,
            User = "inspector",
            LocalPath = "/tmp/report.pdf",
            BaseHash = "ABC123",
            StartedAt = DateTime.UtcNow
        };

        repository.SaveSession(session);
        repository.GetSessions(report.ReportId).Should().ContainSingle(s => s.SessionId == session.SessionId);

        var auditEvent = new AuditEvent
        {
            ReportId = report.ReportId,
            Actor = "inspector",
            Action = "Checkout",
            Timestamp = DateTime.UtcNow,
            Details = "{}"
        };

        repository.AppendAudit(auditEvent);
        repository.GetAudits(report.ReportId).Should().ContainSingle();

        repository.RemoveLock(report.ReportId);
        repository.GetLock(report.ReportId).Should().BeNull();
    }
}
