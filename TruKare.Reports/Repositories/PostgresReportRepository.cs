using System.Data;
using Dapper;
using Npgsql;
using TruKare.Reports.Models;

namespace TruKare.Reports.Repositories;

public class PostgresReportRepository : IReportRepository
{
    private readonly string _connectionString;

    public PostgresReportRepository(string connectionString)
    {
        _connectionString = string.IsNullOrWhiteSpace(connectionString)
            ? throw new ArgumentException("Connection string cannot be null or empty.", nameof(connectionString))
            : connectionString;
    }

    private IDbConnection CreateConnection() => new NpgsqlConnection(_connectionString);

    public IEnumerable<Report> GetReports()
    {
        const string sql = """
            SELECT
                report_id AS ReportId,
                customer_name AS CustomerName,
                unit_number AS UnitNumber,
                report_type AS ReportType,
                created_at AS CreatedAt,
                status AS Status,
                canonical_path AS CanonicalPath,
                final_path AS FinalPath,
                current_revision AS CurrentRevision,
                current_hash AS CurrentHash,
                last_modified_at AS LastModifiedAt,
                last_modified_by AS LastModifiedBy
            FROM reports
            ORDER BY created_at;
            """;

        using var connection = CreateConnection();
        return connection.Query<Report>(sql);
    }

    public Report? GetReport(Guid id)
    {
        const string sql = """
            SELECT
                report_id AS ReportId,
                customer_name AS CustomerName,
                unit_number AS UnitNumber,
                report_type AS ReportType,
                created_at AS CreatedAt,
                status AS Status,
                canonical_path AS CanonicalPath,
                final_path AS FinalPath,
                current_revision AS CurrentRevision,
                current_hash AS CurrentHash,
                last_modified_at AS LastModifiedAt,
                last_modified_by AS LastModifiedBy
            FROM reports
            WHERE report_id = @ReportId;
            """;

        using var connection = CreateConnection();
        return connection.QueryFirstOrDefault<Report>(sql, new { ReportId = id });
    }

    public void UpsertReport(Report report)
    {
        const string sql = """
            INSERT INTO reports (
                report_id,
                customer_name,
                unit_number,
                report_type,
                created_at,
                status,
                canonical_path,
                final_path,
                current_revision,
                current_hash,
                last_modified_at,
                last_modified_by
            ) VALUES (
                @ReportId,
                @CustomerName,
                @UnitNumber,
                @ReportType,
                @CreatedAt,
                @Status,
                @CanonicalPath,
                @FinalPath,
                @CurrentRevision,
                @CurrentHash,
                @LastModifiedAt,
                @LastModifiedBy
            )
            ON CONFLICT (report_id) DO UPDATE SET
                customer_name = EXCLUDED.customer_name,
                unit_number = EXCLUDED.unit_number,
                report_type = EXCLUDED.report_type,
                created_at = EXCLUDED.created_at,
                status = EXCLUDED.status,
                canonical_path = EXCLUDED.canonical_path,
                final_path = EXCLUDED.final_path,
                current_revision = EXCLUDED.current_revision,
                current_hash = EXCLUDED.current_hash,
                last_modified_at = EXCLUDED.last_modified_at,
                last_modified_by = EXCLUDED.last_modified_by;
            """;

        var parameters = new
        {
            report.ReportId,
            report.CustomerName,
            report.UnitNumber,
            report.ReportType,
            report.CreatedAt,
            Status = (int)report.Status,
            report.CanonicalPath,
            report.FinalPath,
            report.CurrentRevision,
            report.CurrentHash,
            report.LastModifiedAt,
            report.LastModifiedBy
        };

        using var connection = CreateConnection();
        connection.Execute(sql, parameters);
    }

    public ReportLock? GetLock(Guid reportId)
    {
        const string sql = """
            SELECT
                report_id AS ReportId,
                locked_by AS LockedBy,
                locked_at AS LockedAt,
                locked_from_host AS LockedFromHost,
                lock_state AS LockState,
                override_reason AS OverrideReason,
                overridden_by AS OverriddenBy,
                overridden_at AS OverriddenAt
            FROM report_locks
            WHERE report_id = @ReportId;
            """;

        using var connection = CreateConnection();
        return connection.QueryFirstOrDefault<ReportLock>(sql, new { ReportId = reportId });
    }

    public void SaveLock(ReportLock? reportLock)
    {
        if (reportLock == null)
        {
            return;
        }

        const string sql = """
            INSERT INTO report_locks (
                report_id,
                locked_by,
                locked_at,
                locked_from_host,
                lock_state,
                override_reason,
                overridden_by,
                overridden_at
            ) VALUES (
                @ReportId,
                @LockedBy,
                @LockedAt,
                @LockedFromHost,
                @LockState,
                @OverrideReason,
                @OverriddenBy,
                @OverriddenAt
            )
            ON CONFLICT (report_id) DO UPDATE SET
                locked_by = EXCLUDED.locked_by,
                locked_at = EXCLUDED.locked_at,
                locked_from_host = EXCLUDED.locked_from_host,
                lock_state = EXCLUDED.lock_state,
                override_reason = EXCLUDED.override_reason,
                overridden_by = EXCLUDED.overridden_by,
                overridden_at = EXCLUDED.overridden_at;
            """;

        var parameters = new
        {
            reportLock.ReportId,
            reportLock.LockedBy,
            reportLock.LockedAt,
            reportLock.LockedFromHost,
            LockState = (int)reportLock.LockState,
            reportLock.OverrideReason,
            reportLock.OverriddenBy,
            reportLock.OverriddenAt
        };

        using var connection = CreateConnection();
        connection.Execute(sql, parameters);
    }

    public void RemoveLock(Guid reportId)
    {
        const string sql = "DELETE FROM report_locks WHERE report_id = @ReportId;";
        using var connection = CreateConnection();
        connection.Execute(sql, new { ReportId = reportId });
    }

    public CheckoutSession? GetSession(Guid sessionId)
    {
        const string sql = """
            SELECT
                session_id AS SessionId,
                report_id AS ReportId,
                "user" AS "User",
                local_path AS LocalPath,
                base_hash AS BaseHash,
                started_at AS StartedAt,
                ended_at AS EndedAt,
                end_reason AS EndReason,
                is_overridden AS IsOverridden
            FROM checkout_sessions
            WHERE session_id = @SessionId;
            """;

        using var connection = CreateConnection();
        return connection.QueryFirstOrDefault<CheckoutSession>(sql, new { SessionId = sessionId });
    }

    public IEnumerable<CheckoutSession> GetSessions(Guid reportId)
    {
        const string sql = """
            SELECT
                session_id AS SessionId,
                report_id AS ReportId,
                "user" AS "User",
                local_path AS LocalPath,
                base_hash AS BaseHash,
                started_at AS StartedAt,
                ended_at AS EndedAt,
                end_reason AS EndReason,
                is_overridden AS IsOverridden
            FROM checkout_sessions
            WHERE report_id = @ReportId;
            """;

        using var connection = CreateConnection();
        return connection.Query<CheckoutSession>(sql, new { ReportId = reportId });
    }

    public void SaveSession(CheckoutSession session)
    {
        const string sql = """
            INSERT INTO checkout_sessions (
                session_id,
                report_id,
                "user",
                local_path,
                base_hash,
                started_at,
                ended_at,
                end_reason,
                is_overridden
            ) VALUES (
                @SessionId,
                @ReportId,
                @User,
                @LocalPath,
                @BaseHash,
                @StartedAt,
                @EndedAt,
                @EndReason,
                @IsOverridden
            )
            ON CONFLICT (session_id) DO UPDATE SET
                report_id = EXCLUDED.report_id,
                "user" = EXCLUDED."user",
                local_path = EXCLUDED.local_path,
                base_hash = EXCLUDED.base_hash,
                started_at = EXCLUDED.started_at,
                ended_at = EXCLUDED.ended_at,
                end_reason = EXCLUDED.end_reason,
                is_overridden = EXCLUDED.is_overridden;
            """;

        var parameters = new
        {
            session.SessionId,
            session.ReportId,
            session.User,
            session.LocalPath,
            session.BaseHash,
            session.StartedAt,
            session.EndedAt,
            EndReason = session.EndReason.HasValue ? (int?)session.EndReason : null,
            session.IsOverridden
        };

        using var connection = CreateConnection();
        connection.Execute(sql, parameters);
    }

    public void AppendAudit(AuditEvent auditEvent)
    {
        const string sql = """
            INSERT INTO audit_events (
                timestamp,
                actor,
                action,
                report_id,
                details
            ) VALUES (
                @Timestamp,
                @Actor,
                @Action,
                @ReportId,
                @Details
            );
            """;

        using var connection = CreateConnection();
        connection.Execute(sql, auditEvent);
    }

    public IEnumerable<AuditEvent> GetAudits(Guid reportId)
    {
        const string sql = """
            SELECT
                timestamp AS Timestamp,
                actor AS Actor,
                action AS Action,
                report_id AS ReportId,
                details AS Details
            FROM audit_events
            WHERE report_id = @ReportId
            ORDER BY audit_id;
            """;

        using var connection = CreateConnection();
        return connection.Query<AuditEvent>(sql, new { ReportId = reportId });
    }
}
