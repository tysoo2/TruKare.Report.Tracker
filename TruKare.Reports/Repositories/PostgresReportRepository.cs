using System.Data;
using Microsoft.Extensions.Configuration;
using Npgsql;
using TruKare.Reports.Models;

namespace TruKare.Reports.Repositories;

public class PostgresReportRepository : IReportRepository
{
    private readonly string _connectionString;

    public PostgresReportRepository(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("Reports")
            ?? throw new InvalidOperationException("Missing Reports connection string.");
        EnsureSchema();
    }

    public IEnumerable<Report> GetReports()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM reports";
        using var reader = command.ExecuteReader();
        var results = new List<Report>();
        while (reader.Read())
        {
            results.Add(MapReport(reader));
        }

        return results;
    }

    public Report? GetReport(Guid id)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM reports WHERE report_id = @id";
        command.Parameters.AddWithValue("@id", id);
        using var reader = command.ExecuteReader();
        return reader.Read() ? MapReport(reader) : null;
    }

    public void UpsertReport(Report report)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = @"INSERT INTO reports (
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
                @report_id,
                @customer_name,
                @unit_number,
                @report_type,
                @created_at,
                @status,
                @canonical_path,
                @final_path,
                @current_revision,
                @current_hash,
                @last_modified_at,
                @last_modified_by
            )
            ON CONFLICT (report_id) DO UPDATE SET
                customer_name = excluded.customer_name,
                unit_number = excluded.unit_number,
                report_type = excluded.report_type,
                created_at = excluded.created_at,
                status = excluded.status,
                canonical_path = excluded.canonical_path,
                final_path = excluded.final_path,
                current_revision = excluded.current_revision,
                current_hash = excluded.current_hash,
                last_modified_at = excluded.last_modified_at,
                last_modified_by = excluded.last_modified_by";
        command.Parameters.AddWithValue("@report_id", report.ReportId);
        command.Parameters.AddWithValue("@customer_name", report.CustomerName);
        command.Parameters.AddWithValue("@unit_number", report.UnitNumber);
        command.Parameters.AddWithValue("@report_type", report.ReportType);
        command.Parameters.AddWithValue("@created_at", report.CreatedAt);
        command.Parameters.AddWithValue("@status", (int)report.Status);
        command.Parameters.AddWithValue("@canonical_path", report.CanonicalPath);
        command.Parameters.AddWithValue("@final_path", report.FinalPath ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("@current_revision", report.CurrentRevision);
        command.Parameters.AddWithValue("@current_hash", report.CurrentHash ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("@last_modified_at", report.LastModifiedAt ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("@last_modified_by", report.LastModifiedBy ?? (object)DBNull.Value);
        command.ExecuteNonQuery();
    }

    public ReportLock? GetLock(Guid reportId)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM report_locks WHERE report_id = @id";
        command.Parameters.AddWithValue("@id", reportId);
        using var reader = command.ExecuteReader();
        return reader.Read() ? MapLock(reader) : null;
    }

    public void SaveLock(ReportLock? reportLock)
    {
        if (reportLock == null)
        {
            return;
        }

        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = @"INSERT INTO report_locks (
                report_id,
                locked_by,
                locked_at,
                locked_from_host,
                lock_state,
                override_reason,
                overridden_by,
                overridden_at
            ) VALUES (
                @report_id,
                @locked_by,
                @locked_at,
                @locked_from_host,
                @lock_state,
                @override_reason,
                @overridden_by,
                @overridden_at
            )
            ON CONFLICT (report_id) DO UPDATE SET
                locked_by = excluded.locked_by,
                locked_at = excluded.locked_at,
                locked_from_host = excluded.locked_from_host,
                lock_state = excluded.lock_state,
                override_reason = excluded.override_reason,
                overridden_by = excluded.overridden_by,
                overridden_at = excluded.overridden_at";
        command.Parameters.AddWithValue("@report_id", reportLock.ReportId);
        command.Parameters.AddWithValue("@locked_by", reportLock.LockedBy);
        command.Parameters.AddWithValue("@locked_at", reportLock.LockedAt);
        command.Parameters.AddWithValue("@locked_from_host", reportLock.LockedFromHost);
        command.Parameters.AddWithValue("@lock_state", (int)reportLock.LockState);
        command.Parameters.AddWithValue("@override_reason", reportLock.OverrideReason ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("@overridden_by", reportLock.OverriddenBy ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("@overridden_at", reportLock.OverriddenAt ?? (object)DBNull.Value);
        command.ExecuteNonQuery();
    }

    public void RemoveLock(Guid reportId)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM report_locks WHERE report_id = @id";
        command.Parameters.AddWithValue("@id", reportId);
        command.ExecuteNonQuery();
    }

    public CheckoutSession? GetSession(Guid sessionId)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM checkout_sessions WHERE session_id = @id";
        command.Parameters.AddWithValue("@id", sessionId);
        using var reader = command.ExecuteReader();
        return reader.Read() ? MapSession(reader) : null;
    }

    public IEnumerable<CheckoutSession> GetSessions(Guid reportId)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM checkout_sessions WHERE report_id = @id";
        command.Parameters.AddWithValue("@id", reportId);
        using var reader = command.ExecuteReader();
        var sessions = new List<CheckoutSession>();
        while (reader.Read())
        {
            sessions.Add(MapSession(reader));
        }

        return sessions;
    }

    public void SaveSession(CheckoutSession session)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = @"INSERT INTO checkout_sessions (
                session_id,
                report_id,
                user_name,
                local_path,
                base_hash,
                started_at,
                ended_at,
                end_reason,
                is_overridden
            ) VALUES (
                @session_id,
                @report_id,
                @user_name,
                @local_path,
                @base_hash,
                @started_at,
                @ended_at,
                @end_reason,
                @is_overridden
            )
            ON CONFLICT (session_id) DO UPDATE SET
                report_id = excluded.report_id,
                user_name = excluded.user_name,
                local_path = excluded.local_path,
                base_hash = excluded.base_hash,
                started_at = excluded.started_at,
                ended_at = excluded.ended_at,
                end_reason = excluded.end_reason,
                is_overridden = excluded.is_overridden";
        command.Parameters.AddWithValue("@session_id", session.SessionId);
        command.Parameters.AddWithValue("@report_id", session.ReportId);
        command.Parameters.AddWithValue("@user_name", session.User);
        command.Parameters.AddWithValue("@local_path", session.LocalPath);
        command.Parameters.AddWithValue("@base_hash", session.BaseHash);
        command.Parameters.AddWithValue("@started_at", session.StartedAt);
        command.Parameters.AddWithValue("@ended_at", session.EndedAt ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("@end_reason", session.EndReason.HasValue ? (int)session.EndReason.Value : (object)DBNull.Value);
        command.Parameters.AddWithValue("@is_overridden", session.IsOverridden);
        command.ExecuteNonQuery();
    }

    public void AppendAudit(AuditEvent auditEvent)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = @"INSERT INTO audit_events (
                timestamp,
                actor,
                action,
                report_id,
                details
            ) VALUES (
                @timestamp,
                @actor,
                @action,
                @report_id,
                @details
            )";
        command.Parameters.AddWithValue("@timestamp", auditEvent.Timestamp);
        command.Parameters.AddWithValue("@actor", auditEvent.Actor);
        command.Parameters.AddWithValue("@action", auditEvent.Action);
        command.Parameters.AddWithValue("@report_id", auditEvent.ReportId);
        command.Parameters.AddWithValue("@details", auditEvent.Details);
        command.ExecuteNonQuery();
    }

    public IEnumerable<AuditEvent> GetAudits(Guid reportId)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM audit_events WHERE report_id = @id ORDER BY timestamp";
        command.Parameters.AddWithValue("@id", reportId);
        using var reader = command.ExecuteReader();
        var events = new List<AuditEvent>();
        while (reader.Read())
        {
            events.Add(MapAudit(reader));
        }

        return events;
    }

    private void EnsureSchema()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = @"
            CREATE TABLE IF NOT EXISTS reports (
                report_id uuid PRIMARY KEY,
                customer_name text NOT NULL,
                unit_number text NOT NULL,
                report_type text NOT NULL,
                created_at timestamptz NOT NULL,
                status integer NOT NULL,
                canonical_path text NOT NULL,
                final_path text NULL,
                current_revision integer NOT NULL,
                current_hash text NULL,
                last_modified_at timestamptz NULL,
                last_modified_by text NULL
            );

            CREATE TABLE IF NOT EXISTS report_locks (
                report_id uuid PRIMARY KEY REFERENCES reports(report_id),
                locked_by text NOT NULL,
                locked_at timestamptz NOT NULL,
                locked_from_host text NOT NULL,
                lock_state integer NOT NULL,
                override_reason text NULL,
                overridden_by text NULL,
                overridden_at timestamptz NULL
            );

            CREATE TABLE IF NOT EXISTS checkout_sessions (
                session_id uuid PRIMARY KEY,
                report_id uuid NOT NULL REFERENCES reports(report_id),
                user_name text NOT NULL,
                local_path text NOT NULL,
                base_hash text NOT NULL,
                started_at timestamptz NOT NULL,
                ended_at timestamptz NULL,
                end_reason integer NULL,
                is_overridden boolean NOT NULL DEFAULT false
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                event_id bigserial PRIMARY KEY,
                timestamp timestamptz NOT NULL,
                actor text NOT NULL,
                action text NOT NULL,
                report_id uuid NOT NULL REFERENCES reports(report_id),
                details text NOT NULL
            );
        "";
        command.ExecuteNonQuery();
    }

    private NpgsqlConnection Open()
    {
        var connection = new NpgsqlConnection(_connectionString);
        connection.Open();
        return connection;
    }

    private static Report MapReport(IDataRecord record)
    {
        return new Report
        {
            ReportId = record.GetFieldValue<Guid>(record.GetOrdinal("report_id")),
            CustomerName = record.GetString(record.GetOrdinal("customer_name")),
            UnitNumber = record.GetString(record.GetOrdinal("unit_number")),
            ReportType = record.GetString(record.GetOrdinal("report_type")),
            CreatedAt = record.GetDateTime(record.GetOrdinal("created_at")),
            Status = (ReportStatus)record.GetInt32(record.GetOrdinal("status")),
            CanonicalPath = record.GetString(record.GetOrdinal("canonical_path")),
            FinalPath = record.IsDBNull(record.GetOrdinal("final_path")) ? null : record.GetString(record.GetOrdinal("final_path")),
            CurrentRevision = record.GetInt32(record.GetOrdinal("current_revision")),
            CurrentHash = record.IsDBNull(record.GetOrdinal("current_hash")) ? null : record.GetString(record.GetOrdinal("current_hash")),
            LastModifiedAt = record.IsDBNull(record.GetOrdinal("last_modified_at")) ? null : record.GetDateTime(record.GetOrdinal("last_modified_at")),
            LastModifiedBy = record.IsDBNull(record.GetOrdinal("last_modified_by")) ? null : record.GetString(record.GetOrdinal("last_modified_by"))
        };
    }

    private static ReportLock MapLock(IDataRecord record)
    {
        return new ReportLock
        {
            ReportId = record.GetFieldValue<Guid>(record.GetOrdinal("report_id")),
            LockedBy = record.GetString(record.GetOrdinal("locked_by")),
            LockedAt = record.GetDateTime(record.GetOrdinal("locked_at")),
            LockedFromHost = record.GetString(record.GetOrdinal("locked_from_host")),
            LockState = (LockState)record.GetInt32(record.GetOrdinal("lock_state")),
            OverrideReason = record.IsDBNull(record.GetOrdinal("override_reason")) ? null : record.GetString(record.GetOrdinal("override_reason")),
            OverriddenBy = record.IsDBNull(record.GetOrdinal("overridden_by")) ? null : record.GetString(record.GetOrdinal("overridden_by")),
            OverriddenAt = record.IsDBNull(record.GetOrdinal("overridden_at")) ? null : record.GetDateTime(record.GetOrdinal("overridden_at"))
        };
    }

    private static CheckoutSession MapSession(IDataRecord record)
    {
        return new CheckoutSession
        {
            SessionId = record.GetFieldValue<Guid>(record.GetOrdinal("session_id")),
            ReportId = record.GetFieldValue<Guid>(record.GetOrdinal("report_id")),
            User = record.GetString(record.GetOrdinal("user_name")),
            LocalPath = record.GetString(record.GetOrdinal("local_path")),
            BaseHash = record.GetString(record.GetOrdinal("base_hash")),
            StartedAt = record.GetDateTime(record.GetOrdinal("started_at")),
            EndedAt = record.IsDBNull(record.GetOrdinal("ended_at")) ? null : record.GetDateTime(record.GetOrdinal("ended_at")),
            EndReason = record.IsDBNull(record.GetOrdinal("end_reason")) ? null : (SessionEndReason)record.GetInt32(record.GetOrdinal("end_reason")),
            IsOverridden = record.GetBoolean(record.GetOrdinal("is_overridden"))
        };
    }

    private static AuditEvent MapAudit(IDataRecord record)
    {
        return new AuditEvent
        {
            Timestamp = record.GetDateTime(record.GetOrdinal("timestamp")),
            Actor = record.GetString(record.GetOrdinal("actor")),
            Action = record.GetString(record.GetOrdinal("action")),
            ReportId = record.GetFieldValue<Guid>(record.GetOrdinal("report_id")),
            Details = record.GetString(record.GetOrdinal("details"))
        };
    }
}
