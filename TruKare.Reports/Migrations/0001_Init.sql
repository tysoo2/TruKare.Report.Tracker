-- Baseline schema
CREATE TABLE IF NOT EXISTS reports (
    report_id UUID PRIMARY KEY,
    customer_name TEXT NOT NULL,
    unit_number TEXT NOT NULL,
    report_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    status INT NOT NULL,
    canonical_path TEXT NOT NULL,
    final_path TEXT NULL,
    current_revision INT NOT NULL,
    current_hash TEXT NULL,
    last_modified_at TIMESTAMPTZ NULL,
    last_modified_by TEXT NULL
);

CREATE TABLE IF NOT EXISTS report_locks (
    report_id UUID PRIMARY KEY,
    locked_by TEXT NOT NULL,
    locked_at TIMESTAMPTZ NOT NULL,
    locked_from_host TEXT NOT NULL,
    lock_state INT NOT NULL,
    override_reason TEXT NULL,
    overridden_by TEXT NULL,
    overridden_at TIMESTAMPTZ NULL,
    CONSTRAINT fk_report_lock_report FOREIGN KEY (report_id) REFERENCES reports (report_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS checkout_sessions (
    session_id UUID PRIMARY KEY,
    report_id UUID NOT NULL,
    "user" TEXT NOT NULL,
    local_path TEXT NOT NULL,
    base_hash TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ NULL,
    end_reason INT NULL,
    is_overridden BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT fk_session_report FOREIGN KEY (report_id) REFERENCES reports (report_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_events (
    audit_id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    report_id UUID NOT NULL,
    details TEXT NOT NULL,
    CONSTRAINT fk_audit_report FOREIGN KEY (report_id) REFERENCES reports (report_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_report_id ON checkout_sessions (report_id);
CREATE INDEX IF NOT EXISTS idx_audit_report_id ON audit_events (report_id);

-- Baseline data
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
) VALUES
    ('8f0c2cce-3d08-4d1f-9abc-77fd88bf8197', 'Acme Construction', 'Unit-1001', 'Safety', NOW() - INTERVAL '10 days', 0, 'Acme/Unit-1001/Safety/safety-report.pdf', NULL, 1, NULL, NULL, NULL),
    ('e7b8c36a-8464-4ffd-b0a7-8fc25c6998c8', 'BuildRight Partners', 'Unit-2005', 'Inspection', NOW() - INTERVAL '4 days', 0, 'BuildRight/Unit-2005/Inspection/inspection-report.pdf', NULL, 2, NULL, NULL, NULL)
ON CONFLICT (report_id) DO NOTHING;
