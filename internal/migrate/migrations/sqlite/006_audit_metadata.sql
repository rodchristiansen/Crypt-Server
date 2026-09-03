ALTER TABLE audit_events ADD COLUMN target_type TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN target_id TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN metadata TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events (created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events (action);
