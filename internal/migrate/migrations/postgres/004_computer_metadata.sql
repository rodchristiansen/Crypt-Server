ALTER TABLE computers ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT '';
ALTER TABLE computers ADD COLUMN IF NOT EXISTS os_version TEXT NOT NULL DEFAULT '';
ALTER TABLE computers ADD COLUMN IF NOT EXISTS agent_version TEXT NOT NULL DEFAULT '';
ALTER TABLE computers ADD COLUMN IF NOT EXISTS hardware_uuid TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_computers_last_checkin ON computers (last_checkin);
CREATE INDEX IF NOT EXISTS idx_secrets_computer_type ON secrets (computer_id, secret_type);
CREATE INDEX IF NOT EXISTS idx_requests_secret ON requests (secret_id);
