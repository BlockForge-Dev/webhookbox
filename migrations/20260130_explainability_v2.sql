-- attempts: add error_category
ALTER TABLE attempts
  ADD COLUMN IF NOT EXISTS error_category text;

-- policy_decisions: add reason_code + details_json (keep old columns if they exist)
ALTER TABLE policy_decisions
  ADD COLUMN IF NOT EXISTS reason_code text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS details_json jsonb NOT NULL DEFAULT '{}'::jsonb;

-- endpoint_health: quarantine + failure streaks
CREATE TABLE IF NOT EXISTS endpoint_health (
  endpoint_id uuid PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,
  consecutive_failures int NOT NULL DEFAULT 0,
  quarantined_until timestamptz NULL,
  last_failure_category text NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- helpful indexes
CREATE INDEX IF NOT EXISTS idx_attempts_delivery_time
  ON attempts (delivery_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_policy_decisions_delivery_time
  ON policy_decisions (delivery_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_endpoint_health_quarantine
  ON endpoint_health (quarantined_until);
