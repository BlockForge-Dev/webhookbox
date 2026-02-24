-- bootstrap tables when this migration runs before later timestamped files
CREATE TABLE IF NOT EXISTS attempts (
  id uuid PRIMARY KEY,
  delivery_id uuid NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
  attempt_no int NOT NULL,
  status_code int NULL,
  latency_ms int NULL,
  error_type text NULL,
  error_category text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (delivery_id, attempt_no)
);

CREATE TABLE IF NOT EXISTS policy_decisions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  delivery_id uuid NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
  job_id uuid NULL REFERENCES jobs(id) ON DELETE SET NULL,
  decision text NOT NULL,
  reason text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  reason_code text NOT NULL DEFAULT '',
  details_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

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
