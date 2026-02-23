-- Bootstrap policy tables used by API/worker.
-- Timestamp is intentionally before explainability_v2 so fresh DBs apply this first.

CREATE TABLE IF NOT EXISTS tenant_policies (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  max_in_flight int NOT NULL DEFAULT 10 CHECK (max_in_flight > 0),
  max_payload_bytes int NOT NULL DEFAULT 262144 CHECK (max_payload_bytes > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
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

CREATE INDEX IF NOT EXISTS tenant_policies_tenant_id_idx
  ON tenant_policies (tenant_id);

CREATE INDEX IF NOT EXISTS policy_decisions_delivery_created_idx
  ON policy_decisions (delivery_id, created_at DESC);

CREATE INDEX IF NOT EXISTS policy_decisions_tenant_created_idx
  ON policy_decisions (tenant_id, created_at DESC);
