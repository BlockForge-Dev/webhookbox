CREATE TABLE IF NOT EXISTS events (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  payload_json JSONB NOT NULL,
  idempotency_key TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ✅ Idempotency guarantee: same tenant + same key can't insert twice
CREATE UNIQUE INDEX IF NOT EXISTS events_tenant_idempotency_uq
  ON events (tenant_id, idempotency_key);

-- Helpful indexes for querying later
CREATE INDEX IF NOT EXISTS events_tenant_created_idx
  ON events (tenant_id, created_at DESC);
