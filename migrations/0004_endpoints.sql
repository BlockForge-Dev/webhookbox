CREATE TABLE IF NOT EXISTS endpoints (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Helpful indexes
CREATE INDEX IF NOT EXISTS endpoints_tenant_id_idx
  ON endpoints (tenant_id);

CREATE INDEX IF NOT EXISTS endpoints_tenant_enabled_idx
  ON endpoints (tenant_id, enabled);
