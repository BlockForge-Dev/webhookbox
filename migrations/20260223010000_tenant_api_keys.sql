CREATE TABLE IF NOT EXISTS tenant_api_keys (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  label text NOT NULL DEFAULT 'default',
  key_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS tenant_api_keys_tenant_created_idx
  ON tenant_api_keys (tenant_id, created_at DESC);
