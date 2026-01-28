CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Optional: prevent duplicate tenant names (nice for dev)
CREATE UNIQUE INDEX IF NOT EXISTS tenants_name_uq ON tenants (name);
