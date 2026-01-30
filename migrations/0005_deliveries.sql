-- Delivery status is an enum (nice + safe)
DO $$ BEGIN
  CREATE TYPE delivery_status AS ENUM ('pending', 'retrying', 'delivered', 'failed');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS deliveries (
  id UUID PRIMARY KEY,
  event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,

  status delivery_status NOT NULL DEFAULT 'pending',
  attempts_count INT NOT NULL DEFAULT 0,
  next_run_at TIMESTAMPTZ,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prevent duplicate deliveries for the same event+endpoint
CREATE UNIQUE INDEX IF NOT EXISTS deliveries_event_endpoint_uq
  ON deliveries (event_id, endpoint_id);

-- Useful indexes
CREATE INDEX IF NOT EXISTS deliveries_event_id_idx
  ON deliveries (event_id);

CREATE INDEX IF NOT EXISTS deliveries_endpoint_id_idx
  ON deliveries (endpoint_id);

CREATE INDEX IF NOT EXISTS deliveries_status_next_run_idx
  ON deliveries (status, next_run_at);
