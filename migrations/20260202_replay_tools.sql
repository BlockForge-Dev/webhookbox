-- Replay tools: allow multiple deliveries per event+endpoint for replays
ALTER TABLE deliveries
  ADD COLUMN IF NOT EXISTS is_replay boolean NOT NULL DEFAULT false;

ALTER TABLE deliveries
  ADD COLUMN IF NOT EXISTS replay_of_delivery_id uuid NULL REFERENCES deliveries(id) ON DELETE SET NULL;

ALTER TABLE deliveries
  ADD COLUMN IF NOT EXISTS target_url text NULL;

DROP INDEX IF EXISTS deliveries_event_endpoint_uq;

CREATE UNIQUE INDEX IF NOT EXISTS deliveries_event_endpoint_uq
  ON deliveries (event_id, endpoint_id)
  WHERE is_replay = false;
