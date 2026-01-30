-- Attempts: one row per HTTP try (success or fail)
CREATE TABLE IF NOT EXISTS attempts (
  id uuid PRIMARY KEY,
  delivery_id uuid NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
  attempt_no int NOT NULL,
  status_code int NULL,
  latency_ms int NULL,
  error_type text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (delivery_id, attempt_no)
);

CREATE INDEX IF NOT EXISTS attempts_delivery_id_idx
  ON attempts (delivery_id, created_at DESC);


-- DLQ: when max attempts exceeded, we store a record for inspection/replay later
CREATE TABLE IF NOT EXISTS dead_letters (
  id uuid PRIMARY KEY,
  delivery_id uuid NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
  last_job_id uuid NULL REFERENCES jobs(id) ON DELETE SET NULL,
  reason text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS dead_letters_delivery_id_idx
  ON dead_letters (delivery_id, created_at DESC);
