-- no-transaction
DO $$
BEGIN
  ALTER TYPE delivery_status ADD VALUE IF NOT EXISTS 'sending';
EXCEPTION
  WHEN undefined_object THEN NULL;
END $$;
