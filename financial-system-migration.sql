-- ============================================================================
-- JajiGo Financial System Migration
-- Built against the CONFIRMED LIVE production schema + confirmed empty tables:
--   orders = 0 rows, providers = 0 rows, commission_payments does not exist,
--   0 role='provider' users, 1 admin, 10 customers.
--
-- 100% additive: every statement uses IF NOT EXISTS / IF EXISTS guards.
-- Nothing here drops, renames, or changes the type of any existing column.
-- Re-runnable: safe to run this script twice without duplicating data.
--
-- REVIEW ONLY. Do not run against production without a fresh backup, even
-- though the tables this touches are currently empty.
-- ============================================================================

BEGIN;

-- ============================================================================
-- SECTION 1A: PERMANENT CUSTOMER / ADMIN IDs  (on users table)
--   JG-CUS-000001 for role='customer'
--   JG-ADM-000001 for role='admin'
--   role='provider' users deliberately do NOT get a users.public_id here —
--   requirement #2 says provider identity belongs on the providers table
--   (see SECTION 1B). A provider's permanent ID is tied to their business
--   record, not their login account.
-- ============================================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS public_id VARCHAR(20);

CREATE SEQUENCE IF NOT EXISTS customer_public_id_seq START 1;
CREATE SEQUENCE IF NOT EXISTS admin_public_id_seq START 1;

-- Backfill existing customer/admin rows, oldest-first, only where public_id
-- is still NULL (safe to re-run; never touches an already-assigned row).
WITH ranked AS (
  SELECT id, role, ROW_NUMBER() OVER (PARTITION BY role ORDER BY id) AS rn
  FROM users
  WHERE public_id IS NULL AND role IN ('customer','admin')
)
UPDATE users u
SET public_id = CASE r.role
  WHEN 'customer' THEN 'JG-CUS-' || LPAD(r.rn::text, 6, '0')
  WHEN 'admin'    THEN 'JG-ADM-' || LPAD(r.rn::text, 6, '0')
END
FROM ranked r
WHERE u.id = r.id;

-- Initialize each sequence from the HIGHEST NUMERIC SUFFIX actually assigned
-- (never from COUNT(*)), so re-running this after manual edits or gaps is
-- always safe and never reuses a number.
SELECT setval(
  'customer_public_id_seq',
  COALESCE((SELECT MAX(substring(public_id from 'JG-CUS-(\d+)')::bigint) FROM users WHERE role='customer'), 0),
  true
);
SELECT setval(
  'admin_public_id_seq',
  COALESCE((SELECT MAX(substring(public_id from 'JG-ADM-(\d+)')::bigint) FROM users WHERE role='admin'), 0),
  true
);

CREATE UNIQUE INDEX IF NOT EXISTS users_public_id_unique
  ON users(public_id) WHERE public_id IS NOT NULL;

-- Once every customer/admin row is backfilled, enforce that no FUTURE
-- customer/admin row can be missing one (providers are exempt by design).
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM users WHERE role IN ('customer','admin') AND public_id IS NULL
  ) AND NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'users_public_id_required_for_role'
  ) THEN
    ALTER TABLE users ADD CONSTRAINT users_public_id_required_for_role
      CHECK (role NOT IN ('customer','admin') OR public_id IS NOT NULL);
  END IF;
END $$;

-- Server-controlled generation for every future customer/admin user.
-- public_id is NEVER accepted from a request body — this trigger is the
-- only writer, and it no-ops if a value is already present.
CREATE OR REPLACE FUNCTION assign_user_public_id() RETURNS TRIGGER AS $$
DECLARE
  seq_name TEXT;
  prefix   TEXT;
  n        BIGINT;
BEGIN
  IF NEW.public_id IS NOT NULL THEN
    RETURN NEW;
  END IF;

  IF NEW.role = 'customer' THEN
    seq_name := 'customer_public_id_seq'; prefix := 'JG-CUS-';
  ELSIF NEW.role = 'admin' THEN
    seq_name := 'admin_public_id_seq'; prefix := 'JG-ADM-';
  ELSE
    RETURN NEW; -- provider-role login accounts get no users.public_id
  END IF;

  n := nextval(seq_name);
  NEW.public_id := prefix || LPAD(n::text, 6, '0');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_assign_user_public_id ON users;
CREATE TRIGGER trg_assign_user_public_id
BEFORE INSERT ON users
FOR EACH ROW EXECUTE FUNCTION assign_user_public_id();

-- ============================================================================
-- SECTION 1B: PERMANENT PROVIDER ID  (on providers table — the business record)
-- ============================================================================

ALTER TABLE providers ADD COLUMN IF NOT EXISTS public_id VARCHAR(20);

CREATE SEQUENCE IF NOT EXISTS provider_public_id_seq START 1;

WITH ranked AS (
  SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS rn
  FROM providers WHERE public_id IS NULL
)
UPDATE providers p
SET public_id = 'JG-PRV-' || LPAD(r.rn::text, 6, '0')
FROM ranked r
WHERE p.id = r.id;

SELECT setval(
  'provider_public_id_seq',
  COALESCE((SELECT MAX(substring(public_id from 'JG-PRV-(\d+)')::bigint) FROM providers), 0),
  true
);

CREATE UNIQUE INDEX IF NOT EXISTS providers_public_id_unique
  ON providers(public_id) WHERE public_id IS NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM providers WHERE public_id IS NULL) THEN
    ALTER TABLE providers ALTER COLUMN public_id SET NOT NULL;
  END IF;
END $$;

CREATE OR REPLACE FUNCTION assign_provider_public_id() RETURNS TRIGGER AS $$
DECLARE n BIGINT;
BEGIN
  IF NEW.public_id IS NOT NULL THEN
    RETURN NEW;
  END IF;
  n := nextval('provider_public_id_seq');
  NEW.public_id := 'JG-PRV-' || LPAD(n::text, 6, '0');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_assign_provider_public_id ON providers;
CREATE TRIGGER trg_assign_provider_public_id
BEFORE INSERT ON providers
FOR EACH ROW EXECUTE FUNCTION assign_provider_public_id();

-- ============================================================================
-- SECTION 2: ORDER SETTLEMENT SUPPORT
-- Reuses orders.subtotal / total / commission / provider_net / items exactly
-- as they already exist. Does NOT touch order_code's existing NOT NULL/UNIQUE
-- constraint — only auto-fills it server-side when the app doesn't supply one.
-- ============================================================================

CREATE SEQUENCE IF NOT EXISTS order_code_seq START 1;

-- Confirmed: 0 existing rows, so there is nothing to backfill or protect
-- against colliding with. Still initialized from MAX(suffix), never COUNT(*),
-- so this remains correct if this script is ever re-run after real orders exist.
SELECT setval(
  'order_code_seq',
  COALESCE((SELECT MAX(substring(order_code from 'JG-ORD-(\d+)')::bigint) FROM orders), 0),
  true
);

CREATE OR REPLACE FUNCTION assign_order_code() RETURNS TRIGGER AS $$
BEGIN
  IF NEW.order_code IS NULL THEN
    NEW.order_code := 'JG-ORD-' || LPAD(nextval('order_code_seq')::text, 6, '0');
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_assign_order_code ON orders;
CREATE TRIGGER trg_assign_order_code
BEFORE INSERT ON orders
FOR EACH ROW EXECUTE FUNCTION assign_order_code();

-- Which of the two payment models applies. NULLABLE ON PURPOSE:
-- historical/unknown orders stay NULL forever unless an admin manually
-- reviews and sets one. New orders are REJECTED in application code if this
-- is missing — see server.js POST /api/orders.
ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_model VARCHAR(20);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'orders_payment_model_check'
  ) THEN
    ALTER TABLE orders ADD CONSTRAINT orders_payment_model_check
      CHECK (payment_model IS NULL OR payment_model IN ('platform_collected','provider_collected'));
  END IF;
END $$;

-- Marks the moment an order's financial ledger entries were created.
-- NULL = not yet settled. The application's UPDATE ... WHERE settled_at IS NULL
-- guard is what makes settlement idempotent (see server.js settleOrder()).
ALTER TABLE orders ADD COLUMN IF NOT EXISTS settled_at TIMESTAMPTZ;

-- Delivery verification fields used by the provider completion flow.
-- Existing orders remain nullable/untouched; new orders are populated by server.js.
ALTER TABLE orders ADD COLUMN IF NOT EXISTS verification_code VARCHAR(6);
ALTER TABLE orders ADD COLUMN IF NOT EXISTS verification_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS verify_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS verify_locked BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS verify_locked_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_orders_verification_locked ON orders(verify_locked) WHERE verify_locked=true;

CREATE INDEX IF NOT EXISTS idx_orders_settled_at ON orders(settled_at);
CREATE INDEX IF NOT EXISTS idx_orders_provider_status ON orders(provider_id, status);
CREATE INDEX IF NOT EXISTS idx_orders_payment_model ON orders(payment_model);

-- ============================================================================
-- SECTION 3: FINANCIAL TRANSACTION LEDGER
-- Append-only source of truth. Balances are always computed by summing this
-- table (and provider_withdrawals / commission_records) — never stored as a
-- mutable running balance anywhere.
-- ============================================================================

CREATE SEQUENCE IF NOT EXISTS financial_transaction_seq START 1;

CREATE TABLE IF NOT EXISTS financial_transactions (
  id               BIGSERIAL PRIMARY KEY,
  transaction_code VARCHAR(40) UNIQUE,
  user_id          BIGINT REFERENCES users(id),
  provider_id      BIGINT REFERENCES providers(id),
  order_id         BIGINT REFERENCES orders(id),
  type             VARCHAR(30) NOT NULL CHECK (type IN (
                     'customer_payment','provider_sale','jajigo_commission',
                     'provider_payout','commission_payment','refund','adjustment'
                   )),
  direction        VARCHAR(10) NOT NULL CHECK (direction IN ('credit','debit')),
  amount           NUMERIC(14,2) NOT NULL CHECK (amount >= 0),
  status           VARCHAR(20) NOT NULL DEFAULT 'completed'
                     CHECK (status IN ('pending','completed','failed','reversed')),
  description      TEXT DEFAULT '',
  reference        VARCHAR(80),
  created_by       BIGINT REFERENCES users(id),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION assign_transaction_code() RETURNS TRIGGER AS $$
BEGIN
  IF NEW.transaction_code IS NULL THEN
    NEW.transaction_code := 'TXN-' || LPAD(nextval('financial_transaction_seq')::text, 8, '0');
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_assign_transaction_code ON financial_transactions;
CREATE TRIGGER trg_assign_transaction_code
BEFORE INSERT ON financial_transactions
FOR EACH ROW EXECUTE FUNCTION assign_transaction_code();

CREATE INDEX IF NOT EXISTS idx_fin_tx_user     ON financial_transactions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fin_tx_provider ON financial_transactions(provider_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fin_tx_order    ON financial_transactions(order_id);
CREATE INDEX IF NOT EXISTS idx_fin_tx_type     ON financial_transactions(type);

-- ============================================================================
-- SECTION 4: COMMISSION RECORDS (Model B — customer paid provider directly)
-- Brand-new table. commission_payments does NOT exist in production
-- (confirmed via to_regclass), so nothing legacy is being reused or altered.
-- ============================================================================

CREATE TABLE IF NOT EXISTS commission_records (
  id            BIGSERIAL PRIMARY KEY,
  provider_id   BIGINT NOT NULL REFERENCES providers(id),
  order_id      BIGINT NOT NULL REFERENCES orders(id),
  amount        NUMERIC(14,2) NOT NULL CHECK (amount >= 0),
  status        VARCHAR(20) NOT NULL DEFAULT 'owed' CHECK (status IN ('owed','cleared')),
  cleared_by    BIGINT REFERENCES users(id),
  cleared_at    TIMESTAMPTZ,
  admin_note    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(order_id)
);

CREATE INDEX IF NOT EXISTS idx_commission_records_provider ON commission_records(provider_id, status);

-- ============================================================================
-- SECTION 5: PROVIDER WITHDRAWAL REQUESTS (Model A payout workflow)
-- ============================================================================

CREATE TABLE IF NOT EXISTS provider_withdrawals (
  id              BIGSERIAL PRIMARY KEY,
  provider_id     BIGINT NOT NULL REFERENCES providers(id),
  amount          NUMERIC(14,2) NOT NULL CHECK (amount > 0),
  status          VARCHAR(20) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','approved','paid','rejected')),
  requested_by    BIGINT NOT NULL REFERENCES users(id),
  reviewed_by     BIGINT REFERENCES users(id),
  admin_note      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  paid_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_provider_withdrawals_provider ON provider_withdrawals(provider_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_provider_withdrawals_status   ON provider_withdrawals(status);

-- ============================================================================
-- SECTION 6: FINANCIAL AUDIT LOG (append-only; no route ever updates/deletes it)
-- ============================================================================

CREATE TABLE IF NOT EXISTS financial_audit_log (
  id               BIGSERIAL PRIMARY KEY,
  action           VARCHAR(60) NOT NULL,
  performed_by     BIGINT REFERENCES users(id),
  provider_id      BIGINT REFERENCES providers(id),
  order_id         BIGINT REFERENCES orders(id),
  reference_table  VARCHAR(60),
  reference_id     BIGINT,
  amount           NUMERIC(14,2),
  previous_status  VARCHAR(30),
  new_status       VARCHAR(30),
  note             TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fin_audit_performed_by ON financial_audit_log(performed_by, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fin_audit_provider      ON financial_audit_log(provider_id, created_at DESC);

COMMIT;

-- ============================================================================
-- Post-migration sanity checks (read-only — safe to run any time)
-- ============================================================================
-- SELECT role, COUNT(*), COUNT(public_id) FROM users GROUP BY role;
-- SELECT COUNT(*) FROM providers WHERE public_id IS NULL;            -- expect 0
-- SELECT COUNT(*) FROM orders WHERE order_code IS NULL;              -- expect 0
-- SELECT COUNT(*) FROM orders WHERE payment_model IS NULL;           -- expect = all historical orders, by design
-- SELECT to_regclass('public.financial_transactions');
-- SELECT to_regclass('public.commission_records');
-- SELECT to_regclass('public.provider_withdrawals');
-- SELECT to_regclass('public.financial_audit_log');
