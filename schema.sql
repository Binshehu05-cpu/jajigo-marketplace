-- JajiGo Morning Rush + order-safety migration
-- ADDITIVE ONLY. Review against the live schema and take a fresh pg_dump
-- before production execution. This script does not delete existing rows.

BEGIN;

-- Providers: Morning Rush configuration and explicit payment-model switches.
ALTER TABLE providers
  ADD COLUMN IF NOT EXISTS morning_rush_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS morning_rush_paused boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS morning_open_time time,
  ADD COLUMN IF NOT EXISTS morning_close_time time,
  ADD COLUMN IF NOT EXISTS morning_prep_minutes integer NOT NULL DEFAULT 15,
  ADD COLUMN IF NOT EXISTS morning_packaging_fee numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS morning_max_orders integer,
  ADD COLUMN IF NOT EXISTS platform_payment_enabled boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS provider_payment_enabled boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE providers
  DROP CONSTRAINT IF EXISTS providers_morning_prep_minutes_check;
ALTER TABLE providers
  ADD CONSTRAINT providers_morning_prep_minutes_check
  CHECK (morning_prep_minutes > 0);

ALTER TABLE providers
  DROP CONSTRAINT IF EXISTS providers_morning_packaging_fee_check;
ALTER TABLE providers
  ADD CONSTRAINT providers_morning_packaging_fee_check
  CHECK (morning_packaging_fee >= 0);

ALTER TABLE providers
  DROP CONSTRAINT IF EXISTS providers_morning_max_orders_check;
ALTER TABLE providers
  ADD CONSTRAINT providers_morning_max_orders_check
  CHECK (morning_max_orders IS NULL OR morning_max_orders > 0);

-- Products: identify breakfast products. NULL stock means unlimited/not tracked.
ALTER TABLE products
  ADD COLUMN IF NOT EXISTS is_breakfast boolean NOT NULL DEFAULT false;

ALTER TABLE products
  ALTER COLUMN stock_qty DROP NOT NULL;

ALTER TABLE products
  DROP CONSTRAINT IF EXISTS products_stock_qty_nonnegative_check;
ALTER TABLE products
  ADD CONSTRAINT products_stock_qty_nonnegative_check
  CHECK (stock_qty IS NULL OR stock_qty >= 0);

-- Orders: one shared order system; breakfast is an order type.
ALTER TABLE orders
  ADD COLUMN IF NOT EXISTS order_type varchar(20) NOT NULL DEFAULT 'standard',
  ADD COLUMN IF NOT EXISTS packaging_fee numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS stock_restored_at timestamptz;

ALTER TABLE orders
  DROP CONSTRAINT IF EXISTS orders_order_type_check;
ALTER TABLE orders
  ADD CONSTRAINT orders_order_type_check
  CHECK (order_type IN ('standard','breakfast'));

ALTER TABLE orders
  DROP CONSTRAINT IF EXISTS orders_packaging_fee_nonnegative_check;
ALTER TABLE orders
  ADD CONSTRAINT orders_packaging_fee_nonnegative_check
  CHECK (packaging_fee >= 0);

-- Existing delivery-code protection in the current server also uses these
-- fields. Add them if they are not already present.
ALTER TABLE orders
  ADD COLUMN IF NOT EXISTS verify_attempts integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS verify_locked boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS verify_locked_at timestamptz;

ALTER TABLE orders
  DROP CONSTRAINT IF EXISTS orders_verify_attempts_check;
ALTER TABLE orders
  ADD CONSTRAINT orders_verify_attempts_check
  CHECK (verify_attempts >= 0);

CREATE INDEX IF NOT EXISTS idx_products_breakfast_available
  ON products(provider_id, is_breakfast, is_available);

CREATE INDEX IF NOT EXISTS idx_orders_provider_type_created
  ON orders(provider_id, order_type, created_at);

CREATE INDEX IF NOT EXISTS idx_orders_unsettled_status
  ON orders(status, settled_at);

COMMIT;
