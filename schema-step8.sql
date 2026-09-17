CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  phone VARCHAR(20) UNIQUE NOT NULL,
  full_name VARCHAR(120) NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'customer' CHECK (role IN ('customer','provider','admin')),
  status VARCHAR(20) NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS providers (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  business_name VARCHAR(160) NOT NULL,
  description TEXT DEFAULT '',
  category_id INTEGER,
  address TEXT DEFAULT '',
  delivery_mode VARCHAR(30) DEFAULT 'provider_delivery',
  delivery_fee INTEGER NOT NULL DEFAULT 0,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  lat DOUBLE PRECISION,
  lng DOUBLE PRECISION,
  opening_hours JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS products (
  id BIGSERIAL PRIMARY KEY,
  provider_id BIGINT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
  category_id INTEGER,
  type VARCHAR(20) NOT NULL DEFAULT 'product',
  name VARCHAR(160) NOT NULL,
  description TEXT DEFAULT '',
  icon VARCHAR(16) DEFAULT '📦',
  price INTEGER NOT NULL CHECK (price >= 0),
  stock_qty INTEGER,
  is_available BOOLEAN NOT NULL DEFAULT TRUE,
  variants JSONB NOT NULL DEFAULT '[]'::jsonb,
  photo TEXT DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE products ADD COLUMN IF NOT EXISTS icon VARCHAR(16) DEFAULT '📦';

CREATE TABLE IF NOT EXISTS orders (
  id BIGSERIAL PRIMARY KEY,
  order_code VARCHAR(40) UNIQUE NOT NULL,
  customer_id BIGINT NOT NULL REFERENCES users(id),
  provider_id BIGINT NOT NULL REFERENCES providers(id),
  status VARCHAR(30) NOT NULL DEFAULT 'pending',
  payment_method VARCHAR(40) NOT NULL,
  payment_status VARCHAR(30) NOT NULL DEFAULT 'pending',
  delivery_mode VARCHAR(30) NOT NULL,
  address TEXT,
  customer_phone VARCHAR(20),
  subtotal INTEGER NOT NULL,
  delivery_fee INTEGER NOT NULL DEFAULT 0,
  total INTEGER NOT NULL,
  commission INTEGER NOT NULL DEFAULT 0,
  provider_net INTEGER NOT NULL DEFAULT 0,
  items JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_orders_provider ON orders(provider_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_products_provider ON products(provider_id);

-- Step 8 provider registration fields
ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(180);
ALTER TABLE providers ADD COLUMN IF NOT EXISTS shop_number VARCHAR(80);
ALTER TABLE providers ADD COLUMN IF NOT EXISTS alt_phone VARCHAR(20);
