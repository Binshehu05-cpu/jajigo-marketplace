-- Safe Step 8 database migration. Existing data is preserved.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(180);
ALTER TABLE providers ADD COLUMN IF NOT EXISTS shop_number VARCHAR(80);
ALTER TABLE providers ADD COLUMN IF NOT EXISTS alt_phone VARCHAR(20);
