import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { randomBytes } from 'node:crypto';
import { OAuth2Client } from 'google-auth-library';

const { Pool } = pg;
const app = express();
const port = Number(process.env.PORT || 10000);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost')
    ? false
    : { rejectUnauthorized: false }
});

const origins = (process.env.CORS_ORIGINS || '*')
  .split(',')
  .map(x => x.trim())
  .filter(Boolean);

const COMMISSION_RATE = Math.max(
  0,
  Math.min(50, Number(process.env.COMMISSION_RATE || 10))
);
const COMMISSION_ON_DELIVERY =
  String(process.env.COMMISSION_ON_DELIVERY || '0') === '1';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '186325933569-f356ld9i6m4k25ebvo088ir664fnvp34.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || origins.includes('*') || origins.includes(origin)) {
      return cb(null, true);
    }
    cb(new Error('CORS blocked'));
  }
}));

app.use(express.json({ limit: '2mb' }));

const ok = (res, data = {}) => res.json({ ok: true, ...data });
const fail = (res, status, message) =>
  res.status(status).json({ ok: false, error: message });

function normPhone(v) {
  let n = String(v || '').replace(/\D/g, '');
  if (n.startsWith('234')) n = '0' + n.slice(3);
  return n;
}

function tokenFor(user) {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not configured.');
  }
  return jwt.sign(
    { sub: String(user.id), role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    if (!h.startsWith('Bearer ')) {
      return fail(res, 401, 'Authentication required.');
    }
    req.auth = jwt.verify(h.slice(7), process.env.JWT_SECRET);
    next();
  } catch {
    return fail(res, 401, 'Invalid token.');
  }
}

function role(...roles) {
  return (req, res, next) =>
    roles.includes(req.auth?.role)
      ? next()
      : fail(res, 403, 'Not allowed.');
}

function positiveInt(v) {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 ? n : null;
}

function nonNegativeNumber(v) {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    ok(res, { service: 'jajigo-marketplace', database: true });
  } catch (e) {
    console.error('Health error:', e);
    fail(res, 503, 'Database unavailable.');
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const phone = normPhone(req.body.phone);
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (name.length < 2) return fail(res, 400, 'Full name is required.');
    if (!/^0\d{10}$/.test(phone)) return fail(res, 400, 'Invalid Nigerian phone number.');
    if (!email) return fail(res, 400, 'Email address is required.');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return fail(res, 400, 'Please enter a valid email address.');
    }
    if (password.length < 6) {
      return fail(res, 400, 'Password must be at least 6 characters.');
    }

    const phoneExists = await pool.query(
      'SELECT id FROM users WHERE phone=$1', [phone]
    );
    if (phoneExists.rowCount) {
      return fail(res, 409, 'Phone number already has an account.');
    }

    const emailExists = await pool.query(
      'SELECT id FROM users WHERE LOWER(email)=LOWER($1)', [email]
    );
    if (emailExists.rowCount) {
      return fail(res, 409, 'Email address already has an account.');
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (phone,full_name,email,password_hash,role)
       VALUES ($1,$2,$3,$4,'customer')
       RETURNING id,phone,full_name,email,avatar_url,role,status`,
      [phone, name, email, hash]
    );

    const user = result.rows[0];
    ok(res, {
      message: 'Account created successfully.',
      token: tokenFor(user),
      user,
      remoteCustomer: true
    });
  } catch (e) {
    console.error('Registration error:', e);
    if (e.code === '23505') {
      return fail(res, 409, 'Phone number or email already exists.');
    }
    fail(res, 500, 'Registration failed.');
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!email || !password) {
      return fail(res, 400, 'Email and password are required.');
    }

    // password_hash is deliberately selected because bcrypt.compare()
    // needs the stored hash. It is removed before the user is returned.
    const result = await pool.query(
      `SELECT id,phone,full_name,email,password_hash,avatar_url,role,status
       FROM users WHERE LOWER(email)=LOWER($1)`,
      [email]
    );

    if (!result.rowCount) return fail(res, 401, 'Wrong email or password.');

    const user = result.rows[0];
    if (user.status !== 'active') {
      return fail(res, 403, 'Account is not active.');
    }

    const passwordCorrect = await bcrypt.compare(
      password,
      user.password_hash
    );
    if (!passwordCorrect) return fail(res, 401, 'Wrong email or password.');

    delete user.password_hash;

    ok(res, {
      message: 'Login successful.',
      token: tokenFor(user),
      user,
      remoteCustomer: true
    });
  } catch (e) {
    console.error('Login error:', e);
    fail(res, 500, 'Login failed.');
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const credential = String(req.body.credential || '').trim();

    if (!credential) return fail(res, 400, 'Google credential is required.');
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    if (!payload?.sub || !payload.email) {
      return fail(res, 401, 'Invalid Google account.');
    }

    const googleId = payload.sub;
    const email = String(payload.email).trim().toLowerCase();
    const name = String(payload.name || email.split('@')[0]).trim();
    const avatarUrl = String(payload.picture || '').trim();

    let result = await pool.query(
      `SELECT id,phone,full_name,email,google_id,avatar_url,role,status
       FROM users WHERE google_id=$1`,
      [googleId]
    );

    if (!result.rowCount) {
      result = await pool.query(
        `SELECT id,phone,full_name,email,google_id,avatar_url,role,status
         FROM users WHERE LOWER(email)=LOWER($1)`,
        [email]
      );
    }

    let user;

    if (result.rowCount) {
      user = result.rows[0];
      if (user.status !== 'active') {
        return fail(res, 403, 'Account is not active.');
      }

      const updated = await pool.query(
        `UPDATE users SET
           google_id=$1,
           email=COALESCE(email,$2),
           avatar_url=COALESCE(NULLIF($3,''),avatar_url)
         WHERE id=$4
         RETURNING id,phone,full_name,email,google_id,avatar_url,role,status`,
        [googleId, email, avatarUrl, user.id]
      );
      user = updated.rows[0];
    } else {
      const googlePasswordHash = await bcrypt.hash(
        randomBytes(32).toString('hex'), 12
      );

      const created = await pool.query(
        `INSERT INTO users
          (full_name,password_hash,email,google_id,avatar_url,role,status)
         VALUES ($1,$2,$3,$4,$5,'customer','active')
         RETURNING id,phone,full_name,email,google_id,avatar_url,role,status`,
        [name, googlePasswordHash, email, googleId, avatarUrl]
      );
      user = created.rows[0];
    }

    ok(res, {
      message: 'Google login successful.',
      token: tokenFor(user),
      user,
      remoteCustomer: true
    });
  } catch (e) {
    console.error('Google authentication error:', e);
    if (e.code === '23505') {
      return fail(res, 409, 'An account with this Google account or email already exists.');
    }
    fail(res, 401, 'Google authentication failed.');
  }
});

app.get('/api/bootstrap', auth, async (req, res) => {
  try {
    const customers = req.auth.role === 'admin'
      ? pool.query(`SELECT id,phone,full_name,email,avatar_url,role,status
                    FROM users WHERE role='customer' ORDER BY id`)
      : pool.query(`SELECT id,phone,full_name,email,avatar_url,role,status
                    FROM users WHERE id=$1`, [req.auth.sub]);

    const orders = req.auth.role === 'customer'
      ? pool.query(
          `SELECT o.*,u.full_name AS customer_name,p.business_name
           FROM orders o
           JOIN users u ON u.id=o.customer_id
           JOIN providers p ON p.id=o.provider_id
           WHERE o.customer_id=$1 ORDER BY o.created_at DESC`,
          [req.auth.sub]
        )
      : req.auth.role === 'provider'
        ? pool.query(
            `SELECT o.*,u.full_name AS customer_name,p.business_name
             FROM orders o
             JOIN users u ON u.id=o.customer_id
             JOIN providers p ON p.id=o.provider_id
             WHERE o.provider_id IN
               (SELECT id FROM providers WHERE user_id=$1)
             ORDER BY o.created_at DESC`,
            [req.auth.sub]
          )
        : pool.query(
            `SELECT o.*,u.full_name AS customer_name,p.business_name
             FROM orders o
             JOIN users u ON u.id=o.customer_id
             JOIN providers p ON p.id=o.provider_id
             ORDER BY o.created_at DESC`
          );

    const [c,v,o,pr] = await Promise.all([
      customers,
      pool.query(
        `SELECT p.*,u.phone AS user_phone,u.full_name AS owner_name
         FROM providers p JOIN users u ON u.id=p.user_id
         WHERE p.status='approved' ORDER BY p.id`
      ),
      orders,
      pool.query(
        `SELECT p.*,pr.business_name
         FROM products p JOIN providers pr ON pr.id=p.provider_id
         WHERE p.is_available=true AND pr.status='approved'
         ORDER BY p.id DESC`
      )
    ]);

    ok(res, {
      customers: c.rows,
      providers: v.rows,
      orders: o.rows,
      products: pr.rows
    });
  } catch (e) {
    console.error('Bootstrap error:', e);
    fail(res, 500, 'Could not load marketplace data.');
  }
});

/* ========================= ADMIN PROVIDERS ========================= */

async function setProviderStatus(req, res, status) {
  try {
    const id = positiveInt(req.params.id);
    if (!id) return fail(res, 400, 'Invalid provider ID.');

    const existing = await pool.query(
      `SELECT id,status,user_id,business_name
       FROM providers WHERE id=$1`,
      [id]
    );
    if (!existing.rowCount) return fail(res, 404, 'Provider not found.');

    const updated = await pool.query(
      `UPDATE providers SET status=$1 WHERE id=$2 RETURNING *`,
      [status, id]
    );

    ok(res, {
      message: status === 'approved'
        ? 'Provider approved successfully.'
        : status === 'rejected'
          ? 'Provider rejected successfully.'
          : 'Provider status updated successfully.',
      provider: updated.rows[0]
    });
  } catch (e) {
    console.error('Provider status error:', e);
    fail(res, 500, 'Failed to update provider.');
  }
}

app.get('/api/admin/providers', auth, role('admin'), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT p.*,u.phone AS user_phone,u.full_name AS owner_name,u.email AS owner_email
       FROM providers p JOIN users u ON u.id=p.user_id
       ORDER BY CASE WHEN p.status='pending' THEN 0 ELSE 1 END,p.id DESC`
    );
    ok(res, { providers: r.rows });
  } catch (e) {
    console.error('Admin providers error:', e);
    fail(res, 500, 'Failed to load providers.');
  }
});

app.patch('/api/admin/providers/:id/status', auth, role('admin'), async (req, res) => {
  const status = String(req.body.status || '').trim().toLowerCase();
  if (!['approved','rejected','pending'].includes(status)) {
    return fail(res, 400, 'Invalid provider status.');
  }
  return setProviderStatus(req, res, status);
});

app.post('/api/admin/providers/:id/approve', auth, role('admin'), async (req, res) => {
  return setProviderStatus(req, res, 'approved');
});

app.post('/api/admin/providers/:id/reject', auth, role('admin'), async (req, res) => {
  return setProviderStatus(req, res, 'rejected');
});

/* ============================= PRODUCTS ============================ */

app.post('/api/products', auth, role('provider'), async (req, res) => {
  try {
    const b = req.body || {};
    const name = String(b.name || '').trim();
    const description = String(b.description || '').trim();
    const price = nonNegativeNumber(b.price);
    const stockQty = nonNegativeNumber(b.stock_qty);
    const imageUrl = String(b.image_url || '').trim();

    if (!name) return fail(res, 400, 'Product name is required.');
    if (price === null) return fail(res, 400, 'Invalid product price.');
    if (stockQty === null) return fail(res, 400, 'Invalid stock quantity.');

    const pr = await pool.query(
      `SELECT id,category_id FROM providers
       WHERE user_id=$1 AND status='approved'`,
      [req.auth.sub]
    );
    if (!pr.rowCount) return fail(res, 403, 'Provider not approved.');

    const p = await pool.query(
      `INSERT INTO products
       (provider_id,category_id,name,description,price,stock_qty,image_url,is_available)
       VALUES ($1,$2,$3,$4,$5,$6,$7,true) RETURNING *`,
      [pr.rows[0].id,pr.rows[0].category_id,name,description,price,stockQty,imageUrl]
    );

    ok(res, { message: 'Product created successfully.', product: p.rows[0] });
  } catch (e) {
    console.error('Create product error:', e);
    fail(res, 500, 'Failed to create product.');
  }
});

async function updateProduct(req, res, adminOnly = false) {
  try {
    const id = positiveInt(req.params.id);
    if (!id) return fail(res, 400, 'Invalid product ID.');

    const b = req.body || {};
    const r = await pool.query(
      `SELECT p.*,pr.user_id FROM products p
       JOIN providers pr ON pr.id=p.provider_id WHERE p.id=$1`,
      [id]
    );
    if (!r.rowCount) return fail(res, 404, 'Product not found.');

    if (
      !adminOnly &&
      req.auth.role === 'provider' &&
      String(r.rows[0].user_id) !== String(req.auth.sub)
    ) {
      return fail(res, 403, 'Not your product.');
    }

    const price = b.price === undefined ? null : nonNegativeNumber(b.price);
    const stockQty = b.stock_qty === undefined ? null : nonNegativeNumber(b.stock_qty);

    if (price === null && b.price !== undefined) {
      return fail(res, 400, 'Invalid product price.');
    }
    if (stockQty === null && b.stock_qty !== undefined) {
      return fail(res, 400, 'Invalid stock quantity.');
    }

    const u = await pool.query(
      `UPDATE products SET
         name=COALESCE(NULLIF($1,''),name),
         description=COALESCE($2,description),
         price=COALESCE($3,price),
         stock_qty=COALESCE($4,stock_qty),
         image_url=COALESCE($5,image_url),
         is_available=COALESCE($6,is_available)
       WHERE id=$7 RETURNING *`,
      [
        b.name === undefined ? null : String(b.name).trim(),
        b.description === undefined ? null : String(b.description).trim(),
        price,
        stockQty,
        b.image_url === undefined ? null : String(b.image_url).trim(),
        b.is_available === undefined ? null : Boolean(b.is_available),
        id
      ]
    );

    ok(res, { message: 'Product updated successfully.', product: u.rows[0] });
  } catch (e) {
    console.error('Update product error:', e);
    fail(res, 500, 'Failed to update product.');
  }
}

app.patch('/api/products/:id', auth, role('provider','admin'), async (req, res) => {
  return updateProduct(req, res, false);
});

app.delete('/api/products/:id', auth, role('provider','admin'), async (req, res) => {
  try {
    const id = positiveInt(req.params.id);
    if (!id) return fail(res, 400, 'Invalid product ID.');

    const r = await pool.query(
      `SELECT p.id,pr.user_id FROM products p
       JOIN providers pr ON pr.id=p.provider_id WHERE p.id=$1`,
      [id]
    );
    if (!r.rowCount) return fail(res, 404, 'Product not found.');

    if (
      req.auth.role === 'provider' &&
      String(r.rows[0].user_id) !== String(req.auth.sub)
    ) {
      return fail(res, 403, 'Not your product.');
    }

    await pool.query('DELETE FROM products WHERE id=$1', [id]);
    ok(res, { message: 'Product deleted successfully.' });
  } catch (e) {
    console.error('Delete product error:', e);
    fail(res, 500, 'Failed to delete product.');
  }
});

/* Explicit admin routes for the Admin Product Management screen. */
app.patch('/api/admin/products/:id', auth, role('admin'), async (req, res) => {
  return updateProduct(req, res, true);
});

app.delete('/api/admin/products/:id', auth, role('admin'), async (req, res) => {
  try {
    const id = positiveInt(req.params.id);
    if (!id) return fail(res, 400, 'Invalid product ID.');

    const r = await pool.query(
      'DELETE FROM products WHERE id=$1 RETURNING id',
      [id]
    );
    if (!r.rowCount) return fail(res, 404, 'Product not found.');

    ok(res, {
      message: 'Product deleted successfully.',
      product_id: r.rows[0].id
    });
  } catch (e) {
    console.error('Admin delete product error:', e);
    fail(res, 500, 'Failed to delete product.');
  }
});

/* ============================== ORDERS ============================= */

app.post('/api/orders', auth, role('customer'), async (req, res) => {
  const c = await pool.connect();

  try {
    const b = req.body || {};
    if (!b.provider_id || !Array.isArray(b.items) || !b.items.length) {
      return fail(res, 400, 'Provider and items required.');
    }

    const providerId = positiveInt(b.provider_id);
    if (!providerId) return fail(res, 400, 'Invalid provider.');

    const items = b.items.map(i => ({
      product_id: positiveInt(i.product_id),
      qty: positiveInt(i.qty)
    }));

    if (items.some(i => !i.product_id || !i.qty)) {
      return fail(res, 400, 'Invalid order item.');
    }

    await c.query('BEGIN');

    const ids = items.map(x => x.product_id);
    const pr = await c.query(
      `SELECT id,name,price,stock_qty,is_available,provider_id
       FROM products WHERE id=ANY($1::bigint[]) FOR UPDATE`,
      [ids]
    );

    const map = new Map(pr.rows.map(p => [String(p.id), p]));

    if (!items.every(i => {
      const p = map.get(String(i.product_id));
      return p && p.is_available && Number(i.qty) <= Number(p.stock_qty);
    })) {
      await c.query('ROLLBACK');
      return fail(res, 400, 'Some items unavailable or out of stock.');
    }

    if (!items.every(i =>
      Number(map.get(String(i.product_id)).provider_id) === providerId
    )) {
      await c.query('ROLLBACK');
      return fail(res, 400, 'All items must be from same provider.');
    }

    const total = items.reduce(
      (s, i) =>
        s + Number(i.qty) * Number(map.get(String(i.product_id)).price),
      0
    );

    const commission = Math.round(total * COMMISSION_RATE / 100);
    const deliveryMode = String(b.delivery_mode || 'provider_delivery');

    if (!['provider_delivery','customer_pickup'].includes(deliveryMode)) {
      await c.query('ROLLBACK');
      return fail(res, 400, 'Invalid delivery mode.');
    }

    const deliveryFee =
      deliveryMode === 'customer_pickup'
        ? 0
        : Math.max(0, Number(b.delivery_fee || 0));

    const o = await c.query(
      `INSERT INTO orders
       (customer_id,provider_id,total_price,commission_amount,delivery_fee,delivery_mode,status)
       VALUES ($1,$2,$3,$4,$5,$6,'pending')
       RETURNING id,total_price,commission_amount,delivery_fee,delivery_mode,status,created_at`,
      [req.auth.sub,providerId,total,commission,deliveryFee,deliveryMode]
    );

    const oid = o.rows[0].id;

    for (const i of items) {
      const p = map.get(String(i.product_id));
      await c.query(
        `INSERT INTO order_items (order_id,product_id,quantity,unit_price)
         VALUES ($1,$2,$3,$4)`,
        [oid,p.id,i.qty,p.price]
      );
      await c.query(
        `UPDATE products SET stock_qty=stock_qty-$1 WHERE id=$2`,
        [i.qty,p.id]
      );
    }

    await c.query('COMMIT');

    ok(res, {
      message: 'Order created successfully.',
      order: { id: oid, ...o.rows[0] }
    });
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Create order error:', e);
    fail(res, 500, 'Failed to create order.');
  } finally {
    c.release();
  }
});

app.patch('/api/orders/:id/status', auth, role('provider','admin'), async (req, res) => {
  try {
    const id = positiveInt(req.params.id);
    const next = String(req.body.status || '').trim();

    if (!id) return fail(res, 400, 'Invalid order ID.');

    const allowed = {
      pending: ['accepted','rejected','cancelled'],
      accepted: ['shipped','cancelled'],
      shipped: ['delivered','cancelled'],
      rejected: [],
      cancelled: [],
      delivered: []
    };

    const r = await pool.query(
      `SELECT o.status,o.provider_id,p.user_id
       FROM orders o JOIN providers p ON p.id=o.provider_id
       WHERE o.id=$1`,
      [id]
    );

    if (!r.rowCount) return fail(res, 404, 'Order not found.');

    if (
      req.auth.role === 'provider' &&
      String(r.rows[0].user_id) !== String(req.auth.sub)
    ) {
      return fail(res, 403, 'Not your order.');
    }

    if (!allowed[r.rows[0].status]?.includes(next)) {
      return fail(res, 400, 'Invalid status transition.');
    }

    const u = await pool.query(
      `UPDATE orders SET status=$1 WHERE id=$2 RETURNING *`,
      [next,id]
    );

    ok(res, {
      message: 'Order status updated successfully.',
      order: u.rows[0]
    });
  } catch (e) {
    console.error('Order status error:', e);
    fail(res, 500, 'Failed to update order status.');
  }
});

/* ======================== COMMISSION PAYMENTS =======================
   These routes use the commission_payments table already referenced
   by the current HTML. No automatic schema migration is performed
   because the exact deployed table definition must be preserved.
===================================================================== */

app.get('/api/admin/commission-payments', auth, role('admin'), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT * FROM commission_payments
       ORDER BY CASE WHEN status='pending' THEN 0 ELSE 1 END,id DESC`
    );
    ok(res, { commission_payments: r.rows });
  } catch (e) {
    console.error('Commission list error:', e);
    fail(res, 500, 'Failed to load commission payments.');
  }
});

app.patch('/api/admin/commission-payments/:id', auth, role('admin'), async (req, res) => {
  try {
    const id = positiveInt(req.params.id);
    const status = String(req.body.status || '').trim().toLowerCase();

    if (!id) return fail(res, 400, 'Invalid commission payment ID.');
    if (!['confirmed','rejected','pending'].includes(status)) {
      return fail(res, 400, 'Invalid commission payment status.');
    }

    const r = await pool.query(
      `UPDATE commission_payments SET
         status=$1,
         confirmed_at=CASE
           WHEN $1 IN ('confirmed','rejected') THEN CURRENT_TIMESTAMP
           ELSE confirmed_at
         END
       WHERE id=$2 RETURNING *`,
      [status,id]
    );

    if (!r.rowCount) {
      return fail(res, 404, 'Commission payment not found.');
    }

    ok(res, {
      message: 'Commission payment updated successfully.',
      commission_payment: r.rows[0]
    });
  } catch (e) {
    console.error('Commission update error:', e);
    fail(res, 500, 'Failed to update commission payment.');
  }
});

/* ========================== PUBLIC PRODUCTS ======================== */

app.get('/api/products', async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT p.*,pr.business_name
       FROM products p JOIN providers pr ON pr.id=p.provider_id
       WHERE p.is_available=true AND pr.status='approved'
       ORDER BY p.id DESC`
    );
    ok(res, { products: r.rows });
  } catch (e) {
    console.error('Products error:', e);
    fail(res, 500, 'Failed to fetch products.');
  }
});

app.listen(port, () => {
  console.log(`JajiGo marketplace backend listening on ${port}`);
});
