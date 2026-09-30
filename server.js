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

/* ===================== MONEY / FINANCIAL HELPERS =====================
   All money math happens here, on the backend, using JS numbers rounded
   to 2 decimal places to match NUMERIC(14,2). The frontend's totals,
   commission, provider_net, or balances are NEVER trusted for anything
   that writes to the database.
======================================================================= */

// Round to 2 decimal places the same way NUMERIC(14,2) would store it.
function round2(n) {
  return Math.round((Number(n) + Number.EPSILON) * 100) / 100;
}

// Writes one row to the append-only audit log. Always called with the
// SAME client/transaction as the financial change it documents, so the
// audit entry can never exist without the change (or vice versa).
async function writeAuditLog(client, {
  action, performedBy = null, providerId = null, orderId = null,
  referenceTable = null, referenceId = null, amount = null,
  previousStatus = null, newStatus = null, note = null
}) {
  await client.query(
    `INSERT INTO financial_audit_log
      (action,performed_by,provider_id,order_id,reference_table,reference_id,
       amount,previous_status,new_status,note)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [action, performedBy, providerId, orderId, referenceTable, referenceId,
     amount, previousStatus, newStatus, note]
  );
}

async function insertFinancialTransaction(client, {
  userId = null, providerId = null, orderId = null, type, direction,
  amount, status = 'completed', description = '', reference = null,
  createdBy = null
}) {
  const r = await client.query(
    `INSERT INTO financial_transactions
      (user_id,provider_id,order_id,type,direction,amount,status,description,reference,created_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     RETURNING *`,
    [userId, providerId, orderId, type, direction, amount, status, description, reference, createdBy]
  );
  return r.rows[0];
}

// A provider's available-for-withdrawal balance. Deliberately NOT
// "sales minus all withdrawals" (see requirement #13):
//   + everything ever credited to the provider as provider_sale
//   - everything already actually PAID OUT (provider_payout debits)
//   - everything currently pending or approved (reserved, not yet paid,
//     so the same naira can't be requested twice before payment clears)
// Must be called with an open client inside a transaction that has
// already taken pg_advisory_xact_lock(providerId) if the caller is about
// to act on the result (e.g. approve a new withdrawal).
async function getProviderBalance(client, providerId) {
  const earned = await client.query(
    `SELECT COALESCE(SUM(amount),0) AS total FROM financial_transactions
     WHERE provider_id=$1 AND type='provider_sale' AND direction='credit' AND status='completed'`,
    [providerId]
  );
  const paidOut = await client.query(
    `SELECT COALESCE(SUM(amount),0) AS total FROM financial_transactions
     WHERE provider_id=$1 AND type='provider_payout' AND direction='debit' AND status='completed'`,
    [providerId]
  );
  const reserved = await client.query(
    `SELECT COALESCE(SUM(amount),0) AS total FROM provider_withdrawals
     WHERE provider_id=$1 AND status IN ('pending','approved')`,
    [providerId]
  );

  const totalEarned = Number(earned.rows[0].total);
  const totalPaidOut = Number(paidOut.rows[0].total);
  const totalReserved = Number(reserved.rows[0].total);

  return {
    total_earned: round2(totalEarned),
    total_paid_out: round2(totalPaidOut),
    total_reserved: round2(totalReserved),
    available_balance: round2(totalEarned - totalPaidOut - totalReserved)
  };
}

/* ============================================================================
   SETTLEMENT
   Fires only when an order genuinely reaches 'delivered'. Uses the existing
   verification_code / verification_verified / verified_at fields: if an
   order never had a verification_code issued, verification wasn't part of
   its delivery flow and settlement proceeds on status alone. If it DID have
   a verification_code issued, settlement requires verification_verified=true
   — a "delivered" status alone is not enough for a code-gated order.
   >>> This interpretation is a judgment call flagged in the notes file —
   >>> confirm it matches your actual delivery-confirmation flow. <<<

   Idempotency: guarded by "WHERE settled_at IS NULL" on the final UPDATE,
   which is atomic under Postgres MVCC — a second concurrent call always
   sees 0 rows affected and does nothing further.

   NEVER fabricates records for payment_model IS NULL (historical/unknown
   orders) — those are left completely untouched and reported separately
   for manual admin review.
============================================================================ */

const SETTLEMENT_RESULT = {
  SETTLED: 'settled',
  ALREADY_SETTLED: 'already_settled',
  NOT_DELIVERED: 'not_delivered',
  NOT_VERIFIED: 'not_verified',
  NEEDS_MANUAL_REVIEW: 'needs_manual_review'
};

async function settleOrder(client, orderId, actingUserId) {
  await client.query('SELECT pg_advisory_xact_lock($1)', [orderId]);

  const r = await client.query(
    `SELECT * FROM orders WHERE id=$1 FOR UPDATE`,
    [orderId]
  );
  if (!r.rowCount) {
    return { result: 'not_found' };
  }
  const order = r.rows[0];

  if (order.settled_at) {
    return { result: SETTLEMENT_RESULT.ALREADY_SETTLED, order };
  }

  if (order.status !== 'delivered') {
    return { result: SETTLEMENT_RESULT.NOT_DELIVERED, order };
  }

  if (order.verification_code && !order.verification_verified) {
    return { result: SETTLEMENT_RESULT.NOT_VERIFIED, order };
  }

  if (!order.payment_model) {
    // Historical/unknown order. Do NOT fabricate anything. Leave it for
    // an admin to explicitly set payment_model after manual review.
    return { result: SETTLEMENT_RESULT.NEEDS_MANUAL_REVIEW, order };
  }

  const total = round2(order.total);
  const commission = round2(order.commission);
  const providerNet = round2(order.provider_net);

  if (order.payment_model === 'platform_collected') {
    await insertFinancialTransaction(client, {
      userId: order.customer_id, orderId: order.id,
      type: 'customer_payment', direction: 'credit', amount: total,
      description: `Customer payment for order ${order.order_code}`,
      reference: order.order_code, createdBy: actingUserId
    });

    await insertFinancialTransaction(client, {
      providerId: order.provider_id, orderId: order.id,
      type: 'provider_sale', direction: 'credit', amount: providerNet,
      description: `Provider earnings for order ${order.order_code}`,
      reference: order.order_code, createdBy: actingUserId
    });

    await insertFinancialTransaction(client, {
      orderId: order.id,
      type: 'jajigo_commission', direction: 'credit', amount: commission,
      status: 'completed',
      description: `JajiGo commission collected via platform for order ${order.order_code}`,
      reference: order.order_code, createdBy: actingUserId
    });

    await writeAuditLog(client, {
      action: 'order_settled_platform_collected', performedBy: actingUserId,
      providerId: order.provider_id, orderId: order.id,
      referenceTable: 'orders', referenceId: order.id,
      amount: total, previousStatus: null, newStatus: 'settled',
      note: 'Model A settlement: customer_payment + provider_sale + jajigo_commission recorded.'
    });
  } else {
    // provider_collected (Model B): customer already paid the provider
    // directly, outside the platform. JajiGo did NOT receive money, and
    // the provider does NOT get a platform payout for this order. Only
    // the commission owed to JajiGo is tracked, separately, as "owed".
    await client.query(
      `INSERT INTO commission_records (provider_id, order_id, amount, status)
       VALUES ($1,$2,$3,'owed')
       ON CONFLICT (order_id) DO NOTHING`,
      [order.provider_id, order.id, commission]
    );

    await insertFinancialTransaction(client, {
      providerId: order.provider_id, orderId: order.id,
      type: 'jajigo_commission', direction: 'credit', amount: commission,
      status: 'pending', // pending = owed, not yet actually collected
      description: `JajiGo commission owed (provider-collected order ${order.order_code})`,
      reference: order.order_code, createdBy: actingUserId
    });

    await writeAuditLog(client, {
      action: 'order_settled_provider_collected', performedBy: actingUserId,
      providerId: order.provider_id, orderId: order.id,
      referenceTable: 'commission_records', referenceId: order.id,
      amount: commission, previousStatus: null, newStatus: 'owed',
      note: 'Model B settlement: commission_records owed entry created, no provider payout fabricated.'
    });
  }

  const settled = await client.query(
    `UPDATE orders SET settled_at=NOW() WHERE id=$1 AND settled_at IS NULL RETURNING *`,
    [order.id]
  );

  if (!settled.rowCount) {
    // Someone else settled it in the sliver of time between our checks and
    // this UPDATE. Extremely unlikely given the advisory lock, but if it
    // ever happens we must not have written duplicate ledger rows above —
    // the caller should treat this as a hard error and roll back.
    throw new Error('Concurrent settlement conflict detected for order ' + order.id);
  }

  return { result: SETTLEMENT_RESULT.SETTLED, order: settled.rows[0] };
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

/* ============================================================================
   AUTH (unchanged from current server.js — no financial logic here)
============================================================================ */

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
       RETURNING id,phone,full_name,email,avatar_url,role,status,public_id`,
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

    const result = await pool.query(
      `SELECT id,phone,full_name,email,password_hash,avatar_url,role,status,public_id
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
      `SELECT id,phone,full_name,email,google_id,avatar_url,role,status,public_id
       FROM users WHERE google_id=$1`,
      [googleId]
    );

    if (!result.rowCount) {
      result = await pool.query(
        `SELECT id,phone,full_name,email,google_id,avatar_url,role,status,public_id
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
         RETURNING id,phone,full_name,email,google_id,avatar_url,role,status,public_id`,
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
         RETURNING id,phone,full_name,email,google_id,avatar_url,role,status,public_id`,
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
      ? pool.query(`SELECT id,phone,full_name,email,avatar_url,role,status,public_id
                    FROM users WHERE role='customer' ORDER BY id`)
      : pool.query(`SELECT id,phone,full_name,email,avatar_url,role,status,public_id
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
        `SELECT p.*,p.public_id AS provider_public_id,u.phone AS user_phone,u.full_name AS owner_name
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
      `SELECT p.*,p.public_id AS provider_public_id,u.phone AS user_phone,u.full_name AS owner_name,u.email AS owner_email
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

/* ============================= PRODUCTS =============================
   Uses products.photo (the real live column). image_url is never
   referenced anywhere in this file.
======================================================================= */

app.post('/api/products', auth, role('provider'), async (req, res) => {
  try {
    const b = req.body || {};
    const name = String(b.name || '').trim();
    const description = String(b.description || '').trim();
    const price = nonNegativeNumber(b.price);
    const stockQty = nonNegativeNumber(b.stock_qty);
    const photo = String(b.photo || '').trim();

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
       (provider_id,category_id,name,description,price,stock_qty,photo,is_available)
       VALUES ($1,$2,$3,$4,$5,$6,$7,true) RETURNING *`,
      [pr.rows[0].id,pr.rows[0].category_id,name,description,price,stockQty,photo]
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
         photo=COALESCE($5,photo),
         is_available=COALESCE($6,is_available)
       WHERE id=$7 RETURNING *`,
      [
        b.name === undefined ? null : String(b.name).trim(),
        b.description === undefined ? null : String(b.description).trim(),
        price,
        stockQty,
        b.photo === undefined ? null : String(b.photo).trim(),
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

/* ============================================================================
   ORDERS — rewritten against the real live schema.
   No order_items table. No total_price / commission_amount / image_url.
   Line items live in orders.items (JSONB), server-computed and locked down.
============================================================================ */

app.post('/api/orders', auth, role('customer'), async (req, res) => {
  const c = await pool.connect();

  try {
    const b = req.body || {};

    if (!b.provider_id || !Array.isArray(b.items) || !b.items.length) {
      return fail(res, 400, 'Provider and items required.');
    }

    const paymentModel = String(b.payment_model || '').trim();
    if (!['platform_collected','provider_collected'].includes(paymentModel)) {
      return fail(res, 400,
        'payment_model is required and must be either "platform_collected" or "provider_collected".');
    }

    const providerId = positiveInt(b.provider_id);
    if (!providerId) return fail(res, 400, 'Invalid provider.');

    const rawItems = b.items.map(i => ({
      product_id: positiveInt(i.product_id),
      qty: positiveInt(i.qty)
    }));

    if (rawItems.some(i => !i.product_id || !i.qty)) {
      return fail(res, 400, 'Invalid order item.');
    }

    const deliveryMode = String(b.delivery_mode || 'provider_delivery');
    if (!['provider_delivery','customer_pickup'].includes(deliveryMode)) {
      return fail(res, 400, 'Invalid delivery mode.');
    }

    const address = b.address ? String(b.address).trim() : null;
    const customerPhone = b.customer_phone ? normPhone(b.customer_phone) : null;
    const paymentMethod = String(b.payment_method || '').trim() || null;

    await c.query('BEGIN');

    const providerRow = await c.query(
      `SELECT id, status, delivery_fee FROM providers WHERE id=$1 FOR UPDATE`,
      [providerId]
    );
    if (!providerRow.rowCount || providerRow.rows[0].status !== 'approved') {
      await c.query('ROLLBACK');
      return fail(res, 400, 'Provider not available.');
    }

    const ids = rawItems.map(x => x.product_id);
    const pr = await c.query(
      `SELECT id,name,price,stock_qty,is_available,provider_id,photo
       FROM products WHERE id=ANY($1::bigint[]) FOR UPDATE`,
      [ids]
    );

    const map = new Map(pr.rows.map(p => [String(p.id), p]));

    if (!rawItems.every(i => {
      const p = map.get(String(i.product_id));
      return p && p.is_available && Number(i.qty) <= Number(p.stock_qty);
    })) {
      await c.query('ROLLBACK');
      return fail(res, 400, 'Some items unavailable or out of stock.');
    }

    if (!rawItems.every(i =>
      Number(map.get(String(i.product_id)).provider_id) === providerId
    )) {
      await c.query('ROLLBACK');
      return fail(res, 400, 'All items must be from same provider.');
    }

    // Server-computed line items — nothing here comes from the frontend
    // except product_id and qty, which were already validated above.
    const lineItems = rawItems.map(i => {
      const p = map.get(String(i.product_id));
      const unitPrice = round2(p.price);
      const lineTotal = round2(unitPrice * i.qty);
      return {
        product_id: p.id,
        name: p.name,
        photo: p.photo,
        unit_price: unitPrice,
        qty: i.qty,
        line_total: lineTotal
      };
    });

    const subtotal = round2(lineItems.reduce((s, i) => s + i.line_total, 0));

    const deliveryFee = deliveryMode === 'customer_pickup'
      ? 0
      : round2(Math.max(0, Number(providerRow.rows[0].delivery_fee || 0)));

    const total = round2(subtotal + deliveryFee);

    // COMMISSION_RATE / COMMISSION_ON_DELIVERY preserved exactly as before:
    // if COMMISSION_ON_DELIVERY is enabled, delivery fee is included in the
    // base commission is calculated on; otherwise commission is calculated
    // on subtotal only. provider_net is always total minus commission —
    // the provider keeps everything else regardless of which base was used.
    const commissionBase = COMMISSION_ON_DELIVERY ? total : subtotal;
    const commission = round2(commissionBase * COMMISSION_RATE / 100);
    const providerNet = round2(total - commission);

    const o = await c.query(
      `INSERT INTO orders
        (customer_id,provider_id,status,payment_method,payment_status,
         delivery_mode,address,customer_phone,subtotal,delivery_fee,total,
         commission,provider_net,items,payment_model)
       VALUES ($1,$2,'pending',$3,'pending',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       RETURNING *`,
      [
        req.auth.sub, providerId, paymentMethod, deliveryMode, address,
        customerPhone, subtotal, deliveryFee, total, commission, providerNet,
        JSON.stringify(lineItems), paymentModel
      ]
    );

    const order = o.rows[0];

    for (const i of rawItems) {
      await c.query(
        `UPDATE products SET stock_qty = stock_qty - $1 WHERE id=$2`,
        [i.qty, i.product_id]
      );
    }

    await c.query('COMMIT');

    ok(res, { message: 'Order created successfully.', order });
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Create order error:', e);
    fail(res, 500, 'Failed to create order.');
  } finally {
    c.release();
  }
});

app.patch('/api/orders/:id/status', auth, role('provider','admin'), async (req, res) => {
  const c = await pool.connect();

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

    await c.query('BEGIN');

    const r = await c.query(
      `SELECT o.*,p.user_id
       FROM orders o JOIN providers p ON p.id=o.provider_id
       WHERE o.id=$1 FOR UPDATE`,
      [id]
    );

    if (!r.rowCount) {
      await c.query('ROLLBACK');
      return fail(res, 404, 'Order not found.');
    }

    const existing = r.rows[0];

    if (
      req.auth.role === 'provider' &&
      String(existing.user_id) !== String(req.auth.sub)
    ) {
      await c.query('ROLLBACK');
      return fail(res, 403, 'Not your order.');
    }

    if (!allowed[existing.status]?.includes(next)) {
      await c.query('ROLLBACK');
      return fail(res, 400, 'Invalid status transition.');
    }

    const u = await c.query(
      `UPDATE orders SET status=$1, updated_at=NOW() WHERE id=$2 RETURNING *`,
      [next, id]
    );

    let settlement = null;

    if (next === 'delivered') {
      // Attempt settlement in the SAME transaction as the status change,
      // so an order can never be marked delivered without either being
      // settled or explicitly flagged for manual review — never a
      // half-applied state.
      settlement = await settleOrder(c, id, req.auth.sub);
    }

    await c.query('COMMIT');

    ok(res, {
      message: 'Order status updated successfully.',
      order: u.rows[0],
      settlement: settlement
        ? { result: settlement.result }
        : null
    });
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Order status error:', e);
    fail(res, 500, 'Failed to update order status.');
  } finally {
    c.release();
  }
});

// Manual settlement endpoint — lets an admin retry settlement (e.g. after
// verification lands late) without needing another status transition.
app.post('/api/admin/orders/:id/settle', auth, role('admin'), async (req, res) => {
  const c = await pool.connect();
  try {
    const id = positiveInt(req.params.id);
    if (!id) return fail(res, 400, 'Invalid order ID.');

    await c.query('BEGIN');
    const settlement = await settleOrder(c, id, req.auth.sub);
    await c.query('COMMIT');

    if (settlement.result === 'not_found') return fail(res, 404, 'Order not found.');

    ok(res, { message: 'Settlement processed.', result: settlement.result, order: settlement.order });
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Manual settlement error:', e);
    fail(res, 500, 'Failed to process settlement.');
  } finally {
    c.release();
  }
});

// Admin-only: resolve a historical order's payment_model after manual
// review. This is the ONLY way payment_model is ever set for an order
// that didn't provide one at creation time — never inferred automatically.
app.patch('/api/admin/orders/:id/payment-model', auth, role('admin'), async (req, res) => {
  const c = await pool.connect();
  try {
    const id = positiveInt(req.params.id);
    const paymentModel = String(req.body.payment_model || '').trim();

    if (!id) return fail(res, 400, 'Invalid order ID.');
    if (!['platform_collected','provider_collected'].includes(paymentModel)) {
      return fail(res, 400, 'payment_model must be platform_collected or provider_collected.');
    }

    await c.query('BEGIN');

    const existing = await c.query(
      `SELECT id, payment_model, settled_at FROM orders WHERE id=$1 FOR UPDATE`,
      [id]
    );
    if (!existing.rowCount) {
      await c.query('ROLLBACK');
      return fail(res, 404, 'Order not found.');
    }
    if (existing.rows[0].settled_at) {
      await c.query('ROLLBACK');
      return fail(res, 409, 'Order is already settled; payment_model cannot be changed.');
    }
    if (existing.rows[0].payment_model) {
      await c.query('ROLLBACK');
      return fail(res, 409, 'Order already has a payment_model set.');
    }

    const updated = await c.query(
      `UPDATE orders SET payment_model=$1 WHERE id=$2 RETURNING *`,
      [paymentModel, id]
    );

    await writeAuditLog(c, {
      action: 'order_payment_model_manually_set', performedBy: req.auth.sub,
      orderId: id, referenceTable: 'orders', referenceId: id,
      previousStatus: 'null', newStatus: paymentModel,
      note: 'Historical order payment_model set by admin after manual review.'
    });

    await c.query('COMMIT');

    ok(res, { message: 'payment_model set. You can now call /api/admin/orders/:id/settle.', order: updated.rows[0] });
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Set payment_model error:', e);
    fail(res, 500, 'Failed to set payment_model.');
  } finally {
    c.release();
  }
});

// Historical/unsettled orders needing manual admin review (payment_model
// IS NULL, or delivered-but-not-settled for any reason).
app.get('/api/admin/orders/needs-review', auth, role('admin'), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT o.*, u.full_name AS customer_name, p.business_name
       FROM orders o
       JOIN users u ON u.id=o.customer_id
       JOIN providers p ON p.id=o.provider_id
       WHERE o.settled_at IS NULL
         AND (o.payment_model IS NULL OR o.status='delivered')
       ORDER BY o.created_at ASC`
    );
    ok(res, { orders: r.rows });
  } catch (e) {
    console.error('Needs-review error:', e);
    fail(res, 500, 'Failed to load orders needing review.');
  }
});

/* ============================================================================
   CUSTOMER FINANCE
============================================================================ */

app.get('/api/customers/me/finance', auth, role('customer'), async (req, res) => {
  try {
    const customerId = req.auth.sub;

    const stats = await pool.query(
      `SELECT
         COALESCE(SUM(total) FILTER (WHERE created_at::date = CURRENT_DATE), 0) AS spending_today,
         COALESCE(SUM(total) FILTER (WHERE date_trunc('month', created_at) = date_trunc('month', CURRENT_DATE)), 0) AS spending_month,
         COALESCE(SUM(total) FILTER (WHERE date_trunc('year', created_at) = date_trunc('year', CURRENT_DATE)), 0) AS spending_year,
         COALESCE(SUM(total), 0) AS spending_total,
         COUNT(*) AS total_orders,
         COALESCE(AVG(total), 0) AS average_order_value
       FROM orders
       WHERE customer_id=$1 AND settled_at IS NOT NULL`,
      [customerId]
    );

    const userRow = await pool.query(
      `SELECT public_id FROM users WHERE id=$1`, [customerId]
    );

    const history = await pool.query(
      `SELECT transaction_code, order_id, type, direction, amount, status, description, created_at
       FROM financial_transactions
       WHERE user_id=$1
       ORDER BY created_at DESC
       LIMIT 100`,
      [customerId]
    );

    ok(res, {
      jajigo_customer_id: userRow.rows[0]?.public_id || null,
      spending_today: round2(stats.rows[0].spending_today),
      spending_this_month: round2(stats.rows[0].spending_month),
      spending_this_year: round2(stats.rows[0].spending_year),
      total_spending: round2(stats.rows[0].spending_total),
      total_orders: Number(stats.rows[0].total_orders),
      average_order_value: round2(stats.rows[0].average_order_value),
      transaction_history: history.rows
    });
  } catch (e) {
    console.error('Customer finance error:', e);
    fail(res, 500, 'Failed to load customer finance summary.');
  }
});

/* ============================================================================
   PROVIDER FINANCE / WALLET
============================================================================ */

async function requireOwnProvider(req, res) {
  const pr = await pool.query(
    `SELECT id, public_id FROM providers WHERE user_id=$1`,
    [req.auth.sub]
  );
  if (!pr.rowCount) {
    fail(res, 403, 'No provider profile associated with this account.');
    return null;
  }
  return pr.rows[0];
}

app.get('/api/providers/me/finance', auth, role('provider'), async (req, res) => {
  try {
    const provider = await requireOwnProvider(req, res);
    if (!provider) return;

    const sales = await pool.query(
      `SELECT
         COALESCE(SUM(total) FILTER (WHERE created_at::date = CURRENT_DATE), 0) AS sales_today,
         COALESCE(SUM(total) FILTER (WHERE date_trunc('month', created_at) = date_trunc('month', CURRENT_DATE)), 0) AS sales_month,
         COALESCE(SUM(total), 0) AS sales_total,
         COUNT(*) FILTER (WHERE status='delivered') AS delivered_orders
       FROM orders
       WHERE provider_id=$1 AND settled_at IS NOT NULL`,
      [provider.id]
    );

    const balance = await getProviderBalance(pool, provider.id);

    const commission = await pool.query(
      `SELECT
         COALESCE(SUM(amount) FILTER (WHERE status='owed'), 0) AS commission_owed,
         COALESCE(SUM(amount) FILTER (WHERE status='cleared'), 0) AS commission_cleared
       FROM commission_records WHERE provider_id=$1`,
      [provider.id]
    );

    const pendingPayout = await pool.query(
      `SELECT COALESCE(SUM(amount),0) AS total FROM provider_withdrawals
       WHERE provider_id=$1 AND status IN ('pending','approved')`,
      [provider.id]
    );

    const history = await pool.query(
      `SELECT transaction_code, order_id, type, direction, amount, status, description, created_at
       FROM financial_transactions
       WHERE provider_id=$1
       ORDER BY created_at DESC
       LIMIT 100`,
      [provider.id]
    );

    ok(res, {
      provider_public_id: provider.public_id,
      todays_sales: round2(sales.rows[0].sales_today),
      monthly_sales: round2(sales.rows[0].sales_month),
      total_sales: round2(sales.rows[0].sales_total),
      delivered_orders: Number(sales.rows[0].delivered_orders),
      pending_payout: round2(pendingPayout.rows[0].total),
      available_withdrawal: balance.available_balance,
      jajigo_commission_owed: round2(commission.rows[0].commission_owed),
      commission_cleared: round2(commission.rows[0].commission_cleared),
      transaction_history: history.rows
    });
  } catch (e) {
    console.error('Provider finance error:', e);
    fail(res, 500, 'Failed to load provider finance summary.');
  }
});

/* ============================================================================
   PROVIDER WITHDRAWALS
============================================================================ */

app.post('/api/providers/me/withdrawals', auth, role('provider'), async (req, res) => {
  const c = await pool.connect();
  try {
    const provider = await requireOwnProvider(req, res);
    if (!provider) { c.release(); return; }

    const amount = nonNegativeNumber(req.body.amount);
    if (!amount || amount <= 0) {
      c.release();
      return fail(res, 400, 'Invalid withdrawal amount.');
    }

    await c.query('BEGIN');
    // Serializes all balance checks + withdrawal requests for this provider,
    // so two concurrent requests can never both pass the balance check
    // against the same available money.
    await c.query('SELECT pg_advisory_xact_lock($1)', [provider.id]);

    const balance = await getProviderBalance(c, provider.id);
    const requested = round2(amount);

    if (requested > balance.available_balance) {
      await c.query('ROLLBACK');
      return fail(res, 400, `Requested amount exceeds available balance (₦${balance.available_balance}).`);
    }

    const w = await c.query(
      `INSERT INTO provider_withdrawals (provider_id, amount, status, requested_by)
       VALUES ($1,$2,'pending',$3) RETURNING *`,
      [provider.id, requested, req.auth.sub]
    );

    await writeAuditLog(c, {
      action: 'withdrawal_requested', performedBy: req.auth.sub,
      providerId: provider.id, referenceTable: 'provider_withdrawals',
      referenceId: w.rows[0].id, amount: requested,
      previousStatus: null, newStatus: 'pending'
    });

    await c.query('COMMIT');
    ok(res, { message: 'Withdrawal requested successfully.', withdrawal: w.rows[0] });
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Withdrawal request error:', e);
    fail(res, 500, 'Failed to request withdrawal.');
  } finally {
    c.release();
  }
});

app.get('/api/providers/me/withdrawals', auth, role('provider'), async (req, res) => {
  try {
    const provider = await requireOwnProvider(req, res);
    if (!provider) return;

    const r = await pool.query(
      `SELECT * FROM provider_withdrawals WHERE provider_id=$1 ORDER BY created_at DESC`,
      [provider.id]
    );
    ok(res, { withdrawals: r.rows });
  } catch (e) {
    console.error('Withdrawal history error:', e);
    fail(res, 500, 'Failed to load withdrawal history.');
  }
});

/* ============================================================================
   ADMIN PAYOUTS (withdrawal approve / reject / pay)
============================================================================ */

app.get('/api/admin/withdrawals', auth, role('admin'), async (req, res) => {
  try {
    const status = req.query.status ? String(req.query.status) : null;
    const r = await pool.query(
      `SELECT w.*, p.business_name, p.public_id AS provider_public_id
       FROM provider_withdrawals w JOIN providers p ON p.id=w.provider_id
       WHERE $1::text IS NULL OR w.status=$1
       ORDER BY CASE WHEN w.status='pending' THEN 0 ELSE 1 END, w.created_at DESC`,
      [status]
    );
    ok(res, { withdrawals: r.rows });
  } catch (e) {
    console.error('Admin withdrawals list error:', e);
    fail(res, 500, 'Failed to load withdrawals.');
  }
});

app.patch('/api/admin/withdrawals/:id/approve', auth, role('admin'), async (req, res) => {
  const c = await pool.connect();
  try {
    const id = positiveInt(req.params.id);
    if (!id) return fail(res, 400, 'Invalid withdrawal ID.');

    await c.query('BEGIN');

    // Atomic conditional UPDATE: only one caller can ever move a given
    // withdrawal from pending -> approved. A retried/duplicate request
    // simply affects 0 rows.
    const u = await c.query(
      `UPDATE provider_withdrawals
       SET status='approved', reviewed_by=$1, updated_at=NOW(), admin_note=COALESCE($2,admin_note)
       WHERE id=$3 AND status='pending'
       RETURNING *`,
      [req.auth.sub, req.body.note || null, id]
    );

    if (!u.rowCount) {
      await c.query('ROLLBACK');
      return fail(res, 409, 'Withdrawal is not in pending status (already approved/rejected/paid, or does not exist).');
    }

    await writeAuditLog(c, {
      action: 'withdrawal_approved', performedBy: req.auth.sub,
      providerId: u.rows[0].provider_id, referenceTable: 'provider_withdrawals',
      referenceId: id, amount: u.rows[0].amount,
      previousStatus: 'pending', newStatus: 'approved'
    });

    await c.query('COMMIT');
    ok(res, { message: 'Withdrawal approved.', withdrawal: u.rows[0] });
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Withdrawal approve error:', e);
    fail(res, 500, 'Failed to approve withdrawal.');
  } finally {
    c.release();
  }
});

app.patch('/api/admin/withdrawals/:id/reject', auth, role('admin'), async (req, res) => {
  const c = await pool.connect();
  try {
    const id = positiveInt(req.params.id);
    if (!id) return fail(res, 400, 'Invalid withdrawal ID.');

    await c.query('BEGIN');

    const u = await c.query(
      `UPDATE provider_withdrawals
       SET status='rejected', reviewed_by=$1, updated_at=NOW(), admin_note=COALESCE($2,admin_note)
       WHERE id=$3 AND status IN ('pending','approved')
       RETURNING *`,
      [req.auth.sub, req.body.note || null, id]
    );

    if (!u.rowCount) {
      await c.query('ROLLBACK');
      return fail(res, 409, 'Withdrawal cannot be rejected from its current status.');
    }

    await writeAuditLog(c, {
      action: 'withdrawal_rejected', performedBy: req.auth.sub,
      providerId: u.rows[0].provider_id, referenceTable: 'provider_withdrawals',
      referenceId: id, amount: u.rows[0].amount,
      previousStatus: 'pending_or_approved', newStatus: 'rejected'
    });

    await c.query('COMMIT');
    ok(res, { message: 'Withdrawal rejected.', withdrawal: u.rows[0] });
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Withdrawal reject error:', e);
    fail(res, 500, 'Failed to reject withdrawal.');
  } finally {
    c.release();
  }
});

app.patch('/api/admin/withdrawals/:id/pay', auth, role('admin'), async (req, res) => {
  const c = await pool.connect();
  try {
    const id = positiveInt(req.params.id);
    if (!id) return fail(res, 400, 'Invalid withdrawal ID.');

    await c.query('BEGIN');

    // Requires 'approved' first — pay can never fire straight from pending.
    // The WHERE status='approved' guard makes this idempotent: a duplicate
    // call (double-click, retried webhook, etc.) affects 0 rows the second
    // time because status is already 'paid'.
    const u = await c.query(
      `UPDATE provider_withdrawals
       SET status='paid', paid_at=NOW(), reviewed_by=$1, updated_at=NOW()
       WHERE id=$2 AND status='approved'
       RETURNING *`,
      [req.auth.sub, id]
    );

    if (!u.rowCount) {
      await c.query('ROLLBACK');
      return fail(res, 409, 'Withdrawal must be in approved status to be paid (or has already been paid).');
    }

    const withdrawal = u.rows[0];

    await insertFinancialTransaction(c, {
      providerId: withdrawal.provider_id,
      type: 'provider_payout', direction: 'debit', amount: round2(withdrawal.amount),
      description: `Payout for withdrawal request #${withdrawal.id}`,
      reference: `WD-${withdrawal.id}`, createdBy: req.auth.sub
    });

    await writeAuditLog(c, {
      action: 'withdrawal_paid', performedBy: req.auth.sub,
      providerId: withdrawal.provider_id, referenceTable: 'provider_withdrawals',
      referenceId: id, amount: withdrawal.amount,
      previousStatus: 'approved', newStatus: 'paid'
    });

    await c.query('COMMIT');
    ok(res, { message: 'Withdrawal paid.', withdrawal });
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Withdrawal pay error:', e);
    fail(res, 500, 'Failed to pay withdrawal.');
  } finally {
    c.release();
  }
});

/* ============================================================================
   ADMIN COMMISSION CLEARING (Model B)
============================================================================ */

app.get('/api/admin/commission-records', auth, role('admin'), async (req, res) => {
  try {
    const status = req.query.status ? String(req.query.status) : null;
    const r = await pool.query(
      `SELECT cr.*, p.business_name, p.public_id AS provider_public_id, o.order_code
       FROM commission_records cr
       JOIN providers p ON p.id=cr.provider_id
       JOIN orders o ON o.id=cr.order_id
       WHERE $1::text IS NULL OR cr.status=$1
       ORDER BY CASE WHEN cr.status='owed' THEN 0 ELSE 1 END, cr.created_at DESC`,
      [status]
    );
    ok(res, { commission_records: r.rows });
  } catch (e) {
    console.error('Commission records list error:', e);
    fail(res, 500, 'Failed to load commission records.');
  }
});

app.patch('/api/admin/commission-records/:id/clear', auth, role('admin'), async (req, res) => {
  const c = await pool.connect();
  try {
    const id = positiveInt(req.params.id);
    if (!id) return fail(res, 400, 'Invalid commission record ID.');

    await c.query('BEGIN');

    // Idempotent: only clears if currently 'owed'. A duplicate clear
    // request affects 0 rows and creates no duplicate ledger entry.
    const u = await c.query(
      `UPDATE commission_records
       SET status='cleared', cleared_by=$1, cleared_at=NOW(), updated_at=NOW(),
           admin_note=COALESCE($2,admin_note)
       WHERE id=$3 AND status='owed'
       RETURNING *`,
      [req.auth.sub, req.body.note || null, id]
    );

    if (!u.rowCount) {
      await c.query('ROLLBACK');
      return fail(res, 409, 'Commission record is not in owed status (already cleared, or does not exist).');
    }

    const record = u.rows[0];

    await insertFinancialTransaction(c, {
      providerId: record.provider_id, orderId: record.order_id,
      type: 'commission_payment', direction: 'credit', amount: round2(record.amount),
      status: 'completed',
      description: `Commission cleared for order (commission_records #${record.id})`,
      reference: `CR-${record.id}`, createdBy: req.auth.sub
    });

    await writeAuditLog(c, {
      action: 'commission_cleared', performedBy: req.auth.sub,
      providerId: record.provider_id, orderId: record.order_id,
      referenceTable: 'commission_records', referenceId: id,
      amount: record.amount, previousStatus: 'owed', newStatus: 'cleared'
    });

    await c.query('COMMIT');
    ok(res, { message: 'Commission marked as cleared.', commission_record: record });
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Commission clear error:', e);
    fail(res, 500, 'Failed to clear commission record.');
  } finally {
    c.release();
  }
});

/* ============================================================================
   AUDIT LOG (read-only API — writes only ever happen via writeAuditLog()
   inside the financial routes above, in the same transaction as the change)
============================================================================ */

app.get('/api/admin/audit-log', auth, role('admin'), async (req, res) => {
  try {
    const providerId = req.query.provider_id ? positiveInt(req.query.provider_id) : null;
    const orderId = req.query.order_id ? positiveInt(req.query.order_id) : null;

    const r = await pool.query(
      `SELECT * FROM financial_audit_log
       WHERE ($1::bigint IS NULL OR provider_id=$1)
         AND ($2::bigint IS NULL OR order_id=$2)
       ORDER BY created_at DESC
       LIMIT 200`,
      [providerId, orderId]
    );
    ok(res, { audit_log: r.rows });
  } catch (e) {
    console.error('Audit log error:', e);
    fail(res, 500, 'Failed to load audit log.');
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
