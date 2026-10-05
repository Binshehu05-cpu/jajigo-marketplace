import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { randomBytes, randomInt } from 'node:crypto';
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

function optionalNonNegativeNumber(v) {
  if (v === undefined || v === null || v === '') return null;
  return nonNegativeNumber(v);
}

function validTimeHHMM(v) {
  const s = String(v || '').trim();
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(s)) return null;
  return s;
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
    user.customer_code = user.public_id || null;
    user.jajigo_customer_id = user.public_id || null;
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
    const identifier = String(req.body.email || req.body.phone || '').trim();
    const email = identifier.toLowerCase();
    const password = String(req.body.password || '');

    if (!identifier || !password) {
      return fail(res, 400, 'Email/phone and password are required.');
    }

    const result = await pool.query(
      `SELECT id,phone,full_name,email,password_hash,avatar_url,role,status,public_id
       FROM users WHERE LOWER(email)=LOWER($1) OR phone=$2
       ORDER BY CASE WHEN LOWER(email)=LOWER($1) THEN 0 ELSE 1 END
       LIMIT 1`,
      [email, normPhone(identifier)]
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
    if (user.role === 'provider') {
      const pr = await pool.query(
        `SELECT id, public_id, business_name, status FROM providers WHERE user_id=$1`,
        [user.id]
      );
      if (pr.rowCount) {
        user.provider_id = pr.rows[0].id;
        user.provider_public_id = pr.rows[0].public_id || null;
        user.provider_code = pr.rows[0].public_id || null;
        user.jajigo_provider_id = pr.rows[0].public_id || null;
        user.business_name = pr.rows[0].business_name;
        user.provider_status = pr.rows[0].status;
      }
    } else if (user.role === 'customer') {
      user.customer_code = user.public_id || null;
      user.jajigo_customer_id = user.public_id || null;
    }

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

/* ============================================================================
   FORGOT / RESET PASSWORD
   Flow: user enters email -> we email a 6-digit code (valid 15 min, max 5
   wrong attempts, stored only as a bcrypt hash) -> user enters code + new
   password. The forgot-password route always gives the same answer whether
   or not the email exists, so it can't be used to discover accounts.

   Email: set RESEND_API_KEY and MAIL_FROM (e.g. "JajiGo <no-reply@yourdomain.com>")
   in your Render environment. Without them, no email is sent. For testing
   only, set RESET_CODE_LOG=1 to print the code in the server log.
============================================================================ */

const RESET_CODE_TTL_MIN = 15;
const RESET_MAX_ATTEMPTS = 5;
const RESET_RESEND_COOLDOWN_SEC = 60;

async function ensurePasswordResetTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL,
      code_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      attempts INT NOT NULL DEFAULT 0,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets (user_id, created_at DESC)`
  );
}

async function sendResetEmail(to, name, code) {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.MAIL_FROM;
  if (!key || !from) {
    console.warn('[password-reset] RESEND_API_KEY / MAIL_FROM not set — email NOT sent.');
    if (process.env.RESET_CODE_LOG === '1') {
      console.log(`[password-reset] code for ${to}: ${code}`);
    }
    return false;
  }
  const safeName = String(name || 'there').replace(/[<>&"]/g, '');
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from,
      to: [to],
      subject: 'Your JajiGo password reset code',
      html: `<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:20px">
        <h2 style="color:#0e7a4f;margin:0 0 12px">JajiGo</h2>
        <p>Hi ${safeName},</p>
        <p>Use this code to reset your password:</p>
        <p style="font-size:32px;font-weight:700;letter-spacing:8px;margin:16px 0">${code}</p>
        <p>It expires in ${RESET_CODE_TTL_MIN} minutes. If you didn't ask for this, you can ignore this email — your password won't change.</p>
      </div>`
    })
  });
  if (!r.ok) {
    console.error('[password-reset] Email provider error:', r.status, await r.text().catch(() => ''));
    return false;
  }
  return true;
}

app.post('/api/auth/forgot-password', async (req, res) => {
  const generic = () => ok(res, {
    message: `If an account exists for that email, a 6-digit code has been sent. It expires in ${RESET_CODE_TTL_MIN} minutes.`
  });
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return fail(res, 400, 'Please enter a valid email address.');
    }

    const u = await pool.query(
      `SELECT id,full_name,email,status FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1`,
      [email]
    );
    if (!u.rowCount || u.rows[0].status !== 'active') return generic();
    const user = u.rows[0];

    // Cooldown: silently ignore repeat requests inside the window.
    const recent = await pool.query(
      `SELECT 1 FROM password_resets
       WHERE user_id=$1 AND created_at > NOW() - ($2 || ' seconds')::interval LIMIT 1`,
      [user.id, String(RESET_RESEND_COOLDOWN_SEC)]
    );
    if (recent.rowCount) return generic();

    const code = String(randomInt(0, 1000000)).padStart(6, '0');
    const codeHash = await bcrypt.hash(code, 10);

    const c = await pool.connect();
    try {
      await c.query('BEGIN');
      await c.query(`UPDATE password_resets SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL`, [user.id]);
      await c.query(
        `INSERT INTO password_resets (user_id,code_hash,expires_at)
         VALUES ($1,$2,NOW() + ($3 || ' minutes')::interval)`,
        [user.id, codeHash, String(RESET_CODE_TTL_MIN)]
      );
      await c.query('COMMIT');
    } catch (e) {
      try { await c.query('ROLLBACK'); } catch {}
      throw e;
    } finally {
      c.release();
    }

    try {
      await sendResetEmail(user.email, user.full_name, code);
    } catch (e) {
      console.error('[password-reset] Email send failed:', e);
    }
    return generic();
  } catch (e) {
    console.error('Forgot password error:', e);
    fail(res, 500, 'Could not start password reset. Please try again.');
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const BAD_CODE = 'That code is wrong or has expired. Please request a new one.';
  const c = await pool.connect();
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const code = String(req.body.code || '').replace(/\D/g, '');
    const password = String(req.body.password || '');

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res, 400, 'Please enter a valid email address.');
    if (!/^\d{6}$/.test(code)) return fail(res, 400, 'Please enter the 6-digit code from your email.');
    if (password.length < 6) return fail(res, 400, 'Password must be at least 6 characters.');

    await c.query('BEGIN');

    const u = await c.query(
      `SELECT id,status FROM users WHERE LOWER(email)=LOWER($1) LIMIT 1`, [email]
    );
    if (!u.rowCount || u.rows[0].status !== 'active') {
      await c.query('ROLLBACK');
      return fail(res, 400, BAD_CODE);
    }
    const userId = u.rows[0].id;

    const pr = await c.query(
      `SELECT id,code_hash,attempts FROM password_resets
       WHERE user_id=$1 AND used_at IS NULL AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1 FOR UPDATE`,
      [userId]
    );
    if (!pr.rowCount || pr.rows[0].attempts >= RESET_MAX_ATTEMPTS) {
      await c.query('ROLLBACK');
      return fail(res, 400, BAD_CODE);
    }
    const reset = pr.rows[0];

    const match = await bcrypt.compare(code, reset.code_hash);
    if (!match) {
      await c.query(`UPDATE password_resets SET attempts=attempts+1 WHERE id=$1`, [reset.id]);
      await c.query('COMMIT'); // keep the failed-attempt count
      return fail(res, 400, BAD_CODE);
    }

    const hash = await bcrypt.hash(password, 12);
    await c.query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [hash, userId]);
    await c.query(`UPDATE password_resets SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL`, [userId]);
    await c.query('COMMIT');

    ok(res, { message: 'Password changed. You can now log in with your new password.' });
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Reset password error:', e);
    fail(res, 500, 'Could not reset password. Please try again.');
  } finally {
    c.release();
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

/* ========================= PROVIDER REGISTRATION ========================= */
app.post('/api/providers/register', async (req, res) => {
  const c = await pool.connect();
  try {
    const b = req.body || {};
    const phone = normPhone(b.phone);
    const email = String(b.email || '').trim().toLowerCase();
    const name = String(b.name || '').trim();
    const business = String(b.business || '').trim();
    const address = String(b.address || '').trim();
    const area = String(b.area || '').trim();
    const whatsapp = normPhone(b.whatsapp || phone);
    const description = String(b.desc || b.description || '').trim();
    const password = String(b.password || '');
    const passwordConfirm = String(b.password_confirm || '');
    const categoryId = positiveInt(b.category_id);
    const businessType = String(b.business_type || '').trim() || null;
    const businessTypeCustom = String(b.business_type_custom || '').trim() || null;
    const openingTime = b.opening_time ? String(b.opening_time).trim() : null;
    const closingTime = b.closing_time ? String(b.closing_time).trim() : null;
    const deliveryMode = String(b.delivery_mode || 'provider_delivery').trim();
    const logoUrl = String(b.logo_url || '').trim() || null;
    const lat = b.lat === undefined || b.lat === null || b.lat === '' ? null : Number(b.lat);
    const lng = b.lng === undefined || b.lng === null || b.lng === '' ? null : Number(b.lng);

    if (name.length < 2) return fail(res, 400, 'Full name is required.');
    if (!/^0\d{10}$/.test(phone)) return fail(res, 400, 'Invalid Nigerian phone number.');
    if (!/^0\d{10}$/.test(whatsapp)) return fail(res, 400, 'Invalid Nigerian WhatsApp number.');
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res, 400, 'Please enter a valid email address.');
    if (password.length < 6) return fail(res, 400, 'Password must be at least 6 characters.');
    if (password !== passwordConfirm) return fail(res, 400, 'Passwords do not match.');
    if (business.length < 2) return fail(res, 400, 'Business name is required.');
    if (!address) return fail(res, 400, 'Business address is required.');
    if (!area) return fail(res, 400, 'Business area is required.');
    if (!categoryId) return fail(res, 400, 'Business category is required.');
    if (!['provider_delivery','customer_pickup','both'].includes(deliveryMode)) return fail(res, 400, 'Invalid delivery mode.');
    if (b.lat !== undefined && b.lat !== null && b.lat !== '' && !Number.isFinite(lat)) return fail(res, 400, 'Invalid latitude.');
    if (b.lng !== undefined && b.lng !== null && b.lng !== '' && !Number.isFinite(lng)) return fail(res, 400, 'Invalid longitude.');

    await c.query('BEGIN');
    const exists = await c.query(
      'SELECT id FROM users WHERE phone=$1 OR LOWER(email)=LOWER($2)',
      [phone, email]
    );
    if (exists.rowCount) {
      await c.query('ROLLBACK');
      return fail(res, 409, 'Phone number or email already has an account.');
    }

    const hash = await bcrypt.hash(password, 12);
    const userResult = await c.query(
      `INSERT INTO users (phone,full_name,email,password_hash,role,status)
       VALUES ($1,$2,$3,$4,'provider','active')
       RETURNING id,phone,full_name,email,avatar_url,role,status,public_id`,
      [phone, name, email, hash]
    );
    const user = userResult.rows[0];

    const providerResult = await c.query(
      `INSERT INTO providers
       (user_id,business_name,category_id,application_description,address,area,whatsapp,
        business_type,business_type_custom,opening_time,closing_time,delivery_mode,logo_url,lat,lng,status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'pending')
       RETURNING *`,
      [user.id,business,categoryId,description,address,area,whatsapp,businessType,businessTypeCustom,
       openingTime,closingTime,deliveryMode,logoUrl,lat,lng]
    );
    const provider = providerResult.rows[0];
    provider.provider_code = provider.public_id || null;
    provider.jajigo_provider_id = provider.public_id || null;
    provider.provider_public_id = provider.public_id || null;
    user.provider_id = provider.id;
    user.provider_code = provider.public_id || null;
    user.jajigo_provider_id = provider.public_id || null;

    await c.query('COMMIT');
    ok(res, {
      message: 'Provider application submitted successfully.',
      token: tokenFor(user),
      user,
      provider,
      pending: true,
      remoteProvider: true
    });
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Provider registration error:', e);
    if (e.code === '23505') return fail(res, 409, 'Phone number, email, or provider record already exists.');
    fail(res, 500, 'Provider registration failed.');
  } finally {
    c.release();
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
        req.auth.role === 'admin'
          ? `SELECT p.*,p.public_id AS provider_public_id,u.phone AS user_phone,u.full_name AS owner_name,u.email AS owner_email
             FROM providers p JOIN users u ON u.id=p.user_id
             ORDER BY p.id`
          : req.auth.role === 'provider'
            ? `SELECT p.*,p.public_id AS provider_public_id,u.phone AS user_phone,u.full_name AS owner_name,u.email AS owner_email
               FROM providers p JOIN users u ON u.id=p.user_id
               WHERE p.user_id=$1
               UNION ALL
               SELECT p.*,p.public_id AS provider_public_id,u.phone AS user_phone,u.full_name AS owner_name,u.email AS owner_email
               FROM providers p JOIN users u ON u.id=p.user_id
               WHERE p.status='approved' AND p.user_id<>$1
               ORDER BY id`
            : `SELECT p.*,p.public_id AS provider_public_id,u.phone AS user_phone,u.full_name AS owner_name,u.email AS owner_email
               FROM providers p JOIN users u ON u.id=p.user_id
               WHERE p.status='approved' ORDER BY p.id`,
        req.auth.role === 'provider' ? [req.auth.sub] : []
      ),
      orders,
      pool.query(
        `SELECT p.*,pr.business_name
         FROM products p JOIN providers pr ON pr.id=p.provider_id
         WHERE p.is_available=true AND pr.status='approved'
         ORDER BY p.id DESC`
      )
    ]);

    const customersOut = c.rows.map(x => ({
      ...x,
      customer_code: x.customer_code || x.public_id || null,
      jajigo_customer_id: x.jajigo_customer_id || x.customer_code || x.public_id || null
    }));
    const providersOut = v.rows.map(x => ({
      ...x,
      provider_code: x.provider_code || x.provider_public_id || x.public_id || null,
      jajigo_provider_id: x.jajigo_provider_id || x.provider_public_id || x.public_id || null
    }));

    ok(res, {
      customers: customersOut,
      providers: providersOut,
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

/* =========================== MORNING RUSH ============================ */

app.get('/api/providers/me/morning-rush', auth, role('provider'), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id,public_id,business_name,morning_rush_enabled,morning_rush_paused,
              morning_open_time,morning_close_time,morning_prep_minutes,
              morning_packaging_fee,morning_max_orders,
              platform_payment_enabled,provider_payment_enabled
       FROM providers WHERE user_id=$1`,
      [req.auth.sub]
    );
    if (!r.rowCount) return fail(res,404,'Provider profile not found.');
    ok(res,{morning_rush:r.rows[0]});
  } catch (e) {
    console.error('Morning Rush settings error:',e);
    fail(res,500,'Failed to load Morning Rush settings.');
  }
});

app.patch('/api/providers/me/morning-rush', auth, role('provider'), async (req, res) => {
  try {
    const b=req.body||{};
    const enabled=b.morning_rush_enabled===undefined?null:Boolean(b.morning_rush_enabled);
    const paused=b.morning_rush_paused===undefined?null:Boolean(b.morning_rush_paused);
    const open=b.morning_open_time===undefined?null:validTimeHHMM(b.morning_open_time);
    const close=b.morning_close_time===undefined?null:validTimeHHMM(b.morning_close_time);
    const prep=b.morning_prep_minutes===undefined?null:positiveInt(b.morning_prep_minutes);
    const packaging=b.morning_packaging_fee===undefined?null:nonNegativeNumber(b.morning_packaging_fee);
    const maxOrdersProvided=b.morning_max_orders!==undefined;
    const maxOrders=b.morning_max_orders===null||b.morning_max_orders===''?null:positiveInt(b.morning_max_orders);
    const platform=b.platform_payment_enabled===undefined?null:Boolean(b.platform_payment_enabled);
    const providerPay=b.provider_payment_enabled===undefined?null:Boolean(b.provider_payment_enabled);

    if (b.morning_open_time!==undefined && !open) return fail(res,400,'morning_open_time must use HH:MM.');
    if (b.morning_close_time!==undefined && !close) return fail(res,400,'morning_close_time must use HH:MM.');
    if (open && close && open>=close) return fail(res,400,'Morning Rush opening time must be before closing time.');
    if (b.morning_prep_minutes!==undefined && !prep) return fail(res,400,'morning_prep_minutes must be a positive integer.');
    if (b.morning_packaging_fee!==undefined && packaging===null) return fail(res,400,'Invalid morning packaging fee.');
    if (b.morning_max_orders!==undefined && b.morning_max_orders!==null && b.morning_max_orders!=='' && !maxOrders) return fail(res,400,'morning_max_orders must be a positive integer or null.');

    const r=await pool.query(
      `UPDATE providers SET
        morning_rush_enabled=COALESCE($1,morning_rush_enabled),
        morning_rush_paused=COALESCE($2,morning_rush_paused),
        morning_open_time=COALESCE($3::time,morning_open_time),
        morning_close_time=COALESCE($4::time,morning_close_time),
        morning_prep_minutes=COALESCE($5,morning_prep_minutes),
        morning_packaging_fee=COALESCE($6,morning_packaging_fee),
        morning_max_orders=CASE WHEN $7 THEN $8 ELSE morning_max_orders END,
        platform_payment_enabled=COALESCE($9,platform_payment_enabled),
        provider_payment_enabled=COALESCE($10,provider_payment_enabled),
        updated_at=NOW()
       WHERE user_id=$11 RETURNING *`,
      [enabled,paused,open,close,prep,packaging,maxOrdersProvided,maxOrders,platform,providerPay,req.auth.sub]
    );
    if(!r.rowCount) return fail(res,404,'Provider profile not found.');
    ok(res,{message:'Morning Rush settings updated.',provider:r.rows[0]});
  } catch(e){
    console.error('Update Morning Rush settings error:',e);
    fail(res,500,'Failed to update Morning Rush settings.');
  }
});

app.get('/api/morning-rush', async (req,res)=>{
  try{
    const r=await pool.query(`
      SELECT p.*,pr.business_name,pr.public_id AS provider_public_id,
             pr.morning_open_time,pr.morning_close_time,pr.morning_prep_minutes,
             pr.morning_packaging_fee,pr.morning_max_orders,
             pr.platform_payment_enabled,pr.provider_payment_enabled,
             COALESCE((SELECT COUNT(*) FROM orders o
               WHERE o.provider_id=pr.id AND o.order_type='breakfast'
                 AND o.created_at::date=(CURRENT_TIMESTAMP AT TIME ZONE 'Africa/Lagos')::date
                 AND o.status NOT IN ('cancelled','rejected')),0) AS morning_orders_today
      FROM products p JOIN providers pr ON pr.id=p.provider_id
      WHERE p.is_available=true AND p.is_breakfast=true AND pr.status='approved'
        AND pr.morning_rush_enabled=true AND pr.morning_rush_paused=false
        AND pr.morning_open_time IS NOT NULL AND pr.morning_close_time IS NOT NULL
        AND (CURRENT_TIMESTAMP AT TIME ZONE 'Africa/Lagos')::time >= pr.morning_open_time
        AND (CURRENT_TIMESTAMP AT TIME ZONE 'Africa/Lagos')::time < pr.morning_close_time
        AND (p.stock_qty IS NULL OR p.stock_qty > 0)
      ORDER BY p.id DESC`);
    ok(res,{morning_rush:r.rows});
  }catch(e){
    console.error('Morning Rush listing error:',e);
    fail(res,500,'Failed to load Morning Rush.');
  }
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
    const stockQty = optionalNonNegativeNumber(b.stock_qty);
    const isBreakfast = Boolean(b.is_breakfast);
    const photo = String(b.photo || '').trim();

    if (!name) return fail(res, 400, 'Product name is required.');
    if (price === null) return fail(res, 400, 'Invalid product price.');
    if (b.stock_qty !== undefined && b.stock_qty !== null && b.stock_qty !== '' && stockQty === null) return fail(res, 400, 'Invalid stock quantity.');

    const pr = await pool.query(
      `SELECT id,category_id FROM providers
       WHERE user_id=$1 AND status='approved'`,
      [req.auth.sub]
    );
    if (!pr.rowCount) return fail(res, 403, 'Provider not approved.');

    const p = await pool.query(
      `INSERT INTO products
       (provider_id,category_id,name,description,price,stock_qty,photo,is_available,is_breakfast)
       VALUES ($1,$2,$3,$4,$5,$6,$7,true,$8) RETURNING *`,
      [pr.rows[0].id,pr.rows[0].category_id,name,description,price,stockQty,photo,isBreakfast]
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
    const stockWasProvided = b.stock_qty !== undefined;
    const stockQty = stockWasProvided ? optionalNonNegativeNumber(b.stock_qty) : null;

    if (price === null && b.price !== undefined) return fail(res,400,'Invalid product price.');
    if (stockWasProvided && b.stock_qty !== null && b.stock_qty !== '' && stockQty === null) return fail(res,400,'Invalid stock quantity.');

    const u = await pool.query(
      `UPDATE products SET
         is_breakfast=COALESCE($1,is_breakfast),
         name=COALESCE(NULLIF($2,''),name),
         description=COALESCE($3,description),
         price=COALESCE($4,price),
         stock_qty=CASE WHEN $5 THEN $6 ELSE stock_qty END,
         photo=COALESCE($7,photo),
         is_available=COALESCE($8,is_available)
       WHERE id=$9 RETURNING *`,
      [
        b.is_breakfast === undefined ? null : Boolean(b.is_breakfast),
        b.name === undefined ? null : String(b.name).trim(),
        b.description === undefined ? null : String(b.description).trim(),
        price,
        stockWasProvided,
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
      return fail(res,400,'payment_model is required and must be either "platform_collected" or "provider_collected".');
    }

    const providerId = positiveInt(b.provider_id);
    if (!providerId) return fail(res,400,'Invalid provider.');

    const orderType = String(b.order_type || 'standard').trim().toLowerCase();
    if (!['standard','breakfast'].includes(orderType)) return fail(res,400,'Invalid order type.');

    const rawItems = b.items.map(i => ({product_id:positiveInt(i.product_id),qty:positiveInt(i.qty)}));
    if (rawItems.some(i => !i.product_id || !i.qty)) return fail(res,400,'Invalid order item.');

    const deliveryMode = String(b.delivery_mode || 'provider_delivery');
    if (!['provider_delivery','customer_pickup'].includes(deliveryMode)) return fail(res,400,'Invalid delivery mode.');

    const address = b.address ? String(b.address).trim() : null;
    const customerPhone = b.customer_phone ? normPhone(b.customer_phone) : null;
    const paymentMethod = String(b.payment_method || '').trim() || null;

    await c.query('BEGIN');

    const providerRow = await c.query(
      `SELECT id,status,delivery_fee,morning_rush_enabled,morning_rush_paused,
              morning_open_time,morning_close_time,morning_prep_minutes,
              morning_packaging_fee,morning_max_orders,
              platform_payment_enabled,provider_payment_enabled
       FROM providers WHERE id=$1 FOR UPDATE`, [providerId]
    );
    if (!providerRow.rowCount || providerRow.rows[0].status !== 'approved') {
      await c.query('ROLLBACK');
      return fail(res,400,'Provider not available.');
    }

    const provider = providerRow.rows[0];
    if (paymentModel === 'platform_collected' && provider.platform_payment_enabled === false) {
      await c.query('ROLLBACK');
      return fail(res,400,'This provider does not currently accept JajiGo platform payment.');
    }
    if (paymentModel === 'provider_collected' && provider.provider_payment_enabled === false) {
      await c.query('ROLLBACK');
      return fail(res,400,'This provider does not currently accept direct provider payment.');
    }

    if (orderType === 'breakfast') {
      const morning = await c.query(
        `SELECT
           ($1 AND NOT $2 AND $3 IS NOT NULL AND $4 IS NOT NULL
            AND (CURRENT_TIMESTAMP AT TIME ZONE 'Africa/Lagos')::time >= $3
            AND (CURRENT_TIMESTAMP AT TIME ZONE 'Africa/Lagos')::time < $4) AS available,
           COALESCE((SELECT COUNT(*) FROM orders o
             WHERE o.provider_id=$5 AND o.order_type='breakfast'
               AND (o.created_at AT TIME ZONE 'Africa/Lagos')::date=(CURRENT_TIMESTAMP AT TIME ZONE 'Africa/Lagos')::date
               AND o.status NOT IN ('cancelled','rejected')),0) AS orders_today`,
        [provider.morning_rush_enabled,provider.morning_rush_paused,provider.morning_open_time,provider.morning_close_time,providerId]
      );
      if (!morning.rows[0].available) {
        await c.query('ROLLBACK');
        return fail(res,400,'Morning Rush is closed or unavailable right now.');
      }
      if (provider.morning_max_orders !== null && Number(morning.rows[0].orders_today) >= Number(provider.morning_max_orders)) {
        await c.query('ROLLBACK');
        return fail(res,400,'This provider has reached its Morning Rush order limit for today.');
      }
    }

    const ids = rawItems.map(x=>x.product_id);
    const pr = await c.query(
      `SELECT id,name,price,stock_qty,is_available,is_breakfast,provider_id,photo
       FROM products WHERE id=ANY($1::bigint[]) FOR UPDATE`, [ids]
    );
    const map = new Map(pr.rows.map(p=>[String(p.id),p]));

    if (!rawItems.every(i => {
      const p=map.get(String(i.product_id));
      return p && p.is_available && (p.stock_qty === null || Number(i.qty) <= Number(p.stock_qty));
    })) {
      await c.query('ROLLBACK');
      return fail(res,400,'Some items unavailable or out of stock.');
    }

    if (!rawItems.every(i=>Number(map.get(String(i.product_id)).provider_id)===providerId)) {
      await c.query('ROLLBACK');
      return fail(res,400,'All items must be from the same provider.');
    }

    if (orderType === 'breakfast' && !rawItems.every(i=>map.get(String(i.product_id)).is_breakfast === true)) {
      await c.query('ROLLBACK');
      return fail(res,400,'Morning Rush orders can contain breakfast items only.');
    }
    if (orderType === 'standard' && rawItems.some(i=>map.get(String(i.product_id)).is_breakfast === true)) {
      await c.query('ROLLBACK');
      return fail(res,400,'Breakfast items must be ordered through Morning Rush.');
    }

    const lineItems = rawItems.map(i=>{
      const p=map.get(String(i.product_id));
      const unitPrice=round2(p.price);
      return {product_id:p.id,name:p.name,photo:p.photo,unit_price:unitPrice,qty:i.qty,line_total:round2(unitPrice*i.qty)};
    });

    const subtotal=round2(lineItems.reduce((sum,i)=>sum+i.line_total,0));
    const deliveryFee=deliveryMode==='customer_pickup' ? 0 : round2(Math.max(0,Number(provider.delivery_fee||0)));
    const packagingFee=orderType==='breakfast' ? round2(Math.max(0,Number(provider.morning_packaging_fee||0))) : 0;
    const total=round2(subtotal+packagingFee+deliveryFee);

    // Commission is always based on food subtotal. Packaging and delivery are not commissioned.
    const commission=round2(subtotal*COMMISSION_RATE/100);
    const providerNet=round2(total-commission);
    const verificationCode=String(100000+(randomBytes(4).readUInt32BE(0)%900000));

    const o=await c.query(
      `INSERT INTO orders
       (customer_id,provider_id,status,payment_method,payment_status,
        delivery_mode,address,customer_phone,subtotal,packaging_fee,delivery_fee,total,
        commission,provider_net,items,payment_model,order_type,verification_code,
        verification_verified,verified_at)
       VALUES ($1,$2,'pending',$3,'pending',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,false,NULL)
       RETURNING *`,
      [req.auth.sub,providerId,paymentMethod,deliveryMode,address,customerPhone,
       subtotal,packagingFee,deliveryFee,total,commission,providerNet,
       JSON.stringify(lineItems),paymentModel,orderType,verificationCode]
    );

    for (const i of rawItems) {
      await c.query(
        `UPDATE products SET stock_qty=CASE WHEN stock_qty IS NULL THEN NULL ELSE stock_qty-$1 END WHERE id=$2`,
        [i.qty,i.product_id]
      );
    }

    await c.query('COMMIT');
    ok(res,{message:'Order created successfully.',order:o.rows[0]});
  } catch(e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Create order error:',e);
    fail(res,500,'Failed to create order.');
  } finally { c.release(); }
});

app.patch('/api/orders/:id/status', auth, role('provider','admin'), async (req, res) => {
  const c = await pool.connect();

  try {
    const id = positiveInt(req.params.id);
    const next = String(req.body.status || '').trim();

    if (!id) return fail(res, 400, 'Invalid order ID.');

    const allowed = {
      pending: ['accepted','rejected','cancelled'],
      accepted: ['preparing','cancelled'],
      preparing: ['ready','cancelled'],
      ready: ['on_the_way','delivered','cancelled'],
      on_the_way: ['delivered'],
      delivered: [],
      completed: [],
      rejected: [],
      cancelled: []
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

    if (['cancelled','rejected'].includes(next)) {
      const items = Array.isArray(existing.items) ? existing.items : [];
      for (const item of items) {
        const pid = positiveInt(item.product_id);
        const qty = positiveInt(item.qty);
        if (pid && qty) {
          await c.query(
            `UPDATE products SET stock_qty=CASE WHEN stock_qty IS NULL THEN NULL ELSE stock_qty+$1 END WHERE id=$2`,
            [qty,pid]
          );
        }
      }
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
app.post('/api/orders/:id/verify-delivery', auth, role('provider'), async (req, res) => {
  const c = await pool.connect();
  try {
    const id = positiveInt(req.params.id);
    const code = String(req.body.code || '').replace(/\D/g, '');
    if (!id) return fail(res, 400, 'Invalid order ID.');
    if (!/^\d{6}$/.test(code)) return fail(res, 400, 'Enter the 6-digit delivery code.');

    await c.query('BEGIN');
    const r = await c.query(
      `SELECT o.*,p.user_id FROM orders o JOIN providers p ON p.id=o.provider_id WHERE o.id=$1 FOR UPDATE`,
      [id]
    );
    if (!r.rowCount) { await c.query('ROLLBACK'); return fail(res,404,'Order not found.'); }
    const order = r.rows[0];
    if (String(order.user_id) !== String(req.auth.sub)) { await c.query('ROLLBACK'); return fail(res,403,'Not your order.'); }
    if (order.status !== 'delivered') { await c.query('ROLLBACK'); return fail(res,400,'Order must be marked delivered before verification.'); }
    if (order.verification_verified) { await c.query('ROLLBACK'); return ok(res,{message:'Delivery already verified.',order}); }
    if (order.verify_locked) { await c.query('ROLLBACK'); return fail(res,423,'Delivery code entry is locked. Contact JajiGo admin.'); }
    if (code !== String(order.verification_code || '')) {
      const attempts = Number(order.verify_attempts || 0) + 1;
      const locked = attempts >= 5;
      const u = await c.query(
        `UPDATE orders SET verify_attempts=$1,verify_locked=$2,verify_locked_at=CASE WHEN $2 THEN NOW() ELSE verify_locked_at END,updated_at=NOW() WHERE id=$3 RETURNING *`,
        [attempts,locked,id]
      );
      await c.query('COMMIT');
      return fail(res, 400, locked ? 'Too many wrong codes. Order locked.' : `Wrong code. ${5-attempts} attempt(s) left.`);
    }

    await c.query(`UPDATE orders SET verification_verified=true,verified_at=NOW(),updated_at=NOW() WHERE id=$1`,[id]);
    const settlement = await settleOrder(c,id,req.auth.sub);
    if (settlement.result !== SETTLEMENT_RESULT.SETTLED && settlement.result !== SETTLEMENT_RESULT.ALREADY_SETTLED) {
      throw new Error('Delivery verified but settlement returned '+settlement.result);
    }
    const completed = await c.query(`UPDATE orders SET status='completed',updated_at=NOW() WHERE id=$1 RETURNING *`,[id]);
    await c.query('COMMIT');
    ok(res,{message:'Delivery verified and order completed.',order:completed.rows[0]});
  } catch (e) {
    try { await c.query('ROLLBACK'); } catch {}
    console.error('Verify delivery error:',e);
    fail(res,500,'Failed to verify delivery.');
  } finally { c.release(); }
});

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
      type: 'commission_payment', direction: 'debit', amount: round2(record.amount),
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

ensurePasswordResetTable().catch(e =>
  console.error('Could not create password_resets table:', e)
);

app.listen(port, () => {
  console.log(`JajiGo marketplace backend listening on ${port}`);
});
