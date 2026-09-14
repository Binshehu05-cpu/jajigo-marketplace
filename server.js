import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import {randomBytes} from 'node:crypto';
import {OAuth2Client} from 'google-auth-library';

const {Pool}=pg;
const app=express();
const port=Number(process.env.PORT||10000);
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL?.includes('localhost')?false:{rejectUnauthorized:false}});
const origins=(process.env.CORS_ORIGINS||'*').split(',').map(x=>x.trim()).filter(Boolean);
const COMMISSION_RATE=Math.max(0,Math.min(50,Number(process.env.COMMISSION_RATE||10)));
const COMMISSION_ON_DELIVERY=String(process.env.COMMISSION_ON_DELIVERY||'0')==='1';
const googleClient=new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
app.use(cors({origin:(origin,cb)=>{if(!origin||origins.includes('*')||origins.includes(origin))return cb(null,true);cb(new Error('CORS blocked'));}}));
app.use(express.json({limit:'2mb'}));

const ok=(res,data)=>res.json({ok:true,...data});
const fail=(res,status,message)=>res.status(status).json({ok:false,error:message});
function normPhone(v){let n=String(v||'').replace(/\D/g,'');if(n.startsWith('234'))n='0'+n.slice(3);return n;}
function tokenFor(user){return jwt.sign({sub:String(user.id),role:user.role},process.env.JWT_SECRET,{expiresIn:'7d'});}
function auth(req,res,next){try{const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return fail(res,401,'Authentication required.');req.auth=jwt.verify(h.slice(7),process.env.JWT_SECRET);}catch(e){return fail(res,401,'Invalid token.');}next();}
function role(...roles){return (req,res,next)=>roles.includes(req.auth?.role)?next():fail(res,403,'Not allowed.');}

app.get('/api/health',async(req,res)=>{try{await pool.query('SELECT 1');ok(res,{service:'jajigo-marketplace',database:true});}catch(e){fail(res,503,'Database unavailable.');}});

app.post('/api/auth/register', async (req, res) => {
  try {
    const phone = normPhone(req.body.phone);
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (name.length < 2) {
      return fail(res, 400, 'Full name is required.');
    }

    if (!/^0\d{10}$/.test(phone)) {
      return fail(res, 400, 'Invalid Nigerian phone number.');
    }

    if (!email) {
      return fail(res, 400, 'Email address is required.');
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailPattern.test(email)) {
      return fail(res, 400, 'Please enter a valid email address.');
    }

    if (password.length < 6) {
      return fail(res, 400, 'Password must be at least 6 characters.');
    }

    // Check phone
    const phoneExists = await pool.query(
      'SELECT id FROM users WHERE phone=$1',
      [phone]
    );

    if (phoneExists.rowCount) {
      return fail(res, 409, 'Phone number already has an account.');
    }

    // Check email
    const emailExists = await pool.query(
      'SELECT id FROM users WHERE LOWER(email)=LOWER($1)',
      [email]
    );

    if (emailExists.rowCount) {
      return fail(res, 409, 'Email address already has an account.');
    }

    // Secure password hash
    const hash = await bcrypt.hash(password, 12);

    // Create account
    const result = await pool.query(
      `
      INSERT INTO users (
        phone,
        full_name,
        email,
        password_hash,
        role
      )
      VALUES ($1,$2,$3,$4,'customer')
      RETURNING
        id,
        phone,
        full_name,
        email,
        avatar_url,
        role,
        status
      `,
      [
        phone,
        name,
        email,
        hash
      ]
    );

    const user = result.rows[0];

    ok(res, {
      message: 'Account created successfully.',
      token: tokenFor(user),
      user
    });

  } catch (e) {
    console.error('Registration error:', e);
    fail(res, 500, 'Registration failed.');
  }
});


app.post('/api/auth/login', async (req, res) => {
  try {
    const email = String(req.body.email || '')
      .trim()
      .toLowerCase();

    const password = String(req.body.password || '');

    if (!email || !password) {
      return fail(res, 400, 'Email and password are required.');
    }

    const result = await pool.query(
      `
      SELECT
        id,
        phone,
        full_name,
        email,
        avatar_url,
        role,
        status
      FROM users
      WHERE LOWER(email)=LOWER($1)
      `,
      [email]
    );

    if (!result.rowCount) {
      return fail(res, 401, 'Wrong email or password.');
    }

    const user = result.rows[0];

    if (user.status !== 'active') {
      return fail(res, 403, 'Account is not active.');
    }

    const passwordCorrect = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordCorrect) {
      return fail(res, 401, 'Wrong email or password.');
    }

    delete user.password_hash;

    ok(res, {
      message: 'Login successful.',
      token: tokenFor(user),
      user
    });

  } catch (e) {
    console.error('Login error:', e);
    fail(res, 500, 'Login failed.');
  }
});

app.post('/api/auth/google', async (req, res) => {
  try {
    const credential = String(req.body.credential || '').trim();

    if (!credential) {
      return fail(res, 400, 'Google credential is required.');
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();

    if (!payload?.sub || !payload.email) {
      return fail(res, 401, 'Invalid Google account.');
    }

    const googleId = payload.sub;
    const email = String(payload.email).trim().toLowerCase();
    const name = String(payload.name || email.split('@')[0]).trim();
    const avatarUrl = String(payload.picture || '').trim();

    // Find existing Google account
    let result = await pool.query(
      `
      SELECT
        id,
        phone,
        full_name,
        email,
        google_id,
        avatar_url,
        role,
        status
      FROM users
      WHERE google_id=$1
      `,
      [googleId]
    );

    // If Google account isn't connected yet, try matching by email
    if (!result.rowCount) {
      result = await pool.query(
        `
        SELECT
          id,
          phone,
          full_name,
          email,
          google_id,
          avatar_url,
          role,
          status
        FROM users
        WHERE LOWER(email)=LOWER($1)
        `,
        [email]
      );
    }

    let user;

    if (result.rowCount) {
      user = result.rows[0];

      if (user.status !== 'active') {
        return fail(res, 403, 'Account is not active.');
      }

      // Connect Google to existing account
      const updated = await pool.query(
        `
        UPDATE users
        SET
          google_id=$1,
          email=COALESCE(email,$2),
          avatar_url=COALESCE(NULLIF($3,''),avatar_url)
        WHERE id=$4
        RETURNING
          id,
          phone,
          full_name,
          email,
          google_id,
          avatar_url,
          role,
          status
        `,
        [googleId, email, avatarUrl, user.id]
      );

      user = updated.rows[0];

    } else {
      // Create a new Google customer account
      const googlePasswordHash = await bcrypt.hash(randomBytes(32).toString('hex'), 12);
      const created = await pool.query(
        `
        INSERT INTO users (
          full_name,
          email,
          google_id,
          avatar_url,
          role,
          status
        )
        VALUES ($1,$2,$3,$4,$5,'customer','active')
        RETURNING
          id,
          phone,
          full_name,
          email,
          google_id,
          avatar_url,
          role,
          status
        `,
        [name, googlePasswordHash, email, googleId, avatarUrl]
      );

      user = created.rows[0];
    }

    ok(res, {
      message: 'Google login successful.',
      token: tokenFor(user),
      user
    });

  } catch (e) {
    console.error('Google authentication error:', e);

    if (e.code === '23505') {
      return fail(
        res,
        409,
        'An account with this Google account or email already exists.'
      );
    }

    fail(res, 401, 'Google authentication failed.');
  }
});

app.get('/api/bootstrap',auth,async(req,res)=>{try{
  const customers=req.auth.role==='admin'
    ? pool.query("SELECT id,phone,full_name,role,status FROM users WHERE role='customer' ORDER BY id")
    : pool.query("SELECT id,phone,full_name,role,status FROM users WHERE id=$1",[req.auth.sub]);
  const orders=req.auth.role==='customer'
    ? pool.query("SELECT o.*,u.full_name AS customer_name,p.business_name FROM orders o JOIN users u ON u.id=o.customer_id JOIN providers p ON p.id=o.provider_id WHERE o.customer_id=$1 ORDER BY o.created_at DESC")
    : req.auth.role==='provider'
      ? pool.query("SELECT o.*,u.full_name AS customer_name,p.business_name FROM orders o JOIN users u ON u.id=o.customer_id JOIN providers p ON p.id=o.provider_id WHERE o.provider_id IN (SELECT id FROM providers WHERE user_id=$1) ORDER BY o.created_at DESC",[req.auth.sub])
      : pool.query("SELECT o.*,u.full_name AS customer_name,p.business_name FROM orders o JOIN users u ON u.id=o.customer_id JOIN providers p ON p.id=o.provider_id ORDER BY o.created_at DESC");
  const [c,v,o,pr]=await Promise.all([
    customers,
    pool.query("SELECT p.*,u.phone AS user_phone FROM providers p JOIN users u ON u.id=p.user_id WHERE p.status='approved' ORDER BY p.id"),
    orders,
    pool.query("SELECT p.*,pr.business_name FROM products p JOIN providers pr ON pr.id=p.provider_id WHERE p.is_available=true AND pr.status='approved' ORDER BY p.id DESC")
  ]);ok(res,{customers:c.rows,providers:v.rows,orders:o.rows,products:pr.rows});}catch(e){console.error(e);fail(res,500,'Could not load marketplace data.');}});

app.post('/api/products',auth,role('provider'),async(req,res)=>{try{const b=req.body||{};const pr=await pool.query("SELECT id,category_id FROM providers WHERE user_id=$1 AND status='approved'",[req.auth.sub]);if(!pr.rowCount)return fail(res,403,'Provider not approved.');const p=await pool.query("INSERT INTO products (provider_id,category_id,name,description,price,stock_qty,image_url,is_available) VALUES ($1,$2,$3,$4,$5,$6,$7,true) RETURNING *",[pr.rows[0].id,pr.rows[0].category_id,String(b.name||'').trim(),String(b.description||'').trim(),Number(b.price||0),Number(b.stock_qty||0),String(b.image_url||'').trim()]);ok(res,{product:p.rows[0]});}catch(e){console.error(e);fail(res,500,'Failed to create product.');}});

app.patch('/api/products/:id',auth,role('provider','admin'),async(req,res)=>{try{const id=req.params.id,b=req.body||{};const r=await pool.query("SELECT p.*,pr.user_id FROM products p JOIN providers pr ON pr.id=p.provider_id WHERE p.id=$1",[id]);if(!r.rowCount)return fail(res,404,'Product not found.');if(req.auth.role==='provider'&&r.rows[0].user_id!==Number(req.auth.sub))return fail(res,403,'Not your product.');const u=await pool.query("UPDATE products SET name=COALESCE(NULLIF($1,''),name),description=COALESCE(NULLIF($2,''),description),price=COALESCE(NULLIF($3,0),price),stock_qty=COALESCE(NULLIF($4,0),stock_qty),image_url=COALESCE(NULLIF($5,''),image_url),is_available=COALESCE($6,is_available) WHERE id=$7 RETURNING *",[String(b.name||'').trim(),String(b.description||'').trim(),Number(b.price||0),Number(b.stock_qty||0),String(b.image_url||'').trim(),b.is_available,id]);ok(res,{product:u.rows[0]});}catch(e){console.error(e);fail(res,500,'Failed to update product.');}});

app.delete('/api/products/:id',auth,role('provider','admin'),async(req,res)=>{try{const id=req.params.id;const r=await pool.query("SELECT p.id,pr.user_id FROM products p JOIN providers pr ON pr.id=p.provider_id WHERE p.id=$1",[id]);if(!r.rowCount)return fail(res,404,'Product not found.');if(req.auth.role==='provider'&&r.rows[0].user_id!==Number(req.auth.sub))return fail(res,403,'Not your product.');await pool.query("DELETE FROM products WHERE id=$1",[id]);ok(res,{message:'Product deleted.'});}catch(e){console.error(e);fail(res,500,'Failed to delete product.');}});

app.post('/api/orders',auth,role('customer'),async(req,res)=>{const c=await pool.connect();try{const b=req.body||{};if(!b.provider_id||!Array.isArray(b.items)||!b.items.length)return fail(res,400,'Provider and items required.');await c.query('BEGIN');
const ids=b.items.map(x=>x.product_id);const pr=await c.query('SELECT id,name,price,stock_qty,is_available,provider_id FROM products WHERE id=ANY($1::bigint[]) FOR UPDATE',[ids]);const map=new Map(pr.rows.map(p=>[p.id,p]));const all=b.items.every(i=>map.get(i.product_id)?.is_available&&i.qty<=map.get(i.product_id).stock_qty);if(!all){await c.query('ROLLBACK');return fail(res,400,'Some items unavailable or out of stock.');}if(!b.items.every(i=>map.get(i.product_id).provider_id===b.provider_id)){await c.query('ROLLBACK');return fail(res,400,'All items must be from same provider.');}
const total=b.items.reduce((s,i)=>s+i.qty*map.get(i.product_id).price,0);const commission=Math.round(total*COMMISSION_RATE/100);const deliveryMode=String(b.delivery_mode||'provider_delivery');if(!['provider_delivery','customer_pickup'].includes(deliveryMode))throw new Error('Invalid delivery mode.');const df=deliveryMode==='customer_pickup'?0:(b.delivery_fee||0);const o=await c.query("INSERT INTO orders (customer_id,provider_id,total_price,commission_amount,delivery_fee,delivery_mode,status) VALUES ($1,$2,$3,$4,$5,$6,'pending') RETURNING id,total_price,commission_amount,delivery_fee",[req.auth.sub,b.provider_id,total,commission,df,deliveryMode]);const oid=o.rows[0].id;for(const i of b.items){const p=map.get(i.product_id);await c.query("INSERT INTO order_items (order_id,product_id,quantity,unit_price) VALUES ($1,$2,$3,$4)",[oid,p.id,i.qty,p.price]);await c.query("UPDATE products SET stock_qty=stock_qty-$1 WHERE id=$2",[i.qty,p.id]);}await c.query('COMMIT');ok(res,{order:{id:oid,...o.rows[0]}});}catch(e){await c.query('ROLLBACK');console.error(e);fail(res,500,'Failed to create order.');}finally{c.release();}});

app.patch('/api/orders/:id/status',auth,role('provider','admin'),async(req,res)=>{try{const id=req.params.id,next=String(req.body.status||'');const allowed={pending:['accepted','rejected','cancelled'],accepted:['shipped','cancelled'],shipped:['delivered','cancelled'],rejected:[],cancelled:[],delivered:[]};const r=await pool.query("SELECT o.status,o.provider_id,p.user_id FROM orders o JOIN providers p ON p.id=o.provider_id WHERE o.id=$1",[id]);if(!r.rowCount)return fail(res,404,'Order not found.');if(req.auth.role==='provider'&&r.rows[0].user_id!==Number(req.auth.sub))return fail(res,403,'Not your order.');const c=r.rows[0].status;if(!allowed[c]?.includes(next))return fail(res,400,'Invalid status transition.');const u=await pool.query("UPDATE orders SET status=$1 WHERE id=$2 RETURNING *",[next,id]);ok(res,{order:u.rows[0]});}catch(e){console.error(e);fail(res,500,'Failed to update order status.');}});

app.get('/api/products',async(req,res)=>{try{const r=await pool.query("SELECT p.*,pr.business_name FROM products p JOIN providers pr ON pr.id=p.provider_id WHERE p.is_available=true AND pr.status='approved' ORDER BY p.id DESC");ok(res,{products:r.rows});}catch(e){console.error(e);fail(res,500,'Failed to fetch products.');}});

app.listen(port,()=>console.log(`JajiGo marketplace backend listening on ${port}`));
