import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';

const {Pool}=pg;
const app=express();
const port=Number(process.env.PORT||10000);
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL?.includes('localhost')?false:{rejectUnauthorized:false}});
const origins=(process.env.CORS_ORIGINS||'*').split(',').map(x=>x.trim()).filter(Boolean);
const COMMISSION_RATE=Math.max(0,Math.min(50,Number(process.env.COMMISSION_RATE||10)));
const COMMISSION_ON_DELIVERY=String(process.env.COMMISSION_ON_DELIVERY||'0')==='1';
app.use(cors({origin:(origin,cb)=>{if(!origin||origins.includes('*')||origins.includes(origin))return cb(null,true);cb(new Error('CORS blocked'));}}));
app.use(express.json({limit:'2mb'}));

const ok=(res,data)=>res.json({ok:true,...data});
const fail=(res,status,message)=>res.status(status).json({ok:false,error:message});
function normPhone(v){let n=String(v||'').replace(/\D/g,'');if(n.startsWith('234'))n='0'+n.slice(3);return n;}
function tokenFor(user){return jwt.sign({sub:String(user.id),role:user.role},process.env.JWT_SECRET,{expiresIn:'7d'});}
function auth(req,res,next){try{const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return fail(res,401,'Authentication required.');req.auth=jwt.verify(h.slice(7),process.env.JWT_SECRET);next();}catch(e){fail(res,401,'Invalid token.');}}
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
        password_hash,
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

app.get('/api/bootstrap',auth,async(req,res)=>{try{
  const customers=req.auth.role==='admin'
    ? pool.query("SELECT id,phone,full_name,role,status FROM users WHERE role='customer' ORDER BY id")
    : pool.query("SELECT id,phone,full_name,role,status FROM users WHERE id=$1",[req.auth.sub]);
  const orders=req.auth.role==='customer'
    ? pool.query("SELECT o.*,u.full_name AS customer_name,p.business_name FROM orders o JOIN users u ON u.id=o.customer_id JOIN providers p ON p.id=o.provider_id WHERE o.customer_id=$1 ORDER BY o.created_at DESC")
    : req.auth.role==='provider'
      ? pool.query("SELECT o.*,u.full_name AS customer_name,p.business_name FROM orders o JOIN users u ON u.id=o.customer_id JOIN providers p ON p.id=o.provider_id WHERE o.provider_id IN (SELECT id FROM providers WHERE user_id=$1) ORDER BY o.created_at DESC")
      : pool.query("SELECT o.*,u.full_name AS customer_name,p.business_name FROM orders o JOIN users u ON u.id=o.customer_id JOIN providers p ON p.id=o.provider_id ORDER BY o.created_at DESC");
  const [c,v,o,pr]=await Promise.all([
    customers,
    pool.query("SELECT p.*,u.phone AS user_phone FROM providers p JOIN users u ON u.id=p.user_id WHERE p.status='approved' ORDER BY p.id"),
    orders,
    pool.query("SELECT p.*,pr.business_name FROM products p JOIN providers pr ON pr.id=p.provider_id WHERE p.is_available=true AND pr.status='approved' ORDER BY p.id DESC")
  ]);ok(res,{customers:c.rows,providers:v.rows,orders:o.rows,products:pr.rows});}catch(e){console.error(e);fail(res,500,'Could not load marketplace data.');}});

app.post('/api/products',auth,role('provider'),async(req,res)=>{try{const b=req.body||{};const pr=await pool.query("SELECT id,category_id FROM providers WHERE user_id=$1 AND status='approved'",[req.auth.sub]);if(!pr.rowCount)return fail(res,403,'Provider not approved.');const p=await pool.query("INSERT INTO products (provider_id,category_id,name,description,price,stock_qty,images,is_available,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,true,NOW()) RETURNING *",[pr.rows[0].id,b.category_id,b.name,b.description,b.price,b.stock_qty,b.images||[]]);ok(res,{product:p.rows[0]});}catch(e){console.error(e);fail(res,500,'Could not create product.');}});
app.patch('/api/products/:id',auth,role('provider','admin'),async(req,res)=>{try{const id=req.params.id,b=req.body||{};const r=await pool.query("SELECT p.*,pr.user_id FROM products p JOIN providers pr ON pr.id=p.provider_id WHERE p.id=$1",[id]);if(!r.rowCount)return fail(res,404,'Product not found.');if(req.auth.role==='provider'&&r.rows[0].user_id!==req.auth.sub)return fail(res,403,'Not allowed.');const u=await pool.query("UPDATE products SET name=COALESCE($2,name),description=COALESCE($3,description),price=COALESCE($4,price),stock_qty=COALESCE($5,stock_qty),is_available=COALESCE($6,is_available) WHERE id=$1 RETURNING *",[id,b.name,b.description,b.price,b.stock_qty,b.is_available]);ok(res,{product:u.rows[0]});}catch(e){console.error(e);fail(res,500,'Could not update product.');}});
app.delete('/api/products/:id',auth,role('provider','admin'),async(req,res)=>{try{const id=req.params.id;const r=await pool.query("SELECT p.id,pr.user_id FROM products p JOIN providers pr ON pr.id=p.provider_id WHERE p.id=$1",[id]);if(!r.rowCount)return fail(res,404,'Product not found.');if(req.auth.role==='provider'&&r.rows[0].user_id!==req.auth.sub)return fail(res,403,'Not allowed.');await pool.query("DELETE FROM products WHERE id=$1",[id]);ok(res,{});}catch(e){console.error(e);fail(res,500,'Could not delete product.');}});

app.post('/api/orders',auth,role('customer'),async(req,res)=>{const c=await pool.connect();try{const b=req.body||{};if(!b.provider_id||!Array.isArray(b.items)||!b.items.length)return fail(res,400,'Provider and items required.');
const ids=b.items.map(x=>x.product_id);const pr=await c.query('SELECT id,name,price,stock_qty,is_available,provider_id FROM products WHERE id=ANY($1::bigint[]) FOR UPDATE',[ids]);const map=new Map(pr.rows.map(x=>[x.id,x]));let total=0;const detail=[];for(const item of b.items){const p=map.get(item.product_id);if(!p)throw new Error('Product not found.');if(!p.is_available)throw new Error('Product unavailable.');if(p.provider_id!==b.provider_id)throw new Error('All items must be from same provider.');if(item.quantity>p.stock_qty)throw new Error(`Insufficient stock for ${p.name}.`);const subtotal=p.price*item.quantity;total+=subtotal;detail.push({product_id:p.id,quantity:item.quantity,unit_price:p.price,subtotal});}
const deliveryMode=String(b.delivery_mode||'provider_delivery');if(!['provider_delivery','customer_pickup'].includes(deliveryMode))throw new Error('Invalid delivery mode.');const df=deliveryMode==='customer_pickup'?0:Number(b.delivery_fee||0);const com=COMMISSION_ON_DELIVERY?0:Math.round(total*COMMISSION_RATE/100);const o=await c.query("INSERT INTO orders (customer_id,provider_id,total_price,delivery_fee,commission,delivery_mode,order_items,status,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',NOW()) RETURNING *",[req.auth.sub,b.provider_id,total,df,com,deliveryMode,JSON.stringify(detail)]);for(const item of b.items){await c.query('UPDATE products SET stock_qty=stock_qty-$1 WHERE id=$2',[item.quantity,item.product_id]);}await c.query('COMMIT');ok(res,{order:o.rows[0]});}catch(e){await c.query('ROLLBACK');console.error(e);fail(res,e.message?.includes('Product')?400:500,e.message||'Could not create order.');}finally{c.release();}});

app.patch('/api/orders/:id/status',auth,role('provider','admin'),async(req,res)=>{try{const id=req.params.id,next=String(req.body.status||'');const allowed={pending:['accepted','rejected','cancelled'],accepted:['cancelled','delivered'],rejected:[],cancelled:[],delivered:[]};const r=await pool.query("SELECT * FROM orders WHERE id=$1",[id]);if(!r.rowCount)return fail(res,404,'Order not found.');const order=r.rows[0];if(!allowed[order.status]?.includes(next))return fail(res,400,`Cannot transition from ${order.status} to ${next}.`);if(req.auth.role==='provider'&&order.provider_id!==req.auth.sub)return fail(res,403,'Not allowed.');const u=await pool.query("UPDATE orders SET status=$1 WHERE id=$2 RETURNING *",[next,id]);ok(res,{order:u.rows[0]});}catch(e){console.error(e);fail(res,500,'Could not update order status.');}});

app.get('/api/products',async(req,res)=>{try{const r=await pool.query("SELECT p.*,pr.business_name FROM products p JOIN providers pr ON pr.id=p.provider_id WHERE p.is_available=true AND pr.status='approved' ORDER BY p.id DESC");ok(res,{products:r.rows});}catch(e){console.error(e);fail(res,500,'Could not fetch products.');}});

app.listen(port,()=>console.log(`JajiGo marketplace backend listening on ${port}`));
