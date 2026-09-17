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
function auth(req,res,next){try{const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return fail(res,401,'Authentication required.');req.auth=jwt.verify(h.slice(7),process.env.JWT_SECRET);next();}catch{return fail(res,401,'Invalid or expired session.');}}
function role(...roles){return (req,res,next)=>roles.includes(req.auth?.role)?next():fail(res,403,'Not allowed.');}

app.get('/api/health',async(req,res)=>{try{await pool.query('SELECT 1');ok(res,{service:'jajigo-marketplace',database:true});}catch(e){fail(res,503,'Database unavailable.');}});
app.post('/api/auth/register',async(req,res)=>{try{const phone=normPhone(req.body.phone),name=String(req.body.name||'').trim(),password=String(req.body.password||'');if(!/^0\d{10}$/.test(phone))return fail(res,400,'Invalid Nigerian phone number.');if(name.length<2)return fail(res,400,'Full name is required.');if(password.length<6)return fail(res,400,'Password must be at least 6 characters.');const exists=await pool.query('SELECT id FROM users WHERE phone=$1',[phone]);if(exists.rowCount)return fail(res,409,'Phone number already has an account.');const hash=await bcrypt.hash(password,12);const r=await pool.query('INSERT INTO users(phone,full_name,password_hash,role) VALUES($1,$2,$3,\'customer\') RETURNING id,phone,full_name,role,status',[phone,name,hash]);const user=r.rows[0];ok(res,{token:tokenFor(user),user});}catch(e){console.error(e);fail(res,500,'Registration failed.');}});
app.post('/api/auth/register-provider', async (req,res) => {
 const c=await pool.connect();
 try {
  const b=req.body||{};
  const phone=normPhone(b.phone);
  const alt=normPhone(b.alt_phone||'');
  const name=String(b.name||'').trim();
  const email=String(b.email||'').trim().toLowerCase();
  const password=String(b.password||'');
  const business=String(b.business_name||'').trim();
  const description=String(b.description||'').trim();
  const shop=String(b.shop_number||'').trim();
  const address=String(b.address||'').trim();
  const categoryId=Number(b.category_id);
  const mode=String(b.delivery_mode||'provider_delivery');
  if(!/^0\d{10}$/.test(phone)) return fail(res,400,'Invalid primary Nigerian phone number.');
  if(alt&&!/^0\d{10}$/.test(alt)) return fail(res,400,'Invalid alternative phone number.');
  if(name.length<2) return fail(res,400,'Owner/provider name is required.');
  if(!email||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res,400,'Valid email is required.');
  if(password.length<6) return fail(res,400,'Password must be at least 6 characters.');
  if(business.length<2) return fail(res,400,'Business/service/shop name is required.');
  if(!Number.isInteger(categoryId)||categoryId<1) return fail(res,400,'Business category is required.');
  if(address.length<3) return fail(res,400,'Business/service address is required.');
  if(!['provider_delivery','customer_pickup','both'].includes(mode)) return fail(res,400,'Invalid delivery/service mode.');
  const exists=await c.query('SELECT id,phone,email FROM users WHERE phone=$1 OR (email IS NOT NULL AND LOWER(email)=LOWER($2))',[phone,email]);
  if(exists.rowCount){
   const samePhone=exists.rows.some(x=>String(x.phone)===String(phone));
   return fail(res,409,samePhone?'Phone number already has an account.':'Email already has an account.');
  }
  await c.query('BEGIN');
  const hash=await bcrypt.hash(password,12);
  const u=await c.query("INSERT INTO users(phone,full_name,email,password_hash,role,status) VALUES($1,$2,$3,$4,'provider','active') RETURNING id,phone,full_name,email,role,status",[phone,name,email,hash]);
  const user=u.rows[0];
  const pr=await c.query("INSERT INTO providers(user_id,business_name,description,category_id,address,shop_number,alt_phone,delivery_mode,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending') RETURNING *",[user.id,business,description,categoryId,address,shop||null,alt||null,mode]);
  await c.query('COMMIT');
  const provider=pr.rows[0];
  ok(res,{token:tokenFor(user),user:{...user,provider_id:provider.id,business_name:provider.business_name,description:provider.description,category_id:provider.category_id,address:provider.address,shop_number:provider.shop_number,alt_phone:provider.alt_phone,delivery_mode:provider.delivery_mode,provider_status:provider.status},pending:true});
 } catch(e) {
  try{await c.query('ROLLBACK')}catch{}
  console.error(e); fail(res,500,'Provider registration failed.');
 } finally { c.release(); }
});

app.post('/api/auth/login',async(req,res)=>{
  try{
    const phone=normPhone(req.body.phone),password=String(req.body.password||'');
    const r=await pool.query('SELECT id,phone,full_name,password_hash,role,status FROM users WHERE phone=$1',[phone]);
    if(!r.rowCount)return fail(res,401,'Wrong phone number or password.');
    const user=r.rows[0];
    if(user.status!=='active')return fail(res,403,'Account is not active.');
    if(!await bcrypt.compare(password,user.password_hash))return fail(res,401,'Wrong phone number or password.');
    delete user.password_hash;
    if(user.role==='provider'){
      const pr=await pool.query('SELECT * FROM providers WHERE user_id=$1',[user.id]);
      if(!pr.rowCount)return fail(res,403,'Provider profile not found.');
      const p=pr.rows[0];
      Object.assign(user,{provider_id:p.id,business_name:p.business_name,description:p.description,category_id:p.category_id,address:p.address,shop_number:p.shop_number,alt_phone:p.alt_phone,delivery_mode:p.delivery_mode,provider_status:p.status});
    }
    ok(res,{token:tokenFor(user),user,pending:user.role==='provider'&&user.provider_status==='pending'});
  }catch(e){console.error(e);fail(res,500,'Login failed.');}
});

app.get('/api/bootstrap',auth,async(req,res)=>{try{
  const customers=req.auth.role==='admin'
    ? pool.query("SELECT id,phone,full_name,role,status FROM users WHERE role='customer' ORDER BY id")
    : pool.query("SELECT id,phone,full_name,role,status FROM users WHERE id=$1",[req.auth.sub]);
  const orders=req.auth.role==='customer'
    ? pool.query("SELECT o.*,u.full_name AS customer_name,p.business_name FROM orders o JOIN users u ON u.id=o.customer_id JOIN providers p ON p.id=o.provider_id WHERE o.customer_id=$1 ORDER BY o.created_at DESC",[req.auth.sub])
    : req.auth.role==='provider'
      ? pool.query("SELECT o.*,u.full_name AS customer_name,p.business_name FROM orders o JOIN users u ON u.id=o.customer_id JOIN providers p ON p.id=o.provider_id WHERE o.provider_id IN (SELECT id FROM providers WHERE user_id=$1) ORDER BY o.created_at DESC",[req.auth.sub])
      : pool.query("SELECT o.*,u.full_name AS customer_name,p.business_name FROM orders o JOIN users u ON u.id=o.customer_id JOIN providers p ON p.id=o.provider_id ORDER BY o.created_at DESC");
  const [c,v,o,pr]=await Promise.all([
    customers,
    pool.query("SELECT p.*,u.phone AS user_phone FROM providers p JOIN users u ON u.id=p.user_id WHERE p.status='approved' ORDER BY p.id"),
    orders,
    pool.query("SELECT p.*,pr.business_name FROM products p JOIN providers pr ON pr.id=p.provider_id WHERE p.is_available=true AND pr.status='approved' ORDER BY p.id DESC")
  ]);ok(res,{customers:c.rows,providers:v.rows,orders:o.rows,products:pr.rows});}catch(e){console.error(e);fail(res,500,'Could not load marketplace data.');}});

app.post('/api/products',auth,role('provider'),async(req,res)=>{try{const b=req.body||{};const pr=await pool.query("SELECT id,category_id FROM providers WHERE user_id=$1 AND status='approved'",[req.auth.sub]);if(!pr.rowCount)return fail(res,403,'Approved provider account required.');const name=String(b.name||'').trim();const price=Math.floor(Number(b.price));if(name.length<2)return fail(res,400,'Product name is required.');if(!Number.isFinite(price)||price<0)return fail(res,400,'Valid price is required.');const r=await pool.query("INSERT INTO products(provider_id,category_id,type,name,description,price,is_available,icon,photo) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *",[pr.rows[0].id,b.category_id||pr.rows[0].category_id,b.type==='service'?'service':'product',name,String(b.description||'').trim(),price,b.is_available!==false,String(b.icon||'📦'),String(b.photo||'')]);ok(res,{product:r.rows[0]});}catch(e){console.error(e);fail(res,400,e.message||'Could not create product.');}});
app.patch('/api/products/:id',auth,role('provider','admin'),async(req,res)=>{try{const id=req.params.id,b=req.body||{};const r=await pool.query("SELECT p.*,pr.user_id FROM products p JOIN providers pr ON pr.id=p.provider_id WHERE p.id=$1",[id]);if(!r.rowCount)return fail(res,404,'Product not found.');if(req.auth.role==='provider'&&String(r.rows[0].user_id)!==String(req.auth.sub))return fail(res,403,'Not your product.');const x=r.rows[0];const name=b.name==null?x.name:String(b.name).trim();const price=b.price==null?x.price:Math.floor(Number(b.price));if(name.length<2||!Number.isFinite(price)||price<0)return fail(res,400,'Invalid product data.');const u=await pool.query("UPDATE products SET name=$1,description=$2,price=$3,is_available=$4,icon=$5,photo=$6 WHERE id=$7 RETURNING *",[name,b.description==null?x.description:String(b.description),price,b.is_available==null?x.is_available:Boolean(b.is_available),b.icon==null?x.icon:String(b.icon),b.photo==null?x.photo:String(b.photo),id]);ok(res,{product:u.rows[0]});}catch(e){console.error(e);fail(res,400,e.message||'Could not update product.');}});
app.delete('/api/products/:id',auth,role('provider','admin'),async(req,res)=>{try{const id=req.params.id;const r=await pool.query("SELECT p.id,pr.user_id FROM products p JOIN providers pr ON pr.id=p.provider_id WHERE p.id=$1",[id]);if(!r.rowCount)return fail(res,404,'Product not found.');if(req.auth.role==='provider'&&String(r.rows[0].user_id)!==String(req.auth.sub))return fail(res,403,'Not your product.');await pool.query('DELETE FROM products WHERE id=$1',[id]);ok(res,{deleted:true,id});}catch(e){console.error(e);fail(res,500,'Could not delete product.');}});

app.post('/api/orders',auth,role('customer'),async(req,res)=>{const c=await pool.connect();try{const b=req.body||{};if(!b.provider_id||!Array.isArray(b.items)||!b.items.length)return fail(res,400,'Provider and items are required.');await c.query('BEGIN');const pv=await c.query('SELECT id,business_name,delivery_fee FROM providers WHERE id=$1 AND status=\'approved\'',[b.provider_id]);if(!pv.rowCount){await c.query('ROLLBACK');return fail(res,404,'Provider not found.');}
const ids=b.items.map(x=>x.product_id);const pr=await c.query('SELECT id,name,price,stock_qty,is_available,provider_id FROM products WHERE id=ANY($1::bigint[]) FOR UPDATE',[ids]);const map=new Map(pr.rows.map(x=>[String(x.id),x]));let subtotal=0;const items=[];for(const i of b.items){const p=map.get(String(i.product_id)),q=Math.max(1,Math.floor(Number(i.quantity||1)));if(!p||!p.is_available||String(p.provider_id)!==String(b.provider_id))throw new Error('Invalid product in order.');if(p.stock_qty!==null&&p.stock_qty<q)throw new Error(`Not enough stock for ${p.name}.`);subtotal+=p.price*q;items.push({product_id:p.id,product_name:p.name,quantity:q,unit_price:p.price,line_total:p.price*q});}
const deliveryMode=String(b.delivery_mode||'provider_delivery');if(!['provider_delivery','customer_pickup'].includes(deliveryMode))throw new Error('Invalid delivery mode.');const df=deliveryMode==='customer_pickup'?0:Number(pv.rows[0].delivery_fee||0);const total=subtotal+df;const commissionBase=COMMISSION_ON_DELIVERY?total:subtotal;const rate=COMMISSION_RATE;const commission=Math.round(commissionBase*rate/100);const net=total-commission;const code='JG-'+Date.now().toString(36).toUpperCase();const ins=await c.query(`INSERT INTO orders(order_code,customer_id,provider_id,status,payment_method,payment_status,delivery_mode,address,customer_phone,subtotal,delivery_fee,total,commission,provider_net,items) VALUES($1,$2,$3,'pending',$4,'pending',$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,[code,req.auth.sub,b.provider_id,b.payment_method||'cash_on_delivery',deliveryMode,b.address||null,b.customer_phone||null,subtotal,df,total,commission,net,JSON.stringify(items)]);for(const i of items){await c.query('UPDATE products SET stock_qty=CASE WHEN stock_qty IS NULL THEN NULL ELSE stock_qty-$1 END WHERE id=$2',[i.quantity,i.product_id]);}await c.query('COMMIT');ok(res,{order:ins.rows[0]});}catch(e){await c.query('ROLLBACK');console.error(e);fail(res,400,e.message||'Could not create order.');}finally{c.release();}});

app.patch('/api/orders/:id/status',auth,role('provider','admin'),async(req,res)=>{try{const id=req.params.id,next=String(req.body.status||'');const allowed={pending:['accepted','rejected','cancelled'],accepted:['preparing','cancelled'],preparing:['ready','cancelled'],ready:['on_the_way','delivered'],on_the_way:['delivered'],delivered:['completed']};const q=await pool.query('SELECT o.* FROM orders o WHERE o.id=$1',[id]);if(!q.rowCount)return fail(res,404,'Order not found.');const o=q.rows[0];if(req.auth.role==='provider'){const p=await pool.query('SELECT id FROM providers WHERE user_id=$1',[req.auth.sub]);if(!p.rowCount||String(p.rows[0].id)!==String(o.provider_id))return fail(res,403,'Not your order.');}if(!(allowed[o.status]||[]).includes(next))return fail(res,400,'Invalid status transition.');const r=await pool.query('UPDATE orders SET status=$1,updated_at=NOW() WHERE id=$2 RETURNING *',[next,id]);ok(res,{order:r.rows[0]});}catch(e){console.error(e);fail(res,500,'Could not update order.');}});

app.get('/api/products',async(req,res)=>{try{const r=await pool.query("SELECT p.*,pr.business_name FROM products p JOIN providers pr ON pr.id=p.provider_id WHERE p.is_available=true AND pr.status='approved' ORDER BY p.id DESC");ok(res,{products:r.rows});}catch(e){fail(res,500,'Could not load products.');}});

async function ensureStep8Schema(){
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(180)');
  await pool.query('ALTER TABLE providers ADD COLUMN IF NOT EXISTS shop_number VARCHAR(80)');
  await pool.query('ALTER TABLE providers ADD COLUMN IF NOT EXISTS alt_phone VARCHAR(20)');
}

ensureStep8Schema()
  .then(()=>app.listen(port,()=>console.log(`JajiGo marketplace backend listening on ${port}`)))
  .catch(e=>{console.error('JajiGo startup schema check failed:',e);process.exit(1);});
