import express from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import pg from "pg";

const { Pool } = pg;
const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.use(express.json({limit:"1mb"}));
app.use(express.static("public"));

const allowedStatuses=["New","Login","Sanction","Disbursed","Rejected"];
function safeEqual(value,expected){const a=Buffer.from(String(value)),b=Buffer.from(String(expected));return a.length===b.length&&crypto.timingSafeEqual(a,b);}

async function initDb(){
  if(!process.env.DATABASE_URL) throw new Error("DATABASE_URL is missing. Add PostgreSQL connection string in Render.");
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY,mobile TEXT UNIQUE NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS otps(id SERIAL PRIMARY KEY,mobile TEXT NOT NULL,otp_hash TEXT NOT NULL,expires_at BIGINT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,used INTEGER NOT NULL DEFAULT 0,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS leads(id TEXT PRIMARY KEY,customer TEXT NOT NULL,mobile TEXT NOT NULL,email TEXT DEFAULT '',banker TEXT DEFAULT '',connector TEXT DEFAULT '',bank TEXT DEFAULT '',appno TEXT DEFAULT '',loan_account TEXT DEFAULT '',status TEXT NOT NULL DEFAULT 'New',loan_amount DOUBLE PRECISION NOT NULL DEFAULT 0,sanction_amount DOUBLE PRECISION NOT NULL DEFAULT 0,disb DOUBLE PRECISION NOT NULL DEFAULT 0,follow_date TEXT DEFAULT '',remark TEXT DEFAULT '',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE TABLE IF NOT EXISTS payments(id TEXT PRIMARY KEY,lead_id TEXT NOT NULL,connector TEXT DEFAULT '',payout_percent DOUBLE PRECISION NOT NULL DEFAULT 0,net_payout DOUBLE PRECISION NOT NULL DEFAULT 0,payment_date TEXT DEFAULT '',payment_mode TEXT DEFAULT '',utr TEXT DEFAULT '',payment_status TEXT NOT NULL DEFAULT 'Pending',remark TEXT DEFAULT '',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
    CREATE INDEX IF NOT EXISTS idx_leads_created_at ON leads(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status);
  `);
}

app.post("/api/auth/login",(req,res)=>{
  const username=String(req.body.username||"").trim(),password=String(req.body.password||"");
  if(!ADMIN_USERNAME||!ADMIN_PASSWORD)return res.status(500).json({error:"Login is not configured. Set ADMIN_USERNAME and ADMIN_PASSWORD in Render."});
  if(!safeEqual(username,ADMIN_USERNAME)||!safeEqual(password,ADMIN_PASSWORD))return res.status(401).json({error:"Invalid user ID or password"});
  res.json({ok:true,token:jwt.sign({username},JWT_SECRET,{expiresIn:"12h"})});
});
function auth(req,res,next){try{const h=req.headers.authorization||"",token=h.startsWith("Bearer ")?h.slice(7):"",user=jwt.verify(token,JWT_SECRET);if(user.username!==ADMIN_USERNAME)throw new Error();req.user=user;next();}catch{res.status(401).json({error:"Login required"});}}
app.get("/api/me",auth,(req,res)=>res.json({username:req.user.username}));

app.get("/api/dashboard",auth,async(req,res)=>{try{
  const counts={};for(const s of allowedStatuses){const r=await pool.query("SELECT COUNT(*)::int c FROM leads WHERE status=$1",[s]);counts[s]=r.rows[0].c;}
  const [total,disb,payout,pending,follow]=await Promise.all([
    pool.query("SELECT COUNT(*)::int c FROM leads"),pool.query("SELECT COALESCE(SUM(disb),0) n FROM leads"),pool.query("SELECT COALESCE(SUM(net_payout),0) n FROM payments"),pool.query("SELECT COUNT(*)::int c FROM payments WHERE payment_status!='Paid'"),pool.query("SELECT COUNT(*)::int c FROM leads WHERE follow_date=$1",[new Date().toISOString().slice(0,10)])
  ]);
  res.json({total:total.rows[0].c,counts,disbursement:Number(disb.rows[0].n),payout:Number(payout.rows[0].n),pending:pending.rows[0].c,follow:follow.rows[0].c});
}catch(e){console.error(e);res.status(500).json({error:"Database error"});}});

app.get("/api/leads",auth,async(req,res)=>{try{
  const {q="",status="",connector=""}=req.query;let sql="SELECT * FROM leads WHERE 1=1",p=[];
  if(q){p.push(`%${String(q).toLowerCase()}%`);sql+=` AND (LOWER(customer) LIKE $${p.length} OR mobile LIKE $${p.length} OR LOWER(appno) LIKE $${p.length})`;}
  if(status){p.push(status);sql+=` AND status=$${p.length}`;}if(connector){p.push(`%${String(connector).toLowerCase()}%`);sql+=` AND LOWER(connector) LIKE $${p.length}`;}
  sql+=" ORDER BY created_at DESC";res.json((await pool.query(sql,p)).rows);
}catch(e){console.error(e);res.status(500).json({error:"Database error"});}});

app.post("/api/leads",auth,async(req,res)=>{try{
  const b=req.body;if(!b.customer)return res.status(400).json({error:"Customer Name is required"});const id=String(b.id||crypto.randomUUID());
  const r=await pool.query(`INSERT INTO leads(id,customer,mobile,email,banker,connector,bank,appno,loan_account,status,loan_amount,sanction_amount,disb,follow_date,remark) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,[id,String(b.customer),String(b.mobile||""),String(b.email||""),String(b.banker||""),String(b.connector||""),String(b.bank||""),String(b.appno||""),String(b.loan_account||""),allowedStatuses.includes(b.status)?b.status:"New",Number(b.loan_amount||0),Number(b.sanction_amount||0),Number(b.disb||0),String(b.follow_date||""),String(b.remark||"")]);
  res.json(r.rows[0]);
}catch(e){console.error(e);res.status(500).json({error:"Could not save lead"});}});

app.put("/api/leads/:id",auth,async(req,res)=>{try{
  const old=(await pool.query("SELECT * FROM leads WHERE id=$1",[req.params.id])).rows[0];if(!old)return res.status(404).json({error:"Lead not found"});const b=req.body;
  const x={customer:b.customer??old.customer,mobile:b.mobile??old.mobile,email:b.email??old.email,banker:b.banker??old.banker,connector:b.connector??old.connector,bank:b.bank??old.bank,appno:b.appno??old.appno,loan_account:b.loan_account??old.loan_account,status:allowedStatuses.includes(b.status)?b.status:old.status,loan_amount:b.loan_amount??old.loan_amount,sanction_amount:b.sanction_amount??old.sanction_amount,disb:b.disb??old.disb,follow_date:b.follow_date??old.follow_date,remark:b.remark??old.remark};
  const r=await pool.query(`UPDATE leads SET customer=$1,mobile=$2,email=$3,banker=$4,connector=$5,bank=$6,appno=$7,loan_account=$8,status=$9,loan_amount=$10,sanction_amount=$11,disb=$12,follow_date=$13,remark=$14,updated_at=NOW() WHERE id=$15 RETURNING *`,[x.customer,x.mobile,x.email,x.banker,x.connector,x.bank,x.appno,x.loan_account,x.status,Number(x.loan_amount||0),Number(x.sanction_amount||0),Number(x.disb||0),x.follow_date,x.remark,req.params.id]);res.json(r.rows[0]);
}catch(e){console.error(e);res.status(500).json({error:"Could not update lead"});}});

app.patch("/api/leads/:id/status",auth,async(req,res)=>{try{const s=String(req.body.status||"");if(!allowedStatuses.includes(s))return res.status(400).json({error:"Invalid status"});const r=await pool.query("UPDATE leads SET status=$1,updated_at=NOW() WHERE id=$2 RETURNING *",[s,req.params.id]);if(!r.rowCount)return res.status(404).json({error:"Lead not found"});res.json(r.rows[0]);}catch(e){console.error(e);res.status(500).json({error:"Database error"});}});

app.get("/api/payments",auth,async(req,res)=>{try{res.json((await pool.query(`SELECT p.*,l.customer,l.appno,l.disb FROM payments p LEFT JOIN leads l ON l.id=p.lead_id ORDER BY p.created_at DESC`)).rows);}catch(e){console.error(e);res.status(500).json({error:"Database error"});}});
app.post("/api/payments",auth,async(req,res)=>{try{const b=req.body;const l=(await pool.query("SELECT * FROM leads WHERE id=$1",[String(b.lead_id||"")])).rows[0];if(!l)return res.status(400).json({error:"Lead not found"});if(l.status!=="Disbursed")return res.status(400).json({error:"Only Disbursed leads can be paid"});const percent=Number(b.payout_percent||0),net=Number((Number(l.disb)*percent/100).toFixed(2)),id=crypto.randomUUID();const r=await pool.query(`INSERT INTO payments(id,lead_id,connector,payout_percent,net_payout,payment_date,payment_mode,utr,payment_status,remark) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,[id,l.id,String(b.connector||l.connector||""),percent,net,String(b.payment_date||""),String(b.payment_mode||"Bank Transfer"),String(b.utr||""),b.payment_status==="Paid"?"Paid":"Pending",String(b.remark||"")]);res.json(r.rows[0]);}catch(e){console.error(e);res.status(500).json({error:"Could not save payment"});}});
app.get("/health",async(req,res)=>{try{await pool.query("SELECT 1");res.json({ok:true,database:"postgresql"});}catch{res.status(503).json({ok:false});}});

initDb().then(()=>app.listen(PORT,()=>console.log(`Loan CRM v4.1 running on port ${PORT}`))).catch(e=>{console.error("Database initialization failed:",e);process.exit(1);});
