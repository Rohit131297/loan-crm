import express from "express";
import Database from "better-sqlite3";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import fs from "fs";
import path from "path";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

app.use(express.json({limit:"1mb"}));
app.use(express.static("public"));

// Render's normal filesystem is ephemeral. Set DB_PATH=/data/loancrm.sqlite
// and mount a persistent Render disk at /data so leads survive restarts/redeploys.
// Local development continues to use ./loancrm.sqlite when DB_PATH is not set.
const DB_PATH = process.env.DB_PATH || path.resolve("loancrm.sqlite");
const dbDir = path.dirname(DB_PATH);
if (dbDir && dbDir !== ".") fs.mkdirSync(dbDir, {recursive:true});
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mobile TEXT UNIQUE NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS otps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mobile TEXT NOT NULL,
  otp_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  used INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS leads (
  id TEXT PRIMARY KEY,
  customer TEXT NOT NULL,
  mobile TEXT NOT NULL,
  email TEXT DEFAULT '',
  banker TEXT DEFAULT '',
  connector TEXT DEFAULT '',
  bank TEXT DEFAULT '',
  appno TEXT DEFAULT '',
  loan_account TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'New',
  loan_amount REAL NOT NULL DEFAULT 0,
  sanction_amount REAL NOT NULL DEFAULT 0,
  disb REAL NOT NULL DEFAULT 0,
  follow_date TEXT DEFAULT '',
  remark TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  lead_id TEXT NOT NULL,
  connector TEXT DEFAULT '',
  payout_percent REAL NOT NULL DEFAULT 0,
  net_payout REAL NOT NULL DEFAULT 0,
  payment_date TEXT DEFAULT '',
  payment_mode TEXT DEFAULT '',
  utr TEXT DEFAULT '',
  payment_status TEXT NOT NULL DEFAULT 'Pending',
  remark TEXT DEFAULT '',
  created_at TEXT NOT NULL
);
`);

const allowedStatuses = ["New","Login","Sanction","Disbursed","Rejected"];
function now(){ return new Date().toISOString(); }
function safeEqual(value, expected) {
  const valueBuffer = Buffer.from(value);
  const expectedBuffer = Buffer.from(expected);
  return valueBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(valueBuffer, expectedBuffer);
}

app.post("/api/auth/login", (req,res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  if (!ADMIN_USERNAME || !ADMIN_PASSWORD) return res.status(500).json({error:"Login is not configured. Set ADMIN_USERNAME and ADMIN_PASSWORD in Render."});
  if (!safeEqual(username, ADMIN_USERNAME) || !safeEqual(password, ADMIN_PASSWORD)) return res.status(401).json({error:"Invalid user ID or password"});
  const token = jwt.sign({username}, JWT_SECRET, {expiresIn:"12h"});
  res.json({ok:true,token});
});

function auth(req,res,next){
  try {
    const h=req.headers.authorization||"";
    const token=h.startsWith("Bearer ")?h.slice(7):"";
    const user=jwt.verify(token,JWT_SECRET);
    if (user.username !== ADMIN_USERNAME) throw new Error("Invalid session");
    req.user=user; next();
  } catch { res.status(401).json({error:"Login required"}); }
}

app.get("/api/me",auth,(req,res)=>res.json({username:req.user.username}));

app.get("/api/dashboard",auth,(req,res)=>{
  const counts={};
  for(const s of allowedStatuses) counts[s]=db.prepare("SELECT COUNT(*) c FROM leads WHERE status=?").get(s).c;
  const disb=db.prepare("SELECT COALESCE(SUM(disb),0) n FROM leads").get().n;
  const payout=db.prepare("SELECT COALESCE(SUM(net_payout),0) n FROM payments").get().n;
  const pending=db.prepare("SELECT COUNT(*) c FROM payments WHERE payment_status!='Paid'").get().c;
  const today=new Date().toISOString().slice(0,10);
  const follow=db.prepare("SELECT COUNT(*) c FROM leads WHERE follow_date=?").get(today).c;
  res.json({total:db.prepare("SELECT COUNT(*) c FROM leads").get().c,counts,disbursement:disb,payout,pending,follow});
});

app.get("/api/leads",auth,(req,res)=>{
  const {q="",status="",connector=""}=req.query;
  let sql="SELECT * FROM leads WHERE 1=1", p=[];
  if(q){sql+=" AND (lower(customer) LIKE ? OR mobile LIKE ? OR lower(appno) LIKE ?)";const x="%"+String(q).toLowerCase()+"%";p.push(x,x,x)}
  if(status){sql+=" AND status=?";p.push(status)}
  if(connector){sql+=" AND lower(connector) LIKE ?";p.push("%"+String(connector).toLowerCase()+"%")}
  sql+=" ORDER BY created_at DESC";
  res.json(db.prepare(sql).all(...p));
});

app.post("/api/leads",auth,(req,res)=>{
  const b=req.body;
  if(!b.customer) return res.status(400).json({error:"Customer Name is required"});
  const id=String(b.id||crypto.randomUUID()), t=now();
  db.prepare(`INSERT INTO leads(id,customer,mobile,email,banker,connector,bank,appno,loan_account,status,loan_amount,sanction_amount,disb,follow_date,remark,created_at,updated_at)
  VALUES(@id,@customer,@mobile,@email,@banker,@connector,@bank,@appno,@loan_account,@status,@loan_amount,@sanction_amount,@disb,@follow_date,@remark,@created_at,@updated_at)`).run({
    id,customer:String(b.customer),mobile:String(b.mobile||""),email:String(b.email||""),banker:String(b.banker||""),connector:String(b.connector||""),
    bank:String(b.bank||""),appno:String(b.appno||""),loan_account:String(b.loan_account||""),status:allowedStatuses.includes(b.status)?b.status:"New",
    loan_amount:Number(b.loan_amount||0),sanction_amount:Number(b.sanction_amount||0),disb:Number(b.disb||0),follow_date:String(b.follow_date||""),
    remark:String(b.remark||""),created_at:t,updated_at:t
  });
  res.json(db.prepare("SELECT * FROM leads WHERE id=?").get(id));
});

app.put("/api/leads/:id",auth,(req,res)=>{
  const b=req.body;
  const old=db.prepare("SELECT * FROM leads WHERE id=?").get(req.params.id);
  if(!old) return res.status(404).json({error:"Lead not found"});
  const x={...old,...b, status:allowedStatuses.includes(b.status)?b.status:old.status, updated_at:now()};
  db.prepare(`UPDATE leads SET customer=@customer,mobile=@mobile,email=@email,banker=@banker,connector=@connector,bank=@bank,appno=@appno,
  loan_account=@loan_account,status=@status,loan_amount=@loan_amount,sanction_amount=@sanction_amount,disb=@disb,follow_date=@follow_date,remark=@remark,updated_at=@updated_at WHERE id=@id`).run(x);
  res.json(db.prepare("SELECT * FROM leads WHERE id=?").get(req.params.id));
});

app.patch("/api/leads/:id/status",auth,(req,res)=>{
  const s=String(req.body.status||"");
  if(!allowedStatuses.includes(s)) return res.status(400).json({error:"Invalid status"});
  const r=db.prepare("UPDATE leads SET status=?,updated_at=? WHERE id=?").run(s,now(),req.params.id);
  if(!r.changes) return res.status(404).json({error:"Lead not found"});
  res.json(db.prepare("SELECT * FROM leads WHERE id=?").get(req.params.id));
});

app.get("/api/payments",auth,(req,res)=>{
  res.json(db.prepare(`SELECT p.*,l.customer,l.appno,l.disb FROM payments p LEFT JOIN leads l ON l.id=p.lead_id ORDER BY p.created_at DESC`).all());
});

app.post("/api/payments",auth,(req,res)=>{
  const b=req.body, lead=db.prepare("SELECT * FROM leads WHERE id=?").get(String(b.lead_id||""));
  if(!lead) return res.status(400).json({error:"Lead not found"});
  if(lead.status!=="Disbursed") return res.status(400).json({error:"Only Disbursed leads can be paid"});
  const percent=Number(b.payout_percent||0), net=Number((lead.disb*percent/100).toFixed(2)), id=crypto.randomUUID();
  db.prepare(`INSERT INTO payments(id,lead_id,connector,payout_percent,net_payout,payment_date,payment_mode,utr,payment_status,remark,created_at)
  VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(id,lead.id,String(b.connector||lead.connector),percent,net,String(b.payment_date||""),String(b.payment_mode||"Bank Transfer"),String(b.utr||""),b.payment_status==="Paid"?"Paid":"Pending",String(b.remark||""),now());
  res.json(db.prepare("SELECT * FROM payments WHERE id=?").get(id));
});

app.listen(PORT,()=>console.log(`Loan CRM v4 running at http://localhost:${PORT} using database ${DB_PATH}`));
