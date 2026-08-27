import express from "express";
import Database from "better-sqlite3";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be set and at least 32 characters long");
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 10) throw new Error("ADMIN_PASSWORD must be set and at least 10 characters long");

app.use(express.json({limit:"1mb"}));
app.use(express.static("public"));
const db = new Database("loancrm.sqlite");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'sales',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS leads (
 id TEXT PRIMARY KEY, customer TEXT NOT NULL, mobile TEXT NOT NULL, email TEXT DEFAULT '', banker TEXT DEFAULT '', connector TEXT DEFAULT '', bank TEXT DEFAULT '', appno TEXT DEFAULT '', loan_account TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'New', loan_amount REAL NOT NULL DEFAULT 0, sanction_amount REAL NOT NULL DEFAULT 0, disb REAL NOT NULL DEFAULT 0, follow_date TEXT DEFAULT '', remark TEXT DEFAULT '', assigned_to TEXT DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS payments (
 id TEXT PRIMARY KEY, lead_id TEXT NOT NULL, connector TEXT DEFAULT '', payout_percent REAL NOT NULL DEFAULT 0, net_payout REAL NOT NULL DEFAULT 0, payment_date TEXT DEFAULT '', payment_mode TEXT DEFAULT '', utr TEXT DEFAULT '', payment_status TEXT NOT NULL DEFAULT 'Pending', remark TEXT DEFAULT '', created_at TEXT NOT NULL
);
`);
try { db.exec("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'sales'"); } catch {}
try { db.exec("ALTER TABLE leads ADD COLUMN assigned_to TEXT DEFAULT ''"); } catch {}
const allowedStatuses=["New","Login","Sanction","Disbursed","Rejected"];
const hash=s=>crypto.createHash("sha256").update(s).digest("hex");
const now=()=>new Date().toISOString();
const existingUser=db.prepare("SELECT id FROM users WHERE username=?").get(ADMIN_USERNAME);
if(!existingUser) db.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)").run(ADMIN_USERNAME,hash(ADMIN_PASSWORD),"admin");
app.post("/api/auth/login",(req,res)=>{const username=String(req.body.username||"").trim();const password=String(req.body.password||"");const user=db.prepare("SELECT * FROM users WHERE username=?").get(username);if(!user||hash(password)!==user.password_hash)return res.status(401).json({error:"Invalid username or password"});const token=jwt.sign({id:user.id,username:user.username,role:user.role},JWT_SECRET,{expiresIn:"12h"});res.json({ok:true,token,username:user.username,role:user.role})});
function auth(req,res,next){try{const h=req.headers.authorization||"";const token=h.startsWith("Bearer ")?h.slice(7):"";req.user=jwt.verify(token,JWT_SECRET);next()}catch{res.status(401).json({error:"Login required"})}}
function adminOnly(req,res,next){if(req.user.role!=="admin")return res.status(403).json({error:"Admin access required"});next()}
app.get("/api/me",auth,(req,res)=>res.json({username:req.user.username,role:req.user.role}));
app.get("/api/users",auth,adminOnly,(req,res)=>res.json(db.prepare("SELECT id,username,role,created_at FROM users ORDER BY id DESC").all()));
app.post("/api/users",auth,adminOnly,(req,res)=>{const username=String(req.body.username||"").trim();const password=String(req.body.password||"");const role=req.body.role==="admin"?"admin":"sales";if(!username||password.length<10)return res.status(400).json({error:"Username and password (minimum 10 characters) are required"});try{const r=db.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)").run(username,hash(password),role);res.json(db.prepare("SELECT id,username,role,created_at FROM users WHERE id=?").get(r.lastInsertRowid))}catch{res.status(400).json({error:"Username already exists"})}});
app.patch("/api/users/:id/password",auth,(req,res)=>{const id=Number(req.params.id);if(req.user.role!=="admin"&&req.user.id!==id)return res.status(403).json({error:"Not allowed"});const password=String(req.body.password||"");if(password.length<10)return res.status(400).json({error:"Password must be at least 10 characters"});const r=db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(hash(password),id);if(!r.changes)return res.status(404).json({error:"User not found"});res.json({ok:true})});
app.delete("/api/users/:id",auth,adminOnly,(req,res)=>{const id=Number(req.params.id);if(id===req.user.id)return res.status(400).json({error:"You cannot delete yourself"});const r=db.prepare("DELETE FROM users WHERE id=?").run(id);if(!r.changes)return res.status(404).json({error:"User not found"});res.json({ok:true})});
function leadScope(req){return req.user.role==="admin"?"":` AND assigned_to=${JSON.stringify(req.user.username)}`}
app.get("/api/dashboard",auth,(req,res)=>{const scope=leadScope(req),counts={};for(const s of allowedStatuses)counts[s]=db.prepare(`SELECT COUNT(*) c FROM leads WHERE status=?${scope}`).get(s).c;const disb=db.prepare(`SELECT COALESCE(SUM(disb),0) n FROM leads WHERE 1=1${scope}`).get().n;const payout=db.prepare("SELECT COALESCE(SUM(p.net_payout),0) n FROM payments p LEFT JOIN leads l ON l.id=p.lead_id WHERE 1=1"+(req.user.role==="admin"?"":` AND l.assigned_to=${JSON.stringify(req.user.username)}`)).get().n;const pending=db.prepare("SELECT COUNT(*) c FROM payments p LEFT JOIN leads l ON l.id=p.lead_id WHERE p.payment_status!='Paid'"+(req.user.role==="admin"?"":` AND l.assigned_to=${JSON.stringify(req.user.username)}`)).get().c;res.json({total:db.prepare(`SELECT COUNT(*) c FROM leads WHERE 1=1${scope}`).get().c,counts,disbursement:disb,payout,pending})});
app.get("/api/leads",auth,(req,res)=>{const{q="",status="",connector=""}=req.query;let sql=`SELECT * FROM leads WHERE 1=1${leadScope(req)}`,p=[];if(q){sql+=" AND (lower(customer) LIKE ? OR mobile LIKE ? OR lower(appno) LIKE ?)";const x="%"+String(q).toLowerCase()+"%";p.push(x,x,x)}if(status){sql+=" AND status=?";p.push(status)}if(connector){sql+=" AND lower(connector) LIKE ?";p.push("%"+String(connector).toLowerCase()+"%")}sql+=" ORDER BY created_at DESC";res.json(db.prepare(sql).all(...p))});
app.post("/api/leads",auth,(req,res)=>{const b=req.body;if(!b.customer)return res.status(400).json({error:"Customer Name is required"});const id=String(b.id||crypto.randomUUID()),t=now(),assigned=req.user.role==="admin"?String(b.assigned_to||""):req.user.username;db.prepare(`INSERT INTO leads(id,customer,mobile,email,banker,connector,bank,appno,loan_account,status,loan_amount,sanction_amount,disb,follow_date,remark,assigned_to,created_at,updated_at) VALUES(@id,@customer,@mobile,@email,@banker,@connector,@bank,@appno,@loan_account,@status,@loan_amount,@sanction_amount,@disb,@follow_date,@remark,@assigned_to,@created_at,@updated_at)`).run({id,customer:String(b.customer),mobile:String(b.mobile||""),email:String(b.email||""),banker:String(b.banker||""),connector:String(b.connector||""),bank:String(b.bank||""),appno:String(b.appno||""),loan_account:String(b.loan_account||""),status:allowedStatuses.includes(b.status)?b.status:"New",loan_amount:Number(b.loan_amount||0),sanction_amount:Number(b.sanction_amount||0),disb:Number(b.disb||0),follow_date:String(b.follow_date||""),remark:String(b.remark||""),assigned_to:assigned,created_at:t,updated_at:t});res.json(db.prepare("SELECT * FROM leads WHERE id=?").get(id))});
app.put("/api/leads/:id",auth,(req,res)=>{const b=req.body,old=db.prepare(`SELECT * FROM leads WHERE id=?${leadScope(req)}`).get(req.params.id);if(!old)return res.status(404).json({error:"Lead not found"});const x={...old,...b,status:allowedStatuses.includes(b.status)?b.status:old.status,assigned_to:req.user.role==="admin"?String(b.assigned_to??old.assigned_to):old.assigned_to,updated_at:now()};db.prepare(`UPDATE leads SET customer=@customer,mobile=@mobile,email=@email,banker=@banker,connector=@connector,bank=@bank,appno=@appno,loan_account=@loan_account,status=@status,loan_amount=@loan_amount,sanction_amount=@sanction_amount,disb=@disb,follow_date=@follow_date,remark=@remark,assigned_to=@assigned_to,updated_at=@updated_at WHERE id=@id`).run(x);res.json(db.prepare("SELECT * FROM leads WHERE id=?").get(req.params.id))});
app.patch("/api/leads/:id/status",auth,(req,res)=>{const s=String(req.body.status||"");if(!allowedStatuses.includes(s))return res.status(400).json({error:"Invalid status"});const r=db.prepare(`UPDATE leads SET status=?,updated_at=? WHERE id=?${leadScope(req)}`).run(s,now(),req.params.id);if(!r.changes)return res.status(404).json({error:"Lead not found"});res.json(db.prepare("SELECT * FROM leads WHERE id=?").get(req.params.id))});
app.get("/api/payments",auth,(req,res)=>{const scope=req.user.role==="admin"?"":` AND l.assigned_to=${JSON.stringify(req.user.username)}`;res.json(db.prepare(`SELECT p.*,l.customer,l.appno,l.disb FROM payments p LEFT JOIN leads l ON l.id=p.lead_id WHERE 1=1${scope} ORDER BY p.created_at DESC`).all())});
app.post("/api/payments",auth,(req,res)=>{const b=req.body,lead=db.prepare(`SELECT * FROM leads WHERE id=?${leadScope(req)}`).get(String(b.lead_id||""));if(!lead)return res.status(400).json({error:"Lead not found"});if(lead.status!=="Disbursed")return res.status(400).json({error:"Only Disbursed leads can be paid"});const percent=Number(b.payout_percent||0),net=Number((lead.disb*percent/100).toFixed(2)),id=crypto.randomUUID();db.prepare(`INSERT INTO payments(id,lead_id,connector,payout_percent,net_payout,payment_date,payment_mode,utr,payment_status,remark,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(id,lead.id,String(b.connector||lead.connector),percent,net,String(b.payment_date||""),String(b.payment_mode||"Bank Transfer"),String(b.utr||""),b.payment_status==="Paid"?"Paid":"Pending",String(b.remark||""),now());res.json(db.prepare("SELECT * FROM payments WHERE id=?").get(id))});
app.listen(PORT,()=>console.log(`Loan CRM v4 running at http://localhost:${PORT}`));