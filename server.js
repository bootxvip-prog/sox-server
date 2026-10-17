// SO X backend - بدون أي مكتبات خارجية. يحتاج Node.js 22 أو أحدث.
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || "";
const ROOT = __dirname;
const PUB = path.join(ROOT, "public");
const DATA = process.env.DATA_DIR || ROOT;
const UP = path.join(DATA, "uploads");
fs.mkdirSync(UP, { recursive: true });

const db = new DatabaseSync(path.join(DATA, "sox.db"));
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, salt TEXT, hash TEXT, created INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user INTEGER, created INTEGER);
CREATE TABLE IF NOT EXISTS cards(id INTEGER PRIMARY KEY, user INTEGER, name TEXT, price REAL, img TEXT, created INTEGER);
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, ip TEXT, name TEXT, text TEXT, hidden INTEGER DEFAULT 0, created INTEGER);
CREATE TABLE IF NOT EXISTS reports(comment INTEGER, ip TEXT, PRIMARY KEY(comment, ip));
CREATE TABLE IF NOT EXISTS likes(ip TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS bans(ip TEXT PRIMARY KEY, until INTEGER, reason TEXT);
CREATE TABLE IF NOT EXISTS strikes(ip TEXT PRIMARY KEY, n INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS visits(ip TEXT, t INTEGER);
`);

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const ipOf = (req) => sha((req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim()).slice(0, 24);
const clean = (s, n) => String(s || "").replace(/[<>&"'`\u0000-\u001f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const BAD = /(https?:\/\/|www\.|<script|javascript:|onerror=|union\s+select|drop\s+table)/i;

// ---------- حماية: حد الطلبات + الحظر ----------
const hits = new Map();
function limited(ip, max = 60, win = 60000) {
  const n = Date.now(), a = (hits.get(ip) || []).filter((t) => n - t < win);
  a.push(n); hits.set(ip, a);
  return a.length > max;
}
setInterval(() => { for (const [k, v] of hits) if (!v.some((t) => Date.now() - t < 60000)) hits.delete(k); }, 60000);

function isBanned(ip) {
  const r = db.prepare("SELECT until FROM bans WHERE ip=?").get(ip);
  return r && r.until > Date.now();
}
function strike(ip, reason) {
  db.prepare("INSERT INTO strikes(ip,n) VALUES(?,1) ON CONFLICT(ip) DO UPDATE SET n=n+1").run(ip);
  const s = db.prepare("SELECT n FROM strikes WHERE ip=?").get(ip);
  if (s.n >= 3) {
    db.prepare("INSERT OR REPLACE INTO bans(ip,until,reason) VALUES(?,?,?)").run(ip, Date.now() + 864e5, reason);
    db.prepare("UPDATE strikes SET n=0 WHERE ip=?").run(ip);
  }
}

// ---------- المتصلون الآن (SSE) ----------
const clients = new Set();
const push = (ev, data) => { for (const c of clients) c.write(`event: ${ev}\ndata: ${JSON.stringify(data)}\n\n`); };

// ---------- أدوات ----------
const json = (res, code, obj) => {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(obj));
};
function body(req, max = 2.5e6) {
  return new Promise((ok, no) => {
    let d = "", n = 0;
    req.on("data", (c) => { n += c.length; if (n > max) { no(new Error("big")); req.destroy(); } else d += c; });
    req.on("end", () => { try { ok(JSON.parse(d || "{}")); } catch { no(new Error("json")); } });
  });
}
function authUser(req) {
  const t = (req.headers.authorization || "").replace("Bearer ", "");
  if (!t) return null;
  const s = db.prepare("SELECT user FROM sessions WHERE token=? AND created>?").get(sha(t), Date.now() - 30 * 864e5);
  return s ? s.user : null;
}
function hashPw(pw, salt) { return crypto.scryptSync(pw, salt, 64).toString("hex"); }
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp", ".svg": "image/svg+xml", ".ico": "image/x-icon" };

function serveFile(res, base, rel) {
  const p = path.normalize(path.join(base, rel));
  if (!p.startsWith(base) || !fs.existsSync(p) || fs.statSync(p).isDirectory()) { res.writeHead(404); return res.end("404"); }
  res.writeHead(200, { "Content-Type": MIME[path.extname(p)] || "application/octet-stream", "Cache-Control": "public, max-age=300" });
  fs.createReadStream(p).pipe(res);
}

// ---------- الخادم ----------
const server = http.createServer(async (req, res) => {
  const ip = ipOf(req);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'");

  if (isBanned(ip)) return json(res, 403, { error: "تم حظرك مؤقتاً بسبب مخالفات متكررة." });
  if (limited(ip)) return json(res, 429, { error: "طلبات كثيرة، انتظر قليلاً." });

  const url = new URL(req.url, "http://x");
  const p = url.pathname;

  try {
    if (req.method === "GET" && p === "/api/live") {
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
      clients.add(res);
      db.prepare("INSERT INTO visits(ip,t) VALUES(?,?)").run(ip, Date.now());
      push("visit", { t: Date.now() });          // إشعار دخول زائر جديد
      push("viewers", { now: clients.size });
      req.on("close", () => { clients.delete(res); push("viewers", { now: clients.size }); });
      return;
    }
    if (req.method === "GET" && p === "/api/stats") {
      const day = db.prepare("SELECT COUNT(DISTINCT ip) c FROM visits WHERE t>?").get(Date.now() - 864e5).c;
      const likes = db.prepare("SELECT COUNT(*) c FROM likes").get().c;
      return json(res, 200, { now: clients.size, day, likes });
    }
    if (req.method === "POST" && p === "/api/like") {
      const had = db.prepare("SELECT 1 FROM likes WHERE ip=?").get(ip);
      if (had) db.prepare("DELETE FROM likes WHERE ip=?").run(ip); else db.prepare("INSERT INTO likes(ip) VALUES(?)").run(ip);
      return json(res, 200, { liked: !had, likes: db.prepare("SELECT COUNT(*) c FROM likes").get().c });
    }
    if (req.method === "GET" && p === "/api/comments") {
      return json(res, 200, db.prepare("SELECT id,name,text,created FROM comments WHERE hidden=0 ORDER BY id DESC LIMIT 100").all());
    }
    if (req.method === "POST" && p === "/api/comments") {
      if (limited(ip + "c", 3, 60000)) return json(res, 429, { error: "انتظر قليلاً قبل تعليق جديد." });
      const b = await body(req, 5000);
      const name = clean(b.name, 30), text = clean(b.text, 300);
      if (!name || !text) return json(res, 400, { error: "اكتب الاسم والتعليق." });
      if (BAD.test(b.name + " " + b.text) || /(.)\1{9,}/.test(text)) { strike(ip, "محتوى مشبوه"); return json(res, 400, { error: "تم رصد محتوى مخالف." }); }
      db.prepare("INSERT INTO comments(ip,name,text,created) VALUES(?,?,?,?)").run(ip, name, text, Date.now());
      return json(res, 201, { ok: true });
    }
    if (req.method === "POST" && p === "/api/report") {
      const b = await body(req, 1000);
      const id = parseInt(b.id, 10);
      const c = db.prepare("SELECT ip FROM comments WHERE id=?").get(id);
      if (!c) return json(res, 404, { error: "غير موجود" });
      db.prepare("INSERT OR IGNORE INTO reports(comment,ip) VALUES(?,?)").run(id, ip);
      const n = db.prepare("SELECT COUNT(*) c FROM reports WHERE comment=?").get(id).c;
      if (n >= 3) { db.prepare("UPDATE comments SET hidden=1 WHERE id=?").run(id); strike(c.ip, "بلاغات من المستخدمين"); }
      return json(res, 200, { ok: true });
    }
    if (req.method === "POST" && p === "/api/register") {
      if (limited(ip + "r", 5, 3600000)) return json(res, 429, { error: "محاولات كثيرة." });
      const b = await body(req, 3000);
      const name = clean(b.name, 40), email = clean(b.email, 80).toLowerCase(), pw = String(b.password || "");
      if (name.length < 3 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || pw.length < 8) return json(res, 400, { error: "تأكد من الاسم والبريد وكلمة مرور من 8 أحرف على الأقل." });
      if (db.prepare("SELECT 1 FROM users WHERE email=?").get(email)) return json(res, 409, { error: "البريد مسجل بالفعل." });
      const salt = crypto.randomBytes(16).toString("hex");
      db.prepare("INSERT INTO users(name,email,salt,hash,created) VALUES(?,?,?,?,?)").run(name, email, salt, hashPw(pw, salt), Date.now());
      return json(res, 201, { ok: true });
    }
    if (req.method === "POST" && p === "/api/login") {
      if (limited(ip + "l", 8, 600000)) return json(res, 429, { error: "محاولات كثيرة، انتظر 10 دقائق." });
      const b = await body(req, 3000);
      const u = db.prepare("SELECT * FROM users WHERE email=?").get(clean(b.email, 80).toLowerCase());
      const ok = u && crypto.timingSafeEqual(Buffer.from(hashPw(String(b.password || ""), u.salt)), Buffer.from(u.hash));
      if (!ok) { return json(res, 401, { error: "بيانات الدخول غير صحيحة." }); }
      const token = crypto.randomBytes(32).toString("hex");
      db.prepare("INSERT INTO sessions(token,user,created) VALUES(?,?,?)").run(sha(token), u.id, Date.now());
      return json(res, 200, { token, name: u.name });
    }
    if (req.method === "GET" && p === "/api/cards") {
      return json(res, 200, db.prepare("SELECT c.id,c.name,c.price,c.img,u.name AS worker FROM cards c JOIN users u ON u.id=c.user ORDER BY c.id DESC LIMIT 60").all());
    }
    if (req.method === "POST" && p === "/api/cards") {
      const uid = authUser(req);
      if (!uid) return json(res, 401, { error: "سجّل الدخول أولاً." });
      const b = await body(req);
      const name = clean(b.name, 50), price = Number(b.price);
      const m = /^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String(b.image || ""));
      if (!name || !(price > 0) || price > 1e6 || !m) return json(res, 400, { error: "أكمل الاسم والسعر وصورة صحيحة." });
      const buf = Buffer.from(m[2], "base64");
      if (buf.length > 1.5e6) return json(res, 400, { error: "الصورة أكبر من 1.5 ميجا." });
      const file = crypto.randomBytes(12).toString("hex") + "." + (m[1] === "jpeg" ? "jpg" : m[1]);
      fs.writeFileSync(path.join(UP, file), buf);
      db.prepare("INSERT INTO cards(user,name,price,img,created) VALUES(?,?,?,?,?)").run(uid, name, price, "/uploads/" + file, Date.now());
      return json(res, 201, { ok: true });
    }
    if (p.startsWith("/api/admin/")) {
      if (!ADMIN_KEY || req.headers["x-admin-key"] !== ADMIN_KEY) { strike(ip, "محاولة دخول للإدارة"); return json(res, 403, { error: "ممنوع" }); }
      if (req.method === "GET" && p === "/api/admin/overview") {
        return json(res, 200, {
          users: db.prepare("SELECT COUNT(*) c FROM users").get().c,
          cards: db.prepare("SELECT id,name,price,img FROM cards ORDER BY id DESC LIMIT 100").all(),
          comments: db.prepare("SELECT id,name,text,hidden FROM comments ORDER BY id DESC LIMIT 100").all(),
          bans: db.prepare("SELECT ip,until,reason FROM bans WHERE until>?").all(Date.now()),
        });
      }
      if (req.method === "POST") {
        const b = await body(req, 2000);
        if (p === "/api/admin/delete-card") db.prepare("DELETE FROM cards WHERE id=?").run(parseInt(b.id, 10));
        else if (p === "/api/admin/delete-comment") db.prepare("DELETE FROM comments WHERE id=?").run(parseInt(b.id, 10));
        else if (p === "/api/admin/unban") db.prepare("DELETE FROM bans WHERE ip=?").run(String(b.ip));
        else return json(res, 404, { error: "غير موجود" });
        return json(res, 200, { ok: true });
      }
    }
    if (p.startsWith("/uploads/")) return serveFile(res, UP, p.slice(9));
    if (req.method === "GET") return serveFile(res, PUB, p === "/" ? "index.html" : p.slice(1));
    json(res, 404, { error: "غير موجود" });
  } catch (e) {
    json(res, 400, { error: "طلب غير صالح" });
  }
});

process.on("uncaughtException", (e) => console.error("خطأ:", e.message));
process.on("unhandledRejection", (e) => console.error("خطأ:", e));
setInterval(() => db.prepare("DELETE FROM visits WHERE t<?").run(Date.now() - 2 * 864e5), 3600000);
server.listen(PORT, () => console.log("SO X يعمل على المنفذ " + PORT));
