// app.js — IAssistant V5 (Final, minimal)
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("cookie-session");
const bcrypt = require("bcrypt");
const { v4: uuid } = require("uuid");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const csurf = require("csurf");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret";
const IS_HTTPS = /^https:\/\//i.test(BASE_URL) || process.env.NODE_ENV === "production";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "ia.db");

const ADMIN_EMAIL = "mdjaroun0@gmail.com";
const ADMIN_EXTRA_PASSWORD = "20082004";

const DEFAULT_WEBHOOK = "https://discord.com/api/webhooks/1404238604519215104/U6UV4C72ojsFJgjV5vWdghmLnpxz3_tQcBrX0qeEDJ2nxWqx_Z6g6FO42D7pXhbCZryY";
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || DEFAULT_WEBHOOK;
async function notifyDiscord(message) {
  if (!DISCORD_WEBHOOK_URL) return;
  try {
    await fetch(DISCORD_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content: message })
    });
  } catch (e) { console.error("Discord webhook error:", e.message); }
}

const app = express();
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(rateLimit({ windowMs: 60_000, max: 200 }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({ name: "ia_sid", keys: [SESSION_SECRET], httpOnly: true, sameSite: "lax", secure: IS_HTTPS, maxAge: 1000 * 60 * 60 * 24 * 30 }));
app.use(express.static("public"));

app.use((req, res, next) => { res.sendHtml = (html) => { res.set("Content-Type","text/html; charset=utf-8"); return res.send(html); }; next(); });
const csrf = csurf();

const brand = { blue: "#2563EB", green: "#10B981" };
function layout({ title = "IAssistant", description = "Assistant IA pour petites entreprises.", content = "" }) {
  const year = new Date().getFullYear();
  return `<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>${title}</title><meta name="description" content="${escapeHtml(description)}"/><script src="https://cdn.tailwindcss.com"></script><script>tailwind.config={theme:{extend:{colors:{brand:'${brand.blue}',accent:'${brand.green}'}}}}</script><style>:root{--brand:${brand.blue}}.btn{background:var(--brand);color:#fff;border-radius:.5rem;padding:.6rem 1rem}.card{background:#fff;border:1px solid #e5e7eb;border-radius:.75rem}</style></head><body class="bg-white text-gray-800"><header class="border-b"><div class="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between"><a href="/" class="flex items-center gap-3"><div style="width:34px;height:34px;background:var(--brand)" class="rounded-lg"></div><div><div class="font-semibold">IAssistant</div><div class="text-xs text-gray-500">Assistant IA pour petites entreprises</div></div></a><nav class="text-sm flex items-center gap-4"><a href="/" class="hover:underline">Accueil</a><a href="/pricing" class="hover:underline">Tarifs</a><a href="/contact" class="hover:underline">Contact</a><a href="/dashboard" class="hover:underline">Espace client</a></nav></div></header>${content}<footer class="border-t mt-16"><div class="max-w-6xl mx-auto px-4 py-8 text-sm text-gray-600 flex items-center justify-between"><div>© ${year} IAssistant</div><div class="flex gap-4"><a href="/privacy" class="hover:underline">Confidentialité</a><a href="/legal" class="hover:underline">Mentions légales</a></div></div></footer></body></html>`;
}
function csrfField(t){ return `<input type="hidden" name="_csrf" value="${t}">`; }
function requireAuth(req,res,next){ if(!req.session.userEmail) return res.redirect("/login"); next(); }
function escapeHtml(s=""){ return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/\"/g,"&quot;").replace(/'/g,"&#039;"); }

app.get("/", (req,res)=>{
  const content = `<section class="bg-gray-50"><div class="max-w-6xl mx-auto px-4 py-16 grid md:grid-cols-2 gap-8 items-center"><div><div class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-50 text-green-700 border border-green-200 mb-3">Première requête 100% gratuite</div><h1 class="text-4xl font-extrabold mb-4 text-blue-700">Déléguez vos tâches à IAssistant</h1><p class="text-gray-700 mb-6">Pour TPE et indépendants : e-mails, devis/factures, réseaux sociaux, synthèses… Vous soumettez, on exécute.</p><div class="flex gap-3 flex-wrap"><a href="/signup" class="btn">Commencer</a><a href="/contact" class="px-4 py-2 border rounded-md">Parler à un humain</a></div></div><div class="card p-6"><h3 class="font-semibold mb-3">Exemples</h3><ul class="text-sm text-gray-700 space-y-2"><li>✔️ Réponses e-mail</li><li>✔️ Devis & factures</li><li>✔️ Posts réseaux</li><li>✔️ Synthèses de RDV</li></ul></div></div></section>`;
  res.sendHtml(layout({ title:"IAssistant – Accueil", content }));
});

app.get("/pricing",(req,res)=>{
  const content = `<section class="max-w-6xl mx-auto px-4 py-16"><h1 class="text-3xl font-bold mb-2">Tarifs</h1><p class="text-sm text-gray-600 mb-8">Abonnements à venir. Première requête offerte.</p><div class="grid md:grid-cols-3 gap-6"><div class="card p-6"><div class="font-bold">Essentiel</div><div class="text-2xl text-blue-700">—</div></div><div class="card p-6 border-2" style="border-color:#2563EB"><div class="font-bold">Business</div><div class="text-2xl text-blue-700">—</div></div><div class="card p-6"><div class="font-bold">Sur‑mesure</div><div class="text-2xl text-blue-700">—</div></div></div></section>`;
  res.sendHtml(layout({ title:"Tarifs – IAsssistant", content }));
});

app.get("/signup", csrf, (req,res)=>{
  const t=req.csrfToken();
  const content = `<section class="max-w-xl mx-auto px-4 py-16"><h2 class="text-2xl font-bold mb-2">Créer un compte</h2><p class="text-sm text-gray-600 mb-6">Première requête gratuite.</p><form method="post" action="/signup" class="card p-6 space-y-4"><div><label class="block text-sm font-medium mb-1">Email</label><input required name="email" type="email" class="w-full border rounded px-3 py-2"/></div><div><label class="block text-sm font-medium mb-1">Mot de passe</label><input required name="password" type="password" class="w-full border rounded px-3 py-2"/></div>${csrfField(t)}<button class="btn w-full" type="submit">Créer le compte</button><div class="text-sm text-gray-600">Déjà inscrit ? <a class="text-blue-600" href="/login">Se connecter</a></div></form></section>`;
  res.sendHtml(layout({ title:"Créer un compte – IAssistant", content }));
});
app.post("/signup", csrf, async (req,res)=>{
  const { email, password } = req.body;
  const exists = await db.get("SELECT id FROM users WHERE email = ?", email);
  if (exists) return res.status(400).send("Email déjà utilisé.");
  const passHash = await bcrypt.hash(password, 10);
  const uid = uuid();
  await db.run("INSERT INTO users (id,email,passHash,free_used,is_admin) VALUES (?,?,?,?,?)", uid, email, passHash, 0, email === ADMIN_EMAIL ? 1 : 0);
  await notifyDiscord(`🆕 **Inscription**\n**Email :** ${email}`);
  req.session.userEmail = email; res.redirect("/dashboard");
});

app.get("/login", csrf, (req,res)=>{
  const t=req.csrfToken();
  const content = `<section class="max-w-xl mx-auto px-4 py-16"><h2 class="text-2xl font-bold mb-6">Connexion</h2><form method="post" action="/login" class="card p-6 space-y-4"><div><label class="block text-sm font-medium mb-1">Email</label><input required name="email" type="email" class="w-full border rounded px-3 py-2"/></div><div><label class="block text-sm text-gray-700 mb-1">Mot de passe</label><input required name="password" type="password" class="w-full border rounded px-3 py-2"/></div>${csrfField(t)}<button class="btn w-full" type="submit">Se connecter</button><div class="text-sm text-gray-600">Nouveau ? <a class="text-blue-600" href="/signup">Créer un compte</a></div></form></section>`;
  res.sendHtml(layout({ title:"Connexion – IAssistant", content }));
});
app.post("/login", csrf, async (req,res)=>{
  const { email, password } = req.body;
  const u = await db.get("SELECT * FROM users WHERE email=?", email);
  if(!u) return res.status(400).send("Compte introuvable.");
  const ok = await bcrypt.compare(password, u.passHash);
  if(!ok) return res.status(400).send("Identifiants incorrects.");
  req.session.userEmail = email; req.session.adminVerified=false;
  res.redirect("/dashboard");
});
app.post("/logout", csrf, (req,res)=>{ req.session=null; res.redirect("/"); });

app.get("/contact", csrf, (req,res)=>{
  const t=req.csrfToken();
  const content = `<section class="max-w-2xl mx-auto px-4 py-16"><h2 class="text-2xl font-bold mb-2">Contact</h2><form method="post" action="/contact" class="card p-6 space-y-4"><div class="grid sm:grid-cols-2 gap-4"><div><label class="block text-sm font-medium mb-1">Nom</label><input name="name" required class="w-full border rounded px-3 py-2"/></div><div><label class="block text-sm font-medium mb-1">Email</label><input name="email" type="email" required class="w-full border rounded px-3 py-2"/></div></div><div><label class="block text-sm font-medium mb-1">Sujet</label><input name="subject" required class="w-full border rounded px-3 py-2"/></div><div><label class="block text-sm font-medium mb-1">Message</label><textarea name="message" rows="6" required class="w-full border rounded px-3 py-2"></textarea></div>${csrfField(t)}<button class="btn" type="submit">Envoyer</button></form></section>`;
  res.sendHtml(layout({ title:"Contact – IAssistant", content }));
});
app.post("/contact", csrf, async (req,res)=>{
  const { name, email, subject, message } = req.body;
  const id = uuid();
  await db.run("INSERT INTO messages (id,name,email,subject,message,createdAt) VALUES (?,?,?,?,?,?)", id, String(name||""), String(email||""), String(subject||""), String(message||""), Date.now());
  await notifyDiscord(`✉️ **Contact**\n**Nom :** ${name}\n**Email :** ${email}\n**Sujet :** ${subject}\n${(message||"").slice(0,1200)}`);
  res.sendHtml(layout({ title:"Merci – IAssistant", content:`<section class="max-w-xl mx-auto px-4 py-16 text-center"><h2 class="text-2xl font-bold mb-2">Merci ✅</h2><p class="text-gray-700">Nous revenons vers vous très vite.</p><a class="btn mt-4 inline-block" href="/">Retour à l’accueil</a></section>` }));
});

app.get("/dashboard", requireAuth, async (req,res)=>{
  const user = await db.get("SELECT * FROM users WHERE email=?", req.session.userEmail);
  const rows = await db.all("SELECT * FROM requests WHERE userId=? ORDER BY createdAt DESC LIMIT 50", user.id);
  const freeLeft = Number(user.free_used) === 0;
  const items = rows.map(r=>`<li class="p-3 bg-white border rounded"><div class="font-medium">${escapeHtml(r.title)}</div><div class="text-xs text-gray-600">${new Date(r.createdAt).toLocaleString("fr-FR")} — #${r.id.slice(0,8)}</div><details class="mt-2 text-sm text-gray-700"><summary class="cursor-pointer">Détails</summary><pre class="whitespace-pre-wrap mt-1">${escapeHtml(r.details)}</pre></details></li>`).join("") || '<li class="text-gray-500">Aucune demande pour le moment.</li>';
  const content = `<section class="max-w-5xl mx-auto px-4 py-10"><div class="flex items-center justify-between mb-6"><h2 class="text-2xl font-bold">Espace client</h2><form method="post" action="/logout"><input type="hidden" name="_csrf" value="" /><button class="text-blue-600">Se déconnecter</button></form></div><div class="grid md:grid-cols-2 gap-6">${freeLeft ? `<form method="post" action="/request" class="card p-6 space-y-4"><h3 class="font-semibold mb-2">Nouvelle demande (offerte)</h3><div><label class="block text-sm font-medium mb-1">Titre</label><input required name="title" class="w-full border rounded px-3 py-2"/></div><div><label class="block text-sm font-medium mb-1">Détails</label><textarea required name="details" rows="6" class="w-full border rounded px-3 py-2"></textarea></div><input type="hidden" name="_csrf" value="" /><button class="btn w-full" type="submit">Envoyer</button><div class="text-xs text-gray-600">Cette demande est offerte.</div></form>` : `<div class="card p-6"><h3 class="font-semibold mb-2">Essai utilisé</h3><p class="text-gray-700">Votre requête gratuite est déjà utilisée.</p></div>`}<div class="card p-6"><h3 class="font-semibold mb-3">Historique</h3><ul class="space-y-3 text-sm">${items}</ul></div></div></section>`;
  res.sendHtml(layout({ title:"Espace client – IAssistant", content }));
});

app.post("/request", requireAuth, csrf, async (req,res)=>{
  const user = await db.get("SELECT * FROM users WHERE email=?", req.session.userEmail);
  if(Number(user.free_used)===1) return res.status(403).send("Requête d’essai déjà utilisée.");
  const { title, details } = req.body;
  const id = uuid();
  await db.run("INSERT INTO requests (id,userId,title,details,createdAt) VALUES (?,?,?,?,?)", id, user.id, title, details, Date.now());
  await db.run("UPDATE users SET free_used=1 WHERE id=?", user.id);
  await notifyDiscord(`🆕 **Nouvelle demande**\n**Client :** ${user.email}\n**Titre :** ${title}\n${details.length>1000?details.slice(0,1000)+'…':details}`);
  res.redirect("/dashboard");
});

// Admin + extra password check
function requireAdmin(req,res,next){
  if(req.session.userEmail!==ADMIN_EMAIL) return res.status(403).send("Accès refusé.");
  if(req.session.adminVerified!==true) return res.redirect("/admin");
  next();
}

app.get("/admin", requireAuth, (req,res)=>{
  if(req.session.userEmail!==ADMIN_EMAIL){
    return res.status(403).send("Accès refusé.");
  }
  if(req.session.adminVerified===true){
    return res.sendHtml(layout({ title:"Admin", content:`<section class="max-w-3xl mx-auto px-4 py-16"><h2 class="text-2xl font-bold mb-2">Espace admin</h2><p class="text-gray-700">Bienvenue ${escapeHtml(req.session.userEmail)}.</p></section>` }));
  }
  const t="csrf";
  const content = `<section class="max-w-md mx-auto px-4 py-16"><h2 class="text-2xl font-bold mb-3">Vérification admin</h2><form method="post" action="/admin/verify" class="card p-6 space-y-4"><div><label class="block text-sm font-medium mb-1">Mot de passe admin</label><input name="adminPass" type="password" required class="w-full border rounded px-3 py-2"/></div><button class="btn w-full" type="submit">Entrer</button></form></section>`;
  res.sendHtml(layout({ title:"Admin – Vérification", content }));
});
app.post("/admin/verify", requireAuth, csrf, (req,res)=>{
  if(req.session.userEmail!==ADMIN_EMAIL) return res.status(403).send("Accès refusé.");
  const { adminPass } = req.body;
  if(adminPass===ADMIN_EXTRA_PASSWORD){ req.session.adminVerified=true; return res.redirect("/admin"); }
  return res.status(401).send("Mot de passe admin incorrect.");
});

app.use(function (err, req, res, next) {
  if (err.code !== 'EBADCSRFTOKEN') return next(err);
  res.status(403).sendHtml(`<!doctype html><meta charset="utf-8"><title>Erreur sécurité</title><div style="font-family:system-ui;padding:40px"><h1>Erreur de sécurité (CSRF)</h1><p>Votre session a expiré.</p><p><a href="/" style="color:#2563EB">Retour à l’accueil</a></p></div>`);
});

app.get("/privacy",(req,res)=>{ res.sendHtml(layout({ title:"Confidentialité", content:`<section class="max-w-3xl mx-auto px-4 py-16"><h1 class="text-2xl font-bold mb-4">Politique de confidentialité</h1><p class="text-gray-700">Nous n’exploitons pas vos données.</p></section>` })); });
app.get("/legal",(req,res)=>{ res.sendHtml(layout({ title:"Mentions légales", content:`<section class="max-w-3xl mx-auto px-4 py-16"><h1 class="text-2xl font-bold mb-4">Mentions légales</h1><p class="text-gray-700">IAssistant – MVP.</p></section>` })); });

app.use((req,res)=>{ res.status(404).sendHtml(layout({ title:"404", content:`<section class="max-w-xl mx-auto px-4 py-24 text-center"><h1 class="text-4xl font-extrabold text-blue-700 mb-3">404</h1><p class="text-gray-600 mb-6">Page introuvable.</p><a class="btn" href="/">Accueil</a></section>` })); });

let db;
(async () => {
  await fs.promises.mkdir(path.dirname(DB_PATH), { recursive: true });
  db = await open({ filename: DB_PATH, driver: sqlite3.Database });
  await db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS users ( id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, passHash TEXT NOT NULL, free_used INTEGER DEFAULT 0, is_admin INTEGER DEFAULT 0 );
    CREATE TABLE IF NOT EXISTS requests ( id TEXT PRIMARY KEY, userId TEXT NOT NULL, title TEXT NOT NULL, details TEXT NOT NULL, createdAt INTEGER NOT NULL, FOREIGN KEY (userId) REFERENCES users(id) );
    CREATE TABLE IF NOT EXISTS messages ( id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL, createdAt INTEGER NOT NULL );
  `);
  await notifyDiscord("✅ IAssistant V5 (minimal) démarré.");
  app.listen(PORT, () => console.log(`IAssistant V5 running on ${BASE_URL} (DB at ${DB_PATH})`));
})();
