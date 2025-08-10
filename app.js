// app.js — IAssistant Enhanced + Favicon (static)
// - Homepage enrichie (marketing)
// - Pages: Contact, Pricing, Privacy, Legal, 404
// - Dashboard: première requête offerte, historique
// - Notifications optionnelles: Email (SMTP) et/ou Discord Webhook
// - Favicon depuis /public/favicon.svg
// Dépendances: express, helmet, express-rate-limit, cookie-session, bcrypt, sqlite, sqlite3, uuid, csurf, nodemailer

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const session = require("cookie-session");
const bcrypt = require("bcrypt");
const { v4: uuid } = require("uuid");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const csurf = require("csurf");
const nodemailer = require("nodemailer");

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret";
const IS_HTTPS = /^https:\/\//i.test(BASE_URL) || process.env.NODE_ENV === "production";

// Email (optionnel)
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";
const SMTP_HOST = process.env.SMTP_HOST || "";
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const mailer = (SMTP_HOST && SMTP_USER && SMTP_PASS)
  ? nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    })
  : null;

async function sendMail({ to, subject, html }) {
  if (!mailer) { console.log("[MAIL:DEV]", { to, subject }); return; }
  await mailer.sendMail({ from: `IAssistant <${SMTP_USER || "no-reply@iaassistant.local"}>`, to, subject, html });
}

// Discord webhook (optionnel)
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || "";
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
app.use(session({
  name: "ia_sid",
  keys: [SESSION_SECRET],
  httpOnly: true,
  sameSite: "lax",
  secure: IS_HTTPS,
  maxAge: 1000 * 60 * 60 * 24 * 30
}));
app.use(csurf());

// Static assets (favicon, images, etc.)
app.use(express.static("public"));

app.use((req, res, next) => {
  res.sendHtml = (html) => { res.set("Content-Type","text/html; charset=utf-8"); return res.send(html); };
  next();
});

// UI helpers
const brand = { blue: "#2563EB", green: "#10B981" };
function layout({ title = "IAssistant", description = "Assistant IA pour petites entreprises : gagnez du temps en déléguant vos tâches répétitives.", content = "" }) {
  const year = new Date().getFullYear();
  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <meta name="description" content="${escapeHtml(description)}" />
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <meta property="og:title" content="${escapeHtml(title)}" />
  <meta property="og:description" content="${escapeHtml(description)}" />
  <meta property="og:type" content="website" />
  <script src="https://cdn.tailwindcss.com"></script>
  <script>tailwind.config={ theme:{ extend:{ colors:{ brand:'${brand.blue}', accent:'${brand.green}' } } } };</script>
  <style>
    :root{--brand-blue:${brand.blue};--accent-green:${brand.green}}
    .btn-primary{background:var(--brand-blue);color:#fff}
    .btn-primary:hover{filter:brightness(0.92)}
    .card{background:#fff;border:1px solid #e5e7eb;border-radius:0.75rem}
    .field{border:1px solid #e5e7eb;border-radius:0.5rem;padding:0.6rem 0.75rem;width:100%}
    .muted{color:#6b7280}
    .container{max-width:72rem;margin:0 auto;padding-left:1rem;padding-right:1rem}
  </style>
</head>
<body class="bg-white text-gray-800">
<header class="border-b">
  <div class="container py-4 flex items-center justify-between">
    <a href="/" class="flex items-center gap-3">
      <div style="width:34px;height:34px;background:var(--brand-blue)" class="rounded-lg grid place-items-center">
        <svg width="22" height="22" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="10" cy="36" r="4" fill="white"/>
          <path d="M18 38 L28 10 H34 L44 38 H38 L35 30 H25 L22 38 H18 Z M27 24 H33 L30 16 L27 24 Z" fill="white"/>
        </svg>
      </div>
      <div>
        <div class="font-semibold">IAssistant</div>
        <div class="text-xs text-gray-500">Assistant IA pour petites entreprises</div>
      </div>
    </a>
    <nav class="text-sm flex items-center gap-4">
      <a href="/" class="hover:text-gray-900">Accueil</a>
      <a href="/pricing" class="hover:text-gray-900">Tarifs</a>
      <a href="/contact" class="hover:text-gray-900">Contact</a>
      <a href="/dashboard" class="hover:text-gray-900">Espace client</a>
    </nav>
  </div>
</header>
<main>${content}</main>
<footer class="border-t mt-16">
  <div class="container py-8 text-sm text-gray-600 flex items-center justify-between">
    <div>© ${year} IAssistant</div>
    <div class="flex gap-4">
      <a href="/privacy" class="hover:text-gray-900">Confidentialité</a>
      <a href="/legal" class="hover:text-gray-900">Mentions légales</a>
    </div>
  </div>
</footer>
</body>
</html>`;
}
function csrfField(token){ return `<input type="hidden" name="_csrf" value="${token}">`; }
function requireAuth(req,res,next){ if(!req.session.userEmail) return res.redirect("/login"); next(); }
function escapeHtml(str=""){ return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/\"/g,"&quot;").replace(/'/g,"&#039;"); }

// Home enrichie
app.get("/", async (req, res) => {
  const content = `
<section class="bg-gray-50">
  <div class="container py-16 grid md:grid-cols-2 gap-10 items-center">
    <div>
      <div class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-50 text-green-700 border border-green-200 mb-3">Première requête 100% gratuite</div>
      <h1 class="text-4xl font-extrabold mb-4" style="color:var(--brand-blue)">Gagnez des heures chaque semaine en déléguant à IAssistant.</h1>
      <p class="muted mb-6">Pour TPE et indépendants : e-mails, devis/factures, réseaux sociaux, comptes-rendus, scripts simples… Vous soumettez, on exécute — <strong>sans friction</strong>.</p>
      <div class="flex gap-3 flex-wrap">
        <a href="/signup" class="px-5 py-3 rounded-md btn-primary">Commencer gratuitement</a>
        <a href="/contact" class="px-5 py-3 rounded-md border">Parler à un humain</a>
      </div>
      <div class="flex items-center gap-6 mt-6 text-sm text-gray-600">
        <div>⚡ Démarrage en 2 min</div>
        <div>🔒 Données en Europe</div>
        <div>💬 Support humain</div>
      </div>
    </div>
    <div class="card p-6">
      <h3 class="font-semibold mb-4">Exemples d’automatisations</h3>
      <ul class="text-sm text-gray-700 space-y-2">
        <li>✔️ Réponses e-mail personnalisées</li>
        <li>✔️ Génération de devis & factures</li>
        <li>✔️ Posts réseaux planifiés</li>
        <li>✔️ Synthèses de rendez-vous</li>
      </ul>
      <div class="text-xs text-gray-500 mt-4">Gain estimé : <strong>8–15h / mois</strong></div>
    </div>
  </div>
</section>

<section class="container py-16">
  <h2 class="text-2xl font-bold mb-6">Pourquoi IAssistant ?</h2>
  <div class="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
    <div class="card p-5"><div class="font-semibold mb-1">Simple</div><p class="muted">Formulaire clair. Vous décrivez, on livre.</p></div>
    <div class="card p-5"><div class="font-semibold mb-1">Rapide</div><p class="muted">Résultats exploitables en quelques heures.</p></div>
    <div class="card p-5"><div class="font-semibold mb-1">Humain + IA</div><p class="muted">Supervision humaine, qualité garantie.</p></div>
    <div class="card p-5"><div class="font-semibold mb-1">Sécurisé</div><p class="muted">Données stockées en Europe, accès restreint.</p></div>
    <div class="card p-5"><div class="font-semibold mb-1">Économique</div><p class="muted">Pas d’embauche, payez à l’usage (abonnements plus tard).</p></div>
    <div class="card p-5"><div class="font-semibold mb-1">Évolutif</div><p class="muted">On commence léger, puis on intègre vos outils.</p></div>
  </div>
</section>

<section class="bg-gray-50">
  <div class="container py-16">
    <h2 class="text-2xl font-bold mb-6">Comment ça marche</h2>
    <ol class="grid md:grid-cols-3 gap-6 text-sm">
      <li class="card p-5"><div class="font-semibold mb-1">1) Créez un compte</div><p class="muted">30 secondes, aucune CB requise.</p></li>
      <li class="card p-5"><div class="font-semibold mb-1">2) Décrivez la tâche</div><p class="muted">Ex. “Répondre à ce client” ou “10 posts Instagram”.</p></li>
      <li class="card p-5"><div class="font-semibold mb-1">3) Recevez le résultat</div><p class="muted">Livraison par e-mail et dans l’historique.</p></li>
    </ol>
  </div>
</section>

<section class="container py-16">
  <h2 class="text-2xl font-bold mb-6">Secteurs servis</h2>
  <div class="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
    <div class="card p-4">Immobilier</div>
    <div class="card p-4">E-commerce</div>
    <div class="card p-4">Coaching & Conseil</div>
    <div class="card p-4">Artisans & Services</div>
  </div>
</section>

<section class="bg-gray-50">
  <div class="container py-16">
    <h2 class="text-2xl font-bold mb-6">Témoignages</h2>
    <div class="grid md:grid-cols-3 gap-6">
      <div class="card p-5"><p class="text-sm">“J’ai gagné ~10h/semaine dès le 1er mois.”</p><div class="mt-3 text-xs text-gray-500">— Julie, agence immo</div></div>
      <div class="card p-5"><p class="text-sm">“Des réponses clients plus rapides et pro.”</p><div class="mt-3 text-xs text-gray-500">— Karim, e-commerce</div></div>
      <div class="card p-5"><p class="text-sm">“Devis récurrents réglés en 1 clic.”</p><div class="mt-3 text-xs text-gray-500">— Léa, consultante</div></div>
    </div>
  </div>
</section>

<section class="container py-16 text-center">
  <h2 class="text-2xl font-bold mb-3">Prêt à tester ?</h2>
  <p class="muted mb-6">Votre première demande est offerte. 0 risque, 100% utile.</p>
  <a href="/signup" class="px-6 py-3 rounded-md btn-primary">Créer mon compte</a>
</section>`;
  res.sendHtml(layout({ title: "IAssistant – Gagnez du temps", content }));
});

// Auth
app.get("/signup",(req,res)=>{
  const token=req.csrfToken();
  const content=`
<section class="container py-16 max-w-xl">
  <h2 class="text-2xl font-bold mb-2">Créer un compte</h2>
  <p class="text-sm text-gray-600 mb-6">Inscrivez-vous et envoyez votre <strong>première requête gratuitement</strong>.</p>
  <form method="post" action="/signup" class="card p-6 space-y-4">
    <div><label class="block text-sm font-medium mb-1">Email</label><input required name="email" type="email" class="field" placeholder="vous@entreprise.com" /></div>
    <div><label class="block text-sm font-medium mb-1">Mot de passe</label><input required name="password" type="password" class="field" /></div>
    ${csrfField(token)}<button class="w-full py-2 rounded-md btn-primary" type="submit">Créer le compte</button>
    <div class="text-sm text-gray-600">Déjà inscrit ? <a class="text-blue-600" href="/login">Se connecter</a></div>
  </form>
</section>`;
  res.sendHtml(layout({ title:"Créer un compte – IAssistant", content }));
});
app.post("/signup", async (req,res)=>{
  const { email, password } = req.body;
  const exists = await db.get("SELECT id FROM users WHERE email = ?", email);
  if (exists) return res.status(400).send("Email déjà utilisé.");
  const passHash = await bcrypt.hash(password, 10);
  await db.run("INSERT INTO users (id,email,passHash,free_used) VALUES (?,?,?,0)", uuid(), email, passHash);
  req.session.userEmail = email; res.redirect("/dashboard");
});

app.get("/login",(req,res)=>{
  const token=req.csrfToken();
  const content=`
<section class="container py-16 max-w-xl">
  <h2 class="text-2xl font-bold mb-6">Connexion</h2>
  <form method="post" action="/login" class="card p-6 space-y-4">
    <div><label class="block text-sm font-medium mb-1">Email</label><input required name="email" type="email" class="field" /></div>
    <div><label class="block text-sm font-medium mb-1">Mot de passe</label><input required name="password" type="password" class="field" /></div>
    ${csrfField(token)}<button class="w-full py-2 rounded-md btn-primary" type="submit">Se connecter</button>
    <div class="text-sm text-gray-600">Nouveau ? <a class="text-blue-600" href="/signup">Créer un compte</a></div>
  </form>
</section>`;
  res.sendHtml(layout({ title:"Connexion – IAssistant", content }));
});
app.post("/login", async (req,res)=>{
  const { email, password } = req.body;
  const user = await db.get("SELECT * FROM users WHERE email = ?", email);
  if (!user) return res.status(400).send("Compte introuvable.");
  const ok = await bcrypt.compare(password, user.passHash);
  if (!ok) return res.status(400).send("Identifiants incorrects.");
  req.session.userEmail = email; res.redirect("/dashboard");
});
app.post("/logout",(req,res)=>{ req.session=null; res.redirect("/"); });

// Pricing
app.get("/pricing",(req,res)=>{
  const content=`
<section class="container py-16">
  <h1 class="text-3xl font-bold mb-2">Tarifs</h1>
  <p class="muted mb-8">Votre première requête est offerte. Les abonnements arrivent bientôt.</p>
  <div class="grid md:grid-cols-3 gap-6">
    <div class="card p-6"><div class="text-lg font-bold mb-1">Essentiel</div><div class="text-2xl font-extrabold" style="color:var(--brand-blue)">—</div><ul class="mt-4 space-y-2 text-sm text-gray-700"><li>✔️ E-mails pro</li><li>✔️ Docs simples</li><li>✔️ 8 posts réseaux/mois</li></ul><div class="mt-6"><a href="/signup" class="w-full inline-block text-center py-2 rounded-md btn-primary">Bientôt</a></div></div>
    <div class="card p-6 border-2" style="border-color:var(--brand-blue)"><div class="text-lg font-bold mb-1">Business</div><div class="text-2xl font-extrabold" style="color:var(--brand-blue)">—</div><ul class="mt-4 space-y-2 text-sm text-gray-700"><li>✔️ Automatisations avancées</li><li>✔️ Intégrations Gmail/Slack</li><li>✔️ 2h de setup inclus</li></ul><div class="mt-6"><a href="/signup" class="w-full inline-block text-center py-2 rounded-md btn-primary">Bientôt</a></div></div>
    <div class="card p-6"><div class="text-lg font-bold mb-1">Sur‑mesure</div><div class="text-2xl font-extrabold" style="color:var(--brand-blue)">—</div><ul class="mt-4 space-y-2 text-sm text-gray-700"><li>✔️ Scripts dédiés</li><li>✔️ Priorité support</li><li>✔️ Formation équipe</li></ul><div class="mt-6"><a href="/contact" class="w-full inline-block text-center py-2 rounded-md btn-primary">Nous contacter</a></div></div>
  </div>
</section>`;
  res.sendHtml(layout({ title:"Tarifs – IAssistant", content }));
});

// Dashboard & demandes
app.get("/dashboard", requireAuth, async (req,res)=>{
  const user = await db.get("SELECT * FROM users WHERE email=?", req.session.userEmail);
  const rows = await db.all("SELECT * FROM requests WHERE userId=? ORDER BY createdAt DESC LIMIT 50", user.id);
  const token = req.csrfToken();
  const freeLeft = Number(user.free_used) === 0;
  const list = rows.map(r=>`<li class="p-3 bg-white border rounded">
    <div class="font-medium">${escapeHtml(r.title)}</div>
    <div class="text-gray-600 text-xs">${new Date(r.createdAt).toLocaleString("fr-FR")} — #${r.id.slice(0,8)}</div>
    <details class="mt-2 text-sm text-gray-700"><summary class="cursor-pointer text-gray-600">Détails</summary><pre class="whitespace-pre-wrap mt-1">${escapeHtml(r.details)}</pre></details>
  </li>`).join("") || '<li class="text-gray-500">Aucune demande pour le moment.</li>';
  const form = freeLeft
    ? `<form method="post" action="/request" class="card p-6 space-y-4">
        <h3 class="font-semibold mb-2">Nouvelle demande (offerte)</h3>
        <p class="text-sm muted">Exemples : “Répondre à ce client…”, “Rédiger un devis…”, “10 posts IG sur …”.</p>
        <div><label class="block text-sm font-medium mb-1">Titre</label><input required name="title" class="field" placeholder="Ex: Répondre à un client"/></div>
        <div><label class="block text-sm font-medium mb-1">Détails</label><textarea required name="details" rows="6" class="field" placeholder="Expliquez précisément la tâche, contexte, ton, contraintes, format de sortie…"></textarea></div>
        ${csrfField(token)}<button class="w-full py-2 rounded-md btn-primary" type="submit">Envoyer la demande</button>
        <div class="text-xs text-gray-600">Cette demande est offerte.</div>
      </form>`
    : `<div class="card p-6"><h3 class="font-semibold mb-2">Essai utilisé</h3><p class="text-gray-700">Vous avez déjà utilisé votre première requête gratuite.</p><p class="text-sm muted mt-2">Les abonnements arrivent bientôt.</p></div>`;

  const content = `
<section class="container py-10">
  <div class="flex items-center justify-between gap-4 mb-6">
    <h2 class="text-2xl font-bold">Espace client</h2>
    <form method="post" action="/logout">${csrfField(token)}<button class="text-blue-600">Se déconnecter</button></form>
  </div>
  <div class="grid md:grid-cols-2 gap-6">
    ${form}
    <div class="card p-6">
      <h3 class="font-semibold mb-3">Historique</h3>
      <ul class="space-y-3 text-sm">${list}</ul>
    </div>
  </div>
</section>`;
  res.sendHtml(layout({ title:"Espace client – IAssistant", content }));
});

app.post("/request", requireAuth, async (req,res)=>{
  const user = await db.get("SELECT * FROM users WHERE email=?", req.session.userEmail);
  if (Number(user.free_used) === 1) return res.status(403).send("Requête d’essai déjà utilisée.");
  const { title, details } = req.body;
  const recId = uuid();
  await db.run("INSERT INTO requests (id,userId,title,details,createdAt) VALUES (?,?,?,?,?)", recId, user.id, title, details, Date.now());
  await db.run("UPDATE users SET free_used=1 WHERE id=?", user.id);

  const msg = [
    "🆕 **Nouvelle demande IAssistant**",
    `**Client :** ${user.email}`,
    `**Titre :** ${title}`,
    `**Détails :** ${details.length > 1000 ? details.slice(0,1000)+"…" : details}`,
    `**Date :** ${new Date().toLocaleString("fr-FR")}`
  ].join("\n");
  await notifyDiscord(msg);
  if (ADMIN_EMAIL) {
    try {
      await sendMail({ to: ADMIN_EMAIL, subject: `[IAssistant] Nouvelle demande — ${title}`, html: `<div style="font-family:system-ui,Segoe UI,Arial"><h2>Nouvelle demande IAssistant</h2><p><strong>Client:</strong> ${escapeHtml(user.email)}</p><p><strong>Titre:</strong> ${escapeHtml(title)}</p><p><strong>Détails:</strong><br/>${escapeHtml(details).replace(/\n/g,"<br/>")}</p><p style="color:#888">ID: ${recId}</p></div>` });
    } catch(e){ console.error("Email (request) error:", e.message); }
  }
  res.redirect("/dashboard");
});

// Contact
app.get("/contact",(req,res)=>{
  const token=req.csrfToken();
  const content=`
<section class="container py-16 max-w-2xl">
  <h2 class="text-2xl font-bold mb-2">Contact</h2>
  <p class="muted mb-6">Dites-nous ce dont vous avez besoin. Nous revenons vers vous rapidement.</p>
  <form method="post" action="/contact" class="card p-6 space-y-4">
    <div class="grid sm:grid-cols-2 gap-4">
      <div><label class="block text-sm font-medium mb-1">Nom</label><input name="name" required class="field" /></div>
      <div><label class="block text-sm font-medium mb-1">Email</label><input name="email" type="email" required class="field" /></div>
    </div>
    <div><label class="block text-sm font-medium mb-1">Sujet</label><input name="subject" required class="field" /></div>
    <div><label class="block text-sm font-medium mb-1">Message</label><textarea name="message" rows="6" required class="field"></textarea></div>
    ${csrfField(token)}<button class="px-5 py-3 rounded-md btn-primary" type="submit">Envoyer</button>
  </form>
</section>`;
  res.sendHtml(layout({ title:"Contact – IAssistant", content }));
});
app.post("/contact", async (req,res)=>{
  const { name, email, subject, message } = req.body;
  const id = uuid();
  await db.run("INSERT INTO messages (id,name,email,subject,message,createdAt) VALUES (?,?,?,?,?,?)", id, String(name||""), String(email||""), String(subject||""), String(message||""), Date.now());
  await notifyDiscord(`✉️ **Contact**\n**Nom :** ${name}\n**Email :** ${email}\n**Sujet :** ${subject}\n${(message||"").slice(0,1200)}`);
  if (ADMIN_EMAIL) {
    try {
      await sendMail({ to: ADMIN_EMAIL, subject: `[IAssistant] Contact — ${subject}`, html: `<div style="font-family:system-ui,Segoe UI,Arial"><h2>Nouveau message de contact</h2><p><strong>Nom:</strong> ${escapeHtml(name)}</p><p><strong>Email:</strong> ${escapeHtml(email)}</p><p><strong>Sujet:</strong> ${escapeHtml(subject)}</p><p><strong>Message:</strong><br/>${escapeHtml(message).replace(/\n/g,"<br/>")}</p><p style="color:#888">ID: ${id}</p></div>` });
    } catch(e){ console.error("Email (contact) error:", e.message); }
  }
  res.sendHtml(layout({ title:"Message envoyé – IAssistant", content:`
  <section class="container py-16 text-center max-w-xl">
    <h2 class="text-2xl font-bold mb-2">Merci ✅</h2>
    <p class="muted">Votre message a bien été reçu. Nous revenons vers vous très vite.</p>
    <div class="mt-6"><a class="px-5 py-3 rounded-md btn-primary" href="/">Retour à l’accueil</a></div>
  </section>` }));
});

// Légal
app.get("/privacy",(req,res)=>{
  res.sendHtml(layout({ title:"Confidentialité – IAssistant", content:`
  <section class="container py-16 max-w-3xl">
    <h1 class="text-2xl font-bold mb-4">Politique de confidentialité</h1>
    <p class="muted">Vos données sont utilisées pour fournir le service (authentification, traitement des demandes, support). Elles ne sont pas revendues.</p>
  </section>` }));
});
app.get("/legal",(req,res)=>{
  res.sendHtml(layout({ title:"Mentions légales – IAssistant", content:`
  <section class="container py-16 max-w-3xl">
    <h1 class="text-2xl font-bold mb-4">Mentions légales</h1>
    <p class="muted">Raison sociale : IAssistant – Site démonstration MVP. Contact : /contact</p>
  </section>` }));
});

// 404
app.use((req,res)=>{
  res.status(404).sendHtml(layout({ title:"Page introuvable – IAssistant", content:`
  <section class="container py-24 text-center max-w-xl">
    <h1 class="text-4xl font-extrabold mb-3" style="color:var(--brand-blue)">404</h1>
    <p class="muted mb-6">Oups, cette page n’existe pas.</p>
    <a href="/" class="px-5 py-3 rounded-md btn-primary">Retour à l’accueil</a>
  </section>` }));
});

// --- DB boot ---
let db;
(async () => {
  db = await open({ filename: "ia.db", driver: sqlite3.Database });
  await db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      passHash TEXT NOT NULL,
      free_used INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS requests (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      title TEXT NOT NULL,
      details TEXT NOT NULL,
      createdAt INTEGER NOT NULL,
      FOREIGN KEY (userId) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      subject TEXT NOT NULL,
      message TEXT NOT NULL,
      createdAt INTEGER NOT NULL
    );
  `);
  app.listen(PORT, () => console.log(`IAssistant Enhanced prêt sur ${BASE_URL}`));
})();

function csrfField(token){ return `<input type="hidden" name="_csrf" value="${token}">`; }
function requireAuth(req,res,next){ if(!req.session.userEmail) return res.redirect("/login"); next(); }
function escapeHtml(str=""){ return String(str).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/\"/g,"&quot;").replace(/'/g,"&#039;"); }
