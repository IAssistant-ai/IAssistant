// app.js — IAssistant Light (pas de Stripe / pas d’e-mail)
// Fonctionnel localement et prêt pour Render

const express = require("express");
const rateLimit = require("express-rate-limit");
const session = require("cookie-session");
const bcrypt = require("bcrypt");
const { v4: uuid } = require("uuid");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const helmet = require("helmet");
const csurf = require("csurf");

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret";
const IS_HTTPS = /^https:\/\//i.test(BASE_URL) || process.env.NODE_ENV === "production";

const app = express();

// Sécurité & limites
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(rateLimit({ windowMs: 60_000, max: 200 }));

// Parsers
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Sessions (cookie sécurisé en prod)
app.use(
  session({
    name: "ia_sid",
    keys: [SESSION_SECRET],
    httpOnly: true,
    sameSite: "lax",
    secure: IS_HTTPS,
    maxAge: 1000 * 60 * 60 * 24 * 30,
  })
);

// CSRF
app.use(csurf());

// Utilitaire envoi HTML (corrige l’affichage “code en haut de page”)
app.use((req, res, next) => {
  res.sendHtml = (html) => {
    res.set("Content-Type", "text/html; charset=utf-8");
    return res.send(html);
  };
  next();
});

// --- Helpers UI & sécurité ---
const brand = { blue: "#2563EB", green: "#10B981" };

function layout({ title = "IAssistant", content = "" }) {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>tailwind.config={ theme:{ extend:{ colors:{ brand:'${brand.blue}', accent:'${brand.green}' } } } };</script>
  <style>
    :root{--brand-blue:${brand.blue};--accent-green:${brand.green}}
    .btn-primary{background:var(--brand-blue);color:#fff}
    .btn-primary:hover{filter:brightness(0.92)}
    .card{background:#fff;border:1px solid #e5e7eb;border-radius:0.75rem}
    .field{border:1px solid #e5e7eb;border-radius:0.5rem;padding:0.6rem 0.75rem;width:100%}
    .muted{color:#6b7280}
  </style>
</head>
<body class="bg-white text-gray-800">
<header class="border-b">
  <div class="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
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
      <a href="/dashboard" class="hover:text-gray-900">Espace client</a>
    </nav>
  </div>
</header>
<main>${content}</main>
<footer class="border-t mt-16">
  <div class="max-w-6xl mx-auto px-4 py-8 text-sm text-gray-600 flex items-center justify-between">
    <div>© ${new Date().getFullYear()} IAssistant</div>
    <div class="flex gap-4">
      <a href="#" class="hover:text-gray-900">Confidentialité</a>
      <a href="#" class="hover:text-gray-900">Mentions légales</a>
    </div>
  </div>
</footer>
</body>
</html>`;
}

function csrfField(token) {
  return `<input type="hidden" name="_csrf" value="${token}">`;
}
function requireAuth(req, res, next) {
  if (!req.session.userEmail) return res.redirect("/login");
  next();
}
function escapeHtml(str = "") {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// --- DB ---
let db;

// --- Routes ---
app.get("/", async (req, res) => {
  const content = `
<section class="bg-gray-50">
  <div class="max-w-6xl mx-auto px-4 py-16 grid md:grid-cols-2 gap-10 items-center">
    <div>
      <div class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-50 text-green-700 border border-green-200 mb-3">Première requête 100% gratuite</div>
      <h1 class="text-4xl font-extrabold mb-4" style="color:var(--brand-blue)">Gagnez du temps. Déléguez à IAssistant.</h1>
      <p class="muted mb-6">Automatisation clé en main pour TPE/indépendants : e‑mails, devis, facturation, réseaux sociaux, synthèses… Vous soumettez, on exécute.</p>
      <div class="flex gap-3 flex-wrap">
        <a href="/signup" class="px-5 py-3 rounded-md btn-primary">Commencer gratuitement</a>
        <a href="/login" class="px-5 py-3 rounded-md border">Se connecter</a>
      </div>
    </div>
    <div class="card p-6">
      <h3 class="font-semibold mb-4">Exemple d'automatisation</h3>
      <ul class="text-sm text-gray-700 space-y-2">
        <li>✔️ Réponses e‑mail personnalisées</li>
        <li>✔️ Génération de devis & factures</li>
        <li>✔️ Posts réseaux planifiés</li>
      </ul>
      <div class="text-xs text-gray-500 mt-4">Gain estimé : <strong>8–15h / mois</strong></div>
    </div>
  </div>
</section>`;
  res.sendHtml(layout({ title: "IAssistant – Accueil", content }));
});

app.get("/signup", (req, res) => {
  const token = req.csrfToken();
  const content = `
<section class="max-w-md mx-auto px-4 py-16">
  <h2 class="text-2xl font-bold mb-2">Créer un compte</h2>
  <p class="text-sm text-gray-600 mb-6">Inscrivez-vous et envoyez votre <strong>première requête gratuitement</strong>.</p>
  <form method="post" action="/signup" class="card p-6 space-y-4">
    <div><label class="block text-sm font-medium mb-1">Email</label><input required name="email" type="email" class="field" placeholder="vous@entreprise.com" /></div>
    <div><label class="block text-sm font-medium mb-1">Mot de passe</label><input required name="password" type="password" class="field" /></div>
    ${csrfField(token)}
    <button class="w-full py-2 rounded-md btn-primary" type="submit">Créer le compte</button>
    <div class="text-sm text-gray-600">Déjà inscrit ? <a class="text-blue-600" href="/login">Se connecter</a></div>
  </form>
</section>`;
  res.sendHtml(layout({ title: "Créer un compte – IAssistant", content }));
});

app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  const exists = await db.get("SELECT id FROM users WHERE email = ?", email);
  if (exists) return res.status(400).sendHtml("Email déjà utilisé.");
  const passHash = await bcrypt.hash(password, 10);
  const user = { id: uuid(), email, passHash, free_used: 0 };
  await db.run(
    "INSERT INTO users (id,email,passHash,free_used) VALUES (?,?,?,?)",
    user.id,
    user.email,
    user.passHash,
    user.free_used
  );
  req.session.userEmail = email;
  res.redirect("/dashboard");
});

app.get("/login", (req, res) => {
  const token = req.csrfToken();
  const content = `
<section class="max-w-md mx-auto px-4 py-16">
  <h2 class="text-2xl font-bold mb-6">Connexion</h2>
  <form method="post" action="/login" class="card p-6 space-y-4">
    <div><label class="block text-sm font-medium mb-1">Email</label><input required name="email" type="email" class="field" /></div>
    <div><label class="block text-sm font-medium mb-1">Mot de passe</label><input required name="password" type="password" class="field" /></div>
    ${csrfField(token)}
    <button class="w-full py-2 rounded-md btn-primary" type="submit">Se connecter</button>
    <div class="text-sm text-gray-600">Nouveau ? <a class="text-blue-600" href="/signup">Créer un compte</a></div>
  </form>
</section>`;
  res.sendHtml(layout({ title: "Connexion – IAssistant", content }));
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await db.get("SELECT * FROM users WHERE email = ?", email);
  if (!user) return res.status(400).sendHtml("Compte introuvable.");
  const ok = await bcrypt.compare(password, user.passHash);
  if (!ok) return res.status(400).sendHtml("Identifiants incorrects.");
  req.session.userEmail = email;
  res.redirect("/dashboard");
});

app.post("/logout", (req, res) => {
  req.session = null;
  res.redirect("/");
});

app.get("/dashboard", requireAuth, async (req, res) => {
  const user = await db.get("SELECT * FROM users WHERE email = ?", req.session.userEmail);
  const requests = await db.all(
    "SELECT * FROM requests WHERE userId = ? ORDER BY createdAt DESC LIMIT 50",
    user.id
  );
  const token = req.csrfToken();
  const freeLeft = Number(user.free_used) === 0;

  const list =
    requests
      .map(
        (r) => `<li class="p-3 bg-white border rounded">
          <div class="font-medium">${escapeHtml(r.title)}</div>
          <div class="text-gray-600 text-xs">${new Date(r.createdAt).toLocaleString("fr-FR")} — #${r.id.slice(0, 8)}</div>
          <details class="mt-2 text-sm text-gray-700"><summary class="cursor-pointer text-gray-600">Détails</summary><pre class="whitespace-pre-wrap mt-1">${escapeHtml(r.details)}</pre></details>
        </li>`
      )
      .join("") || '<li class="text-gray-500">Aucune demande pour le moment.</li>';

  const form = freeLeft
    ? `<form method="post" action="/request" class="card p-6 space-y-4">
         <h3 class="font-semibold mb-2">Nouvelle demande (offerte)</h3>
         <div><label class="block text-sm font-medium mb-1">Titre</label><input required name="title" class="field" placeholder="Ex: Répondre à un client"/></div>
         <div><label class="block text-sm font-medium mb-1">Détails</label><textarea required name="details" rows="6" class="field" placeholder="Expliquez précisément la tâche…"></textarea></div>
         ${csrfField(token)}
         <button class="w-full py-2 rounded-md btn-primary" type="submit">Envoyer la demande</button>
       </form>`
    : `<div class="card p-6">
         <h3 class="font-semibold mb-2">Essai utilisé</h3>
         <p class="text-gray-700">Vous avez déjà utilisé votre première requête gratuite.</p>
         <p class="text-sm muted mt-2">Nous ajouterons l’abonnement plus tard (Stripe).</p>
       </div>`;

  const content = `
<section class="max-w-6xl mx-auto px-4 py-10">
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
  res.sendHtml(layout({ title: "Espace client – IAssistant", content }));
});

app.post("/request", requireAuth, async (req, res) => {
  const user = await db.get("SELECT * FROM users WHERE email = ?", req.session.userEmail);
  if (Number(user.free_used) === 1) return res.status(403).sendHtml("Requête d’essai déjà utilisée.");
  const { title, details } = req.body;
  await db.run(
    "INSERT INTO requests (id,userId,title,details,createdAt) VALUES (?,?,?,?,?)",
    uuid(),
    user.id,
    title,
    details,
    Date.now()
  );
  await db.run("UPDATE users SET free_used = 1 WHERE id = ?", user.id);
  res.redirect("/dashboard");
});

// --- Boot ---
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
  `);
  app.listen(PORT, () => console.log(`IAssistant Light prêt sur ${BASE_URL}`));
})();