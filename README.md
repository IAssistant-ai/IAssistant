# IAssistant Enhanced + Favicon
Homepage enrichie, pages Contact/Pricing/Privacy/Legal, notifications email/Discord optionnelles, favicon via /public/favicon.svg, 404.

## Variables d'environnement (Render → Settings → Environment)
- SESSION_SECRET = chaîne aléatoire
- BASE_URL = https://ton-service.onrender.com (après 1er déploiement)
- (optionnel) ADMIN_EMAIL, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
- (optionnel) DISCORD_WEBHOOK_URL

## Déployer
- Commit/push ces fichiers sur GitHub (ou Upload dans l'UI)
- Render: Build `npm install`, Start `npm start`
- Manual Deploy → Clear build cache & deploy si `package.json` a changé

## Local
```bash
npm install
npm start
# http://localhost:3000
```
