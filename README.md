# IAssistant (Light)
Version légère sans Stripe ni e-mail, idéale pour démarrer et déployer sur Render.

## Démarrer en local
```bash
npm install
npm start
# Ouvrir http://localhost:3000
```

## Déployer sur Render
1. Poussez ce dossier sur GitHub (public pour simplifier au début).
2. Sur https://render.com → **New → Web Service** → Connect GitHub et choisissez ce repo.
3. **Build Command**: `npm install`
4. **Start Command**: `npm start`
5. (Optionnel) Ajoutez `SESSION_SECRET` dans Environment. Après le 1er déploiement, définissez `BASE_URL` avec l’URL Render puis redeploy.

## Notes
- La base SQLite `ia.db` est créée automatiquement. Sur Render Free, elle peut être réinitialisée lors d’un redeploy.
- Quand vous voudrez activer les paiements et les e-mails, on branchera Stripe + SMTP et/ou migrera vers Postgres.
