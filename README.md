# IAssistant V5 (minimal)
- SQLite persistant (via `DB_PATH`, utiliser un Disk Render monté à `/var/data`)
- Webhook Discord intégré
- Admin: `mdjaroun0@gmail.com` + mot de passe admin `20082004` (route /admin)
- Pas de Stripe, pas de SMTP
- Node 20, Tailwind via CDN

## Déployer sur Render
1) Push sur GitHub
2) Render → New Web Service → connecter le repo
3) Env vars:
   - `SESSION_SECRET` (obligatoire)
   - `BASE_URL` (https de Render)
   - `DB_PATH = /var/data/ia.db` + **Disks → Add Disk** (mount `/var/data`)
   - *(optionnel)* `DISCORD_WEBHOOK_URL`
4) Manual Deploy → Clear build cache & deploy
