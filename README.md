# KitBench API starter

This API provides central project-request storage, student email verification/login, community statistics, and optional Razorpay endpoints. It is not live until deployed and configured.

## Run locally
1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env` and replace every placeholder with real values. Keep `.env` private and do not commit it.
3. Run `npm install`, then `npm start`.
4. Visit `http://localhost:3000/health`.

## Deploy
Follow [`DEPLOY_RENDER.md`](DEPLOY_RENDER.md) for Render setup, environment variables, persistent SQLite storage, and connecting the GitHub Pages frontend.

## Important
- Set `FRONTEND_ORIGIN` to the exact published website origin.
- For durable SQLite requests on Render, mount a persistent disk at `/var/data` and set `DB_FILE=/var/data/kitbench.sqlite`; check the host's current pricing.
- Email verification requires valid SMTP credentials.
- Keep `ADMIN_API_TOKEN`, JWT/OTP secrets, SMTP credentials and Razorpay secret private.
- The server-side Razorpay product allowlist is intentionally empty until the product IDs and exact paise prices are configured. Do not accept live payments before test-mode validation.
