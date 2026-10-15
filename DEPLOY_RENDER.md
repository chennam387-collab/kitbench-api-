# KitBench backend deployment guide

This Node.js API provides central project requests, student email verification/login, community statistics, and optional Razorpay endpoints. It is a starter package: it must be deployed and configured before these functions work on the public website.

## 1. Prepare a backend repository

1. Create a new GitHub repository named `kitbench-api` (private is preferable).
2. Upload the contents of this `kitbench-payment-api` folder to the repository root: `server.js`, `package.json`, `.env.example`, and this README.
3. Do **not** upload a real `.env` file, API secrets, SMTP passwords, or a SQLite database.

## 2. Deploy on Render

1. Sign in to Render and choose **New + → Web Service**.
2. Connect the `kitbench-api` repository.
3. Choose a Node runtime. Set **Build Command** to `npm install` and **Start Command** to `npm start`. Node 20 or newer is required.
4. Set the **Health Check Path** to `/health`.
5. Create the service. When deployment finishes, copy its HTTPS URL, such as `https://kitbench-api-xxxx.onrender.com`. Use your actual URL, not this example.

Official instructions: https://render.com/docs/web-services

## 3. Configure environment variables

In the Render service, open **Environment → Add Environment Variable**. Add each key/value separately, then save and redeploy. Never put secret values into the website HTML or a public GitHub repository.

| Key | Value to set |
|---|---|
| `NODE_ENV` | `production` |
| `FRONTEND_ORIGIN` | Exact website origin, e.g. `https://YOUR-USERNAME.github.io` (origin only; no `/KitBench/` path) |
| `DB_FILE` | `/var/data/kitbench.sqlite` if you mount a persistent disk at `/var/data` |
| `JWT_SECRET` | Unique random secret, at least 32 characters |
| `OTP_SECRET` | A different unique random secret, at least 32 characters |
| `ADMIN_API_TOKEN` | A third unique random secret, at least 32 characters; keep private |
| `SMTP_HOST` | SMTP host supplied by your email provider |
| `SMTP_PORT` | Usually `587` for STARTTLS or provider-specified port |
| `SMTP_SECURE` | `false` for port 587; use provider guidance |
| `SMTP_USER` | SMTP username supplied by provider |
| `SMTP_PASS` | SMTP password/app password supplied by provider |
| `MAIL_FROM` | Sender address approved by your email provider |

Keep the `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` unset until you are ready to configure payments. If testing, use Razorpay **test-mode** keys and never expose the secret key in HTML.

Render's environment-variable instructions: https://render.com/docs/configure-environment-variables

### Database persistence

SQLite stores requests in a file. The web service needs a persistent disk mounted at `/var/data`, and `DB_FILE` must be `/var/data/kitbench.sqlite`, otherwise data may be lost when an instance is replaced. Persistent disks may require a paid Render plan; check current pricing before enabling one. A managed PostgreSQL database is another production option, but this starter currently uses SQLite and would need code changes to use PostgreSQL. Back up the database.

## 4. Connect the website to the API

In `index.html`, find this line near the backend integration:

```js
window.KITBENCH_API_BASE = window.KITBENCH_API_BASE || "";
```

After deploying, change it to your actual API URL, for example:

```js
window.KITBENCH_API_BASE = "https://YOUR-ACTUAL-API.onrender.com";
```

Use the real HTTPS URL returned by Render. Commit and push the changed `index.html` to the GitHub Pages repository. GitHub Pages can host the HTML, but it cannot run the Node API itself.

## 5. Test the connection

1. Open `https://YOUR-ACTUAL-API.onrender.com/health`. It should return JSON with `ok: true`.
2. Open the KitBench site, submit a test project request, and check that a request ID is shown.
3. Open the Admin dashboard on KitBench and enter the private `ADMIN_API_TOKEN` to load requests and update statuses. Never share that token with students.
4. Verify requests persist after a backend restart/redeploy before using the site with real users.
5. Test student registration only after SMTP is configured. Email OTPs expire after 10 minutes.

## Project catalog pricing and payments

The website displays entry-level project ideas from ₹499 and shows related projects in each project details view. Displayed prices are not automatically trusted by the payment API. Before accepting payments, add each sellable product ID, title, and exact price in paise to the server-side `PRODUCT_CATALOG` in `server.js`, and test with Razorpay test mode. The current catalog is intentionally empty so the API rejects unconfigured products rather than charging an incorrect amount. Do not enable live payments until product prices, order verification, and fulfillment have been tested.

## Security checklist

- Use HTTPS for the website and API.
- Keep `.env`, SMTP credentials, Razorpay secret, JWT/OTP secrets, and `ADMIN_API_TOKEN` out of GitHub and public HTML.
- Restrict `FRONTEND_ORIGIN` to the actual website origin.
- Use a strong, unique admin token and rotate it if exposed.
- Configure backups and a privacy notice before collecting student data.
