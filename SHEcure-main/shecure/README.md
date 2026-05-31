# SHEcure

> **GEDSI-aligned security monitoring platform** — Pink-powered, inclusive, production-ready.

SHEcure is a full-stack Python (Flask) web application featuring real-time CCTV/webcam monitoring, IP allow-list access control, comprehensive audit logging, and instant unauthorized-access alerts — all wrapped in an accessible, screen-reader-friendly pink UI.

---

## Project Structure

```
shecure/
├── app/
│   ├── __init__.py              # App factory, extensions
│   ├── models/
│   │   ├── user.py              # User, AllowedIP models
│   │   └── logs.py              # AccessLog, ActivityLog, UnauthorizedAlert
│   ├── routes/
│   │   ├── auth.py              # Login, register, logout
│   │   ├── dashboard.py         # Dashboard, activity, alerts
│   │   ├── admin.py             # Admin panel, user/IP management
│   │   ├── camera.py            # MJPEG camera stream
│   │   └── api.py               # REST API endpoints
│   ├── utils/
│   │   └── security.py          # ⚠️ SECURITY-SENSITIVE — see below
│   ├── templates/
│   │   ├── base.html            # Base layout with sidebar
│   │   ├── auth/                # Login & register pages
│   │   ├── dashboard/           # Dashboard, camera, alerts, activity
│   │   ├── admin/               # Admin panel, logs
│   │   └── errors/              # 403, 404 pages
│   └── static/
│       ├── css/main.css         # Full pink design system
│       └── js/main.js           # Live polling, toasts, alerts
├── run.py                       # Entry point
├── requirements.txt
├── Procfile                     # Gunicorn for Railway
├── railway.toml                 # Railway deploy config
├── .env.example                 # Environment template (copy → .env)
└── .gitignore
```

---

## Security-Sensitive Files

| File | What's inside | Action |
|------|--------------|--------|
| `app/utils/security.py` | IP allow-list logic, activity tracking, suspicious pattern detection | **Keep private** — never share publicly |
| `.env` | Secret key, DB credentials, camera credentials | **Never commit** — already in .gitignore |
| `ENFORCE_IP_ALLOWLIST` | Toggle in `.env` to enable IP blocking | Set `true` in production |

---

## Local Setup

```bash
# 1. Clone / unzip the project
cd shecure

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your values

# 5. Run
python run.py
# Open http://localhost:5000
# Default admin: admin / SHEcure@2025!
```

---

## Upload to GitHub

**Step 1 — Create a new GitHub repository**
1. Go to https://github.com/new
2. Name it `shecure`
3. Set to **Private** (recommended — contains security logic)
4. Do NOT initialize with README (you already have files)
5. Click **Create repository**

**Step 2 — Push your code**
```bash
cd shecure
git init
git add .
git commit -m "🔐 Initial SHEcure release"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/shecure.git
git push -u origin main
```

---

## Deploy to Railway

**Step 1 — Create Railway project**
1. Go to https://railway.app and log in
2. Click **New Project → Deploy from GitHub repo**
3. Authorize Railway and select your `shecure` repository

**Step 2 — Add PostgreSQL database**
1. In your Railway project, click **+ New** → **Database** → **PostgreSQL**
2. Railway auto-generates a `DATABASE_URL` — it is injected automatically

**Step 3 — Set environment variables**

In Railway project → **Variables** tab, add:

| Variable | Value |
|----------|-------|
| `SECRET_KEY` | A long random string (e.g. from `python -c "import secrets; print(secrets.token_hex(32))"`) |
| `ADMIN_EMAIL` | your-email@domain.com |
| `ADMIN_PASSWORD` | A strong password |
| `CAMERA_SOURCE` | `0` (webcam) or `rtsp://user:pass@IP/stream` |
| `ENFORCE_IP_ALLOWLIST` | `false` (set `true` to enable IP blocking) |
| `FLASK_ENV` | `production` |

> Railway injects `DATABASE_URL` automatically from the PostgreSQL plugin — do NOT add it manually.

**Step 4 — Deploy**
1. Railway detects `Procfile` and deploys automatically
2. Visit your Railway-generated URL (e.g. `https://shecure-production.up.railway.app`)
3. Log in with your admin credentials

---

## Camera / CCTV Setup

- **Local webcam:** Set `CAMERA_SOURCE=0` in `.env`
- **IP camera / CCTV:** Set `CAMERA_SOURCE=rtsp://username:password@192.168.1.100:554/stream`
- Stream is served as MJPEG at `/camera/stream`
- Camera status can be checked at `/camera/status`

> On Railway (cloud), direct camera access requires a VPN or tunnel to your local network. For cloud deployments, use an IP camera with a public RTSP URL.

---

## Accessibility (GEDSI Compliance)

- All interactive elements have `aria-label` attributes
- Screen-reader announcements via `role="alert"` and `aria-live`
- Keyboard-navigable sidebar and forms
- Focus-visible outlines in brand pink
- High-contrast text ratios
- Semantic HTML5 (`<nav>`, `<main>`, `<header>`, `<aside>`, `<article>`)
- `.sr-only` utility class for screen-reader-only content
- Mobile-responsive layout

---

## Security Features

- **IP Allow-list** — Blocks all IPs not explicitly approved by admin
- **Rate limiting** — 10 login attempts/minute, 5 registrations/hour
- **Activity logging** — Every page visit is logged with user, IP, method
- **Suspicious pattern detection** — Detects XSS, SQL injection patterns in requests
- **Unauthorized alert panel** — Real-time tab for blocked/suspicious access
- **Role-based access** — Admin, member, viewer roles
- **Password hashing** — Werkzeug secure hashing (PBKDF2)
- **Session security** — Flask-Login with secure cookie handling

---

## License

MIT — for internal organizational use. Security logic in `app/utils/security.py` should remain private.
