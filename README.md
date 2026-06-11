# SHEcure

> **GEDSI-aligned CCTV Network Monitoring System** — Built for COMP 012 Network Administration, PUP Santa Rosa Campus, AY 2025–2026.

SHEcure is a full-stack Python (Flask) web application that connects to a physical CCTV camera over a local network and provides real-time monitoring, strict login security, comprehensive user activity logging, PostgreSQL database, and cloud deployment via Railway.

---

## Network Diagram

```
[ CCTV Camera ]
      |
  (Ethernet / IP)
      |
[ Router/Switch ] ←——— [ PC / Laptop running SHEcure ]
      |
  (Local Network)
      |
[ Web Browser ] → http://<server-ip>:5000
```

- CCTV camera is connected to the router via Ethernet or Wi-Fi
- Camera is assigned a static IP (e.g. `192.168.1.100`)
- RTSP stream is accessed by the Flask app and served as MJPEG to the browser
- Cloud deployment (Railway) accesses the camera via the public RTSP URL or VPN tunnel

---

## Screenshots

1. Shecure Login

   ![Login](screenshots/shecure/shecure-login.png)
   
3. Shecure Authenticator

   ![Authenticator](screenshots/shecure/shecure-authenticator.png)
   
5. (Admin) Dashboard

   ![Dashboard](screenshots/admin/admin-dashboard.png)
   
7. (Admin) Camera Feed

   ![Dashboard](screenshots/admin/admin-camera-feed.png)
   
9. (Admin) Activity Log

    ![Dashboard](screenshots/admin/admin-activity-log.png)
   
11. (Admin) Alerts

    ![Dashboard](screenshots/admin/admin-alerts.png)
    
13. (Admin) Admin Panel

    ![Dashboard](screenshots/admin/admin-admin-panel.png)
    
15. (Admin) Access Logs

    ![Dashboard](screenshots/admin/admin-access-logs.png)
    
17. (Member) Dashboard

    ![Member Dashboard](screenshots/member/member-dashboard.png)
   


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
│   │   ├── security.py          # IP allow-list, suspicious pattern detection
│   │   └── username_enc.py      # Fernet encryption for usernames at rest
│   ├── templates/
│   │   ├── base.html
│   │   ├── auth/                # Login & register pages
│   │   ├── dashboard/           # Dashboard, camera, alerts, activity
│   │   ├── admin/               # Admin panel, logs
│   │   └── errors/              # 403, 404 pages
│   └── static/
│       ├── css/main.css
│       └── js/main.js
├── run.py
├── requirements.txt
├── Procfile                     # Gunicorn for Railway
├── railway.toml
└── .gitignore
```

---

## Features

### Physical CCTV + Network
- Physical CCTV camera connected to router via Ethernet
- Network configured with correct IP addressing
- Camera feed accessible over the network via RTSP stream

### Web-Based Monitoring System
- Live CCTV feed displayed on the monitoring dashboard
- Real-time MJPEG video stream at `/camera/stream`
- Camera status check at `/camera/status`
- Responsive dashboard interface

### User Authentication & Security Logs
- Hashed passwords (Werkzeug PBKDF2 / scrypt)
- Encrypted usernames at rest (Fernet + HMAC)
- Role-based access control (admin, member, viewer)
- Session management via Flask-Login
- Rate limiting — 10 login attempts/minute, 5 registrations/hour
- IP allow-list — blocks all unapproved IPs
- Complete user activity logs: login/logout timestamps, actions, IP addresses
- Unauthorized access alert panel
- Logs viewable in the admin panel

### PostgreSQL Database
- Cloud PostgreSQL via Railway
- Tables: `users`, `access_logs`, `activity_logs`, `unauthorized_alerts`, `allowed_ips`
- Proper relationships and structured schema

### Cloud Deployment
- Deployed on Railway with public URL
- Auto-deploys on every GitHub push

---

## Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/fernandezmariacass/SHEcure.git
cd SHEcure/shecure

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

## Camera / CCTV Setup

- **Local webcam:** Set `CAMERA_SOURCE=0` in `.env`
- **IP camera / CCTV:** Set `CAMERA_SOURCE=rtsp://username:password@192.168.1.100:554/stream`
- Stream is served as MJPEG at `/camera/stream`

---

## Deploy to Railway

**Step 1 — Create Railway project**
1. Go to https://railway.app and log in
2. Click **New Project → Deploy from GitHub repo**
3. Authorize Railway and select the `SHEcure` repository

**Step 2 — Add PostgreSQL database**
1. In your Railway project, click **+ New** → **Database** → **PostgreSQL**
2. Railway auto-generates `DATABASE_URL` — injected automatically

**Step 3 — Set environment variables**

| Variable | Value |
|----------|-------|

**Step 4 — Deploy**
1. Railway detects `Procfile` and deploys automatically
2. Visit your Railway-generated public URL
3. Log in with your admin credentials

---

## Security Features

- Hashed passwords (scrypt via Werkzeug)
- Encrypted usernames at rest (Fernet + HMAC index)
- IP allow-list with admin-managed entries
- Rate limiting on login and registration
- Role-based access control
- Session security via Flask-Login
- Full activity and access logging
- Suspicious pattern detection (XSS, SQLi)
- Unauthorized alert panel

