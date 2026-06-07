"""
honeypot.py — Fake route traps for automated scanners and attackers.

How it works:
- A set of well-known "attacker magnet" paths are registered as real Flask routes.
- Any hit on these paths fires a maximum-severity UnauthorizedAlert and an
  AccessLog entry (status="blocked"), then returns a convincing decoy response
  so the attacker believes the path exists and keeps probing — giving you more
  signal without tipping them off.
- The response deliberately mimics what a real WordPress/phpMyAdmin/etc. server
  would return so automated scanners don't skip it as "obviously fake".
- All hits are logged with threat_score=100; the IP, user agent, method, and
  full query string are captured for investigation.

No template files required — responses are plain HTML strings returned inline.

Registration:
    In app/__init__.py, import and register this blueprint BEFORE the security
    middleware so honeypot routes resolve properly:

        from app.routes.honeypot import honeypot_bp
        app.register_blueprint(honeypot_bp)
"""

import logging
from flask import Blueprint, request, Response
from app.utils.security import _get_real_ip

log = logging.getLogger(__name__)

honeypot_bp = Blueprint("honeypot", __name__)

# ── Decoy HTML responses keyed by "flavour" ──────────────────────────────────
# Each response is convincing enough to fool a scanner into thinking the
# service exists, but contains nothing real.

_DECOY_WP_LOGIN = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Log In &lsaquo; SHEcure &#8212; WordPress</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;min-height:100vh}
  #login{width:320px;margin:80px auto 0}
  #login h1{text-align:center;margin-bottom:20px}
  #login h1 a{display:inline-block;width:80px;height:80px;background:#23282d;border-radius:50%;text-indent:-9999px;overflow:hidden}
  .wp-form{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:26px 24px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
  .wp-form label{display:block;font-size:14px;font-weight:600;color:#1d2327;margin-bottom:4px}
  .wp-form input[type=text],.wp-form input[type=password]{display:block;width:100%;padding:8px 10px;font-size:15px;border:1px solid #8c8f94;border-radius:4px;color:#1d2327;margin-bottom:16px;outline:none}
  .wp-form input[type=text]:focus,.wp-form input[type=password]:focus{border-color:#2271b1;box-shadow:0 0 0 1px #2271b1}
  .forgetmenot{display:flex;align-items:center;gap:6px;margin-bottom:16px;font-size:13px;color:#50575e}
  .wp-form input[type=submit]{display:block;width:100%;padding:10px;font-size:14px;font-weight:600;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer}
  .wp-form input[type=submit]:hover{background:#135e96}
  #nav,#backtoblog{text-align:center;margin-top:12px;font-size:13px}
  #nav a,#backtoblog a{color:#50575e;text-decoration:none}
</style>
</head>
<body class="login">
<div id="login">
  <h1><a href="https://wordpress.org/">WordPress</a></h1>
  <div class="wp-form">
    <form name="loginform" id="loginform" action="/wp-login.php" method="post">
      <label for="user_login">Username or Email Address</label>
      <input type="text" name="log" id="user_login" autocomplete="username"/>
      <label for="user_pass">Password</label>
      <input type="password" name="pwd" id="user_pass" autocomplete="current-password"/>
      <div class="forgetmenot"><input type="checkbox" name="rememberme" id="rememberme"/><label for="rememberme">Remember Me</label></div>
      <input type="submit" name="wp-submit" id="wp-submit" value="Log In"/>
      <input type="hidden" name="redirect_to" value="/wp-admin/"/>
    </form>
  </div>
  <p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
  <p id="backtoblog"><a href="/">&larr; Go to SHEcure</a></p>
</div>
</body></html>
"""

_DECOY_PHPMYADMIN = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>phpMyAdmin</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#f5f5f5;font-family:Arial,sans-serif;min-height:100vh}
  #pma_header{background:#f5f5f5;border-bottom:1px solid #ccc;padding:8px 16px;font-size:18px;font-weight:bold;color:#333}
  #pma_header small{font-size:11px;color:#666;font-weight:normal;margin-left:6px}
  .pma-login{width:380px;margin:50px auto 0;background:#fff;border:1px solid #ccc;border-radius:2px;box-shadow:0 2px 4px rgba(0,0,0,.1)}
  .pma-login-header{background:#f0f0f0;border-bottom:1px solid #ccc;padding:10px 16px;font-size:14px;font-weight:bold;color:#333}
  .pma-login-body{padding:20px 16px}
  .pma-login-body label{display:block;font-size:13px;color:#555;margin-bottom:4px}
  .pma-login-body input[type=text],.pma-login-body input[type=password]{display:block;width:100%;padding:7px 9px;font-size:13px;border:1px solid #aaa;border-radius:2px;margin-bottom:14px;outline:none}
  .pma-login-body input[type=text]:focus,.pma-login-body input[type=password]:focus{border-color:#5d8fbd}
  .pma-login-footer{background:#f9f9f9;border-top:1px solid #e0e0e0;padding:10px 16px;text-align:right}
  .pma-login-footer input[type=submit]{padding:7px 18px;font-size:13px;background:#5d8fbd;color:#fff;border:none;border-radius:2px;cursor:pointer}
  .pma-login-footer input[type=submit]:hover{background:#4a7aab}
</style>
</head>
<body>
<div id="pma_header">phpMyAdmin<small>5.2.1</small></div>
<div class="pma-login">
  <div class="pma-login-header">Log in</div>
  <form method="post" action="index.php">
    <div class="pma-login-body">
      <label for="pma_username">Username:</label>
      <input type="text" name="pma_username" id="pma_username" autocomplete="username"/>
      <label for="pma_password">Password:</label>
      <input type="password" name="pma_password" id="pma_password" autocomplete="current-password"/>
    </div>
    <div class="pma-login-footer"><input type="submit" value="Log in"/></div>
  </form>
</div>
</body></html>
"""

_DECOY_GENERIC_ADMIN = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin Panel</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#1a1a2e;font-family:"Segoe UI",Arial,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
  .panel{width:360px;background:#16213e;border:1px solid #0f3460;border-radius:8px;overflow:hidden;box-shadow:0 8px 32px rgba(0,0,0,.4)}
  .panel-header{background:#0f3460;padding:18px 24px;display:flex;align-items:center;gap:10px}
  .panel-icon{width:32px;height:32px;background:#e94560;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:18px;color:#fff;flex-shrink:0}
  .panel-header span{color:#fff;font-size:16px;font-weight:600}
  .panel-body{padding:28px 24px}
  .panel-body label{display:block;font-size:12px;font-weight:600;color:#8892b0;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
  .panel-body input[type=text],.panel-body input[type=password]{display:block;width:100%;padding:10px 12px;font-size:14px;background:#0f3460;border:1px solid #1a4a7a;border-radius:4px;color:#ccd6f6;margin-bottom:18px;outline:none}
  .panel-body input[type=text]:focus,.panel-body input[type=password]:focus{border-color:#e94560}
  .panel-body button{display:block;width:100%;padding:11px;font-size:14px;font-weight:600;background:#e94560;color:#fff;border:none;border-radius:4px;cursor:pointer}
  .panel-body button:hover{background:#c73652}
  .panel-footer{padding:10px 24px 18px;text-align:center;font-size:12px;color:#4a5568}
</style>
</head>
<body>
<div class="panel">
  <div class="panel-header">
    <div class="panel-icon">&#9881;</div>
    <span>Administration</span>
  </div>
  <div class="panel-body">
    <form method="post">
      <label for="username">Username</label>
      <input type="text" name="username" id="username" autocomplete="username"/>
      <label for="password">Password</label>
      <input type="password" name="password" id="password" autocomplete="current-password"/>
      <button type="submit">Sign In</button>
    </form>
  </div>
  <div class="panel-footer">Restricted access &mdash; authorized personnel only</div>
</div>
</body></html>
"""


_DECOY_ENV = "APP_ENV=production\nDB_HOST=localhost\nDB_USER=root\nDB_PASS=\nSECRET_KEY=\n"

_DECOY_GIT_CONFIG = """\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = git@github.com:example/shecure.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
"""

_DECOY_XMLRPC = """\
<?xml version="1.0"?>
<methodResponse><fault><value><struct>
  <member><name>faultCode</name><value><int>403</int></value></member>
  <member><name>faultString</name><value><string>XML-RPC services are disabled.</string></value></member>
</struct></value></fault></methodResponse>
"""

# ── Route definitions ─────────────────────────────────────────────────────────
# Each tuple: (path, methods, decoy_html, content_type, http_status, flavour_label)
#
# http_status is what we send back to the scanner. 200 is most convincing for
# login pages; 403 for paths that "exist but are protected". Either way, the
# alert is always logged on our side.

_TRAPS = [
    # WordPress
    ("/wp-admin",               ["GET", "POST"], _DECOY_WP_LOGIN,       "text/html", 200, "WordPress admin"),
    ("/wp-admin/",              ["GET", "POST"], _DECOY_WP_LOGIN,       "text/html", 200, "WordPress admin"),
    ("/wp-login.php",           ["GET", "POST"], _DECOY_WP_LOGIN,       "text/html", 200, "WordPress login"),
    ("/wp-config.php",          ["GET"],         _DECOY_ENV,            "text/plain", 200, "WordPress config"),
    ("/xmlrpc.php",             ["GET", "POST"], _DECOY_XMLRPC,         "text/xml",  200, "WordPress XML-RPC"),
    # phpMyAdmin
    ("/phpmyadmin",             ["GET", "POST"], _DECOY_PHPMYADMIN,     "text/html", 200, "phpMyAdmin"),
    ("/phpmyadmin/",            ["GET", "POST"], _DECOY_PHPMYADMIN,     "text/html", 200, "phpMyAdmin"),
    ("/pma",                    ["GET", "POST"], _DECOY_PHPMYADMIN,     "text/html", 200, "phpMyAdmin (pma)"),
    ("/pma/",                   ["GET", "POST"], _DECOY_PHPMYADMIN,     "text/html", 200, "phpMyAdmin (pma)"),
    ("/mysql",                  ["GET", "POST"], _DECOY_PHPMYADMIN,     "text/html", 200, "MySQL admin"),
    # Generic admin panels
    ("/admin.php",              ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "admin.php"),
    ("/administrator",          ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "Joomla admin"),
    ("/administrator/",         ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "Joomla admin"),
    ("/panel",                  ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "Generic panel"),
    ("/cpanel",                 ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "cPanel"),
    ("/webadmin",               ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "WebAdmin"),
    ("/manage",                 ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "Manage panel"),
    ("/portal",                 ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "Portal"),
    # Environment / secret files
    ("/.env",                   ["GET"],         _DECOY_ENV,            "text/plain", 200, ".env file"),
    ("/.env.local",             ["GET"],         _DECOY_ENV,            "text/plain", 200, ".env.local file"),
    ("/.env.production",        ["GET"],         _DECOY_ENV,            "text/plain", 200, ".env.production"),
    ("/config.php",             ["GET"],         _DECOY_ENV,            "text/plain", 200, "config.php"),
    ("/config.yaml",            ["GET"],         _DECOY_ENV,            "text/plain", 200, "config.yaml"),
    ("/settings.php",           ["GET"],         _DECOY_ENV,            "text/plain", 200, "settings.php"),
    # Git exposure
    ("/.git/config",            ["GET"],         _DECOY_GIT_CONFIG,     "text/plain", 200, ".git/config"),
    ("/.git/HEAD",              ["GET"],         "ref: refs/heads/main\n", "text/plain", 200, ".git/HEAD"),
    # Shells and backdoors
    ("/shell.php",              ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "PHP shell"),
    ("/backdoor.php",           ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "Backdoor"),
    ("/cmd.php",                ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "cmd.php"),
    ("/c99.php",                ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "c99 shell"),
    ("/r57.php",                ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "r57 shell"),
    # Misc common scan targets
    ("/setup.php",              ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "setup.php"),
    ("/install.php",            ["GET", "POST"], _DECOY_GENERIC_ADMIN,  "text/html", 200, "install.php"),
    ("/backup",                 ["GET"],         _DECOY_GENERIC_ADMIN,  "text/html", 200, "backup dir"),
    ("/backup.zip",             ["GET"],         b"\x50\x4B\x05\x06" + b"\x00" * 18,
                                                                       "application/zip", 200, "backup.zip"),
    ("/db.sql",                 ["GET"],         "-- MySQL dump\n-- Honeypot\n", "text/plain", 200, "db.sql"),
    ("/server-status",          ["GET"],         "<h1>Apache Server Status</h1><p>Honeypot.</p>", "text/html", 200, "Apache status"),
    ("/server-info",            ["GET"],         "<h1>Apache Server Info</h1><p>Honeypot.</p>", "text/html", 200, "Apache info"),
]


_BLOCK_HOURS = 24   # how long a honeypot hit bans the IP


def _fire_honeypot_route_alert(flavour: str) -> None:
    """Log an UnauthorizedAlert + AccessLog for a honeypot route hit,
    then auto-ban the attacker's IP for _BLOCK_HOURS hours.
    """
    from app import db
    from app.models.logs import UnauthorizedAlert, AccessLog
    from app.utils.security import block_ip

    ip = _get_real_ip()  # FIX: use XFF-aware helper, not raw remote_addr (avoids banning the load balancer IP)
    ua = (request.user_agent.string or "")[:512]
    endpoint = request.path
    method = request.method
    qs = request.query_string.decode("utf-8", errors="ignore")

    reason = (
        f"HONEYPOT ROUTE HIT — fake path '{endpoint}' probed "
        f"(matches '{flavour}'). "
        f"Query string: '{qs[:100]}'. "
        "Likely automated scanner or attacker reconnaissance."
    )

    try:
        db.session.rollback()

        alert = UnauthorizedAlert(
            ip_address=ip,
            user_agent=ua,
            endpoint=endpoint[:256],
            method=method,
            threat_score=100,
            threat_reason=reason[:300],
            notes=(
                f"Honeypot route trap triggered. Flavour: {flavour}. "
                f"Method: {method}. QS: {qs[:200]}. UA: {ua[:200]}. "
                f"IP auto-banned for {_BLOCK_HOURS}h."
            ),
            resolved=False,
        )
        db.session.add(alert)

        log_entry = AccessLog(
            username_attempted="<unknown>",
            ip_address=ip,
            user_agent=ua,
            status="blocked",
            reason=f"Honeypot route: {flavour} — auto-banned {_BLOCK_HOURS}h",
            is_unauthorized=True,
        )
        db.session.add(log_entry)

        db.session.commit()
        log.warning(
            "[honeypot] %s %s from %s — alert filed, IP banned %dh (flavour: %s)",
            method, endpoint, ip, _BLOCK_HOURS, flavour,
        )

    except Exception as exc:
        db.session.rollback()
        log.error("[honeypot] DB write failed: %s", exc)

    # Auto-ban the IP — runs even if the alert DB write partially failed.
    # block_ip() does its own session rollback+commit so it is safe here.
    try:
        block_ip(
            ip,
            reason=f"Honeypot auto-ban: probed '{endpoint}' ({flavour})",
            hours=_BLOCK_HOURS,
        )
    except Exception as exc:
        log.error("[honeypot] block_ip failed for %s: %s", ip, exc)


_ACCESS_DENIED_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Denied | SHEcure</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@600;700&family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: #fff0f7;
      font-family: 'DM Sans', sans-serif;
      display: grid;
      place-items: center;
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }}
    .shell {{
      position: relative;
      width: min(480px, calc(100vw - 2rem));
      text-align: center;
      padding: 2.5rem 2rem;
      background: #ffffff;
      border: 1.5px solid #ffadd7;
      border-radius: 20px;
      box-shadow: 0 12px 40px rgba(233,30,140,.18), 0 4px 16px rgba(0,0,0,.08);
      animation: appear 0.25s cubic-bezier(.34,1.56,.64,1) both;
      overflow: hidden;
    }}
    .shell::before {{
      content: '';
      position: absolute;
      inset: 0;
      background:
        radial-gradient(circle at 90% 10%, rgba(233,30,140,.05) 0%, transparent 60%),
        radial-gradient(circle at 10% 90%, rgba(233,30,140,.04) 0%, transparent 60%);
      pointer-events: none;
    }}
    @keyframes appear {{
      from {{ opacity: 0; transform: translateY(14px) scale(0.97); }}
      to   {{ opacity: 1; transform: translateY(0)   scale(1);    }}
    }}
    .glyph {{
      font-size: 3rem;
      line-height: 1;
      margin-bottom: 0.75rem;
      filter: drop-shadow(0 2px 8px rgba(233,30,140,.25));
    }}
    .code {{
      font-family: 'Playfair Display', Georgia, serif;
      font-size: 5rem;
      font-weight: 700;
      line-height: 1;
      color: #e91e8c;
      text-shadow: 0 0 28px rgba(233,30,140,.3);
      letter-spacing: -2px;
    }}
    .label {{
      font-family: 'Playfair Display', Georgia, serif;
      font-size: 1.35rem;
      font-weight: 600;
      color: #9c1261;
      letter-spacing: 3px;
      text-transform: uppercase;
      margin: 0.4rem 0 1.4rem;
    }}
    .msg {{
      font-size: 0.9rem;
      color: #4b5563;
      line-height: 1.7;
      margin-bottom: 1.25rem;
    }}
    .ip-badge {{
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.4rem 1.1rem;
      background: #fff0f7;
      border: 1.5px solid #ffadd7;
      border-radius: 9999px;
      font-family: 'DM Mono', 'Courier New', monospace;
      font-size: 0.85rem;
      color: #9c1261;
      letter-spacing: 0.05em;
      margin-bottom: 1.5rem;
    }}
    .ip-badge::before {{ content: '⟡'; font-size: 0.8rem; color: #f754a8; }}
    .warn-box {{
      padding: 0.75rem 1rem;
      background: #fce4f0;
      border: 1px solid #ffadd7;
      border-radius: 12px;
      color: #9c1261;
      font-size: 0.83rem;
      line-height: 1.5;
    }}
    .footer {{
      margin-top: 1.75rem;
      padding-top: 1rem;
      border-top: 1px solid #ffd6ec;
      font-family: 'DM Mono', 'Courier New', monospace;
      font-size: 0.75rem;
      color: #c084a0;
      letter-spacing: 0.05em;
    }}
  </style>
</head>
<body>
  <div class="shell" role="main">
    <div class="glyph">🚫</div>
    <div class="code">403</div>
    <div class="label">Access Denied</div>
    <p class="msg">
      This request has been logged and your IP has been flagged.<br>
      Further probing may result in permanent restriction.
    </p>
    <div class="ip-badge">{ip}</div>
    <div class="warn-box" role="alert">
      ⚠︎&nbsp; This incident has been reported to the system administrator.
      Further requests from this IP continue to be recorded.
    </div>
    <div class="footer">// .☘︎ &#x035D;&#x02D6; shecure &mdash; no access from this address //</div>
  </div>
</body>
</html>
"""


def _log_honeypot_visit(flavour: str) -> None:
    """Log that a honeypot page was visited (GET) without banning yet.
    The attacker sees the decoy — we record the recon quietly.
    """
    from app.models.logs import AccessLog

    ip = _get_real_ip()  # FIX: use XFF-aware helper
    ua = (request.user_agent.string or "")[:512]
    endpoint = request.path

    try:
        from app import db
        db.session.rollback()
        log_entry = AccessLog(
            username_attempted="<unknown>",
            ip_address=ip,
            user_agent=ua,
            status="honeypot_visit",
            reason=f"Honeypot page visited (GET): {flavour} — watching",
            is_unauthorized=True,
        )
        db.session.add(log_entry)
        db.session.commit()
        log.warning(
            "[honeypot] GET %s from %s — decoy served, watching (flavour: %s)",
            endpoint, ip, flavour,
        )
    except Exception as exc:
        log.error("[honeypot] visit log failed: %s", exc)


def _make_handler(body, content_type: str, status: int, flavour: str):
    """Return a Flask view function for one honeypot trap.

    GET  -> serve the convincing decoy page so the attacker thinks they found
            something real. Log the visit quietly but do NOT ban yet.

    POST -> they tried to submit credentials. Ban the IP, fire the full alert,
            and show the Access Denied page.

    GET-only traps (.env, .git/config, backup.zip, db.sql, etc.) ->
            ban immediately on GET since fetching the file IS the attack.
    """
    # Only defer the ban to POST for interactive HTML pages that have a form.
    _is_interactive = (
        content_type == "text/html"
        and isinstance(body, str)
        and "<form" in body
    )

    def handler(**_kwargs):
        # Always ban immediately — GET or POST.
        try:
            _fire_honeypot_route_alert(flavour)
        except Exception as exc:
            log.error("[honeypot] alert failed: %s", exc)

        if request.method == "GET" and _is_interactive:
            # Serve the fake page — they are already banned.
            # Next visit to /login will be blocked.
            if isinstance(body, bytes):
                resp = Response(body, status=status, mimetype=content_type)
            else:
                resp = Response(body.encode("utf-8"), status=status, mimetype=content_type)
        else:
            # POST or file path GET — render the system banned page (pinkish).
            from flask import render_template, current_app
            ip = _get_real_ip()  # FIX: use XFF-aware helper
            with current_app.app_context():
                resp = Response(
                    render_template("errors/banned.html", client_ip=ip),
                    status=403,
                    mimetype="text/html",
                )

        # Set the block cookie on every response
        resp.set_cookie(
            "_hp_block", "1",
            max_age=86400,
            httponly=True,
            samesite="Lax",
        )
        return resp

    # Flask requires unique function names per route
    handler.__name__ = f"_honeypot_{flavour.replace(' ', '_').replace('/', '_').replace('.', '_')}"
    return handler


# Dynamically register all traps on the blueprint
_registered_names = set()
for _path, _methods, _body, _ctype, _status, _flavour in _TRAPS:
    _name = _flavour.replace(" ", "_").replace("/", "_").replace(".", "_")
    # Deduplicate handler names (e.g. wp-admin trailing slash shares a flavour)
    _suffix = 0
    _unique_name = _name
    while _unique_name in _registered_names:
        _suffix += 1
        _unique_name = f"{_name}_{_suffix}"
    _registered_names.add(_unique_name)

    _view_func = _make_handler(_body, _ctype, _status, _flavour)
    _view_func.__name__ = f"_honeypot_{_unique_name}"
    honeypot_bp.add_url_rule(
        _path,
        endpoint=f"honeypot_{_unique_name}",
        view_func=_view_func,
        methods=_methods,
    )


# FIX: the original set had only 5 entries — far too small to catch real credential-
# stuffing attempts. Expanded to the most-sprayed passwords from public breach dumps.
# These are chosen because:
#   (a) they appear in virtually every credential-stuffing wordlist in the wild, AND
#   (b) no legitimate user of a security-focused app should ever use them.
# This is intentionally NOT a full deny-list (validate_password_strength() + the
# HaveIBeenPwned check cover the rest); it exists solely to catch drive-by attacks
# so we can fire an alert and ban the IP immediately.
_HONEYPOT_PASSWORD_SET = {
    # top-10 all-time
    "password", "123456", "12345678", "1234567890", "qwerty", "abc123",
    "password1", "iloveyou", "admin", "letmein", "welcome", "monkey",
    "dragon", "master", "sunshine", "princess", "shadow", "superman",
    "michael", "football", "login", "passw0rd", "pass@123", "pass1234",
    # "admin" variants — most sprayed against web panels
    "admin123", "admin1234", "admin@123", "admin@2024", "admin@2025",
    "administrator", "adminadmin",
    # app-name variants (SHEcure-specific)
    "shecure", "shecure2025", "shecure@2025", "shecure@2025!", "shecure2024",
    # year + common suffix patterns
    "password2024", "password2025", "password@2024", "password@2025",
    # keyboard walks
    "qwerty123", "qwerty1234", "qwertyuiop", "1q2w3e4r", "1qaz2wsx",
    # classic short pins used as passwords
    "123456789", "12345", "1234", "111111", "000000", "654321",
    # common words
    "test", "testing", "guest", "demo", "user", "root", "toor",
    "honeypot", "changeme", "default", "blank",
}

def is_honeypot_password(password: str) -> bool:
    """Return True if the password matches a known honeypot credential."""
    return password.lower() in _HONEYPOT_PASSWORD_SET


# FIX: corrected signature — was (username, password) which caused a TypeError
# when auth.py called fire_honeypot_alert(username, ip, ua), crashing the function
# before block_ip() was ever reached and leaving the IP un-banned.
def fire_honeypot_alert(username: str, ip: str, ua: str) -> None:
    """Log an alert when honeypot credentials are submitted on the login form."""
    from app import db
    from app.models.logs import UnauthorizedAlert, AccessLog
    from app.utils.security import block_ip

    try:
        db.session.rollback()
        alert = UnauthorizedAlert(
            ip_address=ip,
            user_agent=ua[:512],
            endpoint="/login",
            method="POST",
            threat_score=100,
            threat_reason=f"Honeypot credentials used: username='{username}'",
            notes=f"Login honeypot triggered. IP auto-banned for 24h.",
            resolved=False,
        )
        db.session.add(alert)
        log_entry = AccessLog(
            username_attempted=username,
            ip_address=ip,
            user_agent=ua[:512],
            status="blocked",
            reason="Honeypot login credentials detected",
            is_unauthorized=True,
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        log.error("[honeypot] fire_honeypot_alert DB write failed: %s", exc)

    try:
        block_ip(ip, reason="Honeypot login auto-ban", hours=24)
    except Exception as exc:
        log.error("[honeypot] block_ip failed for %s: %s", ip, exc)
