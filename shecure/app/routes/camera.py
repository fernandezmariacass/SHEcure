import os
import hmac
import time
import threading
from flask import Blueprint, render_template, Response, request, jsonify, abort
from flask_login import login_required, current_user
from app.utils.security import approved_required
from app import csrf

camera_bp = Blueprint("camera", __name__)

_frame_lock = threading.Lock()
_latest_frame = None
_frame_time = 0
_BROADCASTER_SECRET = os.environ.get("BROADCASTER_SECRET", "")
BROADCASTER_USERNAME = os.environ.get("BROADCASTER_USERNAME", "admin")

# ── Ingest limits ─────────────────────────────────────────────────────────────
MAX_FRAME_BYTES = 500 * 1024   # 500 KB per frame
MIN_FRAME_INTERVAL = 0.05      # max ~20 fps from broadcaster


def _set_frame(jpeg_bytes):
    global _latest_frame, _frame_time
    with _frame_lock:
        _latest_frame = jpeg_bytes
        _frame_time = time.time()


def _clear_frame():
    global _latest_frame, _frame_time
    with _frame_lock:
        _latest_frame = None
        _frame_time = 0


def _get_frame():
    with _frame_lock:
        return _latest_frame, _frame_time


def _generate_viewer_stream():
    while True:
        frame, ts = _get_frame()
        if frame:
            yield (
                b"--frame\r\n"
                b"Content-Type: image/jpeg\r\n\r\n"
                + frame + b"\r\n"
            )
        time.sleep(0.05)


@camera_bp.route("/")
@login_required
@approved_required
def feed_page():
    from app.utils.security import _get_real_ip
    from app.models.user import AllowedIP
    import ipaddress as _ipaddress
    ip = _get_real_ip()
    is_admin = (
        current_user.username == BROADCASTER_USERNAME
        or current_user.role == "admin"
    )
    ip_allowed = False
    if ip and ip != "unknown":
        try:
            client = _ipaddress.ip_address(ip)
            entries = AllowedIP.query.filter_by(is_active=True).all()
            for entry in entries:
                try:
                    if "/" not in entry.ip_address and _ipaddress.ip_address(entry.ip_address) == client:
                        ip_allowed = True
                        break
                    if "/" in entry.ip_address and client in _ipaddress.ip_network(entry.ip_address, strict=False):
                        ip_allowed = True
                        break
                except ValueError:
                    continue
        except ValueError:
            pass
    is_broadcaster = is_admin and ip_allowed
    return render_template(
        "dashboard/camera.html",
        is_broadcaster=is_broadcaster,
        is_admin=is_admin,
        ip_allowed=ip_allowed,
        broadcaster_username=BROADCASTER_USERNAME,
    )


@camera_bp.route("/stream")
@login_required
@approved_required
def stream():
    return Response(
        _generate_viewer_stream(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
    )


def _check_broadcaster_session():
    """Return True if the current logged-in user is allowed to broadcast."""
    from app.models.user import AllowedIP
    import ipaddress as _ipaddress
    from app.utils.security import _get_real_ip
    if not current_user.is_authenticated:
        return False
    is_admin = (
        current_user.username == BROADCASTER_USERNAME
        or current_user.role == "admin"
    )
    if not is_admin:
        return False
    ip = _get_real_ip()
    if not ip or ip == "unknown":
        return False
    try:
        client = _ipaddress.ip_address(ip)
        entries = AllowedIP.query.filter_by(is_active=True).all()
        for entry in entries:
            try:
                if "/" not in entry.ip_address and _ipaddress.ip_address(entry.ip_address) == client:
                    return True
                if "/" in entry.ip_address and client in _ipaddress.ip_network(entry.ip_address, strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False


def _ingest_frame(data):
    """Shared internal frame ingestion logic (caller must have already authorised)."""
    _, last_ts = _get_frame()
    if last_ts and (time.time() - last_ts) < MIN_FRAME_INTERVAL:
        return  # silently drop — too fast
    if not data:
        abort(400)
    if len(data) > MAX_FRAME_BYTES:
        abort(413)
    _set_frame(data)


# ── Browser proxy endpoints (session-auth only, secret never sent to browser) ─

@camera_bp.route("/broadcast", methods=["POST"])
@csrf.exempt
@login_required
def broadcast_proxy():
    """
    Receives raw JPEG frames from the broadcaster's browser.
    The browser authenticates via its login session only — BROADCASTER_SECRET
    is added server-side and never exposed to the client.
    """
    if not _check_broadcaster_session():
        abort(403)
    if not _BROADCASTER_SECRET:
        abort(500)
    data = request.get_data()
    _ingest_frame(data)
    return jsonify({"ok": True})


@camera_bp.route("/clear-broadcast", methods=["POST"])
@csrf.exempt
@login_required
def clear_broadcast_proxy():
    """
    Lets the broadcaster's browser clear the feed on stop.
    Authenticated via login session only — no secret exposed to the browser.
    """
    if not _check_broadcaster_session():
        abort(403)
    _clear_frame()
    return jsonify({"ok": True})


# ── Raw ingest/clear (kept for pusher.py / external agents using the secret) ──

@camera_bp.route("/clear", methods=["POST"])
@csrf.exempt
def clear_feed():
    secret = request.headers.get("X-Broadcaster-Secret", "")
    if not _BROADCASTER_SECRET or not hmac.compare_digest(secret, _BROADCASTER_SECRET):
        abort(403)
    _clear_frame()
    return jsonify({"ok": True})


@camera_bp.route("/ingest", methods=["POST"])
@csrf.exempt
def ingest():
    secret = request.headers.get("X-Broadcaster-Secret", "")
    if not _BROADCASTER_SECRET or not hmac.compare_digest(secret, _BROADCASTER_SECRET):
        abort(403)
    data = request.get_data()
    _ingest_frame(data)
    return jsonify({"ok": True})


@camera_bp.route("/status")
@login_required
def status():
    _, ts = _get_frame()
    online = (time.time() - ts) < 5
    return jsonify({"online": online})


# ── Internal helpers ──────────────────────────────────────────────────────────

import json as _json

# ── WebSocket ingest (used by agent-1.py) ─────────────────────────────────────

def _ws_ingest_handler(ws):
    """
    WebSocket handler for the local agent.
    Protocol:
      1. Agent sends INGEST_KEY as first text message → server replies "OK" or closes.
      2. Agent sends raw JPEG bytes as binary messages → server stores each frame.
    """
    try:
        auth = ws.receive()
        if not _BROADCASTER_SECRET or not hmac.compare_digest(auth, _BROADCASTER_SECRET):
            ws.send("REJECTED")
            return
        ws.send("OK")

        while True:
            data = ws.receive()
            if data is None:
                break
            if isinstance(data, str):
                continue  # ignore stray text
            _ingest_frame(data)
    except Exception:
        pass


def init_websocket(app):
    """
    Call this from create_app() after registering blueprints.
    Uses simple-websocket (already a gevent/gunicorn-compatible dependency).
    """
    from simple_websocket import Server as _WS

    @app.route("/ws/ingest", websocket=True)
    def ws_ingest():
        ws = _WS(request.environ)
        _ws_ingest_handler(ws)
        return ""


# ── Device inventory endpoint (used by agent-1.py) ───────────────────────────

@camera_bp.route("/ingest/devices", methods=["POST"])
@csrf.exempt
def ingest_devices():
    """
    Receives the nmap device list from the local agent.
    Authenticated with X-Ingest-Key (same value as BROADCASTER_SECRET).
    Upserts each device into the network_devices table.
    """
    key = request.headers.get("X-Ingest-Key", "")
    if not _BROADCASTER_SECRET or not hmac.compare_digest(key, _BROADCASTER_SECRET):
        abort(403)

    payload = request.get_json(silent=True)
    if not payload or "devices" not in payload:
        abort(400)

    from app import db
    from app.models.logs import NetworkDevice, now_pst

    for d in payload["devices"]:
        ip = d.get("ip", "").strip()
        if not ip:
            continue
        device = NetworkDevice.query.filter_by(ip=ip).first()
        if device is None:
            device = NetworkDevice(ip=ip)
            db.session.add(device)
        device.mac        = d.get("mac", "N/A")
        device.hostname   = d.get("hostname", ip)
        device.vendor     = d.get("vendor", "Unknown")
        device.open_ports = _json.dumps(d.get("open_ports", []))
        device.os         = d.get("os", "Unknown")
        device.last_seen  = now_pst()

    db.session.commit()
    return jsonify({"ok": True, "count": len(payload["devices"])})


def _log_stream_access():
    """Write an ActivityLog entry for every stream connection."""
    try:
        from app import db
        from app.models.logs import ActivityLog
        from app.utils.security import _get_real_ip
        entry = ActivityLog(
            user_id=current_user.id,
            username=current_user.username,
            ip_address=_get_real_ip(),
            method="GET",
            endpoint="/camera/stream",
            action="Opened camera stream",
            description="Live camera stream session started",
            is_suspicious=False,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        pass  # Never let logging break the stream
