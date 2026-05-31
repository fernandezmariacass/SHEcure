import os
import hmac
import time
import threading
from flask import Blueprint, render_template, Response, request, jsonify, abort
from flask_login import login_required, current_user
from app.utils.security import approved_required

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
    is_broadcaster = (
        current_user.username == BROADCASTER_USERNAME
        or current_user.role == "admin"
    )
    return render_template(
        "dashboard/camera.html",
        is_broadcaster=is_broadcaster,
        broadcaster_username=BROADCASTER_USERNAME,
    )


@camera_bp.route("/stream")
@login_required
@approved_required
def stream():
    # ADDED: log every stream connection for accountability
    _log_stream_access()
    return Response(
        _generate_viewer_stream(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
    )


@camera_bp.route("/ingest", methods=["POST"])
def ingest():
    secret = request.headers.get("X-Broadcaster-Secret", "")
    if not _BROADCASTER_SECRET or not hmac.compare_digest(secret, _BROADCASTER_SECRET):
        abort(403)

    # ADDED: enforce minimum interval to prevent DoS via frame flooding
    _, last_ts = _get_frame()
    if last_ts and (time.time() - last_ts) < MIN_FRAME_INTERVAL:
        # Silently drop — don't penalise the broadcaster, just skip the frame
        return jsonify({"ok": True})

    data = request.get_data()
    if not data:
        abort(400)

    # ADDED: enforce max frame size to prevent memory exhaustion
    if len(data) > MAX_FRAME_BYTES:
        abort(413)

    _set_frame(data)
    return jsonify({"ok": True})


@camera_bp.route("/status")
@login_required
def status():
    _, ts = _get_frame()
    online = (time.time() - ts) < 5
    return jsonify({"online": online})


# ── Internal helpers ──────────────────────────────────────────────────────────

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
