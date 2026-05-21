import os
import time
import threading
from flask import Blueprint, render_template, Response, request, jsonify, abort
from flask_login import login_required, current_user
from app.utils.security import approved_required

camera_bp = Blueprint("camera", __name__)

_frame_lock = threading.Lock()
_latest_frame = None
_frame_time = 0
BROADCASTER_USERNAME = os.environ.get("BROADCASTER_USERNAME", "admin")


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
    return Response(
        _generate_viewer_stream(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
    )


@camera_bp.route("/ingest", methods=["POST"])
def ingest():
    secret = request.headers.get("X-Broadcaster-Secret", "")
    if secret != _BROADCASTER_SECRET:
        abort(403)
    data = request.get_data()
    if not data:
        abort(400)
    _set_frame(data)
    return jsonify({"ok": True})


@camera_bp.route("/status")
@login_required
def status():
    _, ts = _get_frame()
    online = (time.time() - ts) < 5
    return jsonify({"online": online})
