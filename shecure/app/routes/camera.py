import os
import cv2
from flask import Blueprint, render_template, Response, jsonify, request
from flask_login import login_required
from app.utils.security import approved_required

camera_bp = Blueprint("camera", __name__)

# Camera source: 0 = webcam, or RTSP URL from env
CAMERA_SOURCE = os.environ.get("CAMERA_SOURCE", "0")


def _open_camera():
    src = int(CAMERA_SOURCE) if CAMERA_SOURCE.isdigit() else CAMERA_SOURCE
    cap = cv2.VideoCapture(src)
    return cap


def _generate_frames():
    cap = _open_camera()
    if not cap.isOpened():
        return
    try:
        while True:
            success, frame = cap.read()
            if not success:
                break
            _, buffer = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
            yield (
                b"--frame\r\n"
                b"Content-Type: image/jpeg\r\n\r\n" + buffer.tobytes() + b"\r\n"
            )
    finally:
        cap.release()


@camera_bp.route("/")
@login_required
@approved_required
def feed_page():
    source_label = CAMERA_SOURCE if not CAMERA_SOURCE.isdigit() else "Local Webcam"
    return render_template("dashboard/camera.html", source_label=source_label)


@camera_bp.route("/stream")
@login_required
@approved_required
def stream():
    """MJPEG stream endpoint."""
    return Response(
        _generate_frames(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
    )


@camera_bp.route("/status")
@login_required
def status():
    cap = _open_camera()
    ok = cap.isOpened()
    if ok:
        cap.release()
    return jsonify({"online": ok, "source": CAMERA_SOURCE})
