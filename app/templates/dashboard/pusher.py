"""
pusher.py — Run this on YOUR LOCAL machine to stream your webcam/CCTV
            to the Railway server.

Usage:
    python pusher.py --url https://YOUR-APP.railway.app \
                     --secret YOUR_BROADCASTER_SECRET \
                     --source 0
"""

import cv2
import time
import argparse
import requests

def run(server_url, secret, source):
    src = int(source) if str(source).isdigit() else source
    cap = cv2.VideoCapture(src)

    if not cap.isOpened():
        print(f"❌ Cannot open camera source: {source}")
        return

    print(f"✅ Camera open. Streaming to {server_url} ...")
    ingest_url = f"{server_url.rstrip('/')}/camera/ingest"

    while True:
        ok, frame = cap.read()
        if not ok:
            print("⚠️  Frame read failed — retrying...")
            time.sleep(1)
            continue

        _, buf = cv2.imencode(".jpg", frame,
                              [cv2.IMWRITE_JPEG_QUALITY, 70])
        try:
            r = requests.post(
                ingest_url,
                data=buf.tobytes(),
                headers={
                    "Content-Type":         "image/jpeg",
                    "X-Broadcaster-Secret": secret,
                },
                timeout=5,
            )
            if r.status_code != 200:
                print(f"Server replied {r.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"⚠️  Connection error: {e} — retrying in 2s")
            time.sleep(2)

        time.sleep(1 / 15)   # 15 fps

    cap.release()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url",    required=True,  help="Railway app URL")
    parser.add_argument("--secret", required=True,  help="BROADCASTER_SECRET value")
    parser.add_argument("--source", default="0",    help="Camera source: 0=webcam, or RTSP URL")
    args = parser.parse_args()
    run(args.url, args.secret, args.source)
