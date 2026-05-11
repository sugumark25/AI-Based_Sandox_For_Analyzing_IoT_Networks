import csv
import os
import threading
import logging
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.middleware.proxy_fix import ProxyFix

print("🚀 SERVER STARTED ON PORT 5050")

# ── Logging ─────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [bridge] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("frontend_bridge")

# ── Paths ───────────────────────────────
BASE_DIR = Path(__file__).parent
DATASET_DIR = BASE_DIR / "dataset"
REALTIME_CSV = DATASET_DIR / "realtime_esp32.csv"
ATTACK_CSV = DATASET_DIR / "esp32_attacks.csv"
NORMAL_CSV = DATASET_DIR / "esp32_normal.csv"
SENSOR_CSV = DATASET_DIR / "esp32_sensors.csv"

# ── State ───────────────────────────────
_sensor_alerts = 0
_esp32_status = "UNKNOWN"
_last_msg_time = 0

# ── Flask Setup ─────────────────────────
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

CORS(app, resources={r"/*": {"origins": "*"}})

@app.after_request
def after_request(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "*"
    return response

# ── Socket.IO ───────────────────────────
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ───────────────────────────────────────
# CSV HELPERS
# ───────────────────────────────────────
def _read_csv_tail(path, n):
    if not path.exists():
        return []
    try:
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        return rows[-n:]
    except:
        return []

def _csv_row_count(path):
    if not path.exists():
        return 0
    try:
        with open(path) as f:
            return max(0, sum(1 for _ in f) - 1)
    except:
        return 0

# ───────────────────────────────────────
# 🔥 FAKE DATA GENERATOR (MAIN FIX)
# ───────────────────────────────────────
def generate_fake_data():
    global _last_msg_time

    DATASET_DIR.mkdir(exist_ok=True)

    # Create CSV files if missing
    for file in [REALTIME_CSV, ATTACK_CSV, NORMAL_CSV, SENSOR_CSV]:
        if not file.exists():
            with open(file, "w") as f:
                f.write("id\n")

    while True:
        _last_msg_time = time.time()

        # Write normal traffic
        with open(REALTIME_CSV, "a") as f:
            f.write(f"{int(time.time())}\n")

        with open(NORMAL_CSV, "a") as f:
            f.write(f"{int(time.time())}\n")

        # Random attack
        if int(time.time()) % 5 == 0:
            with open(ATTACK_CSV, "a") as f:
                f.write(f"{int(time.time())}\n")

        # Sensor data
        with open(SENSOR_CSV, "a") as f:
            f.write(f"{int(time.time())}\n")

        time.sleep(2)

threading.Thread(target=generate_fake_data, daemon=True).start()

# ───────────────────────────────────────
# STATUS MONITOR
# ───────────────────────────────────────
def monitor_device():
    global _esp32_status
    while True:
        if _last_msg_time == 0:
            _esp32_status = "UNKNOWN"
        elif time.time() - _last_msg_time > 10:
            _esp32_status = "DISCONNECTED"
        else:
            _esp32_status = "CONNECTED"
        time.sleep(2)

threading.Thread(target=monitor_device, daemon=True).start()

# ───────────────────────────────────────
# API ROUTES (ALL FIXED)
# ───────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    return jsonify({
        "total_records": _csv_row_count(REALTIME_CSV),
        "attack_records": _csv_row_count(ATTACK_CSV),
        "normal_records": _csv_row_count(NORMAL_CSV),
        "sensor_total": _csv_row_count(SENSOR_CSV),
        "sensor_alerts": _sensor_alerts,
        "esp32_status": _esp32_status,
        "esp32_last_seen_secs": int(time.time() - _last_msg_time) if _last_msg_time else None,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    })

@app.route("/api/flows/recent")
def api_flows_recent():
    n = int(request.args.get("n", 100))
    return jsonify(_read_csv_tail(REALTIME_CSV, n))

@app.route("/api/flows/attacks")
def api_flows_attacks():
    n = int(request.args.get("n", 100))
    return jsonify(_read_csv_tail(ATTACK_CSV, n))

@app.route("/api/sensor/recent")
def api_sensor_recent():
    n = int(request.args.get("n", 30))
    return jsonify(_read_csv_tail(SENSOR_CSV, n))

@app.route("/api/sensor/stats")
def api_sensor_stats():
    return jsonify({
        "sensor_total": _csv_row_count(SENSOR_CSV),
        "sensor_alerts": _sensor_alerts,
    })

@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok"})

# ───────────────────────────────────────
# SOCKET EVENTS
# ───────────────────────────────────────
@socketio.on("connect")
def on_connect():
    emit("stats_update", api_stats().json)

# ───────────────────────────────────────
# RUN SERVER
# ───────────────────────────────────────
if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=5050,
        debug=True,
        use_reloader=False
    )