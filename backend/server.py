import os, time, random, threading, joblib
from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from routes import api_bp
from utils.feature_extraction import extract_features

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "iot-secret-2024")

# ✅ KEEP CORS (already correct)
CORS(app, resources={r"/*": {"origins": "*"}})

# ✅ KEEP SOCKET (just minor stability tweak)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    logger=False,
    engineio_logger=False
)

# ✅ REGISTER API ROUTES
app.register_blueprint(api_bp, url_prefix="/api")

# ─────────────────────────────────────────────────────
# MODEL PATHS
# ─────────────────────────────────────────────────────
MODEL_DIR   = os.path.join(os.path.dirname(__file__), "models")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")

# ─────────────────────────────────────────────────────
# SIMULATION DATA
# ─────────────────────────────────────────────────────
_NORMAL = {"duration":0.5,"src_pkts":12,"dst_pkts":8,"src_bytes":1200,
           "dst_bytes":900,"proto":"tcp","conn_state":"SF"}

_ATTACKS = [
    {"duration":0.001,"src_pkts":5000,"dst_pkts":10,"src_bytes":1_500_000,
     "dst_bytes":500,"proto":"udp","conn_state":"S0","_label":"DDoS"},
    {"duration":0.001,"src_pkts":2,"dst_pkts":0,"src_bytes":40,
     "dst_bytes":0,"proto":"tcp","conn_state":"REJ","_label":"Port Scan"},
    {"duration":1.2,"src_pkts":50,"dst_pkts":300,"src_bytes":2000,
     "dst_bytes":120_000,"proto":"tcp","conn_state":"SF",
     "num_failed_logins":8,"_label":"Botnet C2"},
    {"duration":0.02,"src_pkts":1,"dst_pkts":0,"src_bytes":60,
     "dst_bytes":0,"proto":"icmp","conn_state":"S0","_label":"ICMP Sweep"},
]

def _noise(d):
    out = d.copy()
    for k in ("src_bytes","dst_bytes","src_pkts","dst_pkts"):
        if k in out:
            out[k] = float(out[k]) * random.uniform(0.8, 1.25)
    return out

# ─────────────────────────────────────────────────────
# SIMULATION LOOP
# ─────────────────────────────────────────────────────
def _simulate():
    scaler   = None
    detector = None

    while True:
        if scaler is None or detector is None:
            try:
                scaler   = joblib.load(SCALER_PATH)
                from anomaly_detector import get_detector
                detector = get_detector()
            except Exception:
                scaler = detector = None

        is_attack = random.random() < 0.22
        tmpl      = random.choice(_ATTACKS) if is_attack else _NORMAL.copy()
        sim_label = tmpl.get("_label", "Attack") if is_attack else "Normal"
        raw       = _noise(tmpl)

        result = None
        if scaler and detector:
            try:
                vec    = extract_features(raw)
                vec_sc = scaler.transform(vec.reshape(1, -1))[0]
                result = detector.predict_single(vec_sc)
            except Exception:
                result = None

        if result is None:
            p = random.uniform(0.55, 0.99) if is_attack else random.uniform(0.01, 0.44)
            result = {
                "is_attack":   p >= 0.5,
                "confidence":  round(abs(p - 0.5) + 0.5, 4),
                "probability": round(p, 4),
                "xgb_prob":    round(p, 4),
                "ae_recon_err":round(random.uniform(0, 0.5), 6),
                "ae_threshold":0.12,
            }

        socketio.emit("network_event", {
            **result,
            "sim_label":    sim_label,
            "device_id":    f"ESP32-{random.randint(1, 3):02d}",
            "anomaly_score":round(
                random.uniform(3, 7.5) if is_attack
                else random.uniform(0.1, 1.8), 2),
            "packet_rate":  round(
                (raw.get("src_pkts", 1) + raw.get("dst_pkts", 0))
                / max(raw.get("duration", 0.5), 0.001), 1),
            "byte_rate":    round(
                (raw.get("src_bytes", 0) + raw.get("dst_bytes", 0))
                / max(raw.get("duration", 0.5), 0.001), 1),
        })

        time.sleep(0.6)

# ─────────────────────────────────────────────────────
# SOCKET EVENTS
# ─────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    emit("status", {"message": "Connected to IoT Anomaly Detection server"})

@socketio.on("predict_live")
def on_predict_live(data):
    try:
        scaler   = joblib.load(SCALER_PATH)
        detector = __import__("anomaly_detector").get_detector()
        vec_sc   = scaler.transform(extract_features(data).reshape(1, -1))[0]
        emit("prediction_result", detector.predict_single(vec_sc))
    except Exception as e:
        emit("prediction_error", {"error": str(e)})

# ─────────────────────────────────────────────────────
# ROOT
# ─────────────────────────────────────────────────────
@app.route("/")
def index():
    return {"service": "IoT Anomaly Detection API", "version": "1.0.0"}

# ─────────────────────────────────────────────────────
# APP FACTORY
# ─────────────────────────────────────────────────────
def create_app():
    threading.Thread(target=_simulate, daemon=True, name="Simulation").start()
    return app, socketio

# ─────────────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────────────
if __name__ == "__main__":
    threading.Thread(target=_simulate, daemon=True).start()

    # ✅ FIX: RUN ON PORT 5001 (matches frontend)
    port = int(os.getenv("PORT", 5001))

    print(f"\n🚀 Server → http://localhost:{port}")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)