"""
backend/mqtt_subscriber.py
MQTT subscriber — listens for ESP32 network flow data published
over MQTT, runs ML inference, and emits results via Socket.IO
to the React dashboard.

Topics:
  iot/flows/<device_id>     → raw flow features JSON from ESP32
  iot/alerts/<device_id>    → publish detection result back to device

Usage:
    python mqtt_subscriber.py                    # default broker localhost
    python mqtt_subscriber.py --broker 192.168.1.1 --port 1883
    python mqtt_subscriber.py --broker mqtt.example.com --tls

MQTT Broker setup (local):
    sudo apt install mosquitto mosquitto-clients
    sudo systemctl start mosquitto
"""

import argparse
import json
import os
import time
import logging
import threading
import joblib
import numpy as np

import paho.mqtt.client as mqtt

from utils.feature_extraction import extract_features, describe_flow
from anomaly_detector import get_detector

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("mqtt_subscriber")

# ── Config ────────────────────────────────────────────────────────────────────
MODEL_DIR   = os.path.join(os.path.dirname(__file__), "models")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")

TOPIC_FLOWS  = "iot/flows/#"        # subscribe wildcard — all devices
TOPIC_ALERT  = "iot/alerts/{}"      # publish back to device
TOPIC_STATS  = "iot/server/stats"   # periodic stats publish
TOPIC_MIRROR = "iot/mirror/#"       # mirrored metadata from edge

# ── Runtime stats ─────────────────────────────────────────────────────────────
_stats = {
    "total": 0, "attacks": 0, "normal": 0,
    "total_latency_ms": 0.0, "start_time": time.time(),
}
_lock = threading.Lock()


def load_resources():
    """Load scaler and detector once at startup."""
    if not os.path.exists(SCALER_PATH):
        # Don't raise — allow the subscriber to run without models.
        log.warning("scaler.pkl not found. Running without ML models. Run train.py to generate models if available.")
        try:
            detector = get_detector()
        except Exception:
            detector = None
        return None, detector
    try:
        scaler = joblib.load(SCALER_PATH)
    except Exception as e:
        log.warning("Failed loading scaler.pkl: %s", e)
        scaler = None
    try:
        detector = get_detector()
    except Exception as e:
        log.warning("Failed loading detector: %s", e)
        detector = None

    if detector is not None:
        try:
            log.info("Models loaded. AE threshold=%.6f", detector.ae_threshold)
        except Exception:
            pass
    return scaler, detector


def process_flow(raw: dict, scaler, detector) -> dict:
    """Extract features → scale → predict. Returns result dict."""
    t0     = time.perf_counter()
    vec    = extract_features(raw)
    vec_sc = scaler.transform(vec.reshape(1, -1))[0]
    result = detector.predict_single(vec_sc)
    result["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    result["features"]   = describe_flow(vec)
    return result


def publish_result(client: mqtt.Client, device_id: str, result: dict, raw: dict):
    """Publish detection result back to the ESP32 device."""
    payload = json.dumps({
        "is_attack":    result["is_attack"],
        "confidence":   result["confidence"],
        "probability":  result["probability"],
        "latency_ms":   result["latency_ms"],
        "ae_recon_err": result["ae_recon_err"],
        "timestamp":    time.time(),
    })
    topic = TOPIC_ALERT.format(device_id)
    client.publish(topic, payload, qos=1)


def publish_stats(client: mqtt.Client):
    """Publish running stats to broker every 30 seconds."""
    def _loop():
        while True:
            time.sleep(30)
            with _lock:
                total = _stats["total"]
                payload = json.dumps({
                    "total":       total,
                    "attacks":     _stats["attacks"],
                    "normal":      _stats["normal"],
                    "attack_rate": round(_stats["attacks"] / max(total, 1) * 100, 2),
                    "avg_latency": round(_stats["total_latency_ms"] / max(total, 1), 2),
                    "uptime_s":    round(time.time() - _stats["start_time"], 0),
                })
            client.publish(TOPIC_STATS, payload, qos=0)
            log.info("Stats published → %s", TOPIC_STATS)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()


# ── MQTT Callbacks ────────────────────────────────────────────────────────────

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        log.info("Connected to MQTT broker")
        client.subscribe(TOPIC_FLOWS, qos=1)
        client.subscribe(TOPIC_MIRROR, qos=1)
        log.info("Subscribed → %s", TOPIC_FLOWS)
        log.info("Subscribed → %s", TOPIC_MIRROR)
    else:
        log.error("Connection failed: rc=%d", rc)


def on_disconnect(client, userdata, rc):
    log.warning("Disconnected from broker (rc=%d). Auto-reconnecting...", rc)


def on_message(client, userdata, msg):
    """Called on every incoming MQTT message."""
    scaler, detector = userdata

    # Extract device_id from topic: iot/flows/<device_id>
    parts     = msg.topic.split("/")
    device_id = parts[-1] if len(parts) >= 3 else "unknown"

    try:
        raw = json.loads(msg.payload.decode("utf-8"))
    except json.JSONDecodeError as e:
        log.warning("Bad JSON from %s: %s", device_id, e)
        return

    # If this is a mirrored sample, handle via sandbox ingestion
    if msg.topic.startswith("iot/mirror"):
        try:
            from sandbox import ingest_sample as ingest_mirror
            rec = ingest_mirror(raw)
            log.info("Sandbox ingested mirror from %s → %s", device_id, rec.get("sandbox_decision"))
            try:
                from server import socketio
                socketio.emit("mirrored_sample", {**rec})
            except Exception:
                pass
        except Exception as e:
            log.error("Failed to handle mirrored sample: %s", e)
        return

    try:
        result = process_flow(raw, scaler, detector)
    except Exception as e:
        log.error("Inference error for %s: %s", device_id, e)
        return

    label  = "ATTACK" if result["is_attack"] else "normal"
    conf   = result["confidence"]
    lat    = result["latency_ms"]
    z      = raw.get("anomaly_score", "N/A")

    log.info("[%s] %-8s conf=%.2f  z=%-5s  latency=%.1fms",
             device_id, label.upper(), conf, z, lat)

    # Publish result back to device
    publish_result(client, device_id, result, raw)

    # Update stats
    with _lock:
        _stats["total"] += 1
        _stats["total_latency_ms"] += lat
        if result["is_attack"]:
            _stats["attacks"] += 1
            log.warning("⚠️  ATTACK detected on %s — type inferred, conf=%.4f",
                        device_id, conf)
        else:
            _stats["normal"] += 1

    # Optional: forward to Socket.IO dashboard
    _forward_to_dashboard(device_id, result, raw)


def _forward_to_dashboard(device_id: str, result: dict, raw: dict):
    """
    If server.py Socket.IO instance is running in the same process,
    emit the event to connected dashboard clients.
    This is a no-op if running standalone.
    """
    try:
        from server import socketio
        socketio.emit("network_event", {
            **result,
            "device_id":    device_id,
            "sim_label":    "ATTACK" if result["is_attack"] else "Normal",
            "anomaly_score":raw.get("anomaly_score", 0),
            "packet_rate":  raw.get("packet_rate",
                (raw.get("src_pkts",0)+raw.get("dst_pkts",0)) /
                max(raw.get("duration",0.5), 0.001)),
            "byte_rate":    raw.get("byte_rate",
                (raw.get("src_bytes",0)+raw.get("dst_bytes",0)) /
                max(raw.get("duration",0.5), 0.001)),
        })
    except Exception:
        pass  # running standalone — skip dashboard forward


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="IoT MQTT Anomaly Subscriber")
    ap.add_argument("--broker",   default="localhost",  help="MQTT broker host")
    ap.add_argument("--port",     type=int, default=1883)
    ap.add_argument("--username", default=None)
    ap.add_argument("--password", default=None)
    ap.add_argument("--tls",      action="store_true",  help="Enable TLS")
    ap.add_argument("--keepalive",type=int, default=60)
    args = ap.parse_args()

    log.info("Loading ML models...")
    scaler, detector = load_resources()

    # ── Build MQTT client
    client = mqtt.Client(client_id="iot-anomaly-server", userdata=(scaler, detector))
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_message    = on_message

    if args.username:
        client.username_pw_set(args.username, args.password)
    if args.tls:
        client.tls_set()

    log.info("Connecting to broker %s:%d ...", args.broker, args.port)
    client.connect(args.broker, args.port, keepalive=args.keepalive)

    # Publish periodic stats
    publish_stats(client)

    log.info("Listening for flows on topic: %s", TOPIC_FLOWS)
    log.info("Publishing alerts to:         %s", TOPIC_ALERT.format("<device_id>"))
    log.info("Press Ctrl+C to stop.\n")

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        log.info("\nShutting down...")
        with _lock:
            t = _stats["total"]
            log.info("Final stats — total=%d  attacks=%d  normal=%d  rate=%.1f%%",
                     t, _stats["attacks"], _stats["normal"],
                     _stats["attacks"] / max(t, 1) * 100)
        client.disconnect()


if __name__ == "__main__":
    main()