# backend/data_collector.py
"""
data_collector.py
=================
Collects and stores NORMAL (baseline) network flow data into:
    dataset/data.csv

This CSV is used later for:
  - Training the StandardScaler (scaler.pkl)
  - Training the TinyML model (edge_model.tflite)
  - Establishing the rolling baseline mean/std for Z-score

HOW TO USE:
-----------
  python data_collector.py --duration 300   # collect 5 minutes of normal data
  python data_collector.py --count 1000     # collect exactly 1000 flow samples

CSV COLUMNS (22 features + metadata):
  timestamp, label, duration, src_bytes, dst_bytes,
  src_pkts, dst_pkts, packet_rate, byte_rate, bytes_per_pkt,
  payload_ratio, proto_tcp, proto_udp, proto_icmp,
  conn_ok, conn_s0, conn_rej, jitter, flow_weight,
  magnitude, variance, logged_in, num_failed_logins, srv_count
"""

import os
import csv
import time
import random
import argparse
import threading
from datetime import datetime

import paho.mqtt.client as mqtt

# ── Config ────────────────────────────────────────────────────────
DATASET_DIR   = os.path.join(os.path.dirname(__file__), "dataset")
DATA_CSV_PATH = os.path.join(DATASET_DIR, "data.csv")

MQTT_BROKER   = "localhost"
MQTT_PORT     = 1883
MQTT_TOPIC    = "iot/edge/normal/#"   # subscribe to all normal flow topics

# ── CSV Header ────────────────────────────────────────────────────
CSV_COLUMNS = [
    "timestamp",
    "label",            # always "normal" in this file
    "duration",
    "src_bytes",
    "dst_bytes",
    "src_pkts",
    "dst_pkts",
    "packet_rate",
    "byte_rate",
    "bytes_per_pkt",
    "payload_ratio",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "conn_ok",
    "conn_s0",
    "conn_rej",
    "jitter",
    "flow_weight",
    "magnitude",
    "variance",
    "logged_in",
    "num_failed_logins",
    "srv_count",
]

# ── Counters ──────────────────────────────────────────────────────
_records_written = 0
_lock = threading.Lock()


# ─────────────────────────────────────────────────────────────────
def _ensure_dataset_dir():
    """Create dataset/ directory if it doesn't exist."""
    os.makedirs(DATASET_DIR, exist_ok=True)


def _ensure_csv_header():
    """
    Create data.csv with header row if file doesn't exist yet.
    If file already exists, leave it untouched (append mode).
    """
    _ensure_dataset_dir()

    if not os.path.exists(DATA_CSV_PATH):
        with open(DATA_CSV_PATH, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writeheader()
        print(f"[DATA_COLLECTOR] Created: {DATA_CSV_PATH}")
    else:
        print(f"[DATA_COLLECTOR] Appending to existing: {DATA_CSV_PATH}")


def write_normal_record(features: dict):
    """
    Write a single normal flow record to data.csv.

    Parameters
    ----------
    features : dict
        Must contain all 22 feature keys.
        'label' and 'timestamp' are added automatically.
    """
    global _records_written

    row = {
        "timestamp":          datetime.utcnow().isoformat(),
        "label":              "normal",
        "duration":           features.get("duration",           0.0),
        "src_bytes":          features.get("src_bytes",          0),
        "dst_bytes":          features.get("dst_bytes",          0),
        "src_pkts":           features.get("src_pkts",           0),
        "dst_pkts":           features.get("dst_pkts",           0),
        "packet_rate":        features.get("packet_rate",        0.0),
        "byte_rate":          features.get("byte_rate",          0.0),
        "bytes_per_pkt":      features.get("bytes_per_pkt",      0.0),
        "payload_ratio":      features.get("payload_ratio",      0.0),
        "proto_tcp":          int(features.get("proto_tcp",      0)),
        "proto_udp":          int(features.get("proto_udp",      0)),
        "proto_icmp":         int(features.get("proto_icmp",     0)),
        "conn_ok":            int(features.get("conn_ok",        0)),
        "conn_s0":            int(features.get("conn_s0",        0)),
        "conn_rej":           int(features.get("conn_rej",       0)),
        "jitter":             features.get("jitter",             0.0),
        "flow_weight":        features.get("flow_weight",        0.0),
        "magnitude":          features.get("magnitude",          0.0),
        "variance":           features.get("variance",           0.0),
        "logged_in":          int(features.get("logged_in",      0)),
        "num_failed_logins":  int(features.get("num_failed_logins", 0)),
        "srv_count":          features.get("srv_count",          0),
    }

    with _lock:
        with open(DATA_CSV_PATH, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writerow(row)
        _records_written += 1

    print(
        f"[DATA_COLLECTOR] Record #{_records_written:>5} written | "
        f"pkt_rate={row['packet_rate']:.2f}  "
        f"src_bytes={row['src_bytes']}"
    )


# ─────────────────────────────────────────────────────────────────
# MQTT mode — receive normal flows from ESP32 over MQTT
# ─────────────────────────────────────────────────────────────────
def _on_mqtt_message(client, userdata, msg):
    """
    Called when MQTT message arrives on iot/edge/normal/#.
    Parses JSON payload and writes to data.csv.
    """
    import json

    try:
        payload = json.loads(msg.payload.decode("utf-8"))
        features_list = payload.get("features", [])

        if len(features_list) != 22:
            print(f"[DATA_COLLECTOR] WARN: expected 22 features, got {len(features_list)}")
            return

        # Map list index → feature name (must match scaler.h order)
        FEATURE_NAMES = [
            "duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts",
            "packet_rate", "byte_rate", "bytes_per_pkt", "payload_ratio",
            "proto_tcp", "proto_udp", "proto_icmp",
            "conn_ok", "conn_s0", "conn_rej",
            "jitter", "flow_weight", "magnitude", "variance",
            "logged_in", "num_failed_logins", "srv_count",
        ]

        features = dict(zip(FEATURE_NAMES, features_list))
        write_normal_record(features)

    except Exception as e:
        print(f"[DATA_COLLECTOR] Parse error: {e}")


def start_mqtt_collection():
    """Connect to MQTT broker and listen for normal flow data."""
    print(f"[DATA_COLLECTOR] Connecting to MQTT broker {MQTT_BROKER}:{MQTT_PORT}")

    client = mqtt.Client(client_id="data_collector")
    client.on_message = _on_mqtt_message

    client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
    client.subscribe(MQTT_TOPIC, qos=1)

    print(f"[DATA_COLLECTOR] Subscribed to: {MQTT_TOPIC}")
    print(f"[DATA_COLLECTOR] Writing normal data to: {DATA_CSV_PATH}")
    print("[DATA_COLLECTOR] Press Ctrl+C to stop\n")

    client.loop_forever()


# ─────────────────────────────────────────────────────────────────
# Simulation mode — generate synthetic normal data for testing
# ─────────────────────────────────────────────────────────────────
def generate_synthetic_normal(count: int = 500, interval_ms: int = 100):
    """
    Generate synthetic normal traffic records for testing.
    Saves to data.csv using write_normal_record().

    Parameters
    ----------
    count       : number of records to generate
    interval_ms : delay between records in milliseconds
    """
    print(f"[DATA_COLLECTOR] Generating {count} synthetic normal records...")

    for i in range(count):
        # Simulate realistic normal traffic ranges
        src_pkts    = random.randint(5, 50)
        dst_pkts    = random.randint(4, 45)
        src_bytes   = src_pkts * random.randint(64, 512)
        dst_bytes   = dst_pkts * random.randint(64, 512)
        duration    = round(random.uniform(0.01, 2.0), 4)
        packet_rate = round((src_pkts + dst_pkts) / max(duration, 0.001), 2)
        byte_rate   = round((src_bytes + dst_bytes) / max(duration, 0.001), 2)
        bytes_per_pkt = round((src_bytes + dst_bytes) / max(src_pkts + dst_pkts, 1), 2)

        # Random protocol (mostly TCP for normal)
        proto = random.choices(["tcp", "udp", "icmp"], weights=[0.75, 0.20, 0.05])[0]

        features = {
            "duration":          duration,
            "src_bytes":         src_bytes,
            "dst_bytes":         dst_bytes,
            "src_pkts":          src_pkts,
            "dst_pkts":          dst_pkts,
            "packet_rate":       packet_rate,
            "byte_rate":         byte_rate,
            "bytes_per_pkt":     bytes_per_pkt,
            "payload_ratio":     round(random.uniform(0.3, 0.9), 4),
            "proto_tcp":         1 if proto == "tcp"  else 0,
            "proto_udp":         1 if proto == "udp"  else 0,
            "proto_icmp":        1 if proto == "icmp" else 0,
            "conn_ok":           1,
            "conn_s0":           0,
            "conn_rej":          0,
            "jitter":            round(random.uniform(0.0, 0.01), 6),
            "flow_weight":       round(random.uniform(-80, -50), 2),
            "magnitude":         round(random.uniform(5000, 30000), 2),
            "variance":          round(random.uniform(500, 8000), 2),
            "logged_in":         random.randint(0, 1),
            "num_failed_logins": 0,
            "srv_count":         random.randint(1, 20),
        }

        write_normal_record(features)

        if interval_ms > 0:
            time.sleep(interval_ms / 1000.0)

    print(f"\n[DATA_COLLECTOR] Done. {count} records written to {DATA_CSV_PATH}")


# ─────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────
def get_record_count() -> int:
    """Return how many data records are currently in data.csv."""
    if not os.path.exists(DATA_CSV_PATH):
        return 0
    with open(DATA_CSV_PATH, "r") as f:
        return sum(1 for _ in f) - 1  # subtract header row


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normal data collector for ESP32 IDS")
    parser.add_argument("--mode",     choices=["mqtt", "simulate"], default="simulate",
                        help="Collection mode: 'mqtt' (from ESP32) or 'simulate' (synthetic)")
    parser.add_argument("--count",    type=int, default=500,
                        help="Number of records to generate (simulate mode only)")
    parser.add_argument("--interval", type=int, default=100,
                        help="Delay between records in ms (simulate mode only)")
    args = parser.parse_args()

    _ensure_csv_header()
    print(f"[DATA_COLLECTOR] Existing records in CSV: {get_record_count()}")

    if args.mode == "mqtt":
        start_mqtt_collection()
    else:
        generate_synthetic_normal(count=args.count, interval_ms=args.interval)
