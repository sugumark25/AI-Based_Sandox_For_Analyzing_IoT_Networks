"""
utils/feature_extraction.py
=============================
Extracts the 22 unified features from raw network flow metadata
sent by the ESP32 edge device or from the API payload.

Public functions:
    extract_features(raw)     — dict → numpy array of 22 features
    zscore_anomaly(values, v) — lightweight Z-score (mirrors ESP32)
    describe_flow(vec)        — named dict for logging / API response
"""

import numpy as np
from typing import Dict, Any, List


# ── 22 feature names in exact order ───────────────────────────────
FEATURE_NAMES: List[str] = [
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


def extract_features(raw: Dict[str, Any]) -> np.ndarray:
    """
    Convert a raw flow dict (from ESP32 JSON or API POST body)
    into the 22-feature numpy vector expected by the ML models.

    All keys are optional — missing values default to 0.

    Recognised keys:
        duration, src_bytes, dst_bytes, src_pkts, dst_pkts,
        proto         (str: "tcp" / "udp" / "icmp"),
        conn_state    (str: "SF" / "S0" / "REJ" / "FIN" / "CON" / "RST"),
        jitter, flow_weight, magnitude, variance,
        logged_in, num_failed_logins, srv_count,
        anomaly_score (ignored — used by collector only)

    Returns:
        np.ndarray shape (22,) dtype float32, NaN/Inf replaced with 0/1e6.
    """
    eps = 1e-9

    duration  = max(float(raw.get("duration",  0.001)), eps)
    src_bytes = float(raw.get("src_bytes", 0))
    dst_bytes = float(raw.get("dst_bytes", 0))
    src_pkts  = float(raw.get("src_pkts",  1))
    dst_pkts  = float(raw.get("dst_pkts",  0))

    total_pkts  = src_pkts + dst_pkts
    total_bytes = src_bytes + dst_bytes

    # Protocol
    proto      = str(raw.get("proto", "tcp")).lower().strip()
    proto_tcp  = 1.0 if proto == "tcp"  else 0.0
    proto_udp  = 1.0 if proto == "udp"  else 0.0
    proto_icmp = 1.0 if proto == "icmp" else 0.0

    # Connection state
    state    = str(raw.get("conn_state",
                           raw.get("state", "SF"))).upper().strip()
    conn_ok  = 1.0 if state in ("SF", "FIN", "CON") else 0.0
    conn_s0  = 1.0 if state in ("S0", "INT")        else 0.0
    conn_rej = 1.0 if state in ("REJ", "RST")       else 0.0

    # Statistical / derived features
    jitter       = float(raw.get("jitter",       raw.get("stddev", 0)))
    flow_weight  = float(raw.get("flow_weight",  raw.get("rate",   0)))
    magnitude    = float(raw.get("magnitude",    raw.get("max",    0)))
    variance     = float(raw.get("variance",     0))
    logged_in    = float(raw.get("logged_in",    0))
    failed_logins= float(raw.get("num_failed_logins", 0))
    srv_count    = float(raw.get("srv_count",    0))

    vec = np.array([
        duration,
        src_bytes,
        dst_bytes,
        src_pkts,
        dst_pkts,
        total_pkts  / duration,              # packet_rate
        total_bytes / duration,              # byte_rate
        total_bytes / (total_pkts + eps),    # bytes_per_pkt
        dst_bytes   / (src_bytes  + eps),    # payload_ratio
        proto_tcp,
        proto_udp,
        proto_icmp,
        conn_ok,
        conn_s0,
        conn_rej,
        jitter,
        flow_weight,
        magnitude,
        variance,
        logged_in,
        failed_logins,
        srv_count,
    ], dtype=np.float32)

    return np.nan_to_num(vec, nan=0.0, posinf=1e6, neginf=-1e6)


def zscore_anomaly(values: List[float], new_val: float) -> float:
    """
    Lightweight Z-score identical to the ESP32 edge logic.
    Returns Z-score of new_val against the rolling window.
    Values above 2.5 are considered suspicious.
    """
    if len(values) < 3:
        return 0.0
    arr  = np.array(values, dtype=np.float32)
    mean = float(arr.mean())
    std  = float(arr.std()) + 1e-9
    return float(abs(new_val - mean) / std)


def describe_flow(vec: np.ndarray) -> Dict[str, float]:
    """Return a named dict for logging or API responses."""
    return {
        FEATURE_NAMES[i]: round(float(vec[i]), 4)
        for i in range(min(len(vec), len(FEATURE_NAMES)))
    }
    