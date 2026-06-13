"""
backend/sandbox.py
-------------------
Lightweight sandbox ingestion and analysis for mirrored samples.
This module stores mirrored metadata, runs a deeper analysis (best-effort),
and returns a sandbox decision. If heavy models are available it will use
the trained `AnomalyDetector`; otherwise falls back to a simple heuristic.
"""
import os
import json
import sqlite3
import logging
import uuid
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

log = logging.getLogger("sandbox")

BASE_DIR = Path(__file__).parent
DB_DIR = BASE_DIR / "data"
# Use consolidated DB from block_manager to keep commands and mirrored samples together
try:
    from block_manager import DB_PATH as BM_DB_PATH
    DB_PATH = BM_DB_PATH
    from block_manager import _get_conn as _bm_get_conn
except Exception:
    DB_PATH = DB_DIR / "mirrored_samples.db"
    _bm_get_conn = None
MODEL_DIR = BASE_DIR / "models"
SCALER_PATH = MODEL_DIR / "scaler.pkl"


def _get_conn():
    DB_DIR.mkdir(exist_ok=True)
    if _bm_get_conn:
        return _bm_get_conn()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create mirrored_samples table if missing."""
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mirrored_samples (
                id TEXT PRIMARY KEY,
                device_id TEXT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                payload_hash TEXT,
                sample_bytes BLOB,
                edge_score REAL,
                sandbox_score REAL,
                sandbox_decision TEXT,
                raw_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def analyze_sample(sample: dict) -> Tuple[float, str]:
    """Run deeper analysis on the mirrored sample.
    Returns (sandbox_score, decision) where decision is 'CONFIRMED' or 'REJECTED'.
    Uses trained models if available, otherwise a fallback heuristic.
    """
    # Best-effort: try to use existing AnomalyDetector
    try:
        from anomaly_detector import get_detector
        import joblib
        import numpy as np

        detector = get_detector()
        scaler = None
        if os.path.exists(SCALER_PATH):
            scaler = joblib.load(SCALER_PATH)

        # If the mirrored sample contains a feature vector, use it
        vec = None
        if isinstance(sample.get("features"), list):
            vec = np.array(sample.get("features"), dtype=float)

        # Fallback: if packet_rate/byte_rate present, construct a minimal vector
        if vec is None:
            # Minimal safe vector length fallback to zeros (detector will likely error);
            # avoid calling detector.predict_single when not possible.
            vec = None

        if vec is not None and scaler is not None:
            vec_sc = scaler.transform(vec.reshape(1, -1))[0]
            res = detector.predict_single(vec_sc)
            sandbox_score = float(res.get("probability", res.get("confidence", 0.0)))
            decision = "CONFIRMED" if res.get("is_attack") else "REJECTED"
            return sandbox_score, decision
    except Exception as e:
        log.debug("Sandbox model unavailable or analysis failed: %s", e)

    # Heuristic fallback: use edge_score if provided
    edge_score = float(sample.get("edge_score") or sample.get("anomaly_score") or 0.0)
    # Normalize: treat > 0.8 as confirmed, > 0.5 as suspect
    if edge_score >= 0.8:
        return edge_score, "CONFIRMED"
    if edge_score >= 0.5:
        return edge_score * 0.9, "CONFIRMED"
    return edge_score, "REJECTED"


def ingest_sample(sample: dict) -> dict:
    """Persist sample, run analysis, update DB, and return record dict."""
    init_db()
    sample_id = f"ms_{uuid.uuid4().hex[:12]}"
    device_id = sample.get("device_id") or sample.get("device") or "unknown"
    timestamp = sample.get("timestamp") or datetime.utcnow().isoformat()
    src_ip = sample.get("src_ip")
    dst_ip = sample.get("dst_ip")
    src_port = sample.get("src_port")
    dst_port = sample.get("dst_port")
    proto = sample.get("proto")
    payload_hash = sample.get("payload_hash")
    sample_bytes = None
    if isinstance(sample.get("sample_bytes"), (str, bytes)):
        try:
            sample_bytes = sample.get("sample_bytes") if isinstance(sample.get("sample_bytes"), bytes) else sample.get("sample_bytes").encode("utf-8")
        except Exception:
            sample_bytes = None

    edge_score = None
    try:
        edge_score = float(sample.get("edge_score"))
    except Exception:
        edge_score = None

    sandbox_score, sandbox_decision = analyze_sample(sample)

    raw_json = json.dumps(sample)

    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO mirrored_samples
            (id, device_id, timestamp, src_ip, dst_ip, src_port, dst_port, proto,
             payload_hash, sample_bytes, edge_score, sandbox_score, sandbox_decision, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sample_id, device_id, timestamp, src_ip, dst_ip, src_port, dst_port, proto,
            payload_hash, sample_bytes, edge_score, sandbox_score, sandbox_decision, raw_json
        ))
        conn.commit()

    log.info("Mirrored sample ingested: %s device=%s decision=%s score=%.4f",
             sample_id, device_id, sandbox_decision, float(sandbox_score or 0.0))

    # If sandbox confirms, promote existing PENDING_SANDBOX command or create
    try:
        if sandbox_decision == "CONFIRMED":
            from block_manager import get_block_manager
            bm = get_block_manager()
            attacker = sample.get("src_ip") or sample.get("attacker_ip")
            if attacker:
                existing = bm.find_pending_sandbox(device_id, attacker)
                if existing:
                    bm.promote_command(existing)
                else:
                    bm.create_command(
                        device_id=device_id,
                        action="block_ip",
                        target=attacker,
                        reason="Sandbox confirmed threat",
                        attack_data=sample,
                        status="PENDING",
                    )
    except Exception as e:
        log.debug("Failed to promote/create block from sandbox: %s", e)

    return {
        "sample_id": sample_id,
        "device_id": device_id,
        "sandbox_decision": sandbox_decision,
        "sandbox_score": sandbox_score,
        "timestamp": timestamp,
    }


def list_recent(limit: int = 50):
    init_db()
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, device_id, timestamp, src_ip, dst_ip, sandbox_score, sandbox_decision, created_at FROM mirrored_samples ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return [dict(r) for r in rows]
