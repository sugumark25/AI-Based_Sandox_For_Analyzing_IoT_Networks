"""
backend/routes.py
==================
All REST API endpoints registered as a Blueprint.
"""

import os
import time
import json
import logging
from datetime import datetime
from pathlib import Path

from flask import Blueprint, request, jsonify

# ✅ ADD THIS IMPORT
from flask_cors import CORS

import numpy as np

from realtime_collector import ingest_from_http, get_recent_records
from realtime_collector import get_stats as get_realtime_stats
from data_collector import write_normal_record
from block_manager import get_block_manager
from attack_analyzer import should_block
from utils.feature_extraction import extract_features

log      = logging.getLogger("routes")

api_bp   = Blueprint("api", __name__)

# ✅ ADD THIS LINE (THIS FIXES YOUR ISSUE)
CORS(api_bp)

BASE_DIR = Path(__file__).parent
MODEL_DIR = BASE_DIR / "models"

# ── Feature names ────────────────────────────────────
FEATURE_NAMES = [
    "duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts",
    "packet_rate", "byte_rate", "bytes_per_pkt", "payload_ratio",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_ok", "conn_s0", "conn_rej",
    "jitter", "flow_weight", "magnitude", "variance",
    "logged_in", "num_failed_logins", "srv_count",
]

# ── Session stats ────────────────────────────────────
_stats = {
    "total_requests":  0,
    "attack_count":    0,
    "normal_count":    0,
    "start_time":      datetime.now().isoformat(),
    "last_request":    None,
    "avg_latency_ms":  0.0,
    "latency_history": [],
}

# (ALL YOUR ORIGINAL CODE BELOW — UNCHANGED)

# ─────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────

def _get_detector():
    try:
        from anomaly_detector import get_detector
        import joblib
        scaler_path = MODEL_DIR / "scaler.pkl"
        if not scaler_path.exists():
            return None, None
        detector = get_detector()
        scaler   = joblib.load(str(scaler_path))
        return detector, scaler
    except Exception as e:
        log.warning("Detector not available: %s", e)
        return None, None


def _extract_and_scale(raw: dict):
    from utils.feature_extraction import extract_features
    detector, scaler = _get_detector()
    if detector is None:
        return None, None, None
    vec    = extract_features(raw)
    vec    = np.nan_to_num(vec, nan=0.0, posinf=1e6, neginf=-1e6)
    vec_sc = scaler.transform(vec.reshape(1, -1))[0]
    return vec_sc, detector, scaler


def _update_session_stats(is_attack: bool, latency_ms: float):
    _stats["total_requests"] += 1
    _stats["last_request"]    = datetime.now().isoformat()
    if is_attack:
        _stats["attack_count"] += 1
    else:
        _stats["normal_count"] += 1
    _stats["latency_history"].append(latency_ms)
    if len(_stats["latency_history"]) > 100:
        _stats["latency_history"].pop(0)
    _stats["avg_latency_ms"] = round(float(np.mean(_stats["latency_history"])), 2)


# ─────────────────────────────────────────────────────
# ALL ROUTES (UNCHANGED)
# ─────────────────────────────────────────────────────

@api_bp.route("/predict", methods=["POST"])
def predict():
    t0  = time.time()
    raw = request.get_json(force=True, silent=True) or {}

    if not raw:
        return jsonify({"error": "invalid JSON"}), 400

    ingest_from_http(raw)

    vec_sc, detector, _ = _extract_and_scale(raw)

    if detector is None:
        return jsonify({
            "error":      "Model not trained yet",
            "is_attack":  bool(raw.get("edge_decision", False)),
            "confidence": 0.0,
            "latency_ms": 0.0,
            "status":     "received",
            "device":     raw.get("device_id", "unknown"),
        }), 503

    result     = detector.predict_single(vec_sc)
    latency_ms = (time.time() - t0) * 1000

    _update_session_stats(bool(result["is_attack"]), latency_ms)

    # Extract features for analysis
    features = extract_features(raw) if isinstance(raw, dict) else np.array([])
    features_dict = {}
    if isinstance(features, np.ndarray) and len(features) >= 22:
        feature_names = [
            "duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts",
            "packet_rate", "byte_rate", "bytes_per_pkt", "payload_ratio",
            "proto_tcp", "proto_udp", "proto_icmp",
            "conn_ok", "conn_s0", "conn_rej",
            "jitter", "flow_weight", "magnitude", "variance",
            "logged_in", "num_failed_logins", "srv_count",
        ]
        features_dict = {name: float(features[i]) for i, name in enumerate(feature_names)}
    
    # Analyze attack and generate blocking command if needed
    block_decision = None
    block_cmd = None
    if result.get("is_attack"):
        block_decision = should_block(result, features_dict)
        
        if block_decision and block_decision.get("should_block"):
            # Create blocking command
            block_mgr = get_block_manager()
            device_id = raw.get("device_id", "esp32-unknown")
            # Do NOT send command directly to device — wait for sandbox confirmation.
            # Create the command in PENDING_SANDBOX state so it is not returned
            # by /api/commands/pending until sandbox confirms.
            block_cmd = block_mgr.create_command(
                device_id=device_id,
                action=block_decision["action"],
                target=block_decision["target"],
                reason=block_decision["attack_type"],
                attack_data=features_dict,
                status="PENDING_SANDBOX",
            )
            
            log.warning(
                f"🔒 BLOCKING: {block_decision['attack_type']} | "
                f"{block_decision['action']} {block_decision['target']}"
            )

    response_data = {
        "is_attack":    bool(result["is_attack"]),
        "confidence":   round(float(result["confidence"]),    4),
        "probability":  round(float(result["probability"]),   4),
        "xgb_prob":     round(float(result.get("xgb_prob",   0)), 4),
        "ae_recon_err": round(float(result.get("ae_recon_err", 0)), 6),
        "ae_threshold": round(float(result.get("ae_threshold", 0)), 6),
        "latency_ms":   round(latency_ms, 2),
        "device_id":    raw.get("device_id", "unknown"),
        "status":       "received",
        "timestamp":    datetime.now().isoformat(),
    }
    
    # Add blocking info if applicable
    if block_decision:
        response_data["block_decision"] = {
            "should_block": block_decision.get("should_block"),
            "attack_type": block_decision.get("attack_type"),
            "action": block_decision.get("action"),
            "target": block_decision.get("target"),
            "confidence": block_decision.get("confidence"),
        }
        if block_cmd:
            response_data["cmd_id"] = block_cmd.cmd_id
    
    return jsonify(response_data)


@api_bp.route("/stats", methods=["GET"])
def get_stats():
    uptime_s = (
        datetime.now() - datetime.fromisoformat(_stats["start_time"])
    ).total_seconds()
    return jsonify({
        **_stats,
        "uptime_seconds": round(uptime_s, 0),
        "attack_rate": round(
            _stats["attack_count"] / max(_stats["total_requests"], 1) * 100, 2
        ),
    })


@api_bp.route("/health", methods=["GET"])
def health():
    detector, _ = _get_detector()
    model_ok = detector is not None

    return jsonify({
        "status": "ok" if model_ok else "degraded",
        "model_ok": model_ok,
        "timestamp": datetime.now().isoformat(),
        "version": "5.0",
    })


# ─────────────────────────────────────────────────────
# MIRROR / SANDBOX ENDPOINTS
# ─────────────────────────────────────────────────────


@api_bp.route("/mirror", methods=["POST"])
def post_mirror():
    """Accept mirrored metadata from edge devices via HTTP POST.
    This endpoint is optional; edges may publish to MQTT instead.
    """
    payload = request.get_json(force=True, silent=True) or {}
    if not payload:
        return jsonify({"error": "invalid JSON"}), 400
    try:
        from sandbox import ingest_sample
        rec = ingest_sample(payload)
        return jsonify({"status": "ingested", **rec}), 201
    except Exception as e:
        log.error("Sandbox ingestion failed: %s", e)
        return jsonify({"error": "ingestion failed", "detail": str(e)}), 500


@api_bp.route("/mirror/history", methods=["GET"])
def mirror_history():
    limit = int(request.args.get("limit", 50))
    try:
        from sandbox import list_recent
        rows = list_recent(limit=limit)
        return jsonify({"count": len(rows), "samples": rows}), 200
    except Exception as e:
        log.error("Failed to fetch mirror history: %s", e)
        return jsonify({"error": "failed", "detail": str(e)}), 500


@api_bp.route("/mirror/latest", methods=["GET"])
def mirror_latest():
    try:
        from sandbox import list_recent
        rows = list_recent(limit=1)
        return jsonify(rows[0] if rows else {}), 200
    except Exception as e:
        log.error("Failed to fetch latest mirror: %s", e)
        return jsonify({"error": "failed", "detail": str(e)}), 500


# ─────────────────────────────────────────────────────
# BLOCKING COMMANDS API
# ─────────────────────────────────────────────────────

@api_bp.route("/commands/create", methods=["POST"])
def create_blocking_command():
    """
    Create a new blocking command from attack analysis.
    
    POST /api/commands/create
    {
        "device_id": "ESP32E-01",
        "action": "block_ip",
        "target": "192.168.1.100",
        "reason": "DDoS Attack",
        "attack_data": { ...flow features... }
    }
    """
    payload = request.get_json(force=True, silent=True) or {}
    
    device_id = payload.get("device_id", "unknown")
    action = payload.get("action", "block_ip")
    target = payload.get("target", "")
    reason = payload.get("reason", "Detected Attack")
    attack_data = payload.get("attack_data", {})
    
    if not target:
        return jsonify({"error": "target is required"}), 400
    
    block_mgr = get_block_manager()
    cmd = block_mgr.create_command(
        device_id=device_id,
        action=action,
        target=target,
        reason=reason,
        attack_data=attack_data
    )
    
    return jsonify({
        "cmd_id": cmd.cmd_id,
        "status": cmd.status,
        "action": cmd.action,
        "target": cmd.target,
        "reason": cmd.reason,
        "created_at": cmd.created_at,
    }), 201


@api_bp.route("/commands/pending/<device_id>", methods=["GET"])
def get_pending_commands(device_id):
    """
    Get all pending blocking commands for a device.
    
    GET /api/commands/pending/ESP32E-01
    
    Typically called by ESP32 to poll for commands.
    """
    block_mgr = get_block_manager()
    commands = block_mgr.get_pending_commands(device_id)
    
    # Mark commands as sent
    for cmd in commands:
        block_mgr.mark_sent(cmd.cmd_id)
    
    return jsonify({
        "device_id": device_id,
        "count": len(commands),
        "commands": [cmd.to_dict() for cmd in commands],
    }), 200


@api_bp.route("/commands/<cmd_id>/confirm", methods=["POST"])
def confirm_command(cmd_id):
    """
    Confirm that a blocking command has been executed by ESP32.
    
    POST /api/commands/{cmd_id}/confirm
    {
        "status": "executed",
        "duration_sec": 0.05,
        "result": "block_success"
    }
    """
    payload = request.get_json(force=True, silent=True) or {}
    status = payload.get("status", "executed")
    duration_sec = float(payload.get("duration_sec", 0))
    
    block_mgr = get_block_manager()
    
    if status == "executed":
        block_mgr.mark_executed(cmd_id, duration_sec)
    elif status == "failed":
        reason = payload.get("reason", "Unknown error")
        block_mgr.mark_failed(cmd_id, reason)
    
    return jsonify({
        "cmd_id": cmd_id,
        "status": status,
    }), 200


@api_bp.route("/commands/<cmd_id>/status", methods=["GET"])
def get_command_status(cmd_id):
    """
    Get status of a specific blocking command.
    
    GET /api/commands/{cmd_id}/status
    """
    block_mgr = get_block_manager()
    cmd = block_mgr.get_command(cmd_id)
    
    if not cmd:
        return jsonify({"error": "command not found"}), 404
    
    return jsonify(cmd.to_dict()), 200


@api_bp.route("/blocks/history", methods=["GET"])
def get_blocks_history():
    """
    Get historical blocking records.
    
    GET /api/blocks/history?device_id=ESP32E-01&limit=50
    """
    device_id = request.args.get("device_id", None)
    limit = int(request.args.get("limit", 100))
    
    block_mgr = get_block_manager()
    history = block_mgr.get_block_history(device_id=device_id, limit=limit)
    
    return jsonify({
        "count": len(history),
        "device_id": device_id,
        "history": history,
    }), 200


@api_bp.route("/blocks/summary", methods=["GET"])
def get_blocks_summary():
    """
    Get summary of blocking operations.
    
    GET /api/blocks/summary
    """
    block_mgr = get_block_manager()
    history = block_mgr.get_block_history(limit=1000)
    
    total_blocks = len(history)
    by_action = {}
    by_reason = {}
    
    for record in history:
        action = record.get("action", "unknown")
        reason = record.get("reason", "unknown")
        by_action[action] = by_action.get(action, 0) + 1
        by_reason[reason] = by_reason.get(reason, 0) + 1
    
    return jsonify({
        "total_blocks": total_blocks,
        "by_action": by_action,
        "by_reason": by_reason,
        "history_sample": history[:10] if history else [],
    }), 200

#     Defines the RESTful API endpoints (e.g., /health, /predict, /predict_batch,
# /stats) used by the frontend to fetch system status, trigger manual predictions,
# and retrieve model metrics