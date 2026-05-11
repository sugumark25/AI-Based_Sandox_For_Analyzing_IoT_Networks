"""
backend/online_trainer.py
Retrains the model by combining:
  - Original 4 datasets (bot_iot, iot23_v1, iot23_v2, ton_iot)
  - Real-time ESP32 collected data (esp32_realtime.csv)

This makes the model learn your actual network environment patterns,
reducing false positives and improving detection accuracy over time.

Called automatically by data_collector.py when enough data is collected.
Can also be run manually:
    python online_trainer.py
    python online_trainer.py --realtime_only   # retrain on ESP32 data only
    python online_trainer.py --weight 0.4      # give 40% weight to real-time data
"""

import argparse
import os
import json
import numpy as np
import pandas as pd
import joblib
import logging
from datetime import datetime

from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score, roc_auc_score, accuracy_score

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("online_trainer")

# ── Paths ─────────────────────────────────────────────────────────────────────
MODEL_DIR     = os.path.join(os.path.dirname(__file__), "models")
DATASET_DIR   = os.path.join(os.path.dirname(__file__), "dataset")
SCALER_PATH   = os.path.join(MODEL_DIR, "scaler.pkl")
REALTIME_CSV  = os.path.join(DATASET_DIR, "esp32_realtime.csv")
HISTORY_FILE  = os.path.join(MODEL_DIR, "retrain_history.json")

from utils.preprocessing import (
    FEATURES, LABEL_COL,
    load_all_datasets, split
)


def load_realtime_data(min_samples: int = 100) -> tuple:
    """
    Load the real-time ESP32 collected data.
    Returns (X, y) or (None, None) if not enough data.
    """
    if not os.path.exists(REALTIME_CSV):
        log.warning("No real-time data found at %s", REALTIME_CSV)
        return None, None

    df = pd.read_csv(REALTIME_CSV)

    # Drop uncertain labels (-1) kept from collection
    df = df[df["label"].isin([0, 1])].copy()

    if len(df) < min_samples:
        log.warning("Only %d real-time samples — need at least %d to retrain",
                    len(df), min_samples)
        return None, None

    log.info("Real-time data: %d rows  attack=%.1f%%",
             len(df), df["label"].mean() * 100)

    X = df[FEATURES].values.astype(np.float32)
    y = df["label"].values.astype(int)
    X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

    return X, y


def combine_datasets(
    X_orig: np.ndarray, y_orig: np.ndarray,
    X_rt:   np.ndarray, y_rt:   np.ndarray,
    rt_weight: float = 0.3
) -> tuple:
    """
    Combine original 4-dataset training data with real-time data.

    rt_weight = fraction of final dataset from real-time data
    e.g. rt_weight=0.3 → 30% real-time, 70% original datasets

    Real-time data is oversampled/undersampled to match the weight.
    """
    n_total    = len(X_orig)
    n_realtime = int(n_total * rt_weight / (1 - rt_weight))
    n_realtime = min(n_realtime, len(X_rt))

    # Sample real-time data
    idx = np.random.RandomState(42).choice(len(X_rt), n_realtime, replace=False)
    X_rt_sampled = X_rt[idx]
    y_rt_sampled = y_rt[idx]

    X_combined = np.vstack([X_orig, X_rt_sampled])
    y_combined = np.concatenate([y_orig, y_rt_sampled])

    # Shuffle
    perm = np.random.RandomState(42).permutation(len(X_combined))
    X_combined = X_combined[perm]
    y_combined = y_combined[perm]

    log.info("Combined dataset: %d original + %d real-time = %d total",
             len(X_orig), n_realtime, len(X_combined))
    log.info("Attack rate: %.2f%%", y_combined.mean() * 100)

    return X_combined, y_combined


def save_retrain_history(metrics: dict, n_realtime: int):
    """Append retraining event to history log."""
    history = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE) as f:
            history = json.load(f)

    history.append({
        "timestamp":    datetime.utcnow().isoformat(),
        "n_realtime":   n_realtime,
        "accuracy":     metrics["accuracy"],
        "f1_macro":     metrics["f1_macro"],
        "auc_roc":      metrics["auc_roc"],
    })

    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

    log.info("Retrain history saved (%d entries)", len(history))


def retrain_with_realtime(
    rt_weight:      float = 0.3,
    realtime_only:  bool  = False,
    epochs:         int   = 40,
    batch_size:     int   = 256,
):
    """
    Main retraining function.
    Combines original datasets + real-time ESP32 data → retrains model.
    """
    from anomaly_detector import AnomalyDetector

    log.info("="*50)
    log.info("  Online Retraining Started")
    log.info("="*50)

    # ── Load real-time data ───────────────────────────────────────────────────
    X_rt, y_rt = load_realtime_data(min_samples=100)

    if X_rt is None:
        log.error("Not enough real-time data to retrain. Aborting.")
        return

    if realtime_only:
        # Train only on ESP32 data (fine-tuning mode)
        log.info("Fine-tuning mode: using real-time data only (%d samples)", len(X_rt))
        scaler = StandardScaler()
        X      = scaler.fit_transform(X_rt)
        y      = y_rt
    else:
        # ── Load original 4 datasets ──────────────────────────────────────────
        log.info("Loading original 4 datasets...")
        try:
            X_orig, y_orig, _ = load_all_datasets(DATASET_DIR, max_per=50_000)
        except FileNotFoundError as e:
            log.error("Original datasets not found: %s", e)
            log.info("Falling back to real-time only training...")
            scaler = StandardScaler()
            X = scaler.fit_transform(X_rt)
            y = y_rt
        else:
            # Combine: original + real-time
            X, y = combine_datasets(X_orig, y_orig, X_rt, y_rt, rt_weight=rt_weight)

            # Fit new scaler on combined data
            scaler = StandardScaler()
            X      = scaler.fit_transform(
                np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
            )

    # ── Split ─────────────────────────────────────────────────────────────────
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42)
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_tr, y_tr, test_size=0.125, stratify=y_tr, random_state=42)

    log.info("Split → train=%d  val=%d  test=%d", len(X_tr), len(X_val), len(X_te))

    # ── Retrain model ─────────────────────────────────────────────────────────
    log.info("Retraining XGBoost + Autoencoder...")
    detector = AnomalyDetector()
    detector.train(X_tr, y_tr, X_val, y_val,
                   epochs=epochs, batch_size=batch_size)

    # ── Evaluate ──────────────────────────────────────────────────────────────
    metrics = detector.evaluate(X_te, y_te)
    log.info("Retrain Results → Acc=%.4f  F1=%.4f  AUC=%.4f",
             metrics["accuracy"], metrics["f1_macro"], metrics["auc_roc"])

    # ── Save updated models ───────────────────────────────────────────────────
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(scaler, SCALER_PATH)
    detector.save()

    # ── Save history ──────────────────────────────────────────────────────────
    save_retrain_history(metrics, n_realtime=len(X_rt))

    # ── Reload model in running server ───────────────────────────────────────
    _reload_server_model()

    log.info("Online retraining complete!")
    return metrics


def _reload_server_model():
    """
    Signal the running Flask server to reload the model
    without restarting.
    """
    try:
        import anomaly_detector as ad
        ad._detector = None          # reset singleton
        ad.get_detector()            # force reload
        log.info("Server model reloaded successfully")
    except Exception as e:
        log.warning("Could not reload server model: %s", e)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rt_weight",     type=float, default=0.3,
                    help="Fraction of training data from real-time (0.0–1.0)")
    ap.add_argument("--realtime_only", action="store_true",
                    help="Train only on ESP32 real-time data")
    ap.add_argument("--epochs",        type=int,   default=40)
    ap.add_argument("--batch_size",    type=int,   default=256)
    ap.add_argument("--min_samples",   type=int,   default=100,
                    help="Minimum real-time samples required to retrain")
    args = ap.parse_args()

    retrain_with_realtime(
        rt_weight=args.rt_weight,
        realtime_only=args.realtime_only,
        epochs=args.epochs,
        batch_size=args.batch_size,
    )

    # Show history
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE) as f:
            history = json.load(f)
        print(f"\nRetrain history ({len(history)} runs):")
        print(f"  {'Time':<25} {'Samples':<10} {'Acc':<8} {'F1':<8} {'AUC'}")
        for h in history[-5:]:  # show last 5
            print(f"  {h['timestamp'][:19]:<25} {h['n_realtime']:<10} "
                  f"{h['accuracy']:<8} {h['f1_macro']:<8} {h['auc_roc']}")


if __name__ == "__main__":
    main()