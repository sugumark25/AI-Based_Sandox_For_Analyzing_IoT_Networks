"""
evaluate.py  —  IoT Anomaly Detection — Evaluation Script
Improvements applied:
  #1  Uses model's optimised decision threshold by default (not hardcoded 0.5)
      Pass --threshold to override.

Usage:
    python evaluate.py                          # uses ./dataset/ + saved threshold
    python evaluate.py --data_dir ./dataset
    python evaluate.py --report                 # saves text report
    python evaluate.py --threshold 0.35         # force a custom threshold
"""

import argparse
import os
import json
import numpy as np
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    classification_report, confusion_matrix, roc_curve, auc,
    precision_recall_curve, accuracy_score, f1_score,
    roc_auc_score, average_precision_score
)

from utils.preprocessing import load_all_datasets, split, FEATURES
from anomaly_detector import AnomalyDetector

MODEL_DIR   = os.path.join(os.path.dirname(__file__), "models")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
EVAL_DIR    = os.path.join(MODEL_DIR, "eval")


def load_models():
    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError("scaler.pkl not found. Run train.py first.")
    scaler   = joblib.load(SCALER_PATH)
    detector = AnomalyDetector()
    detector.load()
    return scaler, detector


def plot_confusion_matrix(y_true, y_pred, out_path, threshold):
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()

    fig, axes = plt.subplots(1, 2, figsize=(12, 4))

    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=axes[0],
                xticklabels=["Normal", "Attack"], yticklabels=["Normal", "Attack"])
    axes[0].set_title(f"Confusion Matrix (counts)  thr={threshold:.3f}")
    axes[0].set_xlabel("Predicted"); axes[0].set_ylabel("Actual")

    cm_norm = cm.astype(float) / cm.sum(axis=1)[:, np.newaxis]
    sns.heatmap(cm_norm, annot=True, fmt=".2%", cmap="Blues", ax=axes[1],
                xticklabels=["Normal", "Attack"], yticklabels=["Normal", "Attack"])
    axes[1].set_title("Confusion Matrix (normalized)")
    axes[1].set_xlabel("Predicted"); axes[1].set_ylabel("Actual")

    plt.suptitle(f"TP={tp}  TN={tn}  FP={fp}  FN={fn}", fontsize=11)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[PLOT] Confusion matrix → {out_path}")


def plot_roc_curve(y_true, y_proba, out_path):
    fpr, tpr, thresholds = roc_curve(y_true, y_proba)
    roc_auc = auc(fpr, tpr)

    j_scores = tpr - fpr
    opt_idx  = np.argmax(j_scores)
    opt_thr  = thresholds[opt_idx]

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    axes[0].plot(fpr, tpr, color="#00d4ff", lw=2, label=f"AUC = {roc_auc:.4f}")
    axes[0].plot([0, 1], [0, 1], "k--", lw=1, label="Random")
    axes[0].scatter(fpr[opt_idx], tpr[opt_idx], color="#ff3d71", s=100, zorder=5,
                    label=f"Youden threshold = {opt_thr:.3f}")
    axes[0].set_xlabel("False Positive Rate"); axes[0].set_ylabel("True Positive Rate")
    axes[0].set_title("ROC Curve"); axes[0].legend(); axes[0].grid(alpha=0.3)

    precision, recall, _ = precision_recall_curve(y_true, y_proba)
    ap = average_precision_score(y_true, y_proba)
    axes[1].plot(recall, precision, color="#00e096", lw=2, label=f"AP = {ap:.4f}")
    axes[1].set_xlabel("Recall"); axes[1].set_ylabel("Precision")
    axes[1].set_title("Precision–Recall Curve"); axes[1].legend(); axes[1].grid(alpha=0.3)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[PLOT] ROC/PR curves → {out_path}")
    return roc_auc, opt_thr


def plot_score_distribution(y_true, y_proba, threshold, out_path):
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))

    normal_scores = y_proba[y_true == 0]
    attack_scores = y_proba[y_true == 1]

    axes[0].hist(normal_scores, bins=50, alpha=0.7, color="#00e096", label="Normal", density=True)
    axes[0].hist(attack_scores, bins=50, alpha=0.7, color="#ff3d71", label="Attack", density=True)
    axes[0].axvline(threshold, color="white", linestyle="--",
                    label=f"Threshold {threshold:.3f}")
    axes[0].set_xlabel("Ensemble Probability"); axes[0].set_ylabel("Density")
    axes[0].set_title("Score Distribution"); axes[0].legend(); axes[0].grid(alpha=0.3)

    axes[1].scatter(normal_scores[:500],
                    np.random.normal(0, 0.05, min(500, len(normal_scores))),
                    alpha=0.3, s=5, color="#00e096", label="Normal")
    axes[1].scatter(attack_scores[:500],
                    np.random.normal(1, 0.05, min(500, len(attack_scores))),
                    alpha=0.3, s=5, color="#ff3d71", label="Attack")
    axes[1].set_xlabel("Ensemble Score"); axes[1].set_ylabel("True Class (jittered)")
    axes[1].set_title("Score vs True Class"); axes[1].legend(); axes[1].grid(alpha=0.3)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[PLOT] Score distribution → {out_path}")


def plot_feature_importance(detector, out_path):
    if detector.xgb_model is None:
        return
    importance = detector.xgb_model.feature_importances_

    # Feature names: original 22 + 29 engineered = 51 total
    original_names = list(FEATURES)
    extra_names = [
        # Group A
        "total_bytes", "total_pkts", "byte_asym", "pkt_asym",
        "log_src_bytes", "log_dst_bytes", "log_duration",
        "log_magnitude", "conn_anomaly", "rate_x_asym",
        # Group B
        "tcp_ratio", "udp_ratio", "icmp_ratio", "icmp_x_bytes",
        # Group C
        "abs_byte_asym", "abs_pkt_asym",
        "src_dst_byte_ratio", "src_dst_pkt_ratio",
        "src_bpp", "dst_bpp", "bpp_diff",
        # Group D
        "conn_ok_ratio", "conn_fail_ratio", "login_fail_rate", "flow_mag_ratio",
        # Group E
        "log_packet_rate", "log_byte_rate", "log_variance", "log_srv_count",
    ]
    all_names = original_names + extra_names

    # Pad / trim to match actual feature count
    n = len(importance)
    if len(all_names) < n:
        all_names += [f"feat_{i}" for i in range(len(all_names), n)]
    all_names = all_names[:n]

    indices = np.argsort(importance)[-20:]   # top 20 (was 15)

    fig, ax = plt.subplots(figsize=(9, 7))
    colors = ["#00d4ff" if importance[i] > np.median(importance) else "#4a6a8a"
              for i in indices]
    ax.barh([all_names[i] for i in indices], importance[indices], color=colors)
    ax.set_xlabel("Feature Importance (gain)")
    ax.set_title("XGBoost — Top 20 Feature Importances (with engineered features)")
    ax.grid(axis="x", alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[PLOT] Feature importance → {out_path}")


def threshold_sweep(y_true, y_proba):
    thresholds = np.arange(0.10, 0.95, 0.05)   # wider sweep (was 0.1–0.95)
    results    = []
    for thr in thresholds:
        preds = (y_proba >= thr).astype(int)
        results.append({
            "threshold": round(float(thr), 2),
            "accuracy":  round(accuracy_score(y_true, preds), 4),
            "f1_macro":  round(f1_score(y_true, preds, average="macro"), 4),
            "f1_attack": round(f1_score(y_true, preds, pos_label=1), 4),
            "precision": round(float(np.sum((preds == 1) & (y_true == 1)) /
                                     (np.sum(preds == 1) + 1e-9)), 4),
            "recall":    round(float(np.sum((preds == 1) & (y_true == 1)) /
                                     (np.sum(y_true == 1) + 1e-9)), 4),
            "fpr":       round(float(np.sum((preds == 1) & (y_true == 0)) /
                                     (np.sum(y_true == 0) + 1e-9)), 4),
        })
    return results


def save_text_report(metrics, sweep, out_path):
    with open(out_path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  IoT Anomaly Detection — Evaluation Report  (v2)\n")
        f.write("=" * 60 + "\n\n")

        f.write("── FINAL TEST METRICS ──\n")
        for k, v in metrics.items():
            if k not in ("report", "confusion"):
                f.write(f"  {k:<25} {v}\n")

        f.write("\n── CLASSIFICATION REPORT ──\n")
        report = metrics.get("report", {})
        for cls in ["Normal", "Attack", "macro avg", "weighted avg"]:
            if cls in report:
                r = report[cls]
                f.write(f"  {cls:<15} P={r['precision']:.4f}  "
                        f"R={r['recall']:.4f}  F1={r['f1-score']:.4f}\n")

        f.write("\n── CONFUSION MATRIX ──\n")
        cm = np.array(metrics["confusion"])
        tn, fp, fn, tp_ = cm.ravel()
        f.write(f"  TP={tp_}  TN={tn}  FP={fp}  FN={fn}\n")

        f.write("\n── THRESHOLD SWEEP ──\n")
        f.write(f"  {'Thr':<6} {'Acc':<8} {'F1':<8} {'Prec':<8} "
                f"{'Recall':<8} {'FPR':<8}\n")
        for r in sweep:
            f.write(f"  {r['threshold']:<6} {r['accuracy']:<8} {r['f1_macro']:<8} "
                    f"{r['precision']:<8} {r['recall']:<8} {r['fpr']:<8}\n")

    print(f"[REPORT] Saved → {out_path}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data_dir",  default=os.path.join(os.path.dirname(__file__), "dataset"))
    ap.add_argument("--max_rows",  type=int,   default=100_000)
    # IMPROVEMENT 1: default None → use the threshold saved during training
    ap.add_argument("--threshold", type=float, default=None,
                    help="Decision threshold (default: use value from training)")
    ap.add_argument("--report",    action="store_true", help="Save text evaluation report")
    args = ap.parse_args()

    os.makedirs(EVAL_DIR, exist_ok=True)

    print("=" * 55)
    print("  IoT Anomaly Detection — Evaluation  (v2)")
    print("=" * 55)

    # ── Load models
    print("\n[LOAD] Loading trained models...")
    scaler, detector = load_models()

    # Resolve threshold
    threshold = args.threshold if args.threshold is not None else detector.decision_threshold
    print(f"[INFO] Decision threshold : {threshold:.3f}  "
          f"({'user-supplied' if args.threshold is not None else 'from training'})")

    # ── Load and prepare test data
    print("[LOAD] Loading datasets...")
    X, y, _ = load_all_datasets(args.data_dir, max_per=args.max_rows)

    from sklearn.model_selection import train_test_split
    _, X_te, _, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    print(f"[INFO] Test set: {len(X_te)} samples | attack_rate={y_te.mean():.2%}")

    # ── Get predictions
    print("\n[EVAL] Running inference on test set...")
    y_proba = detector._ensemble_proba(X_te)
    y_pred  = (y_proba >= threshold).astype(int)

    # ── Core metrics
    metrics = {
        "threshold":      threshold,
        "test_size":      len(y_te),
        "accuracy":       round(accuracy_score(y_te, y_pred), 4),
        "f1_macro":       round(f1_score(y_te, y_pred, average="macro"), 4),
        "f1_attack":      round(f1_score(y_te, y_pred, pos_label=1), 4),
        "f1_normal":      round(f1_score(y_te, y_pred, pos_label=0), 4),
        "auc_roc":        round(roc_auc_score(y_te, y_proba), 4),
        "avg_precision":  round(average_precision_score(y_te, y_proba), 4),
        "xgb_weight":     detector.xgb_weight,
        "ae_weight":      detector.ae_weight,
        "confusion":      confusion_matrix(y_te, y_pred).tolist(),
        "report":         classification_report(y_te, y_pred,
                              target_names=["Normal", "Attack"], output_dict=True),
    }

    print(f"\n{'─' * 45}")
    print(f"  Threshold    : {threshold:.3f}")
    print(f"  Accuracy     : {metrics['accuracy']:.4f}")
    print(f"  F1 (macro)   : {metrics['f1_macro']:.4f}")
    print(f"  F1 (attack)  : {metrics['f1_attack']:.4f}")
    print(f"  AUC-ROC      : {metrics['auc_roc']:.4f}")
    print(f"  Avg Precision: {metrics['avg_precision']:.4f}")
    print(f"  XGB weight   : {detector.xgb_weight:.2f}")
    print(f"  AE  weight   : {detector.ae_weight:.2f}")
    print(f"{'─' * 45}")
    print("\n" + classification_report(y_te, y_pred, target_names=["Normal", "Attack"]))

    # ── Threshold sweep
    print("[EVAL] Running threshold sweep...")
    sweep = threshold_sweep(y_te, y_proba)

    # ── Plots
    print("\n[PLOT] Generating evaluation plots...")
    plot_confusion_matrix(y_te, y_pred,
        os.path.join(EVAL_DIR, "confusion_matrix.png"), threshold)
    roc_auc_val, opt_thr = plot_roc_curve(y_te, y_proba,
        os.path.join(EVAL_DIR, "roc_pr_curves.png"))
    plot_score_distribution(y_te, y_proba, threshold,
        os.path.join(EVAL_DIR, "score_distribution.png"))
    plot_feature_importance(detector,
        os.path.join(EVAL_DIR, "feature_importance.png"))

    print(f"\n[INFO] Optimal threshold (Youden's J) = {opt_thr:.4f}")
    if abs(opt_thr - threshold) > 0.05:
        print(f"[TIP]  Youden threshold ({opt_thr:.3f}) differs from current "
              f"({threshold:.3f}) by >{abs(opt_thr - threshold):.2f}.  "
              f"Consider: python evaluate.py --threshold {opt_thr:.2f}")

    # ── Save JSON results
    eval_results = {**metrics, "threshold_sweep": sweep}
    eval_results.pop("report", None)
    out_json = os.path.join(EVAL_DIR, "eval_results.json")
    with open(out_json, "w") as f:
        json.dump(eval_results, f, indent=2)
    print(f"[SAVE] Results → {out_json}")

    if args.report:
        save_text_report(metrics, sweep, os.path.join(EVAL_DIR, "eval_report.txt"))

    print(f"\n✅  Evaluation complete. All outputs in {EVAL_DIR}/")


if __name__ == "__main__":
    main()
#     A standalone script to deeply evaluate the trained models. Generates detailed
# metrics, confusion matrices, ROC/PR curves, and analyzes the best thresholds.