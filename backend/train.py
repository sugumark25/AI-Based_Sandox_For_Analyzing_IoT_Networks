"""
train.py  —  IoT Anomaly Detection — Training Script
Improvements applied:
  #1  Decision threshold searched on val set (already done in AnomalyDetector)
  #2  SMOTE enabled by default (--no-smote to disable)
  #4  Tuned XGBoost hyperparameters (inside AnomalyDetector)
  #5  Expanded feature engineering (inside AnomalyDetector)
  #7  Deeper autoencoder (inside AnomalyDetector)
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
from sklearn.metrics import classification_report, f1_score, accuracy_score

from utils.preprocessing import load_all_datasets, apply_smote, split, FEATURES
from anomaly_detector import AnomalyDetector

MODEL_DIR   = os.path.join(os.path.dirname(__file__), "models")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data_dir",   default=os.path.join(os.path.dirname(__file__), "dataset"))
    ap.add_argument("--epochs",     type=int, default=60)
    ap.add_argument("--batch_size", type=int, default=256)
    ap.add_argument("--max_rows",   type=int, default=100_000)
    ap.add_argument("--sample-frac", type=float, default=1.0,
                    help="Fraction of each CSV to sample before processing (0.0-1.0)")
    ap.add_argument("--stack", action="store_true",
                    help="Train a stacking meta-classifier (LogisticRegression) on XGB+AE outputs")
    ap.add_argument("--optimize-for", choices=["f1","accuracy"], default="f1",
                    help="Objective for decision-threshold search on validation")
    # IMPROVEMENT 2: SMOTE is now ON by default; pass --no-smote to disable
    ap.add_argument("--no-smote",   dest="smote", action="store_false",
                    help="Disable SMOTE oversampling (not recommended)")
    ap.set_defaults(smote=True)
    ap.add_argument("--cv",         action="store_true")
    args = ap.parse_args()

    print("\n" + "=" * 55)
    print("  IoT Anomaly Detection — Training  (v2)")
    print("  4 Datasets · 22 Features · XGBoost + Deep-AE")
    print("  Improvements: SMOTE · ThreshOpt · WeightOpt")
    print("                TunedXGB · DeepAE · ExpandedFeats")
    print("=" * 55)

    # ── Step 1: Load all 4 datasets ───────────────────────────────────────────
    X, y, scaler = load_all_datasets(args.data_dir, max_per=args.max_rows,
                                     sample_frac=args.sample_frac)

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(scaler, SCALER_PATH)
    print(f"[SAVE] Scaler saved → {SCALER_PATH}")
    print(f"[INFO] Final dataset shape : {X.shape}")
    print(f"[INFO] Attack rate         : {y.mean():.2%}\n")

    # ── Step 2: SMOTE (enabled by default) ───────────────────────────────────
    if args.smote:
        print("[SMOTE] Applying SMOTE to balance training classes...")
        # SMOTE is applied AFTER train/val/test split — do the split first
        X_tr, X_val, X_te, y_tr, y_val, y_te = split(X, y)
        print(f"[SPLIT] Before SMOTE — train={len(X_tr):,}  "
              f"val={len(X_val):,}  test={len(X_te):,}")
        X_tr, y_tr = apply_smote(X_tr, y_tr)
        print(f"[SPLIT] After  SMOTE — train={len(X_tr):,}  "
              f"attack_rate={y_tr.mean():.2%}\n")
    else:
        print("[SMOTE] Disabled.")
        X_tr, X_val, X_te, y_tr, y_val, y_te = split(X, y)
        print(f"[SPLIT] train={len(X_tr):,}  val={len(X_val):,}  test={len(X_te):,}\n")

    # ── Step 3: Optional Cross-Validation ────────────────────────────────────
    if args.cv:
        from sklearn.model_selection import StratifiedKFold
        from sklearn.metrics import f1_score, roc_auc_score

        print("[CV] Running 5-fold stratified cross-validation...")
        skf  = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        f1s, aucs = [], []

        for fold, (tr_idx, te_idx) in enumerate(skf.split(X, y)):
            print(f"\n  Fold {fold+1}/5")
            Xtr, Xte = X[tr_idx], X[te_idx]
            ytr, yte = y[tr_idx], y[te_idx]
            split_pt = int(len(Xtr) * 0.85)

            # Apply SMOTE per fold (only on training portion)
            if args.smote:
                Xtr_sm, ytr_sm = apply_smote(Xtr[:split_pt], ytr[:split_pt])
            else:
                Xtr_sm, ytr_sm = Xtr[:split_pt], ytr[:split_pt]

            det = AnomalyDetector()
            det.train(Xtr_sm, ytr_sm,
                      Xtr[split_pt:], ytr[split_pt:], epochs=20)
            m = det.evaluate(Xte, yte)
            f1s.append(m["f1_macro"])
            aucs.append(m["auc_roc"])
            print(f"  F1={m['f1_macro']:.4f}  AUC={m['auc_roc']:.4f}")

        print(f"\n[CV] F1  : {np.mean(f1s):.4f} ± {np.std(f1s):.4f}")
        print(f"[CV] AUC : {np.mean(aucs):.4f} ± {np.std(aucs):.4f}")
        json.dump(
            {"f1": [float(x) for x in f1s], "auc": [float(x) for x in aucs]},
            open(os.path.join(MODEL_DIR, "cv_scores.json"), "w"), indent=2
        )

    # ── Step 4: Train final model ─────────────────────────────────────────────
    print("[TRAIN] Training XGBoost + Deep-Autoencoder ensemble...")
    detector = AnomalyDetector()
    history  = detector.train(
        X_tr, y_tr, X_val, y_val,
        epochs=args.epochs,
        batch_size=args.batch_size,
    )

    # Optional stacking meta-classifier
    meta_model_path = os.path.join(MODEL_DIR, "meta_model.pkl")
    if args.stack:
        from sklearn.linear_model import LogisticRegression
        print("[STACK] Training stacking meta-classifier on val predictions...")
        # Prepare validation features: XGB prob + AE prob
        X_val_aug = detector._prep(X_val)
        if getattr(detector, "xgb_calib", None) is not None:
            try:
                xgb_val_p = detector.xgb_calib.predict_proba(X_val_aug)[:, 1]
            except Exception:
                xgb_val_p = detector.xgb_model.predict_proba(X_val_aug)[:, 1]
        else:
            xgb_val_p = detector.xgb_model.predict_proba(X_val_aug)[:, 1]
        X_recon_val = detector.ae_model.predict(X_val, verbose=0)
        recon_err_val = np.mean((X_val - X_recon_val) ** 2, axis=1)
        ae_score_val = (recon_err_val - detector.ae_threshold) / (detector.ae_threshold + 1e-9)
        ae_val_p = (1.0 / (1.0 + np.exp(-np.clip(ae_score_val, -500, 500))))

        meta_X_val = np.column_stack([xgb_val_p, ae_val_p])
        meta_y_val = y_val

        meta = LogisticRegression(solver="lbfgs")
        meta.fit(meta_X_val, meta_y_val)
        joblib.dump(meta, meta_model_path)
        print(f"[STACK] Meta-model saved → {meta_model_path}")

        # Find best threshold on validation (according to chosen objective)
        meta_val_p = meta.predict_proba(meta_X_val)[:, 1]
        best_t, best_score = 0.5, -1.0
        for t in np.arange(0.05, 0.96, 0.01):
            preds = (meta_val_p >= t).astype(int)
            if args.optimize_for == "f1":
                s = f1_score(meta_y_val, preds, average="macro", zero_division=0)
            else:
                s = accuracy_score(meta_y_val, preds)
            if s > best_score:
                best_score, best_t = s, float(t)
        print(f"[STACK] Best meta threshold on val = {best_t:.3f} ({args.optimize_for}={best_score:.4f})")
        meta_test_X = None

    # ── Step 5: Evaluate on test set ─────────────────────────────────────────
    print("\n[EVAL] Evaluating on held-out test set...")
    # Default: use detector ensemble
    metrics = detector.evaluate(X_te, y_te)
    proba   = detector._ensemble_proba(X_te)

    # Use the optimised threshold (not hardcoded 0.5)
    thresh  = detector.decision_threshold
    preds   = (proba >= thresh).astype(int)

    # If stacking was requested, evaluate the meta-model instead
    if args.stack:
        import joblib as _jl
        from sklearn.metrics import accuracy_score as _acc, f1_score as _f1, roc_auc_score as _auc, confusion_matrix as _cm, classification_report as _cr
        if os.path.exists(meta_model_path):
            meta = _jl.load(meta_model_path)
            # prepare test features
            X_te_aug = detector._prep(X_te)
            if getattr(detector, "xgb_calib", None) is not None:
                try:
                    xgb_te_p = detector.xgb_calib.predict_proba(X_te_aug)[:, 1]
                except Exception:
                    xgb_te_p = detector.xgb_model.predict_proba(X_te_aug)[:, 1]
            else:
                xgb_te_p = detector.xgb_model.predict_proba(X_te_aug)[:, 1]
            X_recon_te = detector.ae_model.predict(X_te, verbose=0)
            recon_err_te = np.mean((X_te - X_recon_te) ** 2, axis=1)
            ae_score_te = (recon_err_te - detector.ae_threshold) / (detector.ae_threshold + 1e-9)
            ae_te_p = (1.0 / (1.0 + np.exp(-np.clip(ae_score_te, -500, 500))))

            meta_X_test = np.column_stack([xgb_te_p, ae_te_p])
            meta_p_test = meta.predict_proba(meta_X_test)[:, 1]

            # choose threshold previously found on validation if present, else 0.5
            meta_thresh = best_t if 'best_t' in locals() else 0.5
            meta_preds = (meta_p_test >= meta_thresh).astype(int)

            metrics = {
                "accuracy":  round(_acc(y_te, meta_preds), 4),
                "f1_macro":  round(_f1(y_te, meta_preds, average='macro'), 4),
                "auc_roc":   round(_auc(y_te, meta_p_test), 4),
                "confusion": _cm(y_te, meta_preds).tolist(),
                "report":    _cr(y_te, meta_preds, target_names=["Normal","Attack"], output_dict=True),
            }
            proba = meta_p_test
            thresh = meta_thresh
        else:
            print("[STACK] Meta model not found — falling back to ensemble evaluation.")

    print(f"\n  Decision threshold used : {thresh:.3f}")
    print("\n" + classification_report(y_te, preds, target_names=["Normal", "Attack"]))
    print(f"  Accuracy : {metrics['accuracy']:.4f}")
    print(f"  F1 Macro : {metrics['f1_macro']:.4f}")
    print(f"  AUC-ROC  : {metrics['auc_roc']:.4f}")

    # ── Step 6: Save metrics ──────────────────────────────────────────────────
    metrics_out = {k: v for k, v in metrics.items() if k != "report"}
    metrics_out["decision_threshold"] = thresh
    metrics_out["xgb_weight"]         = detector.xgb_weight
    metrics_out["ae_weight"]          = detector.ae_weight
    json.dump(metrics_out,
              open(os.path.join(MODEL_DIR, "metrics.json"), "w"), indent=2)

    # ── Step 7: Save plots ────────────────────────────────────────────────────
    cm = np.array(metrics["confusion"])
    plt.figure(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=["Normal", "Attack"],
                yticklabels=["Normal", "Attack"])
    plt.title(f"Confusion Matrix — Ensemble  (thr={thresh:.3f})")
    plt.xlabel("Predicted"); plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig(os.path.join(MODEL_DIR, "confusion_matrix.png"), dpi=150)
    plt.close()

    print(f"\n✅  Training complete!")
    print(f"    Models saved to      : {MODEL_DIR}/")
    print(f"    Decision threshold   : {thresh:.3f}")
    print(f"    Ensemble weights     : XGB={detector.xgb_weight:.2f}  "
          f"AE={detector.ae_weight:.2f}")
    print(f"    Accuracy             : {metrics['accuracy']:.4f}")
    print(f"    F1 (macro)           : {metrics['f1_macro']:.4f}")
    print(f"    AUC-ROC              : {metrics['auc_roc']:.4f}")


if __name__ == "__main__":
    main()