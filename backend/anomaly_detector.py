import os
import numpy as np
import joblib
import xgboost as xgb
from sklearn.metrics import (
    classification_report, roc_auc_score, f1_score,
    confusion_matrix, accuracy_score, precision_recall_curve
)
from sklearn.calibration import CalibratedClassifierCV

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, regularizers

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
XGB_PATH  = os.path.join(MODEL_DIR, "xgboost_model.pkl")
AE_PATH   = os.path.join(MODEL_DIR, "autoencoder_model.keras")
META_PATH = os.path.join(MODEL_DIR, "model_meta.pkl")
XGB_CALIB_PATH = os.path.join(MODEL_DIR, "xgboost_model.calib.pkl")

# ── IMPROVEMENT 7: Deeper, more expressive autoencoder ────────────────────────
def build_autoencoder(input_dim, encoding_dim=16):
    """
    Deeper AE: 512→256→128→64→encoding_dim bottleneck.
    encoding_dim=16 (was 14) — slightly wider for better normal-traffic modelling.
    Dropout tuned to 0.12 (was 0.15).
    """
    reg = regularizers.l2(1e-5)
    inp = keras.Input(shape=(input_dim,))

    # Encoder
    x = layers.Dense(512, activation="relu", kernel_regularizer=reg)(inp)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.12)(x)
    x = layers.Dense(256, activation="relu", kernel_regularizer=reg)(x)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.12)(x)
    x = layers.Dense(128, activation="relu", kernel_regularizer=reg)(x)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.12)(x)
    x = layers.Dense(64, activation="relu", kernel_regularizer=reg)(x)
    x = layers.BatchNormalization()(x)
    encoded = layers.Dense(encoding_dim, activation="relu")(x)

    # Decoder
    x = layers.Dense(64, activation="relu", kernel_regularizer=reg)(encoded)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.12)(x)
    x = layers.Dense(128, activation="relu", kernel_regularizer=reg)(x)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.12)(x)
    x = layers.Dense(256, activation="relu", kernel_regularizer=reg)(x)
    x = layers.BatchNormalization()(x)
    x = layers.Dropout(0.12)(x)
    x = layers.Dense(512, activation="relu", kernel_regularizer=reg)(x)
    decoded = layers.Dense(input_dim, activation="linear")(x)

    model = keras.Model(inp, decoded)
    model.compile(
        optimizer=keras.optimizers.Adam(3e-4),
        loss="huber"
    )
    return model


def _safe_sigmoid(x, scale=1.0):
    x = np.clip(x * scale, -500, 500)
    return 1.0 / (1.0 + np.exp(-x))


def _add_interaction_features(X):
    """
    Expanded feature engineering (IMPROVEMENT 5).

    Original 22 columns:
      0:duration, 1:src_bytes, 2:dst_bytes, 3:src_pkts, 4:dst_pkts,
      5:packet_rate, 6:byte_rate, 7:bytes_per_pkt, 8:payload_ratio,
      9:proto_tcp, 10:proto_udp, 11:proto_icmp,
      12:conn_ok, 13:conn_s0, 14:conn_rej,
      15:jitter, 16:flow_weight, 17:magnitude, 18:variance,
      19:logged_in, 20:num_failed_logins, 21:srv_count

    Added groups:
      A. Original 10 interaction features (kept from v1)
      B. Protocol ratio features  — TCP/UDP/ICMP distribution shifts
      C. Bi-directional metrics   — byte symmetry, packet direction bias
      D. Connection-quality ratios — failure rates, service diversity
      E. Log-transformed rates    — log packet_rate, log byte_rate
    """
    eps = 1e-9

    # ── Group A: original interactions ────────────────────────────────────────
    total_bytes   = X[:, 1] + X[:, 2]
    total_pkts    = X[:, 3] + X[:, 4]
    byte_asym     = (X[:, 1] - X[:, 2]) / (total_bytes + eps)
    pkt_asym      = (X[:, 3] - X[:, 4]) / (total_pkts + eps)
    log_src_bytes = np.log1p(X[:, 1])
    log_dst_bytes = np.log1p(X[:, 2])
    log_duration  = np.log1p(X[:, 0])
    log_magnitude = np.log1p(X[:, 17])
    conn_anomaly  = X[:, 13] + X[:, 14]          # s0 + rej = bad connections
    rate_x_asym   = X[:, 6] * np.abs(byte_asym)  # byte_rate × asymmetry

    # ── Group B: protocol ratio features ─────────────────────────────────────
    proto_sum    = X[:, 9] + X[:, 10] + X[:, 11] + eps
    tcp_ratio    = X[:, 9]  / proto_sum
    udp_ratio    = X[:, 10] / proto_sum
    icmp_ratio   = X[:, 11] / proto_sum
    # ICMP dominance is a common DDoS/scan indicator
    icmp_x_bytes = X[:, 11] * total_bytes

    # ── Group C: bi-directional metrics ──────────────────────────────────────
    # Absolute asymmetry (direction-agnostic)
    abs_byte_asym = np.abs(byte_asym)
    abs_pkt_asym  = np.abs(pkt_asym)
    # src-to-dst byte ratio (high = potential exfiltration)
    src_dst_byte_ratio = X[:, 1] / (X[:, 2] + eps)
    src_dst_pkt_ratio  = X[:, 3] / (X[:, 4] + eps)
    # Bytes per packet per direction
    src_bpp = X[:, 1] / (X[:, 3] + eps)
    dst_bpp = X[:, 2] / (X[:, 4] + eps)
    bpp_diff = np.abs(src_bpp - dst_bpp)

    # ── Group D: connection-quality ratios ────────────────────────────────────
    conn_total      = X[:, 12] + X[:, 13] + X[:, 14] + eps
    conn_ok_ratio   = X[:, 12] / conn_total   # fraction of OK connections
    conn_fail_ratio = (X[:, 13] + X[:, 14]) / conn_total  # fraction of bad
    # Failed logins relative to srv_count
    login_fail_rate = X[:, 20] / (X[:, 21] + eps)
    # Flow weight normalised by magnitude
    flow_mag_ratio  = X[:, 16] / (X[:, 17] + eps)

    # ── Group E: log-transformed rates ───────────────────────────────────────
    log_packet_rate = np.log1p(X[:, 5])
    log_byte_rate   = np.log1p(X[:, 6])
    log_variance    = np.log1p(X[:, 18])
    log_srv_count   = np.log1p(X[:, 21])

    extra = np.column_stack([
        # A
        total_bytes, total_pkts, byte_asym, pkt_asym,
        log_src_bytes, log_dst_bytes, log_duration,
        log_magnitude, conn_anomaly, rate_x_asym,
        # B
        tcp_ratio, udp_ratio, icmp_ratio, icmp_x_bytes,
        # C
        abs_byte_asym, abs_pkt_asym,
        src_dst_byte_ratio, src_dst_pkt_ratio,
        src_bpp, dst_bpp, bpp_diff,
        # D
        conn_ok_ratio, conn_fail_ratio, login_fail_rate, flow_mag_ratio,
        # E
        log_packet_rate, log_byte_rate, log_variance, log_srv_count,
    ])
    return np.hstack([X, extra])


def _optimize_weights(xgb_proba, ae_p, y_val):
    """
    IMPROVEMENT 3: Grid-search ensemble weights on validation set.
    Returns (xgb_weight, ae_weight) that maximise macro-F1.
    """
    best_f1, best_w = 0.0, (0.80, 0.20)
    for w in np.arange(0.5, 1.01, 0.05):
        ens = w * xgb_proba + (1 - w) * ae_p
        preds = (ens >= 0.5).astype(int)
        f = f1_score(y_val, preds, average="macro", zero_division=0)
        if f > best_f1:
            best_f1, best_w = f, (float(w), float(1 - w))
    print(f"  [WeightOpt] best xgb_w={best_w[0]:.2f}  ae_w={best_w[1]:.2f}  "
          f"F1={best_f1:.4f}")
    return best_w


class AnomalyDetector:
    def __init__(self, xgb_weight=0.80, ae_weight=0.20):
        self.xgb_weight         = xgb_weight
        self.ae_weight          = ae_weight
        self.xgb_model          = None
        self.ae_model           = None
        self.ae_threshold       = 0.5
        self.decision_threshold = 0.5
        self.trained            = False

    def _prep(self, X):
        return _add_interaction_features(X)

    def train(self, X_train, y_train, X_val, y_val, epochs=100, batch_size=512):
        os.makedirs(MODEL_DIR, exist_ok=True)
        pos = int(y_train.sum())
        neg = len(y_train) - pos
        spw = neg / (pos + 1e-9)

        X_tr_aug = self._prep(X_train)
        X_va_aug = self._prep(X_val)

        # ── IMPROVEMENT 4: Tuned XGBoost hyperparameters ─────────────────────
        print("\n[XGBoost] Training with expanded interaction features...")
        print(f"  Feature dim: {X_tr_aug.shape[1]}  "
              f"pos={pos:,}  neg={neg:,}  spw={spw:.2f}")

        self.xgb_model = xgb.XGBClassifier(
            n_estimators      = 2000,   # was 1500 — more trees for complex patterns
            max_depth         = 9,      # was 8 — slightly deeper
            learning_rate     = 0.015,  # was 0.02 — slower, more precise
            subsample         = 0.85,
            colsample_bytree  = 0.75,   # was 0.80 — more regularisation
            colsample_bylevel = 0.75,   # was 0.80
            colsample_bynode  = 0.80,   # NEW — per-node column sampling
            min_child_weight  = 5,      # was 3 — avoid tiny leaf nodes
            gamma             = 0.15,   # was 0.1
            reg_alpha         = 0.1,    # was 0.05 — stronger L1
            reg_lambda        = 1.5,    # was 1.2 — stronger L2
            scale_pos_weight  = spw,
            eval_metric       = ["auc", "logloss"],
            tree_method       = "hist",
            random_state      = 42,
            n_jobs            = -1,
            early_stopping_rounds = 75,  # was 50 — more patience
        )
        self.xgb_model.fit(
            X_tr_aug, y_train,
            eval_set=[(X_va_aug, y_val)],
            verbose=100,
        )
        joblib.dump(self.xgb_model, XGB_PATH)

        # Calibrate XGBoost probabilities on validation set (can improve fusion)
        try:
            # Use small cv to fit calibrator; 'prefit' not available in this sklearn version
            self.xgb_calib = CalibratedClassifierCV(self.xgb_model, method="sigmoid", cv=3)
            self.xgb_calib.fit(X_va_aug, y_val)
            joblib.dump(self.xgb_calib, XGB_CALIB_PATH)
            xgb_proba = self.xgb_calib.predict_proba(X_va_aug)[:, 1]
            print("[CALIB] XGBoost probability calibration applied (sigmoid)")
        except Exception as e:
            self.xgb_calib = None
            xgb_proba = self.xgb_model.predict_proba(X_va_aug)[:, 1]
            print(f"[CALIB] Calibration skipped: {e}")
        xgb_preds = (xgb_proba >= 0.5).astype(int)
        print(f"\n  XGBoost Val — "
              f"Acc={accuracy_score(y_val, xgb_preds):.4f}  "
              f"F1={f1_score(y_val, xgb_preds, average='macro'):.4f}  "
              f"AUC={roc_auc_score(y_val, xgb_proba):.4f}")

        # ── IMPROVEMENT 7: Deeper autoencoder ────────────────────────────────
        print("\n[Autoencoder] Training deeper AE on normal traffic...")
        X_normal = X_train[y_train == 0]
        print(f"  Normal samples for AE training: {len(X_normal):,}")

        self.ae_model = build_autoencoder(X_train.shape[1], encoding_dim=16)
        callbacks = [
            keras.callbacks.EarlyStopping(
                monitor="val_loss", patience=15,       # was 12
                restore_best_weights=True),
            keras.callbacks.ReduceLROnPlateau(
                monitor="val_loss", factor=0.5,
                patience=7, min_lr=1e-6),              # patience was 6
            keras.callbacks.ModelCheckpoint(
                AE_PATH, save_best_only=True, monitor="val_loss"),
        ]
        self.ae_model.fit(
            X_normal, X_normal,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.15,
            callbacks=callbacks,
            verbose=0,  
        )

        # Threshold = 97th percentile of normal reconstruction error
        recon_normal = self.ae_model.predict(X_normal, verbose=0)
        err_normal   = np.mean((X_normal - recon_normal) ** 2, axis=1)
        self.ae_threshold = float(np.percentile(err_normal, 97))
        print(f"  AE threshold (97th pct)={self.ae_threshold:.6f}")

        # ── IMPROVEMENT 3: Optimise ensemble weights on val ───────────────────
        X_recon_val = self.ae_model.predict(X_val, verbose=0)
        recon_err   = np.mean((X_val - X_recon_val) ** 2, axis=1)
        ae_score    = (recon_err - self.ae_threshold) / (self.ae_threshold + 1e-9)
        ae_p        = _safe_sigmoid(ae_score)

        print("\n[WeightOpt] Searching best ensemble weights...")
        self.xgb_weight, self.ae_weight = _optimize_weights(xgb_proba, ae_p, y_val)

        ens_proba = self._ensemble_proba_raw(X_va_aug, xgb_proba, recon_err)

        # ── IMPROVEMENT 1: Find best decision threshold on val ────────────────
        best_thresh, best_f1 = 0.5, 0.0
        for t in np.arange(0.15, 0.80, 0.005):   # wider search (was 0.20–0.80)
            preds = (ens_proba >= t).astype(int)
            f = f1_score(y_val, preds, average="macro", zero_division=0)
            if f > best_f1:
                best_f1, best_thresh = f, float(t)

        self.decision_threshold = best_thresh
        preds_best = (ens_proba >= best_thresh).astype(int)

        print(f"\n[Ensemble] threshold={best_thresh:.3f}  "
              f"Acc={accuracy_score(y_val, preds_best):.4f}  "
              f"F1={f1_score(y_val, preds_best, average='macro'):.4f}  "
              f"AUC={roc_auc_score(y_val, ens_proba):.4f}")
        print(classification_report(
            y_val, preds_best,
            target_names=["Normal", "Attack"], zero_division=0))

        joblib.dump({
            "ae_threshold":        self.ae_threshold,
            "decision_threshold":  self.decision_threshold,
            "xgb_weight":          self.xgb_weight,
            "ae_weight":           self.ae_weight,
        }, META_PATH)
        self.trained = True

        return {
            "val_f1":  [best_f1],
            "val_auc": [roc_auc_score(y_val, ens_proba)],
        }

    # Combine XGBoost and Autoencoder using weighted ensemble
    def _ensemble_proba_raw(self, X_aug, xgb_proba, recon_err):
        ae_score = (recon_err - self.ae_threshold) / (self.ae_threshold + 1e-9)
        ae_p     = _safe_sigmoid(ae_score)
        return self.xgb_weight * xgb_proba + self.ae_weight * ae_p

    def _ensemble_proba(self, X, recon_err=None):
        X_aug  = self._prep(X)
        # Use calibrated probabilities if available
        if getattr(self, "xgb_calib", None) is not None:
            try:
                xgb_p = self.xgb_calib.predict_proba(X_aug)[:, 1]
            except Exception:
                xgb_p = self.xgb_model.predict_proba(X_aug)[:, 1]
        else:
            xgb_p = self.xgb_model.predict_proba(X_aug)[:, 1]
        if recon_err is None:
            X_recon   = self.ae_model.predict(X, verbose=0)
            recon_err = np.mean((X - X_recon) ** 2, axis=1)
        ae_score = (recon_err - self.ae_threshold) / (self.ae_threshold + 1e-9)
        ae_p     = _safe_sigmoid(ae_score)
        return self.xgb_weight * xgb_p + self.ae_weight * ae_p

    def predict_single(self, x):
        if not self.trained:
            raise RuntimeError("Model not loaded. Run train.py first.")
        X        = x.reshape(1, -1)
        X_aug    = self._prep(X)
        xgb_p    = float(self.xgb_model.predict_proba(X_aug)[0, 1])
        X_recon  = self.ae_model.predict(X, verbose=0)
        recon_e  = float(np.mean((X - X_recon) ** 2))
        ae_score = (recon_e - self.ae_threshold) / (self.ae_threshold + 1e-9)
        ae_p     = float(_safe_sigmoid(np.array([ae_score]))[0])
        ens_p    = self.xgb_weight * xgb_p + self.ae_weight * ae_p
        thresh   = self.decision_threshold
        return {
            "is_attack":    bool(ens_p >= thresh),
            "confidence":   round(float(ens_p if ens_p >= thresh else 1 - ens_p), 4),
            "probability":  round(float(ens_p), 4),
            "xgb_prob":     round(xgb_p, 4),
            "ae_recon_err": round(recon_e, 6),
            "ae_threshold": round(self.ae_threshold, 6),
        }

    def evaluate(self, X_test, y_test):
        proba  = self._ensemble_proba(X_test)
        thresh = self.decision_threshold
        preds  = (proba >= thresh).astype(int)
        return {
            "accuracy":  round(accuracy_score(y_test, preds), 4),
            "f1_macro":  round(f1_score(y_test, preds, average="macro"), 4),
            "auc_roc":   round(roc_auc_score(y_test, proba), 4),
            "confusion": confusion_matrix(y_test, preds).tolist(),
            "report":    classification_report(
                             y_test, preds,
                             target_names=["Normal", "Attack"],
                             output_dict=True),
        }

    def save(self):
        joblib.dump(self.xgb_model, XGB_PATH)
        # Save calibrator if present
        if getattr(self, "xgb_calib", None) is not None:
            try:
                joblib.dump(self.xgb_calib, XGB_CALIB_PATH)
            except Exception:
                pass
        self.ae_model.save(AE_PATH)
        joblib.dump({
            "ae_threshold":       self.ae_threshold,
            "decision_threshold": self.decision_threshold,
            "xgb_weight":         self.xgb_weight,
            "ae_weight":          self.ae_weight,
        }, META_PATH)

    def load(self):
        if not os.path.exists(XGB_PATH):
            raise FileNotFoundError("XGBoost model not found. Run train.py first.")
        ae_path = AE_PATH
        if not os.path.exists(ae_path):
            ae_path = ae_path.replace(".keras", ".h5")
        if not os.path.exists(ae_path):
            raise FileNotFoundError("Autoencoder not found. Run train.py first.")
        self.xgb_model          = joblib.load(XGB_PATH)
        self.ae_model           = keras.models.load_model(ae_path)
        # Load calibrator if available
        if os.path.exists(XGB_CALIB_PATH):
            try:
                self.xgb_calib = joblib.load(XGB_CALIB_PATH)
            except Exception:
                self.xgb_calib = None
        else:
            self.xgb_calib = None
        meta                    = joblib.load(META_PATH)
        self.ae_threshold       = meta["ae_threshold"]
        self.decision_threshold = meta.get("decision_threshold", 0.5)
        self.xgb_weight         = meta["xgb_weight"]
        self.ae_weight          = meta["ae_weight"]
        self.trained            = True
        print(f"[LOAD] Models loaded.  "
              f"AE threshold={self.ae_threshold:.6f}  "
              f"Decision threshold={self.decision_threshold:.3f}")


_detector = None

def get_detector():
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
        _detector.load()
    return _detector


# Build a deep autoencoder model
# Train the XGBoost classifier
# Train the autoencoder using normal traffic
# Add extra interaction features to improve detection
# Calibrate XGBoost prediction probabilities
# Convert autoencoder reconstruction error into anomaly probability
# Search the best ensemble weights
# Search the best decision threshold
# Predict whether a single network flow is normal or attack
# Evaluate the model using accuracy, F1-score, AUC-ROC, and confusion matrix
# Save trained models and metadata
# Load saved models for backend/API prediction