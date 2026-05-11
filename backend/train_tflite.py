"""
train_tflite.py
===============
Trains a lightweight neural network on ESP32 flow data,
converts it to TFLite, and exports as a C header file
ready to flash to the ESP32.

Output files:
  models/edge_model.tflite     — TFLite model
  edge_device/src/model.h      — C array for ESP32
  edge_device/src/scaler.h     — Scaler constants for ESP32

Usage:
    python train_tflite.py
"""

import os
import sys
import numpy as np
import pandas as pd
from pathlib import Path

BASE_DIR     = Path(__file__).parent
DATASET_DIR  = BASE_DIR / "dataset"
MODEL_DIR    = BASE_DIR / "models"
EDGE_SRC_DIR = BASE_DIR.parent / "edge_device" / "src"

FEATURE_COLS = [
    "duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts",
    "packet_rate", "byte_rate", "bytes_per_pkt", "payload_ratio",
    "proto_tcp", "proto_udp", "proto_icmp",
    "conn_ok", "conn_s0", "conn_rej",
    "jitter", "flow_weight", "magnitude", "variance",
    "logged_in", "num_failed_logins", "srv_count",
]

# ═══════════════════════════════════════════════════════════════
# 1. Load data
# ═══════════════════════════════════════════════════════════════

def load_data():
    dfs = []

    # Normal flows from data.csv
    normal_path = DATASET_DIR / "data.csv"
    if normal_path.exists():
        df = pd.read_csv(str(normal_path))
        df = df[FEATURE_COLS + ["label"]] if "label" in df.columns else df[FEATURE_COLS].assign(label="normal")
        df["label"] = "normal"
        dfs.append(df)
        print(f"  Normal flows  : {len(df)} rows")
    else:
        print("  WARNING: data.csv not found")

    # Attack flows from realtime_esp32.csv
    attack_path = DATASET_DIR / "realtime_esp32.csv"
    if attack_path.exists():
        df = pd.read_csv(str(attack_path), on_bad_lines="skip")
        df = df[df["timestamp"] != "timestamp"]  # remove duplicate headers
        df = df[df["edge_decision"] == "attack"]
        df = df[FEATURE_COLS].copy()
        df["label"] = "attack"
        dfs.append(df)
        print(f"  Attack flows  : {len(df)} rows")
    else:
        print("  WARNING: realtime_esp32.csv not found")

    if not dfs:
        print("ERROR: No data found")
        sys.exit(1)

    combined = pd.concat(dfs, ignore_index=True).dropna()
    combined[FEATURE_COLS] = combined[FEATURE_COLS].apply(pd.to_numeric, errors="coerce").fillna(0)

    X = combined[FEATURE_COLS].values.astype(np.float32)
    y = (combined["label"] == "attack").astype(np.float32).values

    print(f"  Total rows    : {len(X)}")
    print(f"  Attack rate   : {y.mean():.1%}")
    return X, y


# ═══════════════════════════════════════════════════════════════
# 2. Scale
# ═══════════════════════════════════════════════════════════════

def scale_data(X):
    mean  = X.mean(axis=0)
    scale = X.std(axis=0) + 1e-9
    X_sc  = (X - mean) / scale
    X_sc  = np.clip(X_sc, -10, 10)
    return X_sc.astype(np.float32), mean, scale


# ═══════════════════════════════════════════════════════════════
# 3. Train TensorFlow model
# ═══════════════════════════════════════════════════════════════

def train_model(X, y):
    try:
        import tensorflow as tf
    except ImportError:
        print("ERROR: pip install tensorflow")
        sys.exit(1)

    # Balance classes
    n_attack = int(y.sum())
    n_normal = int((1 - y).sum())
    print(f"\n  Training: {n_normal} normal + {n_attack} attack")

    # Simple model — small enough for ESP32 (< 50KB)
    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(22,)),
        tf.keras.layers.Dense(32, activation="relu"),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(16, activation="relu"),
        tf.keras.layers.Dense(1,  activation="sigmoid"),
    ])

    model.compile(
        optimizer="adam",
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )

    # Class weights for imbalanced data
    weight_attack = n_normal / max(n_attack, 1)
    class_weight  = {0: 1.0, 1: weight_attack}

    model.fit(
        X, y,
        epochs=50,
        batch_size=32,
        validation_split=0.2,
        class_weight=class_weight,
        verbose=1,
    )

    # Evaluate
    loss, acc = model.evaluate(X, y, verbose=0)
    print(f"\n  Train accuracy: {acc:.4f}")

    return model


# ═══════════════════════════════════════════════════════════════
# 4. Convert to TFLite
# ═══════════════════════════════════════════════════════════════

def convert_to_tflite(model):
    import tensorflow as tf

    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    converter.target_spec.supported_types = [tf.float16]

    tflite_model = converter.convert()

    MODEL_DIR.mkdir(exist_ok=True)
    tflite_path = MODEL_DIR / "edge_model.tflite"
    tflite_path.write_bytes(tflite_model)

    size_kb = len(tflite_model) / 1024
    print(f"\n  TFLite model  : {tflite_path}")
    print(f"  Model size    : {size_kb:.1f} KB")

    if size_kb > 100:
        print("  WARNING: Model > 100KB — may be too large for ESP32")
    else:
        print("  ✅ Model size OK for ESP32")

    return tflite_model


# ═══════════════════════════════════════════════════════════════
# 5. Export C header files
# ═══════════════════════════════════════════════════════════════

def export_model_h(tflite_model):
    EDGE_SRC_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EDGE_SRC_DIR / "model.h"

    # Convert bytes to C array
    hex_data = ", ".join(f"0x{b:02x}" for b in tflite_model)
    size     = len(tflite_model)

    content = f"""#pragma once
/*
  model.h — TFLite model for ESP32 Edge Inference
  Auto-generated by train_tflite.py
  Model size: {size} bytes ({size/1024:.1f} KB)
  Features : 22
  Output   : sigmoid (0=normal, 1=attack)
*/

#ifndef MODEL_H
#define MODEL_H

const unsigned int g_model_len = {size};

alignas(8) const unsigned char g_model_data[] = {{
  {hex_data}
}};

#endif // MODEL_H
"""

    out_path.write_text(content)
    print(f"\n  model.h       : {out_path}")
    print(f"  Array size    : {size} bytes")


def export_scaler_h(mean, scale):
    EDGE_SRC_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EDGE_SRC_DIR / "scaler.h"

    mean_str  = ", ".join(f"{v:.6f}f" for v in mean)
    scale_str = ", ".join(f"{v:.6f}f" for v in scale)

    content = f"""#pragma once
/*
  scaler.h — StandardScaler constants for ESP32
  Auto-generated by train_tflite.py
*/

#ifndef SCALER_H
#define SCALER_H

#define SCALER_N_FEATURES 22

const float SCALER_MEAN[SCALER_N_FEATURES] = {{
  {mean_str}
}};

const float SCALER_SCALE[SCALER_N_FEATURES] = {{
  {scale_str}
}};

#endif // SCALER_H
"""

    out_path.write_text(content)
    print(f"  scaler.h      : {out_path}")


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  ESP32 TFLite Model Trainer")
    print("=" * 55)

    print("\n[1] Loading data...")
    X, y = load_data()

    print("\n[2] Scaling features...")
    X_sc, mean, scale = scale_data(X)

    print("\n[3] Training model...")
    model = train_model(X_sc, y)

    print("\n[4] Converting to TFLite...")
    tflite_model = convert_to_tflite(model)

    print("\n[5] Exporting C headers...")
    export_model_h(tflite_model)
    export_scaler_h(mean, scale)

    print("\n" + "=" * 55)
    print("  ✅ Done!")
    print("=" * 55)
    print("\nNext steps:")
    print("  1. Update tinyml_inference.h to use TFLite runtime")
    print("  2. Add TFLite library to platformio.ini")
    print("  3. Upload firmware: pio run --target upload")
    print("  4. ESP32 will run inference locally on device")