import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
import joblib

# ── 22 Unified features ───────────────────────────────────────────────────────
FEATURES = [
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

LABEL_COL = "label"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe(df, *cols, default=0.0):
    for col in cols:
        if col in df.columns:
            return pd.to_numeric(df[col], errors="coerce").fillna(default)
    return pd.Series(default, index=df.index)


def _derive(df):
    eps = 1e-9
    dur = df["duration"].clip(lower=eps)
    tp  = df["src_pkts"]  + df["dst_pkts"]
    tb  = df["src_bytes"] + df["dst_bytes"]
    df["packet_rate"]   = tp  / dur
    df["byte_rate"]     = tb  / dur
    df["bytes_per_pkt"] = tb  / (tp + eps)
    df["payload_ratio"] = df["dst_bytes"] / (df["src_bytes"] + eps)
    return df


def _finalize(df):
    for col in FEATURES:
        if col not in df.columns:
            df[col] = 0.0
    return df[FEATURES + [LABEL_COL]]


# ── Dataset 1: BotNeTIoT-L01 ─────────────────────────────────────────────────
# Labels: 0=normal, 1=attack (integers)
# Columns: src_ip, src_port, dst_ip, dst_port, proto, service,
#          duration, src_bytes, dst_bytes, conn_state, src_pkts,
#          src_ip_bytes, dst_pkts, dst_ip_bytes, label, type

def load_botniot(path, max_rows=100_000, sample_frac: float = None):
    df = pd.read_csv(path, low_memory=False)
    if sample_frac is not None and 0.0 < sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=42)
    df.columns = df.columns.str.strip()
    print(f"  [BotNeTIoT] Total rows: {len(df):,}")
    print(f"  [BotNeTIoT] Label distribution: {df['label'].value_counts().to_dict()}")

    out = pd.DataFrame(index=df.index)
    out["duration"]  = _safe(df, "duration")
    out["src_bytes"] = _safe(df, "src_bytes")
    out["dst_bytes"] = _safe(df, "dst_bytes")
    out["src_pkts"]  = _safe(df, "src_pkts")
    out["dst_pkts"]  = _safe(df, "dst_pkts")

    proto = _safe(df, "proto").astype(str).str.lower()
    out["proto_tcp"]  = (proto == "tcp").astype(float)
    out["proto_udp"]  = (proto == "udp").astype(float)
    out["proto_icmp"] = (proto == "icmp").astype(float)

    state = _safe(df, "conn_state").astype(str).str.upper()
    out["conn_ok"]  = (state == "SF").astype(float)
    out["conn_s0"]  = (state == "S0").astype(float)
    out["conn_rej"] = (state == "REJ").astype(float)

    out["jitter"]            = 0.0
    out["flow_weight"]       = 0.0
    out["magnitude"]         = _safe(df, "src_ip_bytes")
    out["variance"]          = 0.0
    out["logged_in"]         = 0.0
    out["num_failed_logins"] = 0.0
    out["srv_count"]         = 0.0

    out[LABEL_COL] = pd.to_numeric(
        df["label"], errors="coerce").fillna(0).astype(int)

    out = _derive(_finalize(out))

    # Balance before returning
    benign  = out[out[LABEL_COL] == 0]
    attacks = out[out[LABEL_COL] == 1]
    n = min(len(benign), len(attacks), max_rows // 2)
    out = pd.concat([
        benign.sample(n=n,  random_state=42),
        attacks.sample(n=n, random_state=42),
    ], ignore_index=True)

    print(f"  [BotNeTIoT]  rows={len(out):,}  "
          f"attack={out[LABEL_COL].sum():,}  "
          f"normal={(out[LABEL_COL]==0).sum():,}")
    return out


# ── Dataset 2: IoT-23 v1 (Zeek conn log — has label + type columns) ───────────
# Labels: 0=normal, 1=attack (integers)
# Columns: src_ip, src_port, ..., label, type

def load_iot23_v1(path, max_rows=100_000, sample_frac: float = None):
    df = pd.read_csv(path, low_memory=False)
    if sample_frac is not None and 0.0 < sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=42)
    df.columns = df.columns.str.strip()
    print(f"  [IoT-23 v1] Total rows: {len(df):,}")
    print(f"  [IoT-23 v1] Label distribution: {df['label'].value_counts().to_dict()}")

    out = pd.DataFrame(index=df.index)
    out["duration"]  = _safe(df, "duration")
    out["src_bytes"] = _safe(df, "src_bytes")
    out["dst_bytes"] = _safe(df, "dst_bytes")
    out["src_pkts"]  = _safe(df, "src_pkts")
    out["dst_pkts"]  = _safe(df, "dst_pkts")

    proto = _safe(df, "proto").astype(str).str.lower()
    out["proto_tcp"]  = (proto == "tcp").astype(float)
    out["proto_udp"]  = (proto == "udp").astype(float)
    out["proto_icmp"] = (proto == "icmp").astype(float)

    state = _safe(df, "conn_state").astype(str).str.upper()
    out["conn_ok"]  = (state == "SF").astype(float)
    out["conn_s0"]  = (state == "S0").astype(float)
    out["conn_rej"] = (state == "REJ").astype(float)

    out["jitter"]            = 0.0
    out["flow_weight"]       = 0.0
    out["magnitude"]         = _safe(df, "src_ip_bytes")
    out["variance"]          = 0.0
    out["logged_in"]         = 0.0
    out["num_failed_logins"] = 0.0
    out["srv_count"]         = 0.0

    out[LABEL_COL] = pd.to_numeric(
        df["label"], errors="coerce").fillna(0).astype(int)

    out = _derive(_finalize(out))

    benign  = out[out[LABEL_COL] == 0]
    attacks = out[out[LABEL_COL] == 1]
    n = min(len(benign), len(attacks), max_rows // 2)
    out = pd.concat([
        benign.sample(n=n,  random_state=42),
        attacks.sample(n=n, random_state=42),
    ], ignore_index=True)

    print(f"  [IoT-23 v1]  rows={len(out):,}  "
          f"attack={out[LABEL_COL].sum():,}  "
          f"normal={(out[LABEL_COL]==0).sum():,}")
    return out


# ── Dataset 3: IoT-23 v2 (tab-separated Zeek conn logs) ──────────────────────
# May be tab-separated; columns include: label, detailed-label

def load_iot23_v2(path, max_rows=100_000, sample_frac: float = None):
    # Try multiple separators
    for sep in ["\t", ",", r"\s+"]:
        try:
            df = pd.read_csv(path, sep=sep, low_memory=False,
                             engine="python" if sep == r"\s+" else "c")
            df.columns = df.columns.str.strip()
            if len(df.columns) >= 5:
                break
        except Exception:
            continue

    print(f"  [IoT-23 v2] Total rows: {len(df):,}")
    print(f"  [IoT-23 v2] Columns: {list(df.columns)}")

    out = pd.DataFrame(index=df.index)
    out["duration"]  = _safe(df, "duration")
    out["src_bytes"] = _safe(df, "orig_bytes",  "src_bytes")
    out["dst_bytes"] = _safe(df, "resp_bytes",  "dst_bytes")
    out["src_pkts"]  = _safe(df, "orig_pkts",   "src_pkts")
    out["dst_pkts"]  = _safe(df, "resp_pkts",   "dst_pkts")

    proto = _safe(df, "proto").astype(str).str.lower()
    out["proto_tcp"]  = (proto == "tcp").astype(float)
    out["proto_udp"]  = (proto == "udp").astype(float)
    out["proto_icmp"] = (proto == "icmp").astype(float)

    state = _safe(df, "conn_state").astype(str).str.upper()
    out["conn_ok"]  = (state == "SF").astype(float)
    out["conn_s0"]  = (state == "S0").astype(float)
    out["conn_rej"] = (state == "REJ").astype(float)

    out["jitter"]            = 0.0
    out["flow_weight"]       = 0.0
    out["magnitude"]         = _safe(df, "orig_ip_bytes")
    out["variance"]          = 0.0
    out["logged_in"]         = 0.0
    out["num_failed_logins"] = 0.0
    out["srv_count"]         = 0.0

    # Find label column
    if "label" in df.columns:
        lbl = df["label"].astype(str).str.strip().str.lower()
        print(f"  [DEBUG] Unique labels: {lbl.unique()[:10]}")
        # Try integer first
        as_int = pd.to_numeric(df["label"], errors="coerce")
        if as_int.notna().mean() > 0.9:
            out[LABEL_COL] = as_int.fillna(0).astype(int)
        else:
            out[LABEL_COL] = (~lbl.str.contains(
                r"benign|normal|^-$", regex=True, na=False)).astype(int)
    elif "detailed-label" in df.columns:
        lbl = df["detailed-label"].astype(str).str.strip().str.lower()
        print(f"  [DEBUG] Unique detailed-labels: {lbl.unique()[:10]}")
        out[LABEL_COL] = (~lbl.str.contains(
            r"benign|normal|^-$", regex=True, na=False)).astype(int)
    else:
        print(f"  [WARN] No label column found")
        out[LABEL_COL] = 1

    out = _derive(_finalize(out))
    if sample_frac is not None and 0.0 < sample_frac < 1.0:
        out = out.sample(frac=sample_frac, random_state=42)

    benign  = out[out[LABEL_COL] == 0]
    attacks = out[out[LABEL_COL] == 1]
    print(f"  [DEBUG] benign={len(benign):,}  attack={len(attacks):,}")
    n = min(len(benign), len(attacks), max_rows // 2)
    out = pd.concat([
        benign.sample(n=n,  random_state=42),
        attacks.sample(n=n, random_state=42),
    ], ignore_index=True)

    print(f"  [IoT-23 v2]  rows={len(out):,}  "
          f"attack={out[LABEL_COL].sum():,}  "
          f"normal={(out[LABEL_COL]==0).sum():,}")
    return out


# ── Dataset 4: TON-IoT Network ────────────────────────────────────────────────
# Only 30 normal rows out of 1M — use all 30 normal + 30 attacks sample
# Uses FIN/CON state as additional normal proxy if needed

def load_toniot(path, max_rows=100_000, sample_frac: float = None):
    df = pd.read_csv(path, low_memory=False)
    if sample_frac is not None and 0.0 < sample_frac < 1.0:
        df = df.sample(frac=sample_frac, random_state=42)
    df.columns = df.columns.str.strip()
    print(f"  [TON-IoT] Full file rows: {len(df):,}")

    out = pd.DataFrame(index=df.index)
    out["duration"]  = _safe(df, "dur",    "duration")
    out["src_bytes"] = _safe(df, "sbytes", "src_bytes")
    out["dst_bytes"] = _safe(df, "dbytes", "dst_bytes")
    out["src_pkts"]  = _safe(df, "spkts",  "src_pkts")
    out["dst_pkts"]  = _safe(df, "dpkts",  "dst_pkts")

    proto = _safe(df, "proto").astype(str).str.lower()
    out["proto_tcp"]  = (proto == "tcp").astype(float)
    out["proto_udp"]  = (proto == "udp").astype(float)
    out["proto_icmp"] = (proto == "icmp").astype(float)

    state = _safe(df, "state").astype(str).str.upper()
    out["conn_ok"]  = (state.isin(["FIN", "CON"])).astype(float)
    out["conn_s0"]  = (state == "INT").astype(float)
    out["conn_rej"] = (state.isin(["RST", "REQ"])).astype(float)

    out["jitter"]      = _safe(df, "stddev")
    out["flow_weight"] = _safe(df, "rate")
    out["magnitude"]   = _safe(df, "max")
    out["variance"]    = _safe(df, "stddev") ** 2

    out["logged_in"]         = 0.0
    out["num_failed_logins"] = 0.0
    out["srv_count"]         = _safe(df, "drate")

    if "attack" in df.columns:
        out[LABEL_COL] = pd.to_numeric(
            df["attack"], errors="coerce").fillna(0).astype(int)
    elif "category" in df.columns:
        lbl = df["category"].astype(str).str.strip().str.lower()
        out[LABEL_COL] = (~lbl.str.contains("normal", na=False)).astype(int)
    else:
        out[LABEL_COL] = 1

    normal_count = int((out[LABEL_COL] == 0).sum())
    attack_count = int((out[LABEL_COL] == 1).sum())
    print(f"  [TON-IoT] normal={normal_count:,}  attack={attack_count:,}")

    # Too few normal rows — use FIN/CON state rows as proxy normals
    if normal_count < 100:
        print(f"  [WARN] Only {normal_count} normal rows — using FIN/CON state as proxy")
        fin_con_idx = out.index[state.isin(["FIN", "CON"])]
        # Only relabel rows that are currently attack
        attack_fin_con = fin_con_idx[out.loc[fin_con_idx, LABEL_COL] == 1]
        out.loc[attack_fin_con, LABEL_COL] = 0
        normal_count = int((out[LABEL_COL] == 0).sum())
        print(f"  [INFO] After proxy — normal={normal_count:,}")

    out = _derive(_finalize(out))

    benign  = out[out[LABEL_COL] == 0]
    attacks = out[out[LABEL_COL] == 1]
    n = min(len(benign), len(attacks), max_rows // 2)

    if n < 10:
        print(f"  [SKIP] Not enough balanced samples for TON-IoT (n={n})")
        # Return empty dataframe with correct columns
        return pd.DataFrame(columns=FEATURES + [LABEL_COL])

    out = pd.concat([
        benign.sample(n=n,  random_state=42),
        attacks.sample(n=n, random_state=42),
    ], ignore_index=True)

    print(f"  [TON-IoT]    rows={len(out):,}  "
          f"attack={out[LABEL_COL].sum():,}  "
          f"normal={(out[LABEL_COL]==0).sum():,}")
    return out


# ── Master loader ─────────────────────────────────────────────────────────────

DATASET_LOADERS = {
    "bot_iot.csv":  load_botniot,
    "iot23_v1.csv": load_iot23_v1,
    "iot23_v2.csv": load_iot23_v2,
    "ton_iot.csv":  load_toniot,
}


def load_all_datasets(dataset_dir, max_per=100_000, sample_frac: float = None):
    """
    Load all 4 datasets → map each to 22 unified features
    → balance each individually → combine → scale.

    Returns: (X, y, scaler)
    """
    frames = []

    print("\n" + "="*50)
    print("  Loading all 4 IoT datasets")
    print("="*50)

    for fname, loader_fn in DATASET_LOADERS.items():
        fpath = os.path.join(dataset_dir, fname)

        if not os.path.exists(fpath):
            print(f"\n[SKIP] {fname} not found in {dataset_dir}/")
            continue

        print(f"\n[LOAD] {fname} ...")
        try:
            df = loader_fn(fpath, max_rows=max_per, sample_frac=sample_frac)
        except Exception as e:
            print(f"[ERROR] {fname} failed: {e}")
            import traceback; traceback.print_exc()
            continue

        if len(df) == 0:
            print(f"  [SKIP] Empty result for {fname}")
            continue

        benign  = df[df[LABEL_COL] == 0]
        attacks = df[df[LABEL_COL] == 1]

        if len(benign) < 10:
            print(f"  [SKIP] Too few normal samples ({len(benign)}) in {fname}")
            continue
        if len(attacks) < 10:
            print(f"  [SKIP] Too few attack samples ({len(attacks)}) in {fname}")
            continue

        frames.append(df)
        print(f"  [OK] {fname} → {len(df):,} rows added")

    if not frames:
        raise FileNotFoundError(
            f"\nNo datasets loaded from: {dataset_dir}\n"
            "Check that your CSV files exist and have both normal and attack rows.\n"
            "Required filenames:\n"
            "  bot_iot.csv  |  iot23_v1.csv  |  iot23_v2.csv  |  ton_iot.csv\n"
        )

    combined = pd.concat(frames, ignore_index=True).sample(frac=1, random_state=42)

    print("\n" + "="*50)
    print(f"  Datasets loaded     : {len(frames)} / 4")
    print(f"  Total rows          : {len(combined):,}")
    print(f"  Total attack rows   : {combined[LABEL_COL].sum():,}")
    print(f"  Total normal rows   : {(combined[LABEL_COL]==0).sum():,}")
    print(f"  Overall attack rate : {combined[LABEL_COL].mean():.2%}")
    print("="*50 + "\n")

    X = combined[FEATURES].values.astype(np.float32)
    y = combined[LABEL_COL].values.astype(int)
    X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

    scaler = StandardScaler()
    X      = scaler.fit_transform(X)

    return X, y, scaler


def apply_smote(X, y, random_state=42):
    sm = SMOTE(random_state=random_state, k_neighbors=5)
    X_res, y_res = sm.fit_resample(X, y)
    print(f"[SMOTE] {len(y):,} → {len(y_res):,} samples")
    return X_res, y_res


def split(X, y, test_size=0.2, val_size=0.1):
    print(f"[SPLIT] Total={len(y):,}  Attack={y.sum():,}  Normal={(y==0).sum():,}")

    min_class = min(int(y.sum()), int((y == 0).sum()))
    if min_class < 10:
        raise ValueError(
            f"Not enough samples to split. "
            f"Attack={y.sum()}, Normal={(y==0).sum()}. "
            f"Check your dataset label columns."
        )

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=42)
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_tr, y_tr,
        test_size=val_size / (1 - test_size),
        stratify=y_tr, random_state=42)
    return X_tr, X_val, X_te, y_tr, y_val, y_te