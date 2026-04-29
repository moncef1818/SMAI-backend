"""
train_model.py
==============
Trains a Random Forest classifier on CICIDS-2017 data and saves the
sklearn Pipeline (scaler + model) as network_model.joblib.

Usage
-----
  # With real CICIDS-2017 CSVs:
  python train_model.py --data-dir /path/to/cicids2017/csvs

  # Quick smoke-test with synthetic data (no dataset needed):
  python train_model.py --synthetic

Rule-based alerts have been fully removed — all threat detection is ML-only.
"""

import argparse
import os
import glob
import logging
import warnings

import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)

CICIDS_COLUMN_MAP = {
    "Flow Duration": "FlowDuration",
    "Flow Bytes/s": "FlowBytesPerSec",
    "Flow Packets/s": "FlowPktsPerSec",
    "Total Fwd Packets": "FwdPackets",
    "Total Backward Packets": "BwdPackets",
    "Total Length of Fwd Packets": "FwdBytes",
    "Total Length of Bwd Packets": "BwdBytes",
    "Fwd Packet Length Mean": "FwdPktLenMean",
    "Fwd Packet Length Max": "FwdPktLenMax",
    "Fwd Packet Length Min": "FwdPktLenMin",
    "Bwd Packet Length Mean": "BwdPktLenMean",
    "Average Packet Size": "AvgPktSize",
    "Flow IAT Mean": "IatMean",
    "Flow IAT Std": "IatStd",
    "Flow IAT Max": "IatMax",
    "Flow IAT Min": "IatMin",
    "Fwd IAT Mean": "FwdIatMean",
    "Bwd IAT Mean": "BwdIatMean",
    "SYN Flag Count": "SynCount",
    "ACK Flag Count": "AckCount",
    "RST Flag Count": "RstCount",
    "PSH Flag Count": "PshCount",
    "FIN Flag Count": "FinCount",
    "URG Flag Count": "UrgCount",
    "Fwd Header Length": "FwdHeaderLength",
    "Bwd Header Length": "BwdHeaderLength",
    "Subflow Fwd Packets": "SubflowFwdPackets",
    "Subflow Bwd Packets": "SubflowBwdPackets",
    "Subflow Fwd Bytes": "SubflowFwdBytes",
    "Subflow Bwd Bytes": "SubflowBwdBytes",
    "Init_Win_bytes_forward": "InitWinBytesFwd",
    "Init_Win_bytes_backward": "InitWinBytesBwd",
    "act_data_pkt_fwd": "ActDataPktFwd",
    "min_seg_size_forward": "MinSegSizeFwd",
    "Destination Port": "DstPort",
    "Protocol": "Protocol",
    "Label": "Label",
}

FEATURE_COLS = [
    "FlowDuration", "FlowBytesPerSec", "FlowPktsPerSec",
    "FwdPackets", "BwdPackets", "FwdBytes", "BwdBytes",
    "FwdPktLenMean", "FwdPktLenMax", "FwdPktLenMin",
    "BwdPktLenMean", "AvgPktSize",
    "IatMean", "IatStd", "IatMax", "IatMin", "FwdIatMean", "BwdIatMean",
    "SynCount", "AckCount", "RstCount", "PshCount", "FinCount", "UrgCount",
    "FwdHeaderLength", "BwdHeaderLength",
    "SubflowFwdPackets", "SubflowBwdPackets", "SubflowFwdBytes", "SubflowBwdBytes",
    "InitWinBytesFwd", "InitWinBytesBwd", "ActDataPktFwd", "MinSegSizeFwd",
    "IatCoefficientOfVariation", "ExfiltrationZScore",
    "ByteRatio", "PacketRatio", "IatCoeffVariation",
    "TotalFlags", "DstPortBin", "Protocol",
    "IsHighPort", "IsWellKnownPort",
]

WELL_KNOWN_PORTS = {80, 443, 22, 21, 25, 53, 3389, 8080, 8443}

LABEL_GROUPING = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "Heartbleed": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack \x96 Brute Force": "WebAttack",
    "Web Attack \x96 XSS": "WebAttack",
    "Web Attack \x96 Sql Injection": "WebAttack",
    "Web Attack – Brute Force": "WebAttack",
    "Web Attack – XSS": "WebAttack",
    "Web Attack – Sql Injection": "WebAttack",
    "Infiltration": "Infiltration",
    "Bot": "Bot",
}


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    fwd_b = df.get("FwdBytes", pd.Series(0, index=df.index)).fillna(0)
    bwd_b = df.get("BwdBytes", pd.Series(0, index=df.index)).fillna(0)
    fwd_p = df.get("FwdPackets", pd.Series(0, index=df.index)).fillna(0)
    bwd_p = df.get("BwdPackets", pd.Series(0, index=df.index)).fillna(0)
    iat_m = df.get("IatMean", pd.Series(0, index=df.index)).fillna(0)
    iat_s = df.get("IatStd", pd.Series(0, index=df.index)).fillna(0)

    df["ByteRatio"]        = fwd_b / (fwd_b + bwd_b + 1)
    df["PacketRatio"]      = fwd_p / (fwd_p + bwd_p + 1)
    df["IatCoeffVariation"]= iat_s / (iat_m + 1)

    flag_cols = ["SynCount", "AckCount", "RstCount", "PshCount", "FinCount", "UrgCount"]
    df["TotalFlags"] = df[[c for c in flag_cols if c in df.columns]].sum(axis=1)

    dst_port = df.get("DstPort", pd.Series(0, index=df.index)).fillna(0)
    df["DstPortBin"] = pd.cut(dst_port, bins=[-1, 1023, 49151, 65535], labels=[0, 1, 2]).astype(float)
    df["IsHighPort"]      = (dst_port > 1024).astype(float)
    df["IsWellKnownPort"] = dst_port.apply(lambda p: 1.0 if int(p) in WELL_KNOWN_PORTS else 0.0)

    if "IatCoefficientOfVariation" not in df.columns:
        df["IatCoefficientOfVariation"] = df["IatCoeffVariation"]
    if "ExfiltrationZScore" not in df.columns:
        df["ExfiltrationZScore"] = 0.0
    if "Protocol" not in df.columns:
        df["Protocol"] = 6.0
    return df


def load_cicids(data_dir: str) -> pd.DataFrame:
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")
    dfs = []
    for f in csv_files:
        log.info(f"Loading {os.path.basename(f)} ...")
        try:
            df = pd.read_csv(f, low_memory=False)
            df.columns = df.columns.str.strip()
            dfs.append(df)
        except Exception as exc:
            log.warning(f"  Skipped {f}: {exc}")
    full = pd.concat(dfs, ignore_index=True)
    log.info(f"Loaded {len(full):,} rows from {len(csv_files)} files.")
    return full


def preprocess(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    df = df.rename(columns=CICIDS_COLUMN_MAP)
    if "Label" in df.columns:
        df["Label"] = df["Label"].str.strip().map(lambda x: LABEL_GROUPING.get(x, x))
    else:
        df["Label"] = "BENIGN"
    df = df.dropna(subset=["Label"])
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0).clip(-1e12, 1e12)
    df = engineer_features(df)
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0.0
    return df[FEATURE_COLS], df["Label"]


def make_synthetic_data(n_samples: int = 20_000) -> tuple[pd.DataFrame, pd.Series]:
    """
    Synthetic flows with realistic per-class distributions.
    IatCoefficientOfVariation and ExfiltrationZScore are genuine ML features here —
    no rule thresholds are applied anywhere.
    """
    rng = np.random.default_rng(42)
    rows, labels = [], []

    classes = {
        "BENIGN":      (0.60, dict(FlowBytesPerSec=(5000,3000),   IatMean=(70000,20000),  FwdBytes=(10000,5000),  IatCoV=(0.6,0.2),   ExfilZ=(0.5,0.3))),
        "DoS":         (0.12, dict(FlowBytesPerSec=(80000,20000), IatMean=(500,200),      FwdBytes=(100000,30000),IatCoV=(0.5,0.15),  ExfilZ=(0.6,0.3))),
        "DDoS":        (0.08, dict(FlowBytesPerSec=(200000,50000),IatMean=(200,100),      FwdBytes=(200000,80000),IatCoV=(0.55,0.15), ExfilZ=(0.6,0.3))),
        "PortScan":    (0.06, dict(FlowBytesPerSec=(100,50),      IatMean=(1000,500),     FwdBytes=(100,50),      IatCoV=(0.4,0.1),   ExfilZ=(0.4,0.2),  SynCount=(1,0))),
        "BruteForce":  (0.06, dict(FlowBytesPerSec=(500,200),     IatMean=(5000,2000),    FwdBytes=(500,200),     IatCoV=(0.3,0.1),   ExfilZ=(0.5,0.2))),
        "WebAttack":   (0.04, dict(FlowBytesPerSec=(3000,1000),   IatMean=(20000,5000),   FwdBytes=(3000,1000),   IatCoV=(0.45,0.15), ExfilZ=(0.5,0.2))),
        "Bot":         (0.03, dict(FlowBytesPerSec=(200,50),      IatMean=(60000000,1000),FwdBytes=(500,100),     IatCoV=(0.05,0.02), ExfilZ=(4.5,1.0))),
        "Infiltration":(0.01, dict(FlowBytesPerSec=(1000,500),    IatMean=(30000,10000),  FwdBytes=(1000,500),    IatCoV=(0.35,0.1),  ExfilZ=(4.2,0.9))),
    }

    counts = (np.array([v[0] for v in classes.values()]) * n_samples).astype(int)

    for (label, (_, p)), count in zip(classes.items(), counts):
        for _ in range(count):
            fwd_b   = max(0, rng.normal(*p.get("FwdBytes", (5000,2000))))
            iat_m   = max(0, rng.normal(*p.get("IatMean",  (50000,10000))))
            bps     = max(0, rng.normal(*p.get("FlowBytesPerSec", (5000,2000))))
            iat_cov = max(0, rng.normal(*p.get("IatCoV",  (0.5,0.15))))
            exfil_z = max(0, rng.normal(*p.get("ExfilZ",  (0.5,0.3))))

            row = {
                "FlowDuration":    rng.integers(100_000, 5_000_000),
                "FlowBytesPerSec": bps,
                "FlowPktsPerSec":  bps / max(fwd_b / max(rng.integers(5,30), 1), 1),
                "FwdPackets":      rng.integers(2, 100),
                "BwdPackets":      rng.integers(0, 80),
                "FwdBytes":        fwd_b,
                "BwdBytes":        max(0, rng.normal(fwd_b*0.5, fwd_b*0.2+1)),
                "FwdPktLenMean":   fwd_b / max(rng.integers(5,30), 1),
                "FwdPktLenMax":    rng.integers(40, 1500),
                "FwdPktLenMin":    rng.integers(20, 100),
                "BwdPktLenMean":   max(0, rng.normal(500,200)),
                "AvgPktSize":      max(0, rng.normal(700,300)),
                "IatMean":         iat_m,
                "IatStd":          iat_m * max(0.01, rng.uniform(0.01,0.5)),
                "IatMax":          iat_m * rng.uniform(1.5,4),
                "IatMin":          iat_m * rng.uniform(0.01,0.5),
                "FwdIatMean":      iat_m * rng.uniform(0.8,1.2),
                "BwdIatMean":      iat_m * rng.uniform(0.8,1.2),
                "SynCount":        p.get("SynCount",(0,0))[0] if "SynCount" in p else rng.integers(0,2),
                "AckCount":        rng.integers(0,30),
                "RstCount":        rng.integers(0,2),
                "PshCount":        rng.integers(0,15),
                "FinCount":        rng.integers(0,2),
                "UrgCount":        0,
                "FwdHeaderLength": rng.integers(20,500),
                "BwdHeaderLength": rng.integers(20,400),
                "SubflowFwdPackets":rng.integers(2,80),
                "SubflowBwdPackets":rng.integers(0,60),
                "SubflowFwdBytes": fwd_b,
                "SubflowBwdBytes": max(0, rng.normal(fwd_b*0.5, fwd_b*0.2+1)),
                "InitWinBytesFwd": 65535,
                "InitWinBytesBwd": 65535,
                "ActDataPktFwd":   rng.integers(1,20),
                "MinSegSizeFwd":   rng.integers(20,80),
                "IatCoefficientOfVariation": iat_cov,
                "ExfiltrationZScore":        exfil_z,
                "DstPort":   rng.choice([80, 443, 22, 4444, 8080, int(rng.integers(1024,65535))]),
                "Protocol":  rng.choice([6, 17], p=[0.85, 0.15]),
            }
            rows.append(row)
            labels.append(label)

    df = pd.DataFrame(rows)
    df = engineer_features(df)
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0.0
    return df[FEATURE_COLS], pd.Series(labels)


def train(X: pd.DataFrame, y: pd.Series, output_path: str):
    log.info(f"Dataset shape: {X.shape}")
    log.info(f"Label distribution:\n{y.value_counts()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    log.info("Building pipeline: StandardScaler + RandomForestClassifier ...")
    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    pipeline = Pipeline([("scaler", StandardScaler()), ("clf", clf)])

    log.info("Training ...")
    pipeline.fit(X_train, y_train)

    log.info("Evaluating on held-out test set ...")
    y_pred = pipeline.predict(X_test)
    print("\n" + "=" * 60)
    print("CLASSIFICATION REPORT")
    print("=" * 60)
    print(classification_report(y_test, y_pred, zero_division=0))

    joblib.dump(pipeline, output_path)
    log.info(f"Model saved → {output_path}")

    imp_df = pd.DataFrame({"feature": FEATURE_COLS,
                            "importance": pipeline.named_steps["clf"].feature_importances_
                           }).sort_values("importance", ascending=False)
    log.info("Top 10 features:\n" + imp_df.head(10).to_string(index=False))
    return pipeline


def main():
    parser = argparse.ArgumentParser(description="Train ML-only network flow threat model.")
    parser.add_argument("--data-dir",    type=str,  default=None)
    parser.add_argument("--synthetic",   action="store_true")
    parser.add_argument("--output",      type=str,  default="network_model.joblib")
    parser.add_argument("--synthetic-n", type=int,  default=20_000)
    args = parser.parse_args()

    if args.synthetic:
        log.info("Generating synthetic training data ...")
        X, y = make_synthetic_data(args.synthetic_n)
    elif args.data_dir:
        raw  = load_cicids(args.data_dir)
        X, y = preprocess(raw)
    else:
        parser.error("Provide --data-dir or --synthetic")

    train(X, y, args.output)


if __name__ == "__main__":
    main()
