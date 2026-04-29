"""
train_model.py — PhishGuard XGBoost trainer
Dataset: GregaVrbancic/Phishing-Dataset (dataset_full.csv)
Output:  models/xgb_agent_current.joblib
         models/agent_current_features.json

Usage:
    pip install xgboost scikit-learn pandas numpy joblib --break-system-packages
    python train_model.py                              # downloads dataset automatically
    python train_model.py --csv path/to/dataset.csv   # use local file
"""

import argparse, json, os, urllib.request
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (classification_report, roc_auc_score,
                              confusion_matrix, accuracy_score)
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

# ── Config ─────────────────────────────────────────────────────────────────────
DATASET_URL = (
    "https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/"
    "master/dataset_full.csv"
)
MODEL_DIR   = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH  = os.path.join(MODEL_DIR, "xgb_agent_current.joblib")
FEAT_PATH   = os.path.join(MODEL_DIR, "agent_current_features.json")

# ── Features from dataset that map to main.py extract() ───────────────────────
#
# The dataset has 111 columns.  We keep the subset that our feature-extractor
# actually populates, so the model never sees a column it can't get at runtime.
#
DATASET_FEATURE_MAP = {
    # dataset column          : internal name used in extract()
    "length_url":               "length_url",
    "qty_dot_url":              "qty_dot_url",
    "qty_hyphen_url":           "qty_hyphen_url",
    "qty_slash_url":            "qty_slash_url",
    "qty_at_url":               "qty_at_url",
    "qty_questionmark_url":     "qty_questionmark_url",
    "qty_equal_url":            "qty_equal_url",
    "qty_and_url":              "qty_and_url",
    "qty_percent_url":          "qty_percent_url",
    "qty_dot_domain":           "qty_dot_domain",
    "qty_hyphen_domain":        "qty_hyphen_domain",
    "domain_length":            "domain_length",
    "domain_in_ip":             "domain_in_ip",
    "qty_slash_directory":      "qty_slash_directory",
    "directory_length":         "directory_length",
    "params_length":            "params_length",
    "qty_params":               "qty_params",
    "qty_equal_params":         "qty_equal_params",
    "email_in_url":             "email_in_url",
    "url_shortened":            "url_shortened",
    "tls_ssl_certificate":      "tls_ssl_certificate",
    # Engineered extras computed by extract() — synthesised from URL stats
    # (they'll be computed from the raw columns below during training too)
}

# Extra engineered columns we compute from the raw dataset rows (mirrors extract())
ENGINEERED = [
    "url_special_total",
    "url_special_density",
    "has_at_url",
    "many_subdomains",
    "domain_hyphen_ratio",
    "short_domain",
    "deep_path",
    "no_tls",
    "long_url",
    "very_long_url",
]

TARGET_COL = "phishing"   # 1 = phishing, 0 = legitimate


# ── Helpers ────────────────────────────────────────────────────────────────────
def download_dataset(dest: str) -> str:
    path = os.path.join(dest, "dataset_full.csv")
    if os.path.exists(path):
        print(f"[dataset] Using cached {path}")
        return path
    print(f"[dataset] Downloading from GitHub …")
    os.makedirs(dest, exist_ok=True)
    urllib.request.urlretrieve(DATASET_URL, path)
    print(f"[dataset] Saved to {path}")
    return path


def engineer(df: pd.DataFrame) -> pd.DataFrame:
    """Add the same engineered features that extract() computes at inference."""
    url_chars = ".-_/?=@&%#!~"
    # url_special_total: sum of special-char counts already in the dataset columns
    special_cols = [c for c in [
        "qty_dot_url", "qty_hyphen_url", "qty_slash_url",
        "qty_at_url", "qty_questionmark_url", "qty_equal_url",
        "qty_and_url", "qty_percent_url",
    ] if c in df.columns]
    df["url_special_total"]   = df[special_cols].sum(axis=1)
    df["url_special_density"] = df["url_special_total"] / df["length_url"].clip(lower=1)
    df["has_at_url"]          = (df["qty_at_url"] > 0).astype(int)
    df["many_subdomains"]     = (df["qty_dot_domain"] > 3).astype(int)
    df["domain_hyphen_ratio"] = df["qty_hyphen_domain"] / df["domain_length"].clip(lower=1)
    df["short_domain"]        = (df["domain_length"] < 6).astype(int)
    df["deep_path"]           = (df["qty_slash_directory"] > 3).astype(int)
    df["no_tls"]              = (df["tls_ssl_certificate"] == 0).astype(int)
    df["long_url"]            = (df["length_url"] > 75).astype(int)
    df["very_long_url"]       = (df["length_url"] > 100).astype(int)
    return df


def load_and_prepare(csv_path: str):
    print(f"[data] Loading {csv_path} …")
    df = pd.read_csv(csv_path)
    print(f"[data] Shape: {df.shape}")

    # Normalise target column name (dataset uses 'phishing' or last column)
    if TARGET_COL not in df.columns:
        # Try last column
        df = df.rename(columns={df.columns[-1]: TARGET_COL})
    
    # Map -1/1 labels → 0/1 if needed (some versions use -1 for legit)
    if df[TARGET_COL].min() == -1:
        df[TARGET_COL] = df[TARGET_COL].map({-1: 0, 1: 1})

    # Keep only columns we need
    keep = list(DATASET_FEATURE_MAP.keys()) + [TARGET_COL]
    missing = [c for c in keep if c not in df.columns and c != TARGET_COL]
    if missing:
        print(f"[warn] Missing dataset columns (will zero-fill): {missing}")
        for c in missing:
            df[c] = 0
    df = df[[c for c in keep if c in df.columns]].copy()

    # Engineer extras
    df = engineer(df)

    # Final feature list (everything except target)
    feature_cols = [c for c in df.columns if c != TARGET_COL]

    X = df[feature_cols].fillna(0)
    y = df[TARGET_COL].astype(int)

    print(f"[data] Features: {len(feature_cols)}  |  Phishing: {y.sum()}  |  Legit: {(y==0).sum()}")
    return X, y, feature_cols


def train(X, y, feature_cols):
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y
    )

    model = XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        min_child_weight=3,
        gamma=0.1,
        reg_alpha=0.05,
        reg_lambda=1.0,
        scale_pos_weight=1,          # dataset is balanced; set >1 if skewed
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
        verbosity=0,
    )

    print("\n[train] 5-fold cross-validation …")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_auc = cross_val_score(model, X_tr, y_tr, cv=cv, scoring="roc_auc", n_jobs=-1)
    print(f"  CV AUC:  {cv_auc.mean():.4f} ± {cv_auc.std():.4f}")

    print("[train] Fitting final model …")
    model.fit(
        X_tr, y_tr,
        eval_set=[(X_te, y_te)],
        verbose=False,
    )

    # ── Evaluation ─────────────────────────────────────────────────────────────
    y_prob = model.predict_proba(X_te)[:, 1]
    y_pred = model.predict(X_te)

    print(f"\n[eval] Test AUC:      {roc_auc_score(y_te, y_prob):.4f}")
    print(f"[eval] Test Accuracy: {accuracy_score(y_te, y_pred):.4f}")
    print("\n[eval] Classification Report:")
    print(classification_report(y_te, y_pred, target_names=["Legit", "Phishing"]))

    cm = confusion_matrix(y_te, y_pred)
    print("[eval] Confusion Matrix (rows=actual, cols=predicted):")
    print(f"       Legit    Phishing")
    print(f"Legit  {cm[0,0]:>6}   {cm[0,1]:>6}")
    print(f"Phish  {cm[1,0]:>6}   {cm[1,1]:>6}")

    # ── Feature importance (top 15) ────────────────────────────────────────────
    fi = pd.Series(model.feature_importances_, index=feature_cols).sort_values(ascending=False)
    print("\n[feat] Top 15 important features:")
    for name, score in fi.head(15).items():
        bar = "█" * int(score * 200)
        print(f"  {name:<30} {score:.4f}  {bar}")

    return model


def save(model, feature_cols):
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    with open(FEAT_PATH, "w") as f:
        json.dump(feature_cols, f, indent=2)
    print(f"\n[save] Model  → {MODEL_PATH}")
    print(f"[save] Features → {FEAT_PATH}  ({len(feature_cols)} features)")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=None, help="Path to dataset_full.csv (auto-downloads if omitted)")
    ap.add_argument("--cache-dir", default="data", help="Where to cache the downloaded CSV")
    args = ap.parse_args()

    csv_path = args.csv or download_dataset(args.cache_dir)
    X, y, feature_cols = load_and_prepare(csv_path)
    model = train(X, y, feature_cols)
    save(model, feature_cols)
    print("\n✅  Done!  Start the API:  uvicorn main:app --reload --port 8000")


if __name__ == "__main__":
    main()
