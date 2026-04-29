"""
PhishGuard API — /predict only
Run:  uvicorn main:app --reload --port 8000
Docs: http://localhost:8000/docs
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict
import joblib, json, numpy as np, pandas as pd
import os, time, re
from urllib.parse import urlparse

# ── Load model ─────────────────────────────────────────────────────────────────
BASE = os.path.dirname(__file__)

_model_path = os.path.join(BASE, "models", "xgb_agent_current.joblib")
_feat_path  = os.path.join(BASE, "models", "agent_current_features.json")

if not os.path.exists(_model_path):
    raise RuntimeError(
        f"Model not found at {_model_path}. "
        "Run  python train_model.py  first."
    )

MODEL    = joblib.load(_model_path)
with open(_feat_path) as f:
    FEATURES = json.load(f)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "short.link",
    "cutt.ly", "rb.gy", "tiny.cc",
}

app = FastAPI(
    title="PhishGuard",
    description="Phishing detector — POST your agent JSON to /predict",
    version="2.1",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Rule engine ────────────────────────────────────────────────────────────────
#
# Severity / points guide:
#   CRITICAL (40 pts) — near-certain phishing signal on its own (IP URL, shortener,
#                       email-in-URL, cross-domain form, confirmed IP+no-TLS combo).
#   HIGH     (20 pts) — strong signal that needs corroboration (no HTTPS alone on a
#                       login page, hidden iframes, very long URL …).
#   MEDIUM   (10 pts) — weak / contextual signal.
#
# Key design decisions:
#   • "no_https" alone is HIGH (20), not CRITICAL. Plenty of internal/dev sites
#     have no TLS. It only becomes CRITICAL when combined with a password field
#     via "password_no_https".
#   • "sparse_content_form" threshold raised to < 150 words so normal login pages
#     (350 + words) don't get flagged; the HIGH tier only fires on truly bare pages.
#   • "password_no_https" is CRITICAL — collecting credentials over plain HTTP is
#     unambiguously malicious.
#
RULES: List[tuple] = [
    # (name, severity, points, check_fn)

    # ── CRITICAL — individually sufficient for a hard PHISHING call ────────────
    ("ip_based_url",           "CRITICAL", 40, lambda f: f["domain_in_ip"] == 1),
    ("url_shortened",          "CRITICAL", 40, lambda f: f["url_shortened"] == 1),
    ("email_in_url",           "CRITICAL", 40, lambda f: f["email_in_url"] == 1),
    ("password_no_https",      "CRITICAL", 40, lambda f: f["has_password"] == 1 and f["tls_ssl_certificate"] == 0),
    ("external_form_action",   "CRITICAL", 40, lambda f: f["form_crossdomain"] == 1),

    # ── HIGH — strong signals that need corroboration ──────────────────────────
    ("no_https",               "HIGH",     20, lambda f: f["tls_ssl_certificate"] == 0),
    ("very_long_url",          "HIGH",     20, lambda f: f["length_url"] > 100),
    ("many_subdomains",        "HIGH",     20, lambda f: f["qty_dot_domain"] > 3),
    ("hidden_iframes",         "HIGH",     20, lambda f: f["hidden_frames"] > 0),
    ("many_hidden_inputs",     "HIGH",     20, lambda f: f["hidden_inputs"] > 3),
    # Raised threshold: < 150 words means a truly bare page, not a normal login page
    ("sparse_content_form",    "HIGH",     20, lambda f: f["words"] < 150 and f["forms"] > 0),

    # ── MEDIUM — weak / contextual signals ────────────────────────────────────
    ("at_in_url",              "MEDIUM",   10, lambda f: f["qty_at_url"] > 0),
    ("many_hyphens_url",       "MEDIUM",   10, lambda f: f["qty_hyphen_url"] > 4),
    ("many_slashes_url",       "MEDIUM",   10, lambda f: f["qty_slash_url"] > 5),
    ("many_cookies",           "MEDIUM",   10, lambda f: f["cookies"] > 15),
    ("many_ext_scripts",       "MEDIUM",   10, lambda f: f["ext_scripts"] > 5),
    ("high_link_density",      "MEDIUM",   10, lambda f: f["words"] > 0 and f["links"] / max(f["words"], 1) > 0.5),
    ("no_paragraph_with_form", "MEDIUM",   10, lambda f: f["paragraphs"] == 0 and f["forms"] > 0),
]


def _run_rules(features: dict) -> dict:
    triggered, score = [], 0
    for name, severity, pts, check in RULES:
        try:
            if check(features):
                triggered.append({"rule": name, "severity": severity, "points": pts})
                score += pts
        except Exception:
            pass
    if score >= 40:
        verdict = "PHISHING"
    elif score >= 20:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LEGITIMATE"
    return {"score": score, "verdict": verdict, "rules": triggered}


# ── Feature extraction ─────────────────────────────────────────────────────────
def _extract(agent: dict) -> dict:
    """
    Extract every feature our model and rule-engine need from the agent JSON.
    No external network calls — pure string / dict processing.
    """
    url    = agent.get("url", "")
    p      = urlparse(url)
    domain = p.netloc
    path   = p.path
    params = p.query
    dirpath = "/".join(path.split("/")[:-1])

    # TLS — trust the agent flag first, fall back to URL scheme
    flags = (agent.get("phishingMetrics") or {}).get("flags") or {}
    tls   = 0 if flags.get("noHttps") else (1 if url.startswith("https://") else 0)

    content  = agent.get("content")  or {}
    forms    = agent.get("formData") or {}
    scripts  = agent.get("scripts")  or {}
    cookies  = agent.get("cookies")  or {}
    behavior = agent.get("behavior") or {}

    f: dict = {
        # ── URL character counts (match dataset column names exactly) ──────────
        "length_url":           len(url),
        "qty_dot_url":          url.count("."),
        "qty_hyphen_url":       url.count("-"),
        "qty_slash_url":        url.count("/"),
        "qty_at_url":           url.count("@"),
        "qty_questionmark_url": url.count("?"),
        "qty_equal_url":        url.count("="),
        "qty_and_url":          url.count("&"),
        "qty_percent_url":      url.count("%"),
        # ── Domain ────────────────────────────────────────────────────────────
        "qty_dot_domain":       domain.count("."),
        "qty_hyphen_domain":    domain.count("-"),
        "domain_length":        len(domain),
        "domain_in_ip":         int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain))),
        # ── Path / params ─────────────────────────────────────────────────────
        "qty_slash_directory":  dirpath.count("/"),
        "directory_length":     len(dirpath),
        "params_length":        len(params),
        "qty_params":           len(params.split("&")) if params else 0,
        "qty_equal_params":     params.count("="),
        # ── Special URL-level flags ────────────────────────────────────────────
        "email_in_url":         int("@" in url or "%40" in url),
        "url_shortened":        int(domain.lower().split(":")[0] in SHORTENERS),
        "tls_ssl_certificate":  tls,
        # ── Engineered URL features (mirror train_model.py engineer()) ─────────
        "url_special_total":    sum(url.count(c) for c in ".-_/?=@&%#!~"),
        "has_at_url":           int(url.count("@") > 0),
        "many_subdomains":      int(domain.count(".") > 3),
        "domain_hyphen_ratio":  domain.count("-") / max(len(domain), 1),
        "short_domain":         int(len(domain) < 6),
        "deep_path":            int(dirpath.count("/") > 3),
        "no_tls":               int(tls == 0),
        "long_url":             int(len(url) > 75),
        "very_long_url":        int(len(url) > 100),
        # ── Page / agent signals (rule-engine only, not fed to ML model) ───────
        "words":          int(content.get("wordsCount")        or 0),
        "links":          int(content.get("linkCount")         or 0),
        "iframes":        int(content.get("iframeCount")       or 0),
        "hidden_frames":  int(content.get("hiddenframesCount") or 0),
        "paragraphs":     int(content.get("paragraphCount")    or 0),
        "forms":          int(forms.get("formCount")           or 0),
        "has_password":   int(bool(forms.get("hasPasswordField"))),
        "hidden_inputs":  int(forms.get("hiddenFieldCount")    or 0),
        "form_crossdomain": int((forms.get("crossdomain") or 0) > 0),
        "ext_scripts":    int(scripts.get("externalScriptCount") or 0),
        "cookies":        int(cookies.get("cookieCount")       or 0),
        "time_on_page":   int(behavior.get("timeOnPage")       or 0),
        "scroll_depth":   float(behavior.get("scrollDepth")    or 0),
        "click_count":    int(behavior.get("clickCount")       or 0),
    }

    f["url_special_density"] = f["url_special_total"] / max(f["length_url"], 1)
    return f


def _ml_predict(f: dict) -> float:
    """Run XGBoost; return P(phishing)."""
    row = pd.DataFrame([{col: f.get(col, 0) for col in FEATURES}])
    return float(MODEL.predict_proba(row)[0][1])


# ── Verdict logic ──────────────────────────────────────────────────────────────
def _combine(rules: dict, prob: float) -> tuple[str, str]:
    """
    Return (verdict, risk).

    Decision matrix:
    ┌─────────────────────────────┬───────────────────────────────────────────┐
    │ Rule signal                 │ ML confirms (prob)?  → verdict            │
    ├─────────────────────────────┼───────────────────────────────────────────┤
    │ Any CRITICAL hit            │ always                → PHISHING           │
    │ HIGH hits, score ≥ 40       │ always                → PHISHING           │
    │ HIGH hits, score 20-39      │ prob ≥ 0.85           → PHISHING           │
    │ HIGH hits, score 20-39      │ prob < 0.85           → SUSPICIOUS         │
    │ MEDIUM only, score ≥ 20     │ prob ≥ 0.90           → PHISHING           │
    │ MEDIUM only, score ≥ 20     │ prob ≥ 0.70           → SUSPICIOUS         │
    │ MEDIUM only, score < 20     │ prob ≥ 0.90           → SUSPICIOUS         │
    │ No rules                    │ prob ≥ 0.97           → SUSPICIOUS         │
    │ No rules                    │ prob < 0.97           → LEGITIMATE         │
    └─────────────────────────────┴───────────────────────────────────────────┘

    Key principles:
    - CRITICAL rules (IP URL, shortener, email-in-URL, password+no-TLS,
      cross-domain form) are individually definitive — no ML needed.
    - "no_https" alone is HIGH (not CRITICAL) — many internal/dev sites lack TLS.
      It only escalates when ML also agrees (prob ≥ 0.85).
    - ML alone cannot reach PHISHING — max it can do without rules is SUSPICIOUS.
    - The SaaS login case (HTTPS ✓, clean URL, small form) scores 0 rules and
      low-enough ML → correctly stays LEGITIMATE.
    """
    has_critical = any(r["severity"] == "CRITICAL" for r in rules["rules"])
    has_high     = any(r["severity"] == "HIGH"     for r in rules["rules"])
    has_medium   = any(r["severity"] == "MEDIUM"   for r in rules["rules"])
    score        = rules["score"]

    # Count critical hits (some cases need to distinguish one vs many)
    n_critical = sum(1 for r in rules["rules"] if r["severity"] == "CRITICAL")

    if has_critical:
        verdict = "PHISHING"

    elif has_high and score >= 40:
        # Multiple HIGH signals stacking up — definitive even without ML
        verdict = "PHISHING"

    elif has_high:
        # One or two HIGH signals — require ML to confirm
        verdict = "PHISHING" if prob >= 0.85 else "SUSPICIOUS"

    elif has_medium and score >= 20:
        # Several MEDIUM signals — ML decides between PHISHING and SUSPICIOUS
        if prob >= 0.90:
            verdict = "PHISHING"
        elif prob >= 0.70:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LEGITIMATE"

    elif has_medium:
        # Few MEDIUM signals — only flag if ML is very confident
        verdict = "SUSPICIOUS" if prob >= 0.90 else "LEGITIMATE"

    elif prob >= 0.97:
        # Zero rule hits but ML extremely confident — soft flag only
        verdict = "SUSPICIOUS"

    else:
        verdict = "LEGITIMATE"

    # ── Risk level (independent of verdict — reflects raw signal strength) ──────
    if has_critical or (has_high and score >= 40):
        risk = "critical"
    elif has_high and prob >= 0.85:
        risk = "high"
    elif has_high or (has_medium and score >= 20):
        risk = "medium"
    elif score > 0 or prob >= 0.70:
        risk = "medium"
    else:
        risk = "low"

    return verdict, risk


# ── Request schema — matches agent JSON ───────────────────────────────────────
class AgentJSON(BaseModel):
    url: str
    phishingMetrics: Optional[Dict] = {}
    content:         Optional[Dict] = {}
    formData:        Optional[Dict] = {}
    scripts:         Optional[Dict] = {}
    cookies:         Optional[Dict] = {}
    storage:         Optional[Dict] = {}
    behavior:        Optional[Dict] = {}
    fingerprint:     Optional[Dict] = {}
    # Any extra keys sent by the agent are silently ignored


# ── Response schema ────────────────────────────────────────────────────────────
class PredictResponse(BaseModel):
    verdict:         str           # PHISHING | SUSPICIOUS | LEGITIMATE
    risk:            str           # critical | high | medium | low
    ml_probability:  float         # P(phishing) from XGBoost, 0-1
    rule_score:      int           # sum of triggered rule points
    rule_verdict:    str           # rule-only verdict before combination
    triggered_rules: List[Dict]    # list of {rule, severity, points}
    url:             str
    latency_ms:      float


# ── Endpoints ──────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status":   "ok",
        "model":    "xgb_agent_current",
        "features": len(FEATURES),
        "rules":    len(RULES),
    }


@app.post("/predict", response_model=PredictResponse)
async def predict(payload: AgentJSON):
    """
    Analyse a URL + optional page signals collected by your browser agent.

    - **verdict**: PHISHING | SUSPICIOUS | LEGITIMATE
    - **ml_probability**: raw XGBoost score (0 = safe, 1 = phishing)
    - **triggered_rules**: list of heuristic rules that fired
    """
    t0 = time.time()

    try:
        feat  = _extract(payload.model_dump())
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Feature extraction failed: {exc}")

    rules   = _run_rules(feat)
    prob    = _ml_predict(feat)
    verdict, risk = _combine(rules, prob)

    return PredictResponse(
        verdict        = verdict,
        risk           = risk,
        ml_probability = round(prob, 4),
        rule_score     = rules["score"],
        rule_verdict   = rules["verdict"],
        triggered_rules= rules["rules"],
        url            = payload.url,
        latency_ms     = round((time.time() - t0) * 1000, 2),
    )
