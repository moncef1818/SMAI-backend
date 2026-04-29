"""
NetworkMonitorService — ML Inference API  (ML-only, no rule-based alerts)
Receives flow events from the agent and returns threat predictions.
"""

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
import pandas as pd
import numpy as np
import joblib
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Network Flow Threat Detection API (ML-only)",
    description="Receives NetworkMonitorService flow events and predicts threat class using ML only.",
    version="2.0.0",
)

MODEL_PATH = os.getenv("MODEL_PATH", "network_model.joblib")
_pipeline = None


@app.on_event("startup")
def load_model():
    global _pipeline
    if not os.path.exists(MODEL_PATH):
        logger.warning(
            f"Model file '{MODEL_PATH}' not found. "
            "Run train_model.py first, then restart the server."
        )
        return
    _pipeline = joblib.load(MODEL_PATH)
    logger.info(f"Model loaded from {MODEL_PATH}")


# ---------------------------------------------------------------------------
# Input schema
# ---------------------------------------------------------------------------
class FlowEvent(BaseModel):
    # Envelope
    LogSource:   Optional[str] = None
    EventType:   Optional[str] = None
    TimeStamp:   Optional[str] = None
    ProcessID:   Optional[int] = None
    ProcessName: Optional[str] = None

    # 5-tuple
    SrcIp:    Optional[str] = None
    DstIp:    Optional[str] = None
    SrcPort:  Optional[int] = None
    DstPort:  Optional[int] = None
    Protocol: Optional[int] = None

    # Timing & throughput
    FlowDuration:    Optional[float] = None
    FlowBytesPerSec: Optional[float] = None
    FlowPktsPerSec:  Optional[float] = None

    # Packet / byte counts
    FwdPackets: Optional[int]   = None
    BwdPackets: Optional[int]   = None
    FwdBytes:   Optional[float] = None
    BwdBytes:   Optional[float] = None

    # Packet length stats
    FwdPktLenMean: Optional[float] = None
    FwdPktLenMax:  Optional[float] = None
    FwdPktLenMin:  Optional[float] = None
    BwdPktLenMean: Optional[float] = None
    AvgPktSize:    Optional[float] = None

    # IAT stats (microseconds)
    IatMean:    Optional[float] = None
    IatStd:     Optional[float] = None
    IatMax:     Optional[float] = None
    IatMin:     Optional[float] = None
    FwdIatMean: Optional[float] = None
    BwdIatMean: Optional[float] = None

    # TCP flags
    SynCount: Optional[int] = None
    AckCount: Optional[int] = None
    RstCount: Optional[int] = None
    PshCount: Optional[int] = None
    FinCount: Optional[int] = None
    UrgCount: Optional[int] = None

    # Header / subflow
    FwdHeaderLength:   Optional[int]   = None
    BwdHeaderLength:   Optional[int]   = None
    SubflowFwdPackets: Optional[int]   = None
    SubflowBwdPackets: Optional[int]   = None
    SubflowFwdBytes:   Optional[float] = None
    SubflowBwdBytes:   Optional[float] = None

    # TCP handshake
    InitWinBytesFwd: Optional[int] = None
    InitWinBytesBwd: Optional[int] = None
    ActDataPktFwd:   Optional[int] = None
    MinSegSizeFwd:   Optional[int] = None

    # SMAI detection features
    IatCoefficientOfVariation: Optional[float] = None
    ExfiltrationZScore:        Optional[float] = None


# ---------------------------------------------------------------------------
# Feature names — must match train_model.py FEATURE_COLS exactly
# ---------------------------------------------------------------------------
FEATURE_NAMES = [
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


def extract_features(flow: FlowEvent) -> np.ndarray:
    def safe(val, default=0.0):
        return float(val) if val is not None else default

    fwd_bytes = safe(flow.FwdBytes)
    bwd_bytes = safe(flow.BwdBytes)
    fwd_pkts  = safe(flow.FwdPackets)
    bwd_pkts  = safe(flow.BwdPackets)
    iat_mean  = safe(flow.IatMean)
    iat_std   = safe(flow.IatStd)
    dst_port  = safe(flow.DstPort)
    protocol  = safe(flow.Protocol, 6.0)

    byte_ratio    = fwd_bytes / (fwd_bytes + bwd_bytes + 1.0)
    packet_ratio  = fwd_pkts  / (fwd_pkts  + bwd_pkts  + 1.0)
    iat_cv_derived = iat_std  / (iat_mean  + 1.0)

    total_flags = (
        safe(flow.SynCount) + safe(flow.AckCount) + safe(flow.RstCount)
        + safe(flow.PshCount) + safe(flow.FinCount) + safe(flow.UrgCount)
    )

    well_known = {80, 443, 22, 21, 25, 53, 3389, 8080, 8443}
    is_high_port  = 1.0 if dst_port > 1024 else 0.0
    is_well_known = 1.0 if int(dst_port) in well_known else 0.0

    if dst_port < 1024:
        dst_port_bin = 0.0
    elif dst_port < 49152:
        dst_port_bin = 1.0
    else:
        dst_port_bin = 2.0

    # Use agent-supplied IatCoefficientOfVariation when available, else derive it
    iat_cov = (
        safe(flow.IatCoefficientOfVariation, iat_cv_derived)
        if flow.IatCoefficientOfVariation is not None
        else iat_cv_derived
    )
    exfil_z = safe(flow.ExfiltrationZScore, 0.0)

    vector = [
        safe(flow.FlowDuration), safe(flow.FlowBytesPerSec), safe(flow.FlowPktsPerSec),
        fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes,
        safe(flow.FwdPktLenMean), safe(flow.FwdPktLenMax), safe(flow.FwdPktLenMin),
        safe(flow.BwdPktLenMean), safe(flow.AvgPktSize),
        iat_mean, iat_std, safe(flow.IatMax), safe(flow.IatMin),
        safe(flow.FwdIatMean), safe(flow.BwdIatMean),
        safe(flow.SynCount), safe(flow.AckCount), safe(flow.RstCount),
        safe(flow.PshCount), safe(flow.FinCount), safe(flow.UrgCount),
        safe(flow.FwdHeaderLength), safe(flow.BwdHeaderLength),
        safe(flow.SubflowFwdPackets), safe(flow.SubflowBwdPackets),
        safe(flow.SubflowFwdBytes), safe(flow.SubflowBwdBytes),
        safe(flow.InitWinBytesFwd), safe(flow.InitWinBytesBwd),
        safe(flow.ActDataPktFwd), safe(flow.MinSegSizeFwd),
        iat_cov, exfil_z,
        byte_ratio, packet_ratio, iat_cv_derived,
        total_flags, dst_port_bin, protocol,
        is_high_port, is_well_known,
    ]

    return pd.DataFrame([vector], columns=FEATURE_NAMES)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": _pipeline is not None,
        "model_path": MODEL_PATH,
        "mode": "ML-only",
    }


@app.post("/predict")
def predict(flow: FlowEvent):
    """
    Main endpoint — pure ML prediction, no hard-coded rules.

    Returns:
      - ml_prediction: predicted class label + per-class probabilities
      - threat_score:  1 - P(BENIGN), range [0, 1]
      - recommended_action: human-readable next step
    """
    if _pipeline is None:
        return JSONResponse(
            status_code=503,
            content={"error": "Model not loaded. Run train_model.py and restart."},
        )

    try:
        features     = extract_features(flow)
        pred_class   = _pipeline.predict(features)[0]
        probas       = _pipeline.predict_proba(features)[0]
        classes      = list(_pipeline.classes_)
        proba_dict   = {cls: round(float(p), 4) for cls, p in zip(classes, probas)}
        benign_prob  = proba_dict.get("BENIGN", proba_dict.get("benign", 1.0))
        threat_score = round(1.0 - benign_prob, 4)
    except Exception as exc:
        logger.error(f"Inference error: {exc}")
        return JSONResponse(status_code=500, content={"error": str(exc)})

    # Recommended action driven purely by ML threat score
    if threat_score >= 0.9:
        action = "BLOCK — isolate host immediately and open incident."
    elif threat_score >= 0.6:
        action = "INVESTIGATE — capture full PCAP and escalate to analyst."
    elif threat_score >= 0.3:
        action = "MONITOR — tag process for enhanced logging."
    else:
        action = "ALLOW — flow appears benign."

    return JSONResponse(content={
        "flow_id": {
            "timestamp": flow.TimeStamp,
            "process":   flow.ProcessName,
            "pid":       flow.ProcessID,
            "src":       f"{flow.SrcIp}:{flow.SrcPort}",
            "dst":       f"{flow.DstIp}:{flow.DstPort}",
        },
        "ml_prediction": {
            "predicted_class": pred_class,
            "probabilities":   proba_dict,
        },
        "threat_score":       threat_score,
        "recommended_action": action,
    })


@app.post("/predict/batch")
def predict_batch(flows: list[FlowEvent]):
    """Batch endpoint — accepts a list of flow events."""
    return [predict(flow).body for flow in flows]
