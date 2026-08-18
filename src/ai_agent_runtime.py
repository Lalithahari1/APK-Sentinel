"""APK Sentinel - DNN powered AI security agent.

This module bridges the existing APK Sentinel static analyzer to the user's
trained final DNN model. It deliberately keeps runtime/dynamic analysis
honest: the 161 dynamic feature slots remain zero unless a sandbox/runtime
collector is added later.
"""
from __future__ import annotations

import os
from pathlib import Path
from functools import lru_cache

import numpy as np
import pandas as pd

try:
    import tensorflow as tf
except Exception:
    tf = None

try:
    from sklearn.preprocessing import StandardScaler
except Exception:
    StandardScaler = None


PROJECT_ROOT = Path(__file__).resolve().parent

# The UI normally lives in <project>/app/*.py, while this module is copied
# into <project>/src/. These candidates make the integration tolerant of the
# user's current folder layout.
ROOT_CANDIDATES = [
    PROJECT_ROOT,
    PROJECT_ROOT.parent,
    PROJECT_ROOT.parent.parent,
]


def _first_existing(*paths: Path):
    for path in paths:
        if path.exists():
            return path
    return None


def _project_root() -> Path:
    for root in ROOT_CANDIDATES:
        if (root / "models").exists() or (root / "datasets").exists():
            return root
    return PROJECT_ROOT


ROOT = _project_root()
MODEL_PATH = _first_existing(
    ROOT / "models" / "final_dnn_model.keras",
    ROOT / "models" / "dnn_model.keras",
    PROJECT_ROOT / "models" / "final_dnn_model.keras",
)
TRAIN_PATH = _first_existing(
    ROOT / "datasets" / "X_final_train.csv",
    ROOT / "datasets" / "X_train.csv",
    PROJECT_ROOT / "datasets" / "X_final_train.csv",
    PROJECT_ROOT / "datasets" / "X_train.csv",
)
IMPORTANCE_PATH = _first_existing(
    ROOT / "results" / "dnn_feature_importance.csv",
    ROOT / "results" / "final_report" / "dnn_feature_importance.csv",
    PROJECT_ROOT / "results" / "dnn_feature_importance.csv",
)


@lru_cache(maxsize=1)
def load_dnn():
    if tf is None:
        raise RuntimeError("TensorFlow is not installed in the active environment.")
    if MODEL_PATH is None:
        raise FileNotFoundError("final_dnn_model.keras was not found.")
    return tf.keras.models.load_model(MODEL_PATH)


@lru_cache(maxsize=1)
def load_training_features():
    if TRAIN_PATH is None:
        raise FileNotFoundError("X_final_train.csv/X_train.csv was not found.")
    df = pd.read_csv(TRAIN_PATH)
    return list(df.columns), df.astype("float32")


@lru_cache(maxsize=1)
def load_scaler():
    """Reproduce the project's existing DNN preprocessing.

    The training scripts fit StandardScaler on X_final_train/X_train and then
    transform validation/test data. No persisted scaler was found in the
    supplied project artifacts, so inference mirrors that established workflow.
    """
    if StandardScaler is None:
        raise RuntimeError("scikit-learn is not installed.")
    _, train_df = load_training_features()
    scaler = StandardScaler()
    scaler.fit(train_df.values)
    return scaler


def _flatten_values(result: dict) -> list[str]:
    values: list[str] = []
    for key in (
        "permissions",
        "activities",
        "services",
        "receivers",
        "providers",
        "urls",
        "domains",
        "static_indicators",
    ):
        raw = result.get(key, []) or []
        if isinstance(raw, dict):
            raw = list(raw.values())
        if not isinstance(raw, (list, tuple, set)):
            raw = [raw]
        for item in raw:
            if isinstance(item, dict):
                for subkey in ("name", "permission", "signal", "value"):
                    if item.get(subkey):
                        values.append(str(item[subkey]))
            else:
                values.append(str(item))
    return values


def build_feature_vector(result: dict, manifest_text: str = "") -> tuple[pd.DataFrame, dict]:
    """Create the same ordered 340-column representation expected by DNN.

    Static evidence is mapped to matching feature names. Dynamic features are
    intentionally left at zero because the current application does not run
    the APK in a sandbox.
    """
    feature_names, _ = load_training_features()
    vector = pd.DataFrame(np.zeros((1, len(feature_names)), dtype=np.float32), columns=feature_names)

    observed = _flatten_values(result)
    observed_norm = {x.strip().lower() for x in observed if x.strip()}
    manifest_norm = (manifest_text or "").lower()

    matched = []
    dynamic_count = 0

    for feature in feature_names:
        if str(feature).startswith("dynamic_"):
            dynamic_count += 1
            continue

        f = str(feature).strip()
        fl = f.lower()
        is_match = fl in observed_norm

        # APK Sentinel's static feature vocabulary is mostly manifest/API/
        # permission indicators. A manifest substring match is intentionally
        # conservative for longer feature names.
        if not is_match and len(f) >= 6 and manifest_norm:
            is_match = fl in manifest_norm

        if is_match:
            vector.loc[0, feature] = 1.0
            matched.append(f)

    static_count = len([f for f in feature_names if not str(f).startswith("dynamic_")])
    active_static = int(vector[[f for f in feature_names if not str(f).startswith("dynamic_")]].sum(axis=1).iloc[0])

    info = {
        "total_features": len(feature_names),
        "static_features": static_count,
        "dynamic_features": dynamic_count,
        "active_static_features": active_static,
        "active_dynamic_features": 0,
        "active_features": int(vector.sum(axis=1).iloc[0]),
        "matched_features": matched,
    }
    return vector, info


def _top_importance(limit: int = 10):
    if IMPORTANCE_PATH is None:
        return []
    try:
        df = pd.read_csv(IMPORTANCE_PATH)
        if "Feature" not in df.columns:
            return []
        importance_col = next(
            (c for c in df.columns if c.lower() in {"importance", "score", "absolute_importance"}),
            None,
        )
        if importance_col is None:
            return df["Feature"].head(limit).astype(str).tolist()
        df = df.sort_values(importance_col, ascending=False)
        return df["Feature"].head(limit).astype(str).tolist()
    except Exception:
        return []


def run_dnn(result: dict, manifest_text: str = "") -> dict:
    """Run the trained DNN and return an AI-agent-ready assessment."""
    vector, feature_info = build_feature_vector(result, manifest_text)
    scaler = load_scaler()
    model = load_dnn()

    scaled = scaler.transform(vector.astype("float32").values).astype("float32")
    raw = np.asarray(model.predict(scaled, verbose=0)).reshape(-1)
    probability = float(raw[0])
    probability = max(0.0, min(1.0, probability))

    # The trained project uses binary sigmoid output; class 1 is treated as
    # the malware class for this project pipeline.
    verdict = "MALWARE" if probability >= 0.50 else "BENIGN"
    confidence = probability if verdict == "MALWARE" else 1.0 - probability

    active = set(feature_info["matched_features"])
    important = _top_importance(10)
    influential_active = [f for f in important if f in active]

    reasons = []
    risk_signals = result.get("risk_signal_details", []) or []
    if risk_signals:
        reasons.append(f"{len(risk_signals)} static security signal(s) were detected.")
    if result.get("permissions"):
        reasons.append(f"The APK declares {len(result.get('permissions') or [])} permission(s).")
    if result.get("services"):
        reasons.append(f"{len(result.get('services') or [])} Android service component(s) were found.")
    if result.get("receivers"):
        reasons.append(f"{len(result.get('receivers') or [])} broadcast receiver component(s) were found.")
    if result.get("domains"):
        reasons.append(f"{len(result.get('domains') or [])} network domain indicator(s) were extracted.")
    if influential_active:
        reasons.append("Some model-important static features are active in this APK.")
    if not reasons:
        reasons.append("No strong static evidence was surfaced by the analyzer.")

    if verdict == "MALWARE":
        recommendation = "Treat the APK as suspicious. Do not install it on a personal device; isolate it and perform deeper sandbox/runtime analysis."
    elif confidence >= 0.80:
        recommendation = "The DNN currently leans benign. Still verify the source, signature and distribution channel before installation."
    else:
        recommendation = "The DNN result is uncertain. Perform additional static review and, if available, controlled dynamic analysis."

    return {
        "model": "Final DNN",
        "model_path": str(MODEL_PATH) if MODEL_PATH else "",
        "probability_malware": round(probability, 6),
        "malware_probability_percent": round(probability * 100, 2),
        "verdict": verdict,
        "confidence_percent": round(confidence * 100, 2),
        "threshold": 0.50,
        "feature_info": feature_info,
        "top_model_features": important,
        "active_influential_features": influential_active,
        "reasons": reasons,
        "recommendation": recommendation,
        "dynamic_analysis_performed": False,
        "note": "The current deployed pipeline performs static APK analysis. Dynamic feature slots are retained for model compatibility but are not populated by runtime execution.",
    }


def generate_agent_summary(ai: dict, result: dict) -> str:
    verdict = ai.get("verdict", "UNKNOWN")
    p = ai.get("malware_probability_percent", 0)
    confidence = ai.get("confidence_percent", 0)
    lines = [
        f"APK Sentinel AI Security Agent",
        f"Model: {ai.get('model', 'Final DNN')}",
        f"Verdict: {verdict}",
        f"Malware probability: {p}%",
        f"Confidence: {confidence}%",
        "",
        "Why:",
    ]
    lines.extend(f"- {reason}" for reason in ai.get("reasons", []))
    lines += [
        "",
        f"Recommendation: {ai.get('recommendation', '')}",
        "",
        ai.get("note", ""),
    ]
    return "\n".join(lines)
