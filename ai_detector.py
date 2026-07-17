"""
ai_detector.py — Bank-Grade AML Machine Learning Engine
==========================================================
Hybrid supervised + unsupervised detection aligned with modern bank AML:
  • RandomForest classifier for typology-based risk (supervised)
  • Isolation Forest for behavioral anomaly detection (unsupervised)
  • Synthetic bootstrap dataset for cold-start training
  • Model versioning, cross-validation metrics, and governance metadata
  
NOTE: This module maintains backward compatibility with the existing system.
For advanced features, use the new aml_system.py module which includes:
  - XGBoost/LightGBM ensemble models
  - SMOTE class imbalance handling
  - 50+ comprehensive features
  - SHAP explainability
  - Fraud pattern detection
  - Model versioning registry
  - Continuous learning
"""

import json
import os
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


MODEL_PATH = os.path.join(os.path.dirname(__file__), "aml_ai_model.pkl")
METADATA_PATH = os.path.join(os.path.dirname(__file__), "aml_ai_model_meta.json")
MODEL_VERSION = "2.0.0"
LABELS = ("normal", "suspicious", "super_suspicious")

PROFILE_FEATURE_DEFAULTS = {
    "sender_avg_amount": 0.0,
    "sender_max_amount": 0.0,
    "sender_tx_count": 0.0,
    "amount_to_sender_avg": 1.0,
    "amount_to_sender_max": 1.0,
    "sender_tx_count_24h": 0.0,
    "sender_volume_24h": 0.0,
    "amount_to_sender_volume_24h": 1.0,
    "is_new_recipient": 0.0,
}

CHANNEL_ENCODING = {
    "online": 0, "mobile": 1, "atm": 2, "branch": 3,
    "card": 4, "ach": 5, "wire": 6, "swift": 7,
}

# Synthetic bootstrap: representative bank AML typologies for cold-start
_BOOTSTRAP = [
    {"amount": 45, "hour": 10, "transaction_type": "deposit", "sender_account": "A", "receiver_account": "A",
     "sender_avg_amount": 200, "sender_max_amount": 500, "sender_tx_count": 15, "risk_level": "normal"},
    {"amount": 120, "hour": 14, "transaction_type": "transfer", "sender_account": "B", "receiver_account": "C",
     "sender_avg_amount": 150, "sender_max_amount": 400, "sender_tx_count": 8, "risk_level": "normal"},
    {"amount": 350, "hour": 11, "transaction_type": "withdraw", "sender_account": "D", "receiver_account": "D",
     "sender_avg_amount": 300, "sender_max_amount": 800, "sender_tx_count": 20, "risk_level": "normal"},
    {"amount": 9500, "hour": 14, "transaction_type": "deposit", "sender_account": "E", "receiver_account": "E",
     "sender_avg_amount": 500, "sender_max_amount": 2000, "sender_tx_count": 3, "is_new_recipient": 1.0,
     "risk_level": "suspicious"},
    {"amount": 9800, "hour": 15, "transaction_type": "deposit", "sender_account": "F", "receiver_account": "F",
     "sender_avg_amount": 800, "sender_max_amount": 3000, "sender_tx_count": 5, "risk_level": "suspicious"},
    {"amount": 5500, "hour": 2, "transaction_type": "transfer", "sender_account": "G", "receiver_account": "H",
     "sender_avg_amount": 200, "sender_max_amount": 500, "sender_tx_count": 2, "is_new_recipient": 1.0,
     "sender_tx_count_24h": 4, "sender_volume_24h": 12000, "risk_level": "suspicious"},
    {"amount": 15000, "hour": 3, "transaction_type": "transfer", "sender_account": "I", "receiver_account": "J",
     "sender_avg_amount": 300, "sender_max_amount": 1000, "sender_tx_count": 1, "is_new_recipient": 1.0,
     "risk_level": "super_suspicious"},
    {"amount": 25000, "hour": 1, "transaction_type": "withdraw", "sender_account": "K", "receiver_account": "K",
     "sender_avg_amount": 50000, "sender_max_amount": 80000, "sender_tx_count": 50,
     "sender_tx_count_24h": 8, "sender_volume_24h": 95000, "risk_level": "super_suspicious"},
    {"amount": 12000, "hour": 14, "transaction_type": "deposit", "sender_account": "L", "receiver_account": "L",
     "sender_avg_amount": 400, "sender_max_amount": 1500, "sender_tx_count": 4, "risk_level": "super_suspicious"},
    {"amount": 500, "hour": 2, "transaction_type": "transfer", "sender_account": "M", "receiver_account": "N",
     "sender_avg_amount": 100, "sender_max_amount": 300, "sender_tx_count": 12, "sender_tx_count_24h": 6,
     "sender_volume_24h": 4500, "is_new_recipient": 1.0, "risk_level": "suspicious"},
]


def map_risk_to_ai_label(risk_level: str, risk_score: float = 0) -> str:
    """Map rule-engine risk levels to AI training labels."""
    level = (risk_level or "normal").lower()
    if level in ("normal", "low") and risk_score < 25:
        return "normal"
    if level in ("high_risk", "critical", "super_suspicious") or risk_score >= 60:
        return "super_suspicious"
    if level in ("suspicious", "medium") or risk_score >= 25:
        return "suspicious"
    return "normal"


def _timestamp_hour(timestamp):
    try:
        return datetime.fromisoformat(str(timestamp)).hour
    except (TypeError, ValueError):
        return 12


def _value(transaction, key, default=None):
    try:
        if hasattr(transaction, "get"):
            return transaction.get(key, default)
        return transaction[key]
    except (KeyError, TypeError):
        return default


def transaction_features(transaction):
    tx_type = _value(transaction, "transaction_type", "")
    sender = _value(transaction, "sender_account", "")
    receiver = _value(transaction, "receiver_account", "")
    timestamp = _value(transaction, "timestamp", "")
    channel = (_value(transaction, "channel", "online") or "online").lower()
    amount = float(_value(transaction, "amount", 0))
    hour = _timestamp_hour(timestamp)

    return [
        amount,
        hour,
        1 if tx_type == "deposit" else 0,
        1 if tx_type == "withdraw" else 0,
        1 if tx_type == "transfer" else 0,
        1 if sender == receiver else 0,
        1 if hour < 5 or hour >= 23 else 0,
        float(_value(transaction, "sender_avg_amount", PROFILE_FEATURE_DEFAULTS["sender_avg_amount"]) or 0),
        float(_value(transaction, "sender_max_amount", PROFILE_FEATURE_DEFAULTS["sender_max_amount"]) or 0),
        float(_value(transaction, "sender_tx_count", PROFILE_FEATURE_DEFAULTS["sender_tx_count"]) or 0),
        float(_value(transaction, "amount_to_sender_avg", PROFILE_FEATURE_DEFAULTS["amount_to_sender_avg"]) or 0),
        float(_value(transaction, "amount_to_sender_max", PROFILE_FEATURE_DEFAULTS["amount_to_sender_max"]) or 0),
        float(_value(transaction, "sender_tx_count_24h", PROFILE_FEATURE_DEFAULTS["sender_tx_count_24h"]) or 0),
        float(_value(transaction, "sender_volume_24h", PROFILE_FEATURE_DEFAULTS["sender_volume_24h"]) or 0),
        float(_value(transaction, "amount_to_sender_volume_24h", PROFILE_FEATURE_DEFAULTS["amount_to_sender_volume_24h"]) or 0),
        float(_value(transaction, "is_new_recipient", PROFILE_FEATURE_DEFAULTS["is_new_recipient"]) or 0),
        float(CHANNEL_ENCODING.get(channel, 0)),
        1 if amount >= 10000 else 0,
        1 if 8500 <= amount <= 9999 else 0,
    ]


def _prepare_labelled_rows(transactions):
    labelled = []
    for row in transactions:
        risk_level = row.get("risk_level") if hasattr(row, "get") else row["risk_level"]
        risk_score = float(row.get("risk_score", 0) if hasattr(row, "get") else row.get("risk_score", 0))
        ai_label = map_risk_to_ai_label(risk_level, risk_score)
        if ai_label in LABELS:
            item = dict(row) if hasattr(row, "keys") else row
            item["ai_training_label"] = ai_label
            labelled.append(item)
    return labelled


def _augment_with_bootstrap(labelled):
    if len(labelled) >= 30:
        return labelled
    combined = list(_BOOTSTRAP) + labelled
    for row in combined:
        if "ai_training_label" not in row:
            row["ai_training_label"] = row.get("risk_level", "normal")
    return combined


def train_ai_model(transactions):
    labelled = _prepare_labelled_rows(transactions)
    labels_set = {row["ai_training_label"] for row in labelled}

    if len(labelled) < 10 or len(labels_set) < 2:
        labelled = _augment_with_bootstrap(labelled)
        labels_set = {row["ai_training_label"] for row in labelled}

    if len(labelled) < 10 or len(labels_set) < 2:
        return None

    x_train = np.array([transaction_features(row) for row in labelled])
    y_train = [row["ai_training_label"] for row in labelled]

    classifier = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            min_samples_leaf=3,
            class_weight="balanced_subsample",
            random_state=42,
        )),
    ])
    classifier.fit(x_train, y_train)

    anomaly = IsolationForest(
        n_estimators=150,
        contamination=0.08,
        random_state=42,
    )
    anomaly.fit(x_train)

    cv_score = None
    if len(set(y_train)) >= 2 and len(y_train) >= 20:
        try:
            scores = cross_val_score(classifier, x_train, y_train, cv=min(5, len(y_train) // 5), scoring="f1_weighted")
            cv_score = float(np.mean(scores))
        except Exception:
            cv_score = None

    bundle = {
        "classifier": classifier,
        "anomaly_detector": anomaly,
        "version": MODEL_VERSION,
        "feature_count": x_train.shape[1],
        "classes": list(classifier.classes_),
    }
    joblib.dump(bundle, MODEL_PATH)

    metadata = {
        "version": MODEL_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_samples": len(labelled),
        "label_distribution": {label: y_train.count(label) for label in LABELS},
        "cross_val_f1_weighted": cv_score,
        "feature_count": x_train.shape[1],
        "algorithm": "RandomForest + IsolationForest ensemble",
    }
    with open(METADATA_PATH, "w", encoding="utf-8") as fh:
        json.dump(metadata, fh, indent=2)

    return bundle


def load_ai_model():
    if not os.path.exists(MODEL_PATH):
        return None
    bundle = joblib.load(MODEL_PATH)
    if isinstance(bundle, Pipeline):
        return {"classifier": bundle, "anomaly_detector": None, "version": "1.0.0"}
    return bundle


def get_model_metadata():
    if os.path.exists(METADATA_PATH):
        with open(METADATA_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    bundle = load_ai_model()
    if bundle is None:
        return {"trained": False, "version": MODEL_VERSION}
    return {
        "trained": True,
        "version": bundle.get("version", "1.0.0"),
        "algorithm": "RandomForest + IsolationForest ensemble",
    }


def predict_risk_level(transaction):
    bundle = load_ai_model()
    if bundle is None:
        return None, 0.0, None

    classifier = bundle.get("classifier")
    anomaly = bundle.get("anomaly_detector")
    features = transaction_features(transaction)

    try:
        probabilities = classifier.predict_proba([features])[0]
    except ValueError:
        delete_ai_model()
        return None, 0.0, None

    classes = list(classifier.classes_)
    best_index = int(probabilities.argmax())
    predicted = classes[best_index]
    confidence = float(probabilities[best_index])

    anomaly_score = None
    if anomaly is not None:
        try:
            raw = anomaly.decision_function([features])[0]
            anomaly_score = float(raw)
            if raw < -0.05 and predicted == "normal":
                predicted = "suspicious"
                confidence = max(confidence, 0.62)
            elif raw < -0.15:
                if predicted != "super_suspicious":
                    predicted = "super_suspicious" if confidence < 0.70 else predicted
                confidence = max(confidence, 0.72)
        except Exception:
            pass

    return predicted, confidence, anomaly_score


def delete_ai_model():
    for path in (MODEL_PATH, METADATA_PATH):
        if os.path.exists(path):
            os.remove(path)
