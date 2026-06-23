import os
from datetime import datetime

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


MODEL_PATH = os.path.join(os.path.dirname(__file__), "aml_ai_model.pkl")
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
    ]


def train_ai_model(transactions):
    labelled = [
        row for row in transactions
        if row["risk_level"] in LABELS
    ]
    labels = {row["risk_level"] for row in labelled}
    if len(labelled) < 30 or len(labels) < 2:
        return None

    x_train = [transaction_features(row) for row in labelled]
    y_train = [row["risk_level"] for row in labelled]
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=150,
            class_weight="balanced",
            random_state=42,
        )),
    ])
    model.fit(x_train, y_train)
    joblib.dump(model, MODEL_PATH)
    return model


def load_ai_model():
    if not os.path.exists(MODEL_PATH):
        return None
    return joblib.load(MODEL_PATH)


def predict_risk_level(transaction):
    model = load_ai_model()
    if model is None:
        return None, 0.0

    try:
        probabilities = model.predict_proba([transaction_features(transaction)])[0]
    except ValueError:
        delete_ai_model()
        return None, 0.0
    classes = list(model.classes_)
    best_index = int(probabilities.argmax())
    return classes[best_index], float(probabilities[best_index])


def delete_ai_model():
    if os.path.exists(MODEL_PATH):
        os.remove(MODEL_PATH)
