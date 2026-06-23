from sklearn.ensemble import IsolationForest
import pandas as pd
import joblib

df = pd.read_csv("transactions.csv")

X = df[
    [
        "amount",
        "hour",
        "balance",
        "daily_sent",
        "daily_received",
        "hourly_tx_count",
        "recipient_count",
        "previous_alerts"
    ]
]

model = IsolationForest(
    contamination=0.03,
    random_state=42
)

model.fit(X)

joblib.dump(model, "aml_ai_model.pkl")