import joblib

model = joblib.load("aml_ai_model.pkl")

def detect_anomaly(features):
    prediction = model.predict([features])

    if prediction[0] == -1:
        return True

    return False