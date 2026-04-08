import pickle
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "model.pkl")
vectorizer_path = os.path.join(BASE_DIR, "vectorizer.pkl")
labels_path = os.path.join(BASE_DIR, "label_classes.pkl")

with open(model_path, "rb") as f:
    model = pickle.load(f)

with open(vectorizer_path, "rb") as f:
    vectorizer = pickle.load(f)

if os.path.exists(labels_path):
    with open(labels_path, "rb") as f:
        label_classes = pickle.load(f)
else:
    label_classes = ["safe", "phishing", "spam", "suspicious", "fraud", "malware"]


def normalize_label(label: str) -> str:
    label = (label or "safe").strip().lower()
    allowed = {"safe", "phishing", "spam", "suspicious", "fraud", "malware"}
    return label if label in allowed else "suspicious"


def predict_text(text: str) -> dict:
    if not text or not text.strip():
        return {
            "prediction": "safe",
            "confidence": 0.50,
            "all_scores": {"safe": 0.50}
        }

    X = vectorizer.transform([text])
    prediction = normalize_label(model.predict(X)[0])

    confidence = 0.75
    all_scores = {}

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)[0]
        classes = model.classes_

        for cls, prob in zip(classes, probabilities):
            all_scores[str(cls)] = round(float(prob), 4)

        confidence = float(max(probabilities))

    return {
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "all_scores": all_scores
    }