from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os

data = [
    ("Your bank account is blocked click this link and verify otp immediately", "phishing"),
    ("Urgent update your kyc now to avoid account suspension", "phishing"),
    ("Click here to reset your password now", "phishing"),
    ("Your login session expired verify your bank details", "phishing"),
    ("Army welfare payment pending verify your account immediately", "phishing"),
    ("Defence salary portal needs urgent login verification", "phishing"),

    ("You have won a cash reward click now", "spam"),
    ("Free recharge offer available click and claim", "spam"),
    ("Congratulations you are selected for lottery claim prize now", "spam"),
    ("Limited offer buy now and get bonus reward", "spam"),

    ("Please send your regiment details and posting location", "suspicious"),
    ("Can you share deployment movement details urgently", "suspicious"),
    ("Send confidential unit information for verification", "suspicious"),
    ("Let us continue this conversation on private video call", "suspicious"),
    ("I am your online friend please trust me and send documents", "suspicious"),

    ("Transfer money now to secure your account", "fraud"),
    ("Your atm card will be deactivated pay processing fee now", "fraud"),
    ("Update bank details and send otp to avoid penalty", "fraud"),
    ("Refund pending provide card number and cvv immediately", "fraud"),
    ("Investment plan available send amount now for guaranteed return", "fraud"),

    ("Download this apk file to see secure defence message", "malware"),
    ("Open attached zip file to view salary update", "malware"),
    ("Install this app for secure military communication", "malware"),
    ("Download executable file to unlock report", "malware"),
    ("Attached file contains urgent classified update install now", "malware"),

    ("Meeting scheduled tomorrow at 5 pm please attend", "safe"),
    ("Project discussion completed successfully", "safe"),
    ("Please call me when you are free", "safe"),
    ("Lunch plan for today let me know", "safe"),
    ("The report has been submitted to the faculty", "safe"),
    ("Class starts at 9 am tomorrow", "safe"),
    ("We will meet in the lab after lunch", "safe"),
    ("Your assignment is approved and uploaded", "safe"),
    ("Family function is planned this weekend", "safe"),
    ("Please bring the documents for verification at office", "safe"),
]

texts = [item[0] for item in data]
labels = [item[1] for item in data]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "model.pkl")
vectorizer_path = os.path.join(BASE_DIR, "vectorizer.pkl")
labels_path = os.path.join(BASE_DIR, "label_classes.pkl")

X_train, X_test, y_train, y_test = train_test_split(
    texts,
    labels,
    test_size=0.25,
    random_state=42,
    stratify=labels
)

vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    ngram_range=(1, 2),
    min_df=1,
    max_df=0.95
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

model = LogisticRegression(
    max_iter=2000,
    class_weight="balanced",
    random_state=42
)

model.fit(X_train_vec, y_train)

y_pred = model.predict(X_test_vec)
accuracy = accuracy_score(y_test, y_pred)

print("\nModel Training Completed")
print(f"Accuracy: {accuracy:.4f}")
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred, zero_division=0))

with open(model_path, "wb") as f:
    pickle.dump(model, f)

with open(vectorizer_path, "wb") as f:
    pickle.dump(vectorizer, f)

with open(labels_path, "wb") as f:
    pickle.dump(sorted(list(set(labels))), f)

print("\nSaved successfully:")
print(model_path)
print(vectorizer_path)
print(labels_path)