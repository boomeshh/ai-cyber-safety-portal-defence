"""
ml_engine.py — Hardened hybrid AI threat analysis engine for Rakshak AI.
Supports: controlled synthetic ratio training, before/after metric comparison,
safe auto-retrain, top-feature explanation, and confidence-calibrated merge logic.
Falls back safely to rule-based scoring at every failure point.
"""

import os
import json
import pickle
import sqlite3
import logging
from collections import Counter
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger("ml_engine")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODELS_DIR, exist_ok=True)

MODEL_PATH      = os.path.join(MODELS_DIR, "threat_model.pkl")
VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer.pkl")
META_PATH       = os.path.join(MODELS_DIR, "model_meta.json")

LEGACY_MODEL_PATH      = os.path.join(BASE_DIR, "model.pkl")
LEGACY_VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")

# ---------------------------------------------------------------------------
# Tunable constants
# ---------------------------------------------------------------------------
CONF_HIGH = 0.72
CONF_LOW  = 0.50

SYNTHETIC_TRAINING_ENABLED      = True
DEFAULT_SYNTHETIC_RATIO         = 0.30
MAX_SYNTHETIC_RATIO             = 0.50
AUTO_RETRAIN_ENABLED            = True
AUTO_RETRAIN_COMPLAINT_THRESHOLD  = 20
AUTO_RETRAIN_MAX_MODEL_AGE_HOURS  = 24

# ---------------------------------------------------------------------------
# Normalized threat label taxonomy
# ---------------------------------------------------------------------------
THREAT_LABELS = [
    "Phishing",
    "Suspicious Communication",
    "Malware / APK Threat",
    "Honeytrap / Romance Manipulation",
    "Espionage / OPSEC Risk",
    "Identity / Financial Fraud",
    "Unknown / Needs Review",
]

_RISK_ORDER = [
    "Espionage / OPSEC Risk",
    "Malware / APK Threat",
    "Phishing",
    "Honeytrap / Romance Manipulation",
    "Identity / Financial Fraud",
    "Suspicious Communication",
    "Unknown / Needs Review",
]

_LABEL_MAP = {
    "phishing":              "Phishing",
    "spam":                  "Identity / Financial Fraud",
    "fraud":                 "Identity / Financial Fraud",
    "malware":               "Malware / APK Threat",
    "suspicious":            "Suspicious Communication",
    "safe":                  "Unknown / Needs Review",
    "financial fraud":       "Identity / Financial Fraud",
    "honeytrap":             "Honeytrap / Romance Manipulation",
    "romance":               "Honeytrap / Romance Manipulation",
    "opsec":                 "Espionage / OPSEC Risk",
    "espionage":             "Espionage / OPSEC Risk",
    "defence impersonation": "Phishing",
    "apk":                   "Malware / APK Threat",
}


def normalize_threat_label(raw_label: str) -> str:
    if not raw_label:
        return "Unknown / Needs Review"
    lower = raw_label.strip().lower()
    for key, normalized in _LABEL_MAP.items():
        if key in lower:
            return normalized
    for label in THREAT_LABELS:
        if label.lower() == lower:
            return label
    return "Suspicious Communication"


def _risk_rank(label: str) -> int:
    try:
        return _RISK_ORDER.index(label)
    except ValueError:
        return len(_RISK_ORDER)


def _pick_safer_label(a: str, b: str) -> str:
    return a if _risk_rank(a) <= _risk_rank(b) else b

# ---------------------------------------------------------------------------
# Model cache (lazy-loaded, invalidated on retrain)
# ---------------------------------------------------------------------------
_model_cache: dict = {}


def _load_artifacts() -> dict:
    global _model_cache
    if _model_cache.get("loaded"):
        return _model_cache

    for m_path, v_path in [
        (MODEL_PATH, VECTORIZER_PATH),
        (LEGACY_MODEL_PATH, LEGACY_VECTORIZER_PATH),
    ]:
        if os.path.exists(m_path) and os.path.exists(v_path):
            try:
                with open(m_path, "rb") as f:
                    model = pickle.load(f)
                with open(v_path, "rb") as f:
                    vectorizer = pickle.load(f)
                _model_cache = {
                    "loaded": True, "model": model,
                    "vectorizer": vectorizer, "path": m_path,
                }
                logger.info(f"[ml_engine] Model loaded from {m_path}")
                return _model_cache
            except Exception as e:
                logger.warning(f"[ml_engine] Failed to load from {m_path}: {e}")

    _model_cache = {"loaded": False}
    return _model_cache


def _invalidate_cache():
    global _model_cache
    _model_cache = {}


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
DB_NAME = os.path.join(BASE_DIR, "complaints.db")


def load_real_training_samples(db_path: str = DB_NAME) -> tuple[list, list]:
    texts, labels = [], []
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT complaint_text, threat_type, corrected_label FROM complaints "
            "WHERE complaint_text IS NOT NULL AND complaint_text != ''"
        ).fetchall()
        conn.close()
        for row in rows:
            text = (row["complaint_text"] or "").strip()
            # Prefer corrected_label if available (admin feedback)
            raw = (row["corrected_label"] or row["threat_type"] or "").strip()
            if text and raw:
                texts.append(text)
                labels.append(normalize_threat_label(raw))
    except Exception as e:
        logger.error(f"[ml_engine] Real DB read error: {e}")
    return texts, labels


def load_synthetic_training_samples(db_path: str = DB_NAME) -> tuple[list, list]:
    texts, labels = [], []
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='synthetic_training_samples'"
        ).fetchall()]
        if not tables:
            conn.close()
            return [], []
        rows = conn.execute(
            "SELECT complaint_text, threat_label FROM synthetic_training_samples "
            "WHERE complaint_text IS NOT NULL AND complaint_text != ''"
        ).fetchall()
        conn.close()
        for row in rows:
            text = (row["complaint_text"] or "").strip()
            label = (row["threat_label"] or "").strip()
            if text and label:
                texts.append(text)
                labels.append(normalize_threat_label(label))
    except Exception as e:
        logger.error(f"[ml_engine] Synthetic DB read error: {e}")
    return texts, labels


def _count_complaints_since(trained_at_iso: Optional[str], db_path: str = DB_NAME) -> int:
    if not trained_at_iso:
        return 0
    try:
        conn = sqlite3.connect(db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM complaints WHERE created_at > ?",
            (trained_at_iso,)
        ).fetchone()[0]
        conn.close()
        return int(count or 0)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Seed data (always available even with empty DB)
# ---------------------------------------------------------------------------
_SEED_DATA = [
    ("Your bank account is blocked click this link and verify otp immediately", "Phishing"),
    ("Urgent update your kyc now to avoid account suspension", "Phishing"),
    ("Click here to reset your password now", "Phishing"),
    ("Your login session expired verify your bank details", "Phishing"),
    ("Army welfare payment pending verify your account immediately", "Phishing"),
    ("Defence salary portal needs urgent login verification", "Phishing"),
    ("Verify your account now or it will be permanently blocked", "Phishing"),
    ("You have won a cash reward click now", "Identity / Financial Fraud"),
    ("Free recharge offer available click and claim", "Identity / Financial Fraud"),
    ("Congratulations you are selected for lottery claim prize now", "Identity / Financial Fraud"),
    ("Transfer money now to secure your account", "Identity / Financial Fraud"),
    ("Your atm card will be deactivated pay processing fee now", "Identity / Financial Fraud"),
    ("Refund pending provide card number and cvv immediately", "Identity / Financial Fraud"),
    ("Investment plan available send amount now for guaranteed return", "Identity / Financial Fraud"),
    ("Send your bank details to receive the pending refund", "Identity / Financial Fraud"),
    ("Please send your regiment details and posting location", "Espionage / OPSEC Risk"),
    ("Can you share deployment movement details urgently", "Espionage / OPSEC Risk"),
    ("Send confidential unit information for verification", "Espionage / OPSEC Risk"),
    ("Classified document attached please review and confirm", "Espionage / OPSEC Risk"),
    ("Share your unit location and strength for the report", "Espionage / OPSEC Risk"),
    ("Let us continue this conversation on private video call", "Honeytrap / Romance Manipulation"),
    ("I am your online friend please trust me and send documents", "Honeytrap / Romance Manipulation"),
    ("She wants to meet you privately send your location", "Honeytrap / Romance Manipulation"),
    ("Romance scam victim sent money to online contact", "Honeytrap / Romance Manipulation"),
    ("My friend wants to meet you please share your number", "Honeytrap / Romance Manipulation"),
    ("Download this apk file to see secure defence message", "Malware / APK Threat"),
    ("Open attached zip file to view salary update", "Malware / APK Threat"),
    ("Install this app for secure military communication", "Malware / APK Threat"),
    ("Download executable file to unlock report", "Malware / APK Threat"),
    ("Attached file contains urgent classified update install now", "Malware / APK Threat"),
    ("Please install this apk to access your welfare benefits", "Malware / APK Threat"),
    ("Suspicious message received from unknown number", "Suspicious Communication"),
    ("Unknown caller asked for personal details", "Suspicious Communication"),
    ("Received strange link from unknown contact", "Suspicious Communication"),
    ("Someone is asking for my personal information repeatedly", "Suspicious Communication"),
    ("Meeting scheduled tomorrow at 5 pm please attend", "Unknown / Needs Review"),
    ("Project discussion completed successfully", "Unknown / Needs Review"),
    ("Please call me when you are free", "Unknown / Needs Review"),
    ("The report has been submitted to the faculty", "Unknown / Needs Review"),
    ("Class starts at 9 am tomorrow", "Unknown / Needs Review"),
]

# ---------------------------------------------------------------------------
# Controlled training dataset builder
# ---------------------------------------------------------------------------
def build_controlled_training_dataset(
    db_path: str = DB_NAME,
    use_synthetic: bool = True,
    synthetic_ratio_override: Optional[float] = None,
) -> tuple[list, list, dict]:
    """
    Build the final training dataset with a controlled synthetic ratio.
    Returns (texts, labels, stats_dict).
    """
    real_texts, real_labels = load_real_training_samples(db_path)

    # Merge seed data (deduplicate by text)
    seen: set = set(real_texts)
    for text, label in _SEED_DATA:
        if text not in seen:
            seen.add(text)
            real_texts.append(text)
            real_labels.append(normalize_threat_label(label))

    real_count = len(real_texts)

    syn_texts_used: list = []
    syn_labels_used: list = []
    synthetic_count = 0

    if use_synthetic and SYNTHETIC_TRAINING_ENABLED:
        ratio = synthetic_ratio_override if synthetic_ratio_override is not None else DEFAULT_SYNTHETIC_RATIO
        ratio = min(ratio, MAX_SYNTHETIC_RATIO)

        syn_texts_all, syn_labels_all = load_synthetic_training_samples(db_path)

        if syn_texts_all:
            # Cap synthetic contribution
            max_syn = int(real_count * ratio / (1.0 - ratio)) if ratio < 1.0 else len(syn_texts_all)
            max_syn = min(max_syn, len(syn_texts_all))

            # Stratified downsample if needed
            if len(syn_texts_all) > max_syn:
                paired = list(zip(syn_texts_all, syn_labels_all))
                # Shuffle deterministically for reproducibility
                import random as _rnd
                _rnd.seed(42)
                _rnd.shuffle(paired)
                paired = paired[:max_syn]
                syn_texts_used = [p[0] for p in paired]
                syn_labels_used = [p[1] for p in paired]
            else:
                syn_texts_used = syn_texts_all
                syn_labels_used = syn_labels_all

            synthetic_count = len(syn_texts_used)

    all_texts = real_texts + syn_texts_used
    all_labels = real_labels + syn_labels_used
    total = len(all_texts)
    actual_ratio = round(synthetic_count / total, 4) if total > 0 else 0.0

    stats = {
        "real_count": real_count,
        "synthetic_count": synthetic_count,
        "total": total,
        "actual_synthetic_ratio": actual_ratio,
    }
    return all_texts, all_labels, stats


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train_threat_model(
    db_path: str = DB_NAME,
    use_synthetic: bool = True,
    synthetic_ratio_override: Optional[float] = None,
    trigger_reason: str = "manual",
) -> dict:
    """
    Train LogisticRegression with controlled synthetic ratio.
    Saves artifacts + metadata. Returns full result dict including
    before/after metric comparison.
    """
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    except ImportError as e:
        return {"success": False, "error": f"scikit-learn not installed: {e}"}

    # Load previous metadata for comparison
    prev_meta = _load_meta_safe()
    prev_accuracy  = prev_meta.get("training_accuracy")
    prev_macro_f1  = prev_meta.get("macro_f1")

    # Build dataset
    all_texts, all_labels, ds_stats = build_controlled_training_dataset(
        db_path, use_synthetic, synthetic_ratio_override
    )
    total = ds_stats["total"]
    warnings_list: list = []

    if total < 10:
        warnings_list.append(f"Very small training set ({total} samples). Accuracy may be low.")

    # Class distribution + imbalance check
    dist = Counter(all_labels)
    logger.info(f"[ml_engine] Class distribution: {dict(dist)}")
    if dist:
        max_c = max(dist.values())
        min_c = min(dist.values())
        if max_c > 0 and (min_c / max_c) < 0.25:
            minority = [k for k, v in dist.items() if v == min_c]
            warnings_list.append(
                f"Class imbalance: minority={minority} ({min_c} vs {max_c} max). "
                "class_weight='balanced' applied."
            )

    try:
        vectorizer = TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            ngram_range=(1, 2),
            sublinear_tf=True,
            max_features=8000,
            min_df=1,
            max_df=0.95,
        )
        X = vectorizer.fit_transform(all_texts)

        model = LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
            solver="lbfgs",
        )

        training_accuracy = None
        macro_precision = macro_recall = macro_f1 = None

        if total >= 20:
            try:
                X_train, X_test, y_train, y_test = train_test_split(
                    X, all_labels, test_size=0.2, random_state=42
                )
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                training_accuracy = round(float(accuracy_score(y_test, y_pred)), 4)
                p, r, f, _ = precision_recall_fscore_support(
                    y_test, y_pred, average="macro", zero_division=0
                )
                macro_precision = round(float(p), 4)
                macro_recall    = round(float(r), 4)
                macro_f1        = round(float(f), 4)
                # Retrain on full data
                model.fit(X, all_labels)
            except Exception as split_err:
                logger.warning(f"[ml_engine] Split failed: {split_err}. Full-set training.")
                model.fit(X, all_labels)
        else:
            model.fit(X, all_labels)

        # Save artifacts — only replace if new model is not worse than previous
        _model_replaced = True
        if (
            training_accuracy is not None
            and prev_accuracy is not None
            and training_accuracy < prev_accuracy - 0.02  # allow 2% tolerance
        ):
            logger.warning(
                f"[ml_engine] New accuracy {training_accuracy:.4f} is worse than previous "
                f"{prev_accuracy:.4f}. Keeping existing model."
            )
            warnings_list.append(
                f"Model NOT replaced: new accuracy ({training_accuracy:.3f}) is worse than "
                f"previous ({prev_accuracy:.3f}). Existing model preserved."
            )
            _model_replaced = False
        else:
            with open(MODEL_PATH, "wb") as f:
                pickle.dump(model, f)
            with open(VECTORIZER_PATH, "wb") as f:
                pickle.dump(vectorizer, f)

        classes = sorted(set(all_labels))
        warning_str = " | ".join(warnings_list) if warnings_list else None

        # Before/after deltas
        accuracy_delta  = None
        macro_f1_delta  = None
        if training_accuracy is not None and prev_accuracy is not None:
            accuracy_delta = round(training_accuracy - prev_accuracy, 4)
        if macro_f1 is not None and prev_macro_f1 is not None:
            macro_f1_delta = round(macro_f1 - prev_macro_f1, 4)

        meta = {
            "algorithm":             "LogisticRegression",
            "classes":               classes,
            "trained_at":            datetime.now().isoformat(),
            "sample_count":          total,
            "real_sample_count":     ds_stats["real_count"],
            "synthetic_sample_count": ds_stats["synthetic_count"],
            "synthetic_ratio":       ds_stats["actual_synthetic_ratio"],
            "feature_count":         len(vectorizer.vocabulary_),
            "training_accuracy":     training_accuracy,
            "macro_precision":       macro_precision,
            "macro_recall":          macro_recall,
            "macro_f1":              macro_f1,
            "previous_accuracy":     prev_accuracy,
            "previous_macro_f1":     prev_macro_f1,
            "accuracy_delta":        accuracy_delta,
            "macro_f1_delta":        macro_f1_delta,
            "warning":               warning_str,
            "class_distribution":    dict(dist),
            "trigger_reason":        trigger_reason,
            "auto_retrain_enabled":  AUTO_RETRAIN_ENABLED,
            "model_replaced":        _model_replaced,
        }
        with open(META_PATH, "w") as f:
            json.dump(meta, f, indent=2)

        _invalidate_cache()
        logger.info(
            f"[ml_engine] Training complete. total={total} real={ds_stats['real_count']} "
            f"syn={ds_stats['synthetic_count']} acc={training_accuracy} f1={macro_f1}"
        )

        # Performance verdict
        if accuracy_delta is None:
            verdict = "baseline"
        elif accuracy_delta > 0.01:
            verdict = "improved"
        elif accuracy_delta < -0.01:
            verdict = "declined"
        else:
            verdict = "unchanged"

        return {
            "success":                True,
            "algorithm":              "LogisticRegression",
            "classes":                classes,
            "trained_at":             meta["trained_at"],
            "sample_count":           total,
            "real_sample_count":      ds_stats["real_count"],
            "synthetic_sample_count": ds_stats["synthetic_count"],
            "synthetic_ratio":        ds_stats["actual_synthetic_ratio"],
            "feature_count":          meta["feature_count"],
            "training_accuracy":      training_accuracy,
            "macro_precision":        macro_precision,
            "macro_recall":           macro_recall,
            "macro_f1":               macro_f1,
            "previous_accuracy":      prev_accuracy,
            "previous_macro_f1":      prev_macro_f1,
            "accuracy_delta":         accuracy_delta,
            "macro_f1_delta":         macro_f1_delta,
            "performance_verdict":    verdict,
            "warning":                warning_str,
            "trigger_reason":         trigger_reason,
        }

    except Exception as e:
        logger.error(f"[ml_engine] Training failed: {e}")
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------
def _load_meta_safe() -> dict:
    """Load model_meta.json safely. Returns {} on any failure."""
    try:
        if os.path.exists(META_PATH):
            with open(META_PATH) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def load_model_info() -> dict:
    """Return complete model metadata. Never crashes."""
    artifacts = _load_artifacts()
    model_exists = artifacts.get("loaded", False)
    meta = _load_meta_safe()

    base = {
        "model_exists":           model_exists,
        "algorithm":              meta.get("algorithm", "LogisticRegression"),
        "trained_at":             meta.get("trained_at"),
        "sample_count":           meta.get("sample_count"),
        "real_sample_count":      meta.get("real_sample_count"),
        "synthetic_sample_count": meta.get("synthetic_sample_count"),
        "synthetic_ratio":        meta.get("synthetic_ratio"),
        "feature_count":          meta.get("feature_count"),
        "classes":                meta.get("classes", THREAT_LABELS),
        "training_accuracy":      meta.get("training_accuracy"),
        "macro_precision":        meta.get("macro_precision"),
        "macro_recall":           meta.get("macro_recall"),
        "macro_f1":               meta.get("macro_f1"),
        "previous_accuracy":      meta.get("previous_accuracy"),
        "previous_macro_f1":      meta.get("previous_macro_f1"),
        "accuracy_delta":         meta.get("accuracy_delta"),
        "macro_f1_delta":         meta.get("macro_f1_delta"),
        "warning":                meta.get("warning"),
        "class_distribution":     meta.get("class_distribution", {}),
        "fallback_active":        not model_exists,
        "auto_retrain_enabled":   meta.get("auto_retrain_enabled", AUTO_RETRAIN_ENABLED),
        "last_trigger_reason":    meta.get("trigger_reason"),
    }

    # Add feedback count from DB
    try:
        conn = sqlite3.connect(DB_NAME)
        feedback_count = conn.execute(
            "SELECT COUNT(*) FROM complaints WHERE corrected_label IS NOT NULL AND corrected_label != ''"
        ).fetchone()[0]
        conn.close()
        base["feedback_count"] = int(feedback_count or 0)
    except Exception:
        base["feedback_count"] = 0

    if not meta and model_exists:
        base["warning"] = "Model loaded from legacy path. Re-train to generate metadata."
    elif not meta and not model_exists:
        base["warning"] = "No trained model found. Using rule-based fallback."

    return base

# ---------------------------------------------------------------------------
# Auto-retrain helpers
# ---------------------------------------------------------------------------
def should_auto_retrain(db_path: str = DB_NAME) -> tuple[bool, str]:
    """
    Returns (should_retrain: bool, reason: str).
    Checks complaint count threshold and model age.
    """
    if not AUTO_RETRAIN_ENABLED:
        return False, "auto_retrain_disabled"

    meta = _load_meta_safe()
    trained_at_iso = meta.get("trained_at")

    # Check complaint count since last training
    new_complaints = _count_complaints_since(trained_at_iso, db_path)
    if new_complaints >= AUTO_RETRAIN_COMPLAINT_THRESHOLD:
        return True, f"complaint_threshold_reached ({new_complaints} new complaints)"

    # Check model age
    if trained_at_iso:
        try:
            trained_dt = datetime.fromisoformat(trained_at_iso)
            age_hours = (datetime.now() - trained_dt).total_seconds() / 3600
            if age_hours >= AUTO_RETRAIN_MAX_MODEL_AGE_HOURS:
                return True, f"model_age_exceeded ({round(age_hours, 1)}h >= {AUTO_RETRAIN_MAX_MODEL_AGE_HOURS}h)"
        except Exception:
            pass
    else:
        # No model at all — retrain
        return True, "no_model_exists"

    return False, "no_retrain_needed"


def maybe_auto_retrain(db_path: str = DB_NAME) -> None:
    """
    Trigger auto-retrain if conditions are met.
    Called after complaint creation — never blocks the request.
    All failures are logged and swallowed.
    """
    try:
        should, reason = should_auto_retrain(db_path)
        if should:
            logger.info(f"[ml_engine] Auto-retrain triggered: {reason}")
            result = train_threat_model(
                db_path=db_path,
                use_synthetic=True,
                trigger_reason="auto",
            )
            if result.get("success"):
                logger.info(
                    f"[ml_engine] Auto-retrain complete. "
                    f"acc={result.get('training_accuracy')} f1={result.get('macro_f1')}"
                )
            else:
                logger.warning(f"[ml_engine] Auto-retrain failed: {result.get('error')}")
    except Exception as e:
        logger.error(f"[ml_engine] maybe_auto_retrain exception: {e}")


def get_retrain_status(db_path: str = DB_NAME) -> dict:
    """Return current auto-retrain status for the /ai/retrain-status endpoint."""
    meta = _load_meta_safe()
    trained_at_iso = meta.get("trained_at")
    new_complaints = _count_complaints_since(trained_at_iso, db_path)

    model_age_hours = None
    if trained_at_iso:
        try:
            trained_dt = datetime.fromisoformat(trained_at_iso)
            model_age_hours = round((datetime.now() - trained_dt).total_seconds() / 3600, 2)
        except Exception:
            pass

    should, reason = should_auto_retrain(db_path)

    return {
        "auto_retrain_enabled":        AUTO_RETRAIN_ENABLED,
        "model_age_hours":             model_age_hours,
        "complaints_since_last_train": new_complaints,
        "threshold":                   AUTO_RETRAIN_COMPLAINT_THRESHOLD,
        "max_model_age_hours":         AUTO_RETRAIN_MAX_MODEL_AGE_HOURS,
        "should_retrain_now":          should,
        "next_retrain_reason":         reason,
    }


# ---------------------------------------------------------------------------
# Top-feature explanation
# ---------------------------------------------------------------------------
def _get_top_features(vectorizer, model, text: str, raw_pred: str, top_n: int = 5) -> list:
    """Extract top TF-IDF × coefficient words for the predicted class. Safe."""
    try:
        import numpy as np
        X = vectorizer.transform([text])
        feature_names = vectorizer.get_feature_names_out()
        classes = list(model.classes_)

        # Find class index
        target = raw_pred
        if target not in classes:
            for c in classes:
                if normalize_threat_label(c) == normalize_threat_label(raw_pred):
                    target = c
                    break
            else:
                return []

        class_idx = classes.index(target)
        if hasattr(model, "coef_"):
            coef = model.coef_[class_idx] if model.coef_.ndim > 1 else model.coef_[0]
            tfidf_scores = X.toarray()[0]
            contributions = tfidf_scores * coef
            top_indices = contributions.argsort()[::-1][:top_n]
            return [
                feature_names[i]
                for i in top_indices
                if contributions[i] > 0 and tfidf_scores[i] > 0
            ][:top_n]
    except Exception as e:
        logger.debug(f"[ml_engine] Feature extraction failed: {e}")
    return []


# ---------------------------------------------------------------------------
# Prediction with confidence calibration
# ---------------------------------------------------------------------------
def predict_threat_ml(text: str) -> dict:
    """
    Run ML prediction with confidence calibration.
    Returns safe fallback dict on any failure.
    """
    if not text or not text.strip():
        return {
            "label": "Unknown / Needs Review", "confidence": 0.0,
            "available": False, "all_scores": {}, "top_features": [],
            "calibration_note": "Empty input — ML skipped.",
        }

    artifacts = _load_artifacts()
    if not artifacts.get("loaded"):
        return {
            "label": "Unknown / Needs Review", "confidence": 0.0,
            "available": False, "all_scores": {}, "top_features": [],
            "calibration_note": "Model not loaded — rule-based fallback active.",
        }

    try:
        model = artifacts["model"]
        vectorizer = artifacts["vectorizer"]
        X = vectorizer.transform([text])
        raw_pred = model.predict(X)[0]
        label = normalize_threat_label(str(raw_pred))

        confidence = 0.65
        all_scores: dict = {}
        calibration_note = ""

        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X)[0]
            classes = model.classes_
            for cls, prob in zip(classes, probs):
                all_scores[normalize_threat_label(str(cls))] = round(float(prob), 4)
            raw_conf = float(max(probs))

            if raw_conf < CONF_LOW:
                confidence = raw_conf * 0.8
                calibration_note = f"Low confidence ({round(raw_conf*100)}%) — influence reduced."
            elif raw_conf >= CONF_HIGH:
                confidence = min(raw_conf * 1.05, 0.99)
                calibration_note = f"High confidence ({round(raw_conf*100)}%) — boosted."
            else:
                confidence = raw_conf
                calibration_note = f"Moderate confidence ({round(raw_conf*100)}%)."
        else:
            calibration_note = "No predict_proba — using default confidence."

        top_features = _get_top_features(vectorizer, model, text, str(raw_pred))

        return {
            "label": label, "confidence": round(confidence, 4),
            "available": True, "all_scores": all_scores,
            "top_features": top_features, "calibration_note": calibration_note,
        }
    except Exception as e:
        logger.error(f"[ml_engine] Prediction error: {e}")
        return {
            "label": "Unknown / Needs Review", "confidence": 0.0,
            "available": False, "all_scores": {}, "top_features": [],
            "calibration_note": f"Prediction failed: {e}",
        }

# ---------------------------------------------------------------------------
# Hybrid decision merge
# ---------------------------------------------------------------------------
def merge_rule_and_ml_decision(
    rule_tags: set,
    rule_score: int,
    ml_label: str,
    ml_confidence: float,
    ml_available: bool,
    top_features: Optional[list] = None,
) -> dict:
    """
    Four-path merge with clear priority rules.
    Path 1: ML unavailable / confidence < CONF_LOW  → rule only
    Path 2: confidence >= CONF_HIGH + agree          → ML dominant, boost
    Path 3: confidence >= CONF_HIGH + disagree       → safer label, explain
    Path 4: CONF_LOW <= confidence < CONF_HIGH       → weighted blend
    """
    rule_label = _dominant_rule_label(rule_tags)
    features_str = (
        f" Key signals: {', '.join(top_features[:4])}." if top_features else ""
    )

    if not ml_available or ml_confidence < CONF_LOW:
        return {
            "final_label": rule_label,
            "final_score": rule_score,
            "ai_confidence": max(40, min(72, rule_score)),
            "merge_note": (
                "Rule-based engine used exclusively "
                f"({'ML unavailable' if not ml_available else f'ML confidence {round(ml_confidence*100)}% below threshold'})."
            ),
            "decision_path": "rule_only",
        }

    labels_agree = (
        ml_label == rule_label
        or ml_label in rule_label
        or rule_label in ml_label
    )

    if ml_confidence >= CONF_HIGH and labels_agree:
        boost = int(ml_confidence * 18)
        return {
            "final_label": ml_label,
            "final_score": min(rule_score + boost, 100),
            "ai_confidence": min(int(ml_confidence * 100) + 6, 99),
            "merge_note": (
                f"Rule engine and ML agree on '{ml_label}' "
                f"(ML {round(ml_confidence*100)}%).{features_str} Confidence boosted."
            ),
            "decision_path": "ml_dominant_agree",
        }

    if ml_confidence >= CONF_HIGH and not labels_agree:
        safer = _pick_safer_label(rule_label, ml_label)
        return {
            "final_label": safer,
            "final_score": min(rule_score + 10, 100),
            "ai_confidence": max(52, int(ml_confidence * 82)),
            "merge_note": (
                f"Conflict: rule→'{rule_label}', ML→'{ml_label}' "
                f"({round(ml_confidence*100)}%).{features_str} "
                f"Using higher-risk: '{safer}'."
            ),
            "decision_path": "conflict_safer_label",
        }

    # Blended
    ml_weight = (ml_confidence - CONF_LOW) / (CONF_HIGH - CONF_LOW)
    rule_weight = 1.0 - ml_weight
    blended = int(rule_score * rule_weight + (rule_score + int(ml_confidence * 20)) * ml_weight)
    ai_conf = int(rule_score * 0.45 + ml_confidence * 100 * 0.55)
    return {
        "final_label": ml_label if ml_weight >= 0.5 else rule_label,
        "final_score": min(blended, 100),
        "ai_confidence": max(42, min(94, ai_conf)),
        "merge_note": (
            f"Blended (ML {round(ml_weight*100)}%, rule {round(rule_weight*100)}%).{features_str} "
            f"ML:'{ml_label}', Rule:'{rule_label}'."
        ),
        "decision_path": "blended",
    }


def _dominant_rule_label(tags: set) -> str:
    priority = [
        ("OPSEC",                "Espionage / OPSEC Risk"),
        ("Espionage",            "Espionage / OPSEC Risk"),
        ("Malware",              "Malware / APK Threat"),
        ("Honeytrap",            "Honeytrap / Romance Manipulation"),
        ("Phishing",             "Phishing"),
        ("Financial Fraud",      "Identity / Financial Fraud"),
        ("Defence Impersonation","Phishing"),
        ("Suspicious Communication", "Suspicious Communication"),
    ]
    for fragment, label in priority:
        for tag in tags:
            if fragment.lower() in tag.lower():
                return label
    return "Suspicious Communication"


# ---------------------------------------------------------------------------
# Full hybrid analysis (called from main.py)
# ---------------------------------------------------------------------------
def hybrid_analyze_complaint(
    complaint_text: str,
    suspicious_url: str = "",
    evidence_name: str = "",
    rule_result: Optional[dict] = None,
) -> dict:
    """
    Full hybrid analysis pipeline. Never raises.
    Compatible with the existing build_hybrid_result() contract.
    """
    if rule_result is None:
        logger.warning("[ml_engine] hybrid_analyze_complaint called without rule_result.")
        rule_result = {
            "rule_score": 30,
            "indicators": ["Rule engine not invoked"],
            "risk_notes": ["Hybrid engine used ML only."],
            "tags": {"Suspicious Communication"},
        }

    rule_score: int = int(rule_result.get("rule_score") or 30)
    rule_tags: set  = rule_result.get("tags") or {"Suspicious Communication"}
    indicators: list = list(rule_result.get("indicators") or [])
    risk_notes: list = list(rule_result.get("risk_notes") or [])

    try:
        ml = predict_threat_ml(complaint_text)
    except Exception as e:
        logger.error(f"[ml_engine] predict_threat_ml raised: {e}")
        ml = {
            "label": "Unknown / Needs Review", "confidence": 0.0,
            "available": False, "all_scores": {}, "top_features": [],
            "calibration_note": f"Exception: {e}",
        }

    ml_label      = ml.get("label", "Unknown / Needs Review")
    ml_confidence = float(ml.get("confidence") or 0.0)
    ml_available  = bool(ml.get("available", False))
    top_features  = ml.get("top_features") or []
    calib_note    = ml.get("calibration_note", "")

    try:
        merge = merge_rule_and_ml_decision(
            rule_tags, rule_score, ml_label, ml_confidence, ml_available, top_features
        )
    except Exception as e:
        logger.error(f"[ml_engine] merge failed: {e}")
        merge = {
            "final_label": _dominant_rule_label(rule_tags),
            "final_score": rule_score,
            "ai_confidence": max(40, min(72, rule_score)),
            "merge_note": f"Merge error — rule fallback: {e}",
            "decision_path": "error_fallback",
        }

    final_score   = int(merge["final_score"])
    final_label   = merge["final_label"]
    ai_confidence = int(merge["ai_confidence"])
    merge_note    = merge["merge_note"]
    decision_path = merge.get("decision_path", "unknown")

    if ml_available:
        indicators.append(f"ML predicted: {ml_label} ({round(ml_confidence*100)}% confidence)")
        if top_features:
            indicators.append(f"Key text signals: {', '.join(top_features[:4])}")
        if ml_confidence >= 0.85:
            indicators.append("Very high-confidence ML alert")
        elif ml_confidence >= CONF_HIGH:
            indicators.append("High-confidence ML alert")
        if calib_note:
            indicators.append(f"Calibration: {calib_note}")
    else:
        indicators.append(f"ML unavailable — rule fallback. {calib_note}".strip())

    if final_score >= 81:
        level = "Critical"
        mitigation = (
            "Do not interact further. Disconnect affected device, preserve evidence, "
            "reset credentials, and escalate to CERT immediately."
        )
        status = "Escalated"
    elif final_score >= 61:
        level = "High"
        mitigation = (
            "Avoid clicking links or opening files. Verify through trusted official "
            "channels and change credentials if already exposed."
        )
        status = "Under Review"
    elif final_score >= 31:
        level = "Medium"
        mitigation = "Proceed cautiously. Preserve screenshots/files and verify the sender."
        status = "Open"
    else:
        level = "Low"
        mitigation = "Monitor the issue and verify authenticity through official channels."
        status = "Open"

    rule_label_str = _dominant_rule_label(rule_tags)
    ai_reason  = "Detected Indicators:\n"
    ai_reason += "\n".join(f"• {item}" for item in indicators[:8])
    ai_reason += "\n\nRisk Explanation:\n" + " ".join(risk_notes[:3])
    ai_reason += "\n\nHybrid Engine Analysis:\n"
    ai_reason += f"• Rule-based: {rule_label_str}\n"
    ai_reason += f"• ML predicted: {ml_label}\n"
    ai_reason += f"• Decision path: {decision_path}\n"
    ai_reason += f"• {merge_note}\n"
    ai_reason += f"• AI Confidence: {ai_confidence}%"
    if top_features:
        ai_reason += f"\n• Top signals: {', '.join(top_features[:5])}"

    return {
        "score":             final_score,
        "level":             level,
        "reason":            ai_reason,
        "mitigation":        mitigation,
        "threat_type":       final_label,
        "rule_based_type":   rule_label_str,
        "ml_predicted_type": ml_label,
        "confidence":        ai_confidence,
        "status":            status,
        "indicators":        indicators,
        "ml_prediction":     ml_label,
        "ml_confidence_raw": round(ml_confidence, 4),
        "model_used": (
            "TF-IDF + LogisticRegression (Hybrid)" if ml_available else "Rule-Based Fallback"
        ),
        "top_features":  top_features,
        "decision_path": decision_path,
    }
