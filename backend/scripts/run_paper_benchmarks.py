"""Reproducible, read-only benchmarks for the Rakshak AI research paper.

Run from the repository root:

    python backend/scripts/run_paper_benchmarks.py

The benchmark imports only side-effect-free security and ML modules.  In
particular, it does not import ``main.py`` because that module initialises and
seeds the production SQLite database at import time.
"""

from __future__ import annotations

import csv
import logging
import io
import os
import statistics
import sys
import time
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("RAKSHAK_TESTING", "1")

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

import firebase_auth
import ml_engine
from security_utils import (
    MAX_FILE_SIZE_BYTES,
    encrypt_payload,
    generate_safe_filename,
    sanitize_text,
    validate_file_upload,
)

logging.getLogger("firebase_auth").setLevel(logging.CRITICAL)


SEED = 42
ATTEMPTS_PER_VECTOR = 100
CRYPTO_ITERATIONS = 1000


def _milliseconds(start_ns: int, end_ns: int) -> float:
    return (end_ns - start_ns) / 1_000_000


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    rank = (len(ordered) - 1) * percentile / 100
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = rank - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _markdown_table(headers: list[str], rows: list[list[object]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(str(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def _csv_table(headers: list[str], rows: list[list[object]]) -> str:
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(headers)
    writer.writerows(rows)
    return output.getvalue().rstrip()


def _timed_call(function, *args) -> tuple[object, float]:
    start = time.perf_counter_ns()
    result = function(*args)
    return result, _milliseconds(start, time.perf_counter_ns())


def _run_security_benchmark() -> tuple[list[str], list[list[object]]]:
    payloads = {
        "Stored XSS": [
            "<script>alert(1)</script>",
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>payload</svg>',
        ],
        "Path Traversal": [
            "../../etc/passwd",
            r"..\..\Windows\System32\config\SAM",
            "/var/www/../../secret.txt",
        ],
        "Disguised/Polyglot Upload": [
            ("invoice.php.jpg", "image/jpeg", b"<?php echo 'polyglot';"),
            ("update.exe", "application/octet-stream", b"MZ\x90\x00"),
            ("report.html", "image/png", b"<script>alert(1)</script>"),
        ],
        "Oversized Payload DoS": [
            ("evidence.png", "image/png"),
        ],
    }

    rows: list[list[object]] = []
    for vector, samples in payloads.items():
        latencies: list[float] = []
        blocked = 0
        for index in range(ATTEMPTS_PER_VECTOR):
            sample = samples[index % len(samples)]
            start = time.perf_counter_ns()
            if vector == "Stored XSS":
                sanitized = sanitize_text(sample)  # type: ignore[arg-type]
                mitigated = "<" not in sanitized and ">" not in sanitized
            elif vector == "Path Traversal":
                safe_name = generate_safe_filename(sample)  # type: ignore[arg-type]
                mitigated = (
                    ".." not in safe_name
                    and "/" not in safe_name
                    and "\\" not in safe_name
                )
            elif vector == "Disguised/Polyglot Upload":
                filename, mime, content = sample  # type: ignore[misc]
                accepted, _ = validate_file_upload(
                    filename, mime, len(content), content
                )
                mitigated = not accepted
            else:
                filename, mime = sample  # type: ignore[misc]
                accepted, _ = validate_file_upload(
                    filename, mime, MAX_FILE_SIZE_BYTES + 1
                )
                mitigated = not accepted
            latencies.append(_milliseconds(start, time.perf_counter_ns()))
            blocked += int(mitigated)

        rows.append([
            vector,
            ATTEMPTS_PER_VECTOR,
            blocked,
            f"{blocked / ATTEMPTS_PER_VECTOR * 100:.2f}",
            f"{statistics.mean(latencies):.4f}",
        ])

    forged_credentials = [
        HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=f"forged-token-{SEED}-{index}",
        )
        for index in range(ATTEMPTS_PER_VECTOR)
    ]
    auth_latencies: list[float] = []
    auth_blocked = 0
    verifier_stub = SimpleNamespace(
        verify_id_token=lambda token: (_ for _ in ()).throw(
            ValueError("synthetic forged token")
        ),
        ExpiredIdTokenError=type("ExpiredIdTokenError", (Exception,), {}),
        RevokedIdTokenError=type("RevokedIdTokenError", (Exception,), {}),
        InvalidIdTokenError=type("InvalidIdTokenError", (Exception,), {}),
        CertificateFetchError=type("CertificateFetchError", (Exception,), {}),
    )
    auth_module = firebase_auth.firebase_auth_module or verifier_stub
    with patch.object(firebase_auth, "_FIREBASE_AVAILABLE", True), patch.object(
        firebase_auth, "firebase_auth_module", auth_module
    ), patch.object(
        auth_module,
        "verify_id_token",
        side_effect=ValueError("synthetic forged token"),
    ):
        for credentials in forged_credentials:
            start = time.perf_counter_ns()
            try:
                firebase_auth.verify_firebase_token(credentials)
            except HTTPException as error:
                auth_blocked += int(error.status_code == 401)
            auth_latencies.append(_milliseconds(start, time.perf_counter_ns()))

    rows.append([
        "Unauthenticated/Forged JWT",
        ATTEMPTS_PER_VECTOR,
        auth_blocked,
        f"{auth_blocked / ATTEMPTS_PER_VECTOR * 100:.2f}",
        f"{statistics.mean(auth_latencies):.4f}",
    ])
    return (
        ["Attack vector", "Total attempts", "Blocked count", "Block rate (%)",
         "Mean validation latency (ms)"],
        rows,
    )


def _run_crypto_benchmark() -> tuple[list[str], list[list[object]]]:
    baseline_latencies: list[float] = []
    pipeline_latencies: list[float] = []

    for index in range(CRYPTO_ITERATIONS):
        text = f"synthetic complaint {SEED}-{index}: verify the reported message"

        start = time.perf_counter_ns()
        text.encode("utf-8")
        baseline_latencies.append(_milliseconds(start, time.perf_counter_ns()))

        start = time.perf_counter_ns()
        sanitized = sanitize_text(text)
        encrypt_payload(sanitized)
        generate_safe_filename(f"evidence-{index}.txt", prefix="RK")
        pipeline_latencies.append(_milliseconds(start, time.perf_counter_ns()))

    baseline_mean = statistics.mean(baseline_latencies)
    pipeline_mean = statistics.mean(pipeline_latencies)
    overhead_ms = pipeline_mean - baseline_mean
    overhead_percent = (overhead_ms / baseline_mean * 100) if baseline_mean else 0.0
    headers = [
        "Pipeline",
        "Iterations",
        "Mean latency (ms)",
        "P95 latency (ms)",
        "P99 latency (ms)",
        "Overhead (ms)",
        "Overhead (%)",
    ]
    rows = [
        [
            "Baseline text processing",
            CRYPTO_ITERATIONS,
            f"{baseline_mean:.4f}",
            f"{_percentile(baseline_latencies, 95):.4f}",
            f"{_percentile(baseline_latencies, 99):.4f}",
            "0.0000",
            "0.00",
        ],
        [
            "sanitize_text + production AES-256-GCM + SHA-256 filename",
            CRYPTO_ITERATIONS,
            f"{pipeline_mean:.4f}",
            f"{_percentile(pipeline_latencies, 95):.4f}",
            f"{_percentile(pipeline_latencies, 99):.4f}",
            f"{overhead_ms:.4f}",
            f"{overhead_percent:.2f}",
        ],
    ]
    return headers, rows


def _run_ml_benchmark() -> tuple[list[str], list[list[object]]]:
    variants = (
        "for the defence review",
        "before the next operational briefing",
        "through the authorised response channel",
        "during the incident triage window",
        "with the attached case reference",
    )
    corpus = {
        "Phishing": (
            "Urgent bank account verification requires your OTP",
            "Defence salary portal login will be disabled unless you verify now",
            "Reset your secure account password using this message link",
        ),
        "Suspicious Communication": (
            "Unknown caller repeatedly requested personal service details",
            "Suspicious message arrived from an unverified contact",
            "A strange communication asks for information without context",
        ),
        "Malware / APK Threat": (
            "Install the attached APK to open the classified update",
            "Download this executable archive to unlock the defence report",
            "Open the suspicious attachment to activate the secure application",
        ),
        "Honeytrap / Romance Manipulation": (
            "An online contact asked for a private meeting and my location",
            "A romance contact pressured me to send documents and money",
            "Someone I met online is building trust before requesting secrets",
        ),
        "Espionage / OPSEC Risk": (
            "Share classified unit movement details and deployment location",
            "An unknown person requested confidential regiment information",
            "Send the operational plan and restricted defence document",
        ),
        "Identity / Financial Fraud": (
            "A caller requested card details and a fee for a promised refund",
            "Transfer money now to secure the guaranteed investment return",
            "A lottery message asks for bank information to claim the prize",
        ),
        "Unknown / Needs Review": (
            "The team meeting is scheduled for tomorrow at nine in the morning",
            "Please call me when you are free to discuss the project report",
            "The routine status update was submitted to the faculty office",
        ),
    }
    labels = list(ml_engine.THREAT_LABELS)
    if set(corpus) != set(labels):
        raise RuntimeError("Benchmark corpus must cover every exact ML threat label")

    # Warm the lazy model cache so inference timings exclude model loading.
    ml_engine.predict_threat_ml("warm up the threat triage model")

    observations: list[tuple[str, str, float]] = []
    for expected, bases in corpus.items():
        for base in bases:
            for variant in variants:
                text = f"{base} {variant}."
                start = time.perf_counter_ns()
                result = ml_engine.predict_threat_ml(text)
                latency = _milliseconds(start, time.perf_counter_ns())
                observations.append((expected, result["label"], latency))

    if any(
        sum(expected == label for expected, _, _ in observations) != len(variants) * 3
        for label in labels
    ):
        raise RuntimeError("Benchmark corpus is not balanced")

    headers = [
        "Threat label",
        "Support",
        "Correct",
        "Precision",
        "Recall",
        "F1-score",
        "Mean inference latency (ms)",
    ]
    rows: list[list[object]] = []
    for label in labels:
        true_positive = sum(
            expected == label and predicted == label
            for expected, predicted, _ in observations
        )
        false_positive = sum(
            expected != label and predicted == label
            for expected, predicted, _ in observations
        )
        false_negative = sum(
            expected == label and predicted != label
            for expected, predicted, _ in observations
        )
        support = true_positive + false_negative
        precision = (
            true_positive / (true_positive + false_positive)
            if true_positive + false_positive
            else 0.0
        )
        recall = true_positive / support if support else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )
        latencies = [
            latency for expected, _, latency in observations if expected == label
        ]
        rows.append([
            label,
            support,
            true_positive,
            f"{precision:.4f}",
            f"{recall:.4f}",
            f"{f1:.4f}",
            f"{statistics.mean(latencies):.4f}",
        ])

    macro_precision = statistics.mean(float(row[3]) for row in rows)
    macro_recall = statistics.mean(float(row[4]) for row in rows)
    macro_f1 = statistics.mean(float(row[5]) for row in rows)
    total = len(observations)
    accuracy = sum(expected == predicted for expected, predicted, _ in observations) / total
    weighted_f1 = sum(
        int(row[1]) * float(row[5]) for row in rows
    ) / total
    rows.extend([
        [
            "Macro average",
            total,
            "",
            f"{macro_precision:.4f}",
            f"{macro_recall:.4f}",
            f"{macro_f1:.4f}",
            f"{statistics.mean(item[2] for item in observations):.4f}",
        ],
        [
            "Weighted F1 / accuracy",
            total,
            f"{accuracy:.4f}",
            "",
            "",
            f"{weighted_f1:.4f}",
            "",
        ],
    ])
    return headers, rows


def main() -> None:
    print("# Rakshak AI paper benchmarks")
    print(f"Seed: {SEED}; security attempts/vector: {ATTEMPTS_PER_VECTOR}; "
          f"crypto iterations: {CRYPTO_ITERATIONS}; ML samples/class: 15")
    print("Benchmark 2 uses security_utils.encrypt_payload().")

    benchmarks = [
        ("## Benchmark 1: Security Hardening & Attack Mitigation Matrix",
         _run_security_benchmark()),
        ("## Benchmark 2: Cryptographic & Sanitization Latency Overhead",
         _run_crypto_benchmark()),
        ("## Benchmark 3: Hybrid Threat Triage / ML Risk Scoring Evaluation",
         _run_ml_benchmark()),
    ]
    for title, (headers, rows) in benchmarks:
        print(f"\n{title}\n")
        print(_markdown_table(headers, rows))
        print("\nCSV:\n```csv")
        print(_csv_table(headers, rows))
        print("```")


if __name__ == "__main__":
    main()
