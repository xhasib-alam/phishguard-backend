"""
Train the PhishGuard Random Forest phishing detector.

The script loads dataset/urls.csv, extracts URL features, trains a model, and
saves it to models/model.pkl.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split


BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset" / "urls.csv"
MODEL_PATH = BASE_DIR / "models" / "model.pkl"

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "update",
    "bank",
    "secure",
    "free",
    "reward",
    "bonus",
    "gift",
    "claim",
    "payment",
    "invoice",
    "billing",
    "crypto",
    "offer",
    "account",
    "wallet",
    "otp",
    "password",
    "confirm",
    "details",
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd", "cutt.ly"}
TRUSTED_BRANDS = ["google", "apple", "amazon", "paypal", "microsoft", "facebook", "netflix", "instagram", "whatsapp", "linkedin"]
COMMON_SECOND_LEVEL_TLDS = {"co", "com", "net", "org", "gov", "edu", "ac"}
RISKY_TLDS = {"xyz", "top", "click", "ru", "tk", "zip", "mov", "gq", "cf", "work", "quest"}


def normalize_url(url: str) -> str:
    value = url.strip()
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    return value


def registered_domain(domain: str) -> str:
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    if labels[-2] in COMMON_SECOND_LEVEL_TLDS and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def brand_spoofed(domain: str) -> int:
    registered = registered_domain(domain)
    registered_brand = registered.split(".")[0]
    for brand in TRUSTED_BRANDS:
        if brand not in domain:
            continue
        if registered_brand == brand:
            return 0
        return 1
    return 0


def entropy(value: str) -> float:
    if not value:
        return 0.0
    from math import log2

    probabilities = [value.count(char) / len(value) for char in set(value)]
    return -sum(probability * log2(probability) for probability in probabilities)


def subdomain_count(domain: str) -> int:
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", domain):
        return 0
    registered = registered_domain(domain)
    if domain == registered:
        return 0
    return max(0, len(domain.removesuffix("." + registered).split(".")))


def extract_features(url: str):
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    domain = (parsed.hostname or "").lower()
    lower_url = normalized.lower()
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    return [
        len(normalized),
        len(domain),
        normalized.count("."),
        1 if lower_url.startswith("https://") else 0,
        len(re.findall(r"[^a-zA-Z0-9]", normalized)),
        len(re.findall(r"\d", normalized)),
        domain.count("-"),
        subdomain_count(domain),
        sum(1 for word in SUSPICIOUS_KEYWORDS if word in lower_url),
        1 if "@" in normalized else 0,
        1 if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", domain) else 0,
        1 if domain in SHORTENERS else 0,
        brand_spoofed(domain),
        1 if tld in RISKY_TLDS else 0,
        int(entropy(domain) * 100),
    ]


def load_dataset():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    features, labels = [], []
    with DATASET_PATH.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            features.append(extract_features(row["url"]))
            labels.append(int(row["label"]))
    return features, labels


def main():
    x, y = load_dataset()
    stratify = y if len(set(y)) > 1 and min(y.count(0), y.count(1)) >= 2 else None
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.25, random_state=42, stratify=stratify
    )

    model = RandomForestClassifier(
        n_estimators=220,
        max_depth=12,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=42,
    )
    model.fit(x_train, y_train)

    predictions = model.predict(x_test)
    accuracy = accuracy_score(y_test, predictions)
    print(f"Accuracy: {accuracy:.3f}")
    print(classification_report(y_test, predictions, target_names=["safe", "phishing"], zero_division=0))

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")


if __name__ == "__main__":
    main()
