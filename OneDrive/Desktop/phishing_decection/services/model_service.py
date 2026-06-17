"""Model performance metadata for dashboard display."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def performance_summary() -> dict[str, Any]:
    model_exists = Path("models/model.pkl").exists()
    return {
        "model_version": "rf-url-v1",
        "model_loaded": model_exists,
        "accuracy": 0.94,
        "precision": 0.93,
        "recall": 0.91,
        "f1_score": 0.92,
        "roc_auc": 0.95,
        "confusion_matrix": [[186, 11], [15, 172]],
        "note": "Metrics are dashboard defaults. Retrain with train_model.py and update this service with evaluation artifacts for production evidence.",
    }
