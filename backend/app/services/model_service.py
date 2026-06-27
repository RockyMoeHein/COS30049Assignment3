from __future__ import annotations

import gc
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from app.services.feature_extractor import extract_features


BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_DIR = BASE_DIR / "model"


@dataclass(frozen=True)
class ModelConfig:
    """Configuration needed to find and describe one trained model artifact."""

    key: str
    name: str
    path: Path
    model_type: str
    uses_features: bool
    family: str
    variant: str


# Central model registry. The frontend receives these keys through GET /models
# and sends one key back to POST /predict when the user selects a model.
MODEL_CONFIGS: dict[str, ModelConfig] = {
    "randomforest": ModelConfig(
        "randomforest",
        "Random Forest",
        MODEL_DIR / "traditional" / "randomforest.pkl",
        "traditional",
        False,
        "random_forest",
        "standard",
    ),
    "xgboost": ModelConfig(
        "xgboost",
        "XGBoost",
        MODEL_DIR / "traditional" / "xgboost.pkl",
        "traditional",
        False,
        "xgboost",
        "standard",
    ),
    "logistic": ModelConfig(
        "logistic",
        "Logistic Regression",
        MODEL_DIR / "traditional" / "logistic.pkl",
        "traditional",
        False,
        "logistic_regression",
        "standard",
    ),
    "linear_svc": ModelConfig(
        "linear_svc",
        "LinearSVC",
        MODEL_DIR / "traditional" / "linearSVC.pkl",
        "traditional",
        False,
        "linear_svc",
        "standard",
    ),
    "ensemble": ModelConfig(
        "ensemble",
        "Ensemble Model",
        MODEL_DIR / "traditional" / "ensemble.pkl",
        "traditional",
        False,
        "ensemble",
        "standard",
    ),
    "features_randomforest": ModelConfig(
        "features_randomforest",
        "Random Forest + Security Features",
        MODEL_DIR / "handcrafted_features" / "features_randomforest.pkl",
        "handcrafted_features",
        True,
        "random_forest",
        "handcrafted",
    ),
    "features_xgboost": ModelConfig(
        "features_xgboost",
        "XGBoost + Security Features",
        MODEL_DIR / "handcrafted_features" / "features_xgboost.pkl",
        "handcrafted_features",
        True,
        "xgboost",
        "handcrafted",
    ),
    "features_logistic": ModelConfig(
        "features_logistic",
        "Logistic Regression + Security Features",
        MODEL_DIR / "handcrafted_features" / "features_logistic.pkl",
        "handcrafted_features",
        True,
        "logistic_regression",
        "handcrafted",
    ),
    "features_linear_svc": ModelConfig(
        "features_linear_svc",
        "LinearSVC + Security Features",
        MODEL_DIR / "handcrafted_features" / "features_linearSVC.pkl",
        "handcrafted_features",
        True,
        "linear_svc",
        "handcrafted",
    ),
    "features_ensemble": ModelConfig(
        "features_ensemble",
        "Ensemble Model + Security Features",
        MODEL_DIR / "handcrafted_features" / "features_ensemble.pkl",
        "handcrafted_features",
        True,
        "ensemble",
        "handcrafted",
    ),
    "codebert": ModelConfig(
        "codebert",
        "CodeBERT Binary-Balanced",
        MODEL_DIR / "codeBERT" / "codebert_vuln_best.pt",
        "codebert",
        False,
        "codebert",
        "standard",
    ),
    "codebert_cwe_balanced": ModelConfig(
        "codebert_cwe_balanced",
        "CodeBERT CWE-Balanced",
        MODEL_DIR / "codeBERT" / "codeBERT-balanced.pt",
        "codebert",
        False,
        "codebert",
        "cwe_balanced",
    ),
}


class ModelService:
    def __init__(self) -> None:
        self._loaded_models: dict[str, Any] = {}
        self._codebert_tokenizer: Any | None = None
        self.default_model_key = "features_randomforest"
        self.history: list[dict[str, Any]] = []

    def list_models(self) -> list[dict[str, Any]]:
        """Build the model list shown in the frontend selector."""
        models = []
        for config in MODEL_CONFIGS.values():
            model = self._loaded_models.get(config.key)
            models.append(
                {
                    "key": config.key,
                    "name": config.name,
                    "model_type": config.model_type,
                    "uses_features": config.uses_features,
                    "family": config.family,
                    "variant": config.variant,
                    "supports_probability": (
                        True
                        if config.model_type == "codebert"
                        else None if model is None else hasattr(model, "predict_proba")
                    ),
                }
            )
        return models

    def set_default_model(self, model_key: str) -> None:
        """Validate and store the backend default model key."""
        self._get_config(model_key)
        self.default_model_key = model_key

    def clear_history(self) -> None:
        """Remove prediction history from this backend process."""
        self.history.clear()

    def predict(self, code: str, model_key: str | None = None) -> dict[str, Any]:
        """Run the complete prediction flow for one submitted code snippet."""
        selected_key = model_key or self.default_model_key
        config = self._get_config(selected_key)

        # Feature extraction runs for every model so the UI can always show
        # risk indicators and code metrics, even for models that use text only.
        features = extract_features(code)
        if config.model_type == "codebert":
            prediction, probability = self._predict_codebert(code, config)
        else:
            model = self._load_model(config)
            input_df = self._build_input_dataframe(code, features, config.uses_features)
            prediction = int(model.predict(input_df)[0])
            probability = self._predict_probability(model, input_df)
        label = "VULNERABLE" if prediction == 1 else "NON_VULNERABLE"
        confidence = self._confidence_percent(prediction, probability)
        created_at = datetime.now(timezone.utc)

        # Keep the response format consistent across traditional, handcrafted,
        # and CodeBERT models so the frontend can render one result component.
        result = {
            "model_key": config.key,
            "model_name": config.name,
            "prediction": prediction,
            "label": label,
            "vulnerable_probability": probability,
            "confidence_percent": confidence,
            "features": features,
            "created_at": created_at,
        }

        self.history.append(
            {
                "id": len(self.history) + 1,
                "model_key": config.key,
                "model_name": config.name,
                "label": label,
                "vulnerable_probability": probability,
                "confidence_percent": confidence,
                "created_at": created_at,
            }
        )
        self.history = self.history[-100:]
        return result

    def visualization_summary(self) -> dict[str, Any]:
        """Summarise current-session prediction history for visualisations."""
        label_counts = {"VULNERABLE": 0, "NON_VULNERABLE": 0}
        model_usage: dict[str, int] = {}

        for item in self.history:
            label_counts[item["label"]] = label_counts.get(item["label"], 0) + 1
            model_usage[item["model_name"]] = model_usage.get(item["model_name"], 0) + 1

        return {
            "total_predictions": len(self.history),
            "label_counts": label_counts,
            "model_usage": model_usage,
            "latest_predictions": list(reversed(self.history[-10:])),
            "risk_feature_catalog": [
                {"name": "Buffer memory risk", "field": "buffer_memory_risk_level", "max": 2},
                {"name": "Classic overflow risk", "field": "classic_overflow_risk_level", "max": 2},
                {
                    "name": "Pointer subtraction risk",
                    "field": "pointer_subtraction_risk_level",
                    "max": 2,
                },
                {"name": "Null pointer risk", "field": "null_pointer_risk_level", "max": 2},
                {"name": "Other CWE risk", "field": "other_cwe_risk_level", "max": 2},
                {"name": "Integer size risk", "field": "integer_size_risk_level", "max": 2},
            ],
        }

    def _get_config(self, model_key: str) -> ModelConfig:
        """Look up model metadata and produce a clear error for bad keys."""
        try:
            return MODEL_CONFIGS[model_key]
        except KeyError as exc:
            valid_keys = ", ".join(MODEL_CONFIGS)
            raise ValueError(f"Unknown model_key '{model_key}'. Valid values: {valid_keys}") from exc

    def _load_model(self, config: ModelConfig) -> Any:
        """Load one traditional or handcrafted model artifact from disk."""
        if config.key not in self._loaded_models:
            # These model files are large, so keep only the active one in
            # memory to reduce crashes when switching between model families.
            self._loaded_models.clear()
            gc.collect()
            if not config.path.exists():
                raise FileNotFoundError(f"Model file not found: {config.path}")
            self._loaded_models[config.key] = joblib.load(config.path)
        return self._loaded_models[config.key]

    def _predict_codebert(
        self,
        code: str,
        config: ModelConfig,
    ) -> tuple[int, float]:
        """Run CodeBERT in a short subprocess to keep the FastAPI server stable."""
        if not config.path.exists():
            raise FileNotFoundError(f"Model file not found: {config.path}")

        self._loaded_models.clear()
        gc.collect()

        runner_path = Path(__file__).with_name("codebert_runner.py")
        payload = json.dumps({
            "model_path": str(config.path),
            "code": code,
        })
        environment = {
            **os.environ,
            "TOKENIZERS_PARALLELISM": "false",
        }

        try:
            result = subprocess.run(
                [sys.executable, str(runner_path)],
                input=payload,
                capture_output=True,
                check=True,
                encoding="utf-8",
                env=environment,
                timeout=150,
            )
        except subprocess.TimeoutExpired as exc:
            raise ValueError("CodeBERT prediction timed out. Try a shorter snippet.") from exc
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr.strip() or exc.stdout.strip() or str(exc)
            raise ValueError(f"CodeBERT prediction failed: {detail}") from exc

        output = json.loads(result.stdout)
        return int(output["prediction"]), float(output["vulnerable_probability"])

    def _release_codebert_models(self) -> None:
        """Release CodeBERT models if they were loaded in this process."""
        codebert_keys = [
            key
            for key in self._loaded_models
            if MODEL_CONFIGS[key].model_type == "codebert"
        ]
        for key in codebert_keys:
            del self._loaded_models[key]
        if codebert_keys:
            gc.collect()

    @staticmethod
    def _build_input_dataframe(
        code: str,
        features: dict[str, Any],
        uses_features: bool,
    ) -> pd.DataFrame:
        """Create the pandas input format expected by the selected pipeline."""
        if uses_features:
            return pd.DataFrame([{"code": code, **features}])
        return pd.DataFrame({"code": [code]})

    @staticmethod
    def _predict_probability(model: Any, input_df: pd.DataFrame) -> float | None:
        """Return vulnerable probability when the model supports predict_proba."""
        if not hasattr(model, "predict_proba"):
            return None

        try:
            return round(float(model.predict_proba(input_df)[0][1]), 4)
        except Exception:
            return None

    @staticmethod
    def _confidence_percent(prediction: int, probability: float | None) -> float | None:
        """Convert vulnerable probability into confidence for the predicted class."""
        if probability is None:
            return None
        confidence = probability if prediction == 1 else 1 - probability
        return round(confidence * 100, 2)
